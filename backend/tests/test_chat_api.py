"""
Task 9:main.py —— 会话 API + SSE 单流 + 限流。

验收标准:① SSE 帧序列 stage×16(原样转发)→ token* → done(终帧)
② 60 秒内第 11 条 → 429(限流)③ 空白 text 且无附件 → 400
④ LLMFailure(protocol) → event: error {class:"protocol"},无 mock 回复
⑤ done 帧含 message_id/chain_refs/verification。
"""
from __future__ import annotations

import base64
import json
import os
import types

os.environ.setdefault("CG_NO_BOOT", "1")  # 测试不触发 lifespan 装配

import pytest
from fastapi.testclient import TestClient

from app import main as main_mod
from app.bootstrap import build_chat_service
from app.llm import LLMFailure, LLMGateway, MockChat

STAGES = ["detect", "tokenize", "package", "hash",
          "dispatch", "verify", "restore", "persist"]


def parse_sse(text: str) -> list[tuple[str, dict]]:
    """解析 SSE 帧序列:每帧 `event: X` + `data: <json>`,以空行分隔。"""
    frames: list[tuple[str, dict]] = []
    for block in text.strip().split("\n\n"):
        lines = block.splitlines()
        kind = lines[0].split(":", 1)[1].strip()
        data = json.loads(lines[1].split(":", 1)[1].strip())
        frames.append((kind, data))
    return frames


class ProtocolFailGateway:
    """protocol 失败 stub:直抛 LLMFailure("protocol"),绝不降级(验收④)。"""

    def chat(self, messages, on_token=None):
        raise LLMFailure("protocol", "HTTP 401 Unauthorized")


class BoomGateway:
    """未分类异常 stub:校验 fail-closed 的 internal 错误帧。"""

    def chat(self, messages, on_token=None):
        raise RuntimeError("boom")


def make_chat(tmp_path, monkeypatch, gateway=None):
    """装配测试客户端:CG_NO_BOOT + 固定 VAULT_KEY + 显式挂 app.state.chat。"""
    monkeypatch.setenv("CG_NO_BOOT", "1")
    monkeypatch.setattr("app.keys._ENV_PATH_DEFAULT", tmp_path / "isolated.env")
    monkeypatch.setenv("VAULT_KEY", "a1" * 32)
    main_mod._chat_rate_hits.clear()
    main_mod._chain_verify_cache.clear()
    service = build_chat_service(
        tmp_path, gateway=gateway or LLMGateway(mimo=None, mock=MockChat()))
    monkeypatch.setattr(main_mod.app.state, "chat", service, raising=False)
    return types.SimpleNamespace(client=TestClient(main_mod.app), service=service)


@pytest.fixture()
def chat(tmp_path, monkeypatch):
    return make_chat(tmp_path, monkeypatch)


# --------------------------------------------------------------------------- #
# ① SSE 帧序列:16 条 stage 原样转发 → token* → done 终帧(⑤ done 载荷)
# --------------------------------------------------------------------------- #
def test_sse_frame_sequence_and_done_payload(chat):
    sid = chat.client.post("/api/chat/sessions",
                           json={"title": "验收"}).json()["id"]
    text = "张三的手机号是13800138000"

    resp = chat.client.post(f"/api/chat/sessions/{sid}/messages",
                            json={"text": text})

    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/event-stream")
    frames = parse_sse(resp.text)
    kinds = [k for k, _ in frames]

    # stage 帧原样转发:8 阶段 × start/done 成对、顺序固定、载荷恰好三键
    stage_frames = [d for k, d in frames if k == "stage"]
    assert [(d["stage"], d["status"]) for d in stage_frames] == \
        [(n, s) for n in STAGES for s in ("start", "done")]
    assert all(set(d) == {"stage", "status", "t_ms"} for d in stage_frames)

    # token 帧格式固定,发生在 dispatch start 与 dispatch done 之间
    token_frames = [d for k, d in frames if k == "token"]
    assert token_frames and all(set(d) == {"delta", "reasoning"} for d in token_frames)
    i_start = [i for i, (k, d) in enumerate(frames)
               if k == "stage" and d["stage"] == "dispatch"
               and d["status"] == "start"][0]
    i_done = [i for i, (k, d) in enumerate(frames)
              if k == "stage" and d["stage"] == "dispatch" and d["status"] == "done"][0]
    assert all(i_start < i < i_done for i, k in enumerate(kinds) if k == "token")

    # 只有 stage/token 中间帧,done 是唯一终帧(⑤)
    assert set(kinds[:-1]) <= {"stage", "token"}
    assert kinds[-1] == "done"
    done = frames[-1][1]
    assert {"message_id", "chain_refs", "verification"} <= set(done)
    assert done["message_id"].startswith("msg_")
    assert done["chain_refs"] == [0] and done["status"] == "verified"
    assert [v["layer"] for v in done["verification"]] == \
        ["输入绑定/防重放", "模型身份", "响应完整性", "可审计日志"]
    assert all(v["ok"] for v in done["verification"])


# --------------------------------------------------------------------------- #
# ② 限流:60 秒内第 11 条 → 429,滑窗按会话
# --------------------------------------------------------------------------- #
def test_rate_limit_11th_within_60s_429(chat):
    sid = chat.client.post("/api/chat/sessions", json={}).json()["id"]
    for i in range(10):
        r = chat.client.post(f"/api/chat/sessions/{sid}/messages",
                             json={"text": f"第{i}条"})
        assert r.status_code == 200

    r = chat.client.post(f"/api/chat/sessions/{sid}/messages",
                         json={"text": "第11条"})
    assert r.status_code == 429
    assert r.json() == {"detail": "限流:每会话每分钟最多 10 条"}


# --------------------------------------------------------------------------- #
# ③ 空白输入:400,不入链不落盘
# --------------------------------------------------------------------------- #
def test_blank_text_400(chat):
    sid = chat.client.post("/api/chat/sessions", json={}).json()["id"]
    for body in ({"text": ""}, {"text": "   \n\t  "}):
        r = chat.client.post(f"/api/chat/sessions/{sid}/messages", json=body)
        assert r.status_code == 400
        assert "空白" in r.json()["detail"]
    assert chat.service.sessions.list_messages(sid) == []
    assert chat.service.chain.entries == []

    # 空白正文 + 附件:允许发送(仅「空白且无附件」才拒绝)
    content_b64 = base64.b64encode("附件内容".encode("utf-8")).decode("ascii")
    r = chat.client.post(f"/api/chat/sessions/{sid}/messages",
                         json={"text": "   ",
                               "files": [{"filename": "a.txt",
                                          "content_b64": content_b64}]})
    assert r.status_code == 200
    assert parse_sse(r.text)[-1][0] == "done"


# --------------------------------------------------------------------------- #
# ④ protocol 错误:event: error class=protocol,无 mock 回复
# --------------------------------------------------------------------------- #
def test_protocol_error_frame_no_mock_reply(tmp_path, monkeypatch):
    chat = make_chat(tmp_path, monkeypatch, gateway=ProtocolFailGateway())
    sid = chat.client.post("/api/chat/sessions", json={}).json()["id"]

    r = chat.client.post(f"/api/chat/sessions/{sid}/messages",
                         json={"text": "你好"})

    frames = parse_sse(r.text)
    kinds = [k for k, _ in frames]
    assert kinds[-1] == "error"
    assert "done" not in kinds and "token" not in kinds   # 无 mock 回复
    err = frames[-1][1]
    assert err["class"] == "protocol"
    assert "401" in err["message"]
    # 失败轮不落盘、不入链
    assert chat.service.sessions.list_messages(sid) == []
    assert chat.service.chain.entries == []


# --------------------------------------------------------------------------- #
# 未分类异常:event: error class=internal(fail-closed,不外泄栈轨迹)
# --------------------------------------------------------------------------- #
def test_internal_error_frame_fail_closed(tmp_path, monkeypatch):
    chat = make_chat(tmp_path, monkeypatch, gateway=BoomGateway())
    sid = chat.client.post("/api/chat/sessions", json={}).json()["id"]

    r = chat.client.post(f"/api/chat/sessions/{sid}/messages",
                         json={"text": "你好"})

    frames = parse_sse(r.text)
    assert [k for k, _ in frames][-1] == "error"
    err = frames[-1][1]
    assert err["class"] == "internal"
    assert "Traceback" not in err["message"]


# --------------------------------------------------------------------------- #
# 会话 CRUD:创建/列表/详情(消息动态还原 user_view)/未知 404
# --------------------------------------------------------------------------- #
def test_sessions_crud_and_dynamic_user_view(chat):
    text = "张三的手机号是13800138000"
    sess = chat.client.post("/api/chat/sessions", json={"title": "T1"}).json()
    sid = sess["id"]
    assert sess["title"] == "T1"

    assert any(s["id"] == sid for s in
               chat.client.get("/api/chat/sessions").json())

    chat.client.post(f"/api/chat/sessions/{sid}/messages", json={"text": text})
    det = chat.client.get(f"/api/chat/sessions/{sid}").json()
    assert det["session"]["id"] == sid
    msgs = det["messages"]
    assert [m["role"] for m in msgs] == ["user", "assistant"]
    assert msgs[0]["user_view"] == text                    # 动态还原(不落盘)
    assert "13800138000" not in msgs[0]["llm_view"]        # llm_view 在令牌空间

    assert chat.client.get("/api/chat/sessions/nope").status_code == 404
    r = chat.client.post("/api/chat/sessions/nope/messages", json={"text": "hi"})
    assert r.status_code == 404
