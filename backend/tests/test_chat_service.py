"""
Task 8:chat_service.py —— 单轮编排 + provider 封缄 + 入链。

验收标准:① 全轮(MockChat)产出双视角消息 + 带 mid 链条目 + chain_refs 双向一致
② 空白输入抛 ValueError 不入链 ③ 断流(stub gateway)已收内容落盘 + incomplete +
Review Focus 2 断言(刷新/重启后可见) ④ degraded="mock" 透传到 reply_meta
⑤ reasoning 只存 reasoning_ct 不进下一轮 prompt。
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from app.chat_service import ChatService
from app.crypto.hashchain import HashChain
from app.keys import Vault
from app.llm import LLMGateway, MockChat, ReplyStream
from app.proxy import CryptoGuard
from app.sessions import SessionStore
from app.store import SealedNDJSON, replay_chain

STAGE_NAMES = ["detect", "tokenize", "package", "hash",
               "dispatch", "verify", "restore", "persist"]


# --------------------------------------------------------------------------- #
# 夹具:真实 Vault/存储 + MockChat 网关(测试内 stub 网关见各用例)
# --------------------------------------------------------------------------- #
def make_vault() -> Vault:
    """固定密钥测试 Vault(ctor 直注入,免 .env)。"""
    return Vault(
        mapping_key=bytes(range(32)),
        reasoning_key=bytes(range(32, 64)),
        chain_mac_key=bytes(range(64, 96)),
        demo_chain_mac_key=bytes(range(96, 128)),
        fingerprint="test-fp",
    )


class Env:
    """测试环境聚合:ChatService + 全部存储句柄(供重启重载断言)。"""

    def __init__(self, tmp_path: Path, gateway=None):
        self.tmp_path = tmp_path
        self.vault = make_vault()
        self.sessions_log = SealedNDJSON(tmp_path / "sessions", "seg", self.vault.chain_mac_key)
        self.messages_log = SealedNDJSON(tmp_path / "messages", "seg", self.vault.chain_mac_key)
        self.chain_log = SealedNDJSON(tmp_path / "chain", "seg", self.vault.chain_mac_key)
        self.sessions = SessionStore(self.vault, self.sessions_log, self.messages_log)
        self.chain = HashChain()
        self.guard = CryptoGuard()
        self.gateway = gateway if gateway is not None else MockChat()
        self.svc = ChatService(self.guard, self.sessions, self.gateway,
                               self.chain, self.chain_log)

    def reload_stores(self) -> SessionStore:
        """模拟重启:同目录重建三本日志 + SessionStore + 链回放。"""
        sessions_log = SealedNDJSON(self.tmp_path / "sessions", "seg", self.vault.chain_mac_key)
        messages_log = SealedNDJSON(self.tmp_path / "messages", "seg", self.vault.chain_mac_key)
        self.chain_log = SealedNDJSON(self.tmp_path / "chain", "seg", self.vault.chain_mac_key)
        self.chain = replay_chain(self.chain_log)
        return SessionStore(self.vault, sessions_log, messages_log)


class BrokenStreamGateway:
    """断流 stub:吐出部分 token 后返回 incomplete=True(Review Focus 2)。"""

    def __init__(self, partial: str, reasoning: str = ""):
        self.partial = partial
        self.reasoning = reasoning
        self.captured: list[list[dict]] = []

    def chat(self, messages, on_token=None):
        self.captured.append([dict(m) for m in messages])
        if on_token is not None:
            if self.reasoning:
                on_token(self.reasoning, True)
            for i in range(0, len(self.partial), 2):
                on_token(self.partial[i:i + 2], False)
        return ReplyStream(output=self.partial, reasoning_content=self.reasoning,
                           incomplete=True, degraded=None, model="stub-stream")


class CaptureGateway:
    """双轮 stub:记录每轮 messages,首轮回带 reasoning(验收⑤捕获断言)。"""

    def __init__(self, outputs: list[str], reasonings: list[str]):
        self.outputs = outputs
        self.reasonings = reasonings
        self.captured: list[list[dict]] = []
        self._i = 0

    def chat(self, messages, on_token=None):
        self.captured.append([dict(m) for m in messages])
        out = self.outputs[self._i]
        rsn = self.reasonings[self._i]
        self._i += 1
        if on_token is not None:
            if rsn:
                on_token(rsn, True)
            if out:
                on_token(out, False)
        return ReplyStream(output=out, reasoning_content=rsn,
                           incomplete=False, degraded=None, model="stub-cap")


def collect_events() -> tuple[list[tuple[str, dict]], callable]:
    events: list[tuple[str, dict]] = []
    return events, (lambda kind, payload: events.append((kind, payload)))


# --------------------------------------------------------------------------- #
# ① 全轮:双视角消息 + 带 mid 链条目 + chain_refs 双向一致
# --------------------------------------------------------------------------- #
def test_full_turn_dual_view_and_chain(tmp_path):
    env = Env(tmp_path)
    sid = env.sessions.create_session("全轮")["id"]
    events, on_event = collect_events()
    text = "张三的手机号是13800138000"

    result = env.svc.run_turn(sid, text, None, on_event)

    # —— 返回形态与状态 ——
    assert set(result) == {"message_id", "assistant_message_id", "verification",
                           "chain_refs", "incomplete", "degraded", "status"}
    assert result["status"] == "verified"
    assert result["incomplete"] is False
    assert result["degraded"] is None

    # —— 八阶段事件:start/done 成对、顺序固定、t_ms 为真实计时 ——
    stage_events = [p for k, p in events if k == "stage"]
    assert [(p["stage"], p["status"]) for p in stage_events] == \
        [(n, s) for n in STAGE_NAMES for s in ("start", "done")]
    for p in stage_events:
        assert isinstance(p["t_ms"], float) and p["t_ms"] >= 0
    starts = [p for p in stage_events if p["status"] == "start"]
    dones = [p for p in stage_events if p["status"] == "done"]
    assert all(p["t_ms"] == 0.0 for p in starts)
    assert sum(p["t_ms"] for p in dones) > 0          # 真实计时非全零
    token_events = [p for k, p in events if k == "token"]
    assert token_events and all("delta" in p and "reasoning" in p for p in token_events)
    assert events[-1][0] == "done" and events[-1][1] == result

    # —— 双视角消息记录 ——
    msgs = env.sessions.list_messages(sid)
    assert [m["role"] for m in msgs] == ["user", "assistant"]
    user, assistant = msgs
    assert user["id"] == result["message_id"]
    assert assistant["id"] == result["assistant_message_id"]
    # llm_view 在令牌空间:user_view 动态还原为原文(逐字一致)
    assert "张三" not in user["llm_view"] and "13800138000" not in user["llm_view"]
    assert user["user_view"] == text
    assert assistant["llm_view"]  # 模型原始令牌空间输出
    # user_view / reasoning 明文永不落盘(SEC-STORE-1)
    raw_dump = json.dumps(env.messages_log.read_all(), ensure_ascii=False)
    assert "user_view" not in raw_dump

    # —— 链条目带 message_id + chain_refs 双向一致 ——
    entries = env.chain.entries
    assert [e["entry_type"] for e in entries] == ["QUERY"]
    assert all(e["message_id"] == result["message_id"] for e in entries)
    assert result["chain_refs"] == [e["index"] for e in entries]
    assert user["chain_refs"] == result["chain_refs"]
    assert assistant["chain_refs"] == []
    # QUERY payload_digest = req.input_hash
    outbound = user["artifacts"]["outbound"]
    assert entries[0]["payload_digest"] == outbound["input_hash"]
    # 写穿 chain_log(封缄行 = 链条目 + entry_checksum)
    logged = env.chain_log.read_all()
    assert [(e["entry_type"], e["index"], e.get("message_id")) for e in logged] == \
        [(e["entry_type"], e["index"], e["message_id"]) for e in entries]
    # guard.merkle_leaves 同步追加
    assert env.guard.merkle_leaves[-len(entries):] == [e["hash"] for e in entries]

    # —— artifacts:entities 无明文(仅 value_len),tokens 无 value ——
    arts = user["artifacts"]
    assert set(arts) == {"outbound", "canonical_preimage", "tokens", "entities"}
    assert arts["canonical_preimage"] == outbound["canonical_preimage"]
    dumped = json.dumps(arts, ensure_ascii=False)
    assert "张三" not in dumped and "13800138000" not in dumped
    assert arts["entities"] and all(
        set(e) == {"type", "start", "end", "value_len"} for e in arts["entities"])
    assert arts["tokens"] and all("value" not in t for t in arts["tokens"])
    assert set(assistant["artifacts"]) == {"response_hash", "signature"}

    # —— 回程验证四层齐全且全过 ——
    assert [v["layer"] for v in result["verification"]] == \
        ["输入绑定/防重放", "模型身份", "响应完整性", "可审计日志"]
    assert all(v["ok"] for v in result["verification"])
    assert assistant["reply_meta"]["model"] == "CryptoGuard-Mock-LLM-v1"


# --------------------------------------------------------------------------- #
# ② 空白输入:抛 ValueError,不入链不落盘
# --------------------------------------------------------------------------- #
def test_blank_input_raises_nothing_persisted(tmp_path):
    env = Env(tmp_path)
    sid = env.sessions.create_session("空白")["id"]
    events, on_event = collect_events()

    for blank in ("", "   ", "\n\t  "):
        with pytest.raises(ValueError):
            env.svc.run_turn(sid, blank, None, on_event)
    with pytest.raises(ValueError):
        env.svc.run_turn(sid, None, [], on_event)  # type: ignore[arg-type]

    assert env.chain.entries == []
    assert env.chain_log.read_all() == []
    assert env.sessions.list_messages(sid) == []
    assert env.guard.merkle_leaves == []
    assert events == []   # 任何阶段事件都不发


# --------------------------------------------------------------------------- #
# ③ 断流:已收内容落盘 + incomplete + Review Focus 2(重启后可见)
# --------------------------------------------------------------------------- #
def test_incomplete_stream_persisted_and_survives_reload(tmp_path):
    partial = "已收到您的请求,处理到一半断了"
    env = Env(tmp_path, gateway=BrokenStreamGateway(partial))
    sid = env.sessions.create_session("断流")["id"]
    events, on_event = collect_events()

    result = env.svc.run_turn(sid, "介绍一下13800138000的情况", None, on_event)

    assert result["incomplete"] is True
    assert result["status"] == "incomplete"
    # 响应完整性行被覆写为「跳过(不完整)」,其余层照常评估
    rows = {v["layer"]: v for v in result["verification"]}
    assert rows["响应完整性"] == {"layer": "响应完整性", "ok": None, "detail": "跳过(不完整)"}
    assert rows["输入绑定/防重放"]["ok"] is True
    assert rows["模型身份"]["ok"] is True

    # 已收内容落盘 + incomplete 透传 reply_meta(Review Focus 2)
    user, assistant = env.sessions.list_messages(sid)
    assert assistant["llm_view"] == partial
    assert assistant["reply_meta"]["incomplete"] is True
    assert user["reply_meta"]["incomplete"] is True
    assert result["message_id"] == user["id"]

    # 重启(重建存储 + 链回放)后消息与 incomplete 状态仍可见
    store2 = env.reload_stores()
    msgs2 = store2.list_messages(sid)
    assert [m["llm_view"] for m in msgs2] == [user["llm_view"], partial]
    assert msgs2[1]["reply_meta"]["incomplete"] is True
    assert msgs2[0]["user_view"] == "介绍一下13800138000的情况"
    assert store2.get_message(assistant["id"])["llm_view"] == partial
    assert env.chain.verify() and env.chain.entries[0]["message_id"] == user["id"]


# --------------------------------------------------------------------------- #
# ④ degraded="mock" 透传到 reply_meta
# --------------------------------------------------------------------------- #
def test_degraded_mock_lands_in_reply_meta(tmp_path):
    env = Env(tmp_path, gateway=LLMGateway(mimo=None, mock=MockChat()))
    sid = env.sessions.create_session("降级")["id"]

    result = env.svc.run_turn(sid, "你好", None, None)

    assert result["degraded"] == "mock"
    msgs = env.sessions.list_messages(sid)
    assert msgs[1]["reply_meta"]["degraded"] == "mock"
    assert msgs[0]["reply_meta"]["degraded"] == "mock"
    assert result["status"] == "verified"


# --------------------------------------------------------------------------- #
# ⑤ reasoning 只存 reasoning_ct,不进下一轮 prompt
# --------------------------------------------------------------------------- #
def test_reasoning_sealed_and_never_in_next_prompt(tmp_path):
    secret = "秘密推理CHAIN-777不可外泄"
    gw = CaptureGateway(outputs=["第一轮回答", "第二轮回答"],
                        reasonings=[secret, ""])
    env = Env(tmp_path, gateway=gw)
    sid = env.sessions.create_session("推理")["id"]
    events, on_event = collect_events()

    env.svc.run_turn(sid, "张三的手机号是13800138000", None, on_event)
    env.svc.run_turn(sid, "继续", None, on_event)

    msgs = env.sessions.list_messages(sid)
    assistant1 = msgs[1]
    # reasoning 封缄在 reasoning_ct,可解封还原
    assert assistant1["reasoning_ct"] is not None
    assert env.sessions.decrypt_reasoning(assistant1["reasoning_ct"]) == \
        {"reasoning_content": secret}
    # 明文 reasoning 不落盘
    assert secret not in json.dumps(env.messages_log.read_all(), ensure_ascii=False)
    # 分轨 token 事件带 reasoning=True
    assert any(k == "token" and p["reasoning"] and p["delta"] == secret
               for k, p in events)

    # 下一轮 prompt:历史只回传 llm_view,reasoning 绝不进 messages(捕获断言)
    turn2 = gw.captured[1]
    assert [m["role"] for m in turn2] == ["system", "user", "assistant", "user"]
    assert all(set(m) == {"role", "content"} for m in turn2)
    assert secret not in json.dumps(turn2, ensure_ascii=False)
    assert turn2[2]["content"] == assistant1["llm_view"]   # 原始令牌空间输出
    assert turn2[1]["content"] == msgs[0]["llm_view"]      # 令牌空间历史,非明文
    assert "张三" not in turn2[1]["content"]
    assert turn2[3]["content"] == msgs[2]["llm_view"]


# --------------------------------------------------------------------------- #
# 入链顺序:USER_OVERRIDE / FILE_COMMIT / QUERY(均带 message_id)
# --------------------------------------------------------------------------- #
def test_chain_order_files_and_overrides(tmp_path):
    env = Env(tmp_path)
    sid = env.sessions.create_session("文件")["id"]
    override = {"event_id": "ov1", "entity_span": [0, 2], "entity_type": "NAME",
                "original_token": "tok123", "action": "force_allow",
                "replacement": None, "user_ack": True,
                "ts": "2026-10-12T00:00:00.000000Z"}
    data = "张三的手机号13800138000".encode("utf-8")
    files = [{"filename": "note.txt", "data": data}]

    result = env.svc.run_turn(sid, "联系张三", files, None, [override])

    entries = env.chain.entries
    assert [e["entry_type"] for e in entries] == ["USER_OVERRIDE", "FILE_COMMIT", "QUERY"]
    assert all(e["message_id"] == result["message_id"] for e in entries)
    assert result["chain_refs"] == [0, 1, 2]
    user = env.sessions.list_messages(sid)[0]
    assert user["chain_refs"] == [0, 1, 2]
    # FILE_COMMIT payload_digest = file_hash|filename_token(裁定 R21)
    fc = entries[1]["payload_digest"]
    assert fc.startswith(hashlib.sha256(data).hexdigest() + "|")
    # USER_OVERRIDE 载荷 = canon(override 列表),出站包带 override_events
    outbound = user["artifacts"]["outbound"]
    assert outbound["override_events"][0]["event_id"] == "ov1"
    assert outbound["file_payloads"][0]["content_tier"] == "readable"
    # 消息 files 元数据(设计 §3.3 形态)
    assert user["files"] == [{"name": "note.txt",
                              "file_hash": hashlib.sha256(data).hexdigest(),
                              "channel": "readable"}]
    # 文件内实体令牌并入映射,文件令牌形态不出现在明文落盘
    assert any(t["type"] in ("NAME", "PHONE") for t in user["artifacts"]["tokens"])


# --------------------------------------------------------------------------- #
# 空白正文 + 附件:允许发送(仅「空白且无附件」才拒绝)
# --------------------------------------------------------------------------- #
def test_blank_text_with_files_allowed(tmp_path):
    env = Env(tmp_path)
    sid = env.sessions.create_session("附件")["id"]
    data = "项目代号 天枢计划".encode("utf-8")

    result = env.svc.run_turn(sid, "   ", [{"filename": "a.txt", "data": data}], None)

    assert result["status"] == "verified"
    assert [e["entry_type"] for e in env.chain.entries] == ["FILE_COMMIT", "QUERY"]
    user = env.sessions.list_messages(sid)[0]
    assert user["llm_view"] == "   "
