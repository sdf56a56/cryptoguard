"""
Task 10:查看器 API —— pipeline / chain / proof / preimage。

验收标准:① pipeline 一次取全且 user_view 动态还原 ② proof 数据经
verify_proof 自洽 ③ preimage 端点恰好四字段、match 仅是两值比较布尔
④ 链缓存:连续两次调用第二次免 verify 重算,入链后失效。
"""
from __future__ import annotations

import os
import types

os.environ.setdefault("CG_NO_BOOT", "1")  # 测试不触发 lifespan 装配

import pytest
from fastapi.testclient import TestClient

from app import main as main_mod
from app.bootstrap import build_chat_service
from app.canon import h_hex
from app.crypto.merkle import MerkleTree
from app.llm import LLMGateway, MockChat


@pytest.fixture()
def chat(tmp_path, monkeypatch):
    """装配测试客户端 + 跑一轮真实对话(供 pipeline/proof 断言)。"""
    monkeypatch.setenv("CG_NO_BOOT", "1")
    monkeypatch.setattr("app.keys._ENV_PATH_DEFAULT", tmp_path / "isolated.env")
    monkeypatch.setenv("VAULT_KEY", "b2" * 32)
    main_mod._chat_rate_hits.clear()
    main_mod._chain_verify_cache.clear()
    service = build_chat_service(
        tmp_path, gateway=LLMGateway(mimo=None, mock=MockChat()))
    monkeypatch.setattr(main_mod.app.state, "chat", service, raising=False)
    return types.SimpleNamespace(client=TestClient(main_mod.app), service=service)


def run_turn(chat, text="张三的手机号是13800138000"):
    """直接走编排跑一轮(查看器断言不依赖 SSE),返回 done 摘要。"""
    sid = chat.service.sessions.create_session("查看器")["id"]
    result = chat.service.run_turn(sid, text)
    return sid, result


# --------------------------------------------------------------------------- #
# ① pipeline:一次取全(user_view 动态还原 + artifacts/verification/链条目/files)
# --------------------------------------------------------------------------- #
def test_pipeline_full_payload_with_dynamic_user_view(chat):
    text = "张三的手机号是13800138000"
    sid, result = run_turn(chat, text)
    mid = result["message_id"]

    r = chat.client.get(f"/api/messages/{mid}/pipeline")
    assert r.status_code == 200
    payload = r.json()
    assert set(payload) == {"message", "artifacts", "verification",
                            "chain_entries", "files"}

    message = payload["message"]
    assert message["id"] == mid and message["session_id"] == sid
    assert message["user_view"] == text                    # 动态还原,不落盘
    assert "13800138000" not in message["llm_view"]

    assert set(payload["artifacts"]) == {"outbound", "canonical_preimage",
                                         "tokens", "entities"}
    assert payload["artifacts"]["entities"]                # 检测命中
    assert payload["artifacts"]["tokens"]                  # 令牌分级
    assert [v["layer"] for v in payload["verification"]] == \
        ["输入绑定/防重放", "模型身份", "响应完整性", "可审计日志"]

    entries = chat.service.chain.entries
    assert payload["chain_entries"] == [entries[i] for i in message["chain_refs"]]
    assert payload["chain_entries"][0]["message_id"] == mid
    assert payload["files"] == message["files"] == []

    # assistant 记录同样可查(无链条目)
    r2 = chat.client.get(f"/api/messages/{result['assistant_message_id']}/pipeline")
    assert r2.status_code == 200
    assert r2.json()["chain_entries"] == []

    assert chat.client.get("/api/messages/msg_nope/pipeline").status_code == 404


# --------------------------------------------------------------------------- #
# 链状态:chain / chain_valid / chain_root / merkle / count 一次取全
# --------------------------------------------------------------------------- #
def test_chain_endpoint_shape_and_merkle(chat):
    run_turn(chat)
    r = chat.client.get("/api/chain")
    payload = r.json()
    assert set(payload) == {"chain", "chain_valid", "chain_root", "merkle", "count"}

    entries = chat.service.chain.entries
    assert payload["chain"] == entries
    assert payload["chain_valid"] is True
    assert payload["chain_root"] == chat.service.chain.root
    assert payload["count"] == len(entries) == 1
    tree = MerkleTree([e["hash"] for e in entries])
    assert payload["merkle"] == tree.to_dict()
    assert payload["merkle"]["root"] == tree.root


# --------------------------------------------------------------------------- #
# ④ 链缓存:同 (条数, root) 免重算;入链后失效
# --------------------------------------------------------------------------- #
def test_chain_verify_cache_hit_and_invalidation(chat, monkeypatch):
    run_turn(chat)
    calls: list[int] = []
    chain = chat.service.chain
    real_verify = chain.verify

    def counting_verify():
        calls.append(1)
        return real_verify()

    monkeypatch.setattr(chain, "verify", counting_verify)
    main_mod._chain_verify_cache.clear()

    assert chat.client.get("/api/chain").json()["chain_valid"] is True
    assert len(calls) == 1
    assert chat.client.get("/api/chain").json()["chain_valid"] is True
    assert len(calls) == 1                        # 命中缓存,免重算

    chain.append("QUERY", "d" * 64, "2026-10-12T00:00:00.000000Z",
                 message_id="msg_cache")
    assert chat.client.get("/api/chain").json()["chain_valid"] is True
    assert len(calls) == 2                        # 入链 → 键变 → 失效重算
    assert chat.client.get("/api/chain").json()["chain_valid"] is True
    assert len(calls) == 2


# --------------------------------------------------------------------------- #
# ② Merkle 单条证明:数据自洽(verify_proof 复验),越界 404
# --------------------------------------------------------------------------- #
def test_chain_entry_proof_self_consistent(chat):
    run_turn(chat)
    entries = chat.service.chain.entries

    r = chat.client.get("/api/chain/entry/0/proof")
    assert r.status_code == 200
    payload = r.json()
    assert set(payload) == {"index", "leaf", "proof", "root", "verified"}
    assert payload["index"] == 0
    assert payload["leaf"] == entries[0]["hash"]
    assert payload["verified"] is True

    # 独立复验:全链叶子集建树,verify_proof 数据自洽
    tree = MerkleTree([e["hash"] for e in entries])
    assert payload["root"] == tree.root
    assert tree.verify_proof(payload["leaf"], 0, payload["proof"],
                             payload["root"]) is True

    assert chat.client.get("/api/chain/entry/1/proof").status_code == 404
    assert chat.client.get("/api/chain/entry/-1/proof").status_code == 404


# --------------------------------------------------------------------------- #
# ③ preimage 独立复算:恰好四字段,match 仅是两值比较布尔(纯数据、无结论)
# --------------------------------------------------------------------------- #
def test_preimage_endpoint_pure_data(chat):
    preimage = {"d": "CG/IN/v2", "t": "张三", "n": "abc"}
    good = h_hex(preimage)

    r = chat.client.post("/api/verify/preimage",
                         json={"preimage": preimage, "expected_hash": good})
    payload = r.json()
    assert set(payload) == {"preimage", "expected_hash",
                            "recomputed_hash", "match"}
    assert payload["preimage"] == preimage
    assert payload["expected_hash"] == good
    assert payload["recomputed_hash"] == good
    assert payload["match"] is True
    assert type(payload["match"]) is bool

    r2 = chat.client.post("/api/verify/preimage",
                          json={"preimage": preimage,
                                "expected_hash": "0" * 64})
    p2 = r2.json()
    assert set(p2) == {"preimage", "expected_hash", "recomputed_hash", "match"}
    assert p2["recomputed_hash"] == good
    assert p2["match"] is False and type(p2["match"]) is bool
