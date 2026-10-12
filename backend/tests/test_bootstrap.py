"""
Task 11:bootstrap.py —— 启动装配 + lifespan 接线 + 失败路径。

验收标准:① tmp 目录 build → 跑 2 轮 → 重建实例 → 会话/链/消息可还原且
chain.verify() True(SEC-REPLAY-1)② 篡改链一字节 → build 抛
StoreIntegrityError ③ 指纹不匹配 → VaultKeyError ④ 跨段轮转后启动回放通过。
"""
from __future__ import annotations

import json
import os

os.environ.setdefault("CG_NO_BOOT", "1")  # 测试不触发 lifespan 装配(个例除外)

import pytest
from fastapi.testclient import TestClient

from app import main as main_mod
from app.bootstrap import build_chat_service
from app.keys import Vault, VaultKeyError
from app.llm import LLMGateway, MockChat
from app.store import StoreIntegrityError, entry_checksum


def isolate_env(tmp_path, monkeypatch, vault_key: str | None = "c3" * 32):
    """隔离 backend/.env 回退路径 + 固定 VAULT_KEY(或删除模拟缺失)。"""
    monkeypatch.setattr("app.keys._ENV_PATH_DEFAULT", tmp_path / "isolated.env")
    if vault_key is None:
        monkeypatch.delenv("VAULT_KEY", raising=False)
    else:
        monkeypatch.setenv("VAULT_KEY", vault_key)
    monkeypatch.delenv("MIMO_API_KEY", raising=False)


def mock_gateway():
    return LLMGateway(mimo=None, mock=MockChat())


def run_two_turns(svc, sid=None):
    sid = sid or svc.sessions.create_session("回放")["id"]
    r1 = svc.run_turn(sid, "张三的手机号是13800138000")
    r2 = svc.run_turn(sid, "继续")
    return sid, r1, r2


# --------------------------------------------------------------------------- #
# ① SEC-REPLAY-1:build → 2 轮 → 重建 → 会话/链/消息可还原,链验证通过
# --------------------------------------------------------------------------- #
def test_rebuild_restores_sessions_chain_messages(tmp_path, monkeypatch):
    isolate_env(tmp_path, monkeypatch)
    svc1 = build_chat_service(tmp_path, gateway=mock_gateway())
    sid, r1, r2 = run_two_turns(svc1)
    root1 = svc1.chain.root

    svc2 = build_chat_service(tmp_path, gateway=mock_gateway())

    sessions = svc2.sessions.list_sessions()
    assert [s["id"] for s in sessions] == [sid]
    msgs = svc2.sessions.list_messages(sid)
    assert [m["role"] for m in msgs] == ["user", "assistant", "user", "assistant"]
    assert [m["id"] for m in msgs] == \
        [r1["message_id"], r1["assistant_message_id"],
         r2["message_id"], r2["assistant_message_id"]]
    assert msgs[0]["user_view"] == "张三的手机号是13800138000"   # 动态还原
    assert msgs[2]["user_view"] == "继续"
    assert svc2.chain.verify() is True
    assert svc2.chain.root == root1
    assert [e["message_id"] for e in svc2.chain.entries] == \
        [r1["message_id"], r2["message_id"]]
    assert svc2.sessions.get_message(r1["message_id"])["chain_refs"] == [0]


# --------------------------------------------------------------------------- #
# ② 篡改链一字节 → build 抛 StoreIntegrityError
# --------------------------------------------------------------------------- #
def test_chain_tamper_one_byte_raises_on_build(tmp_path, monkeypatch):
    isolate_env(tmp_path, monkeypatch)
    svc = build_chat_service(tmp_path, gateway=mock_gateway())
    run_two_turns(svc)

    seg = sorted((tmp_path / "chain").glob("seg-*.ndjson"))[0]
    raw = seg.read_text(encoding="utf-8")
    tampered = raw.replace('"payload_digest": "',
                           '"payload_digest": "X', 1)   # JSON 仍合法,内容变一字节
    assert tampered != raw
    seg.write_text(tampered, encoding="utf-8")

    with pytest.raises(StoreIntegrityError) as exc:
        build_chat_service(tmp_path, gateway=mock_gateway())
    assert exc.value.kind == "corrupt"      # entry_checksum(损坏检测)先拦


def test_chain_tamper_with_recomputed_checksum_chain_break(tmp_path, monkeypatch):
    """持 mac_key 改内容并重算 entry_checksum 仍被链回放(chain_break)捕获。"""
    isolate_env(tmp_path, monkeypatch)
    svc = build_chat_service(tmp_path, gateway=mock_gateway())
    run_two_turns(svc)
    mac_key = Vault.load_or_init(tmp_path).chain_mac_key

    seg = sorted((tmp_path / "chain").glob("seg-*.ndjson"))[0]
    rows = [json.loads(line) for line in seg.read_text(encoding="utf-8").splitlines()]
    rows[0]["payload_digest"] = rows[0]["payload_digest"] + "X"   # 改内容
    rows[0]["entry_checksum"] = entry_checksum(mac_key, rows[0])  # 重算校验和
    seg.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n",
                   encoding="utf-8")

    with pytest.raises(StoreIntegrityError) as exc:
        build_chat_service(tmp_path, gateway=mock_gateway())
    assert exc.value.kind == "chain_break"


def test_cross_check_message_chain_ref_mismatch(tmp_path, monkeypatch):
    """SEC-REPLAY 双向索引:消息 chain_refs 与链条目 mid 不符 → chain_break。"""
    isolate_env(tmp_path, monkeypatch)
    svc = build_chat_service(tmp_path, gateway=mock_gateway())
    run_two_turns(svc)                       # 链 2 条:索引 0/1
    mac_key = Vault.load_or_init(tmp_path).chain_mac_key

    seg = sorted((tmp_path / "messages").glob("seg-*.ndjson"))[0]
    rows = [json.loads(line) for line in seg.read_text(encoding="utf-8").splitlines()]
    rows[0]["chain_refs"] = [1]              # 越权指向他人链条目(索引在范围内)
    rows[0]["entry_checksum"] = entry_checksum(mac_key, rows[0])
    seg.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n",
                   encoding="utf-8")

    with pytest.raises(StoreIntegrityError) as exc:
        build_chat_service(tmp_path, gateway=mock_gateway())
    assert exc.value.kind == "chain_break"


# --------------------------------------------------------------------------- #
# ③ 信任根失败:指纹不匹配 / key 缺失 → VaultKeyError
# --------------------------------------------------------------------------- #
def test_fingerprint_mismatch_vault_key_error(tmp_path, monkeypatch):
    isolate_env(tmp_path, monkeypatch)
    build_chat_service(tmp_path, gateway=mock_gateway())   # 首次写入指纹

    isolate_env(tmp_path, monkeypatch, vault_key="d4" * 32)  # 换钥 → 指纹不符
    with pytest.raises(VaultKeyError):
        build_chat_service(tmp_path, gateway=mock_gateway())


def test_missing_vault_key_vault_key_error(tmp_path, monkeypatch):
    isolate_env(tmp_path, monkeypatch)
    build_chat_service(tmp_path, gateway=mock_gateway())   # 首次写入指纹

    isolate_env(tmp_path, monkeypatch, vault_key=None)     # key 缺失
    with pytest.raises(VaultKeyError):
        build_chat_service(tmp_path, gateway=mock_gateway())


# --------------------------------------------------------------------------- #
# ④ 跨段轮转后启动回放通过
# --------------------------------------------------------------------------- #
def test_replay_across_rotated_segments(tmp_path, monkeypatch):
    isolate_env(tmp_path, monkeypatch)
    svc = build_chat_service(tmp_path, gateway=mock_gateway(),
                             seg_max_entries=1)            # 每条目轮转一段
    sid, r1, r2 = run_two_turns(svc)
    assert len(list((tmp_path / "chain").glob("seg-*.ndjson"))) >= 2

    svc2 = build_chat_service(tmp_path, gateway=mock_gateway())
    assert svc2.chain.verify() is True
    assert svc2.chain.root == svc.chain.root
    assert len(svc2.sessions.list_messages(sid)) == 4
    assert svc2.sessions.list_messages(sid)[0]["user_view"] == \
        "张三的手机号是13800138000"


# --------------------------------------------------------------------------- #
# MIMO_API_KEY 缺失:mimo=None(mock-only,恒降级 degraded="mock")
# --------------------------------------------------------------------------- #
def test_default_gateway_mock_only_without_api_key(tmp_path, monkeypatch):
    isolate_env(tmp_path, monkeypatch)
    svc = build_chat_service(tmp_path)          # gateway=None → 按环境组装

    assert isinstance(svc._gateway, LLMGateway)
    assert svc._gateway.mimo is None            # mock-only
    sid = svc.sessions.create_session("降级")["id"]
    result = svc.run_turn(sid, "你好")
    assert result["degraded"] == "mock"


# --------------------------------------------------------------------------- #
# lifespan 接线:CG_NO_BOOT 跳过 / 装配成功挂 app.state.chat / 三失败启动终止
# --------------------------------------------------------------------------- #
def test_lifespan_skipped_with_env_flag(tmp_path, monkeypatch):
    monkeypatch.setenv("CG_NO_BOOT", "1")

    def _boom(_path, gateway=None):   # pragma: no cover - 不应被调用
        raise AssertionError("CG_NO_BOOT=1 时不应装配")

    monkeypatch.setattr(main_mod, "build_chat_service", _boom)
    monkeypatch.setattr(main_mod.app.state, "chat", "untouched", raising=False)
    with TestClient(main_mod.app):
        assert main_mod.app.state.chat == "untouched"


def test_lifespan_wires_app_state_chat(tmp_path, monkeypatch):
    sentinel = object()
    monkeypatch.delenv("CG_NO_BOOT", raising=False)
    monkeypatch.setattr(main_mod, "build_chat_service",
                        lambda _path, gateway=None: sentinel)
    with TestClient(main_mod.app):
        assert main_mod.app.state.chat is sentinel


def test_lifespan_aborts_on_vault_key_error(tmp_path, monkeypatch):
    def _fail(_path, gateway=None):
        raise VaultKeyError("指纹不符")

    monkeypatch.delenv("CG_NO_BOOT", raising=False)
    monkeypatch.setattr(main_mod, "build_chat_service", _fail)
    with pytest.raises(VaultKeyError):
        with TestClient(main_mod.app):
            pass                       # pragma: no cover - 启动即应抛出


def test_lifespan_aborts_on_store_integrity_error(tmp_path, monkeypatch):
    def _fail(_path, gateway=None):
        raise StoreIntegrityError("chain_break", "链断")

    monkeypatch.delenv("CG_NO_BOOT", raising=False)
    monkeypatch.setattr(main_mod, "build_chat_service", _fail)
    with pytest.raises(StoreIntegrityError):
        with TestClient(main_mod.app):
            pass                       # pragma: no cover - 启动即应抛出
