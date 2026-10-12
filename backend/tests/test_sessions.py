"""
Task 7:sessions.py —— 会话 + 双视角映射(session_mapping_ct / mapping_delta_ct)。

验收标准:① 加密往返还原一致 ② 多轮共指:轮 2 引用轮 1 实体可还原(Review Focus 1)
③ 跨会话 restore 被拒 ④ 序列化记录无 user_view 键、明文值不出现在落盘字符串
(SEC-STORE-1 主断言) ⑤ 重启后(重建 SessionStore)可继续 add_message 且 T1 共指稳定。
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from app.crypto.aead import AeadCipher
from app.keys import Vault
from app.sessions import SessionStore
from app.store import SealedNDJSON
from app.tokens import T2Cipher, t1_pseudonym


def make_vault() -> Vault:
    """固定密钥测试 Vault(ctor 直注入,免 .env)。"""
    return Vault(
        mapping_key=bytes(range(32)),
        reasoning_key=bytes(range(32, 64)),
        chain_mac_key=bytes(range(64, 96)),
        demo_chain_mac_key=bytes(range(96, 128)),
        fingerprint="test-fp",
    )


def make_logs(tmp_path: Path, vault: Vault) -> tuple[SealedNDJSON, SealedNDJSON]:
    """data/sessions、data/messages 两实例,段名 seg,mac_key=chain_mac_key(接线约定)。"""
    sessions_log = SealedNDJSON(tmp_path / "sessions", "seg", vault.chain_mac_key)
    messages_log = SealedNDJSON(tmp_path / "messages", "seg", vault.chain_mac_key)
    return sessions_log, messages_log


def make_store(tmp_path: Path, vault: Vault | None = None) -> SessionStore:
    vault = make_vault() if vault is None else vault
    sessions_log, messages_log = make_logs(tmp_path, vault)
    return SessionStore(vault, sessions_log, messages_log)


# --------------------------------------------------------------------------- #
# 会话记录形态 + 密钥封缄
# --------------------------------------------------------------------------- #
def test_create_session_record_shape(tmp_path):
    """create_session → uuid4().hex 会话记录;secrets/mapping 均封缄(iv+ciphertext)。"""
    store = make_store(tmp_path)
    rec = store.create_session("测试会话")
    assert rec["type"] == "session"
    assert re.fullmatch(r"[0-9a-f]{32}", rec["id"])  # uuid4().hex
    assert rec["title"] == "测试会话"
    assert rec["rev"] == 0
    assert set(rec) == {
        "type", "id", "title", "created", "rev",
        "session_secrets_ct", "session_mapping_ct", "entry_checksum",
    }
    for blob in (rec["session_secrets_ct"], rec["session_mapping_ct"]):
        assert set(blob) == {"iv", "ciphertext"}
    # 空映射:无替换形态可还,文本原样
    assert store.restore_view(rec["id"], "你好[NAME#abc123defg]") == "你好[NAME#abc123defg]"


def test_open_tokenizer_rebuilds_secrets(tmp_path):
    """session_secrets_ct 解封重建 Tokenizers:k_t1(32B)/session_salt(16B)/t2(32B)。"""
    store = make_store(tmp_path)
    sid = store.create_session("tok")["id"]
    tok = store.open_tokenizer(sid)
    assert isinstance(tok.k_t1, bytes) and len(tok.k_t1) == 32
    assert isinstance(tok.session_salt, bytes) and len(tok.session_salt) == 16
    assert isinstance(tok.t2, T2Cipher) and len(tok.t2.key_bytes) == 32
    with pytest.raises(ValueError):
        store.open_tokenizer("9" * 32)  # 未知会话


# --------------------------------------------------------------------------- #
# ① 加密往返 ② 多轮共指
# --------------------------------------------------------------------------- #
def test_seal_restore_roundtrip_exact(tmp_path):
    """① llm_view(替换形态)经封缄映射还原 == 原明文,逐字一致。"""
    store = make_store(tmp_path)
    sid = store.create_session("rt")["id"]
    mapping = {"[NAME#m3xk2p9wq1]": "张三丰", "[CARD#7h4nq8v2zk]": "6222-0212-3456-7890"}
    original = "付款给6222-0212-3456-7890,联系人张三丰"
    llm_view = "付款给[CARD#7h4nq8v2zk],联系人[NAME#m3xk2p9wq1]"
    store.add_message(sid, "user", llm_view, mapping_delta=mapping)
    assert store.restore_view(sid, llm_view) == original


def test_multi_turn_coreference_restores_fully(tmp_path):
    """② 轮 2 文本引用轮 1 实体可完整还原(session_mapping_ct 累积,latest rev 生效)。"""
    vault = make_vault()
    sessions_log, messages_log = make_logs(tmp_path, vault)
    store = SessionStore(vault, sessions_log, messages_log)
    sid = store.create_session("共指")["id"]
    m1 = store.add_message(sid, "user", "你好[NAME#aaaaaaaaaaaa]",
                           {"[NAME#aaaaaaaaaaaa]": "张三丰"})
    m2 = store.add_message(sid, "user", "[NAME#aaaaaaaaaaaa]的卡号是[CARD#bbbbbbbbbbbb]",
                           {"[CARD#bbbbbbbbbbbb]": "6222-0212-3456-7890"})
    # 轮 2 同时还原轮 1 实体与本轮新实体
    assert store.restore_view(sid, m2["llm_view"]) == "张三丰的卡号是6222-0212-3456-7890"
    assert store.restore_view(sid, m1["llm_view"]) == "你好张三丰"
    # 每轮增量合并后重封缄:会话日志追加新版本行(rev 递增),latest rev 赢
    revs = [r["rev"] for r in sessions_log.read_all() if r["type"] == "session"]
    assert revs == [0, 1, 2]
    # 重启(重建 SessionStore)后累积映射仍生效
    store2 = make_store(tmp_path, vault)
    assert store2.restore_view(sid, m2["llm_view"]) == "张三丰的卡号是6222-0212-3456-7890"


# --------------------------------------------------------------------------- #
# ③ 跨会话 restore 被拒
# --------------------------------------------------------------------------- #
def test_cross_session_restore_rejected(tmp_path):
    """③ 跨会话/跨作用域 restore 抛 ValueError;同会话正常还原。"""
    store = make_store(tmp_path)
    a = store.create_session("A")["id"]
    b = store.create_session("B")["id"]
    ma = store.add_message(a, "user", "你好[NAME#aaaaaaaaaaaa]",
                           {"[NAME#aaaaaaaaaaaa]": "张三丰"})
    rec_a = store.get_message(ma["id"])
    # 消息记录(session_id=A)交给会话 B 还原 → 作用域不匹配 → 拒绝
    with pytest.raises(ValueError):
        store.restore_view(b, rec_a)
    with pytest.raises(ValueError):
        store.restore_view(b, {"session_id": a, "llm_view": ma["llm_view"]})
    # 未知会话同样拒绝
    with pytest.raises(ValueError):
        store.restore_view("0" * 32, "文本")
    # 同会话通过:消息 user_view 用其 OWN 会话映射还原
    assert store.restore_view(a, rec_a) == "你好张三丰"


# --------------------------------------------------------------------------- #
# ④ SEC-STORE-1:user_view 不落盘、映射明文不出现在落盘字符串
# --------------------------------------------------------------------------- #
def test_serialized_records_hide_user_view_and_plaintext(tmp_path):
    """④ 落盘原始行无 user_view 键、无映射明文值、无 reasoning 明文;user_view 仅内存动态还原。"""
    store = make_store(tmp_path)
    sid = store.create_session("泄漏扫描")["id"]
    mapping = {
        "[NAME#m3xk2p9wq1]": "张三丰",
        "[ADDR#5r8kd0m3pn]": "北京市海淀区中关村大街1号",
    }
    m1 = store.add_message(sid, "user", "[NAME#m3xk2p9wq1]住在[ADDR#5r8kd0m3pn]",
                           mapping_delta=mapping,
                           reasoning_ct={"reasoning_content": "本地推演-机密细节"})
    m2 = store.add_message(sid, "assistant", "已记录[NAME#m3xk2p9wq1]的地址")
    # 落盘原始字符串(SEC-STORE-1 主断言)
    raw = ""
    for d in (tmp_path / "sessions", tmp_path / "messages"):
        for p in sorted(d.glob("*.ndjson")):
            raw += p.read_text(encoding="utf-8")
    assert '"user_view"' not in raw
    for secret in ("张三丰", "北京市海淀区中关村大街1号", "本地推演-机密细节"):
        assert secret not in raw
    # read_all 序列化同样干净(递归无 user_view 键、无明文)
    dumped = json.dumps(
        [r for r in store.messages_log.read_all()] + [r for r in store.sessions_log.read_all()],
        ensure_ascii=False,
    )
    assert '"user_view"' not in dumped
    for secret in ("张三丰", "北京市海淀区中关村大街1号", "本地推演-机密细节"):
        assert secret not in dumped
    # user_view 只在内存响应体中动态还原存在
    rec = store.get_message(m1["id"])
    assert rec["user_view"] == "张三丰住在北京市海淀区中关村大街1号"
    assert store.get_message(m2["id"])["user_view"] == "已记录张三丰的地址"


def test_reasoning_ct_sealed_not_plaintext(tmp_path):
    """reasoning 以 reasoning_ct 封缄落盘(或 null),解封还原 dict;明文不出盘。"""
    store = make_store(tmp_path)
    sid = store.create_session("r")["id"]
    rec = store.add_message(sid, "assistant", "好的[NAME#m3xk2p9wq1]",
                            reasoning_ct={"reasoning_content": "本地推演-机密细节"})
    blob = rec["reasoning_ct"]
    assert isinstance(blob, dict) and set(blob) == {"iv", "ciphertext"}
    assert store.decrypt_reasoning(blob) == {"reasoning_content": "本地推演-机密细节"}
    assert store.decrypt_reasoning(None) is None
    user_rec = store.add_message(sid, "user", "你好")
    assert user_rec["reasoning_ct"] is None  # 用户消息无 reasoning


# --------------------------------------------------------------------------- #
# ⑤ 重启重建 → 继续 add_message、T1 共指稳定
# --------------------------------------------------------------------------- #
def test_restart_continues_with_stable_t1_coreference(tmp_path):
    """⑤ 重建 SessionStore 后:同 tokenizer(T1 共指稳定)、可继续 add_message、全量还原。"""
    vault = make_vault()
    sessions_log, messages_log = make_logs(tmp_path, vault)
    store = SessionStore(vault, sessions_log, messages_log)
    sid = store.create_session("重启")["id"]
    tok1 = store.open_tokenizer(sid)
    tok_str = t1_pseudonym(tok1.k_t1, "NAME", "张三丰", tok1.session_salt)
    form = f"[NAME#{tok_str[:10]}]"  # tokenize_entities 的 T1 文内替换形态
    store.add_message(sid, "user", f"{form}来了", {form: "张三丰"})
    # 重启:同目录重建 SessionStore
    store2 = make_store(tmp_path, vault)
    tok2 = store2.open_tokenizer(sid)
    assert t1_pseudonym(tok2.k_t1, "NAME", "张三丰", tok2.session_salt) == tok_str
    assert tok2.k_t1 == tok1.k_t1 and tok2.session_salt == tok1.session_salt
    # 同一实体在轮 2 得到同一替换形态(T1 共指),继续 add_message 后全量还原
    store2.add_message(sid, "user", f"{form}的电话是[PHONE#cccccccccccc]",
                       {"[PHONE#cccccccccccc]": "138-0013-8000"})
    msgs = store2.list_messages(sid)
    assert [m["role"] for m in msgs] == ["user", "user"]
    assert msgs[0]["user_view"] == "张三丰来了"
    assert msgs[1]["user_view"] == "张三丰的电话是138-0013-8000"


# --------------------------------------------------------------------------- #
# 消息记录形态 / 校验 / 列表作用域
# --------------------------------------------------------------------------- #
def test_message_record_shape_and_defaults(tmp_path):
    """消息记录字段齐全:id=msg_+hex12;缺省参数落安全缺省值;mapping_delta_ct 封缄。"""
    vault = make_vault()
    store = make_store(tmp_path, vault)
    sid = store.create_session("d")["id"]
    rec = store.add_message(sid, "user", "你好")
    assert re.fullmatch(r"msg_[0-9a-f]{12}", rec["id"])
    assert set(rec) == {
        "type", "id", "session_id", "role", "ts", "llm_view", "mapping_delta_ct",
        "reasoning_ct", "files", "chain_refs", "reply_meta", "verification",
        "artifacts", "entry_checksum",
    }
    assert rec["type"] == "message" and rec["session_id"] == sid and rec["role"] == "user"
    assert rec["files"] == [] and rec["chain_refs"] == [] and rec["artifacts"] == {}
    assert rec["verification"] == []
    assert rec["reply_meta"] == {"model": None, "incomplete": False, "degraded": None}
    assert rec["reasoning_ct"] is None
    assert set(rec["mapping_delta_ct"]) == {"iv", "ciphertext"}
    # 空增量解封为 {}
    assert AeadCipher(vault.mapping_key).decrypt(
        rec["mapping_delta_ct"]["iv"], rec["mapping_delta_ct"]["ciphertext"]) == {}
    # 显式字段透传
    rec2 = store.add_message(
        sid, "assistant", "ok", mapping_delta={"[A#1]": "v"},
        reasoning_ct={"reasoning_content": "x"}, files=[{"name": "a.txt"}],
        chain_refs=[3, 4], reply_meta={"model": "mimo-v2.6-flash", "incomplete": True,
                                       "degraded": "mock"},
        verification=[{"ok": True}], artifacts={"p": "q"},
    )
    assert rec2["files"] == [{"name": "a.txt"}] and rec2["chain_refs"] == [3, 4]
    assert rec2["reply_meta"]["incomplete"] is True and rec2["reply_meta"]["degraded"] == "mock"
    assert rec2["verification"] == [{"ok": True}] and rec2["artifacts"] == {"p": "q"}


def test_add_message_validation(tmp_path):
    """role 必须 user|assistant;未知会话拒绝。"""
    store = make_store(tmp_path)
    sid = store.create_session("v")["id"]
    with pytest.raises(ValueError):
        store.add_message(sid, "system", "x")
    with pytest.raises(ValueError):
        store.add_message("f" * 32, "user", "x")


def test_list_messages_scoped_with_dynamic_user_view(tmp_path):
    """list_messages 只回本会话消息,每条带动态 user_view;未知 id/会话 ValueError。"""
    store = make_store(tmp_path)
    a = store.create_session("A")["id"]
    b = store.create_session("B")["id"]
    ma = store.add_message(a, "user", "你好[NAME#aaaaaaaaaaaa]",
                           {"[NAME#aaaaaaaaaaaa]": "张三丰"})
    mb = store.add_message(b, "user", "你好[NAME#bbbbbbbbbbbb]",
                           {"[NAME#bbbbbbbbbbbb]": "李四"})
    la = store.list_messages(a)
    assert [m["id"] for m in la] == [ma["id"]]
    assert la[0]["user_view"] == "你好张三丰"
    lb = store.list_messages(b)
    assert [m["id"] for m in lb] == [mb["id"]]
    assert lb[0]["user_view"] == "你好李四"
    # get_message 用消息 OWN 会话映射还原
    assert store.get_message(ma["id"])["user_view"] == "你好张三丰"
    with pytest.raises(ValueError):
        store.get_message("msg_000000000000")
    with pytest.raises(ValueError):
        store.list_messages("9" * 32)
