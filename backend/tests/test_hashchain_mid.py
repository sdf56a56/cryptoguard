"""Task 2:哈希链条目 message_id 双向索引(可选 "mid" 前映像)。

验收标准:① 无 mid 条目哈希与旧 5 键公式逐字节一致(旧测试不改亦须全绿)
② 带 mid 条目 verify()=True 且 entry 往返 message_id
③ 篡改/剥离/强加 mid → verify()=False ④ 全量回归全绿。
"""
from __future__ import annotations

from app.canon import h_hex
from app.crypto.hashchain import D_LOG, HashChain


def _old_preimage(entry_type: str, payload_digest: str, ts: str, prev: str) -> dict:
    """旧 5 键前映像(不含 "mid"),用于逐字节比对。"""
    return {"d": D_LOG, "ty": entry_type, "p": payload_digest, "ts": ts, "prev": prev}


def test_no_mid_hash_matches_old_formula():
    """① 无 message_id 条目:哈希 = 旧 5 键前映像,entry 保持旧形状。"""
    c = HashChain()
    e0 = c.append("QUERY", "abc", "2026-10-12T00:00:00Z")
    assert e0["hash"] == h_hex(_old_preimage("QUERY", "abc", "2026-10-12T00:00:00Z", "0" * 64))
    assert "message_id" not in e0
    assert set(e0) == {"index", "entry_type", "payload_digest", "timestamp", "prev_hash", "hash"}
    # 链式 prev 绑定同样逐字节一致
    e1 = c.append("USER_OVERRIDE", "def", "2026-10-12T00:00:01Z")
    assert e1["hash"] == h_hex(_old_preimage("USER_OVERRIDE", "def", "2026-10-12T00:00:01Z", e0["hash"]))
    assert c.verify() is True


def test_mid_roundtrip_and_verify():
    """② 带 message_id 条目:entry 往返 id,哈希 = 加 "mid" 的前映像,verify()=True。"""
    c = HashChain()
    e = c.append("QUERY", "abc", "2026-10-12T00:00:00Z", message_id="m-1")
    assert e["message_id"] == "m-1"
    assert e["hash"] == h_hex({
        "d": D_LOG, "ty": "QUERY", "p": "abc",
        "ts": "2026-10-12T00:00:00Z", "prev": "0" * 64, "mid": "m-1",
    })
    # mid 真正绑定进哈希:与无 mid 前映像哈希不同
    assert e["hash"] != h_hex(_old_preimage("QUERY", "abc", "2026-10-12T00:00:00Z", "0" * 64))
    assert c.verify() is True


def test_mixed_chain_verify_per_entry():
    """verify() 按条目有无 message_id 分别选用前映像:混合链全绿。"""
    c = HashChain()
    c.append("QUERY", "d0", "ts0")
    c.append("QUERY", "d1", "ts1", message_id="m-1")
    c.append("USER_OVERRIDE", "d2", "ts2")
    c.append("QUERY", "d3", "ts3", message_id="m-3")
    assert c.verify() is True


def test_tamper_mid_breaks_chain():
    """③ 篡改存储的 message_id → verify()=False。"""
    c = HashChain()
    c.append("QUERY", "d0", "ts0", message_id="m-0")
    e = c.append("QUERY", "d1", "ts1", message_id="m-1")
    e["message_id"] = "m-1-tampered"
    assert c.verify() is False


def test_strip_mid_breaks_chain():
    """剥离 message_id(6 键前映像条目被降格为 5 键)→ verify()=False。"""
    c = HashChain()
    c.append("QUERY", "d0", "ts0", message_id="m-0")
    del c.entries[0]["message_id"]
    assert c.verify() is False


def test_forge_mid_on_old_entry_breaks_chain():
    """给旧 5 键条目强加 message_id → verify()=False(双向绑定)。"""
    c = HashChain()
    c.append("QUERY", "d0", "ts0")
    c.entries[0]["message_id"] = "forged"
    assert c.verify() is False
