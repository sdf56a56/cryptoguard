"""Task 12:哈希链 entry_type 枚举 + Merkle 打包触发器(SEC-PACK-1/2)。"""
from app.crypto.hashchain import HashChain


def test_entry_type_recorded():
    c = HashChain()
    e = c.append("QUERY", "abc", "2026-10-11T00:00:00Z")
    assert e["entry_type"] == "QUERY"


def test_pack_every_10():
    c = HashChain()
    for i in range(10):
        c.append("QUERY", f"d{i}", "ts")
    assert len(c.packs) == 1 and c.packs[0]["range"] == [0, 9]


def test_pack_force_immediate():                 # SEC-PACK-1 修正:立即打包按钮
    c = HashChain()
    c.append("QUERY", "d0", "ts")
    p = c.maybe_pack(0.0, force=True)
    assert p is not None and len(p["merkle_root"]) == 64


def test_pack_timer_5min():
    import time as _t
    c = HashChain()
    c.append("QUERY", "d0", "ts")
    assert c.maybe_pack(0.0) is None
    assert c.maybe_pack(301.0) is not None        # 5 分钟到期


def test_tamper_breaks_chain():
    c = HashChain()
    for i in range(3):
        c.append("QUERY", f"d{i}", "ts")
    c.entries[1]["payload_digest"] = "tampered"
    assert c.verify() is False
