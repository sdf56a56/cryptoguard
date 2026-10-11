"""Task 11:proxy.py 流水线重写(query_v2)+ USER_OVERRIDE 绑定 + run_in_executor。"""
from app.proxy import CryptoGuard


def test_query_v2_end_to_end():
    g = CryptoGuard()
    r = g.query_v2("张三 13800138000 查询余额")
    assert r["status"] == "verified"
    assert "张三" not in r["outbound"]["redacted_text"]
    assert r["outbound"]["schema_version"] == "CG/2.0"
    assert "mock_sleep_ms" in r


def test_override_bound_into_input_hash():
    g = CryptoGuard()
    ev = {"event_id": "e1", "entity_span": [0, 2], "entity_type": "NAME",
          "original_token": "x", "action": "force_allow", "replacement": None,
          "user_ack": True, "ts": "2026-10-11T00:00:00.000000Z"}
    r1 = g.query_v2("张三就诊", overrides=[ev])
    r2 = g.query_v2("张三就诊", overrides=[])
    assert r1["input_hash"] != r2["input_hash"]


def test_reject_smuggled_directive():
    g = CryptoGuard()
    bad = {"op": "sum", "tokens": ["[FAKE#deadbeef]"], "result_ref": "c_01"}
    r = g.query_v2("余额统计", directive=bad)
    assert r["gateway_rejected"] and any(e["entry_type"] == "COMPUTE_GATE" for e in g.chain.entries)


def test_canonical_preimage_and_exec_sync():
    """R8:结果含 canonical_preimage;R7:exec_sync 线程池执行。"""
    g = CryptoGuard()
    r = g.query_v2("张三就诊")
    assert r["canonical_preimage"].startswith("{") and "CG/INPUT/v2" in r["canonical_preimage"]
    assert g.exec_sync(lambda x: x * 2, 21) == 42
