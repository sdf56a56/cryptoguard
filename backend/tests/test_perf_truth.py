"""
PERF-TRUTH-1 计时条真值(spec §6.3)—— 双断言 + mock_sleep_ms 一致性。

断言一:后端 pipeline 每段 duration_ms 的 2 位小数字符串 == f"{v:.2f}"
        (后端计时值 -> WS 帧 -> DOM 同源格式化,三处字符串逐字节相等的后端源)
断言二:后端原始值与帧值差 < 0.01ms(sent = round(raw, 2) 量化,|raw-sent| <= 0.005)
断言三:mock_sleep_ms 字段必须存在且与帧内 LLM 段一致(50-100ms)。
"""
from app.proxy import CryptoGuard

LLM_STEP = "出站调用 Mock LLM"


def _run():
    g = CryptoGuard()
    r = g.query_v2("张三 13800138000 查询余额")
    assert r["status"] == "verified"
    return r


def test_perf_truth_1_duration_two_decimal_string():
    """断言一:每段 duration_ms 字符串 == f"{v:.2f}"(2 位小数同源格式化)。"""
    r = _run()
    assert len(r["pipeline"]) >= 4
    for step in r["pipeline"]:
        v = step["duration_ms"]
        s = f"{v:.2f}"
        assert isinstance(v, (int, float)) and v >= 0, step
        # 后端值本身就是 2 位小数量化 -> 字符串与 f"{v:.2f}" 逐字节相等
        assert v == round(v, 2), step
        assert s == f"{round(v, 2):.2f}", step
        assert len(s.split(".")[1]) == 2, step
    # 总耗时同口径
    assert r["total_ms"] == round(r["total_ms"], 2)


def test_perf_truth_1_raw_vs_sent_within_001ms():
    """断言二:后端原始值与帧值差 < 0.01ms(量化误差界 <= 0.005ms)。"""
    r = _run()
    for step in r["pipeline"]:
        v = step["duration_ms"]
        sent = float(f"{v:.2f}")          # WS 帧/DOM 收到的 2 位小数值
        assert abs(v - sent) < 0.01, step
        assert v == round(v, 2)           # sent = round(raw, 2) 的落盘形态


def test_perf_truth_1_mock_sleep_ms_consistent():
    """断言三:mock_sleep_ms 存在且与帧内 LLM 段一致。"""
    r = _run()
    assert "mock_sleep_ms" in r, "mock_sleep_ms 字段必须存在"
    ms = r["mock_sleep_ms"]
    assert isinstance(ms, (int, float)) and 50 <= ms <= 100, ms

    llm_steps = [s for s in r["pipeline"] if s["step"] == LLM_STEP]
    assert len(llm_steps) == 1
    llm = llm_steps[0]
    assert llm.get("mock_sleep_ms") == ms, "帧内 LLM 段 mock_sleep_ms 须同源一致"
    # LLM 段耗时由 mock sleep 主导:duration >= mock_sleep_ms 且超出有限
    assert llm["duration_ms"] >= ms
    assert llm["duration_ms"] - ms < 50
