"""PERF-FF1-1:FF1 实测校准。>2ms/个 必须降级可观测,不许静默。"""
from app.tokens import T2Cipher, ff1_unit_ms_p95, FF1_DEGRADED

def test_ff1_p95_budget_or_visible_degradation():
    c = T2Cipher(key=bytes(range(32)))
    c.encrypt_id17("11010519491231002")          # 预热
    p95 = ff1_unit_ms_p95(c, n=1000)
    assert p95 <= 2.0 or FF1_DEGRADED, (
        f"FF1 P95={p95:.2f}ms/个 超 2ms 预算,必须置 FF1_DEGRADED=True 并触发降级横幅"
    )
