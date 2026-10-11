"""层 1 时间窗单测(spec §3.3):|now − timestamp| ≤ 300s,过期即拒。

纯函数 within_freshness_window 直测(假时钟注入,monkeypatch-free);
query_v2 的层 1 验证在路径上调用同一函数(见 proxy._verify_v2)。
"""
from datetime import datetime, timedelta, timezone

from app.proxy import CryptoGuard, within_freshness_window

TS_FMT = "%Y-%m-%dT%H:%M:%S.%fZ"
NOW = datetime(2026, 10, 11, 12, 0, 0, tzinfo=timezone.utc)


def _ts(delta_s: float) -> str:
    return (NOW + timedelta(seconds=delta_s)).strftime(TS_FMT)


def test_fresh_timestamp_within_window():
    # 刚签发 + 2 分钟前签发 → 窗内
    assert within_freshness_window(_ts(0), now=NOW) is True
    assert within_freshness_window(_ts(-120), now=NOW) is True


def test_stale_timestamp_rejected():
    # 5 分钟 + 1s 之前 → 超窗即拒
    assert within_freshness_window(_ts(-301), now=NOW) is False


def test_boundary_300s_ok_301s_rejected():
    # 边界 300s 整(含未来向,abs 口径)→ True;301s → False
    assert within_freshness_window(_ts(-300), now=NOW) is True
    assert within_freshness_window(_ts(300), now=NOW) is True
    assert within_freshness_window(_ts(-301), now=NOW) is False
    assert within_freshness_window(_ts(301), now=NOW) is False


def test_invalid_timestamp_fail_closed():
    # 解析失败 → False(fail-closed)
    assert within_freshness_window("not-a-timestamp", now=NOW) is False
    assert within_freshness_window("", now=NOW) is False


def test_in_path_layer1_combines_echo_and_window():
    # 在路径接线:真实 query_v2 的「输入绑定/防重放」条目 = 回显 AND 时间窗,
    # 通过时 detail 含「时间窗」
    g = CryptoGuard()
    r = g.query_v2("张三 13800138000 查询余额")
    layer1 = next(v for v in r["verification"] if v["layer"] == "输入绑定/防重放")
    assert layer1["ok"] is True
    assert "时间窗" in layer1["detail"]
