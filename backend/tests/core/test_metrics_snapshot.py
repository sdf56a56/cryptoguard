"""看板指标快照与直方图分位数（纯内存，不触网）。"""
from __future__ import annotations

from app.middleware.metrics import (Metrics, aggregate_histograms,
                                    histogram_quantile)


def test_snapshot_exposes_counters_and_histograms():
    metrics = Metrics()
    metrics.inc("requests_total", {"status": "200", "path": "/v1/chat/completions"})
    metrics.inc("requests_total", {"status": "500", "path": "/v1/chat/completions"}, 2)
    metrics.observe("request_duration_seconds", 0.1, {"path": "/v1/chat/completions"})
    metrics.observe("request_duration_seconds", 2.0, {"path": "/v1/chat/completions"})

    snapshot = metrics.snapshot()
    assert snapshot["uptime_s"] >= 0
    assert snapshot["created_epoch"] > 0
    assert len(snapshot["counters"]) == 2
    assert len(snapshot["histograms"]) == 1
    histogram = snapshot["histograms"][0]
    assert histogram["count"] == 2
    assert len(histogram["bounds"]) + 1 == len(histogram["counts"])


def test_aggregate_histogram_and_quantile():
    metrics = Metrics()
    metrics.observe("request_duration_seconds", 0.1, {"path": "/a"})
    metrics.observe("request_duration_seconds", 2.0, {"path": "/b"})
    merged = aggregate_histograms(metrics.snapshot()["histograms"],
                                  "request_duration_seconds")
    assert merged["count"] == 2
    p50 = histogram_quantile(merged["bounds"], merged["counts"], 0.50)
    p95 = histogram_quantile(merged["bounds"], merged["counts"], 0.95)
    assert 0 <= p50 <= p95
    assert p95 <= 2.5
    assert aggregate_histograms([], "missing") is None
    assert histogram_quantile([0.1, 1.0], [0, 0, 0], 0.95) == 0.0
