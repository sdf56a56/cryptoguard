"""Prometheus 文本指标 —— 无第三方依赖的最小实现

指标只用于运维观测，**不按 client_id 打标签**（基数风险），也不含任何明文、
密钥或上游响应正文。任何一次导出都只读内存计数器，不触发上游调用。
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict

_PREFIX = "cryptoguard_"
_DEFAULT_BUCKETS = (0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0)


def _escape(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _labels_text(labels: dict | None, extra: dict | None = None) -> str:
    merged = {**(labels or {}), **(extra or {})}
    if not merged:
        return ""
    body = ",".join(f'{key}="{_escape(value)}"' for key, value in sorted(merged.items()))
    return "{" + body + "}"


class Metrics:
    """线程安全的计数器 / 直方图 / 瞬时值容器。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[tuple[str, tuple], float] = defaultdict(float)
        self._gauges: dict[tuple[str, tuple], float] = {}
        self._hist: dict[tuple[str, tuple], list[float]] = {}
        self._hist_counts: dict[tuple[str, tuple], int] = defaultdict(int)
        self._hist_sums: dict[tuple[str, tuple], float] = defaultdict(float)
        self._created = time.time()

    # ------------------------------------------------------------------ #
    def inc(self, name: str, labels: dict | None = None, value: float = 1.0) -> None:
        key = (name, tuple(sorted((labels or {}).items())))
        with self._lock:
            self._counters[key] += value

    def set(self, name: str, value: float, labels: dict | None = None) -> None:
        key = (name, tuple(sorted((labels or {}).items())))
        with self._lock:
            self._gauges[key] = value

    def observe(self, name: str, value: float, labels: dict | None = None,
                buckets: tuple[float, ...] = _DEFAULT_BUCKETS) -> None:
        key = (name, tuple(sorted((labels or {}).items())))
        with self._lock:
            series = self._hist.setdefault(key, [0.0] * (len(buckets) + 1))
            for index, boundary in enumerate(buckets):
                if value <= boundary:
                    series[index] += 1
                    break
            else:
                series[-1] += 1
            self._hist_counts[key] += 1
            self._hist_sums[key] += value

    # ------------------------------------------------------------------ #
    def render(self) -> str:
        """Prometheus text exposition（稳定排序，便于 diff 与测试）。"""
        with self._lock:
            counters = dict(self._counters)
            gauges = dict(self._gauges)
            hist = {key: (list(series), self._hist_counts[key], self._hist_sums[key])
                    for key, series in self._hist.items()}

        lines: list[str] = []
        by_name: dict[str, list[tuple[tuple, float]]] = defaultdict(list)
        for (name, labels), value in counters.items():
            by_name[name].append((labels, value))
        for name in sorted(by_name):
            lines.append(f"# TYPE {_PREFIX}{name} counter")
            for labels, value in sorted(by_name[name]):
                label_text = _labels_text(dict(labels))
                lines.append(f"{_PREFIX}{name}{label_text} {value:g}")

        for name in sorted({key[0] for key in gauges}):
            lines.append(f"# TYPE {_PREFIX}{name} gauge")
            for (metric, labels), value in sorted(gauges.items()):
                if metric != name:
                    continue
                label_text = _labels_text(dict(labels))
                lines.append(f"{_PREFIX}{name}{label_text} {value:g}")

        for (name, labels) in sorted(hist):
            series, count, total = hist[(name, labels)]
            label_dict = dict(labels)
            lines.append(f"# TYPE {_PREFIX}{name} histogram")
            cumulative = 0.0
            for index, boundary in enumerate(_DEFAULT_BUCKETS):
                cumulative += series[index]
                label_text = _labels_text(label_dict, {"le": f"{boundary:g}"})
                lines.append(f"{_PREFIX}{name}_bucket{label_text} {cumulative:g}")
            cumulative += series[-1]
            label_text = _labels_text(label_dict, {"le": "+Inf"})
            lines.append(f"{_PREFIX}{name}_bucket{label_text} {cumulative:g}")
            label_text = _labels_text(label_dict)
            lines.append(f"{_PREFIX}{name}_count{label_text} {count:g}")
            lines.append(f"{_PREFIX}{name}_sum{label_text} {total:g}")

        lines.append(f"# TYPE {_PREFIX}build_info gauge")
        lines.append(f'{_PREFIX}build_info{{service="cryptoguard-gateway"}} 1')
        return "\n".join(lines) + "\n"


def normalize_path(path: str) -> str:
    """把动态路径段折叠成 `{id}`，避免 Prometheus 标签基数爆炸。

    只对已知网关前缀做折叠；未知路径保留原样（最多一条，不递归）。
    """
    known = {
        "/v1/chat/completions", "/v1/messages", "/v1/responses",
        "/v1/models", "/v1/verify", "/v1/confirmations",
        "/v1/messages/count_tokens",
        "/admin/security/policies", "/admin/clients", "/admin/audit",
        "/admin/audit/verify", "/admin/audit/purge",
        "/admin/confirmations", "/admin/providers", "/metrics", "/ready",
        "/health",
    }
    if path in known:
        return path
    parts = [part for part in path.split("/") if part]
    if not parts:
        return "/"
    out: list[str] = []
    for index, part in enumerate(parts):
        # 末段或倒数第二段是标识符：UUID/hex/cgc-/cg- 前缀或纯数字
        looks_like_id = (
            len(part) >= 8 and all(ch in "0123456789abcdefABCDEF-" for ch in part)
        ) or part.isdigit() or part.startswith(("cg-", "cgc-"))
        out.append("{id}" if looks_like_id else part)
    return "/" + "/".join(out)


_TRACKED_PREFIXES = ("/v1/", "/admin/", "/metrics", "/ready", "/health")


class MetricsMiddleware:
    """纯 ASGI 指标包装：请求数/状态码/耗时；不读取请求体、不影响语义。"""

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not str(scope.get("path", "")).startswith(
                _TRACKED_PREFIXES):
            await self.app(scope, receive, send)
            return

        state = getattr(scope.get("app"), "state", None)
        middleware = getattr(state, "middleware", None)
        metrics = getattr(middleware, "metrics", None)
        if metrics is None:
            await self.app(scope, receive, send)
            return

        path = normalize_path(str(scope.get("path", "")))
        method = str(scope.get("method", "GET")).upper()
        status = {"code": 500}
        started = time.monotonic()

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                status["code"] = int(message.get("status", 500))
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            elapsed = time.monotonic() - started
            metrics.inc("requests_total", {"path": path, "method": method,
                                           "status": str(status["code"])})
            metrics.observe("request_duration_seconds", elapsed, {"path": path})
