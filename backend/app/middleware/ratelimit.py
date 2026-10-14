"""
限流与并发控制 —— 客户端级滑动窗口 + 全局并发闸

安全目标:
  - 未认证/失效凭证在到达上游之前即被拒(鉴权先于限流,限流先于上游调用),
    防止未授权主体消耗上游费用;
  - 滑动窗口按客户端计,窗口内超限返回 429 并给出 Retry-After;
  - 并发闸限制同时在途的上游调用数,避免单实例被少量客户端打满连接池;
  - 计数内存占用有界:惰性清理 + 客户端数上限保护。

明确不承诺:
  - 单进程内存计数:多 worker/多副本部署时限额按副本计(需外部存储才能全局一致),
    文档中明确说明;
  - 不承诺分布式精确限流(令牌桶在进程内)。
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict

from .errors import MiddlewareError

_MAX_TRACKED_CLIENTS = 10_000


class SlidingWindowLimiter:
    """按 key(客户端 id)的滑动窗口计数器。"""

    def __init__(self, *, max_tracked: int = _MAX_TRACKED_CLIENTS):
        self._hits: dict[str, list[float]] = defaultdict(list)
        self._lock = threading.Lock()
        self._max_tracked = max_tracked

    def check(self, key: str, limit: int, window_s: float = 60.0,
              now: float | None = None) -> tuple[bool, float]:
        """记一次命中;返回 (是否允许, 超限时的建议重试秒数)。"""
        if limit <= 0:
            return True, 0.0
        ref = time.monotonic() if now is None else now
        with self._lock:
            if len(self._hits) > self._max_tracked:
                self._evict(ref, window_s)
            hits = [t for t in self._hits.get(key, []) if ref - t < window_s]
            if len(hits) >= limit:
                self._hits[key] = hits
                oldest = hits[0] if hits else ref
                return False, max(0.1, window_s - (ref - oldest))
            hits.append(ref)
            self._hits[key] = hits
            return True, 0.0

    def _evict(self, now: float, window_s: float) -> None:
        """清理已完全过窗的键(调用方持锁)。"""
        stale = [k for k, v in self._hits.items()
                 if not v or now - v[-1] >= window_s]
        for key in stale:
            self._hits.pop(key, None)

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


class ConcurrencyGuard:
    """全局在途上游调用计数闸(非阻塞获取,超限立即报 rate_limit)。"""

    def __init__(self, limit: int):
        self._limit = max(1, limit)
        self._semaphore = threading.BoundedSemaphore(self._limit)
        self._in_flight = 0
        self._lock = threading.Lock()

    @property
    def in_flight(self) -> int:
        with self._lock:
            return self._in_flight

    @property
    def limit(self) -> int:
        return self._limit

    def __enter__(self) -> "ConcurrencyGuard":
        if not self._semaphore.acquire(blocking=False):
            raise MiddlewareError(
                "rate_limit",
                f"服务当前并发已达上限({self._limit}),请稍后重试")
        with self._lock:
            self._in_flight += 1
        return self

    def __exit__(self, *exc_info) -> None:
        with self._lock:
            self._in_flight -= 1
        self._semaphore.release()
