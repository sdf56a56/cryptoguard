"""幂等键缓存 —— 客户端重试去重（仅非流式）

为什么需要：Agent 超时重试是常态。没有幂等键时，每次重试都会生成新的
`request_id`、再次调用上游、重复计费、在审计里多一条记录。

安全约束：
  - 缓存的是**最终响应**，以 `vault.mapping_key` 派生的 AEAD 封缄后驻留内存，
    内存中不保存明文响应；
  - 只缓存成功(2xx)的非流式响应；错误不缓存（客户端应重试）；
  - 同一个 key + 不同请求摘要 → 409 conflict，绝不覆盖旧响应；
  - TTL + LRU 有界；进程重启即清空（与单进程部署假设一致）。
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass

from ..crypto.aead import AeadCipher
from ..keys import Vault
from .errors import MiddlewareError


@dataclass
class _Entry:
    request_digest: str
    request_id: str
    status: int
    headers: dict
    sealed: dict
    created: float


class IdempotencyStore:
    """按 `(client_id, idempotency_key)` 缓存最终响应。"""

    def __init__(self, vault: Vault, *, ttl_s: float = 600.0,
                 max_entries: int = 1024) -> None:
        self._cipher = AeadCipher(vault.mapping_key)
        self._ttl = max(1.0, float(ttl_s))
        self._max = max(16, int(max_entries))
        self._entries: OrderedDict[str, _Entry] = OrderedDict()
        self._lock = threading.Lock()
        self._hits = 0
        self._conflicts = 0

    # ------------------------------------------------------------------ #
    @staticmethod
    def scope(client_id: str, key: str) -> str:
        """作用域：按客户端隔离，只存 key 的摘要（不把客户端原始 key 落日志）。"""
        raw = f"{client_id}\x00{key}".encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    @staticmethod
    def request_digest(payload: dict) -> str:
        normalized = json.dumps(payload, sort_keys=True, ensure_ascii=False,
                                default=str)
        return hashlib.sha256(normalized.encode("utf-8")).hexdigest()

    # ------------------------------------------------------------------ #
    def get(self, scope: str, digest: str) -> dict | None:
        """取缓存；同 key 不同摘要抛 conflict；过期按未命中处理。"""
        now = time.monotonic()
        with self._lock:
            entry = self._entries.get(scope)
            if entry is None:
                return None
            if now - entry.created > self._ttl:
                self._entries.pop(scope, None)
                return None
            if entry.request_digest != digest:
                self._conflicts += 1
                raise MiddlewareError(
                    "conflict",
                    "同一个 Idempotency-Key 被用于不同的请求体："
                    "网关拒绝覆盖已有响应（请换一个 key 或复现原请求）")
            self._hits += 1
            self._entries.move_to_end(scope)
            try:
                body = json.loads(self._cipher.decrypt(entry.sealed["iv"],
                                                       entry.sealed["ciphertext"]))
            except Exception:  # noqa: BLE001 — 解封失败按未命中，绝不返回损坏内容
                self._entries.pop(scope, None)
                return None
            return {
                "request_id": entry.request_id,
                "status": entry.status,
                "headers": dict(entry.headers),
                "body": body,
            }

    def put(self, scope: str, digest: str, payload: dict, *,
            status: int = 200, headers: dict | None = None,
            request_id: str = "") -> None:
        """封缄并保存一次成功响应；覆盖同 scope 的旧值（同 digest 重试）。"""
        sealed = self._cipher.encrypt(
            json.dumps(payload, ensure_ascii=False, default=str))
        entry = _Entry(request_digest=digest, request_id=request_id,
                       status=int(status), headers=dict(headers or {}),
                       sealed=sealed, created=time.monotonic())
        with self._lock:
            self._entries[scope] = entry
            self._entries.move_to_end(scope)
            while len(self._entries) > self._max:
                self._entries.popitem(last=False)

    def stats(self) -> dict:
        with self._lock:
            return {"tracked": len(self._entries), "ttl_s": self._ttl,
                    "max_entries": self._max, "hits": self._hits,
                    "conflicts": self._conflicts}
