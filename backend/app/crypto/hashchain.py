"""
哈希链模块 —— 抗篡改日志（Hash Chain）

安全目标：
  - 抗篡改：修改任意历史日志条目会导致后续所有哈希值变化，从而被根哈希检测。
  - 单向性：无法由当前哈希反推历史内容。

明确不承诺：
  - 哈希链只能检测篡改，不能阻止篡改（需配合签名/共识）。
  - 不承诺防拥有链尾写入权的进程写入伪造条目。

归约：安全性依赖 SHA-256 的抗第二原像性（Preimage / Second-preimage resistance）。
"""
from __future__ import annotations

import hashlib
import time


def sha256_hex(*parts: str) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(p.encode("utf-8"))
    return h.hexdigest()


class HashChain:
    """追加式哈希链，存储条目并提供根哈希。"""

    def __init__(self):
        self.entries: list[dict] = []
        self._prev = "0" * 64  # 创世块前驱 = 全零

    def append(self, request_digest: str, response_digest: str,
               timestamp: str, extra: str = "") -> dict:
        entry = {
            "index": len(self.entries),
            "request_digest": request_digest,
            "response_digest": response_digest,
            "timestamp": timestamp,
            "extra": extra,
            "prev_hash": self._prev,
        }
        entry["hash"] = sha256_hex(
            request_digest, response_digest, timestamp, extra, self._prev
        )
        self.entries.append(entry)
        self._prev = entry["hash"]
        return entry

    @property
    def root(self) -> str:
        return self._prev

    def verify(self) -> bool:
        """重算整条链，检测是否存在篡改。"""
        prev = "0" * 64
        for e in self.entries:
            expected = sha256_hex(
                e["request_digest"], e["response_digest"],
                e["timestamp"], e["extra"], prev,
            )
            if expected != e["hash"]:
                return False
            prev = expected
        return prev == self._prev
