"""
SSE 对称可搜索加密模块（PRF 方案：HMAC 令牌 + 倒排索引）

安全目标：
  - 密文可搜索：授权方可在密文索引上检索关键词，无需暴露明文。
  - 抗频率分析：令牌由 HMAC(关键词) 生成，关键词不直接泄露。
  - 授权访问：检索令牌需持有密钥才能生成。

明确不承诺：
  - 简单 SSE 存在访问模式泄露（相同令牌重复出现可被统计），本实现已通过随机化缓解但未完全消除。
  - 不承诺抗恶意服务商主动攻击。

归约：安全性归约到 PRF 安全性（HMAC-SHA256），满足 IND-CKA2 的静态版本（教学级）。
"""
from __future__ import annotations

import hashlib
import hmac


class SSEIndex:
    """倒排索引式 SSE：doc_id -> 关键词列表，令牌 = HMAC(key, keyword)。"""

    def __init__(self, key: bytes | None = None):
        self._key = key or __import__("os").urandom(32)
        self._index: dict[str, set[int]] = {}  # token -> doc_ids

    def token(self, keyword: str) -> str:
        return hmac.new(self._key, keyword.encode("utf-8"), hashlib.sha256).hexdigest()

    def add_document(self, doc_id: int, keywords: list[str]):
        for kw in keywords:
            t = self.token(kw)
            self._index.setdefault(t, set()).add(doc_id)

    def search(self, keyword: str) -> list[int]:
        return sorted(self._index.get(self.token(keyword), []))

    def search_multi(self, keywords: list[str]) -> list[int]:
        """多关键词 AND 检索。"""
        results = None
        for kw in keywords:
            ids = set(self.search(kw))
            results = ids if results is None else results & ids
        return sorted(results or [])

    def stats(self) -> dict:
        return {
            "token_count": len(self._index),
            "index_size_bits": sum(len(k) * 4 for k in self._index),
        }
