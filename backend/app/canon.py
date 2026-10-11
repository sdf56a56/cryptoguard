"""
JCS 哈希基座 —— RFC 8785 JSON Canonicalization Scheme

安全目标:哈希前映像确定性(同对象→同字节),消灭拼接歧义与字节序 bug。
明确不承诺:规范化只保证编码确定性,不提供任何密码学强度(强度来自 SHA-256/HMAC)。
选型:jcs 优先,canonicaljson 降级;BIND-6 向量测试锁定行为。
"""
from __future__ import annotations
import hashlib

try:
    from jcs import canonicalize as _canon_impl
    JCS_LIB = "jcs"
except ImportError:  # pragma: no cover
    from canonicaljson import encode_canonical_json as _canon_impl
    JCS_LIB = "canonicaljson"


def canon(obj: dict | list) -> bytes:
    """RFC 8785 规范化,返回 bytes 作为哈希前映像。"""
    return _canon_impl(obj)


def h_hex(obj: dict) -> str:
    """对规范化 JSON 对象取 SHA-256 hex。"""
    return hashlib.sha256(canon(obj)).hexdigest()
