"""
JCS 哈希基座 —— RFC 8785 JSON Canonicalization Scheme

安全目标:哈希前映像确定性(同对象→同字节),消灭拼接歧义与字节序 bug。
明确不承诺:规范化只保证编码确定性,不提供任何密码学强度(强度来自 SHA-256/HMAC)。
选型:rfc8785 优先,canonicaljson 降级;BIND-6 向量测试锁定行为。
NFC:两库本身均不归一,canon() 在序列化前经 _nfc 对所有字符串做 NFC 预归一化,
保证等价码点序列(NFC/NFD)→同一前映像(模块确定性策略,见 _nfc 注)。
"""
from __future__ import annotations
import hashlib
import unicodedata

try:
    from rfc8785 import dumps as _canon_impl
    JCS_LIB = "rfc8785"
except ImportError:  # pragma: no cover
    from canonicaljson import encode_canonical_json as _canon_impl
    JCS_LIB = "canonicaljson"


def _nfc(obj):
    """序列化前递归归一化字符串为 Unicode NFC(dict/list 递归,其余原样)。

    注:这是本模块的确定性策略,严于 RFC 8785 §3.1 的字面要求
    (该节要求组件 "MUST preserve Unicode string data as is")。
    """
    if isinstance(obj, str):
        return unicodedata.normalize("NFC", obj)
    if isinstance(obj, dict):
        return {_nfc(k): _nfc(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_nfc(x) for x in obj]
    return obj


def canon(obj: dict | list) -> bytes:
    """RFC 8785 规范化(含 NFC 归一化),返回 bytes 作为哈希前映像。"""
    return _canon_impl(_nfc(obj))


def h_hex(obj: dict) -> str:
    """对规范化 JSON 对象取 SHA-256 hex。"""
    return hashlib.sha256(canon(obj)).hexdigest()
