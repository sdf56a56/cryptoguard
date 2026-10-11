"""
分级令牌模块 —— T1 不透明伪名 / T2 格式保留 / T3 保序 / T4 同态

T1 安全目标:伪名不可区分(HMAC PRF),同会话共指,跨会话不可关联。
明确不承诺:不抗同值频率统计(同名出现次数可见)。
归约:PRF 安全。
"""
from __future__ import annotations
import base64
import hashlib
import hmac

T1_DISPLAY_LEN = 10


def t1_pseudonym(k_t1: bytes, type_: str, value: str, session_salt: bytes) -> str:
    raw = hmac.new(
        k_t1,
        type_.encode("utf-8") + b"\x00" + value.encode("utf-8") + b"\x00" + session_salt,
        hashlib.sha256,
    ).digest()
    # 128-bit 截断;b32encode 对 16 字节输出 26 个有效字符 + 6 个 '=' 填充,
    # 去除填充以满足 26 字符小写 Base32 令牌格式。
    return base64.b32encode(raw[:16]).decode("ascii").lower().rstrip("=")
