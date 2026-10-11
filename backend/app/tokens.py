"""
分级令牌模块 —— T1 不透明伪名 / T2 格式保留 / T3 保序 / T4 同态

T1 安全目标:伪名不可区分(HMAC PRF),同会话共指,跨会话不可关联。
明确不承诺:不抗同值频率统计(同名出现次数可见)。
归约:PRF 安全。
"""
from __future__ import annotations
import base64
import bisect
import hashlib
import hmac
import secrets as _secrets
import time

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


# ---------------------------------------------------------------------------
# T2:FF1 格式保留令牌(身份证前 17 位 / 卡号前 15 位 / 手机后 9 位)
# ---------------------------------------------------------------------------

FF1_DEGRADED = False   # PERF-FF1-1:超预算时置 True,UI 横幅读取


class T2Cipher:
    """FF1 格式保留加密。身份证前17位/卡号前15位/手机后9位。"""

    def __init__(self, key: bytes, tweak: bytes = b"cryptoguard"):
        try:
            from ff3 import FF3Cipher
            self._impl = "ff3"
            k = key[:16].hex()
            self._c = FF3Cipher(k, tweak[:7].hex(), radix=10)
        except ImportError:
            import pyffx
            self._impl = "pyffx"
            # R11:pyffx 实例绑定固定长度,按长度各建一个(17/15/9)
            self._px = {
                17: pyffx.String(key[:16], alphabet="0123456789", length=17),
                15: pyffx.String(key[:16], alphabet="0123456789", length=15),
                9: pyffx.String(key[:16], alphabet="0123456789", length=9),
            }

    def encrypt_id17(self, v17: str) -> str:
        return self._enc(v17)

    def decrypt_id17(self, ct: str) -> str:
        return self._dec(ct)

    def encrypt_card15(self, v15: str) -> str:
        return self._enc(v15)

    def encrypt_phone_tail9(self, v9: str) -> str:
        return self._enc(v9)

    def decrypt_phone_tail9(self, ct: str) -> str:
        return self._dec(ct)

    def _enc(self, s: str) -> str:
        if self._impl == "ff3":
            return self._c.encrypt(s)
        return self._px[len(s)].encrypt(s)

    def _dec(self, s: str) -> str:
        if self._impl == "ff3":
            return self._c.decrypt(s)
        return self._px[len(s)].decrypt(s)


def id_check_digit(d17: str) -> str:
    """ISO 7064 MOD 11-2 身份证第 18 位。"""
    w = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
    s = sum(int(d) * wi for d, wi in zip(d17, w))
    return "10X98765432"[s % 11]


def luhn_digit(d15: str) -> str:
    """Luhn 校验位(第 16 位)。"""
    digits = [int(x) for x in d15]
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 0:                    # 第 16 位占奇数位,前 15 位偶数位加倍
            d *= 2
            if d > 9: d -= 9
        total += d
    return str((10 - total % 10) % 10)


def ff1_unit_ms_p95(c: "T2Cipher", n: int = 1000) -> float:
    """PERF-FF1-1 实测:n 次加密耗时 P95(ms/个)。"""
    import statistics
    samples = []
    probe = "1101051949123100"
    for i in range(n):
        t0 = time.perf_counter()
        c._enc(probe + str(i % 10))
        samples.append((time.perf_counter() - t0) * 1000)
    samples.sort()
    return samples[int(n * 0.95)]


# ---------------------------------------------------------------------------
# T3:静态保序令牌(≤20 个数值)+ 分桶降级
# ---------------------------------------------------------------------------


class StaticOPE:
    """简化保序编码:演示前固定 ≤20 个数值,秩+随机间隔,单调保序。
    显式泄漏:序关系 + 等值性(UI 徽章 ⚠️ 泄漏:序关系)。不支持动态插入。"""
    LEAK = "序关系+等值性"
    MAX_VALUES = 20

    def __init__(self, values: list[int]):
        if len(set(values)) > self.MAX_VALUES:
            raise ValueError("静态集合上限 20 个数值(spec §1.3)")
        self._enc: dict[int, int] = {}
        rank = 0
        for v in sorted(set(values)):
            rank += 1 + _secrets.randbelow(64)     # 随机间隔
            self._enc[v] = rank
        self._dec = {r: v for v, r in self._enc.items()}

    def encrypt(self, v: int) -> int:
        if v not in self._enc:
            raise KeyError(f"{v} 不在静态集合内,不支持动态插入")
        return self._enc[v]

    def decrypt(self, e: int) -> int:
        return self._dec[e]


class BucketOPE:
    """分桶保序降级:仅泄漏桶序,桶边界公开声明。"""
    LEAK = "桶序"

    def __init__(self, bounds: list[int]):
        self._bounds = sorted(bounds)

    def encrypt(self, v: int) -> int:
        return bisect.bisect_right(self._bounds, v)
