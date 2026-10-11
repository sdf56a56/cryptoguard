"""
国密算法参考实现（纯 Python，无第三方依赖）

包含：
  - SM3   密码杂凑算法（GB/T 32905）
  - SM4   分组密码算法（GB/T 32907）
  - SM2   椭圆曲线公钥密码算法 · 数字签名（GB/T 32918）

用途：作为 CryptoGuard 的国密签名/哈希演示模块，与 Ed25519 形成双栈对照。

安全目标：
  - SM3：抗碰撞、抗原像、抗第二原像（256-bit 输出）。
  - SM2：EUF-CMA 安全性（基于椭圆曲线离散对数困难问题 ECDLP）。

明确不承诺：
  - 本实现为教学/演示级，未做常数时间优化，不承诺抵抗时序侧信道。
  - 未经过 FIPS / 商用密码认证，生产环境请使用经认证的密码模块。

归约：SM2 安全性归约到 SM2 曲线上的离散对数问题（ECDLP）。
"""
from __future__ import annotations


# --------------------------------------------------------------------------- #
# SM3
# --------------------------------------------------------------------------- #
IV = [
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E,
]
T = [0x79CC4519] * 16 + [0x7A879D8A] * 48


def _rotl(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _p0(x: int) -> int:
    return x ^ _rotl(x, 9) ^ _rotl(x, 17)


def _p1(x: int) -> int:
    return x ^ _rotl(x, 15) ^ _rotl(x, 23)


def _ff(x: int, y: int, z: int, j: int) -> int:
    return x ^ y ^ z if j < 16 else (x & y) | (x & z) | (y & z)


def _gg(x: int, y: int, z: int, j: int) -> int:
    return x ^ y ^ z if j < 16 else (x & y) | (~x & z)


def sm3(message: bytes) -> bytes:
    """SM3 杂凑，返回 32 字节摘要。"""
    length = len(message) * 8
    msg = bytearray(message)
    msg.append(0x80)
    while (len(msg) % 64) != 56:
        msg.append(0x00)
    msg += length.to_bytes(8, "big")

    v = IV[:]
    for block_start in range(0, len(msg), 64):
        block = msg[block_start:block_start + 64]
        w = [int.from_bytes(block[i * 4:i * 4 + 4], "big") for i in range(16)]
        for j in range(16, 68):
            w.append(_p1(w[j - 16] ^ w[j - 9] ^ _rotl(w[j - 3], 15))
                     ^ _rotl(w[j - 13], 7) ^ w[j - 6])
        w1 = [w[j] ^ w[j + 4] for j in range(64)]

        a, b, c, d, e, f, g, h = v
        for j in range(64):
            ss1 = _rotl((_rotl(a, 12) + e + _rotl(T[j], j % 32)) & 0xFFFFFFFF, 7)
            ss2 = ss1 ^ _rotl(a, 12)
            tt1 = (_ff(a, b, c, j) + d + ss2 + w1[j]) & 0xFFFFFFFF
            tt2 = (_gg(e, f, g, j) + h + ss1 + w[j]) & 0xFFFFFFFF
            d = c
            c = _rotl(b, 9)
            b = a
            a = tt1
            h = g
            g = _rotl(f, 19)
            f = e
            e = _p0(tt2)
        v = [(x ^ y) & 0xFFFFFFFF for x, y in zip(v, [a, b, c, d, e, f, g, h])]

    return b"".join(x.to_bytes(4, "big") for x in v)


# --------------------------------------------------------------------------- #
# SM4
# --------------------------------------------------------------------------- #
_SM4_SBOX = [
    0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05,
    0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3, 0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9C, 0x42, 0x50, 0xF4, 0x91, 0xEF, 0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
    0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95, 0x80, 0xDF, 0x94, 0xFA, 0x75, 0x8F, 0x3F, 0xA6,
    0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA, 0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8,
    0x68, 0x6B, 0x81, 0xB2, 0x71, 0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
    0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B, 0x01, 0x21, 0x78, 0x87,
    0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52, 0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E,
    0xEA, 0xBF, 0x8A, 0xD2, 0x40, 0xC7, 0x38, 0xB5, 0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1,
    0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55, 0xAD, 0x93, 0x32, 0x30, 0xF5, 0x8C, 0xB1, 0xE3,
    0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60, 0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F,
    0xD5, 0xDB, 0x37, 0x45, 0xDE, 0xFD, 0x8E, 0x2F, 0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51,
    0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F, 0x11, 0xD9, 0x5C, 0x41, 0x1F, 0x10, 0x5A, 0xD8,
    0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD, 0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0,
    0x89, 0x69, 0x97, 0x4A, 0x0C, 0x96, 0x77, 0x7E, 0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84,
    0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20, 0x79, 0xEE, 0x5F, 0x3E, 0xD7, 0xCB, 0x39, 0x48,
]
_SM4_FK = [0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC]
_SM4_CK = [
    0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269, 0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
    0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249, 0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
    0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229, 0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
    0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209, 0x10171E25, 0x2C333A41, 0x48565F66, 0x5D646B72,
]


def _sm4_tau(x: int) -> int:
    return (_SM4_SBOX[(x >> 24) & 0xFF] << 24 | _SM4_SBOX[(x >> 16) & 0xFF] << 16 |
            _SM4_SBOX[(x >> 8) & 0xFF] << 8 | _SM4_SBOX[x & 0xFF])


def _sm4_l(x: int) -> int:
    return x ^ _rotl(x, 2) ^ _rotl(x, 10) ^ _rotl(x, 18) ^ _rotl(x, 24)


def _sm4_lp(x: int) -> int:
    return x ^ _rotl(x, 13) ^ _rotl(x, 23)


def sm4_encrypt_block(key: bytes, block: bytes) -> bytes:
    """SM4 加密单个 16 字节分组，返回 16 字节密文。"""
    mk = [int.from_bytes(key[i * 4:i * 4 + 4], "big") for i in range(4)]
    k = [mk[i] ^ _SM4_FK[i] for i in range(4)]
    rk = []
    for i in range(32):
        k.append(k[i] ^ _sm4_lp(_sm4_tau(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ _SM4_CK[i])))
        rk.append(k[-1])
    x = [int.from_bytes(block[i * 4:i * 4 + 4], "big") for i in range(4)]
    for i in range(32):
        x.append(x[i] ^ _sm4_l(_sm4_tau(x[i + 1] ^ x[i + 2] ^ x[i + 3] ^ rk[i])))
    out = [x[35], x[34], x[33], x[32]]  # 逆序输出
    return b"".join(v.to_bytes(4, "big") for v in out)


# --------------------------------------------------------------------------- #
# SM2 —— 椭圆曲线点运算与数字签名（GB/T 32918.2）
# --------------------------------------------------------------------------- #
_SM2_P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
_SM2_A = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
_SM2_B = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
_SM2_N = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
_SM2_GX = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
_SM2_GY = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
_SM2_DEFAULT_ID = "1234567812345678"


def _inv(a: int, n: int) -> int:
    return pow(a, n - 2, n)  # n 为素数


def _ec_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % _SM2_P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1 + _SM2_A) * _inv(2 * y1, _SM2_P) % _SM2_P
    else:
        lam = (y2 - y1) * _inv(x2 - x1, _SM2_P) % _SM2_P
    x3 = (lam * lam - x1 - x2) % _SM2_P
    y3 = (lam * (x1 - x3) - y1) % _SM2_P
    return x3, y3


def _ec_mul(k: int, p):
    result = None
    addend = p
    while k:
        if k & 1:
            result = _ec_add(result, addend)
        addend = _ec_add(addend, addend)
        k >>= 1
    return result


def _za(public_key: tuple) -> bytes:
    x, y = public_key
    entla = (len(_SM2_DEFAULT_ID) * 8).to_bytes(2, "big")
    return sm3(entla + _SM2_DEFAULT_ID.encode() +
               _SM2_A.to_bytes(32, "big") + _SM2_B.to_bytes(32, "big") +
               _SM2_GX.to_bytes(32, "big") + _SM2_GY.to_bytes(32, "big") +
               x.to_bytes(32, "big") + y.to_bytes(32, "big"))


class SM2Key:
    """SM2 密钥对与签名/验签。"""

    def __init__(self, private_key: int | None = None):
        if private_key is None:
            import os
            private_key = int.from_bytes(os.urandom(32), "big") % (_SM2_N - 1) + 1
        self.d = private_key
        self.public = _ec_mul(self.d, (_SM2_GX, _SM2_GY))

    def sign(self, message: bytes) -> tuple:
        """返回 (r, s) 签名。"""
        z = _za(self.public) + sm3(message)
        e = int.from_bytes(sm3(z), "big")
        import os
        while True:
            k = int.from_bytes(os.urandom(32), "big") % (_SM2_N - 1) + 1
            x1, _ = _ec_mul(k, (_SM2_GX, _SM2_GY))
            r = (e + x1) % _SM2_N
            if r == 0 or r + k == _SM2_N:
                continue
            s = _inv(1 + self.d, _SM2_N) * ((k - r * self.d) % _SM2_N) % _SM2_N
            if s != 0:
                return r, s

    def verify(self, message: bytes, signature: tuple) -> bool:
        r, s = signature
        if not (1 <= r < _SM2_N and 1 <= s < _SM2_N):
            return False
        z = _za(self.public) + sm3(message)
        e = int.from_bytes(sm3(z), "big")
        t = (r + s) % _SM2_N
        if t == 0:
            return False
        point = _ec_add(_ec_mul(s, (_SM2_GX, _SM2_GY)), _ec_mul(t, self.public))
        if point is None:
            return False
        x1, _ = point
        return (e + x1) % _SM2_N == r
