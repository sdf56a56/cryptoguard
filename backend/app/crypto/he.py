"""
同态加密模块 —— Paillier 加法同态（纯 Python 参考实现）

安全目标：
  - 加法同态：E(m1) * E(m2) = E(m1 + m2)，可在密文上求和/均值。
  - 语义安全 (IND-CPA)：相同明文两次加密产生不同密文（随机 r）。

明确不承诺：
  - 本实现为演示级，密钥长度 512-bit，不满足生产强度（建议 2048+）。
  - Paillier 不支持乘法同态（乘法需 BGV/CKKS 等）。

归约：安全性归约到「判定复合剩余类问题」（Decisional Composite Residuosity, DCR）。
"""
from __future__ import annotations

import math
import os


def _lcm(a: int, b: int) -> int:
    return abs(a * b) // math.gcd(a, b)


def _l(x: int, n: int) -> int:
    return (x - 1) // n


def _is_prime(n: int, rounds: int = 40) -> bool:
    """Miller-Rabin 素性测试。"""
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d = n - 1
    s = 0
    while d % 2 == 0:
        s += 1
        d //= 2
    for _ in range(rounds):
        a = int.from_bytes(os.urandom(8), "big") % (n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _gen_prime(bits: int) -> int:
    while True:
        cand = int.from_bytes(os.urandom(bits // 8 + 1), "big") | (1 << (bits - 1)) | 1
        if _is_prime(cand):
            return cand


class Paillier:
    def __init__(self, bits: int = 512):
        self.p = _gen_prime(bits // 2)
        self.q = _gen_prime(bits // 2)
        self.n = self.p * self.q
        self.n2 = self.n * self.n
        self.g = self.n + 1
        lam = _lcm(self.p - 1, self.q - 1)
        self.mu = pow(_l(pow(self.g, lam, self.n2), self.n), -1, self.n)

    def encrypt(self, m: int) -> int:
        r = int.from_bytes(os.urandom(16), "big") % (self.n - 1) + 1
        return (pow(self.g, m, self.n2) * pow(r, self.n, self.n2)) % self.n2

    def decrypt(self, c: int) -> int:
        lam = _lcm(self.p - 1, self.q - 1)
        return (_l(pow(c, lam, self.n2), self.n) * self.mu) % self.n

    def add(self, c1: int, c2: int) -> int:
        return (c1 * c2) % self.n2


def encrypt_vector(phe: Paillier, values: list[int]) -> list[int]:
    return [phe.encrypt(v) for v in values]


def decrypt_vector(phe: Paillier, ciphertexts: list[int]) -> list[int]:
    return [phe.decrypt(c) for c in ciphertexts]


def sum_encrypted(phe: Paillier, ciphertexts: list[int]) -> int:
    total = 1
    for c in ciphertexts:
        total = (total * c) % phe.n2
    return total
