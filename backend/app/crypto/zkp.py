"""
ZKP 请求合规性证明模块（Schnorr 零知识证明 + Fiat-Shamir）

安全目标：
  - 零知识：证明者向验证者证明「我知道某个秘密」（此处为脱敏映射表的解密密钥），
    而不泄露秘密本身。
  - 完整性/健全性：不知道秘密的人无法通过验证。

明确不承诺：
  - 本模块是 Schnorr 协议（离散对数），**不是** zk-SNARK/zk-STARK，
    不具备「任意电路」证明能力。md 中 zk-SNARK 的 180ms 预算不在本模块承担。
  - 证明「请求已脱敏」通过「证明持有映射表密钥」这一代理变量实现，语义需在文档说明。

归约：安全性归约到离散对数问题（DLOG）+ 随机预言机模型（Fiat-Shamir）。
"""
from __future__ import annotations

import hashlib
import os

# 使用 256-bit 安全素数（RFC 3526 group 14 的素数）
_PRIME = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
_GENERATOR = 2
_BYTES = (_PRIME.bit_length() + 7) // 8  # 素数的字节长度（2048-bit -> 256 字节）


class SchnorrProver:
    """证明者：持有秘密 x，公开 y = g^x。"""

    def __init__(self, secret: int | None = None):
        self.x = secret if secret is not None else int.from_bytes(os.urandom(32), "big") % _PRIME
        self.y = pow(_GENERATOR, self.x, _PRIME)

    def prove(self, aux: bytes = b"") -> dict:
        """非交互式证明（Fiat-Shamir）。"""
        v = int.from_bytes(os.urandom(32), "big") % _PRIME
        commitment = pow(_GENERATOR, v, _PRIME)
        challenge = int.from_bytes(
            hashlib.sha256(commitment.to_bytes(_BYTES, "big") + aux).digest(), "big"
        ) % _PRIME
        response = (v + challenge * self.x) % (_PRIME - 1)
        return {"commitment": hex(commitment), "challenge": hex(challenge), "response": hex(response)}


def verify_proof(y: int, proof: dict, aux: bytes = b"") -> bool:
    """验证者：验证 g^r == commitment * y^c (mod p)。"""
    commitment = int(proof["commitment"], 16)
    challenge = int(proof["challenge"], 16)
    response = int(proof["response"], 16)
    # 校验挑战一致性（Fiat-Shamir）
    expected_c = int.from_bytes(
        hashlib.sha256(commitment.to_bytes(_BYTES, "big") + aux).digest(), "big"
    ) % _PRIME
    if expected_c != challenge:
        return False
    lhs = pow(_GENERATOR, response, _PRIME)
    rhs = (commitment * pow(y, challenge, _PRIME)) % _PRIME
    return lhs == rhs
