"""
签名模块 —— Ed25519（国际）/ SM2-SM3（国密）双栈

安全目标：
  - EUF-CMA：无服务商私钥无法伪造有效响应签名。
  - 不可抵赖：签名可由任意第三方用公钥验证，服务商无法否认已签内容。

明确不承诺：
  - 不承诺防私钥持有者主动作恶（私钥泄露即失效）。
  - SM2 为纯 Python 参考实现，不承诺抵抗时序侧信道。

归约：Ed25519 归约到 Curve25519 上的 ECDLP（+ 一个非随机化假设）；SM2 归约到 SM2 曲线 ECDLP。
"""
from __future__ import annotations

import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature

from .sm_crypto import SM2Key


class Ed25519Signer:
    """Ed25519 签名/验签封装。"""

    def __init__(self, seed: bytes | None = None):
        self._key = Ed25519PrivateKey.generate() if seed is None else Ed25519PrivateKey.from_private_bytes(seed)
        self.public_b64 = base64.b64encode(
            self._key.public_key().public_bytes_raw()
        ).decode()

    def sign(self, message: bytes) -> str:
        return base64.b64encode(self._key.sign(message)).decode()

    def verify(self, message: bytes, signature_b64: str) -> bool:
        try:
            Ed25519PublicKey.from_public_bytes(
                base64.b64decode(self.public_b64)
            ).verify(base64.b64decode(signature_b64), message)
            return True
        except (InvalidSignature, ValueError):
            return False


class SM2Signer:
    """SM2-SM3 签名/验签封装。"""

    def __init__(self):
        self._key = SM2Key()
        x, y = self._key.public
        self.public_hex = (x.to_bytes(32, "big") + y.to_bytes(32, "big")).hex()

    def sign(self, message: bytes) -> dict:
        r, s = self._key.sign(message)
        return {"r": hex(r), "s": hex(s)}

    def verify(self, message: bytes, signature: dict) -> bool:
        return self._key.verify(message, (int(signature["r"], 16), int(signature["s"], 16)))
