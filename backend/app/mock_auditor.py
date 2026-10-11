"""
Mock 第三方审计机构 —— 签发模型身份声明 model_cert

安全目标：
  - 模型身份声明不可伪造：只有审计机构私钥能签发 model_cert。
  - 声明绑定：cert 绑定 model_id、version、release_date、model_hash。

明确不承诺：审计机构为可信第三方（演示假设），不承诺其私钥被攻破后的安全。
"""
from __future__ import annotations

import hashlib

from .crypto.signatures import Ed25519Signer


class MockAuditor:
    def __init__(self, name: str = "Audit-Authority"):
        self.name = name
        self.signer = Ed25519Signer()
        self.auditor_public_b64 = self.signer.public_b64

    def issue_model_cert(self, model_id: str, version: str,
                         release_date: str, model_hash: str) -> dict:
        payload = {
            "model_id": model_id,
            "version": version,
            "release_date": release_date,
            "model_hash": model_hash,
            "auditor": self.name,
        }
        # 对规范化的载荷签名
        message = self._canonical(payload)
        cert = {
            **payload,
            "auditor_public_key": self.auditor_public_b64,
            "signature": self.signer.sign(message),
        }
        return cert

    def verify_model_cert(self, cert: dict) -> bool:
        try:
            payload = {
                "model_id": cert["model_id"],
                "version": cert["version"],
                "release_date": cert["release_date"],
                "model_hash": cert["model_hash"],
                "auditor": cert["auditor"],
            }
            message = self._canonical(payload)
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            import base64
            key = Ed25519PublicKey.from_public_bytes(
                base64.b64decode(cert["auditor_public_key"])
            )
            key.verify(base64.b64decode(cert["signature"]), message)
            return True
        except Exception:
            return False

    @staticmethod
    def _canonical(payload: dict) -> bytes:
        s = "|".join(f"{k}={payload[k]}" for k in sorted(payload))
        return s.encode("utf-8")
