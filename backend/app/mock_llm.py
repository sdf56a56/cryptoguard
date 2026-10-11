"""
Mock 大模型 API —— 接收脱敏输入，返回输出 + 四层可验证信息

支持攻击注入（用于演示）：
  - tamper       篡改输出（签名/哈希不一致）
  - replay       重放旧响应（nonce 不匹配）
  - forge_cert   伪造模型声明（审计机构签名失败）
  - tamper_log   篡改日志（Merkle 证明失败）
  - repudiate    用户诬告（input_hash 绑定失败）
"""
from __future__ import annotations

import hashlib
import time

from .crypto.signatures import Ed25519Signer


class MockLLM:
    def __init__(self, auditor_cert: dict, model_name: str = "CryptoGuard-Mock-LLM-v1"):
        self.provider_signer = Ed25519Signer()
        self.provider_public_b64 = self.provider_signer.public_b64
        self.model_cert = auditor_cert
        self.model_name = model_name
        self._nonce_store: dict[str, str] = {}  # input_hash -> 上次 nonce（防重放）

    def respond(self, redacted_input: str, input_hash: str, nonce: str,
                timestamp: str, attack: str | None = None) -> dict:
        output = self._generate(redacted_input)

        # 重放攻击：如果曾处理过该 input_hash，复用旧 nonce
        if attack == "replay":
            old_nonce = self._nonce_store.get(input_hash, nonce)
            timestamp = self._last_timestamp.get(input_hash, timestamp)
            nonce_used = old_nonce
        else:
            nonce_used = nonce
            self._nonce_store[input_hash] = nonce
            self._last_timestamp = getattr(self, "_last_timestamp", {})
            self._last_timestamp[input_hash] = timestamp

        # 伪造证书攻击
        cert = self.model_cert
        if attack == "forge_cert":
            cert = {**self.model_cert, "model_hash": "FAKE_MODEL_HASH_0000"}

        # 先基于「正确输出」计算哈希与签名
        response_hash = self._response_hash(output, input_hash, cert, nonce_used, timestamp)
        signature = self.provider_signer.sign(response_hash.encode("utf-8"))

        # 篡改攻击：传输中被中间人篡改输出，但哈希/签名仍对应原始输出 → 验证失败
        if attack == "tamper":
            output = output + " [已篡改内容]"

        return {
            "output": output,
            "model_cert": cert,
            "response_hash": response_hash,
            "signature": signature,
            "provider_public_key": self.provider_public_b64,
            "nonce": nonce_used,
            "timestamp": timestamp,
        }

    @staticmethod
    def _response_hash(output: str, input_hash: str, cert: dict,
                       nonce: str, timestamp: str) -> str:
        cert_canonical = "|".join(f"{k}={cert[k]}" for k in sorted(cert) if k != "signature")
        raw = "||".join([output, input_hash, cert_canonical, nonce, timestamp])
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    @staticmethod
    def _generate(redacted_input: str) -> str:
        # 演示：基于占位符的模板回复
        n_placeholders = redacted_input.count("[")
        if n_placeholders:
            return f"已收到您的请求（含 {n_placeholders} 个受保护字段），处理完成：根据脱敏上下文，相关结果已安全返回。"
        return "已收到您的请求，处理完成：结果已安全返回。"
