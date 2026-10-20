"""
AEAD 模块 —— AES-GCM 对称认证加密

安全目标：
  - 机密性 (IND-CPA)：无主密钥无法从密文恢复明文。
  - 完整性/认证性 (INT-CTXT)：任何密文篡改都会导致解密失败。
  - 主密钥不出本地：映射表（占位符 -> 明文）只以密文形态落盘/传输。

明确不承诺：
  - 不承诺抵抗侧信道攻击（本实现为软件实现，未做常数时间加固）。
  - 不承诺防持有主密钥的本地进程被攻破。

归约：安全性依赖 AES 的分组密码安全性与 GCM 的认证安全，标准 NIST 认可算法。
"""
from __future__ import annotations

import os
import base64
import json

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class AeadCipher:
    """AES-GCM 封装：加解密任意 JSON 可序列化对象，输出 base64 字符串。"""

    def __init__(self, key: bytes | None = None):
        # 主密钥：256-bit，由 VAULT_KEY 经 HKDF 派生（生产路径），或测试显式注入。
        #
        # 注意这里的 None 与 b"" 语义不同：只有**显式不传**（None，演示/临时会话密钥）
        # 才随机生成；传入空字节串说明调用方以为自己在用一把真实密钥，此时必须立刻
        # 报错而不是悄悄换一把随机钥 —— 否则今天加密的数据明天再也解不开，且现场
        # 没有任何错误信号（fail-closed）。
        self._key = os.urandom(32) if key is None else key
        self._aead = AESGCM(self._key)

    def encrypt(self, data: dict | list | str) -> dict:
        """加密任意对象，返回 {iv, tag, ciphertext}（base64）。"""
        plaintext = json.dumps(data, ensure_ascii=False).encode("utf-8")
        nonce = os.urandom(12)  # GCM 建议 96-bit nonce，随机且不重用
        ct = self._aead.encrypt(nonce, plaintext, None)
        return {
            "iv": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ct).decode(),
        }

    def decrypt(self, iv_b64: str, ciphertext_b64: str):
        """解密，失败抛异常（表示密文被篡改）。"""
        nonce = base64.b64decode(iv_b64)
        ct = base64.b64decode(ciphertext_b64)
        plaintext = self._aead.decrypt(nonce, ct, None)
        return json.loads(plaintext.decode("utf-8"))
