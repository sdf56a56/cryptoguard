"""
密钥模块 —— HKDF 派生与 VAULT_KEY 信任根（指纹绑定）

安全目标：
  - 根密钥只存于本地（backend/.env / 进程内存），派生子密钥按用途域分隔
    （HKDF info 标签），一把子密钥泄露不影响其他用途。
  - VAULT_KEY 与历史数据强绑定：指纹文件存在而密钥缺失/变更时启动失败，
    禁止静默生成新钥顶替（否则历史密文可被悄悄遗弃或误判为损坏）。
  - 落盘生成物不含明文根密钥：.env 只存 key 本身（本地信任边界内），
    指纹文件只存 SHA-256 摘要，派生密钥均不等于根密钥。

明确不承诺：
  - 不承诺保护已失窃的 backend/.env；不承诺防持有根密钥的本地进程被攻破。
  - 不承诺侧信道/量子抗性；演示级软件实现。

归约：派生安全性归约到 HMAC-SHA256（HKDF, RFC 5869）；指纹绑定依赖
SHA-256 抗碰撞与单向性（由指纹不可反推根密钥）。
"""
from __future__ import annotations

import hashlib
import os
import re
import secrets
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

FINGERPRINT_DOMAIN = b"vault-fp/v1"
FINGERPRINT_FILENAME = "vault_key_fingerprint.txt"
_ENV_PATH_DEFAULT = Path(__file__).resolve().parent.parent / ".env"  # backend/.env
_KEY_RE = re.compile(r"^[0-9a-f]{64}$")  # 32 字节小写十六进制


class VaultKeyError(RuntimeError):
    """VAULT_KEY 缺失/格式非法/与指纹不符等信任根错误，均 fail-closed。"""


def hkdf_sha256(root: bytes, info: str, length: int = 32) -> bytes:
    """HKDF-SHA256（RFC 5869）：从根密钥 root 派生 length 字节子密钥。

    info 为用途域分隔标签（如 "mapping/v1"），相同 root+info 派生结果确定，
    info 不同则输出相互独立。
    """
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=info.encode("utf-8"),
    ).derive(root)


def fingerprint_of(key_bytes: bytes) -> str:
    """VAULT_KEY 指纹：sha256("vault-fp/v1" || key) 的十六进制摘要。"""
    return hashlib.sha256(FINGERPRINT_DOMAIN + key_bytes).hexdigest()


def _load_env_file(path: Path) -> dict[str, str]:
    """手工解析 .env（简单 KEY=VALUE 行），仓库无 dotenv 依赖。"""
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        values[k.strip()] = v.strip()
    return values


def _read_vault_key(env_path: Path) -> str:
    """读取 VAULT_KEY：os.environ 优先，缺省回退 backend/.env；空值视为缺失。"""
    raw = os.environ.get("VAULT_KEY", "").strip()
    if not raw:
        raw = _load_env_file(env_path).get("VAULT_KEY", "").strip()
    return raw


def _write_env_key(env_path: Path, key_hex: str) -> None:
    """将 VAULT_KEY 写入 .env：已有行原地替换，缺行追加，文件缺失则创建。"""
    line = f"VAULT_KEY={key_hex}"
    if env_path.is_file():
        lines = env_path.read_text(encoding="utf-8").splitlines()
        for i, existing in enumerate(lines):
            if existing.split("=", 1)[0].strip() == "VAULT_KEY":
                lines[i] = line
                break
        else:
            lines.append(line)
        text = "\n".join(lines) + "\n"
    else:
        text = line + "\n"
    env_path.parent.mkdir(parents=True, exist_ok=True)
    env_path.write_text(text, encoding="utf-8")


class Vault:
    """信任根封装：持有四把派生子密钥与指纹，不保留根密钥明文。"""

    def __init__(
        self,
        mapping_key: bytes,
        reasoning_key: bytes,
        chain_mac_key: bytes,
        demo_chain_mac_key: bytes,
        fingerprint: str,
        llm_config_key: bytes | None = None,
    ) -> None:
        self.mapping_key = mapping_key
        self.reasoning_key = reasoning_key
        self.chain_mac_key = chain_mac_key
        self.demo_chain_mac_key = demo_chain_mac_key
        self.fingerprint = fingerprint
        #: LLM API Key 落盘加密子密钥。缺省由 chain_mac_key 二次派生，
        #: 仅供 ctor 直注入的测试夹具使用；生产路径由 load_or_init 用根密钥派生。
        self.llm_config_key = (
            llm_config_key if llm_config_key is not None
            else hkdf_sha256(chain_mac_key, "llm-config/v1")
        )

    @classmethod
    def load_or_init(cls, data_dir: Path, env_path: Path | None = None) -> "Vault":
        """加载或首次初始化信任根，按启动规则 fail-closed。

        规则（顺序即判定顺序）：
          (a) 指纹在而 key 缺失/空 → VaultKeyError（禁止静默生成）；
          (b) key 在且指纹在但不符 → VaultKeyError("密钥已变更，历史数据将不可解封")；
          (c) key 在而指纹缺失 → data/ 有 *.ndjson（历史数据）则拒绝，否则补写指纹继续；
          (d) 两者皆无 → 首次生成：key 写 .env、指纹写 data/vault_key_fingerprint.txt；
          (e) 两者皆在且相符 → 正常加载。

        env_path 缺省为 backend/.env；参数仅供测试隔离，生产调用无需传。
        """
        env_path = _ENV_PATH_DEFAULT if env_path is None else env_path
        fp_file = data_dir / FINGERPRINT_FILENAME
        key_hex = _read_vault_key(env_path)
        fp_exists = fp_file.is_file()

        if fp_exists and not key_hex:
            raise VaultKeyError(
                "指纹文件存在但 VAULT_KEY 缺失，禁止静默生成；"
                "请恢复原密钥（backend/.env）后再启动"
            )

        if key_hex:
            if not _KEY_RE.fullmatch(key_hex):
                raise VaultKeyError("VAULT_KEY 格式非法：必须为 64 位小写十六进制（32 字节）")
            key_bytes = bytes.fromhex(key_hex)
            fp = fingerprint_of(key_bytes)
            if fp_exists:
                stored = fp_file.read_text(encoding="utf-8").strip()
                if stored != fp:
                    raise VaultKeyError("密钥已变更，历史数据将不可解封")
            else:
                if any(data_dir.rglob("*.ndjson")):
                    raise VaultKeyError(
                        "指纹文件缺失但存在历史数据（*.ndjson），"
                        "无法确认 VAULT_KEY 与历史数据同源，拒绝启动"
                    )
                data_dir.mkdir(parents=True, exist_ok=True)
                fp_file.write_text(fp + "\n", encoding="utf-8")
        else:
            key_hex = secrets.token_bytes(32).hex()
            key_bytes = bytes.fromhex(key_hex)
            fp = fingerprint_of(key_bytes)
            # 先落钥再落指纹：中途崩溃后重启走规则 (c)，无历史数据可自愈
            _write_env_key(env_path, key_hex)
            data_dir.mkdir(parents=True, exist_ok=True)
            fp_file.write_text(fp + "\n", encoding="utf-8")

        return cls(
            mapping_key=hkdf_sha256(key_bytes, "mapping/v1"),
            reasoning_key=hkdf_sha256(key_bytes, "reasoning/v1"),
            chain_mac_key=hkdf_sha256(key_bytes, "chain-mac/v1"),
            demo_chain_mac_key=hkdf_sha256(key_bytes, "chain-mac/demo/v1"),
            fingerprint=fp,
            llm_config_key=hkdf_sha256(key_bytes, "llm-config/v1"),
        )
