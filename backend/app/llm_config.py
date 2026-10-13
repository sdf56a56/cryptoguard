"""
LLM 配置存储 —— 前端可配置的 Provider / Base URL / Model / API Key

安全目标:
  - API Key 不落明文:落盘前经 AES-GCM 加密,密钥由 VAULT_KEY 经 HKDF
    按用途域派生(llm-config/v1),加密主密钥不与密文同处存放。
  - API Key 不回显:对外只暴露 has_key + 掩码(mask_key),完整密钥永不出后端。
  - 只服务本机单用户:配置接口无鉴权,安全边界为「本机回环 + 单用户」,
    不主张多用户隔离(项目当前无账号体系)。任何能访问该端口的主体
    等价于本机用户,部署到非可信网络前必须自行加鉴权。

明确不承诺:
  - 不承诺抵抗持有 VAULT_KEY 与数据目录的本地进程(可解密配置)。
  - 不承诺配置接口的并发写安全:单写者模型,同 store.py;写入走临时文件
    + 原子替换,避免读到半截文件。
  - 不承诺 provider 预设之外的 base_url 正确性(用户可自定义)。
"""
from __future__ import annotations

import json
import logging
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from .crypto.aead import AeadCipher

logger = logging.getLogger(__name__)

CONFIG_FILENAME = "llm_config.json"

#: Provider 预设。base_url 与 model 均以厂商官方文档为准,不臆测。
#: deepseek 的 models 为官方 API 文档列出的可调用 model ID;
#: 「显示名 → API model ID」分离保存,便于厂商改名时只改显示名。
#:
#: 核实记录(2026-10-13,api-docs.deepseek.com):
#:   - Base URL: https://api.deepseek.com(/v1 为 OpenAI SDK 兼容别名,官方推荐不带)
#:   - deepseek-flash   → DeepSeek-V4.1-Flash(1M 上下文,支持视觉与思考模式)
#:   - deepseek-v4-pro  → DeepSeek-V4-Pro-0813
#:   - deepseek-chat / deepseek-reasoner 已于 2026-07-24 下线,不要再作为默认值
#:   - 流式请求需同时带 stream_options.include_usage,否则服务端 400
PROVIDER_PRESETS: dict[str, dict] = {
    "deepseek": {
        "label": "DeepSeek",
        "base_url": "https://api.deepseek.com",
        #: 该厂商流式调用的强制附加参数(缺省会 400)
        "stream_options": {"include_usage": True},
        "models": [
            {"id": "deepseek-flash", "label": "DeepSeek V4.1 Flash"},
            {"id": "deepseek-v4-pro", "label": "DeepSeek V4 Pro"},
        ],
    },
    "openai-compatible": {
        "label": "OpenAI 兼容（自定义）",
        "base_url": "",
        "stream_options": None,
        "models": [],
    },
}

DEFAULT_PROVIDER = "deepseek"

#: 无任何配置时的默认 Base URL / Model(取 DeepSeek 官方值,不预置密钥)。
def default_base_url() -> str:
    return PROVIDER_PRESETS[DEFAULT_PROVIDER]["base_url"]


def default_model() -> str:
    models = PROVIDER_PRESETS[DEFAULT_PROVIDER]["models"]
    return models[0]["id"] if models else ""


def stream_options_for(provider: str) -> dict | None:
    """该 provider 流式调用必需的附加参数(None 表示不需要)。"""
    return (PROVIDER_PRESETS.get(provider) or {}).get("stream_options")


def label_for_model(provider: str, model: str) -> str:
    """在预设里查 model 的展示名;查不到返回空串(用户自定义模型)。"""
    for m in (PROVIDER_PRESETS.get(provider) or {}).get("models", []):
        if m["id"] == model:
            return m["label"]
    return ""


class LLMConfigError(ValueError):
    """配置非法(字段缺失/URL 不合法/provider 未知),调用方映射 400。"""


def mask_key(api_key: str) -> str:
    """API Key 掩码:保留前缀与末 4 位,中段以 *** 代替。

    过短的 key 一律全掩码,避免掩码本身泄露有效位数。
    """
    if not api_key:
        return ""
    if len(api_key) <= 10:
        return "*" * len(api_key)
    prefix = "sk-" if api_key.startswith("sk-") else api_key[:3]
    return f"{prefix}***{api_key[-4:]}"


def _validate_base_url(raw: str) -> str:
    """校验并规范化 Base URL:必须 http(s) 且带主机名(禁 query/fragment)。"""
    url = (raw or "").strip().rstrip("/")
    if not url:
        raise LLMConfigError("Base URL 不能为空")
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise LLMConfigError("Base URL 必须以 http:// 或 https:// 开头")
    if not parsed.hostname:
        raise LLMConfigError("Base URL 缺少主机名")
    if parsed.query or parsed.fragment:
        raise LLMConfigError("Base URL 不应包含查询串或片段")
    return url


@dataclass
class LLMConfig:
    """一份生效的 LLM 配置。api_key 只存在于内存,不参与任何序列化输出。"""

    provider: str = DEFAULT_PROVIDER
    base_url: str = ""
    model: str = ""
    display_name: str = ""
    api_key: str = ""

    @property
    def has_key(self) -> bool:
        return bool(self.api_key)

    @property
    def configured(self) -> bool:
        """三要素齐全才算「已配置」,缺一不发起真实调用。"""
        return bool(self.api_key and self.base_url and self.model)

    def public_view(self) -> dict:
        """对外视图:绝不含完整 api_key,只给掩码与布尔状态。"""
        return {
            "provider": self.provider,
            "base_url": self.base_url,
            "model": self.model,
            "display_name": self.display_name,
            "has_key": self.has_key,
            "key_masked": mask_key(self.api_key),
            "configured": self.configured,
        }


class LLMConfigStore:
    """配置读写:加密落盘 + 原子替换 + 进程内缓存。

    读路径:缓存未命中 → 解析 data/llm_config.json → 解密 api_key;
    首次运行无文件时回退到环境变量 API_KEY(兼容既有部署),但**不**自动写盘。
    """

    def __init__(self, data_dir: Path, cipher: AeadCipher, env_api_key: str = ""):
        self._path = Path(data_dir) / CONFIG_FILENAME
        self._cipher = cipher
        self._env_fallback = (env_api_key or "").strip()
        self._cache: LLMConfig | None = None

    # ---------------- 读 ----------------
    @property
    def path(self) -> Path:
        """落盘路径(只读;用于状态展示与测试断言)。"""
        return self._path

    @property
    def persisted(self) -> bool:
        """是否已存在落盘配置(False 表示当前密钥可能来自环境变量回退)。"""
        return self._path.is_file()

    def load(self) -> LLMConfig:
        """读当前配置(带缓存);文件缺失/损坏 → 回退默认值 + 环境变量密钥。"""
        if self._cache is not None:
            return self._cache
        cfg = self._read_file()
        if cfg is None:
            cfg = LLMConfig(
                provider=DEFAULT_PROVIDER,
                base_url=default_base_url(),
                model=default_model(),
                display_name="",
                api_key=self._env_api_key(),
            )
        self._cache = cfg
        return cfg

    def _env_api_key(self) -> str:
        """环境变量回退(仅在无落盘配置时生效)。

        os.environ 优先,其次为装配时注入的 backend/.env 取值。
        仅为兼容既有部署的只读回退,前端保存配置后即以落盘配置为准。
        """
        for name in ("DEEPSEEK_API_KEY", "LLM_API_KEY", "MIMO_API_KEY"):
            value = os.environ.get(name, "").strip()
            if value:
                return value
        return self._env_fallback

    def _read_file(self) -> LLMConfig | None:
        if not self._path.is_file():
            return None
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            logger.warning("llm_config 读取失败,按未配置处理: %s", exc)
            return None
        api_key = ""
        blob = raw.get("api_key_enc") or {}
        if blob.get("iv") and blob.get("ciphertext"):
            try:
                api_key = str(self._cipher.decrypt(blob["iv"], blob["ciphertext"]))
            except Exception as exc:  # noqa: BLE001 — 解密失败(换钥/篡改)视为无钥
                logger.warning("llm_config 密钥解密失败(换钥或密文损坏): %s", exc)
                api_key = ""
        return LLMConfig(
            provider=raw.get("provider") or DEFAULT_PROVIDER,
            base_url=raw.get("base_url") or default_base_url(),
            model=raw.get("model") or default_model(),
            display_name=raw.get("display_name") or "",
            api_key=api_key,
        )

    # ---------------- 写 ----------------
    def save(self, *, provider: str, base_url: str, model: str,
             display_name: str = "", api_key: str | None = None) -> LLMConfig:
        """保存配置。api_key=None 表示「保持原密钥不变」(前端不回显密钥)。

        校验失败抛 LLMConfigError(不落盘、不动缓存)。
        """
        if provider not in PROVIDER_PRESETS:
            raise LLMConfigError(
                f"未知 provider: {provider!r}(可选 {sorted(PROVIDER_PRESETS)})")
        url = _validate_base_url(base_url)
        model = (model or "").strip()
        if not model:
            raise LLMConfigError("Model 不能为空")

        current = self.load()
        key = current.api_key if api_key is None else api_key.strip()
        # 显示名留空时按预设标签回填(显示名与 API model ID 分开保存)
        shown = (display_name or "").strip() or label_for_model(provider, model)

        payload = {
            "provider": provider,
            "base_url": url,
            "model": model,
            "display_name": shown,
            "api_key_enc": (
                self._encrypt(key) if key else None
            ),
        }
        self._atomic_write(payload)
        self._cache = LLMConfig(provider=provider, base_url=url, model=model,
                                display_name=shown,
                                api_key=key)
        return self._cache

    def clear_key(self) -> LLMConfig:
        """清空 API Key(保留 provider/base_url/model)。"""
        current = self.load()
        return self.save(provider=current.provider, base_url=current.base_url,
                         model=current.model,
                         display_name=current.display_name, api_key="")

    def _encrypt(self, api_key: str) -> dict:
        return self._cipher.encrypt(api_key)

    def _atomic_write(self, payload: dict) -> None:
        """临时文件 + os.replace 原子替换,并尽量收紧为 0600。"""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        text = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
        fd, tmp = tempfile.mkstemp(dir=str(self._path.parent), suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(text)
            try:
                os.chmod(tmp, 0o600)
            except OSError:  # Windows 上不一定生效,不因此失败
                pass
            os.replace(tmp, self._path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def invalidate(self) -> None:
        """丢弃缓存(测试/外部改动后强制重读)。"""
        self._cache = None
