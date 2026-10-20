"""
控制台托管的上游 Provider 配置 —— 加密落盘、校验、合并与热生效

与 `config.py` 的关系:
  - `CG_PROVIDERS` 仍是「环境变量配置」的来源，适合不可变/受控部署；
  - 本模块管理「控制台配置」：管理员在控制台里增删改 Provider 与 API Key，
    保存后**不重启**即可生效；
  - 同名时托管项覆盖环境变量项；删除托管项后环境变量项恢复。

安全约束:
  - 文件整体用 AES-256-GCM 加密，密钥由 VAULT_KEY 经 HKDF 派生
    (`provider-config/v1` 用途域)；落盘文件 0600、目录 0700、原子替换；
  - API Key 只以密文落盘、只在内存中解密；任何 HTTP 响应/审计/日志/异常都
    不得包含密钥值或自定义 header 的值；
  - `VAULT_KEY` 变更会导致托管配置无法解密：启动 fail-closed，由操作者恢复
    原 `VAULT_KEY` 或移走配置文件；
  - 本模块不改变 `/v1/*` 的协议语义，只改变模型 → 上游的解析结果。

明确不承诺:
  - 不承诺抵抗持有 `VAULT_KEY` 与数据目录的本地攻击者（与现有信任边界一致）；
  - 不承诺热切换对**已在途**的请求生效：在途请求继续使用旧 registry，新请求
    使用新 registry；旧连接池在进程退出时统一关闭。
"""
from __future__ import annotations

import copy
import json
import logging
import os
import re
import threading
import time
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path

from ..crypto.aead import AeadCipher
from ..keys import Vault, hkdf_sha256
from .config import (ConfigError, ProviderSettings, Settings, _validate_base_url,
                     enforce_effective_providers)
from .errors import MiddlewareError
from .providers.registry import build_registry

logger = logging.getLogger(__name__)

CONFIG_DIR_NAME = "config"
CONFIG_FILE_NAME = "provider-config.enc.json"
CONFIG_VERSION = 1
_KEY_INFO = "provider-config/v1"
_PROVIDER_TYPES = ("openai-compatible", "anthropic", "mock")
_TOKEN_LIMIT_FIELDS = ("max_tokens", "max_completion_tokens")
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_SAMPLE_KEYS = frozenset({"sk-test", "test", "changeme", "your-api-key"})
_MAX_KEY_LEN = 8192
_MAX_MODELS = 200
_MAX_HEADERS = 50


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _as_bool(value, *, field_name: str) -> bool:
    if isinstance(value, bool):
        return value
    if value in (0, 1):
        return bool(value)
    raise MiddlewareError("invalid_request", f"{field_name} 必须是布尔值")


def _as_float(value, *, field_name: str, low: float, high: float) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        raise MiddlewareError("invalid_request", f"{field_name} 必须是数字") from None
    if not low <= number <= high:
        raise MiddlewareError("invalid_request",
                              f"{field_name} 必须在 {low:g}..{high:g} 之间")
    return number


def _as_int(value, *, field_name: str, low: int, high: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise MiddlewareError("invalid_request", f"{field_name} 必须是整数") from None
    if not low <= number <= high:
        raise MiddlewareError("invalid_request",
                              f"{field_name} 必须在 {low}..{high} 之间")
    return number


def _clean_models(value) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, (list, tuple)):
        raise MiddlewareError("invalid_request", "models 必须是字符串数组")
    out: list[str] = []
    for item in value:
        model = str(item or "").strip()
        if not model:
            continue
        if len(model) > 200:
            raise MiddlewareError("invalid_request", "单个模型名不能超过 200 字符")
        if model not in out:
            out.append(model)
    if len(out) > _MAX_MODELS:
        raise MiddlewareError("invalid_request", f"models 最多 {_MAX_MODELS} 个")
    return out


def _clean_headers(value) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise MiddlewareError("invalid_request", "extra_headers 必须是对象")
    if len(value) > _MAX_HEADERS:
        raise MiddlewareError("invalid_request", f"extra_headers 最多 {_MAX_HEADERS} 项")
    out: dict[str, str] = {}
    for key, raw in value.items():
        name = str(key or "").strip()
        if not name or not _HEADER_NAME_RE.match(name):
            raise MiddlewareError("invalid_request", f"extra_headers 含非法 header 名: {name!r}")
        text = str(raw if raw is not None else "")
        if "\r" in text or "\n" in text:
            raise MiddlewareError("invalid_request",
                                  f"extra_headers[{name!r}] 不能包含换行")
        out[name] = text
    return out


@dataclass
class ManagedProviderRecord:
    """一个由控制台管理的 Provider（密钥字段为 AEAD 密文）。"""

    name: str
    type: str = "openai-compatible"
    base_url: str = ""
    models: list[str] = field(default_factory=list)
    display_name: str = ""
    api_key_env: str = ""
    api_key_enc: dict | None = None
    extra_headers: dict = field(default_factory=dict)
    stream_options: dict | None = None
    trust_env: bool = False
    timeout_connect: float = 10.0
    timeout_read: float = 120.0
    max_retries: int = 2
    token_limit_field: str = "max_tokens"
    created: str = ""
    updated: str = ""

    def to_provider_settings(self) -> ProviderSettings:
        return ProviderSettings(
            name=self.name,
            type=self.type,
            base_url=self.base_url,
            api_key_env=self.api_key_env,
            trust_env=self.trust_env,
            models=tuple(self.models),
            display_name=self.display_name or self.name,
            timeout_connect=self.timeout_connect,
            timeout_read=self.timeout_read,
            max_retries=self.max_retries,
            extra_headers=dict(self.extra_headers),
            stream_options=copy.deepcopy(self.stream_options),
            token_limit_field=self.token_limit_field,
        )


@dataclass
class ManagedConfig:
    """托管配置的完整快照（整体加密落盘）。"""

    version: int = CONFIG_VERSION
    default_provider: str = ""
    default_model: str = ""
    providers: list[ManagedProviderRecord] = field(default_factory=list)

    @classmethod
    def from_dict(cls, raw) -> "ManagedConfig":
        if not isinstance(raw, dict):
            raise ConfigError("托管 Provider 配置格式非法：根节点必须是对象")
        try:
            version = int(raw.get("version") or CONFIG_VERSION)
        except (TypeError, ValueError):
            version = -1
        if version != CONFIG_VERSION:
            raise ConfigError(
                f"托管 Provider 配置版本不受支持: {raw.get('version')!r}")
        records: list[ManagedProviderRecord] = []
        seen: set[str] = set()
        for item in raw.get("providers") or []:
            if not isinstance(item, dict):
                raise ConfigError("托管 Provider 配置格式非法：providers 项必须是对象")
            known = {f for f in ManagedProviderRecord.__dataclass_fields__}
            record = ManagedProviderRecord(**{k: v for k, v in item.items() if k in known})
            record.name = str(record.name or "").strip()
            if not _NAME_RE.match(record.name):
                raise ConfigError(f"托管 Provider 名称非法: {record.name!r}")
            if record.name in seen:
                raise ConfigError(f"托管 Provider 名称重复: {record.name!r}")
            seen.add(record.name)
            records.append(record)
        return cls(
            version=CONFIG_VERSION,
            default_provider=str(raw.get("default_provider") or "").strip(),
            default_model=str(raw.get("default_model") or "").strip(),
            providers=records,
        )

    def to_dict(self) -> dict:
        return {
            "version": CONFIG_VERSION,
            "default_provider": self.default_provider,
            "default_model": self.default_model,
            "providers": [asdict(record) for record in self.providers],
        }

    def find(self, name: str) -> ManagedProviderRecord | None:
        for record in self.providers:
            if record.name == name:
                return record
        return None


class ManagedProviderStore:
    """托管配置的加载/校验/加密持久化。

    `candidate_*` 只返回内存候选，不写盘；`commit` 才落盘。这样路由可以按
    「校验 → 构建 registry → 落盘 → 原子切换」的顺序执行，任何一步失败都不会
    留下半生效状态。
    """

    def __init__(self, data_dir: Path, vault: Vault, *, production: bool = False):
        self._dir = Path(data_dir) / CONFIG_DIR_NAME
        self._path = self._dir / CONFIG_FILE_NAME
        self._cipher = AeadCipher(hkdf_sha256(vault.chain_mac_key, _KEY_INFO))
        self._production = bool(production)
        self._lock = threading.RLock()
        self._config = self._load()

    # ------------------------------------------------------------------ #
    # 读
    # ------------------------------------------------------------------ #
    @property
    def path(self) -> Path:
        return self._path

    @property
    def config(self) -> ManagedConfig:
        with self._lock:
            return copy.deepcopy(self._config)

    def records(self) -> list[ManagedProviderRecord]:
        with self._lock:
            return [copy.deepcopy(r) for r in self._config.providers]

    def find(self, name: str) -> ManagedProviderRecord | None:
        with self._lock:
            record = self._config.find(name)
            return copy.deepcopy(record) if record is not None else None

    def defaults(self) -> tuple[str, str]:
        with self._lock:
            return self._config.default_provider, self._config.default_model

    def decrypt_record(self, record: ManagedProviderRecord) -> str:
        """解密单条记录的密钥（供候选配置校验；返回值不得记录）。"""
        if not record.api_key_enc:
            return ""
        try:
            key = self._cipher.decrypt(str(record.api_key_enc.get("iv") or ""),
                                       str(record.api_key_enc.get("ciphertext") or ""))
        except Exception as exc:  # noqa: BLE001 — 解密失败必须 fail-closed
            raise ConfigError(
                f"托管 Provider {record.name!r} 的密钥无法解密"
                "（VAULT_KEY 已变更或配置被损坏）") from exc
        return key if isinstance(key, str) else ""

    def keys(self) -> dict[str, str]:
        """解密出托管密钥（只在内存中使用；调用方不得记录返回值）。"""
        with self._lock:
            out: dict[str, str] = {}
            for record in self._config.providers:
                key = self.decrypt_record(record)
                if key:
                    out[record.name] = key
            return out

    # ------------------------------------------------------------------ #
    # 候选（不落盘）
    # ------------------------------------------------------------------ #
    def candidate_upsert(self, payload: dict, *, name: str | None = None,
                         create: bool = False) -> ManagedConfig:
        if not isinstance(payload, dict):
            raise MiddlewareError("invalid_request", "请求体必须是 JSON 对象")
        with self._lock:
            candidate = copy.deepcopy(self._config)
        target_name = str(name or payload.get("name") or "").strip()
        if not _NAME_RE.match(target_name):
            raise MiddlewareError(
                "invalid_request",
                "Provider 名称只能包含字母、数字、点、下划线与连字符，且不超过 64 字符")
        existing = candidate.find(target_name)
        if create and existing is not None:
            raise MiddlewareError("conflict", f"托管 Provider {target_name!r} 已存在")
        if not create and existing is None:
            raise MiddlewareError(
                "not_found", f"托管 Provider {target_name!r} 不存在"
                             "（环境变量配置的 Provider 只能读取或同名覆盖）")
        record = self._validated_record(
            payload, target_name=target_name, existing=existing, create=create)
        if existing is None:
            candidate.providers.append(record)
        else:
            candidate.providers = [record if r.name == target_name else r
                                   for r in candidate.providers]
        return candidate

    def candidate_delete(self, name: str) -> ManagedConfig:
        with self._lock:
            candidate = copy.deepcopy(self._config)
        target = candidate.find(name)
        if target is None:
            raise MiddlewareError(
                "not_found", f"托管 Provider {name!r} 不存在"
                             "（环境变量配置的 Provider 不能通过管理面删除）")
        candidate.providers = [r for r in candidate.providers if r.name != name]
        if candidate.default_provider == name:
            candidate.default_provider = ""
            candidate.default_model = ""
        return candidate

    def candidate_defaults(self, provider: str, model: str) -> ManagedConfig:
        with self._lock:
            candidate = copy.deepcopy(self._config)
        candidate.default_provider = str(provider or "").strip()
        candidate.default_model = str(model or "").strip()
        return candidate

    def commit(self, candidate: ManagedConfig) -> ManagedConfig:
        """加密并原子落盘；成功后才替换内存快照。"""
        with self._lock:
            self._write(candidate)
            self._config = copy.deepcopy(candidate)
            return copy.deepcopy(candidate)

    # ------------------------------------------------------------------ #
    # 校验
    # ------------------------------------------------------------------ #
    def _validated_record(self, payload: dict, *, target_name: str,
                          existing: ManagedProviderRecord | None,
                          create: bool) -> ManagedProviderRecord:
        ptype = str(payload.get("type") or (existing.type if existing else
                                            "openai-compatible")).strip()
        if ptype not in _PROVIDER_TYPES:
            raise MiddlewareError(
                "invalid_request",
                f"type 只能是 {' | '.join(_PROVIDER_TYPES)}")

        base_url = str(payload.get("base_url") if "base_url" in payload else
                       (existing.base_url if existing else "")).strip()
        try:
            if ptype != "mock":
                base_url = _validate_base_url(base_url, target_name)
            elif base_url:
                base_url = _validate_base_url(base_url, target_name)
        except ConfigError as exc:
            # 配置校验错误在管理面是「请求参数非法」而不是「服务未装配」。
            raise MiddlewareError("invalid_request", exc.detail) from exc

        models = _clean_models(payload["models"] if "models" in payload else
                               (existing.models if existing else []))

        display_name = str(payload.get("display_name") if "display_name" in payload
                           else (existing.display_name if existing else "")).strip()
        display_name = display_name[:120] or target_name

        api_key_env = str(payload.get("api_key_env") if "api_key_env" in payload
                          else (existing.api_key_env if existing else "")).strip()
        if api_key_env and not _ENV_NAME_RE.match(api_key_env):
            raise MiddlewareError("invalid_request", "api_key_env 不是合法的环境变量名")

        enc = copy.deepcopy(existing.api_key_enc) if existing else None
        if _as_bool(payload.get("clear_api_key", False), field_name="clear_api_key"):
            enc = None
        raw_key = payload.get("api_key")
        if raw_key is not None and str(raw_key) != "":
            key = str(raw_key).strip()
            if len(key) > _MAX_KEY_LEN:
                raise MiddlewareError("invalid_request",
                                      f"API Key 长度不能超过 {_MAX_KEY_LEN}")
            if "\r" in key or "\n" in key:
                raise MiddlewareError("invalid_request", "API Key 不能包含换行")
            if self._production and key.lower() in _SAMPLE_KEYS:
                raise MiddlewareError("invalid_request", "生产环境禁止使用示例 API Key")
            enc = self._cipher.encrypt(key)

        if "extra_headers" in payload:
            extra_headers = _clean_headers(payload.get("extra_headers"))
        else:
            extra_headers = copy.deepcopy(existing.extra_headers) if existing else {}

        if "stream_options" in payload:
            stream_options = payload.get("stream_options")
            if stream_options is not None and not isinstance(stream_options, dict):
                raise MiddlewareError("invalid_request", "stream_options 必须是对象或 null")
            stream_options = copy.deepcopy(stream_options)
        else:
            stream_options = copy.deepcopy(existing.stream_options) if existing else None

        trust_env = _as_bool(
            payload.get("trust_env", existing.trust_env if existing else False),
            field_name="trust_env")
        timeout_connect = _as_float(
            payload.get("timeout_connect", existing.timeout_connect if existing else 10.0),
            field_name="timeout_connect", low=1, high=600)
        timeout_read = _as_float(
            payload.get("timeout_read", existing.timeout_read if existing else 120.0),
            field_name="timeout_read", low=1, high=600)
        max_retries = _as_int(
            payload.get("max_retries", existing.max_retries if existing else 2),
            field_name="max_retries", low=0, high=5)
        token_field = str(payload.get("token_limit_field") if "token_limit_field" in payload
                          else (existing.token_limit_field if existing else "max_tokens")).strip()
        if token_field not in _TOKEN_LIMIT_FIELDS:
            raise MiddlewareError(
                "invalid_request",
                f"token_limit_field 只能是 {' | '.join(_TOKEN_LIMIT_FIELDS)}")

        now = _now_iso()
        return ManagedProviderRecord(
            name=target_name, type=ptype, base_url=base_url, models=models,
            display_name=display_name, api_key_env=api_key_env, api_key_enc=enc,
            extra_headers=extra_headers, stream_options=stream_options,
            trust_env=trust_env, timeout_connect=timeout_connect,
            timeout_read=timeout_read, max_retries=max_retries,
            token_limit_field=token_field,
            created=(existing.created if existing and existing.created else now),
            updated=now,
        )

    # ------------------------------------------------------------------ #
    # 加解密落盘
    # ------------------------------------------------------------------ #
    def _load(self) -> ManagedConfig:
        path = self._path
        if not path.is_file():
            return ManagedConfig()
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ConfigError(
                f"托管 Provider 配置文件无法读取: {path}（{type(exc).__name__}）") from exc
        try:
            file_version = int(raw.get("version") or 0) if isinstance(raw, dict) else 0
        except (TypeError, ValueError):
            file_version = 0
        if file_version != CONFIG_VERSION:
            raise ConfigError(
                "托管 Provider 配置文件版本非法（期望 version=1）；"
                "请恢复原文件或移走它后重新配置")
        try:
            data = self._cipher.decrypt(str(raw.get("iv") or ""),
                                        str(raw.get("ciphertext") or ""))
        except Exception as exc:  # noqa: BLE001 — 解密失败必须 fail-closed
            raise ConfigError(
                f"托管 Provider 配置无法解密（VAULT_KEY 已变更或文件损坏）: {path}; "
                "请恢复原 VAULT_KEY，或移走该文件后重新在控制台配置") from exc
        config = ManagedConfig.from_dict(data)
        # 加载时也做完整校验：手工改过（或旧版本写入）的非法项不应带病启动。
        for record in config.providers:
            self._validate_loaded_record(record)
        logger.info("已加载托管 Provider 配置: %d 个（加密存储）", len(config.providers))
        return config

    def _validate_loaded_record(self, record: ManagedProviderRecord) -> None:
        if not _NAME_RE.match(record.name or ""):
            raise ConfigError(f"托管 Provider 名称非法: {record.name!r}")
        if record.type not in _PROVIDER_TYPES:
            raise ConfigError(f"托管 Provider {record.name!r} 的 type 非法: {record.type!r}")
        try:
            if record.type != "mock":
                record.base_url = _validate_base_url(record.base_url, record.name)
            record.models = _clean_models(record.models)
            record.extra_headers = _clean_headers(record.extra_headers)
        except MiddlewareError as exc:
            raise ConfigError(
                f"托管 Provider {record.name!r} 配置非法: {exc.detail}") from exc
        if not isinstance(record.api_key_enc, (dict, type(None))):
            raise ConfigError(f"托管 Provider {record.name!r} 的密钥密文格式非法")
        if record.token_limit_field not in _TOKEN_LIMIT_FIELDS:
            raise ConfigError(f"托管 Provider {record.name!r} 的 token_limit_field 非法")
        if not 0 <= int(record.max_retries) <= 5:
            raise ConfigError(f"托管 Provider {record.name!r} 的 max_retries 越界")
        if not 1 <= float(record.timeout_connect) <= 600:
            raise ConfigError(f"托管 Provider {record.name!r} 的 timeout_connect 越界")
        if not 1 <= float(record.timeout_read) <= 600:
            raise ConfigError(f"托管 Provider {record.name!r} 的 timeout_read 越界")

    def _write(self, candidate: ManagedConfig) -> None:
        try:
            self._dir.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(self._dir, 0o700)
            except OSError:  # 非 POSIX 或权限不足：不因此拒绝保存
                pass
            payload = {"version": CONFIG_VERSION,
                       **self._cipher.encrypt(candidate.to_dict())}
            text = json.dumps(payload, ensure_ascii=False)
            tmp = self._path.with_name(f".{self._path.name}.tmp-{os.getpid()}")
            with open(tmp, "w", encoding="utf-8") as handle:
                handle.write(text)
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.chmod(tmp, 0o600)
            except OSError:
                pass
            os.replace(tmp, self._path)
        except OSError as exc:
            raise MiddlewareError(
                "internal", f"托管 Provider 配置写入失败: {type(exc).__name__}") from exc


# --------------------------------------------------------------------------- #
# 合并与视图
# --------------------------------------------------------------------------- #
def compose_settings(base: Settings, managed: ManagedConfig) -> Settings:
    """环境变量配置 + 托管配置 → 生效 Settings。

    - 同名托管项覆盖环境变量项；新托管项追加；
    - 托管默认项非空时覆盖环境默认项；无效默认项回退到第一个可用项（启动期
      容错；控制台写入时由 API 显式拒绝非法值）；
    - 没有任何托管项/默认项时原样返回 `base`（保持现有部署行为不变）。
    """
    if not managed.providers and not managed.default_provider and not managed.default_model:
        return base

    env_names = {p.name for p in base.providers}
    managed_by_name = {r.name: r for r in managed.providers}
    providers: list[ProviderSettings] = []
    for provider in base.providers:
        record = managed_by_name.get(provider.name)
        providers.append(record.to_provider_settings() if record else provider)
    for record in managed.providers:
        if record.name not in env_names:
            providers.append(record.to_provider_settings())
    settings = replace(base, providers=tuple(providers))

    names = {p.name for p in providers}
    default_provider = managed.default_provider or base.default_provider
    if default_provider and default_provider not in names:
        logger.warning("托管默认 Provider %r 不存在，回退到第一个可用 Provider",
                       default_provider)
        default_provider = providers[0].name if providers else ""
    if not default_provider and providers:
        default_provider = providers[0].name
    # 只有「默认 Provider 未变」时才继承环境默认模型；换了 Provider 就必须
    # 用新 Provider 的模型，否则会把模型路由到错误上游。
    if default_provider == base.default_provider:
        default_model = managed.default_model or base.default_model
    else:
        default_model = managed.default_model
    preset = next((p for p in providers if p.name == default_provider), None)
    if preset is not None:
        allowed = set(preset.models)
        if default_model and not settings.allow_unknown_models and default_model not in allowed:
            logger.warning("默认模型 %r 不在 Provider %r 的 models 中，回退到 %r",
                           default_model, default_provider,
                           preset.models[0] if preset.models else "")
            default_model = preset.models[0] if preset.models else ""
        if not default_model and preset.models:
            default_model = preset.models[0]
    elif default_model:
        default_model = ""
    return replace(settings, default_provider=default_provider,
                   default_model=default_model)


class _CandidateStoreView:
    """把候选配置包装成 compose 所需的只读 store 形态（不落盘）。"""

    def __init__(self, store: "ManagedProviderStore", candidate: ManagedConfig):
        self._store = store
        self._candidate = candidate

    @property
    def config(self) -> ManagedConfig:
        return copy.deepcopy(self._candidate)

    def keys(self) -> dict[str, str]:
        out: dict[str, str] = {}
        for record in self._candidate.providers:
            key = self._store.decrypt_record(record)
            if key:
                out[record.name] = key
        return out

    def records(self) -> list[ManagedProviderRecord]:
        return [copy.deepcopy(r) for r in self._candidate.providers]


def compose_settings_with_store(base: Settings, store
                                ) -> tuple[Settings, dict[str, str]]:
    """从 store（或候选用 _CandidateStoreView）合成生效 Settings 与托管密钥表。"""
    keys = store.keys()
    return compose_settings(base, store.config), keys


def validate_candidate_defaults(settings: Settings, candidate: ManagedConfig) -> None:
    """控制台写入时的默认项校验：非法值必须 400，而不是静默回退。"""
    names = {p.name for p in settings.providers}
    provider = candidate.default_provider
    model = candidate.default_model
    if model and not provider:
        raise MiddlewareError("invalid_request",
                              "default_model 需要同时指定 default_provider")
    if provider and provider not in names:
        raise MiddlewareError(
            "invalid_request",
            f"default_provider={provider!r} 不存在（可选: {sorted(names)}）")
    if not provider:
        return
    preset = next(p for p in settings.providers if p.name == provider)
    if model and model not in preset.models and not settings.allow_unknown_models:
        raise MiddlewareError(
            "invalid_request",
            f"模型 {model!r} 不在 Provider {provider!r} 的 models 中"
            f"（可选: {list(preset.models)}）")


def provider_views(settings: Settings, registry, store, env_provider_names: set[str],
                   views_store=None) -> list[dict]:
    """有效 Provider 视图：静态配置 + 运行期密钥状态 + 配置来源。

    `views_store` 可以是候选 store 视图（热生效后立即回显新配置）。
    """
    live = {view["name"]: view for view in registry.health().get("providers") or []}
    managed = {r.name: r for r in (views_store or store).records()}
    views: list[dict] = []
    for provider in settings.providers:
        info = live.get(provider.name, {})
        record = managed.get(provider.name)
        views.append({
            "name": provider.name,
            "type": provider.type,
            "display_name": provider.display_name or provider.name,
            "base_url": provider.base_url,
            "models": list(provider.models),
            "has_key": bool(info.get("has_key", bool(provider.api_key())
                                     or provider.type == "mock")),
            "configured": bool(info.get("configured", False)),
            "key_env": provider.api_key_env,
            "key_source": str(info.get("key_source") or
                              ("none" if provider.type == "mock" else "env")),
            "trust_env": bool(provider.trust_env),
            "timeout_connect": provider.timeout_connect,
            "timeout_read": provider.timeout_read,
            "max_retries": provider.max_retries,
            "token_limit_field": provider.token_limit_field,
            "stream_options": provider.stream_options,
            "source": "managed" if record is not None else "env",
            "editable": record is not None,
            "overrides_env": bool(record is not None and provider.name in env_provider_names),
            "extra_header_names": sorted(record.extra_headers) if record else [],
            "created": record.created if record else "",
            "updated": record.updated if record else "",
        })
    return views


def apply_candidate(app, candidate: ManagedConfig) -> tuple[Settings, list[dict]]:
    """校验后热生效：构建新 registry → 落盘 → 原子切换。

    顺序保证：任何一步失败都不会落盘，也不会切换。调用方应持有 `app.provider_lock`。
    """
    view = _CandidateStoreView(app.provider_store, candidate)
    settings, keys = compose_settings_with_store(app.base_settings, view)
    validate_candidate_defaults(settings, candidate)
    try:
        enforce_effective_providers(settings)
    except ConfigError as exc:
        # 控制台写操作：把生产环境「至少一个 Provider」约束转成 409，而不是 503。
        raise MiddlewareError("conflict", exc.detail) from exc
    registry = build_registry(settings, transports=app.transports,
                              key_overrides=keys)
    app.provider_store.commit(candidate)
    old = app.registry
    app.settings = settings
    app.pipeline.settings = settings
    app.registry = registry
    app.pipeline.registry = registry
    if old is not None and old is not registry:
        app.retired_registries.append(old)
    views = provider_views(settings, registry, app.provider_store,
                           {p.name for p in app.base_settings.providers},
                           views_store=view)
    return settings, views


def managed_meta(store: ManagedProviderStore) -> dict:
    """配置文件的非敏感元信息（路径相对 data 目录，不含密文/密钥）。"""
    return {
        "file": f"{CONFIG_DIR_NAME}/{CONFIG_FILE_NAME}",
        "encrypted": "AES-256-GCM",
        "count": len(store.records()),
        "version": CONFIG_VERSION,
    }
