"""
中间件集中配置 —— 环境变量(CG_*)+ backend/.env,启动期一次校验

安全目标:
  - 密钥只从环境变量 / .env 读取,永不写进源码、镜像或 Git 跟踪文件;
  - 生产环境(CG_ENV=production)硬约束:必须设 CG_ADMIN_TOKEN 且禁止匿名调用
    (CG_ALLOW_ANONYMOUS 必须为 0),否则启动失败(fail-closed);
  - 上游密钥与客户端密钥严格分离:上游密钥在 ProviderSettings.api_key_env 指向的
    环境变量里,客户端密钥的校验材料只存 HMAC 摘要(见 auth.py)。

明确不承诺:
  - 不承诺保护已失窃的 .env / 进程环境(本地信任边界,同 keys.py);
  - 不承诺 CG_PROVIDERS 之外的自定义 base_url 可用性。
"""
from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from .errors import MiddlewareError
from .protection import NEVER_AUTO_RESTORE_TYPES

logger = logging.getLogger(__name__)

_ENV_PATH_DEFAULT = Path(__file__).resolve().parent.parent.parent / ".env"  # backend/.env

ENV_DEVELOPMENT = "development"
ENV_PRODUCTION = "production"

#: 保护模式别名:三种写法都接受,统一归一化为 placeholder/token/encrypt
_PROTECTION_ALIASES = {
    "placeholder": "placeholder", "a": "placeholder", "redact": "placeholder",
    "token": "token", "tokenize": "token", "b": "token",
    "encrypt": "encrypt", "encrypted": "encrypt", "c": "encrypt",
}

#: 恢复模式:off(从不恢复)/auto(按类别白名单)/categories(同 auto,显式名)/
#: confirm(仅恢复白名单类别且需客户端显式 ack) —— 默认 categories(保守)
_RESTORE_MODES = frozenset({"off", "auto", "categories", "confirm"})

#: 默认允许回填客户端的高风险类别之外的安全类别(保守:不含 PHONE/ID/CARD/密钥)
DEFAULT_RESTORE_CATEGORIES = ("EMAIL", "IP", "URL", "ORG")


class ConfigError(MiddlewareError):
    """配置非法 / 生产约束未满足;启动期 fail-fast。"""

    def __init__(self, detail: str):
        super().__init__("config", detail)


@dataclass(frozen=True)
class ProviderSettings:
    """一个上游模型提供商的配置(密钥只以「环境变量名」形式出现)。"""

    name: str
    type: str                       # openai-compatible | anthropic | mock
    base_url: str = ""
    api_key_env: str = ""           # 从哪个环境变量读密钥(空表示未知需要密钥)
    #: 是否让 httpx 采纳环境/系统代理(HTTP_PROXY、Windows 注册表代理等)。默认 False。
    #: 见 .env.example 的说明:代理可读取 Authorization 头与上游响应体。
    trust_env: bool = False
    models: tuple[str, ...] = ()
    display_name: str = ""
    timeout_connect: float = 10.0
    timeout_read: float = 120.0
    max_retries: int = 2            # 有限重试,绝不允许「无限重试」
    extra_headers: dict = field(default_factory=dict)
    stream_options: dict | None = None
    #: token 上限字段名:max_tokens(默认)或 max_completion_tokens
    token_limit_field: str = "max_tokens"

    def api_key(self) -> str:
        """当前进程环境里的上游密钥(空串 = 未配置)。"""
        if not self.api_key_env:
            return ""
        return (os.environ.get(self.api_key_env, "") or "").strip()


def _load_env_file(path: Path) -> dict[str, str]:
    """解析 .env(KEY=VALUE);复用 keys.py 同口径,避免引入新依赖。"""
    from ..keys import _load_env_file as _impl
    return _impl(path)


class _Env:
    """os.environ 优先、backend/.env 兜底的两级读取。"""

    def __init__(self, env_path: Path):
        self._file = _load_env_file(env_path)

    def get(self, name: str, default: str = "") -> str:
        value = os.environ.get(name)
        if value is None:
            value = self._file.get(name)
        if value is None:
            return default
        return str(value).strip()

    def get_int(self, name: str, default: int) -> int:
        raw = self.get(name)
        if raw == "":
            return default
        try:
            return int(raw)
        except ValueError:
            raise ConfigError(f"{name} 必须为整数,实际为 {raw!r}") from None

    def get_float(self, name: str, default: float) -> float:
        raw = self.get(name)
        if raw == "":
            return default
        try:
            return float(raw)
        except ValueError:
            raise ConfigError(f"{name} 必须为数字,实际为 {raw!r}") from None

    def get_bool(self, name: str, default: bool) -> bool:
        raw = self.get(name)
        if raw == "":
            return default
        return raw.lower() in ("1", "true", "yes", "on")

    def get_json(self, name: str, default):
        raw = self.get(name)
        if raw == "":
            return default
        try:
            return json.loads(raw)
        except ValueError as exc:
            raise ConfigError(f"{name} 不是合法 JSON: {exc}") from None

    def get_list(self, name: str, default: tuple[str, ...]) -> tuple[str, ...]:
        raw = self.get(name)
        if raw == "":
            return default
        return tuple(x.strip() for x in raw.split(",") if x.strip())


def _validate_base_url(raw: str, provider: str) -> str:
    url = (raw or "").strip().rstrip("/")
    if not url:
        raise ConfigError(f"提供商 {provider!r} 的 base_url 不能为空")
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ConfigError(f"提供商 {provider!r} 的 base_url 必须以 http(s):// 开头")
    if not parsed.hostname:
        raise ConfigError(f"提供商 {provider!r} 的 base_url 缺少主机名")
    if parsed.query or parsed.fragment:
        raise ConfigError(f"提供商 {provider!r} 的 base_url 不应含查询串或片段")
    return url


def _parse_providers(env: _Env, defaults: tuple) -> tuple[ProviderSettings, ...]:
    """CG_PROVIDERS(JSON 数组)→ ProviderSettings 列表。

    每项形如:
      {"name":"deepseek","type":"openai-compatible","base_url":"https://api.deepseek.com",
       "api_key_env":"CG_PROVIDER_DEEPSEEK_API_KEY","models":["deepseek-flash"],
       "display_name":"DeepSeek","timeout_read":180,"max_retries":2,
       "extra_headers":{},"stream_options":{"include_usage":true},"trust_env":false}

    defaults = (timeout_connect, timeout_read, max_retries, trust_env);
    未在项内显式给出的字段一律取该默认值(trust_env 默认 False,见 .env.example)。
    """
    raw = env.get_json("CG_PROVIDERS", [])
    if not isinstance(raw, list):
        raise ConfigError("CG_PROVIDERS 必须是 JSON 数组")
    d_connect, d_read, d_retries, d_trust_env = defaults
    out: list[ProviderSettings] = []
    seen: set[str] = set()
    for item in raw:
        if not isinstance(item, dict):
            raise ConfigError("CG_PROVIDERS 的每一项必须是 JSON 对象")
        name = str(item.get("name") or "").strip()
        if not name:
            raise ConfigError("CG_PROVIDERS 项缺少 name")
        if name in seen:
            raise ConfigError(f"CG_PROVIDERS 中提供商名重复: {name!r}")
        seen.add(name)
        ptype = str(item.get("type") or "openai-compatible").strip()
        if ptype not in ("openai-compatible", "anthropic", "mock"):
            raise ConfigError(
                f"提供商 {name!r} 的 type={ptype!r} 不支持"
                "(可选 openai-compatible|anthropic|mock)")
        base_url = str(item.get("base_url") or "")
        if ptype != "mock":
            base_url = _validate_base_url(base_url, name)
        models = item.get("models") or []
        if not isinstance(models, list):
            raise ConfigError(f"提供商 {name!r} 的 models 必须是数组")
        extra_headers = item.get("extra_headers") or {}
        if not isinstance(extra_headers, dict):
            raise ConfigError(f"提供商 {name!r} 的 extra_headers 必须是对象")
        stream_options = item.get("stream_options")
        if stream_options is not None and not isinstance(stream_options, dict):
            raise ConfigError(f"提供商 {name!r} 的 stream_options 必须是对象")
        token_field = str(item.get("token_limit_field") or "max_tokens").strip()
        if token_field not in ("max_tokens", "max_completion_tokens"):
            raise ConfigError(
                f"提供商 {name!r} 的 token_limit_field={token_field!r} 不支持"
                "(可选 max_tokens|max_completion_tokens)")
        if ptype != "mock" and not item.get("api_key_env"):
            #: 不强制(允许先起服务后补环境变量),但必须让操作者看得见
            logger.warning("提供商 %s 未声明 api_key_env,将无法从环境变量取得密钥", name)
        out.append(ProviderSettings(
            name=name,
            type=ptype,
            base_url=base_url,
            api_key_env=str(item.get("api_key_env") or "").strip(),
            trust_env=(bool(item["trust_env"]) if item.get("trust_env") is not None
                       else d_trust_env),
            models=tuple(str(m) for m in models),
            display_name=str(item.get("display_name") or name),
            timeout_connect=float(item.get("timeout_connect") or d_connect),
            timeout_read=float(item.get("timeout_read") or d_read),
            max_retries=int(item.get("max_retries") if item.get("max_retries") is not None
                            else d_retries),
            extra_headers={str(k): str(v) for k, v in extra_headers.items()},
            stream_options=stream_options,
            token_limit_field=token_field,
        ))
    return tuple(out)


@dataclass(frozen=True)
class Settings:
    """中间件一次性生效的全局配置。"""

    env: str = ENV_DEVELOPMENT
    host: str = "127.0.0.1"
    port: int = 8100
    admin_token: str = ""
    allow_anonymous: bool = False

    providers: tuple[ProviderSettings, ...] = ()
    default_provider: str = ""
    default_model: str = ""
    model_aliases: dict = field(default_factory=dict)   # 客户端模型名 -> provider/model
    #: 是否允许把未在 CG_PROVIDERS.models 中声明的模型名透传给默认提供商。
    #: 默认 False(白名单,避免误调用未知模型产生费用)。
    allow_unknown_models: bool = False

    protection_mode: str = "token"
    policy_version: str = "cg-policy/1"
    detection_config_path: str = ""

    restore_mode: str = "categories"
    restore_categories: tuple[str, ...] = DEFAULT_RESTORE_CATEGORIES
    #: 达到该风险等级且建议动作为 block 的命中 → 拒绝转发(none|high|critical)
    block_on: str = "critical"
    #: 模式 B 下同值是否复用同一令牌(便于模型共指,代价是等值泄漏)
    stable_tokens: bool = False
    #: 映射金库:TTL(秒)与追踪请求数上限
    vault_ttl_s: int = 3600
    vault_max_requests: int = 4096
    #: 人工确认:待确认凭据有效期(秒)与内存中追踪的确认记录上限。
    #: 有效期应 ≤ vault_ttl_s —— 金库映射先过期会让已批准的释放拿不到明文
    #: (安全失败,但属于配置不当),启动期会给出告警。
    confirm_ttl_s: int = 900
    confirm_max_records: int = 2048

    audit_retention_days: int = 30
    rate_limit_per_min: int = 600
    max_concurrency: int = 32
    max_request_bytes: int = 8_388_608
    stream_buffer_chars: int = 128
    #: 响应侧敏感检测:audit=只统计不回写(默认)| off=关闭
    response_scan: str = "audit"
    admin_readonly_token: str = ""      # 可选:只读管理员(仅能看审计/策略,不能改)
    bootstrap_client_name: str = "bootstrap"
    bootstrap_key_file: str = ""
    #: 浏览器 CORS origin 白名单(空 = 不挂 CORS);生产禁止 "*"
    cors_origins: tuple[str, ...] = ()
    #: 单实例锁:同 data 目录只允许一个网关进程(确认/金库/限流/审计均为进程内状态)
    instance_lock: bool = True
    #: 内容面策略:图片/文档默认拒绝,thinking/cache_control 默认剥离但显式登记
    image_policy: str = "reject"          # reject | pass
    document_policy: str = "reject"       # reject | pass
    anthropic_thinking: str = "strip"     # strip | reject
    cache_control: str = "strip"          # strip | reject
    #: SSE 心跳间隔(秒,0=关闭):等待上游首 token 时发 `: ping`
    sse_heartbeat_s: float = 15.0
    #: 幂等键缓存(仅非流式;内存 + AEAD 封缄)
    idempotency_ttl_s: int = 600
    idempotency_max: int = 1024
    #: 指标是否允许匿名拉取(默认仅管理员/只读管理员)
    metrics_public: bool = False
    #: 新建客户端密钥的默认有效期(天;0=永不过期)
    client_key_ttl_days: int = 0

    @property
    def production(self) -> bool:
        return self.env == ENV_PRODUCTION

    def provider(self, name: str) -> ProviderSettings | None:
        for p in self.providers:
            if p.name == name:
                return p
        return None

    def public_policy(self) -> dict:
        """对外的安全策略视图(绝不含任何密钥或密钥环境变量名之外的信息)。"""
        return {
            "policy_version": self.policy_version,
            "protection_mode": self.protection_mode,
            "restore_mode": self.restore_mode,
            "restore_categories": list(self.restore_categories),
            "never_auto_restore": sorted(NEVER_AUTO_RESTORE_TYPES),
            "block_on": self.block_on,
            "stable_tokens": self.stable_tokens,
            "rate_limit_per_min": self.rate_limit_per_min,
            "max_concurrency": self.max_concurrency,
            "max_request_bytes": self.max_request_bytes,
            "stream_buffer_chars": self.stream_buffer_chars,
            "confirm_ttl_s": self.confirm_ttl_s,
            "audit_retention_days": self.audit_retention_days,
            "response_scan": self.response_scan,
            "allow_anonymous": self.allow_anonymous,
            "image_policy": self.image_policy,
            "document_policy": self.document_policy,
            "anthropic_thinking": self.anthropic_thinking,
            "cache_control": self.cache_control,
            "sse_heartbeat_s": self.sse_heartbeat_s,
            "client_key_ttl_days": self.client_key_ttl_days,
        }

    def provider_public_view(self) -> list[dict]:
        """提供商视图:只暴露名称/类型/模型/密钥环境变量名与「是否已配置」。"""
        return [
            {
                "name": p.name,
                "type": p.type,
                "display_name": p.display_name,
                "base_url": p.base_url,
                "models": list(p.models),
                "has_key": bool(p.api_key()) or p.type == "mock",
                "key_env": p.api_key_env,
                "trust_env": p.trust_env,
            }
            for p in self.providers
        ]


def load_settings(env_path: Path | None = None) -> Settings:
    """从环境 + backend/.env 装配 Settings,并执行启动期校验。

    校验失败抛 ConfigError(lifespan 记 critical 后终止启动,fail-fast)。
    """
    env = _Env(env_path or _ENV_PATH_DEFAULT)
    app_env = env.get("CG_ENV", ENV_DEVELOPMENT).lower()
    if app_env not in (ENV_DEVELOPMENT, ENV_PRODUCTION):
        raise ConfigError(f"CG_ENV 只能为 {ENV_DEVELOPMENT} 或 {ENV_PRODUCTION}")

    defaults = (
        env.get_float("CG_UPSTREAM_TIMEOUT_CONNECT", 10.0),
        env.get_float("CG_UPSTREAM_TIMEOUT_READ", 120.0),
        env.get_int("CG_UPSTREAM_MAX_RETRIES", 2),
        #: 默认不采纳环境/系统代理:代理可读取上游 Authorization 头与响应体,
        #: 且经代理的连接超时不受我们控制(实测 Windows 上会被放大数倍)。
        env.get_bool("CG_UPSTREAM_TRUST_ENV", False),
    )
    providers = _parse_providers(env, defaults)

    mode_raw = env.get("CG_PROTECTION_MODE", "placeholder").lower()
    protection_mode = _PROTECTION_ALIASES.get(mode_raw)
    if protection_mode is None:
        raise ConfigError(
            f"CG_PROTECTION_MODE={mode_raw!r} 不支持(可选 placeholder|token|encrypt)")

    restore_mode = env.get("CG_RESTORE_MODE", "categories").lower()
    if restore_mode not in _RESTORE_MODES:
        raise ConfigError(
            f"CG_RESTORE_MODE={restore_mode!r} 不支持(可选 {'|'.join(sorted(_RESTORE_MODES))})")

    restore_categories = env.get_list("CG_RESTORE_CATEGORIES", DEFAULT_RESTORE_CATEGORIES)
    illegal = sorted(set(restore_categories) & NEVER_AUTO_RESTORE_TYPES)
    if illegal:
        raise ConfigError(
            f"CG_RESTORE_CATEGORIES 含禁止自动恢复的高风险类别: {illegal}"
            "(高风险类别只能经显式人工确认流程处理)")

    block_on = env.get("CG_BLOCK_ON", "critical").lower()
    if block_on not in ("none", "high", "critical"):
        raise ConfigError("CG_BLOCK_ON 只能为 none|high|critical")

    max_retries_default = defaults[2]
    if max_retries_default < 0 or max_retries_default > 5:
        raise ConfigError("CG_UPSTREAM_MAX_RETRIES 必须在 0..5 之间(禁止无限重试)")
    for p in providers:
        if not 0 <= p.max_retries <= 5:
            raise ConfigError(
                f"提供商 {p.name!r} 的 max_retries={p.max_retries} 越界(0..5,禁止无限重试)")

    aliases = env.get_json("CG_MODEL_ALIASES", {})
    if not isinstance(aliases, dict):
        raise ConfigError("CG_MODEL_ALIASES 必须是 JSON 对象")

    default_provider = env.get("CG_DEFAULT_PROVIDER", "")
    if not default_provider and providers:
        default_provider = providers[0].name
    if default_provider and not any(p.name == default_provider for p in providers):
        raise ConfigError(f"CG_DEFAULT_PROVIDER={default_provider!r} 不在 CG_PROVIDERS 中")

    default_model = env.get("CG_DEFAULT_MODEL", "")
    if not default_model and default_provider:
        preset = next(p for p in providers if p.name == default_provider)
        default_model = preset.models[0] if preset.models else ""

    response_scan = env.get("CG_RESPONSE_SCAN", "audit").lower()
    if response_scan not in ("audit", "off"):
        raise ConfigError("CG_RESPONSE_SCAN 只能为 audit|off")

    image_policy = env.get("CG_IMAGE_POLICY", "reject").lower()
    if image_policy not in ("reject", "pass"):
        raise ConfigError("CG_IMAGE_POLICY 只能为 reject|pass")
    document_policy = env.get("CG_DOCUMENT_POLICY", "reject").lower()
    if document_policy not in ("reject", "pass"):
        raise ConfigError("CG_DOCUMENT_POLICY 只能为 reject|pass")
    anthropic_thinking = env.get("CG_ANTHROPIC_THINKING", "strip").lower()
    if anthropic_thinking not in ("strip", "reject"):
        raise ConfigError("CG_ANTHROPIC_THINKING 只能为 strip|reject")
    cache_control = env.get("CG_CACHE_CONTROL", "strip").lower()
    if cache_control not in ("strip", "reject"):
        raise ConfigError("CG_CACHE_CONTROL 只能为 strip|reject")

    sse_heartbeat_s = env.get_float("CG_SSE_HEARTBEAT_S", 15.0)
    if sse_heartbeat_s < 0:
        raise ConfigError("CG_SSE_HEARTBEAT_S 不能为负数")
    idempotency_ttl_s = env.get_int("CG_IDEMPOTENCY_TTL_S", 600)
    if idempotency_ttl_s < 0:
        raise ConfigError("CG_IDEMPOTENCY_TTL_S 不能为负数")
    idempotency_max = env.get_int("CG_IDEMPOTENCY_MAX", 1024)
    if idempotency_max < 0:
        raise ConfigError("CG_IDEMPOTENCY_MAX 不能为负数")
    client_key_ttl_days = env.get_int("CG_CLIENT_KEY_TTL_DAYS", 0)
    if client_key_ttl_days < 0:
        raise ConfigError("CG_CLIENT_KEY_TTL_DAYS 不能为负数")

    cors_origins = env.get_list("CG_CORS_ORIGINS", ())

    confirm_ttl = env.get_int("CG_CONFIRM_TTL_S", 900)
    if confirm_ttl <= 0:
        raise ConfigError("CG_CONFIRM_TTL_S 必须为正整数(确认凭据有效期,秒)")

    rate_limit_per_min = env.get_int("CG_RATE_LIMIT_PER_MIN", 600)
    if rate_limit_per_min < 0:
        raise ConfigError("CG_RATE_LIMIT_PER_MIN 不能为负数(0 = 不限流)")
    max_concurrency = env.get_int("CG_MAX_CONCURRENCY", 32)
    if max_concurrency <= 0:
        raise ConfigError("CG_MAX_CONCURRENCY 必须为正整数")
    max_request_bytes = env.get_int("CG_MAX_REQUEST_BYTES", 8_388_608)
    if max_request_bytes < 1024:
        raise ConfigError("CG_MAX_REQUEST_BYTES 不能小于 1024")
    vault_ttl_s = env.get_int("CG_VAULT_TTL_S", 3600)
    if vault_ttl_s <= 0:
        raise ConfigError("CG_VAULT_TTL_S 必须为正整数")

    settings = Settings(
        env=app_env,
        host=env.get("CG_HOST", "127.0.0.1"),
        port=env.get_int("CG_PORT", 8100),
        admin_token=env.get("CG_ADMIN_TOKEN", ""),
        allow_anonymous=env.get_bool("CG_ALLOW_ANONYMOUS", False),
        providers=providers,
        default_provider=default_provider,
        default_model=default_model,
        model_aliases={str(k): str(v) for k, v in aliases.items()},
        allow_unknown_models=env.get_bool("CG_ALLOW_UNKNOWN_MODELS", False),
        protection_mode=protection_mode,
        policy_version=env.get("CG_POLICY_VERSION", "cg-policy/1"),
        detection_config_path=env.get("CG_DETECTION_CONFIG", ""),
        restore_mode=restore_mode,
        restore_categories=restore_categories,
        block_on=block_on,
        stable_tokens=env.get_bool("CG_STABLE_TOKENS", False),
        vault_ttl_s=vault_ttl_s,
        vault_max_requests=env.get_int("CG_VAULT_MAX_REQUESTS", 4096),
        confirm_ttl_s=confirm_ttl,
        confirm_max_records=env.get_int("CG_CONFIRM_MAX_RECORDS", 2048),
        audit_retention_days=env.get_int("CG_AUDIT_RETENTION_DAYS", 30),
        rate_limit_per_min=rate_limit_per_min,
        max_concurrency=max_concurrency,
        max_request_bytes=max_request_bytes,
        stream_buffer_chars=env.get_int("CG_STREAM_BUFFER_CHARS", 128),
        response_scan=response_scan,
        admin_readonly_token=env.get("CG_ADMIN_READONLY_TOKEN", ""),
        bootstrap_client_name=env.get("CG_BOOTSTRAP_CLIENT_NAME", "bootstrap"),
        bootstrap_key_file=env.get("CG_BOOTSTRAP_KEY_FILE", ""),
        cors_origins=cors_origins,
        instance_lock=env.get_bool("CG_INSTANCE_LOCK", True),
        image_policy=image_policy,
        document_policy=document_policy,
        anthropic_thinking=anthropic_thinking,
        cache_control=cache_control,
        sse_heartbeat_s=sse_heartbeat_s,
        idempotency_ttl_s=idempotency_ttl_s,
        idempotency_max=idempotency_max,
        metrics_public=env.get_bool("CG_METRICS_PUBLIC", False),
        client_key_ttl_days=client_key_ttl_days,
    )
    _enforce_production(settings)
    return settings


def load_cors_origins(env_path: Path | None = None) -> list[str]:
    """只读取 CORS origin 列表（不做完整配置校验，供 import 期挂中间件使用）。"""
    env = _Env(env_path or _ENV_PATH_DEFAULT)
    return [origin for origin in env.get_list("CG_CORS_ORIGINS", ()) if origin]


def _enforce_production(s: Settings) -> None:
    """生产环境硬约束:管理员令牌必设 + 禁匿名 + 禁用示例密钥。"""
    if not s.production:
        return
    if not s.admin_token or len(s.admin_token) < 16:
        raise ConfigError(
            "生产环境必须设置 CG_ADMIN_TOKEN(≥16 字符):管理员接口不接受无凭证访问")
    if s.admin_token.lower() in ("changeme", "admin", "test", "secret", "123456"):
        raise ConfigError("生产环境禁止使用示例 CG_ADMIN_TOKEN")
    if s.allow_anonymous:
        raise ConfigError("生产环境禁止 CG_ALLOW_ANONYMOUS=1(禁止匿名调用上游模型)")
    if s.admin_readonly_token:
        if len(s.admin_readonly_token) < 16:
            raise ConfigError("CG_ADMIN_READONLY_TOKEN 长度必须 ≥16 字符")
        if hmac_equal(s.admin_readonly_token, s.admin_token):
            raise ConfigError("CG_ADMIN_READONLY_TOKEN 不能与 CG_ADMIN_TOKEN 相同")
    if "*" in s.cors_origins:
        raise ConfigError("生产环境禁止 CG_CORS_ORIGINS 含通配 '*'")
    if not s.providers:
        raise ConfigError("生产环境必须至少配置一个上游提供商(CG_PROVIDERS)")
    for p in s.providers:
        if p.type == "mock":
            logger.warning("生产环境配置了 mock 提供商 %s:仅用于连通性演练", p.name)
        key = p.api_key()
        if key and key.lower() in ("sk-test", "test", "changeme", "your-api-key"):
            raise ConfigError(f"提供商 {p.name!r} 使用了示例密钥,生产环境禁止")

    # 非致命但必须让操作者看见的安全取舍
    if s.metrics_public:
        logger.warning("CG_METRICS_PUBLIC=1:/metrics 可匿名访问(仅限受信网络)")
    if not s.instance_lock:
        logger.warning("CG_INSTANCE_LOCK=0:确认/金库/限流/审计状态不再有进程互斥保护")
    if s.image_policy == "pass":
        logger.warning("CG_IMAGE_POLICY=pass:图片内容不经过检测,属于显式接受的未保护面")
    if s.document_policy == "pass":
        logger.warning("CG_DOCUMENT_POLICY=pass:文档内容不经过检测,属于显式接受的未保护面")
    if s.allow_unknown_models:
        logger.warning("CG_ALLOW_UNKNOWN_MODELS=1:未声明模型可透传到默认提供商,有费用风险")
    if s.protection_mode == "placeholder":
        logger.warning("CG_PROTECTION_MODE=placeholder:占位符可枚举,建议生产使用 token/encrypt")


def hmac_equal(left: str, right: str) -> bool:
    """常量时间比较（配置校验用；避免把长度差异当信息）。"""
    import hmac
    return hmac.compare_digest((left or "").encode("utf-8"),
                               (right or "").encode("utf-8"))
