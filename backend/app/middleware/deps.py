"""
装配 —— 把配置 / 信任根 / 存储 / 提供商 / 策略 / 审计拼成一个可挂载的中间件

信任根:`data/` 目录与 `VAULT_KEY`(keys.py 的 load_or_init);所有子密钥由
HKDF 按用途域派生:
  - `client-key/v1`   客户端密钥校验材料的 pepper(见 auth.py)
  - `protection-enc/v*` 保护模式 C 的 AEAD 密钥(版本化,见 protection.py)
  - `audit-mac/v1`    审计记录级 HMAC(见 audit.py)
存储目录：`data/security/`(审计)、`data/clients/`(客户端密钥摘要)、
`data/config/`(控制台托管的上游 Provider 配置,整文件加密)。

首次启动(仅开发环境)会自动生成一个 bootstrap 客户端密钥:写文件(若配置了
CG_BOOTSTRAP_KEY_FILE)或打印到 stderr **一次**,数据库里只留 HMAC 摘要。
生产环境不自动生成(管理员用 POST /admin/clients 显式签发 + 显式撤销)。
"""
from __future__ import annotations

import logging
import sys
import threading
from dataclasses import dataclass, field
from pathlib import Path

from ..paths import default_data_dir
from ..keys import Vault
from .audit import AuditStore
from .auth import AdminAuthenticator, ClientKeyStore
from .config import Settings, enforce_effective_providers, load_settings
from .confirmations import ConfirmationStore
from .errors import MiddlewareError
from .idempotency import IdempotencyStore
from .metrics import Metrics
from .pipeline import Pipeline
from .protection import KeyRing, TokenVault
from .provider_config import (ManagedProviderStore, compose_settings_with_store,
                              managed_meta, provider_views)
from .providers.registry import ProviderRegistry, build_registry
from .ratelimit import ConcurrencyGuard, SlidingWindowLimiter
from .recognizers import DetectorConfig

logger = logging.getLogger(__name__)

__version__ = "1.0.0"


@dataclass
class MiddlewareApp:
    """中间件的全部运行时依赖(挂在 FastAPI 的 app.state.middleware 上)。"""

    settings: Settings
    vault: Vault
    registry: ProviderRegistry
    keyring: KeyRing
    token_vault: TokenVault
    audit: AuditStore
    confirmations: ConfirmationStore
    clients: ClientKeyStore
    admin: AdminAuthenticator
    limiter: SlidingWindowLimiter
    concurrency: ConcurrencyGuard
    pipeline: Pipeline
    detector: DetectorConfig = field(default_factory=DetectorConfig)
    metrics: Metrics = field(default_factory=Metrics)
    idempotency: IdempotencyStore | None = None
    bootstrap_key: str = ""      # 仅在开发环境自动生成时非空(只回显一次)
    #: 启动时的环境变量配置（托管配置合并前的基底；热生效时用于重新合成）
    base_settings: Settings | None = None
    provider_store: ManagedProviderStore | None = None
    #: 测试注入的 httpx transport；热重建 registry 时沿用
    transports: dict = field(default_factory=dict)
    #: 热切换后退役的 registry：在途请求可能仍在用，进程退出时统一关闭
    retired_registries: list = field(default_factory=list)
    provider_lock: object = field(default_factory=threading.RLock)

    # ------------------------------------------------------------------ #
    def effective_provider_views(self) -> list[dict]:
        """有效 Provider 视图（含托管配置来源与运行期密钥状态）。"""
        if self.provider_store is None:
            return _provider_views(self.settings, self.registry)
        base = self.base_settings or self.settings
        return provider_views(self.settings, self.registry, self.provider_store,
                              {p.name for p in base.providers})

    def close(self) -> None:
        """关闭当前与退役的 Provider 连接池（进程退出时调用）。"""
        seen: set[int] = set()
        for registry in [self.registry, *self.retired_registries]:
            if registry is None or id(registry) in seen:
                continue
            seen.add(id(registry))
            try:
                registry.close()
            except Exception as exc:  # noqa: BLE001 — 关闭失败不阻断退出
                logger.warning("关闭 Provider registry 失败: %s", type(exc).__name__)
        self.retired_registries.clear()

    def health(self) -> dict:
        """健康摘要:**不含任何密钥**,不调用上游(避免健康检查放大成本)。"""
        providers = self.effective_provider_views()
        try:
            chain = self.audit.verify()
            audit_view = {"records": chain["records"], "chain_intact": chain["intact"],
                          "failures": len(chain["failures"])}
        except Exception as exc:  # noqa: BLE001 — 审计损坏要在健康检查里暴露
            audit_view = {"records": 0, "chain_intact": False,
                          "error": f"audit_integrity: {type(exc).__name__}"}
        return {
            "status": "ok",
            "service": "cryptoguard-middleware",
            "version": __version__,
            "env": self.settings.env,
            "providers": providers,
            "providers_config": (managed_meta(self.provider_store)
                                 if self.provider_store is not None else {}),
            "policy": self.settings.public_policy(),
            "auth": {
                "client_keys": self.clients.count(),
                "anonymous_allowed": self.settings.allow_anonymous,
                "admin_configured": self.admin.configured,
            },
            "audit": audit_view,
            "vault": self.token_vault.stats(),
            "confirmations": self.confirmations.stats(),
            "idempotency": (self.idempotency.stats()
                            if self.idempotency is not None else {}),
            "deployment": {
                "mode": "single-process",
                "instance_lock": bool(self.settings.instance_lock),
                "note": "确认/金库/限流/审计为进程内状态；多 worker/多副本不受支持",
            },
            "content_policy": {
                "images": self.settings.image_policy,
                "documents": self.settings.document_policy,
                "anthropic_thinking": self.settings.anthropic_thinking,
                "cache_control": self.settings.cache_control,
            },
            "limits": {
                "rate_limit_per_min": self.settings.rate_limit_per_min,
                "max_concurrency": self.settings.max_concurrency,
                "max_request_bytes": self.settings.max_request_bytes,
                "sse_heartbeat_s": self.settings.sse_heartbeat_s,
            },
            "boundary": {
                "integrity": "摘要/哈希链用于检测改动;不证明模型回答的事实正确性",
                "provider_identity": "本地网关的证据不代表模型服务商的签名",
                "not_executed": "中间件不执行模型生成的工具调用,只做保护/转发/审计",
            },
        }


def build_middleware(data_dir: Path | None = None, *, settings: Settings | None = None,
                     transports: dict | None = None,
                     vault: Vault | None = None) -> MiddlewareApp:
    """按配置装配中间件(启动期调用一次)。

    `transports` 仅供测试注入 httpx.MockTransport;生产路径不传。
    """
    settings = settings or load_settings()
    data_dir = Path(data_dir or default_data_dir())
    vault = vault or Vault.load_or_init(data_dir)

    base_settings = settings
    provider_store = ManagedProviderStore(data_dir, vault,
                                          production=base_settings.production)
    settings, provider_keys = compose_settings_with_store(base_settings, provider_store)
    enforce_effective_providers(settings)
    registry = build_registry(settings, transports=transports,
                              key_overrides=provider_keys)
    keyring = KeyRing.from_vault(vault)
    token_vault = TokenVault(vault, ttl_s=settings.vault_ttl_s,
                             max_requests=settings.vault_max_requests,
                             keyring=keyring)
    audit = AuditStore.build(data_dir, vault,
                             retention_days=settings.audit_retention_days)
    confirmations = ConfirmationStore(ttl_s=settings.confirm_ttl_s,
                                      max_records=settings.confirm_max_records)
    clients = ClientKeyStore.build(data_dir, vault)
    admin = AdminAuthenticator(settings.admin_token, production=settings.production)
    detector = DetectorConfig.load(settings.detection_config_path)
    metrics = Metrics()
    idempotency = IdempotencyStore(
        vault, ttl_s=settings.idempotency_ttl_s,
        max_entries=settings.idempotency_max)
    pipeline = Pipeline(settings, registry, token_vault, audit, keyring, detector,
                        metrics=metrics)

    app = MiddlewareApp(
        settings=settings, vault=vault, registry=registry, keyring=keyring,
        token_vault=token_vault, audit=audit, confirmations=confirmations,
        clients=clients, admin=admin,
        limiter=SlidingWindowLimiter(),
        concurrency=ConcurrencyGuard(settings.max_concurrency),
        pipeline=pipeline, detector=detector, metrics=metrics,
        idempotency=idempotency,
        base_settings=base_settings, provider_store=provider_store,
        transports=dict(transports or {}),
    )
    app.bootstrap_key = _bootstrap_client(app)
    for warning in _startup_warnings(settings, registry, provider_store,
                                     base_settings):
        logger.warning("startup: %s", warning)
    return app


def _provider_views(settings: Settings, registry: ProviderRegistry) -> list[dict]:
    """静态配置视图 + 运行期实测的「当前是否取得到密钥」。"""
    live = {view["name"]: view for view in registry.health()["providers"]}
    views: list[dict] = []
    for view in settings.provider_public_view():
        info = live.get(view["name"], {})
        merged = dict(view)
        merged["has_key"] = bool(info.get("has_key", view["has_key"]))
        merged["configured"] = bool(info.get("configured", False))
        views.append(merged)
    return views


# --------------------------------------------------------------------------- #
# 启动期辅助
# --------------------------------------------------------------------------- #
def _bootstrap_client(app: MiddlewareApp) -> str:
    """开发环境首个客户端密钥(只回显一次);生产环境交由管理员签发。"""
    if app.clients.count() > 0:
        return ""
    if app.settings.production:
        logger.warning(
            "生产环境尚未创建任何客户端密钥:请用 CG_ADMIN_TOKEN 调用 "
            "POST /admin/clients 显式签发(不会自动生成)")
        return ""
    record, plaintext = app.clients.create(
        app.settings.bootstrap_client_name or "bootstrap",
        protection_mode="",
        models=[])
    target = app.settings.bootstrap_key_file
    if target:
        path = Path(target)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(plaintext + "\n", encoding="utf-8")
            logger.warning("已生成首个客户端密钥并写入 %s(请妥善保管,不要提交到 Git)", path)
        except OSError as exc:
            logger.error("写入 CG_BOOTSTRAP_KEY_FILE 失败(%s),改打印到 stderr", exc)
            target = ""
    if not target:
        # 直接写 stderr 而不是 logger:密钥不进常规日志文件
        print("\n" + "=" * 72, file=sys.stderr)
        print("CryptoGuard 已生成首个客户端密钥(仅显示这一次):", file=sys.stderr)
        print(f"  {plaintext}", file=sys.stderr)
        print(f"  客户端 id: {record.id}  名称: {record.name}", file=sys.stderr)
        print("  请设置 CG_BOOTSTRAP_KEY_FILE 或立即保存;输错需重新签发。",
              file=sys.stderr)
        print("=" * 72 + "\n", file=sys.stderr)
    return plaintext


def _startup_warnings(settings: Settings, registry: ProviderRegistry,
                      store: ManagedProviderStore | None = None,
                      base_settings: Settings | None = None) -> list[str]:
    """启动期安全提示(不影响可用性,但必须说清楚)。"""
    warnings: list[str] = []
    if settings.allow_anonymous:
        warnings.append(
            "CG_ALLOW_ANONYMOUS=1:未认证请求会消耗上游额度,仅限本机调试使用")
    if store is not None:
        env_names = {p.name for p in (base_settings or settings).providers}
        views = provider_views(settings, registry, store, env_names)
    else:
        views = _provider_views(settings, registry)
    for view in views:
        if view["type"] != "mock" and not view["has_key"]:
            if view.get("source") == "managed":
                source = "控制台托管配置未设置 API Key"
            else:
                source = f"环境变量 {view.get('key_env') or '<未指定 api_key_env>'}"
            warnings.append(
                f"提供商 {view['name']} 未配置密钥({source}):"
                "调用该提供商会 fail-closed 报错")
    for view in views:
        if view.get("trust_env"):
            warnings.append(
                f"提供商 {view['name']} 开启了 trust_env:上游请求可能经环境/系统代理,"
                "代理可见 Authorization 头与响应体,请确认该代理可信")
    if settings.protection_mode == "placeholder":
        warnings.append(
            "保护模式为 placeholder(模式 A):占位符可枚举,如需更强保证请用 token/encrypt")
    if not settings.admin_token:
        warnings.append(
            "未配置 CG_ADMIN_TOKEN:人工确认的批准接口不可用(503),"
            "被扣留的高风险数据将无法通过合法流程释放")
    if settings.confirm_ttl_s > settings.vault_ttl_s:
        warnings.append(
            f"CG_CONFIRM_TTL_S({settings.confirm_ttl_s})大于 CG_VAULT_TTL_S"
            f"({settings.vault_ttl_s}):映射先于确认过期,已批准的释放会拿不到明文"
            "(安全失败,但建议让确认有效期不超过金库 TTL)")
    if settings.detection_config_path:
        warnings.append(f"已加载自定义检测规则: {settings.detection_config_path}")
    if settings.image_policy == "pass":
        warnings.append("CG_IMAGE_POLICY=pass:图片内容不经过检测,属于显式接受的未保护面")
    if settings.document_policy == "pass":
        warnings.append("CG_DOCUMENT_POLICY=pass:文档内容不经过检测,属于显式接受的未保护面")
    if settings.metrics_public:
        warnings.append("CG_METRICS_PUBLIC=1:/metrics 可匿名访问,仅限受信网络")
    if not settings.instance_lock:
        warnings.append("CG_INSTANCE_LOCK=0:已关闭单实例锁,确认/金库/限流/审计不再有进程互斥")
    return warnings
