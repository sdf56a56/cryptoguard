"""
装配 —— 把配置 / 信任根 / 存储 / 提供商 / 策略 / 审计拼成一个可挂载的中间件

复用既有信任根:`data/` 目录与 `VAULT_KEY` 与既有平台**同一份**(keys.py 的
load_or_init),所有子密钥仍由 HKDF 按用途域派生,新增域只有:
  - `client-key/v1`   客户端密钥校验材料的 pepper(见 auth.py)
  - `protection-enc/v*` 保护模式 C 的 AEAD 密钥(版本化,见 protection.py)
  - `audit-mac/v1`    审计记录级 HMAC(见 audit.py)
新增存储目录只有 `data/security/`(审计)与 `data/clients/`(客户端密钥摘要),
不改动既有 chain/ sessions/ messages/ 的任何语义。

首次启动(仅开发环境)会自动生成一个 bootstrap 客户端密钥:写文件(若配置了
CG_BOOTSTRAP_KEY_FILE)或打印到 stderr **一次**,数据库里只留 HMAC 摘要。
生产环境不自动生成(管理员用 POST /admin/clients 显式签发 + 显式撤销)。
"""
from __future__ import annotations

import logging
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from ..bootstrap import default_data_dir
from ..keys import Vault
from .audit import AuditStore
from .auth import AdminAuthenticator, ClientKeyStore
from .config import Settings, load_settings
from .confirmations import ConfirmationStore
from .errors import MiddlewareError
from .pipeline import Pipeline
from .protection import KeyRing, TokenVault
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
    bootstrap_key: str = ""      # 仅在开发环境自动生成时非空(只回显一次)

    # ------------------------------------------------------------------ #
    def health(self) -> dict:
        """健康摘要:**不含任何密钥**,不调用上游(避免健康检查放大成本)。"""
        providers = _provider_views(self.settings, self.registry)
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
            "policy": self.settings.public_policy(),
            "auth": {
                "client_keys": self.clients.count(),
                "anonymous_allowed": self.settings.allow_anonymous,
                "admin_configured": self.admin.configured,
            },
            "audit": audit_view,
            "vault": self.token_vault.stats(),
            "confirmations": self.confirmations.stats(),
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

    registry = build_registry(settings, transports=transports,
                              key_resolvers=_llm_config_resolvers(settings, data_dir, vault))
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
    pipeline = Pipeline(settings, registry, token_vault, audit, keyring, detector)

    app = MiddlewareApp(
        settings=settings, vault=vault, registry=registry, keyring=keyring,
        token_vault=token_vault, audit=audit, confirmations=confirmations,
        clients=clients, admin=admin,
        limiter=SlidingWindowLimiter(),
        concurrency=ConcurrencyGuard(settings.max_concurrency),
        pipeline=pipeline, detector=detector,
    )
    app.bootstrap_key = _bootstrap_client(app)
    for warning in _startup_warnings(settings, registry):
        logger.warning("startup: %s", warning)
    return app


# --------------------------------------------------------------------------- #
# 上游密钥来源(复用既有平台)
# --------------------------------------------------------------------------- #
def _llm_config_resolvers(settings: Settings, data_dir: Path,
                          vault: Vault) -> dict[str, Callable[[], str]]:
    """为声明 key_source=llm-config 的提供商注入密钥解析器。

    复用既有平台的 `LLMConfigStore`(data/llm_config.json,密钥以 AES-GCM 加密落盘,
    由 VAULT_KEY 经 HKDF 派生的 llm-config/v1 子密钥保护),而不是新建一套密钥存储 ——
    这样前端「LLM 配置」页改钥后中间件立即生效,且密文与主密钥仍不同处存放。

    每次调用重读:保证改钥即时生效、不在中间件内长期持有另一份密钥副本;
    代价是一次小文件读取(相对上游推理耗时可忽略)。
    """
    names = [p.name for p in settings.providers if p.key_source == "llm-config"]
    if not names:
        return {}
    from ..crypto.aead import AeadCipher
    from ..llm_config import LLMConfigStore

    store = LLMConfigStore(Path(data_dir), AeadCipher(vault.llm_config_key))

    def resolve() -> str:
        store.invalidate()          # 丢弃缓存,读到前端最新保存的值
        return store.load().api_key

    return {name: resolve for name in names}


def _provider_views(settings: Settings, registry: ProviderRegistry) -> list[dict]:
    """静态配置视图 + 运行期实测的「当前是否取得到密钥」。

    两者必须分开:llm-config 来源的密钥在运行期才可知,静态视图只能反映启动期状态。
    """
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


def _startup_warnings(settings: Settings, registry: ProviderRegistry) -> list[str]:
    """启动期安全提示(不影响可用性,但必须说清楚)。"""
    warnings: list[str] = []
    if settings.allow_anonymous:
        warnings.append(
            "CG_ALLOW_ANONYMOUS=1:未认证请求会消耗上游额度,仅限本机调试使用")
    for view in _provider_views(settings, registry):
        if view["type"] != "mock" and not view["has_key"]:
            source = (f"环境变量 {view['key_env']}" if view["key_source"] == "env"
                      else "既有平台 LLM 配置")
            warnings.append(
                f"提供商 {view['name']} 未配置密钥({source}):"
                "调用该提供商会 fail-closed 报错")
    for view in _provider_views(settings, registry):
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
    return warnings
