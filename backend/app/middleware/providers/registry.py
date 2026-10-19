"""
提供商注册表 —— 模型名 → 提供商/上游模型 的解析与白名单

安全目标:
  - 网关主逻辑不硬编码任何厂商 URL/密钥/字段;全部经 ProviderConfig 注入;
  - 模型白名单:默认只允许路由到 CG_PROVIDERS 或控制台托管 Provider 中显式
    声明的 model;未声明模型一律 404 并列出可用模型(绝不静默转发到未知上游
    消耗费用);
  - `provider/model` 前缀语法允许显式指定提供商,但不绕过白名单。

明确不承诺:不承诺上游是否真的提供该模型(由 /v1/models 的定义与上游自身为准)。
"""
from __future__ import annotations

import logging

import httpx

from ..errors import MiddlewareError
from .anthropic import AnthropicProvider
from .base import ModelProvider, ProviderConfig
from .mock import MockProvider
from .openai_compat import OpenAICompatibleProvider

logger = logging.getLogger(__name__)

#: type → Provider 实现(新增协议只在这里加一行)
_PROVIDER_TYPES: dict[str, type[ModelProvider]] = {
    "openai-compatible": OpenAICompatibleProvider,
    "anthropic": AnthropicProvider,
    "mock": MockProvider,
}


class ProviderRegistry:
    """已装配提供商的集合 + 模型解析。"""

    def __init__(self, providers: dict[str, ModelProvider], *,
                 aliases: dict[str, str] | None = None,
                 default_provider: str = "",
                 default_model: str = "",
                 allow_unknown_models: bool = False):
        self._providers = dict(providers)
        self._aliases = dict(aliases or {})
        self.default_provider = default_provider
        self.default_model = default_model
        self.allow_unknown_models = allow_unknown_models

    # ------------------------------------------------------------------ #
    @property
    def providers(self) -> dict[str, ModelProvider]:
        return dict(self._providers)

    def get(self, name: str) -> ModelProvider:
        provider = self._providers.get(name)
        if provider is None:
            raise MiddlewareError("not_found", f"提供商 {name!r} 未配置")
        return provider

    def resolve(self, model: str) -> tuple[ModelProvider, str]:
        """客户端模型名 → (提供商, 上游模型 ID)。

        解析顺序:别名表 → `provider/model` 前缀 → 各提供商 models 白名单 →
        (allow_unknown_models 时)默认提供商直通 → 否则 404。
        """
        wanted = (model or "").strip()
        if not wanted:
            raise MiddlewareError("invalid_request", "缺少 model 字段")

        alias = self._aliases.get(wanted)
        if alias:
            wanted = alias

        if "/" in wanted:
            prefix, rest = wanted.split("/", 1)
            provider = self._providers.get(prefix)
            if provider is not None and rest:
                if not self.allow_unknown_models and provider.models and rest not in provider.models:
                    raise MiddlewareError(
                        "not_found",
                        f"模型 {rest!r} 不在提供商 {prefix!r} 的白名单内"
                        f"(可用: {list(provider.models)})")
                return provider, rest

        matches = [(p, wanted) for p in self._providers.values() if wanted in p.models]
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            names = sorted(p.name for p, _ in matches)
            raise MiddlewareError(
                "invalid_request",
                f"模型 {wanted!r} 在多个提供商中同名: {names};请用 provider/model 指定")

        if self.allow_unknown_models and self.default_provider:
            return self.get(self.default_provider), wanted

        raise MiddlewareError(
            "not_found",
            f"模型 {wanted!r} 不可用。可选: {sorted(self.list_model_ids())}"
            "(如需透传到上游任意模型,请显式设置 CG_ALLOW_UNKNOWN_MODELS=1)")

    def list_model_ids(self) -> list[str]:
        """对外暴露的模型 id(去重、稳定排序)。"""
        ids: set[str] = set(self._aliases)
        for provider in self._providers.values():
            ids.update(provider.models)
        if self.default_provider and self.default_model:
            ids.add(self.default_model)
        return sorted(ids)

    def models_view(self, *, created: int = 0) -> list[dict]:
        """OpenAI /v1/models 兼容视图。"""
        views: list[dict] = []
        for model_id in self.list_model_ids():
            try:
                provider, upstream = self.resolve(model_id)
            except MiddlewareError:
                continue
            views.append({
                "id": model_id,
                "object": "model",
                "created": created,
                "owned_by": provider.name,
                "cryptoguard": {
                    "provider": provider.name,
                    "provider_type": provider.config.type,
                    "upstream_model": upstream,
                },
            })
        return views

    def close(self) -> None:
        """释放所有提供商的连接池(进程退出时调用;单个失败不影响其余)。"""
        for provider in self._providers.values():
            try:
                provider.close()
            except Exception as exc:  # noqa: BLE001
                logger.warning("关闭提供商 %s 失败: %s", provider.name, type(exc).__name__)

    def health(self) -> dict:
        return {
            "providers": [p.health() for p in self._providers.values()],
            "default_provider": self.default_provider,
            "default_model": self.default_model,
            "allow_unknown_models": self.allow_unknown_models,
        }


def build_registry(settings, *, transports: dict[str, httpx.BaseTransport] | None = None,
                   extra_providers: dict[str, ModelProvider] | None = None,
                   key_overrides: dict[str, str] | None = None) -> ProviderRegistry:
    """按 Settings 装配注册表。

    - 密钥在启动期解析后只存在于内存：`key_overrides`（控制台托管、已解密）优先，
      其次 ProviderSettings.api_key()（环境变量 / backend/.env）；
    - 密钥缺失**不阻断装配**（便于先起服务再补密钥），但调用时由
      ModelProvider.ensure_configured() fail-closed 报 config 错误，绝不出网；
    - transports 仅供测试注入 httpx.MockTransport，生产路径不传。
    """
    transports = transports or {}
    key_overrides = key_overrides or {}
    providers: dict[str, ModelProvider] = {}
    for p in settings.providers:
        impl = _PROVIDER_TYPES.get(p.type)
        if impl is None:
            raise MiddlewareError("config", f"提供商 {p.name!r} 的 type={p.type!r} 无实现")
        managed = p.name in key_overrides
        config = ProviderConfig(
            name=p.name,
            type=p.type,
            base_url=p.base_url,
            api_key=(key_overrides.get(p.name) or "") if managed else p.api_key(),
            api_key_env=p.api_key_env,
            key_source=("managed" if managed else
                        ("env" if (p.type != "mock" and p.api_key_env) else "none")),
            models=tuple(p.models),
            display_name=p.display_name or p.name,
            timeout_connect=p.timeout_connect,
            timeout_read=p.timeout_read,
            max_retries=p.max_retries,
            trust_env=p.trust_env,
            extra_headers=dict(p.extra_headers),
            stream_options=p.stream_options,
            token_limit_field=p.token_limit_field,
        )
        kwargs = {"transport": transports[p.name]} if p.name in transports else {}
        providers[p.name] = impl(config, **kwargs)
        if not config.configured:
            logger.warning("提供商 %s 未配置完整(环境变量 %s 为空):"
                           "调用该提供商会 fail-closed 报错", p.name, p.api_key_env)
    for name, provider in (extra_providers or {}).items():
        providers[name] = provider
    return ProviderRegistry(
        providers,
        aliases=settings.model_aliases,
        default_provider=settings.default_provider,
        default_model=settings.default_model,
        allow_unknown_models=settings.allow_unknown_models,
    )
