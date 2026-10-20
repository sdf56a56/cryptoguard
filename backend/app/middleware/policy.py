"""
策略合成 —— 服务端默认值 + 管理员授予的客户端额度 + 客户端请求指令 → 本次生效策略

铁律:**不可信输入只能收紧,不能放宽**。
  - 保护模式:三者取「最强」(`placeholder < token < encrypt`),客户端无法把
    encrypt 降回 placeholder;
  - 还原白名单:先取「服务端默认 ∪ 管理员为该客户端显式授予」,再与客户端请求
    求交;任何一步都不会把 NEVER_AUTO_RESTORE_TYPES 里的高风险类别放进来;
  - 还原模式:客户端只能在「不比服务端更宽松」的方向上调整
    (`off < confirm < categories < auto`);
  - block_on:客户端只能调得更严,不能调松;
  - 越界一律抛显式错误(不是静默降级),且错误信息里只说明「不允许」,不回显
    服务端完整策略细节。

明确不承诺:
  - 不承诺识别所有越权尝试的意图(仅按上述四条硬规则拦截);
  - 不承诺客户端 key 的分配策略本身合理(那是管理员职责)。
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

from .config import Settings
from .errors import MiddlewareError
from .openai_schemas import CryptoGuardDirectiveIn
from .protection import (MODE_ENCRYPT, MODE_PLACEHOLDER, MODE_TOKEN,
                         NEVER_AUTO_RESTORE_TYPES)
from .restore import (RESTORE_AUTO, RESTORE_CATEGORIES, RESTORE_CONFIRM, RESTORE_OFF,
                      RestorePolicy)

logger = logging.getLogger(__name__)

#: 保护强度序(越大越强);客户端只能往强的方向走
MODE_STRENGTH = {MODE_PLACEHOLDER: 1, MODE_TOKEN: 2, MODE_ENCRYPT: 3}
_STRENGTH_TO_MODE = {v: k for k, v in MODE_STRENGTH.items()}

#: 还原宽松度序(越大越宽松);客户端只能往严的方向走
RESTORE_RANK = {RESTORE_OFF: 0, RESTORE_CONFIRM: 1, RESTORE_CATEGORIES: 2, RESTORE_AUTO: 3}
_RANK_TO_RESTORE = {v: k for k, v in RESTORE_RANK.items()}

#: 阻断强度序(越大越严):none < high < critical
_BLOCK_RANK = {"none": 0, "high": 1, "critical": 2}
_RANK_TO_BLOCK = {v: k for k, v in _BLOCK_RANK.items()}


@dataclass
class EffectivePolicy:
    """一次请求真正生效的策略(审计记录里只写这个,便于事后复现)。"""

    policy_version: str = ""
    protection_mode: str = MODE_PLACEHOLDER
    restore: RestorePolicy = field(default_factory=RestorePolicy)
    block_on: str = "critical"
    stable_tokens: bool = False
    destroy_mapping: bool = False
    #: 客户端**请求**放行的区间(仅作为审计意图记录)。**绝不**用于放行保护:
    #: 未经服务端审批的请求体不可成为「原文出站」的依据(见 confirmations.py)。
    release_requested_spans: set[tuple[int, int]] = field(default_factory=set)
    allowed_models: tuple[str, ...] = ()
    ignored_fields: list[str] = field(default_factory=list)
    adjustments: list[str] = field(default_factory=list)   # 客户端指令造成的收紧/忽略
    #: 内容面策略摘要与「显式接受但未保护」的计数（进入响应元数据与审计）
    content_policy: dict = field(default_factory=dict)
    unprotected_content: dict = field(default_factory=dict)
    dropped_content: dict = field(default_factory=dict)

    def public_view(self) -> dict:
        """对外可见的策略摘要(不含任何明文;供响应元数据与审计)。"""
        return {
            "policy_version": self.policy_version,
            "protection_mode": self.protection_mode,
            "restore_mode": self.restore.mode,
            "restore_categories": list(self.restore.categories),
            "restore_acknowledged": self.restore.acknowledged,
            "never_auto_restore": sorted(NEVER_AUTO_RESTORE_TYPES),
            "block_on": self.block_on,
            "stable_tokens": self.stable_tokens,
            "destroy_mapping": self.destroy_mapping,
            "release_requested": len(self.release_requested_spans),
            "allowed_models": list(self.allowed_models),
            "ignored_fields": list(self.ignored_fields),
            "adjustments": list(self.adjustments),
            "content_policy": dict(self.content_policy),
            "unprotected_content": dict(self.unprotected_content),
            "dropped_content": dict(self.dropped_content),
        }


def resolve_policy(settings: Settings, directive: CryptoGuardDirectiveIn | None,
                   client=None) -> EffectivePolicy:
    """合成生效策略。`client` 为 auth.ClientKey(可为 None:匿名/测试)。"""
    policy = EffectivePolicy(
        policy_version=settings.policy_version,
        protection_mode=settings.protection_mode,
        restore=RestorePolicy(mode=settings.restore_mode,
                              categories=tuple(settings.restore_categories)),
        block_on=settings.block_on,
        stable_tokens=settings.stable_tokens,
        content_policy={
            "images": settings.image_policy,
            "documents": settings.document_policy,
            "anthropic_thinking": settings.anthropic_thinking,
            "cache_control": settings.cache_control,
        },
    )

    if client is not None:
        policy.allowed_models = tuple(getattr(client, "models", ()) or ())
        client_mode = getattr(client, "protection_mode", "") or ""
        if client_mode:
            _strengthen_mode(policy, client_mode, "管理员为该客户端设定的保护模式")
        granted = tuple(getattr(client, "restore_categories", ()) or ())
        if granted:
            merged = list(dict.fromkeys((*policy.restore.categories, *granted)))
            policy.restore.categories = tuple(merged)
            policy.adjustments.append("管理员为该客户端授予了额外还原类别")

    if directive is None:
        return policy

    if directive.protection_mode:
        _strengthen_mode(policy, directive.protection_mode, "客户端请求")
    if directive.restore_mode:
        _narrow_restore_mode(policy, directive.restore_mode)
    if directive.restore_categories is not None:
        _narrow_categories(policy, directive.restore_categories)
    if directive.acknowledged:
        if policy.restore.mode != RESTORE_CONFIRM:
            raise MiddlewareError(
                "invalid_request",
                f"acknowledged 仅在 restore_mode=confirm 下有意义(当前 {policy.restore.mode})")
        policy.restore.acknowledged = True
        policy.adjustments.append("客户端已对还原操作显式确认")
    if directive.allow_spans:
        # 只登记意图,**不放行**:客户端请求体是不可信输入,不能成为原文出站的依据。
        policy.release_requested_spans = {(s.start, s.end) for s in directive.allow_spans}
        policy.adjustments.append(
            f"客户端请求放行 {len(policy.release_requested_spans)} 处命中:"
            "该请求只记入审计,实际还原必须走带身份校验的确认流程(不会直接放行)")
    if directive.destroy_mapping:
        policy.destroy_mapping = True
        policy.restore.mode = RESTORE_OFF
        policy.restore.categories = ()
        policy.adjustments.append("处理完即焚:不保留映射,响应中的令牌不可还原")
    return policy


def _strengthen_mode(policy: EffectivePolicy, requested: str, source: str) -> None:
    want = MODE_STRENGTH.get(requested)
    if want is None:
        raise MiddlewareError("invalid_request", f"未知保护模式 {requested!r}")
    current = MODE_STRENGTH.get(policy.protection_mode, 1)
    if want < current:
        raise MiddlewareError(
            "forbidden",
            f"{source}试图把保护模式降为 {requested!r},但当前策略要求至少 "
            f"{policy.protection_mode!r}:只允许加强,不允许削弱")
    if want > current:
        policy.adjustments.append(f"{source}将保护模式加强为 {requested!r}")
    policy.protection_mode = _STRENGTH_TO_MODE[want]


def _narrow_restore_mode(policy: EffectivePolicy, requested: str) -> None:
    want = RESTORE_RANK.get(requested)
    current = RESTORE_RANK.get(policy.restore.mode, 0)
    if want is None:
        raise MiddlewareError("invalid_request", f"未知还原模式 {requested!r}")
    if want > current:
        raise MiddlewareError(
            "forbidden",
            f"客户端试图把还原模式放宽为 {requested!r},但服务端策略为 "
            f"{policy.restore.mode!r}:只允许收紧")
    if want < current:
        policy.adjustments.append(f"客户端把还原模式收紧为 {requested!r}")
    policy.restore.mode = _RANK_TO_RESTORE[want]


def _narrow_categories(policy: EffectivePolicy, requested: list[str]) -> None:
    # 服务端白名单为空 = 什么都不自动还原。**不得**回退到 DEFAULT(那是放宽)。
    allowed = {c.upper() for c in policy.restore.categories}
    want = {c.upper() for c in requested}
    illegal = sorted(want - allowed)
    if illegal:
        raise MiddlewareError(
            "forbidden",
            f"客户端请求还原的策略外类别: {illegal}(服务端只允许 {sorted(allowed)})")
    policy.restore.categories = tuple(sorted(want))
    policy.adjustments.append(f"客户端把还原类别收窄为 {sorted(want)}")
