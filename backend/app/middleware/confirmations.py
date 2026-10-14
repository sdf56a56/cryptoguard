"""
人工确认 —— 高风险数据的「显式授权才能释放」流程

背景(先说清现状,不假装已有功能):
  在此之前,中间件对高风险类别只有**扣留**机制:protection.NEVER_AUTO_RESTORE_TYPES
  里的类别(私钥/口令/云密钥/连接串/身份证/银行卡/手机号/PHI/PII)无论策略怎么配
  都不会被自动还原。这保证了「未经授权不还原」,但也意味着**没有任何合法途径**把
  这些数据交回用户 —— 一个只有扣留没有放行的系统在真实业务里会被绕过。
  本模块补上那条合法途径,并且要求它必须经过:身份认证 + 权限校验 +
  请求上下文校验 + 有效期 + 一次性消费。

状态模型(唯一口径,`effective_status` 是运行时判定):

```
                (客户端申请)
                     │
                     ▼
   ┌──────────┐  管理员批准   ┌──────────┐  客户端取回一次   ┌──────────┐
   │ pending  │ ───────────► │ approved │ ───────────────► │ consumed │
   └────┬─────┘              └────┬─────┘                  └──────────┘
        │ 管理员拒绝                │ 超过 expires_epoch
        ▼                          ▼
   ┌──────────┐              ┌──────────┐
   │  denied  │              │ expired  │   (pending 超期同样 → expired)
   └──────────┘              └──────────┘
```

  - `denied` / `expired` / `consumed` 一律**安全失败**:再次调用释放接口不会
    返回任何内容(不是「重试」,是终态);
  - 状态由服务端推进,客户端只能申请与查询,**不能**自我批准 —— 批准必须持
    管理员令牌(AdminAuthenticator),没有配置管理员令牌时批准接口直接 503;
  - 凭据绑定 `(client_id, request_id, tokens, expires_epoch)`:换客户端、
    换请求、改令牌集合、过期、重放都不成立。

明确不承诺:
  - 不承诺「人类真的看过了内容」:本模块只保证**授权动作**经过认证的身份与
    显式决定,不保证审批人尽职(那是流程与制度问题);
  - 不承诺管理员不滥权:持 CG_ADMIN_TOKEN 者可批准任意待确认项,这是设计上的
    信任边界(与既有 admin 接口同级);
  - 不承诺跨进程/多副本一致:确认为进程内状态(与映射金库同一生命周期),
    多 worker 部署时需 sticky 或外部存储(与 ratelimit 的边界一致)。
"""
from __future__ import annotations

import logging
import secrets
import threading
import time
from dataclasses import dataclass, field

from .errors import MiddlewareError
from .protection import TokenVault, looks_like_token

logger = logging.getLogger(__name__)

STATUS_PENDING = "pending"
STATUS_APPROVED = "approved"
STATUS_DENIED = "denied"
STATUS_EXPIRED = "expired"
STATUS_CONSUMED = "consumed"

TERMINAL_STATUSES = frozenset({STATUS_DENIED, STATUS_EXPIRED, STATUS_CONSUMED})

#: 单次确认最多覆盖的令牌数(防御:把确认接口当批量导出通道)
MAX_TOKENS_PER_CONFIRMATION = 32
#: 客户端待确认项上限(防御:用申请把内存灌满)
MAX_PENDING_PER_CLIENT = 16


@dataclass
class Confirmation:
    """一次人工确认请求(只存令牌与元信息,**从不**存明文)。"""

    id: str
    client_id: str
    client_name: str
    request_id: str
    tokens: tuple[str, ...]
    token_types: dict[str, str] = field(default_factory=dict)
    reason: str = ""
    created_epoch: float = 0.0
    expires_epoch: float = 0.0
    status: str = STATUS_PENDING
    decided_by: str = ""
    decided_epoch: float = 0.0
    consumed_epoch: float = 0.0
    note: str = ""

    def effective_status(self, now: float | None = None) -> str:
        """运行时状态:未决/已批准但已过期 → expired(不修改存储,纯查询口径)。"""
        now = time.time() if now is None else now
        if self.status in (STATUS_PENDING, STATUS_APPROVED) and now >= self.expires_epoch:
            return STATUS_EXPIRED
        return self.status

    def public_view(self, now: float | None = None) -> dict:
        """对外视图:序号化的令牌与类别,不含明文,也不含可解出明文的材料。"""
        return {
            "confirmation_id": self.id,
            "status": self.effective_status(now),
            "request_id": self.request_id,
            "tokens": list(self.tokens),
            "token_types": dict(self.token_types),
            "token_count": len(self.tokens),
            "reason": self.reason,
            "created_epoch": self.created_epoch,
            "expires_epoch": self.expires_epoch,
            "decided_by": self.decided_by,
            "decided_epoch": self.decided_epoch,
            "consumed_epoch": self.consumed_epoch,
            "note": self.note,
            "boundary": {
                "single_use": "释放接口只能成功一次;之后状态为 consumed",
                "client_bound": "只有发起申请的客户端密钥可查询与释放",
                "admin_approval": "批准必须持管理员令牌,客户端不能自我批准",
                "not_proof_of_review": "确认只表示「有身份者显式批准过」,"
                                       "不代表内容被人工逐字审阅",
            },
        }


class ConfirmationStore:
    """人工确认请求的内存存储(有界 + TTL + 线程安全,与映射金库同生命周期)。"""

    def __init__(self, *, ttl_s: float = 900.0, max_records: int = 2048,
                 clock=time.time) -> None:
        self._ttl = max(1.0, float(ttl_s))
        self._max = max(16, int(max_records))
        self._records: dict[str, Confirmation] = {}
        self._lock = threading.Lock()
        self._clock = clock
        self._approved = 0
        self._denied = 0
        self._consumed = 0

    # ------------------------------------------------------------------ #
    @property
    def ttl_s(self) -> float:
        return self._ttl

    def create(self, *, client_id: str, client_name: str, request_id: str,
               tokens: list[str], token_types: dict[str, str],
               reason: str = "") -> Confirmation:
        """登记一次待确认请求(同一客户端对同一 (请求, 令牌集合) 幂等)。"""
        wanted = tuple(sorted(dict.fromkeys(tokens)))
        if not wanted:
            raise MiddlewareError("invalid_request", "确认申请必须至少包含一个令牌")
        if len(wanted) > MAX_TOKENS_PER_CONFIRMATION:
            raise MiddlewareError(
                "invalid_request",
                f"单次确认最多覆盖 {MAX_TOKENS_PER_CONFIRMATION} 个令牌"
                f"(实际 {len(wanted)}):请分批申请")
        now = self._clock()
        with self._lock:
            for record in self._records.values():
                if (record.client_id == client_id and record.request_id == request_id
                        and record.tokens == wanted
                        and record.effective_status(now) == STATUS_PENDING):
                    return record            # 幂等:不重复生成待确认项
            pending = sum(1 for r in self._records.values()
                          if r.client_id == client_id
                          and r.effective_status(now) == STATUS_PENDING)
            if pending >= MAX_PENDING_PER_CLIENT:
                raise MiddlewareError(
                    "rate_limit",
                    f"待确认请求过多({pending} ≥ {MAX_PENDING_PER_CLIENT}),"
                    "请等待管理员处理或让现有请求过期")
            self._sweep_locked(now)
            record = Confirmation(
                id=f"cgc-{secrets.token_hex(16)}",
                client_id=client_id, client_name=client_name,
                request_id=request_id, tokens=wanted,
                token_types={t: token_types.get(t, "") for t in wanted},
                reason=reason[:200],
                created_epoch=now, expires_epoch=now + self._ttl,
            )
            self._records[record.id] = record
            logger.warning("confirmation_created: id=%s client=%s tokens=%d",
                           record.id, client_id, len(wanted))
            return record

    def get(self, confirmation_id: str) -> Confirmation:
        with self._lock:
            record = self._records.get(confirmation_id)
        if record is None:
            raise MiddlewareError("not_found", "确认请求不存在或已清理")
        return record

    def approve(self, confirmation_id: str, *, by: str) -> Confirmation:
        """管理员批准:只有在 pending 且未过期时成立(其余一律拒绝)。"""
        with self._lock:
            record = self._require(confirmation_id)
            status = record.effective_status(self._clock())
            if status == STATUS_APPROVED:
                return record                # 幂等
            if status != STATUS_PENDING:
                raise MiddlewareError(
                    "forbidden", f"确认请求当前状态为 {status},不可批准"
                    "(仅 pending 可批准)")
            record.status = STATUS_APPROVED
            record.decided_by = by
            record.decided_epoch = self._clock()
            self._approved += 1
        logger.warning("confirmation_approved: id=%s by=%s", confirmation_id, by)
        return record

    def deny(self, confirmation_id: str, *, by: str, reason: str = "") -> Confirmation:
        """管理员拒绝(终态;后续释放一律安全失败)。"""
        with self._lock:
            record = self._require(confirmation_id)
            status = record.effective_status(self._clock())
            if status == STATUS_DENIED:
                return record
            if status != STATUS_PENDING:
                raise MiddlewareError(
                    "forbidden", f"确认请求当前状态为 {status},不可拒绝")
            record.status = STATUS_DENIED
            record.decided_by = by
            record.decided_epoch = self._clock()
            record.note = reason[:200]
            self._denied += 1
        logger.warning("confirmation_denied: id=%s by=%s", confirmation_id, by)
        return record

    def authorize_release(self, confirmation_id: str, *, client_id: str) -> Confirmation:
        """释放前的授权校验(只读,不消费):属主 + approved + 未过期。

        调用方应在**真正取到明文之后**再调用 `consume`;否则一次失败的金库读取
        会白白烧掉客户端唯一的一次释放机会。
        """
        with self._lock:
            record = self._require(confirmation_id)
        if record.client_id != client_id:
            # 不泄漏他人确认请求的状态,也不区分「不存在」与「不属于你」
            raise MiddlewareError("forbidden", "该确认请求不属于当前客户端密钥")
        status = record.effective_status(self._clock())
        if status != STATUS_APPROVED:
            raise MiddlewareError(
                "forbidden",
                f"确认请求当前状态为 {status},不可释放"
                + ("(已释放过一次,凭据已失效)" if status == STATUS_CONSUMED
                   else ";请先取得管理员批准"))
        return record

    def consume(self, confirmation_id: str, *, client_id: str) -> Confirmation:
        """标记已释放(单次使用);状态不满足时抛与 authorize_release 同口径的错误。"""
        with self._lock:
            record = self._require(confirmation_id)
            if record.client_id != client_id:
                raise MiddlewareError("forbidden", "该确认请求不属于当前客户端密钥")
            if record.effective_status(self._clock()) != STATUS_APPROVED:
                raise MiddlewareError("forbidden", "确认请求状态已变化,释放未生效")
            record.status = STATUS_CONSUMED
            record.consumed_epoch = self._clock()
            self._consumed += 1
        logger.warning("confirmation_consumed: id=%s client=%s", confirmation_id, client_id)
        return record

    def list(self, *, client_id: str = "", status: str = "", limit: int = 100) -> list[dict]:
        now = self._clock()
        with self._lock:
            records = list(self._records.values())
        out = [r.public_view(now) for r in records
               if (not client_id or r.client_id == client_id)
               and (not status or r.effective_status(now) == status)]
        out.sort(key=lambda r: r["created_epoch"], reverse=True)
        return out[:max(1, min(int(limit), 500))]

    def stats(self) -> dict:
        now = self._clock()
        with self._lock:
            records = list(self._records.values())
        pending = sum(1 for r in records if r.effective_status(now) == STATUS_PENDING)
        return {"tracked": len(records), "pending": pending, "ttl_s": self._ttl,
                "approved": self._approved, "denied": self._denied,
                "consumed": self._consumed}

    # ------------------------------------------------------------------ #
    def _require(self, confirmation_id: str) -> Confirmation:
        record = self._records.get(confirmation_id)
        if record is None:
            raise MiddlewareError("not_found", "确认请求不存在或已清理")
        return record

    def _sweep_locked(self, now: float) -> None:
        """清理长期处于终态或已过期的记录(有界内存)。"""
        stale = [cid for cid, rec in self._records.items()
                 if now - rec.created_epoch > self._ttl * 4]
        for cid in stale:
            self._records.pop(cid, None)
        while len(self._records) > self._max:
            oldest = min(self._records, key=lambda c: self._records[c].created_epoch)
            self._records.pop(oldest, None)


# --------------------------------------------------------------------------- #
# 释放(唯一把明文交回客户端的路径)
# --------------------------------------------------------------------------- #
def resolve_confirmation(confirmation: Confirmation, *, client_id: str,
                         vault: TokenVault) -> dict:
    """执行一次受控释放,返回 `{token: 明文}`。

    前置条件(全部由调用方 `ConfirmationStore.consume` 保证):已批准、未过期、
    属主匹配、且已消费(单次使用)。这里只负责:
      1. 逐令牌在金库中按 **(request_id, token)** 取回明文 —— 绝不跨请求回退;
      2. 任何一个令牌取不回来(金库过期/损坏/换钥)就**整批失败**,不做部分释放
         (部分释放会让客户端拿到一个「看起来成功但不完整」的结果)。
    """
    if confirmation.client_id != client_id:
        raise MiddlewareError("forbidden", "该确认请求不属于当前客户端密钥")
    secrets_out: dict[str, str] = {}
    missing: list[str] = []
    for token in confirmation.tokens:
        entry = vault.lookup(confirmation.request_id, token)
        if entry is None:
            missing.append(token)
            continue
        secrets_out[token] = entry.plaintext
    if missing:
        raise MiddlewareError(
            "not_found",
            f"{len(missing)} 个令牌无法从金库取回(映射已过期或被清理),"
            "本次不释放任何内容:请重新发起请求并申请确认")
    return secrets_out


def validate_requested_tokens(tokens: list[str], *, vault: TokenVault,
                              request_id: str) -> dict[str, str]:
    """校验客户端申请确认的令牌:形状合法、且确实是本请求金库中签发的。

    这一步是「确认接口不能变成令牌存在性探测器」的关键:申请者只能对自己已经
    收到的令牌提问 —— 令牌不在 (request_id) 金库里就拒绝,不区分「不存在」与
    「别人的」,错误信息统一。
    """
    if not isinstance(tokens, list) or not tokens:
        raise MiddlewareError("invalid_request", "tokens 必须是非空字符串数组")
    types: dict[str, str] = {}
    issued = vault.tokens(request_id)
    unknown: list[str] = []
    for token in tokens:
        if not isinstance(token, str) or not looks_like_token(token.strip()):
            raise MiddlewareError(
                "invalid_request", "tokens 中的元素必须是本中间件签发的令牌形态")
        cleaned = token.strip()
        if cleaned not in issued:
            unknown.append(cleaned)
            continue
        entry = vault.lookup(request_id, cleaned)
        types[cleaned] = entry.type if entry else ""
    if unknown:
        raise MiddlewareError(
            "forbidden",
            f"{len(unknown)} 个令牌不在该请求的映射金库中(伪造/跨请求/已过期),"
            "已拒绝整批申请")
    return types
