"""
计算网关 —— T4/聚合指令白名单校验(不信任模型自由输出)

安全目标:指令只能操作出站清单内令牌;越权拒绝并可入 COMPUTE_GATE 审计链。
明确不承诺:不验证指令语义合理性(如求和混入非数值),由聚合函数类型约束。
"""
from __future__ import annotations
from dataclasses import dataclass

ALLOWED_OPS = {"sum", "mean", "count", "min", "max"}
AGGREGATE_TIERS = {"T3", "T4"}


class GatewayReject(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class ComputeDirective:
    op: str
    tokens: tuple[str, ...]
    result_ref: str


def validate_directive(raw: dict, token_index: dict[str, str]) -> ComputeDirective:
    op = raw.get("op")
    if op not in ALLOWED_OPS:
        raise GatewayReject(f"op={op!r} 不在白名单 {sorted(ALLOWED_OPS)}")
    tokens = raw.get("tokens") or []
    if not tokens:
        raise GatewayReject("tokens 为空")
    for t in tokens:
        if t not in token_index:
            raise GatewayReject(f"令牌 {t} 越权:不在出站 token_index 内")
        if token_index[t] not in AGGREGATE_TIERS:
            raise GatewayReject(f"令牌 {t} 越权:tier={token_index[t]} 不允许聚合")
    return ComputeDirective(op=op, tokens=tuple(tokens), result_ref=str(raw.get("result_ref", "")))


def aggregate(op: str, values: list[int]):
    if op == "sum":   return sum(values)
    if op == "mean":  return sum(values) / len(values)
    if op == "count": return len(values)
    if op == "min":   return min(values)
    if op == "max":   return max(values)
    raise GatewayReject(f"op={op!r} 未知")
