"""
中间件错误类型 —— 统一错误分类 + 面向客户端的错误体映射

安全目标:
  - 错误分类显式化(auth/rate_limit/timeout/network/upstream_4xx/upstream_5xx/
    protocol/config/invalid_request/not_supported),调用方按类决策重试与提示,
    不靠字符串匹配。
  - 绝不把上游 API Key、Authorization 头、上游原始异常栈透给客户端:
    detail 只保留上游返回的 message 摘要(截断),并由 _scrub 二次过滤。

明确不承诺:不承诺上游错误文案的语义准确性(上游可能返回任意文本)。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

#: 错误类别 → 是否可安全重试(POST /chat/completions 的幂等性权衡见 openai_compat)
RETRYABLE_KINDS = frozenset({"rate_limit", "timeout", "network", "upstream_5xx"})

#: 客户端可见的错误类别 → HTTP 状态码
_HTTP_STATUS = {
    "invalid_request": 400,
    "not_supported": 400,
    #: 命中阻断档(私钥/口令等):fail-closed,拒绝转发而不是「处理一下再发」
    "blocked": 400,
    "auth": 401,
    "forbidden": 403,
    "not_found": 404,
    "conflict": 409,
    "rate_limit": 429,
    "timeout": 504,
    "network": 502,
    "upstream_4xx": 502,
    "upstream_5xx": 502,
    "protocol": 502,
    "config": 503,
    "internal": 500,
}

#: 上游错误文本里可能夹带的敏感形态,一律打码后再回给客户端
_SCRUB_PATTERNS = (
    re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._\-]{8,}"),
    re.compile(r"\bsk-[A-Za-z0-9_\-]{8,}"),
    re.compile(r"\bAKIA[0-9A-Z]{8,}"),
    re.compile(r"(?i)\b(api[-_]?key|authorization|access[-_]?token)\b\s*[:=]\s*\S+"),
)


def scrub(text: str) -> str:
    """过滤文本中可能的凭据形态(上游错误回显、日志兜底)。"""
    if not text:
        return ""
    out = text
    for pattern in _SCRUB_PATTERNS:
        out = pattern.sub(lambda m: f"{m.group(1) if m.groups() else '***'}=***", out)
    return out


@dataclass
class MiddlewareError(Exception):
    """中间件统一错误。

    kind   ∈ 见 RETRYABLE_KINDS 与 _HTTP_STATUS 的键集合
    detail 面向用户的说明(已 _scrub,不含凭据)
    upstream_status 上游 HTTP 状态(可空)
    """
    kind: str
    detail: str = ""
    upstream_status: int | None = None
    headers: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.detail = scrub(str(self.detail or self.kind))
        Exception.__init__(self, f"{self.kind}: {self.detail}")

    @property
    def retryable(self) -> bool:
        return self.kind in RETRYABLE_KINDS

    @property
    def http_status(self) -> int:
        return _HTTP_STATUS.get(self.kind, 500)

    def openai_body(self) -> dict:
        """OpenAI 兼容错误体(客户端 SDK 认这个结构)。"""
        code = self.kind
        if self.kind in ("timeout", "network", "upstream_4xx", "upstream_5xx", "protocol"):
            code = "upstream_error" if self.kind != "protocol" else "upstream_protocol_error"
        elif self.kind == "blocked":
            code = "content_blocked"
        return {
            "error": {
                "message": self.detail,
                "type": code,
                "param": None,
                "code": code,
            }
        }

    def anthropic_body(self) -> dict:
        """Anthropic 原生错误体(`{"type":"error","error":{...}}`)。"""
        mapping = {
            "invalid_request": "invalid_request_error",
            "not_supported": "invalid_request_error",
            "blocked": "invalid_request_error",
            "auth": "authentication_error",
            "forbidden": "permission_error",
            "not_found": "not_found_error",
            "conflict": "invalid_request_error",
            "rate_limit": "rate_limit_error",
            "timeout": "api_error",
            "network": "api_error",
            "upstream_4xx": "api_error",
            "upstream_5xx": "api_error",
            "protocol": "api_error",
            "config": "api_error",
            "internal": "api_error",
        }
        return {
            "type": "error",
            "error": {"type": mapping.get(self.kind, "api_error"),
                      "message": self.detail},
        }


def classify_upstream_status(status: int) -> str:
    """上游 HTTP 状态 → 中间件错误类别。"""
    if status in (401, 403):
        return "auth"
    if status == 404:
        return "not_found"
    if status == 429:
        return "rate_limit"
    if status >= 500:
        return "upstream_5xx"
    return "upstream_4xx"
