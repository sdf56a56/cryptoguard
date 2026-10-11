"""
Pydantic 数据模型
"""
from __future__ import annotations

import re
from typing import Annotated, Any, Literal, Optional

from pydantic import BaseModel, Field, ConfigDict, model_validator

from .canon import canon
from .tokenchain import (token_chain, override_hash,
                         input_hash as _input_hash,
                         input_hash_preimage,
                         file_content_hash as _file_content_hash)
from .tokens import t1_pseudonym


class DetectRequest(BaseModel):
    model_config = ConfigDict(protected_namespaces=())
    text: str
    scenario: str = "medical"  # medical / financial
    mode: Optional[str] = None  # placeholder / mask / hash


class PolicyUpdate(BaseModel):
    model_config = ConfigDict(protected_namespaces=())
    mode: Optional[str] = None
    enabled_types: Optional[list[str]] = None


class DetectResponse(BaseModel):
    original: str
    redacted: str
    entities: list[dict]
    mapping: dict[str, str]


class QueryRequest(BaseModel):
    text: str
    scenario: str = "medical"
    attributes: Optional[list[str]] = None  # 用户属性，用于 CP-ABE 授权
    attack: Optional[str] = None  # tamper / replay / forge_cert / tamper_log / repudiate


class VerifyResult(BaseModel):
    layer: str
    ok: bool
    detail: str


class QueryResponse(BaseModel):
    model_config = ConfigDict(protected_namespaces=())
    request_id: str
    status: str  # verified / rejected
    redacted_input: str
    model_output: str
    restored_output: str
    input_hash: str
    nonce: str
    timestamp: str
    model_cert: dict
    response_hash: str
    signature: str
    signature_valid: bool
    cert_valid: bool
    nonce_valid: bool
    verification: list[VerifyResult]
    pipeline: list[dict]  # 流水线各步骤（含耗时）
    attack: Optional[str] = None
    attack_result: Optional[str] = None


class SSESearchRequest(BaseModel):
    keyword: str


class HEStatsRequest(BaseModel):
    values: list[int]


class ZKPRequest(BaseModel):
    aux: str = "CryptoGuard"


# =====================================================================
# CG/2.0 —— 分级令牌出站 Schema(spec §3.2)+ 网关校验
#
# 强约束:extra="forbid";出站包由 build_outbound 后端模板拼装,
# 调用方不得自由构造(字段不来自自由文本拼接)。
# =====================================================================

_Hex32 = Annotated[str, Field(pattern=r"^[0-9a-f]{32}$")]
_Hex64 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
_IsoUtcMicro = Annotated[str, Field(
    pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")]

# 出站令牌显示格式:[TYPE#token],用于网关规则 1 的正文/文件扫描
_TOKEN_REF_RE = re.compile(r"\[([A-Za-z0-9_]+)#([^\]#\s]+)\]")


class TokenRef(BaseModel):
    """出站令牌索引条目 —— 网关白名单全集(spec §3.2)。"""
    model_config = ConfigDict(extra="forbid")

    token: str
    type: str
    tier: Literal["T1", "T2", "T3", "T4"]
    leak_class: str


class OverrideEvent(BaseModel):
    """USER_OVERRIDE 决策事件(不可抵赖,哈希进 input_hash,spec §3.5)。"""
    model_config = ConfigDict(extra="forbid")

    event_id: str
    entity_span: Annotated[list[int], Field(min_length=2, max_length=2)]
    entity_type: str
    original_token: str
    action: Literal["force_allow", "manual_replace", "force_redact"]
    replacement: Optional[str] = None
    user_ack: bool
    ts: str


class FilePayload(BaseModel):
    """文件双通道载荷(spec §2.2/§2.3):evidence 级恒不可读。"""
    model_config = ConfigDict(extra="forbid")

    file_ref: str
    filename_token: str
    content_tier: Literal["readable", "evidence"]
    redacted_content: Optional[str] = None
    file_content_hash: Optional[_Hex64] = None
    file_hash: _Hex64

    @model_validator(mode="after")
    def _evidence_has_no_content(self):
        if self.content_tier == "evidence" and self.redacted_content is not None:
            raise ValueError(
                "evidence 级文件禁止携带 redacted_content(存证通道零可读承诺)")
        return self


class OutboundRequest(BaseModel):
    """出站请求(spec §3.2,后端模板拼装,禁 extra)。

    canonical_preimage 为 R8 本地展示字段(input_hash 的精确前映像),
    不参与 input_hash 计算。
    """
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["CG/2.0"] = "CG/2.0"
    session_id: _Hex32
    redacted_text: str
    file_payloads: list[FilePayload] = Field(default_factory=list, max_length=8)
    token_index: list[TokenRef] = Field(default_factory=list)
    override_events: list[OverrideEvent] = Field(default_factory=list)
    token_root: _Hex64
    input_hash: _Hex64
    nonce: _Hex32
    timestamp: _IsoUtcMicro
    canonical_preimage: str = ""


class ComputeDirectiveModel(BaseModel):
    """计算网关结构化指令(spec §3.4,枚举白名单)。"""
    model_config = ConfigDict(extra="forbid")

    op: Literal["sum", "mean", "count", "min", "max"]
    tokens: list[str]
    result_ref: str


def build_outbound(*, session_id: str, redacted_text: str,
                   file_payloads: list, token_index: list,
                   override_events: list, nonce: str,
                   timestamp: str) -> OutboundRequest:
    """出站包唯一拼装入口(后端模板)。

    内部计算 token_root(token_chain)、override_hash、readable 文件的
    file_content_hash、input_hash,并按 R8 附带 canonical_preimage(展示用,
    不参与 input_hash)。
    """
    fps = [p if isinstance(p, FilePayload) else FilePayload(**p)
           for p in file_payloads]
    tis = [t if isinstance(t, TokenRef) else TokenRef(**t)
           for t in token_index]
    ovs = [e if isinstance(e, OverrideEvent) else OverrideEvent(**e)
           for e in override_events]

    root = token_chain(session_id, [(t.type, t.token) for t in tis])
    ov_h = override_hash([e.model_dump() for e in ovs])
    fhashes = [p.file_content_hash or _file_content_hash(p.redacted_content or "")
               for p in fps if p.content_tier == "readable"]
    preimage = input_hash_preimage(redacted_text, fhashes, root, ov_h,
                                   nonce, timestamp)
    ih = _input_hash(redacted_text, fhashes, root, ov_h, nonce, timestamp)
    return OutboundRequest(
        schema_version="CG/2.0",
        session_id=session_id,
        redacted_text=redacted_text,
        file_payloads=fps,
        token_index=tis,
        override_events=ovs,
        token_root=root,
        input_hash=ih,
        nonce=nonce,
        timestamp=timestamp,
        canonical_preimage=canon(preimage).decode("utf-8"),
    )


def verify_outbound(req: OutboundRequest, k_t1: bytes, session_salt: bytes,
                    token_values: dict[str, tuple[str, str]] | None = None) -> list[str]:
    """网关三规则(spec §3.2),返回违规列表(空=放行)。

    1. 正文/文件中出现的所有令牌 ⊆ token_index;
    2. T1 令牌 HMAC 重算与声明一致(仅当提供 token_values:token -> (type, value));
    3. input_hash 从请求字段重算一致。
    """
    violations: list[str] = []

    # 规则 1:正文/文件令牌 ⊆ token_index(防中间层塞私货令牌)
    known = {t.token for t in req.token_index}
    texts = [req.redacted_text]
    texts += [p.redacted_content for p in req.file_payloads
              if p.redacted_content is not None]
    seen: set[str] = set()
    for text in texts:
        for _typ, tok in _TOKEN_REF_RE.findall(text):
            if tok not in known and tok not in seen:
                seen.add(tok)
                violations.append(f"令牌 {tok} 不在 token_index")

    # 规则 2:T1 HMAC 重算(仅在提供 token_values 时,且仅对 T1 令牌)
    if token_values is not None:
        for t in req.token_index:
            if t.tier != "T1":
                continue
            entry = token_values.get(t.token)
            if entry is None:
                continue
            typ, value = entry
            if t1_pseudonym(k_t1, typ, value, session_salt) != t.token:
                violations.append(f"令牌 {t.token} HMAC 与声明不一致")

    # 规则 3:input_hash 重算一致(出站包未被偷换)
    fhashes = [p.file_content_hash or _file_content_hash(p.redacted_content or "")
               for p in req.file_payloads if p.content_tier == "readable"]
    root = token_chain(req.session_id, [(t.type, t.token) for t in req.token_index])
    ov_h = override_hash([e.model_dump() for e in req.override_events])
    if _input_hash(req.redacted_text, fhashes, root, ov_h,
                   req.nonce, req.timestamp) != req.input_hash:
        violations.append("input_hash 重算不一致")

    return violations
