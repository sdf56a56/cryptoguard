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

# 出站令牌文法(网关规则 1 扫描,裁定 R24,唯一正典形态):
#   显示形态 [TYPE#token]:ASCII 方括号,TYPE=[A-Za-z0-9_]+,tok=[A-Za-z0-9]+;
#   裸形态:26 位小写 base32 连续串([a-z2-7]{26},T1 全量令牌),视为无 TYPE 的令牌引用。
# 全角括号 ［］先归一化为 ASCII 再扫描(封堵全角括号绕过)。
_TOKEN_REF_RE = re.compile(r"\[([A-Za-z0-9_]+)#([A-Za-z0-9]+)\]")
_BARE_TOKEN_RE = re.compile(r"[a-z2-7]{26}")
_FW_BRACKETS = str.maketrans({"［": "[", "］": "]"})


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


# =====================================================================
# CG/2.0 API 入参(Task 14,裁定 R7)
# =====================================================================

class QueryFileRef(BaseModel):
    """query2 内联文件引用(filename + base64 内容)。"""
    model_config = ConfigDict(extra="forbid")

    filename: str
    content_b64: str


class QueryV2Request(BaseModel):
    """POST /api/proxy/query2 入参(裁定 R7,schema_version 硬约束)。"""
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["CG/2.0"]
    text: str
    scenario: str = "medical"
    files: Optional[list[QueryFileRef]] = None
    overrides: Optional[list[dict]] = None
    directive: Optional[dict] = None


class AttackInjectRequest(BaseModel):
    """POST /api/attack/inject 入参(裁定 R9 九攻击名)。"""
    model_config = ConfigDict(extra="forbid")

    attack: str


class ComputeRequest(BaseModel):
    """POST /api/gateway/compute 演示入参:指令 + 可选演示 tier/值映射。

    token_tiers 缺省 = 请求令牌全部按 T3(演示白名单);显式给出时按
    网关三规则严格校验(越权拒绝)。values 缺省 0(演示聚合值)。
    """
    model_config = ConfigDict(extra="forbid")

    op: Literal["sum", "mean", "count", "min", "max"]
    tokens: list[str]
    result_ref: str
    token_tiers: Optional[dict[str, str]] = None
    values: Optional[dict[str, int]] = None


# =====================================================================
# 聊天/查看器 API 入参(Task 9/10)
# =====================================================================

class ChatSessionCreate(BaseModel):
    """POST /api/chat/sessions 入参:title 可选(缺省"新会话")。"""
    model_config = ConfigDict(extra="forbid")

    title: Optional[str] = None


class ChatMessageRequest(BaseModel):
    """POST /api/chat/sessions/{sid}/messages 入参:SSE 单流。

    text 空白且无附件 → 400(与 run_turn 同判据);files 为 base64 内联附件。
    """
    model_config = ConfigDict(extra="forbid")

    text: str = ""
    files: Optional[list[QueryFileRef]] = None


class PreimageVerifyRequest(BaseModel):
    """POST /api/verify/preimage 入参:纯数据复算(服务端不下验证结论)。"""
    model_config = ConfigDict(extra="forbid")

    preimage: dict
    expected_hash: str


class DegradeRequest(BaseModel):
    """POST /api/acceptance/degrade 入参:三选一故障注入(network/protocol/stream)。

    kind 保留自由串:未知类别由处理层白名单校验后 400(验收⑤,不走 422)。
    """
    model_config = ConfigDict(extra="forbid")

    kind: str


def _payload_fhashes(fps: list[FilePayload]) -> list:
    """input_hash 的文件哈希序列(build_outbound 与 verify_outbound 共用同口径)。

    裁定 R24:readable 级恒按 redacted_content 重算 —— 声明的 file_content_hash
    只做一致性校验,不得覆盖内容哈希,否则"改内容留旧哈希"可绕过规则 3;
    evidence 级无内容,声明的 file_content_hash 原样进哈希序列。
    """
    out: list = []
    for p in fps:
        if p.content_tier == "readable":
            out.append(_file_content_hash(p.redacted_content or ""))
        else:
            out.append(p.file_content_hash)
    return out


def _token_whitelisted(tok: str, typ: str | None, index: list[TokenRef]) -> bool:
    """前缀感知白名单(裁定 R24):引用是索引令牌的前缀或全等才算同一令牌。

    显示形态须 TYPE 匹配;TYPE 匹配时任意长度前缀(含 5 字符前缀)是对
    同一令牌的合法引用(显示形态本身就是 10 字符前缀)。裸形态无 TYPE,
    任意 TokenRef 命中前缀/全等关系即通过。方向严格单向:只认
    t.token.startswith(tok)(引用=展示前缀),不认反向 tok.startswith(t.token)
    —— 后缀扩展([TYPE#真令牌+附加字符])是伪造引用,不得过闸。
    """
    for t in index:
        if typ is not None and t.type != typ:
            continue
        if tok == t.token or t.token.startswith(tok):
            return True
    return False


def build_outbound(*, session_id: str, redacted_text: str,
                   file_payloads: list, token_index: list,
                   override_events: list, nonce: str,
                   timestamp: str) -> OutboundRequest:
    """出站包唯一拼装入口(后端模板)。

    内部计算 token_root(token_chain)、override_hash、文件哈希序列
    (readable 级恒按 redacted_content 重算,声明 file_content_hash 不得覆盖
    内容哈希 —— 裁定 R24)、input_hash,并按 R8 附带 canonical_preimage
    (展示用,不参与 input_hash)。
    """
    fps = [p if isinstance(p, FilePayload) else FilePayload(**p)
           for p in file_payloads]
    tis = [t if isinstance(t, TokenRef) else TokenRef(**t)
           for t in token_index]
    ovs = [e if isinstance(e, OverrideEvent) else OverrideEvent(**e)
           for e in override_events]

    root = token_chain(session_id, [(t.type, t.token) for t in tis])
    ov_h = override_hash([e.model_dump() for e in ovs])
    fhashes = _payload_fhashes(fps)
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

    1. 正文/文件中出现的所有令牌 ⊆ token_index(前缀感知,裁定 R24:
       显示形态 [TYPE#tok] 与裸 26 位 base32 均视为令牌引用,
       全角括号 ［］归一化为 ASCII 后扫描;TYPE 匹配时任意前缀即合法引用);
    2. T1 令牌 HMAC 重算与声明一致(仅当提供 token_values:token -> (type, value);
       缺本地映射即违规,fail-closed;T2 FF1 复算未实现 —— 已知偏差);
    3. input_hash 从请求字段重算一致;readable 文件哈希恒按内容重算,
       声明 file_content_hash 与内容不一致即违规(裁定 R24)。
    """
    violations: list[str] = []

    # 规则 1:正文/文件令牌 ⊆ token_index(防中间层塞私货令牌)。
    # 显示形态 + 裸 26 位 base32 两种形态都进闸,全角括号归一化后扫描,
    # 白名单为前缀感知(裁定 R24)。
    texts = [req.redacted_text]
    texts += [p.redacted_content for p in req.file_payloads
              if p.redacted_content is not None]
    seen: set[str] = set()
    for text in texts:
        norm = text.translate(_FW_BRACKETS)
        for typ, tok in _TOKEN_REF_RE.findall(norm):
            if (tok not in seen
                    and not _token_whitelisted(tok, typ, req.token_index)):
                seen.add(tok)
                violations.append(f"令牌 {tok} 不在 token_index")
        for tok in _BARE_TOKEN_RE.findall(norm):
            if (tok not in seen
                    and not _token_whitelisted(tok, None, req.token_index)):
                seen.add(tok)
                violations.append(f"令牌 {tok} 不在 token_index")

    # 规则 2:T1 HMAC 重算(仅在提供 token_values 时,且仅对 T1 令牌;
    # T2 FF1 复算未实现 —— 已知偏差,见 docs/ACCEPTANCE.md)。
    # fail-closed:token_values 已提供但令牌缺本地映射 → 违规,不得静默跳过。
    if token_values is not None:
        for t in req.token_index:
            if t.tier != "T1":
                continue
            entry = token_values.get(t.token)
            if entry is None:
                violations.append(f"令牌 {t.token} 缺少本地映射,无法复核")
                continue
            typ, value = entry
            if t1_pseudonym(k_t1, typ, value, session_salt) != t.token:
                violations.append(f"令牌 {t.token} HMAC 与声明不一致")

    # 规则 3:input_hash 重算一致(出站包未被偷换)。
    # readable 文件哈希恒按 redacted_content 重算(裁定 R24):声明的
    # file_content_hash 与内容不一致即违规,且不得参与 input_hash 重算,
    # 否则"改内容留旧声明哈希"会让 input_hash 依旧吻合(BIND-3/SEC-ATK-7)。
    for p in req.file_payloads:
        if p.content_tier != "readable":
            continue
        recomputed = _file_content_hash(p.redacted_content or "")
        if p.file_content_hash is not None and p.file_content_hash != recomputed:
            violations.append(f"文件 {p.file_ref} file_content_hash 与内容不一致")
    fhashes = _payload_fhashes(req.file_payloads)
    root = token_chain(req.session_id, [(t.type, t.token) for t in req.token_index])
    ov_h = override_hash([e.model_dump() for e in req.override_events])
    if _input_hash(req.redacted_text, fhashes, root, ov_h,
                   req.nonce, req.timestamp) != req.input_hash:
        violations.append("input_hash 重算不一致")

    return violations


# ------------------------------------------------------------------ #
# LLM 配置(设置页):Provider / Base URL / Model / API Key
# ------------------------------------------------------------------ #

class LLMConfigUpdate(BaseModel):
    """PUT /api/llm/config 入参。

    api_key 缺省(None)表示「保持已存密钥不变」——前端不回显完整密钥,
    未改动时不应重新提交;传空串表示显式清空。
    """
    model_config = ConfigDict(extra="forbid")

    provider: str
    base_url: str
    model: str
    display_name: Optional[str] = ""
    api_key: Optional[str] = None


class LLMTestRequest(BaseModel):
    """POST /api/llm/test 入参:允许用「未保存」的值先测再审。

    三字段均可省略,省略项回落到当前已保存配置;api_key 省略时用已存密钥。
    """
    model_config = ConfigDict(extra="forbid")

    base_url: Optional[str] = None
    model: Optional[str] = None
    api_key: Optional[str] = None
