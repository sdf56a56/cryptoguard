"""
Pydantic 数据模型
"""
from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field, ConfigDict


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
