import pytest
from pydantic import ValidationError
from app.schemas import (TokenRef, FilePayload, OutboundRequest,
                         build_outbound, verify_outbound)

def _outbound(**over):
    base = dict(
        session_id="a" * 32,
        redacted_text="患者 [NAME#a3f9b2c1d0e4f5a6b7c8d9e0f1a2b3c4] 就诊",
        file_payloads=[],
        token_index=[TokenRef(token="a3f9b2c1d0e4f5a6b7c8d9e0f1a2b3c4",
                              type="NAME", tier="T1", leak_class="频率可见")],
        override_events=[],
        nonce="b" * 32,
        timestamp="2026-10-11T00:00:00.000000Z",
    )
    base.update(over)
    return build_outbound(**base)

def test_extra_field_forbidden():
    with pytest.raises(ValidationError):
        OutboundRequest(**{**_outbound().model_dump(), "evil": 1})

def test_schema_version_constant():
    assert _outbound().schema_version == "CG/2.0"

def test_verify_pass():
    req = _outbound()
    assert verify_outbound(req, k_t1=b"k" * 32, session_salt=b"s" * 16) == []

def test_verify_catches_smuggled_token():        # 网关规则 1:文本令牌 ⊆ token_index
    req = _outbound(redacted_text="外挂 [FAKE#deadbeef] 令牌")
    assert any("不在 token_index" in v for v in verify_outbound(req, b"k" * 32, b"s" * 16))

def test_verify_catches_input_hash_mismatch():   # 网关规则 3
    req = _outbound()
    req.input_hash = "0" * 64
    assert any("input_hash" in v for v in verify_outbound(req, b"k" * 32, b"s" * 16))

def test_file_payload_evidence_has_no_content():
    with pytest.raises(ValidationError):
        FilePayload(file_ref="f_01", filename_token="x", content_tier="evidence",
                    redacted_content="泄漏!", file_content_hash=None, file_hash="f" * 64)
