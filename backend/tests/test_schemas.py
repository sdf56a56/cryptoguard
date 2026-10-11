import pytest
from pydantic import ValidationError
from app.schemas import (TokenRef, FilePayload, OutboundRequest,
                         build_outbound, verify_outbound)
from app.tokenchain import file_content_hash as _fch

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

# —— T1 形态样例:26 位小写 base32 全量令牌 + 10 字符显示前缀 ——
TOK26 = "aaaaabbbbbcccccddddd222222"
DISP10 = TOK26[:10]                     # "aaaaabbbbb" —— 正文真实显示形态
ROGUE26 = "zzzzzyyyyyxxxxxwwwwwvvvvvv"  # 伪造令牌,与 TOK26 无前缀/全等关系

def _outbound_t1(**over):
    base = dict(
        session_id="a" * 32,
        redacted_text=f"患者 [NAME#{DISP10}] 就诊",
        file_payloads=[],
        token_index=[TokenRef(token=TOK26, type="NAME", tier="T1",
                              leak_class="频率可见")],
        override_events=[],
        nonce="b" * 32,
        timestamp="2026-10-11T00:00:00.000000Z",
    )
    base.update(over)
    return build_outbound(**base)

def _viol(req):
    return verify_outbound(req, b"k" * 32, b"s" * 16)

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

# =====================================================================
# Fix round 1(裁定 R24)—— 网关规则 1:前缀感知白名单 + 裸/全角形态
# =====================================================================

def test_display_prefix_token_is_whitelisted():
    # 真实形态:正文只出现 10 字符显示前缀,token_index 存 26 字符全量令牌
    assert _viol(_outbound_t1()) == []

def test_verify_catches_bare_smuggled_token():
    # 裸 26 位小写 base32 令牌(无括号)也须过白名单
    req = _outbound_t1(redacted_text=f"外挂 {ROGUE26} 令牌")
    assert any("不在 token_index" in v for v in _viol(req))

def test_verify_catches_fullwidth_bracket_smuggled_token():
    # 全角括号 ［TYPE#tok］ 归一化为 ASCII 后同样进闸(封堵绕过)
    req = _outbound_t1(redacted_text="外挂 ［FAKE#deadbeef］ 令牌")
    assert any("不在 token_index" in v for v in _viol(req))

def test_prefix_reference_ruling_r24():
    # 裁定 R24:TYPE 匹配时,真令牌的任意前缀(含 5 字符前缀)是对
    # 同一令牌的合法引用(显示形态本身即 10 字符前缀)
    good = _outbound_t1(redacted_text=f"患者 [NAME#{TOK26[:5]}] 就诊")
    assert _viol(good) == []
    # 前缀不命中任何真令牌 → 伪造前缀引用,违规
    bad = _outbound_t1(redacted_text=f"患者 [NAME#{ROGUE26[:5]}] 就诊")
    assert any("不在 token_index" in v for v in _viol(bad))

# =====================================================================
# Fix round 1(裁定 R24)—— 网关规则 3:readable 文件哈希恒按内容重算
# =====================================================================

def test_verify_catches_stale_file_content_hash():
    # 改文件内容但保留旧声明哈希 → file_content_hash 失配(BIND-3/SEC-ATK-7)
    req = _outbound_t1(file_payloads=[dict(
        file_ref="f_01", filename_token="[FNAME#cafebabe]", content_tier="readable",
        redacted_content="偷换后的内容", file_content_hash=_fch("原始内容"),
        file_hash="f" * 64)])
    assert any("file_content_hash" in v for v in _viol(req))

def test_verify_catches_tampered_file_content():
    # 出站后中途偷换 redacted_content(声明哈希失配,且 input_hash 打穿)
    req = _outbound_t1(file_payloads=[dict(
        file_ref="f_01", filename_token="[FNAME#cafebabe]", content_tier="readable",
        redacted_content="原始内容", file_content_hash=_fch("原始内容"),
        file_hash="f" * 64)])
    req.file_payloads[0].redacted_content = "偷换内容"
    assert any("file_content_hash" in v for v in _viol(req))

def test_verify_allows_consistent_file_content_hash():
    content = "原始内容"
    req = _outbound_t1(file_payloads=[dict(
        file_ref="f_01", filename_token="[FNAME#cafebabe]", content_tier="readable",
        redacted_content=content, file_content_hash=_fch(content),
        file_hash="f" * 64)])
    assert _viol(req) == []

def test_evidence_payload_declared_hash_as_is():
    # evidence 级无内容:声明 file_content_hash 原样进 input_hash,不做内容校验
    req = _outbound_t1(file_payloads=[dict(
        file_ref="f_02", filename_token="[FNAME#cafebabe]", content_tier="evidence",
        redacted_content=None, file_content_hash="e" * 64, file_hash="f" * 64)])
    assert _viol(req) == []
