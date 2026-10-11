import pathlib

import pytest
from app.files import extract_text, route_file, evidence_bundle, MAX_FILE_BYTES
from app.crypto.aead import AeadCipher

def test_txt_extract():
    text, how = extract_text("患者张三".encode(), "a.txt")
    assert text == "患者张三"

def test_empty_text_forces_evidence():           # Review Focus #3
    text, how = extract_text(b"", "scan.pdf")
    assert text == ""
    assert route_file("scan.pdf", text) == "evidence"

def test_binary_forces_evidence():
    assert route_file("x.zip", "") == "evidence"

def test_txt_route_readable():
    assert route_file("a.txt", "有内容") == "readable"

def test_oversize_rejected():
    with pytest.raises(ValueError):
        extract_text(b"0" * (MAX_FILE_BYTES + 1), "big.txt")

def test_evidence_bundle_has_hash_and_cipher():
    b = evidence_bundle(b"\x89PNG fake", "张三的报告.png", AeadCipher())
    assert len(b["file_hash"]) == 64
    assert b["vault_ct"]["ciphertext"]           # AES-GCM 密文非空
    assert b["content_tier"] == "evidence"


# 测试样例文件(files 列表要求):从磁盘抽取 + 默认拒绝路由(附加覆盖,详见报告)
_FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "sample.txt"

def test_fixture_sample_txt_roundtrip():
    data = _FIXTURE.read_bytes()
    text, how = extract_text(data, "sample.txt")
    assert text.strip()
    assert how == "builtin"
    assert route_file("sample.txt", text) == "readable"
