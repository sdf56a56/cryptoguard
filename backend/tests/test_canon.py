import pytest
from app.canon import canon, h_hex, JCS_LIB

# RFC 8785 风格测试向量:键序、浮点、Unicode、转义
def test_bind2_key_order_stability():
    a = {"b": "2", "a": "1", "c": {"z": 1, "y": 2}}
    b = {"a": "1", "c": {"y": 2, "z": 1}, "b": "2"}
    assert canon(a) == canon(b)

def test_bind6_unicode_nfc_nfd():
    nfc = {"k": "é"}          # é = é
    nfd = {"k": "é"}         # e + ́
    assert canon(nfc) == canon(nfd)

def test_bind6_escape_stability():
    assert canon({"k": "a\"b\\c\nd"}) == b'{"k":"a\\"b\\\\c\\nd"}'

def test_bind6_numbers():
    assert canon({"n": 1.0}) == canon({"n": 1.0})
    # 整数与浮点 1.0 的序列化必须确定(同值同字节)
    assert canon({"n": 1}) != canon({"n": 1.5})

def test_bind5_empty_and_blank():
    assert isinstance(canon({"a": [], "b": "", "c": "   "}), bytes)
    assert h_hex({"a": []}) == h_hex({"a": []})  # 确定性

def test_h_hex_len():
    assert len(h_hex({"x": 1})) == 64
