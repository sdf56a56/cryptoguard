import pytest
from app.canon import canon, h_hex, JCS_LIB

# RFC 8785 风格测试向量:键序、浮点、Unicode、转义
def test_bind2_key_order_stability():
    a = {"b": "2", "a": "1", "c": {"z": 1, "y": 2}}
    b = {"a": "1", "c": {"y": 2, "z": 1}, "b": "2"}
    assert canon(a) == canon(b)

def test_bind6_unicode_nfc_nfd():
    nfc = {"k": "\u00e9"}          # e-acute precomposed (U+00E9)
    nfd = {"k": "\u0065\u0301"}  # e + combining acute (U+0065 U+0301)
    assert canon(nfc) == canon(nfd)

def test_cross_check_canonicaljson():
    try:
        from rfc8785 import dumps as _rfc_dumps
        from canonicaljson import encode_canonical_json as _cj_dumps
    except ImportError:  # pragma: no cover
        return  # 两库未同时安装时跳过交叉校验
    simple = {"a": "b", "c": 1}
    assert canon(simple) == _cj_dumps(simple)
    assert _rfc_dumps(simple) == _cj_dumps(simple)

def test_bind6_escape_stability():
    assert canon({"k": "a\"b\\c\nd"}) == b'{"k":"a\\"b\\\\c\\nd"}'

def test_bind6_numbers():
    # rfc8785 uses ECMAScript number formatting: 1.0 -> "1", 1.5 -> "1.5"
    assert canon({"n": 1}) == b'{"n":1}'
    assert canon({"n": 1.0}) == b'{"n":1}'
    assert canon({"n": 1.5}) == b'{"n":1.5}'
    assert canon({"n": 1}) != canon({"n": 1.5})

def test_bind5_empty_and_blank():
    assert isinstance(canon({"a": [], "b": "", "c": "   "}), bytes)
    assert h_hex({"a": []}) == h_hex({"a": []})  # 确定性

def test_h_hex_len():
    assert len(h_hex({"x": 1})) == 64

def test_nfc_key_collision_rejected():
    with pytest.raises(ValueError):
        canon({"\u00e9": 1, "e\u0301": 2})   # NFC U+00E9 vs NFD e+U+0301
