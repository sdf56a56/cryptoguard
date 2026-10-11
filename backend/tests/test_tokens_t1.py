import os
from app.tokens import t1_pseudonym, T1_DISPLAY_LEN

K = b"k" * 32
SALT = b"s" * 16

def test_deterministic_same_session():
    a = t1_pseudonym(K, "NAME", "张三", SALT)
    b = t1_pseudonym(K, "NAME", "张三", SALT)
    assert a == b

def test_different_salt_unlinkable():
    a = t1_pseudonym(K, "NAME", "张三", SALT)
    b = t1_pseudonym(K, "NAME", "张三", b"x" * 16)
    assert a != b

def test_type_separation():
    assert t1_pseudonym(K, "NAME", "张三", SALT) != t1_pseudonym(K, "ORG", "张三", SALT)

def test_format_128bit_base32():
    tok = t1_pseudonym(K, "NAME", "张三", SALT)
    assert len(tok) == 26            # 128 bit / 5 bit ≈ 26 chars
    assert tok == tok.lower()
    assert all(c in "abcdefghijklmnopqrstuvwxyz234567" for c in tok)

def test_display_prefix():
    tok = t1_pseudonym(K, "NAME", "张三", SALT)
    assert len(tok[:T1_DISPLAY_LEN]) == T1_DISPLAY_LEN
