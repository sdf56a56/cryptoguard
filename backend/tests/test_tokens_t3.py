import pytest
from app.tokens import StaticOPE, BucketOPE

VALUES = [10, 25, 3, 99, 40, 7, 7, 60, 1, 55]

def test_order_preserving_static():
    o = StaticOPE(VALUES)
    enc = {v: o.encrypt(v) for v in set(VALUES)}
    for a in set(VALUES):
        for b in set(VALUES):
            if a < b:
                assert enc[a] < enc[b]
            if a == b:
                assert enc[a] == enc[b]

def test_roundtrip():
    o = StaticOPE(VALUES)
    for v in set(VALUES):
        assert o.decrypt(o.encrypt(v)) == v

def test_reject_dynamic_insert():
    o = StaticOPE(VALUES)
    with pytest.raises(KeyError):
        o.encrypt(1000)           # 不支持动态插入 —— spec §1.3 静态边界

def test_reject_over_20():
    with pytest.raises(ValueError):
        StaticOPE(list(range(21)))

def test_bucket_fallback():
    b = BucketOPE(bounds=[0, 50, 100])
    # 原文断言 `b.encrypt(10) < b.encrypt(60) < b.encrypt(90)` 与分桶语义矛盾:
    # 60 与 90 同落 (50, 100] 桶,任何真分桶映射都必须给同值,否则泄漏超出"桶序"。
    # 故第三点改为跨入下一桶的 120,并显式断言同桶等值(仅泄漏桶序)。
    assert b.encrypt(10) < b.encrypt(60) < b.encrypt(120)
    assert b.encrypt(60) == b.encrypt(90)
    assert b.LEAK == "桶序"
