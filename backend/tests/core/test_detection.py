"""基础敏感实体识别（中间件 recognizers 的底座）回归测试。

只覆盖网关真正使用的 `detect_sensitive` / `ENTITY_META`；
T1–T4 分级令牌管线已随演示平台删除。
"""
from __future__ import annotations

from app.detection import DEFAULT_ENABLED, ENTITY_META, detect_sensitive


def test_entity_meta_and_defaults_cover_thirteen_types():
    assert len(ENTITY_META) == 13
    assert set(DEFAULT_ENABLED) == set(ENTITY_META)
    for type_, meta in ENTITY_META.items():
        assert meta["prefix"] and meta["zh"] and meta["sensitivity"]


def test_detects_phone_email_id_and_card():
    text = ("手机 13800138000，邮箱 zhangsan@corp.com.cn，"
            "身份证 11010519491231002X，银行卡 4111111111111111")
    result = detect_sensitive(text)
    types = {e.type for e in result.entities}
    assert {"PHONE", "EMAIL", "ID", "CARD"} <= types


def test_placeholder_mode_replaces_and_preserves_mapping():
    text = "联系 13800138000 或 zhangsan@corp.com.cn"
    result = detect_sensitive(text, mode="placeholder")
    assert "13800138000" not in result.redacted
    assert "zhangsan@corp.com.cn" not in result.redacted
    assert result.mapping
    for placeholder, value in result.mapping.items():
        assert placeholder in result.redacted
        assert value in text


def test_luhn_failure_lowers_card_confidence():
    # 长度像卡号但 Luhn 不过：保留命中，但置信度应降到 0.5（交由策略/人工判断）
    result = detect_sensitive("4111111111111112", enabled_types={"CARD"})
    assert len(result.entities) == 1
    assert result.entities[0].confidence == 0.5


def test_dictionary_entities_are_detected():
    result = detect_sensitive("张三在第一人民医院住院，诊断 HIV")
    types = {e.type for e in result.entities}
    assert "NAME" in types
    assert "ORG" in types
    assert "PHI" in types


def test_overlapping_entities_are_deduplicated_by_span():
    # 同一区间只保留最长/最高置信度一条，避免重复替换导致偏移错位
    result = detect_sensitive("访问 https://example.com/a?x=1 看看")
    spans = [(e.start, e.end) for e in result.entities]
    assert len(spans) == len(set(spans))
    assert any(e.type == "URL" for e in result.entities)


def test_empty_and_plain_text_yield_no_entities():
    assert detect_sensitive("").entities == []
    assert detect_sensitive("今天天气不错").entities == []
