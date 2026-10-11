from app.detection import detect_sensitive, tier_for
from app.detection import tokenize_entities, filename_token, Tokenizers
from app.tokens import T2Cipher

def test_tier_mapping():
    assert tier_for("NAME") == "T1"
    assert tier_for("ID") == "T2"
    assert tier_for("CARD") == "T2"

def test_entities_become_tokens():
    det = detect_sensitive("张三的手机 13800138000")
    toks = tokenize_entities(det.entities, Tokenizers.default())
    assert all(hasattr(t, "token") and hasattr(t, "tier") for t in toks)
    name_tok = [t for t in toks if t.tier == "T1"][0]
    assert "张三" not in name_tok.token       # 令牌不含明文

def test_low_confidence_pending():
    det = detect_sensitive("订单号 622202020001234")   # Luhn 挂 → 0.5 置信度
    toks = tokenize_entities(det.entities, Tokenizers.default())
    assert any(t.pending for t in toks)

def test_filename_tokenized():
    tok = filename_token("张三的报告.docx", Tokenizers.default())
    assert "张三" not in tok

def test_cross_modal_coreference():          # 同会话同值同令牌
    tk = Tokenizers.default()
    a = tokenize_entities(detect_sensitive("张三").entities, tk)
    b = tokenize_entities(detect_sensitive("张三来了").entities, tk)
    assert a[0].token == b[0].token


# 控制器裁定 R20:tier_for 只返回固定枚举 T1/T2/T3/T4,绝不回显输入(附加覆盖,详见报告)
def test_tier_for_fixed_enum_only():
    enum = {"T1", "T2", "T3", "T4"}
    for t in ["NAME", "ORG", "PROJECT", "PHI", "ADDRESS", "PII", "FNAME",
              "ID", "CARD", "PHONE", "EMAIL", "NUM",
              "张三", "T5", "drop table", "", " T1 "]:
        assert tier_for(t) in enum, t
