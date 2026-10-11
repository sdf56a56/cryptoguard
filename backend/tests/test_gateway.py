import pytest
from app.gateway import validate_directive, aggregate, GatewayReject

TOKEN_INDEX = {"[AMT#a1]": "T3", "[AMT#b2]": "T4", "[NAME#c3]": "T1"}

def test_valid_sum():
    d = validate_directive(
        {"op": "sum", "tokens": ["[AMT#a1]", "[AMT#b2]"], "result_ref": "c_01"},
        TOKEN_INDEX)
    assert d.op == "sum"

def test_reject_unknown_op():
    with pytest.raises(GatewayReject):
        validate_directive({"op": "exec", "tokens": ["[AMT#a1]"], "result_ref": "c_01"}, TOKEN_INDEX)

def test_reject_token_not_in_index():          # SEC-ATK-8 核心:注入非法令牌
    with pytest.raises(GatewayReject) as e:
        validate_directive(
            {"op": "sum", "tokens": ["[FAKE#deadbeef]"], "result_ref": "c_01"},
            TOKEN_INDEX)
    assert "越权" in e.value.reason or "不在" in e.value.reason

def test_reject_wrong_tier():
    with pytest.raises(GatewayReject):
        validate_directive(
            {"op": "sum", "tokens": ["[NAME#c3]"], "result_ref": "c_01"}, TOKEN_INDEX)

def test_aggregate_ops():
    assert aggregate("sum", [1, 2, 3]) == 6
    assert aggregate("mean", [2, 4]) == 3.0
    assert aggregate("count", [5, 5]) == 2
    assert aggregate("min", [7, 3]) == 3
    assert aggregate("max", [7, 3]) == 7
