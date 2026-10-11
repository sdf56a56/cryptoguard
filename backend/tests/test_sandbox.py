"""
攻击沙箱测试 —— SEC-ISO-1/2 + 九种攻击注入(裁定 R9)

SEC-ISO-1:所有攻击跑完,主链 verify() 恒真(攻击绝不写主状态);
SEC-ISO-2:reset() 恢复快照,链根逐字段一致。
"""
from app.proxy import CryptoGuard
from app.sandbox import AttackSandbox, ATTACKS


def _fresh():
    g = CryptoGuard()
    g.query_v2("张三 13800138000 就诊")
    return g


def test_all_eight_attacks_fail_verification():
    for name in ATTACKS:
        g = _fresh()
        sb = AttackSandbox(g)
        r = sb.attack(name)
        assert r["ok"] is False and r["layer_hit"], name


def test_iso1_main_chain_never_polluted():       # Review Focus #4
    g = _fresh()
    sb = AttackSandbox(g)
    for name in ATTACKS:
        sb.attack(name)
    assert g.chain.verify() is True


def test_iso2_reset_restores_state():
    g = _fresh()
    before = g.chain.root
    sb = AttackSandbox(g)
    sb.attack("tamper_log")
    sb.reset()
    assert g.chain.root == before
