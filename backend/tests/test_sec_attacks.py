"""
SEC-ATK-1..9 八攻击集中回归(spec §6.2-B,5 拆 5a/5b)+ 沙箱隔离(SEC-ISO)。

SEC-ATK-1 篡改响应 -> 层3「响应完整性」红
SEC-ATK-2 重放 -> 层1「输入绑定/防重放」拒
SEC-ATK-3 伪造 cert -> 层2「模型身份」拒
SEC-ATK-4 篡改日志 -> 链断(副本链 verify False),主链不受污染
SEC-ATK-5a 用户诬告(声称错误输入) -> 「输入绑定/防重放」(input_hash 重算失配)
SEC-ATK-5b 服务商抵赖(否认收到该输入) -> 「响应完整性」(签名覆盖的输出不符)
SEC-ATK-6 令牌张冠李戴 -> token_root 失配,「输入绑定/防重放」
SEC-ATK-7 文件偷换 -> file_content_hash 失配,「输入绑定/防重放」
SEC-ATK-8 注入非法令牌/越权指令 -> 「计算网关」拒 + COMPUTE_GATE 事件入链
"""
from app.proxy import CryptoGuard
from app.sandbox import ATTACKS, LAYER_HIT, AttackSandbox


def _fresh():
    g = CryptoGuard()
    g.query_v2("张三 13800138000 查询余额")
    return g


def _hit(name):
    g = _fresh()
    sb = AttackSandbox(g)
    return g, sb.attack(name)


def test_sec_atk_1_tamper_response_fails_integrity():
    g, r = _hit("tamper")
    assert r["ok"] is False
    assert r["layer_hit"] == "响应完整性" == LAYER_HIT["tamper"]


def test_sec_atk_2_replay_rejected_at_input_binding():
    g, r = _hit("replay")
    assert r["ok"] is False
    assert r["layer_hit"] == "输入绑定/防重放" == LAYER_HIT["replay"]


def test_sec_atk_3_forge_cert_rejected_at_model_identity():
    g, r = _hit("forge_cert")
    assert r["ok"] is False
    assert r["layer_hit"] == "模型身份" == LAYER_HIT["forge_cert"]


def test_sec_atk_4_tamper_log_breaks_chain_copy_only():
    g, r = _hit("tamper_log")
    assert r["ok"] is False
    assert r["layer_hit"] == "可审计日志" == LAYER_HIT["tamper_log"]
    assert "verify()=False" in r["detail"] or "未得逞" in r["detail"]
    assert g.chain.verify() is True          # 主链绝不被污染


def test_5a_user_repudiation_fails():
    """5a 用户诬告:声称错误输入 -> input_hash 重算失配,「输入绑定/防重放」。"""
    g, r = _hit("repudiate_user")
    assert r["ok"] is False
    assert r["layer_hit"] == "输入绑定/防重放" == LAYER_HIT["repudiate_user"]


def test_5b_provider_repudiation_fails():
    """5b 服务商抵赖:否认收到该输入 -> 「响应完整性」。"""
    g, r = _hit("repudiate_provider")
    assert r["ok"] is False
    assert r["layer_hit"] == "响应完整性" == LAYER_HIT["repudiate_provider"]


def test_sec_atk_6_swap_token_fails_token_root_binding():
    g, r = _hit("swap_token")
    assert r["ok"] is False
    assert r["layer_hit"] == "输入绑定/防重放" == LAYER_HIT["swap_token"]


def test_sec_atk_7_swap_file_fails_file_content_hash():
    g, r = _hit("swap_file")
    assert r["ok"] is False
    assert r["layer_hit"] == "输入绑定/防重放" == LAYER_HIT["swap_file"]


def test_sec_atk_8_bad_directive_rejected_and_logged():
    """8 注入非法令牌/越权指令 -> 网关拒 + COMPUTE_GATE 事件入链可查。"""
    g, r = _hit("bad_directive")
    assert r["ok"] is False
    assert r["layer_hit"] == "计算网关" == LAYER_HIT["bad_directive"]

    # 真实流水线注入:gateway_rejected + COMPUTE_GATE 链上条目
    g2 = CryptoGuard()
    rogue = {"op": "sum", "tokens": ["T3#rogue-token"], "result_ref": "r-rogue"}
    res = g2.query_v2("余额统计", directive=rogue)
    assert res["gateway_rejected"] is True
    entries = [e for e in g2.chain.entries if e["entry_type"] == "COMPUTE_GATE"]
    assert entries, "COMPUTE_GATE 事件必须入链"
    # payload_digest = H(指令‖拒绝原因)口径可查:含指令与拒绝原因
    assert "rogue-token" in entries[-1]["payload_digest"]
    assert "reason" in entries[-1]["payload_digest"]


def test_all_nine_attacks_fail_and_hit_expected_layer():
    for name in ATTACKS:
        g = _fresh()
        sb = AttackSandbox(g)
        r = sb.attack(name)
        assert r["ok"] is False, name
        assert r["layer_hit"] == LAYER_HIT[name], name
        assert g.chain.verify() is True, name


def test_sec_iso_3_session_isolation():
    """SEC-ISO-3:会话 A 攻击中,会话 B 正常查询不受污染。"""
    ga = _fresh()
    sb = AttackSandbox(ga)
    root_before = ga.chain.root
    for name in ATTACKS:
        sb.attack(name)
    gb = CryptoGuard()
    r = gb.query_v2("李四 15012345678 查询余额")
    assert r["status"] == "verified"
    assert ga.chain.verify() is True
    assert ga.chain.root == root_before
