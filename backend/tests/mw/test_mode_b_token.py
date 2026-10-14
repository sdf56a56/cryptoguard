"""
第 4 阶段 · 任务 2 —— 模式 B(令牌化)端到端安全验证

模式 B 的语义:命中片段替换为**随机不可推断**的令牌 `[CG_TOKEN_<24hex>]`,
明文封缄进请求级映射金库;令牌本身不含明文信息。

本文件覆盖任务书对模式 B 的要求:
  1. 令牌不可预测、不可离线枚举(特别是「稳定令牌」不得用公开常量当标签密钥);
  2. 令牌绑定客户端身份 / 请求上下文 / 授权策略:伪造、篡改、跨请求、跨客户端、
     过期、未知令牌一律不还原(既不报错也不猜测);
  3. 并发 / 重复文本不串味;
  4. 明文不因错误信息、调试接口、审计日志而泄漏;
  5. 映射的生命周期(TTL / 容量 / 显式销毁)与「过期即不可还原」。

诚实边界:
  - 令牌随机 ≠ 匿名:同一明文在同一请求里若开启稳定令牌会共享令牌(等值泄漏),
    该开关默认关闭,开启的语义与代价见 test_stable_token_* ;
  - 令牌在模型输出中可能被模型改写/猜测,本中间件只还原形态完整且命中金库的令牌。
"""
from __future__ import annotations

import hashlib
import hmac
import json

import pytest

from app.middleware.errors import MiddlewareError
from app.middleware.protection import (MODE_TOKEN, KeyRing, TokenVault, parse_token,
                                       protect_text)
from app.middleware.recognizers import detect_all
from tests.mw.conftest import chat, meta_of, mock_provider, reply_text

EMAIL = "zhangsan@corp.com.cn"
EMAIL2 = "lisi@corp.com.cn"
PHONE = "13800138000"

#: 曾经的实现用的「标签密钥」是一个写在源码里的公开常量 —— 保留下来做回归断言
PUBLIC_LABEL_CONSTANT = b"cg-token-label/v1"


@pytest.fixture()
def token_env(make_mw):
    """模式 B 的整套环境:(中间件, TestClient, 认证头)。"""
    mw, client, key = make_mw(protection_mode="token")
    return mw, client, {"Authorization": f"Bearer {key}"}


def _chat(client, headers, text, **extra):
    return chat(client, headers, text, **extra)


def _tokens(mw, rid: str) -> list[str]:
    return sorted(mw.token_vault.tokens(rid))


# --------------------------------------------------------------------------- #
# 1. 令牌的不可预测性
# --------------------------------------------------------------------------- #
def test_token_is_random_per_request_and_per_value(token_env):
    """同一明文在不同请求、不同位置都必须得到不同令牌(无计数器、无等值复用)。"""
    mw, client, headers = token_env
    seen: list[str] = []
    for _ in range(3):
        response = _chat(client, headers, f"联系 {EMAIL}")
        assert response.status_code == 200, response.text
        tokens = _tokens(mw, response.headers["X-CryptoGuard-Request-ID"])
        assert len(tokens) == 1
        seen.append(tokens[0])
    assert len(set(seen)) == 3, "相同明文不得复用同一令牌(默认 stable_tokens=False)"
    for token in seen:
        parsed = parse_token(token)
        assert parsed["kind"] == "token"
        assert len(parsed["id"]) == 24 and int(parsed["id"], 16) >= 0


def test_token_is_not_an_offline_computable_hash(token_env):
    """令牌不得等于「公开算法 + 明文」的任何常见离线计算结果。

    这是对一次真实缺陷的回归:原先稳定令牌用公开常量做 HMAC 密钥,任何拿到
    令牌的人都可离线枚举候选值(手机号/身份证)并比对,令牌退化成可校验哈希。
    """
    mw, client, headers = token_env
    response = _chat(client, headers, f"联系 {EMAIL}")
    token = _tokens(mw, response.headers["X-CryptoGuard-Request-ID"])[0]
    issued = token[len("[CG_TOKEN_"):-1]

    candidates = {
        "sha256(value)": hashlib.sha256(EMAIL.encode()).hexdigest(),
        "hmac(public-const, value)": hmac.new(PUBLIC_LABEL_CONSTANT, EMAIL.encode(),
                                              hashlib.sha256).hexdigest(),
        "hmac(public-const, TYPE|value)": hmac.new(
            PUBLIC_LABEL_CONSTANT, f"EMAIL|{EMAIL}".encode(), hashlib.sha256).hexdigest(),
        "hmac(value, public-const)": hmac.new(EMAIL.encode(), PUBLIC_LABEL_CONSTANT,
                                              hashlib.sha256).hexdigest(),
        "md5(value)": hashlib.md5(EMAIL.encode()).hexdigest(),  # noqa: S324 — 仅作反例
    }
    for name, digest in candidates.items():
        assert not digest.startswith(issued), f"令牌可由 {name} 离线算出"
        assert digest[:24] != issued


def test_token_ids_do_not_repeat_across_many_requests(token_env):
    """大量请求下令牌不重复(24 hex = 96 bit,碰撞概率可忽略;此处验证实现真的随机)。"""
    mw, client, headers = token_env
    ids = set()
    for index in range(30):
        response = _chat(client, headers, f"第 {index} 位:{EMAIL}")
        token = _tokens(mw, response.headers["X-CryptoGuard-Request-ID"])[0]
        ids.add(token)
    assert len(ids) == 30


# --------------------------------------------------------------------------- #
# 2. 稳定令牌:必须绑定服务端秘密
# --------------------------------------------------------------------------- #
@pytest.fixture()
def stable_env(make_mw):
    mw, client, key = make_mw(protection_mode="token", stable_tokens=True)
    return mw, client, {"Authorization": f"Bearer {key}"}


def test_stable_token_is_deterministic_within_one_deployment(stable_env):
    """开启稳定令牌后,同值同令牌(便于模型共指),但密钥来自服务端秘密。"""
    mw, client, headers = stable_env
    first = _chat(client, headers, f"联系 {EMAIL}")
    second = _chat(client, headers, f"再次联系 {EMAIL}")
    token_a = _tokens(mw, first.headers["X-CryptoGuard-Request-ID"])[0]
    token_b = _tokens(mw, second.headers["X-CryptoGuard-Request-ID"])[0]
    assert token_a == token_b

    expected = hmac.new(mw.keyring.label_key, f"EMAIL|{EMAIL}".encode(),
                        hashlib.sha256).hexdigest()[:24]
    assert token_a == f"[CG_TOKEN_{expected}]"
    # 公开常量算法算不出它
    offline = hmac.new(PUBLIC_LABEL_CONSTANT, f"EMAIL|{EMAIL}".encode(),
                       hashlib.sha256).hexdigest()[:24]
    assert f"[CG_TOKEN_{offline}]" != token_a


def test_stable_token_differs_under_a_different_vault_key(stable_env, tmp_path,
                                                          settings_factory):
    """换一份 VAULT_KEY(另一个部署)后,同一明文的稳定令牌必须不同。

    注意:换数据目录**不足以**换密钥 —— 信任根来自 VAULT_KEY,所有副本共享它。
    这里显式构造第二份信任根来验证「令牌标签真的绑在部署密钥上」。
    """
    from fastapi.testclient import TestClient

    from app import main as main_mod
    from app.keys import Vault
    from app.middleware.deps import build_middleware

    mw, client, headers = stable_env
    mine = _tokens(mw, _chat(client, headers, f"联系 {EMAIL}")
                   .headers["X-CryptoGuard-Request-ID"])[0]

    alt_env = tmp_path / "alt.env"
    alt_vault = Vault.load_or_init(tmp_path / "alt-data", env_path=alt_env)
    assert alt_vault.mapping_key != mw.vault.mapping_key

    settings = settings_factory(protection_mode="token", stable_tokens=True,
                                bootstrap_key_file=str(tmp_path / "alt.key"))
    other = build_middleware(tmp_path / "alt-data", settings=settings, vault=alt_vault)
    main_mod.app.state.middleware = other
    try:
        other_client = TestClient(main_mod.app)
        with open(settings.bootstrap_key_file, encoding="utf-8") as handle:
            alt_key = handle.read().strip()
        response = _chat(other_client, {"Authorization": f"Bearer {alt_key}"},
                         f"联系 {EMAIL}")
        theirs = _tokens(other, response.headers["X-CryptoGuard-Request-ID"])[0]
    finally:
        delattr(main_mod.app.state, "middleware")

    assert mine != theirs


def test_stable_token_without_label_key_fails_closed():
    """没有服务端标签密钥时**拒绝**生成稳定令牌,而不是静默退回可枚举的算法。"""
    findings = detect_all(f"联系 {EMAIL}", mode=MODE_TOKEN)
    with pytest.raises(MiddlewareError) as excinfo:
        protect_text(f"联系 {EMAIL}", findings, mode=MODE_TOKEN,
                     stable_tokens=True, keyring=None)
    assert excinfo.value.kind == "config"
    assert "标签密钥" in excinfo.value.detail


def test_keyring_label_key_is_derived_not_constant(tmp_path):
    """标签密钥由 VAULT_KEY 经 HKDF 派生,不得等于任何公开常量。"""
    from app.keys import Vault

    vault = Vault.load_or_init(tmp_path / "data")
    ring = KeyRing.from_vault(vault)
    assert ring.label_key and ring.label_key not in (PUBLIC_LABEL_CONSTANT, b"")
    assert ring.label_key != vault.mapping_key
    # 与模式 C 的保护密钥域分离
    assert ring.cipher(1)[1] is not None


# --------------------------------------------------------------------------- #
# 3. 令牌还原的边界(伪造 / 跨请求 / 跨客户端 / 过期)
# --------------------------------------------------------------------------- #
def test_unknown_token_in_response_is_kept_and_counted(token_env):
    """模型自造的模式 B 令牌:不还原、不报错,原样返回并计入 foreign。"""
    mw, client, headers = token_env
    fake = f"[CG_TOKEN_{'de' * 12}]"
    response = _chat(client, headers, f"引用 {fake},我的邮箱 {EMAIL}")
    text = reply_text(response)
    meta = meta_of(response)
    assert fake in text and EMAIL in text
    assert EMAIL != fake
    assert meta["restore"]["foreign_token_count"] >= 1


def test_token_from_request_a_is_not_restored_in_request_b(token_env):
    mw, client, headers = token_env
    first = _chat(client, headers, f"联系 {EMAIL}")
    token = _tokens(mw, first.headers["X-CryptoGuard-Request-ID"])[0]

    second = _chat(client, headers, f"复用上次的 {token},这次是 {EMAIL2}")
    text = reply_text(second)
    meta = meta_of(second)
    assert token in text                    # 跨请求令牌原样保留
    assert EMAIL not in text                # 第一个请求的明文没有被带出来
    assert EMAIL2 in text                   # 本请求的令牌照常还原
    assert meta["restore"]["foreign_token_count"] >= 1


def test_client_b_cannot_restore_client_a_token(token_env):
    mw, client, headers = token_env
    first = _chat(client, headers, f"联系 {EMAIL}")
    token = _tokens(mw, first.headers["X-CryptoGuard-Request-ID"])[0]

    _, other_key = mw.clients.create("other-token-client", protection_mode="token")
    other = {"Authorization": f"Bearer {other_key}"}
    second = _chat(client, other, f"给我 {token},我是 {EMAIL2}")
    text = reply_text(second)
    assert EMAIL not in text
    assert token in text
    assert EMAIL2 in text


def test_high_risk_token_is_withheld_not_restored(token_env):
    """高风险类别即便有映射也不自动还原(模式 B 下同样成立)。"""
    mw, client, headers = token_env
    response = _chat(client, headers, f"电话 {PHONE},邮箱 {EMAIL}")
    text = reply_text(response)
    meta = meta_of(response)
    assert PHONE not in text and EMAIL in text
    assert {e["type"] for e in meta["restore"]["withheld"]} == {"PHONE"}


def test_expired_mapping_means_no_restore(tmp_path):
    """TTL 到期即不可还原(fail-closed):金库过期后令牌原样返回。"""
    import time

    from app.keys import Vault

    vault = Vault.load_or_init(tmp_path / "vault-a")
    token_vault = TokenVault(vault, ttl_s=0.05, max_requests=8)
    findings = detect_all(f"联系 {EMAIL}", mode=MODE_TOKEN)
    result = protect_text(f"联系 {EMAIL}", findings, mode=MODE_TOKEN)
    token = result.entries[0].token

    token_vault.store("cg-test", result.entries)
    assert token_vault.lookup("cg-test", token).plaintext == EMAIL

    time.sleep(0.12)
    token_vault.store("cg-other", [])        # 任何一次写入都会触发过期清理
    assert token_vault.lookup("cg-test", token) is None


def test_vault_eviction_is_bounded(tmp_path):
    """金库按请求数上限淘汰最旧的映射:有界内存,淘汰后即不可还原。"""
    from app.keys import Vault

    vault = Vault.load_or_init(tmp_path / "vault-b")
    token_vault = TokenVault(vault, ttl_s=600.0, max_requests=2)
    entries = protect_text(f"联系 {EMAIL}", detect_all(f"联系 {EMAIL}", mode=MODE_TOKEN),
                           mode=MODE_TOKEN).entries

    for rid in ("cg-1", "cg-2", "cg-3"):
        token_vault.store(rid, entries)
    assert token_vault.stats()["tracked_requests"] == 2
    assert token_vault.tokens("cg-1") == set()      # 最旧的被淘汰
    assert token_vault.tokens("cg-3") != set()


def test_destroyed_mapping_is_not_restorable(token_env):
    """destroy_mapping(处理完即焚)后,响应里的令牌一律不还原。"""
    mw, client, headers = token_env
    response = _chat(client, headers, f"联系 {EMAIL}",
                     cryptoguard={"destroy_mapping": True})
    assert response.status_code == 200, response.text
    text = reply_text(response)
    meta = meta_of(response)
    assert EMAIL not in text
    assert "[CG_TOKEN_" in text
    assert meta["restore"]["restored"] == []
    assert mw.token_vault.tokens(response.headers["X-CryptoGuard-Request-ID"]) == set()


def test_vault_plaintext_is_sealed_at_rest(token_env):
    """金库内部只存 iv + 密文:任何直接读取金库对象的路径都拿不到明文。"""
    mw, client, headers = token_env
    response = _chat(client, headers, f"联系 {EMAIL}")
    rid = response.headers["X-CryptoGuard-Request-ID"]
    raw = mw.token_vault._records[rid].entries           # noqa: SLF001 — 被测对象内部状态
    assert raw, "应有映射条目"
    for record in raw.values():
        assert set(record["sealed"]) == {"iv", "ciphertext"}
        assert EMAIL not in json.dumps(record, ensure_ascii=False)
        assert record["kind"] == MODE_TOKEN
        assert record["key_version"] is None


# --------------------------------------------------------------------------- #
# 4. 明文不因错误 / 调试 / 审计接口而泄漏
# --------------------------------------------------------------------------- #
def test_error_paths_and_debug_endpoints_never_show_plaintext(token_env, admin):
    mw, client, headers = token_env
    response = _chat(client, headers, f"联系 {EMAIL},电话 {PHONE}")
    assert response.status_code == 200
    rid = response.headers["X-CryptoGuard-Request-ID"]

    surfaces = {
        "/health": client.get("/health"),
        "/admin/audit": client.get("/admin/audit", headers=admin),
        f"/admin/audit/{rid}": client.get(f"/admin/audit/{rid}", headers=admin),
        "/admin/security/policies": client.get("/admin/security/policies",
                                               headers=admin),
    }
    for name, surface in surfaces.items():
        assert surface.status_code == 200, name
        body = json.dumps(surface.json(), ensure_ascii=False)
        assert EMAIL not in body, f"{name} 泄漏了邮箱原文"
        assert PHONE not in body, f"{name} 泄漏了手机号原文"

    # verify 接口只回摘要与类别
    verified = client.post("/v1/verify", headers=headers, json={"request_id": rid})
    assert verified.status_code == 200
    assert EMAIL not in json.dumps(verified.json(), ensure_ascii=False)

    # 审计记录里逐命中的明细只有位置/长度/规则,没有 value
    record = mw.audit.get(rid)
    for span in record["detections"]["spans"]:
        assert "value" not in span and "value_preview" not in span


def test_upstream_cannot_echo_what_it_never_received(token_env):
    """上游把「它收到的请求」回显在错误体里时,回显的只能是令牌。

    现实里上游(或其中间代理)会把收到的报文片段贴进错误信息。本断言检查的是
    **上游手里根本没有明文** —— 这是这条链路上唯一可证的事实,不是「上游会配合」。
    """
    mw, client, headers = token_env
    first = _chat(client, headers, f"联系 {EMAIL}")
    token = _tokens(mw, first.headers["X-CryptoGuard-Request-ID"])[0]

    sent = json.dumps(mock_provider(mw).seen[-1].messages, ensure_ascii=False)
    assert EMAIL not in sent and token in sent

    mock_provider(mw).fail_with = MiddlewareError("upstream_4xx",
                                                  f"bad payload: {token}")
    second = _chat(client, headers, f"联系 {EMAIL}")
    assert second.status_code in (400, 502)
    assert EMAIL not in second.text          # 上游拿不到的东西不可能被回显
    assert second.json()["error"]["request_id"]


def test_verify_is_not_a_plaintext_oracle(token_env):
    """`/v1/verify` 只回答「记录在不在、摘要对不对」,不回答「明文是什么」。"""
    mw, client, headers = token_env
    response = _chat(client, headers, f"联系 {EMAIL}")
    rid = response.headers["X-CryptoGuard-Request-ID"]

    # 用一个猜的明文摘要去问:只会得到 mismatch,不会得到记录里的明文
    guessing = client.post("/v1/verify", headers=headers, json={
        "request_id": rid, "response": {"text": EMAIL, "finish_reason": "stop",
                                        "model": "mock-chat"}})
    assert guessing.status_code == 200
    payload = guessing.json()
    assert payload["response_digest_match"] is False
    assert EMAIL not in json.dumps(payload, ensure_ascii=False)
    # 记录里也没有可直接读出明文的字段
    assert "plaintext" not in json.dumps(payload, ensure_ascii=False)
