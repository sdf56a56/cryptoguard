"""
第 4 阶段 · 任务 1 —— 模式 A(占位符脱敏)端到端安全验证

模式 A 的语义:把命中片段替换为**请求内可枚举**的占位符 `[TYPE_001]`,
明文封缄进请求级映射金库,回程时按策略还原。

本文件只覆盖任务书要求的「安全属性」,不重复 tests/mw/test_gateway_chain.py
已覆盖的基本链路(健康检查/模型白名单/摘要复算等):

  1. 上游实际收到的内容里没有原始敏感数据(直接检查 Provider 收到的请求对象);
  2. 占位符只在**签发它的那次请求上下文**内可还原;伪造的、别的请求的占位符一律不还原;
  3. 同一请求内不同明文**不得**产生同一占位符(映射碰撞 → 静默错还原);
  4. 相同明文重复出现不得互相覆盖;
  5. 客户端无法用请求体里的 `allow_spans` 自我授权放行(需走人工确认);
  6. 阻断/上游错误/流式路径都不得把原文交出去;
  7. 跨请求、跨客户端、并发请求的映射互相隔离;
  8. 审计落盘与数据目录里不出现原文。

诚实边界(不得据此宣称「系统已绝对安全」):
  - 模式 A 的占位符可枚举,模型可能猜中本次请求已签发的编号从而触发还原;
    此处只保证「不是本请求签发的令牌不会被还原」;
  - 识别器有漏报边界,未命中的片段不会进入保护流程(见 recognizers 的说明)。
"""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor

from tests.mw.conftest import chat, meta_of, mock_provider, reply_text

PHONE = "13800138000"
PHONE2 = "13900139001"
EMAIL = "zhangsan@corp.com.cn"
EMAIL2 = "lisi@corp.com.cn"
EMAIL3 = "wangwu@corp.com.cn"
PEM = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"


def _rid(response) -> str:
    return response.headers["X-CryptoGuard-Request-ID"]


# --------------------------------------------------------------------------- #
# 1. 上游实际收到什么
# --------------------------------------------------------------------------- #
def test_upstream_payload_has_no_original_values(client, auth, mw):
    """核心安全属性:出站请求体里只有占位符,没有原始值。"""
    response = chat(client, auth, f"联系 {EMAIL},电话 {PHONE}")
    assert response.status_code == 200, response.text

    seen = mock_provider(mw).seen[-1]
    sent = json.dumps([m for m in seen.messages], ensure_ascii=False)
    assert "[EMAIL_001]" in sent and "[PHONE_001]" in sent
    assert EMAIL not in sent and PHONE not in sent
    # 结构化字段(role 等)不得被改写
    assert [m["role"] for m in seen.messages] == ["user"]


# --------------------------------------------------------------------------- #
# 2. 占位符的还原上下文边界
# --------------------------------------------------------------------------- #
def test_placeholder_restored_only_for_allowed_category(client, auth):
    """白名单类别还原;高风险类别(手机号)保持占位符,原文不出现在响应里。"""
    response = chat(client, auth, f"联系 {EMAIL},电话 {PHONE}")
    text = reply_text(response)
    meta = meta_of(response)
    assert EMAIL in text
    assert PHONE not in text and "[PHONE_001]" in text
    assert {e["type"] for e in meta["restore"]["restored"]} == {"EMAIL"}
    assert {e["type"] for e in meta["restore"]["withheld"]} == {"PHONE"}


def test_forged_placeholder_in_response_is_not_restored(client, auth):
    """模型/用户自造的占位符(本请求没签发过)必须原样保留,不得触发还原。"""
    response = chat(client, auth, f"上次的编号是 [PHONE_001],这次联系 {EMAIL}")
    assert response.status_code == 200, response.text
    text = reply_text(response)
    meta = meta_of(response)
    assert EMAIL in text                       # 本次签发的照常还原
    assert "[PHONE_001]" in text               # 伪造的原样保留
    assert PHONE not in text                   # 金库里根本没这个映射,拿不出明文
    assert meta["restore"]["foreign_token_count"] >= 1
    assert all(e["token"] != "[PHONE_001]" for e in meta["restore"]["restored"])


def test_unknown_mark_token_in_response_is_not_restored(client, auth):
    """形态合法但非本请求签发的模式 B 令牌同样不还原(跨模式伪造)。"""
    response = chat(client, auth,
                    f"引用 [CG_TOKEN_{'a1' * 12}] 与 [CG_ENC_v1_{'b2' * 8}],联系 {EMAIL}")
    text = reply_text(response)
    meta = meta_of(response)
    assert f"[CG_TOKEN_{'a1' * 12}]" in text
    assert f"[CG_ENC_v1_{'b2' * 8}]" in text
    assert meta["restore"]["foreign_token_count"] >= 2


def test_cross_request_placeholder_is_not_restored(client, auth, mw):
    """A 请求签发的占位符在 B 请求里不得被还原(金库按 request_id 严格隔离)。"""
    first = chat(client, auth, f"联系 {EMAIL} 与 {EMAIL2}")
    assert first.status_code == 200
    rid_first = _rid(first)
    assert mw.token_vault.lookup(rid_first, "[EMAIL_002]").plaintext == EMAIL2

    second = chat(client, auth, f"重发一次:上次的 [EMAIL_002],这次联系 {EMAIL3}")
    assert second.status_code == 200, second.text
    text = reply_text(second)
    meta = meta_of(second)
    assert EMAIL3 in text                       # 本次签发的还原
    assert "[EMAIL_002]" in text                # 上次签发的:跨请求,拒绝还原
    assert EMAIL2 not in text                   # 明文没有被带出来
    assert meta["restore"]["foreign_token_count"] >= 1


# --------------------------------------------------------------------------- #
# 3. 映射碰撞与重复值
# --------------------------------------------------------------------------- #
def test_same_type_different_values_do_not_collide_across_messages(client, auth, mw):
    """回归:两条消息里的不同明文**不得**共用同一占位符。

    修复前 `counters` 是每条消息各自新建的,两条消息都会产出 `[EMAIL_001]`,
    金库按键覆盖 → 后写的明文把先写的顶掉,还原时会张冠李戴。
    """
    body = {"model": "mock-chat", "messages": [
        {"role": "user", "content": f"第一位客户 {EMAIL}"},
        {"role": "assistant", "content": "好的"},
        {"role": "user", "content": f"第二位客户 {EMAIL2}"},
    ]}
    response = client.post("/v1/chat/completions", json=body, headers=auth)
    assert response.status_code == 200, response.text

    seen = mock_provider(mw).seen[-1]
    sent = json.dumps(seen.messages, ensure_ascii=False)
    assert "[EMAIL_001]" in sent and "[EMAIL_002]" in sent
    assert EMAIL not in sent and EMAIL2 not in sent

    rid = _rid(response)
    assert mw.token_vault.lookup(rid, "[EMAIL_001]").plaintext == EMAIL
    assert mw.token_vault.lookup(rid, "[EMAIL_002]").plaintext == EMAIL2
    # 金库里的条目数等于命中数:没有任何一条被覆盖掉
    assert len(mw.token_vault.tokens(rid)) == 2


def test_same_value_repeated_gets_distinct_placeholders_both_mapped(client, auth, mw):
    """"同值重复出现"必须各自有独立占位符,且都映射回同一个明文(不互相覆盖)。

    注:实现上重复出现**不会**复用同一编号(`protect_text` 每次命中都递增计数),
    这与 protection.py 文档里「同值同号」的说法不一致 —— 安全上无害(两个占位符
    都指向同一明文),此处按**真实行为**断言,避免测试固化一句不准确的描述。
    """
    response = chat(client, auth, f"{EMAIL} 和 {EMAIL} 是同一个人的两个邮箱")
    rid = _rid(response)
    tokens = sorted(mw.token_vault.tokens(rid))
    assert tokens == ["[EMAIL_001]", "[EMAIL_002]"]
    assert mw.token_vault.lookup(rid, tokens[0]).plaintext == EMAIL
    assert mw.token_vault.lookup(rid, tokens[1]).plaintext == EMAIL
    text = reply_text(response)
    assert text.count(EMAIL) == 2               # 两个占位符都还原成同一明文


def test_same_text_in_different_fields_does_not_scramble(client, auth, mw):
    """同一明文出现在消息体与工具定义两处时,映射必须各自正确、不串味。"""
    body = {
        "model": "mock-tools",
        "messages": [{"role": "user", "content": f"USE_TOOL 联系人 {EMAIL}"}],
        "tools": [{"type": "function", "function": {
            "name": "notify", "description": f"通知 {EMAIL} 的邮箱",
            "parameters": {"type": "object", "properties": {}}}}],
    }
    response = client.post("/v1/chat/completions", json=body, headers=auth)
    assert response.status_code == 200, response.text

    rid = _rid(response)
    for token in mw.token_vault.tokens(rid):
        assert mw.token_vault.lookup(rid, token).plaintext == EMAIL
    seen = mock_provider(mw).seen[-1]
    sent = json.dumps({"messages": seen.messages, "tools": [
        t if isinstance(t, dict) else str(t) for t in (seen.tools or [])]},
        ensure_ascii=False)
    assert EMAIL not in sent


# --------------------------------------------------------------------------- #
# 4. 客户端不能自我授权放行
# --------------------------------------------------------------------------- #
def test_request_allow_spans_cannot_unblock_private_key(client, auth, mw):
    """回归:请求体里的 allow_spans 曾被当作「放行」依据,可绕过阻断档。"""
    response = client.post("/v1/chat/completions", headers=auth, json={
        "model": "mock-chat",
        "messages": [{"role": "user", "content": f"看看这个 {PEM}"}],
        "cryptoguard": {"allow_spans": [{"type": "PRIVATE_KEY", "start": 5,
                                         "end": 5 + len(PEM)}]},
    })
    assert response.status_code == 400, response.text
    assert response.json()["error"]["code"] == "content_blocked"
    assert mock_provider(mw).seen == []          # 一个字都没出网


def test_request_allow_spans_cannot_release_high_risk_value(client, auth, mw):
    """即便范围写对,高风险类别也不会因此被还原:只记审计意图。"""
    response = client.post("/v1/chat/completions", headers=auth, json={
        "model": "mock-chat",
        "messages": [{"role": "user", "content": f"电话 {PHONE}"}],
        "cryptoguard": {"allow_spans": [{"type": "PHONE", "start": 3,
                                         "end": 3 + len(PHONE)}]},
    })
    assert response.status_code == 200, response.text
    text = reply_text(response)
    meta = meta_of(response)
    assert PHONE not in text and "[PHONE_001]" in text
    assert meta["restore"]["restored"] == []

    rid = _rid(response)
    record = mw.audit.get(rid)
    # 放行请求确实被记录了(可审计),但没有任何放行动作
    assert record["actions"]["release_requested"] == 1
    assert "未放行" in record["actions"]["release_requested_note"]


# --------------------------------------------------------------------------- #
# 5. 阻断 / 上游异常 / 流式
# --------------------------------------------------------------------------- #
def test_blocked_request_is_not_forwarded_and_error_has_no_plaintext(client, auth, mw):
    secret = "MIIEowIBAAKCAQEA"
    response = chat(client, auth, f"私钥如下 {PEM}")
    assert response.status_code == 400
    error = response.json()["error"]
    assert error["code"] == "content_blocked"
    assert secret not in json.dumps(error, ensure_ascii=False)
    assert mock_provider(mw).seen == []


def test_blocked_streaming_request_returns_json_error_not_500(client, auth, mw):
    """回归:流式 + 阻断内容曾在已经进入 SSE 之前抛裸异常 → 500 且无 JSON 错误体。"""
    response = chat(client, auth, f"私钥如下 {PEM}", stream=True)
    assert response.status_code == 400, response.text
    assert response.headers["content-type"].startswith("application/json")
    assert response.json()["error"]["code"] == "content_blocked"
    assert mock_provider(mw).seen == []


def test_upstream_error_does_not_leak_original(client, auth, mw):
    """上游报错时,错误响应里不得出现原文(只保留占位符级别的信息)。"""
    from app.middleware.errors import MiddlewareError

    mock_provider(mw).fail_with = MiddlewareError("timeout", "上游超时")
    response = chat(client, auth, f"联系 {EMAIL}")
    assert response.status_code == 504, response.text
    assert EMAIL not in response.text
    rid = _rid(response)
    record = mw.audit.get(rid)
    assert record["outcome"] == "error" and record["error_kind"] == "timeout"
    assert EMAIL not in json.dumps(record, ensure_ascii=False)


def test_no_plaintext_written_to_data_dir(client, auth, data_dir):
    """审计落盘文件里不出现原文(审计只记类别/位置/长度)。"""
    assert chat(client, auth, f"联系 {EMAIL},电话 {PHONE}").status_code == 200
    blob = "".join(path.read_text(encoding="utf-8", errors="ignore")
                   for path in data_dir.rglob("*") if path.is_file())
    assert EMAIL not in blob and PHONE not in blob


# --------------------------------------------------------------------------- #
# 6. 跨客户端与并发隔离
# --------------------------------------------------------------------------- #
def test_second_client_cannot_reach_first_clients_mapping(client, auth, make_client, mw):
    first = chat(client, auth, f"联系 {EMAIL}")
    rid = _rid(first)
    assert mw.token_vault.lookup(rid, "[EMAIL_001]") is not None

    other = make_client("other")["auth"]
    # B 自己也带一个邮箱:保证本次请求确实建立了映射(否则不会走还原扫描)。
    # 引用的是 [EMAIL_002](A 请求里第二个命中),B 的请求里没有这个令牌。
    second = chat(client, other, f"重发 [EMAIL_002] 给我,我的邮箱 {EMAIL3}")
    assert second.status_code == 200
    text = reply_text(second)
    assert EMAIL not in text and EMAIL2 not in text   # B 拿不到 A 的明文
    assert EMAIL3 in text                             # B 自己的映射照常还原
    assert "[EMAIL_002]" in text                      # 别的客户端签发的原样保留
    assert meta_of(second)["restore"]["foreign_token_count"] >= 1


def test_replayed_placeholder_never_yields_another_requests_plaintext(
        client, auth, make_client, mw):
    """重放别人的占位符字符串,最坏也只能拿到**自己**的值,绝拿不到别人的。

    模式 A 的占位符是「请求内编号」:`[EMAIL_001]` 在不同请求里指向不同明文。
    因此这里的结论必须写清楚 —— 令牌字符串本身不携带身份,身份来自
    `(request_id, token)` 这个二元组;跨请求重放不会命中别人的映射。
    """
    first = chat(client, auth, f"联系 {EMAIL}")           # A 的 [EMAIL_001] → EMAIL
    rid_first = _rid(first)
    assert mw.token_vault.lookup(rid_first, "[EMAIL_001]").plaintext == EMAIL

    other = make_client("other")["auth"]
    second = chat(client, other, f"我是 {EMAIL3},顺便提一句 [EMAIL_001]")
    rid_second = _rid(second)
    text = reply_text(second)

    # 第二个请求自己的 [EMAIL_001] 指向 EMAIL3(与第一个请求无关)
    assert mw.token_vault.lookup(rid_second, "[EMAIL_001]").plaintext == EMAIL3
    assert EMAIL3 in text
    assert EMAIL not in text, "重放占位符拿到的必须是本请求的映射,不是原请求的明文"


def test_concurrent_requests_keep_mappings_isolated(client, auth, mw):
    """并发请求各写各的金库条目:不得出现 A 的请求还原出 B 的明文。"""
    emails = [f"user{i}@corp.com.cn" for i in range(8)]

    def run(email: str):
        response = chat(client, auth, f"联系 {email}")
        return email, response

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(run, emails))

    request_ids = set()
    for email, response in results:
        assert response.status_code == 200, response.text
        rid = _rid(response)
        request_ids.add(rid)
        assert email in reply_text(response)
        tokens = mw.token_vault.tokens(rid)
        assert tokens == {"[EMAIL_001]"}
        assert mw.token_vault.lookup(rid, "[EMAIL_001]").plaintext == email
        # 本次请求的明文不得出现在别的请求的映射里
        for other_rid in request_ids - {rid}:
            assert all(mw.token_vault.lookup(other_rid, t).plaintext != email
                       for t in mw.token_vault.tokens(other_rid))
    assert len(request_ids) == len(emails)
    assert mw.audit.verify()["intact"] is True
