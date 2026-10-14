"""
第 4 阶段 · 任务 4 —— 人工确认与高风险数据释放

背景(先说清,不假装):
  在补齐本模块之前,中间件对高风险类别(手机号/身份证/私钥…)只有**扣留**机制:
  没有任何合法途径把这些数据交回用户。一个只有扣留、没有放行的系统在真实业务里
  一定会被绕过。本文件验证补上的那条合法途径,以及它必须满足的全部约束。

状态模型(唯一口径,见 confirmations.py 的模块文档):
      pending --管理员批准--> approved --客户端取回一次--> consumed
         │                        │
         │ 管理员拒绝              │ 超过有效期
         ▼                        ▼
      denied                   expired

本文件覆盖:
  1. 完整流程(申请 → 批准 → 释放 → 单次消费);
  2. 释放前必须经过带身份的管理员批准:客户端无法自我批准,模型请求还原 ≠ 自动批准;
  3. 凭据绑定:属主、请求、令牌集合、有效期 —— 换客户端 / 换请求 / 伪造 / 过期 /
     重放全部失败;
  4. 未确认 / 被拒 / 超时一律安全失败(不是「重试」,是终态);
  5. 金库映射不可用时整批失败(不做部分释放);
  6. 审计完整且不含明文;
  7. 防御性上限(单次令牌数、待确认项数)。

诚实边界(不得据此宣称「系统已绝对安全」):
  - 只保证「有身份者显式批准过」,不保证审批人真的逐字审阅了内容(流程/制度问题);
  - 持 CG_ADMIN_TOKEN 者可批准任意待确认项,这是设计上的信任边界;
  - 确认为进程内状态,多副本部署需要 sticky session 或外部存储(与限流同级边界);
  - 释放接口的返回值**就是明文**(这是它的用途),调用方有责任不写进日志/仓库。
"""
from __future__ import annotations

import json
import time

import pytest

from app.middleware.confirmations import (MAX_PENDING_PER_CLIENT,
                                          MAX_TOKENS_PER_CONFIRMATION,
                                          STATUS_CONSUMED, ConfirmationStore)
from app.middleware.errors import MiddlewareError
from tests.mw.conftest import chat, meta_of, reply_text

PHONE = "13800138000"
PHONE2 = "13900139001"


# --------------------------------------------------------------------------- #
# 辅助
# --------------------------------------------------------------------------- #
def _confirmation(client, headers, rid: str, tokens: list[str], reason: str = ""):
    return client.post("/v1/confirmations", headers=headers,
                       json={"request_id": rid, "tokens": tokens,
                             "reason": reason or None})


def _release(client, headers, confirmation_id: str):
    return client.post(f"/v1/confirmations/{confirmation_id}/release",
                       headers=headers)


def _approve(client, admin, confirmation_id: str):
    return client.post(f"/admin/confirmations/{confirmation_id}/approve",
                       headers=admin)


def _deny(client, admin, confirmation_id: str, reason: str = ""):
    return client.post(f"/admin/confirmations/{confirmation_id}/deny",
                       headers=admin, json={"reason": reason})


@pytest.fixture()
def phone_token(mw, client, auth):
    """准备一次含手机号的请求,返回 (request_id, 令牌)。

    手机号属高风险(NEVER_AUTO_RESTORE_TYPES):即便策略允许还原也会被扣留,
    因此它正是「需要人工确认才能取回」的那一类数据。
    """

    def make(number: str = PHONE):
        response = chat(client, auth, f"我的手机号是 {number}")
        assert response.status_code == 200, response.text
        text = reply_text(response)
        assert text and number not in text, "高风险数据不得直接出现在响应里"
        rid = response.headers["X-CryptoGuard-Request-ID"]
        tokens = sorted(mw.token_vault.tokens(rid))
        assert len(tokens) == 1
        return rid, tokens[0]

    return make


# --------------------------------------------------------------------------- #
# 1. 完整流程
# --------------------------------------------------------------------------- #
def test_full_confirmation_flow_releases_once(client, auth, admin, mw, phone_token):
    rid, token = phone_token()

    created = _confirmation(client, auth, rid, [token], reason="客服需要回拨")
    assert created.status_code == 200, created.text
    body = created.json()
    cid = body["confirmation_id"]
    assert body["status"] == "pending"
    assert body["token_count"] == 1
    assert body["tokens"] == [token]
    assert body["token_types"] == {token: "PHONE"}
    assert PHONE not in json.dumps(body, ensure_ascii=False)

    # 未批准前不可释放
    not_yet = _release(client, auth, cid)
    assert not_yet.status_code == 403
    assert "secrets" not in not_yet.json()

    approved = _approve(client, admin, cid)
    assert approved.status_code == 200
    assert approved.json()["status"] == "approved"
    assert approved.json()["decided_by"] == "admin"

    released = _release(client, auth, cid)
    assert released.status_code == 200, released.text
    payload = released.json()
    assert payload["secrets"] == {token: PHONE}
    assert payload["released_count"] == 1
    assert payload["status"] == STATUS_CONSUMED

    # 单次消费:凭据立即失效
    again = _release(client, auth, cid)
    assert again.status_code == 403
    assert "secrets" not in again.json()
    assert client.get(f"/v1/confirmations/{cid}",
                      headers=auth).json()["status"] == STATUS_CONSUMED


def test_confirmation_is_visible_only_to_its_owner(client, admin, auth,
                                                   make_client, phone_token):
    rid, token = phone_token()
    cid = _confirmation(client, auth, rid, [token]).json()["confirmation_id"]

    mine = client.get("/v1/confirmations", headers=auth).json()["data"]
    assert [c["confirmation_id"] for c in mine] == [cid]

    other = make_client("other")["auth"]
    assert client.get("/v1/confirmations", headers=other).json()["data"] == []
    assert client.get(f"/v1/confirmations/{cid}", headers=other).status_code == 403
    assert _release(client, other, cid).status_code == 403

    # 管理员可以看到队列与统计
    queue = client.get("/admin/confirmations", headers=admin).json()
    assert cid in [c["confirmation_id"] for c in queue["data"]]
    assert queue["stats"]["pending"] == 1


# --------------------------------------------------------------------------- #
# 2. 必须经过带身份的批准:客户端不能自我批准
# --------------------------------------------------------------------------- #
def test_client_cannot_approve_its_own_confirmation(client, auth, admin,
                                                    phone_token):
    rid, token = phone_token()
    cid = _confirmation(client, auth, rid, [token]).json()["confirmation_id"]

    # 用客户端密钥调管理接口:401(且不区分「没带」与「带错」)
    assert client.post(f"/admin/confirmations/{cid}/approve",
                       headers=auth).status_code == 401
    assert client.post(f"/admin/confirmations/{cid}/approve").status_code == 401
    assert client.post(f"/admin/confirmations/{cid}/approve",
                       headers={"X-Admin-Token": "guess"}).status_code == 401
    # 仍未批准
    assert _release(client, auth, cid).status_code == 403
    # 管理员批准后才可以
    assert _approve(client, admin, cid).status_code == 200
    assert _release(client, auth, cid).status_code == 200


def test_approval_is_unavailable_without_admin_token(make_mw):
    """没有配置 CG_ADMIN_TOKEN 时,批准接口整体不可用(503),而不是放行。"""
    mw, client, key = make_mw(admin_token="")
    headers = {"Authorization": f"Bearer {key}"}
    response = chat(client, headers, f"我的手机号是 {PHONE}")
    rid = response.headers["X-CryptoGuard-Request-ID"]
    token = sorted(mw.token_vault.tokens(rid))[0]
    cid = _confirmation(client, headers, rid, [token]).json()["confirmation_id"]

    assert client.post(f"/admin/confirmations/{cid}/approve",
                       headers={"X-Admin-Token": "anything"}).status_code == 503
    assert _release(client, headers, cid).status_code == 403


def test_model_asking_for_restore_is_not_approval(make_mw):
    """模型/客户端在请求里声明 acknowledged 不等于授权:高风险数据仍被扣留。"""
    mw, client, key = make_mw(restore_mode="confirm")
    headers = {"Authorization": f"Bearer {key}"}
    response = client.post("/v1/chat/completions", headers=headers, json={
        "model": "mock-chat",
        "messages": [{"role": "user", "content": f"我的手机号是 {PHONE},"
                                                 "我的邮箱是 zhangsan@corp.com.cn"}],
        "cryptoguard": {"acknowledged": True, "restore_mode": "confirm"},
    })
    assert response.status_code == 200, response.text
    text = reply_text(response)
    meta = meta_of(response)
    assert PHONE not in text                        # ack 只影响白名单类别
    assert "zhangsan@corp.com.cn" in text
    assert "PHONE" in {entry["type"] for entry in meta["restore"]["withheld"]}
    # ack 不会自动生成任何待确认项:确认必须由客户端显式申请、管理员显式批准
    assert mw.confirmations.stats()["pending"] == 0
    assert mw.confirmations.stats()["tracked"] == 0
    assert meta["restore"]["withheld"], "被扣留的类别必须如实登记在元数据里"


def test_anonymous_callers_are_rejected_from_the_confirmation_flow(make_mw):
    """匿名(开发模式)调用确认接口一律 403:确认流程必须有可识别身份。"""
    _, client, _ = make_mw(allow_anonymous=True)
    assert chat(client, {}, "hi").status_code == 200          # 匿名仍可正常调用模型

    assert client.post("/v1/confirmations", json={
        "request_id": "cg-x", "tokens": ["[PHONE_001]"]}).status_code == 403
    assert client.get("/v1/confirmations").status_code == 403


# --------------------------------------------------------------------------- #
# 3. 凭据绑定:伪造 / 跨请求 / 跨客户端 / 过期 / 重放
# --------------------------------------------------------------------------- #
def test_tokens_not_issued_by_this_request_are_rejected(client, auth, phone_token):
    rid, _ = phone_token()
    forged = _confirmation(client, auth, rid, [f"[CG_TOKEN_{'ab' * 12}]"])
    assert forged.status_code == 403
    assert "不在该请求的映射金库中" in forged.json()["error"]["message"]

    # 明文形态不是令牌 → 400(确认接口不收明文)
    assert _confirmation(client, auth, rid, [PHONE]).status_code == 400
    # 空数组被 schema 拒绝
    assert _confirmation(client, auth, rid, []).status_code == 400
    # 超过单次上限被 schema 拒绝
    assert _confirmation(client, auth, rid,
                         [f"[PHONE_{i:03d}]" for i in range(33)]).status_code == 400


def test_token_from_another_request_is_rejected(client, auth, mw):
    """请求 A 的令牌不能拿到请求 B 里用。

    注意占位符(模式 A)是**请求内的序号**:两个含手机号的请求各自都叫
    `[PHONE_001]`,字符串本身不携带身份。真正起约束作用的是「金库按 request_id
    分区」——下面用「另一个请求里不存在这个令牌」的形态来验证这条边界。
    """
    first = chat(client, auth, f"我的手机号是 {PHONE}")
    rid_a = first.headers["X-CryptoGuard-Request-ID"]
    token_a = sorted(mw.token_vault.tokens(rid_a))[0]
    assert token_a == "[PHONE_001]"

    second = chat(client, auth, "我的邮箱是 zhangsan@corp.com.cn")
    rid_b = second.headers["X-CryptoGuard-Request-ID"]
    token_b = sorted(mw.token_vault.tokens(rid_b))[0]
    assert token_b == "[EMAIL_001]"

    cross = _confirmation(client, auth, rid_b, [token_a])
    assert cross.status_code == 403
    assert "不在该请求的映射金库中" in cross.json()["error"]["message"]
    # 本请求自己的令牌照常可以申请
    assert _confirmation(client, auth, rid_b, [token_b]).status_code == 200


def test_same_label_in_two_requests_resolves_to_each_requests_own_value(
        client, auth, admin, mw):
    """同号标签不串味:拿请求 B 的 id 申请 `[PHONE_001]`,只能得到 B 自己的值。

    这是「跨请求还原」最容易被忽略的形态:占位符字符串相同不代表映射相同。
    """
    rid_a, token_a = _make_phone_request(client, auth, mw, PHONE)
    rid_b, token_b = _make_phone_request(client, auth, mw, PHONE2)
    assert (token_a, token_b) == ("[PHONE_001]", "[PHONE_001]")

    cid = _confirmation(client, auth, rid_b, [token_b]).json()["confirmation_id"]
    assert _approve(client, admin, cid).status_code == 200
    released = _release(client, auth, cid).json()["secrets"]
    assert released == {token_b: PHONE2}
    assert PHONE not in released.values()          # 请求 A 的值取不到

    # 请求 A 自己的确认与请求 B 的互不影响
    cid_a = _confirmation(client, auth, rid_a, [token_a]).json()["confirmation_id"]
    assert _approve(client, admin, cid_a).status_code == 200
    assert _release(client, auth, cid_a).json()["secrets"] == {token_a: PHONE}


def _make_phone_request(client, headers, mw, number: str):
    response = chat(client, headers, f"我的手机号是 {number}")
    assert response.status_code == 200, response.text
    rid = response.headers["X-CryptoGuard-Request-ID"]
    tokens = sorted(mw.token_vault.tokens(rid))
    assert len(tokens) == 1
    return rid, tokens[0]


def test_request_id_of_another_client_is_rejected(client, auth, make_client,
                                                  phone_token):
    rid, token = phone_token()
    other = make_client("other")["auth"]
    stolen = _confirmation(client, other, rid, [token])
    assert stolen.status_code == 403
    assert "不存在或不属于当前客户端密钥" in stolen.json()["error"]["message"]
    # 与「不存在的 request_id」返回完全相同的错误(不区分,避免成为存在性探针)
    unknown = _confirmation(client, other, "cg-00000000000000000000000000000000",
                            [token])
    assert unknown.status_code == 403
    assert unknown.json()["error"]["message"] == stolen.json()["error"]["message"]


def test_confirmation_cannot_be_released_by_another_client(client, auth, admin,
                                                           make_client, phone_token):
    rid, token = phone_token()
    cid = _confirmation(client, auth, rid, [token]).json()["confirmation_id"]
    assert _approve(client, admin, cid).status_code == 200

    thief = make_client("thief")["auth"]
    stolen = _release(client, thief, cid)
    assert stolen.status_code == 403
    assert "secrets" not in stolen.json()
    # 真正的属主仍可释放:别人的尝试没有消耗掉这次机会
    assert _release(client, auth, cid).status_code == 200


def test_expired_confirmation_is_terminal(client, auth, admin, mw, phone_token):
    rid, token = phone_token()
    cid = _confirmation(client, auth, rid, [token]).json()["confirmation_id"]

    # 直接把有效期推到过去(确定性,不依赖 sleep)
    mw.confirmations.get(cid).expires_epoch = time.time() - 1

    assert client.get(f"/v1/confirmations/{cid}",
                      headers=auth).json()["status"] == "expired"
    assert _release(client, auth, cid).status_code == 403
    # 过期后也不能靠批准「复活」
    assert _approve(client, admin, cid).status_code == 403
    assert _release(client, auth, cid).status_code == 403


def test_approved_confirmation_expires_too(client, auth, admin, mw, phone_token):
    """批准不是永久有效:批准后超过有效期仍然不可释放。"""
    rid, token = phone_token()
    cid = _confirmation(client, auth, rid, [token]).json()["confirmation_id"]
    assert _approve(client, admin, cid).status_code == 200

    mw.confirmations.get(cid).expires_epoch = time.time() - 1
    denied = _release(client, auth, cid)
    assert denied.status_code == 403
    assert "secrets" not in denied.json()


def test_denied_confirmation_is_terminal(client, auth, admin, phone_token):
    rid, token = phone_token()
    cid = _confirmation(client, auth, rid, [token]).json()["confirmation_id"]

    denied = _deny(client, admin, cid, reason="非业务必要")
    assert denied.status_code == 200
    assert denied.json()["status"] == "denied"
    assert denied.json()["note"] == "非业务必要"

    assert _release(client, auth, cid).status_code == 403
    assert _approve(client, admin, cid).status_code == 403     # 终态不可翻案
    assert _deny(client, admin, cid).status_code == 200        # 重复拒绝是幂等的


def test_unknown_confirmation_id_is_not_found(client, auth, admin):
    assert _release(client, auth, "cgc-doesnotexist").status_code == 404
    assert _approve(client, admin, "cgc-doesnotexist").status_code == 404
    assert client.get("/v1/confirmations/cgc-doesnotexist",
                      headers=auth).status_code == 404


# --------------------------------------------------------------------------- #
# 4. 金库映射不可用 → 整批失败(不做部分释放)
# --------------------------------------------------------------------------- #
def test_missing_mapping_fails_without_burning_the_credential(client, auth, admin,
                                                              mw, phone_token):
    rid, token = phone_token()
    cid = _confirmation(client, auth, rid, [token]).json()["confirmation_id"]
    assert _approve(client, admin, cid).status_code == 200

    mw.token_vault.drop(rid)                 # 模拟映射过期/被清理
    failed = _release(client, auth, cid)
    assert failed.status_code == 404
    assert "secrets" not in failed.json()
    # 失败不烧机会:金库恢复后仍可释放(否则一次读取失败会让授权永久失效)
    assert client.get(f"/v1/confirmations/{cid}",
                      headers=auth).json()["status"] == "approved"


def test_multi_token_confirmation_is_all_or_nothing(client, auth, admin, mw):
    response = chat(client, auth, f"电话一 {PHONE},电话二 {PHONE2}")
    rid = response.headers["X-CryptoGuard-Request-ID"]
    tokens = sorted(mw.token_vault.tokens(rid))
    assert tokens == ["[PHONE_001]", "[PHONE_002]"]

    cid = _confirmation(client, auth, rid, tokens).json()["confirmation_id"]
    assert _approve(client, admin, cid).status_code == 200

    entries = mw.token_vault._records[rid].entries      # noqa: SLF001 — 模拟单条映射失效
    stash = entries.pop(tokens[1])
    failed = _release(client, auth, cid)
    assert failed.status_code == 404
    assert "secrets" not in failed.json()               # 不做部分释放

    entries[tokens[1]] = stash                          # 两条都在 → 整批释放
    ok = _release(client, auth, cid)
    assert ok.status_code == 200
    assert ok.json()["secrets"] == {tokens[0]: PHONE, tokens[1]: PHONE2}


# --------------------------------------------------------------------------- #
# 5. 审计:完整、可归属、不含明文
# --------------------------------------------------------------------------- #
def test_audit_records_every_step_without_plaintext(client, auth, admin, mw,
                                                    phone_token, data_dir):
    rid, token = phone_token()
    cid = _confirmation(client, auth, rid, [token]).json()["confirmation_id"]
    _approve(client, admin, cid)
    assert _release(client, auth, cid).status_code == 200

    rows = mw.audit.list(limit=100)["items"]
    outcomes = [row["outcome"] for row in rows]
    for expected in ("ok", "confirmation_pending", "confirmation_approved",
                     "confirmation_released"):
        assert expected in outcomes, f"审计缺少 {expected}"

    events = [row for row in rows
              if str(row.get("outcome", "")).startswith("confirmation_")]
    assert len(events) == 3
    owner = mw.clients.list_clients()[0].id
    for event in events:
        assert event["actions"]["tokens"] == [token]   # 记令牌(可追溯),不记明文
        assert event["client_id"] == owner
        assert PHONE not in json.dumps(event, ensure_ascii=False)

    assert mw.audit.verify()["intact"] is True
    on_disk = "".join(path.read_text(encoding="utf-8", errors="ignore")
                      for path in data_dir.rglob("*") if path.is_file())
    assert PHONE not in on_disk, "释放出来的明文不得落盘"


def test_admin_rejections_are_not_attributed_to_the_client(client, admin, mw):
    """管理面的失败不能被写成「某客户端的失败请求」(审计归属必须准确)。"""
    before = mw.audit.count()
    assert _approve(client, admin, "cgc-nope").status_code == 404
    assert mw.audit.count() == before


# --------------------------------------------------------------------------- #
# 6. 防御性上限与对外视图(存储层单元测试,确定性)
# --------------------------------------------------------------------------- #
def test_confirmation_store_limits_and_idempotency():
    store = ConfirmationStore(ttl_s=60.0)

    first = store.create(client_id="c1", client_name="n", request_id="r1",
                         tokens=["[PHONE_001]"], token_types={"[PHONE_001]": "PHONE"})
    same = store.create(client_id="c1", client_name="n", request_id="r1",
                        tokens=["[PHONE_001]"], token_types={})
    assert same.id == first.id                       # 同 (客户端, 请求, 令牌集) 幂等

    store.create(client_id="c1", client_name="n", request_id="r1",
                 tokens=["[PHONE_001]", "[PHONE_002]"], token_types={})
    assert store.stats()["pending"] == 2             # 令牌集不同则是另一条申请

    with pytest.raises(MiddlewareError) as excinfo:
        store.create(client_id="c1", client_name="n", request_id="r2",
                     tokens=[f"[T_{i}]" for i in
                             range(MAX_TOKENS_PER_CONFIRMATION + 1)],
                     token_types={})
    assert excinfo.value.kind == "invalid_request"

    for index in range(MAX_PENDING_PER_CLIENT + 4):
        try:
            store.create(client_id="c2", client_name="n", request_id=f"p{index}",
                         tokens=[f"[PHONE_{index:03d}]"], token_types={})
        except MiddlewareError as exc:
            assert exc.kind == "rate_limit"
            break
    else:  # pragma: no cover — 走到这里说明上限没生效
        pytest.fail("待确认项上限未生效:内存可被申请无限占用")
    assert store.stats()["pending"] <= MAX_PENDING_PER_CLIENT + 2

    # 空令牌集拒绝
    with pytest.raises(MiddlewareError):
        store.create(client_id="c3", client_name="n", request_id="r9",
                     tokens=[], token_types={})


def test_confirmation_public_view_has_no_plaintext_or_key_material():
    store = ConfirmationStore(ttl_s=60.0)
    record = store.create(client_id="c1", client_name="n", request_id="r1",
                          tokens=["[PHONE_001]"],
                          token_types={"[PHONE_001]": "PHONE"})
    view = record.public_view()
    assert set(view) == {"confirmation_id", "status", "request_id", "tokens",
                         "token_types", "token_count", "reason", "created_epoch",
                         "expires_epoch", "decided_by", "decided_epoch",
                         "consumed_epoch", "note", "boundary"}
    assert view["boundary"]["single_use"] and view["boundary"]["client_bound"]
    assert view["boundary"]["admin_approval"]
    assert "not_proof_of_review" in view["boundary"]     # 诚实标注边界
    assert PHONE not in json.dumps(view, ensure_ascii=False)
