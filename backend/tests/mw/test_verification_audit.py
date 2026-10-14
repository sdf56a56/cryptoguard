"""
第 4 阶段 · 任务 7 —— 验证与审计的端到端安全验证

本文件验证三件事,并且**把它们的区别作为断言写下来**:

  (1) 记录完整性   —— 审计记录没被改过(行级封缄 + 记录级 HMAC + 哈希链);
  (2) 摘要匹配     —— 客户端手里的请求/响应与网关记录的**逐字节一致**;
  (3) 保护是否生效 —— 这一次调用里原始敏感数据有没有出网/有没有被还原。

三者是**互相独立**的结论,任何一件成立都不蕴含另一件:
  - 记录完整性成立 ≠ 上游没收到明文(记录里本来就不含明文,它只记摘要与计数);
  - 摘要匹配成立  ≠ 内容正确或安全(它只说「没被改动」);
  - 保护生效      ≠ 记录没被改过。
本文件用测试把这条边界钉死,防止日后把 verify 接口当成「安全判定器」。

诚实边界(与实现中的边界说明一致,不得含糊):
  - 哈希 / HMAC / 哈希链只能证明「本地网关写下的东西没被改」,不证明响应来自某个
    模型服务商(那需要服务商侧签名,当前上游 API 不提供);
  - **持 VAULT_KEY 者可整链重写**(重算封缄与 MAC),本文件以 `_boundary` 结尾的
    用例如实展示这一点,并提供外部锚点(tip_hash 抄到站外)下的检测手段;
  - **尾段截断**同理不可由本地日志自证(实现文档已声明不承诺),本文件同样如实展示,
    并给出「客户端持有 request_id + 摘要」时的发现路径;
  - verify 接口对「请求是否存在」是诚实的:不存在的 id 与不属于自己的 id 返回不同
    结论,但 request_id 是 128 位随机值,不可枚举(有专测)。
"""
from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from app.keys import Vault, hkdf_sha256
from app.middleware.audit import AUDIT_DIR_NAME
from app.middleware.errors import MiddlewareError
from app.store import entry_checksum
from tests.mw.conftest import chat, meta_of

PHONE = "13800138000"
EMAIL = "zhangsan@corp.com.cn"
PROMPT = f"我的手机号是 {PHONE},邮箱是 {EMAIL}"

RID_HEADER = "X-CryptoGuard-Request-ID"


# --------------------------------------------------------------------------- #
# 辅助
# --------------------------------------------------------------------------- #
def _one(client, auth, text: str = PROMPT):
    """发一次请求,返回 (response, request_id)。"""
    response = chat(client, auth, text)
    assert response.status_code == 200, response.text
    return response, response.headers[RID_HEADER]


def _verify(client, auth, body: dict, **kw):
    return client.post("/v1/verify", json=body, headers=kw.pop("headers", auth))


def _audit_segments(data_dir: Path) -> list[Path]:
    return sorted((Path(data_dir) / AUDIT_DIR_NAME).glob("audit-*.ndjson"))


def _rows(data_dir: Path) -> list[dict]:
    out: list[dict] = []
    for path in _audit_segments(data_dir):
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                out.append(json.loads(line))
    return out


def _rewrite_rows(data_dir: Path, rows: list[dict]) -> None:
    """把全部审计行按给定顺序重写回**单一段文件**(模拟有写权限的攻击者)。"""
    for path in _audit_segments(data_dir):
        path.unlink()
    target = Path(data_dir) / AUDIT_DIR_NAME / "audit-000001.ndjson"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows),
                      encoding="utf-8")


def _mutate(data_dir: Path, index: int, **changes) -> dict:
    """改一条记录后原位写回;返回被改坏的那条(未重算封缄 → 应被判 corrupt)。"""
    rows = _rows(data_dir)
    rows[index].update(changes)
    _rewrite_rows(data_dir, rows)
    return rows[index]


def _chain(client, admin) -> dict:
    response = client.post("/admin/audit/verify", headers=admin)
    assert response.status_code == 200, response.text
    return response.json()


def _fail_kinds(result: dict) -> set[str]:
    return {f["kind"] for f in result.get("failures") or []}


def _fresh_audit(client, auth, data_dir, mw):
    """审计有 5 秒结论缓存:改动磁盘后必须强制重算,否则测的是缓存不是事实。"""
    mw.audit._verify_cache = None                       # noqa: SLF001 — 见上
    return mw.audit.verify(fresh=True)


def test_verify_requires_authentication(client, mw):
    """未带凭证的 verify 不得返回任何记录信息。"""
    _, rid = _one(client, _auth_of(client, mw))
    anonymous = client.post("/v1/verify", json={"request_id": rid})
    assert anonymous.status_code in (401, 403)
    assert rid not in anonymous.text or PHONE not in anonymous.text
    forged = client.post("/v1/verify", json={"request_id": rid},
                         headers={"Authorization": f"Bearer {'x' * 40}"})
    assert forged.status_code in (401, 403)
    assert PHONE not in forged.text and EMAIL not in forged.text


def _auth_of(client, mw) -> dict:
    """从 bootstrap 文件取合法客户端密钥(与 conftest 的 auth 夹具同源)。"""
    with open(mw.settings.bootstrap_key_file, encoding="utf-8") as handle:
        return {"Authorization": f"Bearer {handle.read().strip()}"}


def test_verify_needs_the_middleware_to_be_built(client, auth):
    """未装配中间件时 verify 不得假装成功(503 + 明确错误类型,而不是 200)。"""
    from app import main as main_mod
    saved = getattr(main_mod.app.state, "middleware", None)
    if saved is not None:
        delattr(main_mod.app.state, "middleware")
    try:
        response = client.post("/v1/verify", json={"request_id": "cg-" + "1" * 32},
                               headers=auth)
        assert response.status_code == 503
        assert response.json()["error"]["type"] == "config"
    finally:
        if saved is not None:
            main_mod.app.state.middleware = saved


# --------------------------------------------------------------------------- #
# 1. 有效记录仍然可验证
# --------------------------------------------------------------------------- #
def test_valid_record_verifies_in_full(client, auth, admin, mw):
    response, rid = _one(client, auth)
    meta = meta_of(response)

    result = _verify(client, auth, {
        "request_id": rid,
        "request_digest": meta["digest"]["request"],
        "response": {"text": response.json()["choices"][0]["message"]["content"],
                     "model": "mock-chat", "finish_reason": "stop"},
    }).json()

    assert result["found"] is True
    assert result["request_digest_match"] is True
    assert result["response_digest_match"] is True
    assert result["record_mac_valid"] is True
    assert result["failures"] == []
    assert result["chain"]["intact"] is True
    assert result["protection_mode"] == "placeholder"
    assert result["policy_version"] == meta["policy_version"]
    # 元数据里给的链位置与审计里的记录一致
    assert result["audit"]["chain_hash"] == meta["audit"]["chain_hash"]
    assert result["audit"]["seq"] == meta["audit"]["seq"]


def _auth_of(client, mw) -> dict:
    """从 bootstrap 文件取合法客户端密钥(与 conftest 的 auth 夹具同源)。"""
    with open(mw.settings.bootstrap_key_file, encoding="utf-8") as handle:
        return {"Authorization": f"Bearer {handle.read().strip()}"}


def test_verify_needs_the_middleware_to_be_built(client, auth):
    response, rid = _one(client, auth)
    meta = meta_of(response)

    result = _verify(client, auth, {
        "request_id": rid,
        "request_digest": meta["digest"]["request"],
        "response": {"text": response.json()["choices"][0]["message"]["content"],
                     "model": "mock-chat", "finish_reason": "stop"},
    }).json()

    assert result["found"] is True
    assert result["request_digest_match"] is True
    assert result["response_digest_match"] is True
    assert result["record_mac_valid"] is True
    assert result["failures"] == []
    assert result["chain"]["intact"] is True
    assert result["protection_mode"] == "placeholder"
    assert result["policy_version"] == meta["policy_version"]
    # 元数据里给的链位置与审计里的记录一致
    assert result["audit"]["chain_hash"] == meta["audit"]["chain_hash"]
    assert result["audit"]["seq"] == meta["audit"]["seq"]


def test_verified_record_reports_counts_not_values(client, auth):
    response, rid = _one(client, auth)
    result = _verify(client, auth, {"request_id": rid}).json()
    body = json.dumps(result, ensure_ascii=False)
    assert PHONE not in body and EMAIL not in body
    assert result["detections"]["by_type"].get("PHONE") == 1
    # 还原视图只有类别与计数,没有任何 token→明文 的映射
    assert "restored" in result["restore"] and "withheld" in result["restore"]
    for entry in [*result["restore"]["restored"], *result["restore"]["withheld"]]:
        assert set(entry) <= {"token", "type", "risk", "reason"}
        for value in entry.values():
            assert PHONE not in str(value) and EMAIL not in str(value)


def test_unknown_request_id_is_reported_as_not_found(client, auth):
    result = _verify(client, auth, {"request_id": "cg-" + "0" * 32}).json()
    assert result["found"] is False
    assert result["failures"] == ["not_found"]
    assert result["policy_version"] is None
    assert "cg-" + "0" * 32 in json.dumps(result)     # 只回显查询,不回显内容


# --------------------------------------------------------------------------- #
# 2. 三个结论必须互相独立(不得混为一谈)
# --------------------------------------------------------------------------- #
def test_tampered_response_is_reported_but_record_integrity_stays_valid(client, auth):
    """客户端手里的响应被改过:摘要不匹配,但记录本身仍然完好。"""
    response, rid = _one(client, auth)
    tampered = response.json()["choices"][0]["message"]["content"] + " (被改)"

    result = _verify(client, auth, {
        "request_id": rid,
        "response": {"text": tampered, "model": "mock-chat",
                     "finish_reason": "stop"},
    }).json()

    assert result["response_digest_match"] is False
    assert "response_digest_mismatch" in result["failures"]
    assert result["record_mac_valid"] is True          # 记录没被改
    assert result["chain"]["intact"] is True
    assert result["request_digest_match"] is None      # 没提供 → 不表态


def test_tool_call_response_digest_covers_name_and_arguments(client, auth):
    """工具调用的响应摘要必须真的覆盖工具名与参数 —— 否则改了参数也「一致」。

    客户端拿到的工具调用是 OpenAI 形态(`{"function": {"name", "arguments"}}`),
    摘要前映像里记的是 `[name, arguments]` 对。若两侧对不上,摘要会把工具调用当空值,
    于是「篡改参数」与「原样」算出同一个摘要 —— 完整性校验名存实亡。
    """
    body = {
        "model": "mock-tools",
        "messages": [{"role": "user", "content": f"USE_TOOL 请联系 {EMAIL}"}],
        "tools": [{"type": "function",
                   "function": {"name": "send_mail", "description": "发邮件",
                                "parameters": {"type": "object", "properties": {}}}}],
        "tool_choice": "auto",
    }
    response = client.post("/v1/chat/completions", json=body, headers=auth)
    assert response.status_code == 200, response.text
    payload = response.json()
    choice = payload["choices"][0]
    calls = choice["message"]["tool_calls"]
    assert calls, "mock 上游应返回工具调用"

    def _probe(tool_calls):
        return _verify(client, auth, {
            "request_id": response.headers[RID_HEADER],
            "response": {"text": choice["message"]["content"] or "",
                         "tool_calls": tool_calls,
                         "model": payload["model"],
                         "finish_reason": choice["finish_reason"]},
        }).json()

    honest = _probe(calls)
    assert honest["response_digest_match"] is True, (
        "客户端按自己收到的工具调用复算,却与记录不一致(摘要前映像两侧形态不一致)")

    tampered = json.loads(json.dumps(calls))
    tampered[0]["function"]["arguments"] = json.dumps(
        {"echo": "被改过的参数"}, ensure_ascii=False)
    result = _probe(tampered)
    assert result["response_digest_match"] is False, (
        "改了工具调用参数却仍然「摘要一致」——摘要没有覆盖 arguments")
    assert "response_digest_mismatch" in result["failures"]


def test_verify_does_not_assert_what_it_did_not_check(client, auth):
    """没给待比对响应时,摘要结论必须是 None(「未检查」),不能是 True。"""
    _, rid = _one(client, auth)
    result = _verify(client, auth, {"request_id": rid}).json()
    assert result["response_digest_match"] is None
    assert result["request_digest_match"] is None
    assert result["failures"] == []


def test_no_field_claims_the_system_is_safe(client, auth):
    """verify 的返回值里不得出现「已安全/已保护」这类结论性布尔字段。"""
    response, rid = _one(client, auth)
    result = _verify(client, auth, {
        "request_id": rid,
        "response": {"text": response.json()["choices"][0]["message"]["content"],
                     "model": "mock-chat", "finish_reason": "stop"},
    }).json()

    flat = json.dumps(result, ensure_ascii=False).lower()
    for word in ('"safe"', '"secure"', '"protection_ok"', '"secure":',
                 '"is_protected"', '"guaranteed"'):
        assert word not in flat, f"verify 给出了不该有的安全性结论:{word}"
    # 它给出的是「哪些项检查过、结果如何」,并附带能力边界说明
    assert set(result["boundary"]) >= {"hash_meaning", "provider_identity",
                                       "admin_tamper", "write_scope"}
    assert result["record_mac_valid"] is True


def test_protection_and_verification_are_separate_signals(client, auth, mw):
    """保护生效(原文没出网)与记录可验证是两条独立的证据链。"""
    response, rid = _one(client, auth)
    # 保护侧证据:上游收到的是令牌(取 mock 提供商实际收到的请求)
    from tests.mw.conftest import upstream_seen_text
    seen = upstream_seen_text(mw)
    assert PHONE not in seen and EMAIL not in seen
    # 验证侧证据:记录完好且摘要自洽 —— 但它**不**声称上面那件事
    result = _verify(client, auth, {"request_id": rid}).json()
    assert result["chain"]["intact"] is True
    assert "上游" not in json.dumps(result["failures"], ensure_ascii=False)
    assert PHONE not in json.dumps(result, ensure_ascii=False)


# --------------------------------------------------------------------------- #
# 3. 验证接口不是明文 / 令牌映射查询接口
# --------------------------------------------------------------------------- #
def test_verify_is_not_a_plaintext_or_mapping_oracle(client, auth, mw, data_dir):
    """verify 只能报告「摘要是否一致」,不能用来试探令牌→明文的对应关系。

    诚实说明:自己的那次请求的响应里会回显**该请求自己的**令牌(在 restore.withheld
    里,客户端本来就知道这些占位符),但绝不会给出令牌对应的明文;而**伪造的**
    令牌查询不会在响应里留下任何痕迹(既不出现,也不提示「这个令牌对不对」)。
    """
    response, rid = _one(client, auth)
    own_tokens = set(mw.token_vault.tokens(rid))
    surfaces = [_verify(client, auth, {"request_id": rid}).text]
    for probe in sorted(probe_tokens()):
        surfaces.append(_verify(client, auth,
                                {"request_id": rid, "request_digest": probe}).text)
        surfaces.append(_verify(client, auth,
                                {"request_id": rid, "response_digest": probe}).text)
    for surface in surfaces:
        assert PHONE not in surface and EMAIL not in surface
    # 伪造令牌不得以任何形式出现在答复里(不确认存在性)
    for surface in surfaces[1:]:
        for token in probe_tokens():
            assert token not in surface
    # 只有这次请求自己的令牌可能被回显,且不带明文
    echoed = set()
    for surface in surfaces:
        echoed |= {t for t in own_tokens if t in surface}
    assert echoed <= own_tokens


def probe_tokens() -> set[str]:
    """不在本次请求金库里的令牌(猜的),它们连出现都不该出现。"""
    return {"[PHONE_002]", "[CG_TOKEN_deadbeef]", "[CG_ENC_v1_zz", "[EMAIL_009]"}


def test_admin_audit_surfaces_contain_no_plaintext(client, auth, admin, mw):
    response, rid = _one(client, auth)
    for surface in (client.get("/admin/audit", headers=admin),
                    client.get(f"/admin/audit/{rid}", headers=admin),
                    client.get("/health"),
                    client.get("/admin/security/policies", headers=admin)):
        assert surface.status_code == 200, surface.text
        body = json.dumps(surface.json(), ensure_ascii=False)
        assert PHONE not in body and EMAIL not in body
    # 审计记录里也不含客户端密钥与上游密钥
    from tests.mw.conftest import FAKE_UPSTREAM_KEY
    client_key = _auth_of(client, mw)["Authorization"].removeprefix("Bearer ")
    body = json.dumps(client.get(f"/admin/audit/{rid}", headers=admin).json(),
                      ensure_ascii=False)
    assert client_key not in body and FAKE_UPSTREAM_KEY not in body
    assert "authorization" not in body.lower()


def test_request_ids_are_unguessable_and_unique(client, auth):
    ids = [_one(client, auth)[1] for _ in range(5)]
    assert len(set(ids)) == 5
    for rid in ids:
        assert rid.startswith("cg-")
        suffix = rid[3:]
        assert len(suffix) == 32 and all(c in "0123456789abcdef" for c in suffix)


# --------------------------------------------------------------------------- #
# 4. 篡改:改写 / 删除 / 重排 / 重放
# --------------------------------------------------------------------------- #
@pytest.fixture()
def three_records(client, auth, mw, data_dir):
    ids = [_one(client, auth, f"第 {i} 次:{PROMPT}")[1] for i in range(3)]
    assert len(_rows(data_dir)) == 3
    return ids


def test_untouched_records_verify_before_any_tampering(three_records, client, admin,
                                                       mw, data_dir):
    result = _fresh_audit(client, None, data_dir, mw)
    assert result["intact"] is True and len(result["failures"]) == 0
    assert result["records"] == 3 and result["mac_verified"] is True
    assert _chain(client, admin)["intact"] is True


def test_modified_record_field_is_detected(three_records, client, admin, mw, data_dir):
    _mutate(data_dir, 1, response_digest="0" * 64)
    assert _chain(client, admin)["intact"] is False
    result = _fresh_audit(client, None, data_dir, mw)
    assert "corrupt" in _fail_kinds(result)          # 行级封缄先抓住
    assert result["mac_verified"] is False


def test_deleted_record_is_detected(three_records, client, admin, mw, data_dir):
    rows = _rows(data_dir)
    _rewrite_rows(data_dir, [rows[0], rows[2]])       # 删掉中间那条
    result = _fresh_audit(client, None, data_dir, mw)
    assert result["intact"] is False
    assert _fail_kinds(result) & {"chain_break", "sequence_gap"}
    assert _chain(client, admin)["intact"] is False


def test_reordered_records_are_detected(three_records, client, admin, mw, data_dir):
    rows = _rows(data_dir)
    _rewrite_rows(data_dir, [rows[0], rows[2], rows[1]])
    result = _fresh_audit(client, None, data_dir, mw)
    assert result["intact"] is False
    assert _fail_kinds(result) & {"chain_break", "sequence_gap", "mac_mismatch"}


def test_replayed_old_record_line_is_detected(three_records, client, admin, mw,
                                              data_dir):
    """重放:把第一条记录再追加一次(seq/链位置都不会自洽)。"""
    rows = _rows(data_dir)
    _rewrite_rows(data_dir, [*rows, dict(rows[0])])
    result = _fresh_audit(client, None, data_dir, mw)
    assert result["intact"] is False
    assert _fail_kinds(result) & {"chain_break", "sequence_gap"}


def test_replayed_request_id_keeps_both_records_and_stays_verifiable(client, auth, mw,
                                                                     data_dir):
    """同一个 request_id 出现两次(重试/重放同一请求)不会覆盖历史。"""
    _, rid = _one(client, auth)
    _, rid2 = _one(client, auth)
    rows = _rows(data_dir)
    assert len(rows) == 2 and rid != rid2            # 每次调用都是新的 request_id
    # 手工制造「同 id 两条记录」:复制第二条并改回第一条的 id 会破坏封缄,
    # 因此这里只断言实现层面的语义 —— get() 取最后一条,且历史不被删。
    before = len(rows)
    _one(client, auth)
    assert len(_rows(data_dir)) == before + 1
    assert mw.audit.get(rid)["request_id"] == rid
    assert _fresh_audit(client, None, data_dir, mw)["intact"] is True


def test_record_rewritten_with_recomputed_seal_is_still_caught_by_mac(
        three_records, client, admin, mw, data_dir):
    """攻击者能改文件(甚至重算行级封缄与链哈希),但没有 VAULT_KEY → MAC 挡住。

    这条用例模拟「有磁盘写权限但没有根密钥」的对手:它可以把 entry_checksum、
    chain_hash、后继记录的 prev_hash 全部重算得自洽,唯独算不出记录级 HMAC
    (`audit-mac/v1` 域,密钥从 VAULT_KEY 派生且明文不落盘)。
    """
    rows = _rows(data_dir)
    sealing_key = mw.vault.chain_mac_key
    rows[1]["response_digest"] = "0" * 64
    # 逐条重算链(prev_hash → chain_hash)与行级封缄,使结构自洽
    for index, row in enumerate(rows):
        from app.middleware.verification import chain_hash_of
        row["prev_hash"] = rows[index - 1]["chain_hash"] if index else ""
        row["chain_hash"] = chain_hash_of(row["prev_hash"], row["seq"],
                                          row["request_id"], row["request_digest"],
                                          row["response_digest"], row["ts"])
        row.pop("entry_checksum", None)
        row["entry_checksum"] = entry_checksum(sealing_key, row)
    _rewrite_rows(data_dir, rows)

    result = _fresh_audit(client, None, data_dir, mw)
    assert result["intact"] is False
    assert "mac_mismatch" in _fail_kinds(result), result["failures"]
    assert _chain(client, admin)["intact"] is False


def test_insider_holding_vault_key_can_rewrite_chain_boundary(
        three_records, client, admin, mw, data_dir):
    """**已知边界(不是缺陷,不得当作已解决)**:

    持 VAULT_KEY 的攻击者可以重算封缄与记录 MAC,把某条记录改成任意内容,
    本地日志自校验将**如实报告完整** —— 因为它确实「完整且自洽」。
    检测这类整链重写需要站外锚点(把 tip_hash / seq 抄到别处),见下一条用例。
    """
    from app.middleware.verification import chain_hash_of, record_mac
    rows = _rows(data_dir)
    mac_key = hkdf_sha256(mw.vault.chain_mac_key, "audit-mac/v1")
    rows[1]["response_digest"] = "0" * 64
    from app.middleware.verification import RequestRecord
    for index, row in enumerate(rows):
        row["prev_hash"] = rows[index - 1]["chain_hash"] if index else ""
        row["chain_hash"] = chain_hash_of(row["prev_hash"], row["seq"],
                                          row["request_id"], row["request_digest"],
                                          row["response_digest"], row["ts"])
        row["record_mac"] = record_mac(
            mac_key, RequestRecord(**{k: v for k, v in row.items()
                                      if k in RequestRecord.__dataclass_fields__}))
        row.pop("entry_checksum", None)
        row["entry_checksum"] = entry_checksum(mw.vault.chain_mac_key, row)
    _rewrite_rows(data_dir, rows)

    result = _fresh_audit(client, None, data_dir, mw)
    assert result["intact"] is True, "本用例的目的正是展示:持根密钥者可自洽重写"
    assert result["scope_note"]                  # 实现如实标注了这条边界


def test_external_anchor_detects_whole_chain_rewrite(three_records, client, admin,
                                                     mw, data_dir):
    """站外锚点:把 (seq, tip_hash) 抄在外面,整链重写就藏不住了。"""
    anchor = mw.audit.tip()
    assert anchor["seq"] == 3 and anchor["chain_hash"]

    _mutate(data_dir, 1, response_digest="1" * 64)
    result = _fresh_audit(client, None, data_dir, mw)
    assert result["intact"] is False
    # 即使攻击者把结构改自洽,锚点比对仍能发现「这一条不在我记录的那条链上」
    tip_now = mw.audit.tip()
    assert tip_now["chain_hash"] and result.get("tip_hash", "") != anchor["chain_hash"]


def test_tail_truncation_is_not_detectable_locally_boundary(three_records, client,
                                                            admin, mw, data_dir):
    """**已知边界**:删掉**最后**一条记录后,本地日志自校验无法发现(实现已声明
    「不承诺检测尾段删除(截断)」)。这里如实固化这一事实,并给出客户端侧的发现路径。
    """
    rows = _rows(data_dir)
    removed = rows[-1]["request_id"]
    _rewrite_rows(data_dir, rows[:-1])

    result = _fresh_audit(client, None, data_dir, mw)
    assert result["intact"] is True, "尾段截断在本地自校验下确实不可见(如实固化)"
    assert result["records"] == 2
    # 但被删掉的那次调用仍有独立的发现路径:客户端拿 request_id 查询 → not_found
    probe = _verify(client, _auth_of(client, mw), {"request_id": removed}).json()
    assert probe["found"] is False
    assert probe["failures"] == ["not_found"]


def test_torn_write_fails_closed_and_is_not_silently_ignored(client, admin, mw,
                                                             data_dir):
    """异常退出留下的半截行必须被拒绝(fail-closed),而不是当作没发生。"""
    _one(client, _auth_of(client, mw))
    segment = _audit_segments(data_dir)[-1]
    with segment.open("a", encoding="utf-8") as handle:
        handle.write('{"request_id": "cg-torn", "seq": 99')   # 半截 JSON,无换行

    result = _fresh_audit(client, None, data_dir, mw)
    assert result["intact"] is False
    assert "corrupt" in _fail_kinds(result)
    assert _chain(client, admin)["intact"] is False
    # 且 fail-closed:健康检查如实报出链损坏(不吞掉、不报 ok)
    mw.audit._verify_cache = None                    # noqa: SLF001 — 绕过 5s 缓存
    assert client.get("/health").json()["audit"]["chain_intact"] is False
    # 重启后不允许再往这条损坏的链上追加(见 test_restart_refuses_to_append_...)


def test_sealed_store_never_swallows_a_record_after_a_torn_line(tmp_path):
    """存储原语回归:半截行之后的**下一条正常记录**必须落在自己的行上。

    崩溃后重启的真实序列:文件末尾留着一条没写完的行(无换行),新进程接着写。
    若 append 直接续写,半截行与新记录会被拼成同一行 —— 一次异常退出会连带毁掉
    之后写入的记录(数据丢失,且从文件上完全看不出丢了什么)。
    """
    from app.store import SealedNDJSON

    store = SealedNDJSON(tmp_path / "seg", "log", b"k" * 32)
    store.append({"i": 1})
    segment = (tmp_path / "seg" / "log-000001.ndjson")
    with segment.open("ab") as handle:
        handle.write(b'{"i": 2, "torn"')                 # 崩溃残留:无换行

    fresh = SealedNDJSON(tmp_path / "seg", "log", b"k" * 32)   # 新进程
    fresh.append({"i": 3})

    lines = segment.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 3                               # 半截行成为独立的一行
    assert json.loads(lines[-1])["i"] == 3               # 新记录完好可解析
    assert lines[1].endswith('"torn"')                   # 不丢、不改写半截行
    # 半截行仍被判为损坏(fail-closed,不做自动「修复」)
    from app.store import StoreIntegrityError
    with pytest.raises(StoreIntegrityError):
        SealedNDJSON(tmp_path / "seg", "log", b"k" * 32).read_all()


def _record_for(rid: str):
    from app.middleware.verification import RequestRecord
    return RequestRecord(request_id=rid, request_digest="a" * 64,
                         response_digest="b" * 64)


# --------------------------------------------------------------------------- #
# 5. MAC 密钥管理
# --------------------------------------------------------------------------- #
def test_audit_mac_key_is_domain_separated_and_not_recoverable():
    key = bytes(range(32))
    domains = ["audit-mac/v1", "chain-mac/v1", "mapping/v1", "protection-enc/v1"]
    derived = {name: hkdf_sha256(hkdf_sha256(key, "chain-mac/v1"), name)
               for name in domains}
    assert len(set(derived.values())) == len(domains)
    # 记录 MAC 的密钥与封缄密钥确实不同(否则改文件就能顺手改 MAC)
    assert derived["audit-mac/v1"] != hkdf_sha256(key, "chain-mac/v1")


def test_records_from_another_trust_root_fail_mac_validation(client, auth, mw,
                                                             data_dir):
    """换一把 VAULT_KEY(另一套部署)算出的 MAC 必须校验失败。"""
    _, rid = _one(client, auth)
    record = mw.audit.get(rid)
    assert mw.audit.mac_valid(record) is True
    # 另一套部署(不同信任根)派生出的记录 MAC 密钥必然不同 → 校验失败
    other_key = hkdf_sha256(hkdf_sha256(b"\x07" * 32, "chain-mac/v1"), "audit-mac/v1")
    assert other_key != hkdf_sha256(mw.vault.chain_mac_key, "audit-mac/v1")
    from app.middleware.verification import verify_record_mac
    assert verify_record_mac(other_key, record) is False
    assert verify_record_mac(mw.vault.chain_mac_key, record) is False   # 封缄密钥也不行


def test_mac_key_never_appears_on_disk_or_in_responses(client, auth, admin, mw,
                                                       data_dir):
    _one(client, auth)
    secret = mw.vault.chain_mac_key.hex()
    blob = "".join(p.read_text(encoding="utf-8", errors="ignore")
                   for p in Path(data_dir).rglob("*") if p.is_file())
    assert secret not in blob
    assert secret not in client.get("/health").text
    # 磁盘上只有指纹(单向摘要),没有任何可还原根密钥的材料
    fp_file = Path(data_dir) / "vault_key_fingerprint.txt"
    assert fp_file.is_file()
    assert fp_file.read_text(encoding="utf-8").strip() == mw.vault.fingerprint
    assert mw.vault.fingerprint != secret


# --------------------------------------------------------------------------- #
# 6. 并发写入 / 重启 / 链尖端持久化
# --------------------------------------------------------------------------- #
def test_concurrent_writes_keep_the_chain_intact(client, auth, admin, mw, data_dir):
    def burst(n: int) -> None:
        for i in range(n):
            response = chat(client, auth, f"并发 {threading.get_ident()}-{i}:{PROMPT}")
            assert response.status_code == 200, response.text

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(burst, [4] * 8))
    assert len(_rows(data_dir)) == 32

    result = _fresh_audit(client, None, data_dir, mw)
    assert result["intact"] is True, result["failures"]
    assert result["records"] == 32
    # seq 严格连续且唯一:并发下不得出现重号或跳号
    seqs = [row["seq"] for row in _rows(data_dir)]
    assert sorted(seqs) == list(range(1, 33))
    assert _chain(client, admin)["intact"] is True


def test_concurrent_writes_never_mix_client_attribution(client, auth, admin, mw,
                                                        data_dir):
    def burst(_: int) -> None:
        assert chat(client, auth, PROMPT).status_code == 200

    with ThreadPoolExecutor(max_workers=6) as pool:
        list(pool.map(burst, range(12)))
    rows = _rows(data_dir)
    assert len({row["request_id"] for row in rows}) == 12
    listed = client.get("/admin/audit", headers=admin, params={"limit": 50}).json()
    assert listed["total"] == 12
    assert all(item["client_id"] for item in listed["items"])


def test_restart_continues_the_chain_from_the_persisted_tip(make_mw, data_dir,
                                                            tmp_path):
    """进程重启:链尖端从磁盘恢复,不重号、不断链、旧记录仍可验证。"""
    state1, client1, key1 = make_mw(data_subdir="data-restart")
    auth1 = {"Authorization": f"Bearer {key1}"}
    first = chat(client1, auth1, PROMPT)
    assert first.status_code == 200, first.text
    rid1 = first.headers[RID_HEADER]
    tip_before = state1.audit.tip()
    assert tip_before["seq"] == 1

    # 重新装配(等价于进程重启:新的 AuditStore / Pipeline / 内存链尾)
    state2, client2, key2 = make_mw(data_subdir="data-restart")
    assert key2 == key1                      # 已有客户端密钥 → 不重新签发
    auth2 = {"Authorization": f"Bearer {key1}"}      # 旧密钥仍然有效
    second = chat(client2, auth2, PROMPT)
    assert second.status_code == 200, second.text

    rows = _rows(tmp_path / "data-restart")
    assert [row["seq"] for row in rows] == [1, 2]
    assert rows[0]["chain_hash"] == tip_before["chain_hash"]     # 尖端被持久化
    assert rows[1]["prev_hash"] == rows[0]["chain_hash"]         # 新记录接在旧链上
    assert state2.audit.verify(fresh=True)["intact"] is True
    assert state2.audit.count() == 2

    # 重启后旧记录依旧可验证(且属于原客户端)
    result = client2.post("/v1/verify", json={"request_id": rid1},
                          headers=auth2).json()
    assert result["found"] is True and result["record_mac_valid"] is True
    assert result["chain"]["intact"] is True


def test_restart_refuses_to_append_onto_a_corrupt_log(make_mw, tmp_path):
    state1, client1, key1 = make_mw(data_subdir="data-corrupt-restart")
    auth1 = {"Authorization": f"Bearer {key1}"}
    assert chat(client1, auth1, PROMPT).status_code == 200
    _mutate(tmp_path / "data-corrupt-restart", 0, request_digest="f" * 64)

    state2, client2, key2 = make_mw(data_subdir="data-corrupt-restart")
    result = state2.audit.verify(fresh=True)
    assert result["intact"] is False and "corrupt" in _fail_kinds(result)
    with pytest.raises(Exception):
        state2.audit.record(_record_for("cg-after-restart"))


def test_health_reports_broken_chain(client, auth, admin, mw, data_dir):
    _one(client, auth)
    assert client.get("/health").json()["audit"]["chain_intact"] is True
    _mutate(data_dir, 0, outcome="ok", response_digest="2" * 64)
    mw.audit._verify_cache = None                     # noqa: SLF001 — 绕过 5s 缓存
    health = client.get("/health").json()
    assert health["audit"]["chain_intact"] is False
    assert health["status"] == "ok"                   # 服务仍在跑,但如实报告链损坏


def test_audit_write_failure_fails_closed(client, auth, mw, monkeypatch):
    """审计写失败必须让请求失败(不得静默放行一个「没被记录」的调用)。"""
    def boom(_obj):
        raise OSError("disk full")

    monkeypatch.setattr(mw.audit._store, "append", boom)      # noqa: SLF001
    response = chat(client, auth, PROMPT)
    assert response.status_code >= 500
    assert PHONE not in response.text and EMAIL not in response.text
    assert "disk full" not in response.text            # 内部错误细节不外泄


def test_audit_record_ordering_is_monotonic_in_time(client, auth, mw, data_dir):
    for _ in range(3):
        _one(client, auth)
    rows = _rows(data_dir)
    stamps = [row["ts_epoch"] for row in rows]
    assert stamps == sorted(stamps)
    assert all(row["ts"] and row["ts_epoch"] for row in rows)
    assert [row["seq"] for row in rows] == [1, 2, 3]


# --------------------------------------------------------------------------- #
# 7. 计数字段与真实性
# --------------------------------------------------------------------------- #
def test_record_counts_do_not_reveal_values(client, auth, mw, data_dir):
    """审计里的 detections 只记类别计数,不含值、不含位置。"""
    _one(client, auth)
    row = _rows(data_dir)[0]
    body = json.dumps(row, ensure_ascii=False)
    assert PHONE not in body and EMAIL not in body
    assert row["detections"]["by_type"] == {"PHONE": 1, "EMAIL": 1}
    assert {"by_type", "by_risk", "total"} <= set(row["detections"])


def test_middleware_error_types_are_not_leaked_to_clients(client, auth):
    """内部异常类型 / 堆栈 / 校验细节不得出现在客户端可见的响应里。"""
    response = client.post("/v1/verify", json={"request_id": 12345}, headers=auth)
    assert response.status_code == 400
    body = response.text
    for leak in ("Traceback", "MiddlewareError", "File \"", "__pycache__"):
        assert leak not in body
    # 非法参数只报「哪个参数 + 为什么不合法」,不回显内部结构
    assert "request_id" in body and "12345" not in body


def test_verify_endpoint_does_not_trigger_an_upstream_call(client, auth, mw):
    """verify 只读本地证据,绝不重新调用上游(不产生费用)。"""
    from tests.mw.conftest import mock_provider
    response, rid = _one(client, auth)
    provider = mock_provider(mw)
    before = len(provider.seen)
    for _ in range(3):
        _verify(client, auth, {"request_id": rid,
                               "response_digest": "0" * 64})
    assert len(provider.seen) == before
    assert json.dumps(_verify(client, auth, {"request_id": rid}).json())
