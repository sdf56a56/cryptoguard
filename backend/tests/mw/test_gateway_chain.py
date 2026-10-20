"""
阶段 2 验收测试 —— Agent → CryptoGuard → Mock Provider → CryptoGuard → Agent 全链路

对应任务书的验收标准:
  「我能够运行 CryptoGuard,让至少一个真实或可验证的 OpenAI 兼容 Agent 将其作为
   API 中转站;请求经过 CryptoGuard 的敏感数据保护流程后被转发至模型服务;响应返回
  Agent;并且我能够通过审计记录与验证接口检查本次请求的处理记录及完整性。」

覆盖:
  1. 健康检查与模型列表(认证前/后)
  2. 未认证请求不消耗上游(401),匿名默认关闭
  3. 非流式补全:检测 → 保护 → 转发 → 还原 → 审计 → 摘要
  4. 不支持的字段显式报错(绝不静默丢弃)
  5. 阻断档(fail-closed)
  6. /v1/verify:摘要复算、跨客户端不可查、链完整
  7. 管理接口鉴权
  8. 流式(SSE)链路与末帧元数据
  9. Anthropic Messages 入口
 10. 请求体上限
"""
from __future__ import annotations

import json
from pathlib import Path

from app.middleware.verification import recompute_response_digest

PHONE = "13800138000"
#: 刻意不用 example.com:该域名是 RFC 2606 保留的示例域,会被误报抑制规则
#: 判为「疑似示例值」而不做保护(这本身是被测行为,见 test_example_values_not_protected)
EMAIL = "zhangsan@corp.com.cn"


def _chat(client, auth, text: str, **extra):
    body = {"model": "mock-chat", "messages": [{"role": "user", "content": text}]}
    body.update(extra)
    return client.post("/v1/chat/completions", json=body, headers=auth)


# --------------------------------------------------------------------------- #
# 1. 健康检查与模型列表
# --------------------------------------------------------------------------- #
def test_health_ok_without_auth_and_without_secrets(client):
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["service"] == "cryptoguard-middleware"
    # 不泄漏任何密钥材料
    text = json.dumps(body, ensure_ascii=False)
    assert "cgk_" not in text
    assert "admin_token" not in text
    assert body["auth"]["client_keys"] >= 1
    assert body["auth"]["admin_configured"] is True
    assert body["audit"]["chain_intact"] is True
    # 边界说明必须如实存在(不得把哈希宣传成「证明模型回答正确」)
    assert "不证明模型回答的事实正确性" in body["boundary"]["integrity"]


def test_models_requires_auth(client):
    response = client.get("/v1/models")
    assert response.status_code == 401
    body = response.json()
    assert body["error"]["type"] == "auth"
    # 提示信息本身不得被脱敏器破坏(否则用户看不懂怎么传密钥)
    assert "Authorization" in body["error"]["message"]
    assert "x-api-key" in body["error"]["message"]


def test_models_lists_declared_models(client, auth):
    response = client.get("/v1/models", headers=auth)
    assert response.status_code == 200
    body = response.json()
    assert body["object"] == "list"
    ids = [m["id"] for m in body["data"]]
    assert "mock-chat" in ids and "mock-tools" in ids
    assert body["cryptoguard"]["policy"]["protection_mode"] == "placeholder"


# --------------------------------------------------------------------------- #
# 2. 认证先于上游调用
# --------------------------------------------------------------------------- #
def test_invalid_key_rejected(client):
    response = client.get("/v1/models", headers={"Authorization": "Bearer cgk_deadbeef_" + "0" * 48})
    assert response.status_code == 401

    response = client.post("/v1/chat/completions", headers={"Authorization": "Bearer nope"},
                           json={"model": "mock-chat", "messages": [{"role": "user", "content": "hi"}]})
    assert response.status_code == 401


def test_unknown_model_rejected_before_upstream(client, auth):
    response = _chat(client, auth, "hi", model="gpt-nonexistent")
    assert response.status_code == 404
    assert "不可用" in response.json()["error"]["message"]


# --------------------------------------------------------------------------- #
# 3. 非流式全链路:保护 → 转发 → 还原 → 审计
# --------------------------------------------------------------------------- #
def test_full_chain_protects_and_restores(client, auth, mw):
    response = _chat(client, auth, f"联系 {EMAIL},电话 {PHONE},帮我写封邮件")
    assert response.status_code == 200, response.text
    body = response.json()
    text = body["choices"][0]["message"]["content"]

    meta = body["cryptoguard"]
    # 命中记录(只含类别与规则,不含原值)
    assert meta["detected"]["by_type"]["EMAIL"] == 1
    assert meta["detected"]["by_type"]["PHONE"] == 1
    assert EMAIL not in json.dumps(meta, ensure_ascii=False)
    assert PHONE not in json.dumps(meta, ensure_ascii=False)

    # 上游只看到占位符:直接检查 Mock 实际收到的请求体(核心安全属性)
    sent = json.dumps(mw.registry.get("mock").seen[-1].messages, ensure_ascii=False)
    assert "[EMAIL_001]" in sent and "[PHONE_001]" in sent
    assert EMAIL not in sent and PHONE not in sent

    # 还原策略:EMAIL 属白名单 → 还原;PHONE 属 NEVER_AUTO_RESTORE → 保留占位符
    assert EMAIL in text
    assert PHONE not in text
    restored_types = {e["type"] for e in meta["restore"]["restored"]}
    withheld_types = {e["type"] for e in meta["restore"]["withheld"]}
    assert "EMAIL" in restored_types
    assert "PHONE" in withheld_types

    # 审计落盘:request_id 可检索且链完整
    rid = meta["request_id"] or response.headers["X-CryptoGuard-Request-ID"]
    record = mw.audit.get(rid)
    assert record is not None
    assert record["outcome"] == "ok"
    assert record["provider"] == "mock"
    assert record["request_digest"] == meta["digest"]["request"]
    assert record["response_digest"] == meta["digest"]["response"]
    assert mw.audit.verify()["intact"] is True
    # 审计不含原始敏感值
    assert PHONE not in json.dumps(record, ensure_ascii=False)


def test_response_digest_is_reproducible_by_client(client, auth):
    response = _chat(client, auth, "你好")
    body = response.json()
    message = body["choices"][0]["message"]
    recomputed = recompute_response_digest({
        "text": message["content"] or "",
        "tool_calls": [{"name": c["function"]["name"], "arguments": c["function"]["arguments"]}
                       for c in message.get("tool_calls") or []],
        "finish_reason": body["choices"][0]["finish_reason"],
        "model": body["model"],
    })
    assert recomputed == body["cryptoguard"]["digest"]["response"]


def test_tool_call_arguments_stay_valid_json(client, auth, mw):
    body = {
        "model": "mock-tools",
        "messages": [{"role": "user", "content": f"USE_TOOL 请联系 {EMAIL}"}],
        "tools": [{
            "type": "function",
            "function": {"name": "send_mail", "description": "发邮件",
                         "parameters": {"type": "object",
                                        "properties": {"to": {"type": "string"}}}},
        }],
        "tool_choice": "auto",
    }
    response = client.post("/v1/chat/completions", json=body, headers=auth)
    assert response.status_code == 200, response.text
    calls = response.json()["choices"][0]["message"]["tool_calls"]
    assert calls, "应返回工具调用"
    arguments = calls[0]["function"]["arguments"]
    parsed = json.loads(arguments)          # 替换不得破坏 JSON 结构
    assert parsed["echo"]
    # 参数里的邮箱按策略还原(白名单类别)
    assert EMAIL in arguments


def test_example_values_not_protected(client, auth):
    """误报控制:示例域/占位形态的「敏感值」不得被当成真实凭证,也不得被阻断。"""
    response = _chat(client, auth,
                     "示例邮箱 alice@example.com,示例密钥 sk-xxxxxxxxxxxxxxxxxxxx")
    assert response.status_code == 200
    meta = response.json()["cryptoguard"]
    assert meta["detected"]["total"] == 0
    assert meta["restore"]["restored"] == []


# --------------------------------------------------------------------------- #
# 4. 不支持的字段显式报错
# --------------------------------------------------------------------------- #
def test_unknown_field_is_rejected_not_dropped(client, auth):
    response = client.post("/v1/chat/completions", headers=auth, json={
        "model": "mock-chat", "messages": [{"role": "user", "content": "hi"}],
        "foo": 1,
    })
    assert response.status_code == 400
    assert "不支持的参数" in response.json()["error"]["message"]


def test_behavior_affecting_fields_rejected(client, auth):
    for extra in ({"n": 3}, {"logprobs": True}, {"service_tier": "flex"}, {"metadata": {"a": 1}}):
        body = {"model": "mock-chat", "messages": [{"role": "user", "content": "hi"}]}
        body.update(extra)
        response = client.post("/v1/chat/completions", headers=auth, json=body)
        assert response.status_code == 400, extra
        assert response.json()["error"]["type"] == "invalid_request"


def test_max_tokens_and_max_completion_tokens_conflict(client, auth):
    response = _chat(client, auth, "hi", max_tokens=10, max_completion_tokens=20)
    assert response.status_code == 400
    assert "不能同时给出" in response.json()["error"]["message"]


def test_max_completion_tokens_is_accepted(client, auth):
    response = _chat(client, auth, "hi", max_completion_tokens=16)
    assert response.status_code == 200


# --------------------------------------------------------------------------- #
# 5. 阻断档 fail-closed
# --------------------------------------------------------------------------- #
def test_private_key_is_blocked_and_audited(client, auth, mw):
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"
    response = _chat(client, auth, f"帮我看看这个 {pem}")
    assert response.status_code == 400
    error = response.json()["error"]
    assert error["code"] == "content_blocked"
    assert "PRIVATE_KEY" in error["message"]
    assert "MIIEowIBAAKCAQEA" not in error["message"]      # 不回显原值
    rid = error["request_id"]
    record = mw.audit.get(rid)
    assert record is not None and record["outcome"] == "blocked"
    assert mw.audit.verify()["intact"] is True


# --------------------------------------------------------------------------- #
# 6. /v1/verify
# --------------------------------------------------------------------------- #
def test_verify_confirms_record(client, auth, admin):
    body = _chat(client, auth, f"给 {EMAIL} 发个通知").json()
    rid = body["cryptoguard"]["request_id"]
    payload = {
        "request_id": rid,
        "response_digest": body["cryptoguard"]["digest"]["response"],
        "response": {
            "text": body["choices"][0]["message"]["content"] or "",
            "finish_reason": body["choices"][0]["finish_reason"],
            "model": body["model"],
        },
    }
    response = client.post("/v1/verify", json=payload, headers=auth)
    assert response.status_code == 200
    result = response.json()
    assert result["found"] is True
    assert result["response_digest_match"] is True
    assert result["record_mac_valid"] is True
    assert result["chain"]["intact"] is True
    assert result["failures"] == []
    assert result["policy_version"] == "cg-policy/test-1"
    # 边界声明必须如实存在
    assert "不代表模型服务商的签名" in result["boundary"]["provider_identity"]


def test_verify_detects_tampered_response(client, auth):
    body = _chat(client, auth, "你好").json()
    rid = body["cryptoguard"]["request_id"]
    response = client.post("/v1/verify", headers=auth, json={
        "request_id": rid,
        "response": {"text": "被篡改的文本", "finish_reason": "stop", "model": "mock-chat"},
    })
    assert response.status_code == 200
    result = response.json()
    assert result["response_digest_match"] is False
    assert "response_digest_mismatch" in result["failures"]


def test_verify_unknown_id(client, auth):
    response = client.post("/v1/verify", headers=auth, json={"request_id": "cg-doesnotexist"})
    assert response.status_code == 200
    result = response.json()
    assert result["found"] is False
    assert result["failures"] == ["not_found"]


def test_verify_cross_client_forbidden(client, auth, mw):
    rid = _chat(client, auth, "你好").json()["cryptoguard"]["request_id"]
    _, other = mw.clients.create("other-client")
    response = client.post("/v1/verify", json={"request_id": rid},
                           headers={"Authorization": f"Bearer {other}"})
    assert response.status_code == 403
    assert response.json()["failures"] == ["forbidden"]
    # 管理员令牌可以跨客户端查询
    response = client.post("/v1/verify", json={"request_id": rid},
                           headers={"X-Admin-Token": mw.settings.admin_token,
                                    **{"Authorization": f"Bearer {other}"}})
    assert response.status_code == 200
    assert response.json()["found"] is True


# --------------------------------------------------------------------------- #
# 7. 管理接口
# --------------------------------------------------------------------------- #
def test_admin_endpoints_require_token(client, admin):
    assert client.get("/admin/security/policies").status_code == 401
    assert client.get("/admin/audit").status_code == 401
    assert client.get("/admin/clients").status_code == 401

    policies = client.get("/admin/security/policies", headers=admin)
    assert policies.status_code == 200
    body = policies.json()
    assert body["policy"]["policy_version"] == "cg-policy/test-1"
    assert "PK-PEM" in body["detection"]["builtin_rules"]
    assert body["clients"] and "key_hash" not in json.dumps(body)


def test_admin_without_configured_token_returns_503(client, settings_factory, tmp_path):
    from fastapi.testclient import TestClient

    from app import main as main_mod
    from app.middleware.deps import build_middleware
    mw = build_middleware(tmp_path / "data2", settings=settings_factory(admin_token=""))
    main_mod.app.state.middleware = mw
    try:
        response = TestClient(main_mod.app).get(
            "/admin/security/policies", headers={"X-Admin-Token": "whatever"})
        assert response.status_code == 503
    finally:
        delattr(main_mod.app.state, "middleware")


def test_client_lifecycle_create_rotate_revoke(client, admin):
    created = client.post("/admin/clients", headers=admin,
                          json={"name": "codex", "models": ["mock-chat"]})
    assert created.status_code == 201
    data = created.json()
    key = data["api_key"]
    cid = data["client"]["id"]
    assert key.startswith("cgk_")
    assert "key_hash" not in json.dumps(data)

    assert client.get("/v1/models", headers={"Authorization": f"Bearer {key}"}).status_code == 200
    # 客户端模型白名单
    assert _chat(client, {"Authorization": f"Bearer {key}"}, "hi",
                 model="mock-tools").status_code == 403

    rotated = client.post(f"/admin/clients/{cid}/rotate", headers=admin).json()["api_key"]
    assert rotated != key
    assert client.get("/v1/models", headers={"Authorization": f"Bearer {key}"}).status_code == 401
    assert client.get("/v1/models", headers={"Authorization": f"Bearer {rotated}"}).status_code == 200

    client.post(f"/admin/clients/{cid}/revoke", headers=admin)
    assert client.get("/v1/models", headers={"Authorization": f"Bearer {rotated}"}).status_code == 401


def test_client_key_is_not_stored_in_plaintext(client, admin, mw):
    key = client.post("/admin/clients", headers=admin,
                      json={"name": "audit-check"}).json()["api_key"]
    secret = key.rsplit("_", 1)[1]
    data_dir = Path(mw.settings.bootstrap_key_file).parent / "data"
    assert data_dir.is_dir()
    blob = "".join(path.read_text(encoding="utf-8", errors="ignore")
                   for path in data_dir.rglob("*") if path.is_file())
    assert secret not in blob, "客户端密钥不得以明文落盘"
    # 摘要确实存了(HMAC-SHA256 十六进制),但不可反推密钥
    assert any("key_hash" in path.read_text(encoding="utf-8", errors="ignore")
               for path in data_dir.rglob("*") if path.is_file())


def test_audit_listing_and_chain_verify(client, auth, admin):
    _chat(client, auth, "hello")
    listing = client.get("/admin/audit", headers=admin, params={"limit": 10})
    assert listing.status_code == 200
    body = listing.json()
    assert body["total"] >= 1
    assert body["chain"]["intact"] is True
    rid = body["items"][0]["request_id"]
    one = client.get(f"/admin/audit/{rid}", headers=admin)
    assert one.status_code == 200
    assert one.json()["record_mac_valid"] is True
    verified = client.post("/admin/audit/verify", headers=admin)
    assert verified.status_code == 200
    assert verified.json()["intact"] is True


# --------------------------------------------------------------------------- #
# 8. 流式
# --------------------------------------------------------------------------- #
def _sse_events(text: str) -> list[dict]:
    events = []
    for block in text.split("\n\n"):
        for line in block.splitlines():
            if line.startswith("data: "):
                payload = line[6:]
                if payload.strip() == "[DONE]":
                    continue
                try:
                    events.append(json.loads(payload))
                except ValueError:
                    pass
    return events


def test_streaming_chain(client, auth, mw):
    response = _chat(client, auth, f"请联系 {EMAIL}", stream=True)
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/event-stream")
    assert "[DONE]" in response.text

    events = _sse_events(response.text)
    assert events, "应至少有一个数据帧"
    assert events[0]["object"] == "chat.completion.chunk"
    content = "".join(e["choices"][0]["delta"].get("content") or "" for e in events
                      if e.get("choices"))
    assert EMAIL in content, "白名单类别应在流式输出中还原"
    final = events[-1]
    assert final["choices"][0]["finish_reason"] is not None
    meta = final["cryptoguard"]
    assert meta["detected"]["by_type"]["EMAIL"] == 1
    rid = response.headers["X-CryptoGuard-Request-ID"]
    record = mw.audit.get(rid)
    assert record is not None and record["outcome"] == "ok"
    assert record["stream"] is True
    assert record["response_digest"] == meta["digest"]["response"]
    assert mw.audit.verify()["intact"] is True


def test_streaming_tool_call_arguments_remain_json(client, auth):
    body = {
        "model": "mock-tools",
        "stream": True,
        "messages": [{"role": "user", "content": f"USE_TOOL 记录 {EMAIL}"}],
        "tools": [{"type": "function", "function": {"name": "log_it", "parameters": {}}}],
    }
    response = client.post("/v1/chat/completions", json=body, headers=auth)
    assert response.status_code == 200
    events = _sse_events(response.text)
    arguments = "".join(
        c["function"].get("arguments") or ""
        for e in events for c in (e["choices"][0]["delta"].get("tool_calls") or [])
        if e.get("choices"))
    assert arguments, "应有工具参数增量"
    parsed = json.loads(arguments)
    assert EMAIL in parsed["echo"]


# --------------------------------------------------------------------------- #
# 9. Anthropic Messages 入口
# --------------------------------------------------------------------------- #
def test_anthropic_messages_endpoint(client, auth):
    body = {
        "model": "mock-chat",
        "max_tokens": 128,
        "messages": [{"role": "user", "content": f"联系 {EMAIL}"}],
    }
    response = client.post("/v1/messages", json=body, headers=auth)
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["type"] == "message"
    assert payload["role"] == "assistant"
    text = "".join(block["text"] for block in payload["content"] if block["type"] == "text")
    assert EMAIL in text
    assert payload["cryptoguard"]["detected"]["by_type"]["EMAIL"] == 1


def test_anthropic_thinking_is_stripped_and_recorded_by_default(client, auth):
    """Claude Code 默认带 thinking：默认 strip（不 400），但必登记为 ignored。"""
    response = client.post("/v1/messages", headers=auth, json={
        "model": "mock-chat", "max_tokens": 16,
        "messages": [{"role": "user", "content": "hi"}],
        "thinking": {"type": "enabled", "budget_tokens": 100},
    })
    assert response.status_code == 200, response.text
    meta = response.json()["cryptoguard"]
    assert "thinking" in meta["ignored_fields"]
    assert response.headers["X-CryptoGuard-Content-Policy"].startswith("images=")


def test_anthropic_thinking_can_be_rejected_explicitly(make_mw):
    _, client, key = make_mw(anthropic_thinking="reject",
                             data_subdir="thinking-reject")
    response = client.post("/v1/messages", headers={"Authorization": f"Bearer {key}"},
                           json={
        "model": "mock-chat", "max_tokens": 16,
        "messages": [{"role": "user", "content": "hi"}],
        "thinking": {"type": "enabled", "budget_tokens": 100},
    })
    assert response.status_code == 400
    assert response.json()["type"] == "error"


def test_anthropic_streaming(client, auth):
    response = client.post("/v1/messages", headers=auth, json={
        "model": "mock-chat", "max_tokens": 64, "stream": True,
        "messages": [{"role": "user", "content": "你好"}],
    })
    assert response.status_code == 200
    assert "event: message_start" in response.text
    assert "event: message_stop" in response.text


# --------------------------------------------------------------------------- #
# 10. 请求体上限与其他
# --------------------------------------------------------------------------- #
def test_body_limit_enforced(client, auth, mw):
    huge = "x" * (mw.settings.max_request_bytes + 1024)
    response = _chat(client, auth, huge)
    assert response.status_code == 413


def test_unknown_v1_path_returns_json_404(client, auth):
    response = client.get("/v1/embeddings", headers=auth)
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "not_found"


def test_error_body_never_leaks_upstream_key(client, auth):
    response = _chat(client, auth, "hi", model="nope/nope")
    assert "sk-" not in response.text
    assert "Authorization" not in response.text


def test_rate_limit_returns_429_with_retry_after(client, admin, tmp_path):
    key = client.post("/admin/clients", headers=admin,
                      json={"name": "limited", "rate_limit_per_min": 2}).json()["api_key"]
    headers = {"Authorization": f"Bearer {key}"}
    assert _chat(client, headers, "a").status_code == 200
    assert _chat(client, headers, "b").status_code == 200
    third = _chat(client, headers, "c")
    assert third.status_code == 429
    assert "Retry-After" in third.headers
