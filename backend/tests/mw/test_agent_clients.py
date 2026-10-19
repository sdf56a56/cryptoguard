"""
第 5 阶段 · 任务 4 —— Agent 客户端接入的端到端验证

本文件**不新增任何生产代码路径**:它把「真实 Agent 客户端实际发出的报文形状」喂给
现有的 `/v1/chat/completions` 与 `/v1/messages`,并借助 `test_real_http_e2e.py` 的
回声上游(EchoUpstream)在**真实 socket** 上断言整条链路:

    Agent 形状的请求 → CryptoGuard(现有保护链路)→ 现有 Provider
                     → 真实 HTTP 测试上游 → CryptoGuard(现有还原链路)→ Agent 形状的响应

每个用例都断言四件事:
  1. 客户端拿到的是**它自己协议的合法响应**(OpenAI ChatCompletion / Anthropic Messages);
  2. 上游(独立观察面:它自己的接入日志)收到的原始字节里**没有**任何敏感原文;
  3. 现有审计与 `/v1/verify` 依旧完整,客户端能用**自己收到的响应体**复算摘要;
  4. 鉴权失败与上游错误被分类映射,既不泄漏原文,也不泄漏任何密钥。

诚实边界(不得含糊):
  - 上游是**本机回环的测试服务**,不是任何真实模型厂商;本文件不构成真实厂商联调
    (真实厂商用例在 `test_real_http_e2e.py`,默认跳过);
  - 本仓库**未实现** OpenAI Responses API(`/v1/responses`),因此当前版本的 Codex CLI
    (只讲该协议)不能靠改 Base URL 接入 —— 相关用例只断言「失败是显式的」,不假装成功;
  - 「Agent 能连通」只说明这些报文形状在这条链路上成立,不代表「系统已经绝对安全」。
"""
from __future__ import annotations

import json
import re

import pytest

from app.middleware.verification import response_digest
from tests.mw.conftest import FAKE_UPSTREAM_KEY, UPSTREAM_KEY_ENV
from tests.mw.test_real_http_e2e import EchoUpstream, _received_text
from tests.mw.test_upstream_provider import UPSTREAM_ADVERTISED_MODEL

PHONE = "13800138000"
EMAIL = "zhangsan@corp.com.cn"
PROMPT = f"我叫张三,手机号 {PHONE},邮箱 {EMAIL},请帮我写一封邮件"

#: Anthropic 客户端(Claude Code)会带的版本头;本中间件不校验它的取值
ANTHROPIC_VERSION = "2023-06-01"


# --------------------------------------------------------------------------- #
# 夹具:真实 HTTP 回声上游(http_env 的本地版本)
# --------------------------------------------------------------------------- #
@pytest.fixture()
def upstream():
    server = EchoUpstream()
    try:
        yield server
    finally:
        server.close()


@pytest.fixture()
def agent_env(upstream, make_mw, monkeypatch):
    """装配一个**真上游**中间件;返回 (mw, TestClient, auth, upstream)。

    与 `http_env` 的区别仅在于默认保护模式取 `token`(Agent 场景下的常见选择),
    以及默认数据子目录按模式区分,便于同一用例里装配多份互不相干的部署。
    """
    monkeypatch.setenv(UPSTREAM_KEY_ENV, FAKE_UPSTREAM_KEY)

    def make(*, mode: str = "token", subdir: str = "", **provider_kw):
        from app.middleware.config import ProviderSettings

        kwargs = dict(
            name="fake", type="openai-compatible", base_url=upstream.base_url,
            api_key_env=UPSTREAM_KEY_ENV, models=("mock-chat",),
            display_name="Fake Real HTTP Upstream",
            timeout_connect=2.0, timeout_read=5.0, max_retries=0)
        kwargs.update(provider_kw)
        provider = ProviderSettings(**kwargs)
        mw, client, key = make_mw(protection_mode=mode,
                                  data_subdir=subdir or f"agent-{mode}",
                                  providers=(provider,), default_provider="fake")
        return mw, client, {"Authorization": f"Bearer {key}"}, upstream

    return make


# --------------------------------------------------------------------------- #
# 辅助
# --------------------------------------------------------------------------- #
def _openai_body(text: str = PROMPT, **extra) -> dict:
    """一个 OpenAI 兼容 SDK/Agent 会发的补全体(字段名与 SDK 一致)。"""
    body: dict = {
        "model": "mock-chat",
        "messages": [{"role": "user", "content": text}],
        "temperature": 0.2,
        "max_tokens": 256,
        "stream": False,
    }
    body.update(extra)
    return body


def _anthropic_body(text: str = PROMPT, **extra) -> dict:
    """一个 Anthropic 客户端(Claude Code)会发的 Messages 体。"""
    body: dict = {
        "model": "mock-chat",
        "max_tokens": 256,
        "system": [{"type": "text", "text": "你是一个严谨的中文助理。"}],
        "messages": [{"role": "user", "content": [{"type": "text", "text": text}]}],
        "stream": False,
    }
    body.update(extra)
    return body


def _anthropic_headers(key: str) -> dict:
    """Claude Code 用的是 `x-api-key`,并会带 anthropic-version。"""
    return {"x-api-key": key, "anthropic-version": ANTHROPIC_VERSION,
            "content-type": "application/json"}


def _sse_events(raw: str) -> list[tuple[str | None, dict]]:
    """解析 SSE 报文为 [(event_name, payload)];`data: [DONE]` 记作 payload={}。"""
    events: list[tuple[str | None, dict]] = []
    name: str | None = None
    for line in raw.splitlines():
        if line.startswith("event:"):
            name = line[len("event:"):].strip()
        elif line.startswith("data:"):
            payload = line[len("data:"):].strip()
            if not payload or payload == "[DONE]":
                events.append((name, {}))
                name = None
                continue
            try:
                events.append((name, json.loads(payload)))
            except json.JSONDecodeError:
                pass
            name = None
    return events


def _openai_sse_text(raw: str) -> str:
    out = []
    for _, payload in _sse_events(raw):
        for choice in payload.get("choices") or []:
            out.append((choice.get("delta") or {}).get("content") or "")
    return "".join(out)


def _anthropic_sse_text(raw: str) -> str:
    out = []
    for name, payload in _sse_events(raw):
        if name == "content_block_delta":
            delta = payload.get("delta") or {}
            if delta.get("type") == "text_delta":
                out.append(delta.get("text") or "")
    return "".join(out)


def _upstream_bytes(upstream) -> str:
    """上游收到的全部原始报文(路径 + 头 + body),用于断言「没收到什么」。"""
    return json.dumps([{"path": r["path"], "headers": r["headers"],
                        "body": r["body"].decode("utf-8", "replace")}
                       for r in upstream.requests], ensure_ascii=False)


def _files_text(root) -> str:
    return "".join(path.read_text(encoding="utf-8", errors="ignore")
                   for path in root.rglob("*") if path.is_file())


def _client_key(headers: dict) -> str:
    return headers["Authorization"][len("Bearer "):]


# --------------------------------------------------------------------------- #
# 1. 通用 OpenAI 兼容 Agent:两种认证头、非流式与流式
# --------------------------------------------------------------------------- #
def test_openai_agent_round_trip(agent_env, tmp_path):
    """OpenAI 兼容 Agent(Bearer 认证)走完整条链路,并拿到自己协议的响应体。"""
    mw, client, auth, upstream = agent_env()

    response = client.post("/v1/chat/completions", json=_openai_body(), headers=auth)
    assert response.status_code == 200, response.text

    # (1) 响应体是合法的 OpenAI ChatCompletion 形状
    payload = response.json()
    assert payload["object"] == "chat.completion"
    assert payload["model"] == "mock-chat"
    assert re.fullmatch(r"cg-[0-9a-f]{32}", payload["id"])
    assert payload["choices"][0]["index"] == 0
    assert payload["choices"][0]["finish_reason"] == "stop"
    assert payload["cryptoguard"]["protection_mode"] == "token"

    # 白名单类别(EMAIL)在本地还原;高风险(PHONE)保持令牌
    text = payload["choices"][0]["message"]["content"]
    assert EMAIL in text
    assert PHONE not in text

    # (2) 上游手里没有原文(独立观察面:上游自己记录的原始字节)
    assert len(upstream.requests) == 1
    raw = upstream.requests[-1]["body"].decode("utf-8")
    assert PHONE not in raw and EMAIL not in raw
    assert "[CG_TOKEN_" in raw
    # 上游密钥只出现在出网请求里;客户端密钥绝不出现在出网请求里
    assert upstream.requests[-1]["headers"]["authorization"] == f"Bearer {FAKE_UPSTREAM_KEY}"
    assert _client_key(auth) not in _upstream_bytes(upstream)

    # (3) 磁盘上没有原文,也不含任何密钥
    on_disk = _files_text(tmp_path / "agent-token")
    assert PHONE not in on_disk and EMAIL not in on_disk
    assert _client_key(auth) not in on_disk and FAKE_UPSTREAM_KEY not in on_disk

    # 审计确实写了这条记录
    rid = response.headers["X-CryptoGuard-Request-ID"]
    assert mw.audit.get(rid)["outcome"] == "ok"


def test_openai_agent_x_api_key_header_is_accepted(agent_env):
    """同一路径也接受 `x-api-key`(部分 Agent/SDK 的默认认证头)。"""
    _, client, auth, upstream = agent_env(subdir="agent-xapikey")
    headers = {"x-api-key": _client_key(auth), "content-type": "application/json"}

    response = client.post("/v1/chat/completions", json=_openai_body(), headers=headers)
    assert response.status_code == 200, response.text
    assert EMAIL in response.json()["choices"][0]["message"]["content"]
    assert PHONE not in upstream.requests[-1]["body"].decode("utf-8")


def test_openai_agent_streaming_gets_sse_and_upstream_sees_tokens(agent_env):
    """流式 Agent:SSE 帧合法、内容可还原,而上游仍然只看到令牌。"""
    _, client, auth, upstream = agent_env(subdir="agent-stream")

    with client.stream("POST", "/v1/chat/completions",
                       json=_openai_body(stream=True), headers=auth) as response:
        assert response.status_code == 200, response.read()
        assert response.headers["content-type"].startswith("text/event-stream")
        raw = "".join(response.iter_text())

    events = _sse_events(raw)
    assert events, "没有解析到任何 SSE 事件"
    assert events[0][1]["object"] == "chat.completion.chunk"   # 首帧带 role
    assert events[0][1]["choices"][0]["delta"]["role"] == "assistant"
    assert raw.rstrip().endswith("data: [DONE]")               # 以 [DONE] 收尾
    # 末帧给出 finish_reason、usage 与 cryptoguard 元数据(含两侧摘要)
    final = [p for _, p in events if p.get("choices", [{}])[0].get("finish_reason")][-1]
    assert final["choices"][0]["finish_reason"] == "stop"
    assert final["cryptoguard"]["digest"]["response"]

    text = _openai_sse_text(raw)
    assert EMAIL in text and PHONE not in text

    up_raw = upstream.requests[-1]["body"].decode("utf-8")
    assert PHONE not in up_raw and EMAIL not in up_raw
    assert "[CG_TOKEN_" in up_raw


# --------------------------------------------------------------------------- #
# 2. Anthropic 客户端(Claude Code 形状):Messages 入口
# --------------------------------------------------------------------------- #
def test_claude_code_style_request_round_trip(agent_env):
    """Claude Code 形状的请求(系统提示 + 分块 content + x-api-key)。"""
    _, client, auth, upstream = agent_env(mode="token", subdir="agent-cc")

    response = client.post("/v1/messages", json=_anthropic_body(),
                           headers=_anthropic_headers(_client_key(auth)))
    assert response.status_code == 200, response.text

    payload = response.json()
    assert payload["type"] == "message"
    assert payload["role"] == "assistant"
    assert payload["model"] == "mock-chat"
    assert payload["stop_reason"] in ("end_turn", "stop_sequence")
    assert isinstance(payload["usage"]["input_tokens"], int)
    assert isinstance(payload["usage"]["output_tokens"], int)
    assert payload["cryptoguard"]["protection_mode"] == "token"

    text = "".join(b["text"] for b in payload["content"] if b["type"] == "text")
    assert EMAIL in text and PHONE not in text

    # 系统提示也被送去上游了(它同样要过保护链路),但里面没有原文
    sent = json.loads(upstream.requests[-1]["body"].decode("utf-8"))
    assert sent["messages"][0]["role"] == "system"
    assert "严谨的中文助理" in sent["messages"][0]["content"]
    assert sent["max_tokens"] == 256
    raw = upstream.requests[-1]["body"].decode("utf-8")
    assert PHONE not in raw and EMAIL not in raw


def test_claude_code_style_streaming_event_sequence(agent_env):
    """流式 Messages:事件名与顺序符合 Anthropic SSE 约定,且内容不含原文出网。"""
    _, client, auth, upstream = agent_env(mode="token", subdir="agent-cc-stream")

    with client.stream("POST", "/v1/messages",
                       json=_anthropic_body(stream=True),
                       headers=_anthropic_headers(_client_key(auth))) as response:
        assert response.status_code == 200, response.read()
        raw = "".join(response.iter_text())

    names = [name for name, _ in _sse_events(raw)]
    assert names[0] == "message_start"
    assert names[-1] == "message_stop"
    assert "content_block_start" in names and "content_block_stop" in names
    assert "content_block_delta" in names and "message_delta" in names
    assert names.count("message_start") == 1 and names.count("message_stop") == 1
    # 顺序:message_start 在第一个 delta 之前,message_delta 在 message_stop 之前
    assert names.index("message_start") < names.index("content_block_delta")
    assert names.index("message_delta") < names.index("message_stop")

    text = _anthropic_sse_text(raw)
    assert EMAIL in text and PHONE not in text

    up_raw = upstream.requests[-1]["body"].decode("utf-8")
    assert PHONE not in up_raw and EMAIL not in up_raw


def test_claude_code_tool_round_trip_is_forwarded(agent_env):
    """Agent 的「工具调用 → 工具结果」回合能被转换并送出(报文形状见上游原始字节)。"""
    mw, client, auth, upstream = agent_env(mode="token", subdir="agent-cc-tools")
    body = _anthropic_body(stream=False)
    body["messages"] = [
        {"role": "user", "content": [{"type": "text", "text": f"我的邮箱是 {EMAIL}"}]},
        {"role": "assistant", "content": [
            {"type": "tool_use", "id": "toolu_01", "name": "lookup",
             "input": {"q": "zhangsan"}}]},
        {"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "toolu_01",
             "content": [{"type": "text", "text": "查询结果:已注册"}]}]},
    ]
    body["tools"] = [{"name": "lookup", "description": "查询用户",
                      "input_schema": {"type": "object",
                                       "properties": {"q": {"type": "string"}}}}]

    response = client.post("/v1/messages", json=body,
                           headers=_anthropic_headers(_client_key(auth)))
    assert response.status_code == 200, response.text

    sent = json.loads(upstream.requests[-1]["body"].decode("utf-8"))
    roles = [m["role"] for m in sent["messages"]]
    assert "tool" in roles, f"tool_result 没被转成上游的 tool 消息:{roles}"
    tool_msg = next(m for m in sent["messages"] if m["role"] == "tool")
    assert tool_msg["tool_call_id"] == "toolu_01"
    assert "已注册" in tool_msg["content"]
    # 工具定义同样被送出(上游按自己的 OpenAI 形状接收)
    assert [t["function"]["name"] for t in sent["tools"]] == ["lookup"]

    # 工具结果里的邮箱原文同样没有出网(它走的是同一条出站保护链路)
    raw = upstream.requests[-1]["body"].decode("utf-8")
    assert PHONE not in raw and EMAIL not in raw
    assert mw.audit.get(response.headers["X-CryptoGuard-Request-ID"])["outcome"] == "ok"


# --------------------------------------------------------------------------- #
# 3. 链路证据:审计与 /v1/verify 依旧可用,客户端可自证
# --------------------------------------------------------------------------- #
def test_agent_chain_evidence_and_client_side_verification(agent_env):
    """Agent 拿到响应后,能用**自己收到的响应体**复算摘要,并与审计记录对得上。"""
    mw, client, auth, upstream = agent_env(mode="token", subdir="agent-verify")

    response = client.post("/v1/chat/completions", json=_openai_body(), headers=auth)
    assert response.status_code == 200, response.text
    payload = response.json()
    rid = response.headers["X-CryptoGuard-Request-ID"]

    text = payload["choices"][0]["message"]["content"]
    recomputed = response_digest(
        text=text, tool_calls=payload["choices"][0]["message"].get("tool_calls"),
        finish_reason=payload["choices"][0]["finish_reason"], model=payload["model"])

    verified = client.post("/v1/verify", headers=auth, json={
        "request_id": rid,
        "request_digest": response.headers["X-CryptoGuard-Request-Digest"],
        "response": {"text": text,
                     "tool_calls": payload["choices"][0]["message"].get("tool_calls"),
                     "finish_reason": payload["choices"][0]["finish_reason"],
                     "model": payload["model"]},
    })
    assert verified.status_code == 200, verified.text
    report = verified.json()
    assert report["found"] is True
    assert report["failures"] == [], report["failures"]
    assert report["request_digest_match"] is True
    assert report["response_digest_match"] is True
    assert report["record_mac_valid"] is True
    assert report["chain"]["intact"] is True
    assert report["response_digest"] == recomputed

    # 非空断言(防止「摘要恒等于某个常量」这类假通过)
    assert recomputed != response_digest(text=text, finish_reason="length",
                                         model=payload["model"])
    # 审计记录里既没有原文,也没有任何密钥
    record = json.dumps(mw.audit.get(rid), ensure_ascii=False)
    assert PHONE not in record and EMAIL not in record
    assert _client_key(auth) not in record and FAKE_UPSTREAM_KEY not in record


def test_agent_can_verify_but_not_tamper(agent_env):
    """改一个字符就应当被检出(证明上面的「通过」不是因为没校验)。"""
    _, client, auth, upstream = agent_env(mode="token", subdir="agent-tamper")

    response = client.post("/v1/chat/completions", json=_openai_body(), headers=auth)
    payload = response.json()
    rid = response.headers["X-CryptoGuard-Request-ID"]
    text = payload["choices"][0]["message"]["content"]

    verified = client.post("/v1/verify", headers=auth, json={
        "request_id": rid,
        "response": {"text": text + "!", "finish_reason": "stop", "model": payload["model"]},
    })
    assert verified.status_code == 200, verified.text
    assert verified.json()["response_digest_match"] is False
    assert "response_digest_mismatch" in verified.json()["failures"]


# --------------------------------------------------------------------------- #
# 4. 失败路径:认证、模型名、上游错误
# --------------------------------------------------------------------------- #
def test_agent_without_credentials_is_rejected(agent_env):
    """无凭证 / 错凭证:401,且不泄漏任何密钥或原文。"""
    _, client, auth, upstream = agent_env(subdir="agent-noauth")
    key = _client_key(auth)

    for headers in ({}, {"Authorization": "Bearer cgk_not-a-real-key"},
                    {"x-api-key": "cgk_not-a-real-key"}):
        response = client.post("/v1/chat/completions", json=_openai_body(),
                               headers=headers)
        assert response.status_code == 401, response.text
        # OpenAI 形状的错误体:`type`/`code` 都用中间件的错误类别
        assert response.json()["error"]["type"] == "auth"
        assert response.json()["error"]["code"] == "auth"
        assert PHONE not in response.text and key not in response.text

    assert upstream.requests == [], "认证失败却调用了上游"

    # Anthropic 形状的入口同样拒绝,且用 Anthropic 的错误体
    response = client.post("/v1/messages", json=_anthropic_body(),
                           headers={"x-api-key": "cgk_not-a-real-key"})
    assert response.status_code == 401, response.text
    assert response.json()["type"] == "error"
    assert upstream.requests == []


def test_agent_with_unknown_model_gets_404(agent_env):
    """模型名配错是 Agent 接入最常见的失败:必须是清晰的 404,而不是 500 或挂起。"""
    _, client, auth, upstream = agent_env(subdir="agent-badmodel")
    body = _openai_body(model="gpt-4o-not-configured")

    response = client.post("/v1/chat/completions", json=body, headers=auth)
    assert response.status_code == 404, response.text
    assert response.json()["error"]["code"] == "not_found"
    assert upstream.requests == [], "模型未解析成功却调用了上游"


def test_agent_upstream_error_is_mapped_and_leaks_nothing(agent_env):
    """上游报错(它会把收到的报文贴进错误体):客户端最多看到令牌,看不到原文。"""
    mw, client, auth, upstream = agent_env(subdir="agent-uperr")
    upstream.error_status = 429

    response = client.post("/v1/chat/completions", json=_openai_body(), headers=auth)
    assert response.status_code == 429, response.text
    error = response.json()["error"]
    assert error["type"] == "rate_limit"
    assert PHONE not in response.text and EMAIL not in response.text
    assert FAKE_UPSTREAM_KEY not in response.text

    rid = error["request_id"]
    assert mw.audit.get(rid)["error_kind"] == "rate_limit"
    raw = upstream.requests[-1]["body"].decode("utf-8")
    assert PHONE not in raw and EMAIL not in raw and "[CG_TOKEN_" in raw


# --------------------------------------------------------------------------- #
# 5. 明确的缺口(不假装成功)
# --------------------------------------------------------------------------- #
def test_codex_responses_api_is_implemented_and_protects_upstream(agent_env):
    """Codex 只讲 Responses API：本仓库提供无状态最小子集，且上游只看到令牌。"""
    _, client, auth, upstream = agent_env(subdir="agent-codex")

    response = client.post("/v1/responses", headers=auth, json={
        "model": "mock-chat",
        "input": [{"role": "user", "content": PHONE}],
    })
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["object"] == "response"
    assert body["output"][0]["type"] == "message"
    assert len(upstream.requests) == 1, "Responses 请求应当被转发到上游一次"
    raw = upstream.requests[-1]["body"].decode("utf-8")
    assert PHONE not in raw


def test_count_tokens_endpoint_is_not_implemented(agent_env):
    """`/v1/messages/count_tokens` 未实现,返回显式 404(不是挂起,也不是假计数)。

    实测(Claude Code 2.1.150):一次 `-p` 调用只发出 `POST /v1/messages?beta=true`,
    **没有**提交 count_tokens 请求,因此该端点不是连通的必要条件。本用例只钉住
    当前行为:未实现的东西必须显式失败,不得返回一个看起来合理的假 token 数。
    若将来实现了它,本用例会失败 —— 那时应补上真实的计数实现与对应测试。
    """
    _, client, auth, upstream = agent_env(subdir="agent-count")

    response = client.post("/v1/messages/count_tokens",
                           json=_anthropic_body(),
                           headers=_anthropic_headers(_client_key(auth)))
    assert response.status_code == 404, response.text
    assert response.json()["error"]["code"] == "not_found"
    assert upstream.requests == []


def test_upstream_advertised_model_name_does_not_break_agent_verification(agent_env):
    """上游自述的模型名与请求名不同时,客户端复算摘要依然成立。

    (真厂商常回自己的模型名;客户端只拿得到响应体里的 `model`,摘要必须按它算。)
    """
    _, client, auth, upstream = agent_env(subdir="agent-modelname")

    response = client.post("/v1/chat/completions", json=_openai_body(), headers=auth)
    payload = response.json()
    assert payload["model"] == "mock-chat"
    assert payload["model"] != UPSTREAM_ADVERTISED_MODEL

    text = payload["choices"][0]["message"]["content"]
    honest = response_digest(text=text, finish_reason="stop", model=payload["model"])
    assert honest == response.headers["X-CryptoGuard-Response-Digest"]
    # 用上游自述的名字复算会不一致 —— 说明「按响应体 model 复算」不是空话
    assert response_digest(text=text, finish_reason="stop",
                           model=UPSTREAM_ADVERTISED_MODEL) != honest


def test_echo_upstream_received_only_tokens_for_anthropic_requests(agent_env):
    """Anthropic 形状的请求:上游原始字节里连系统提示与工具结果都不含原文。"""
    _, client, auth, upstream = agent_env(mode="token", subdir="agent-cc-bytes")

    response = client.post("/v1/messages", json=_anthropic_body(),
                           headers=_anthropic_headers(_client_key(auth)))
    assert response.status_code == 200, response.text
    raw = upstream.requests[-1]["body"].decode("utf-8")
    sent = json.loads(raw)
    protected = _received_text(sent)
    assert PHONE not in protected and EMAIL not in protected
    assert "[CG_TOKEN_" in protected


def test_openai_reasoning_effort_is_forwarded_to_compatible_upstream(agent_env):
    _, client, auth, upstream = agent_env(subdir="agent-reasoning")
    body = _openai_body()
    body["reasoning_effort"] = "high"
    body["verbosity"] = "low"
    response = client.post("/v1/chat/completions", json=body, headers=auth)
    assert response.status_code == 200, response.text
    sent = json.loads(upstream.requests[-1]["body"].decode("utf-8"))
    assert sent["reasoning_effort"] == "high"
    assert sent["verbosity"] == "low"


def test_openai_only_params_are_rejected_on_anthropic_upstream(make_mw):
    from app.middleware.config import ProviderSettings

    provider = ProviderSettings(
        name="up", type="anthropic", base_url="https://upstream.invalid",
        api_key_env="CG_TEST_ANTHROPIC_KEY", models=("mock-chat",))
    _, client, key = make_mw(providers=(provider,), default_provider="up",
                             data_subdir="agent-anthropic-params")
    response = client.post("/v1/chat/completions",
                           headers={"Authorization": f"Bearer {key}"},
                           json={**_openai_body(), "reasoning_effort": "high"})
    assert response.status_code == 400, response.text
    assert "openai-compatible" in response.text
