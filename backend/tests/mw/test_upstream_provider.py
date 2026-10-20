"""
上游提供商层测试 —— 真实 HTTP 往返(本机临时上游服务),不使用 MockTransport

覆盖任务书 Phase 3 的要求:
  - 密钥管理:密钥只进请求头、不进 URL/错误体/日志;密钥缺失时 fail-closed 且**不出网**;
  - 超时:连接/读取超时分类为 timeout;有限重试:4xx 不重试、429/5xx 重试且次数有硬上限;
  - 错误处理:401/403/404/429/4xx/5xx/网络/超时/协议错误各自分类,不泄露上游密钥;
  - 流式:首字节前可重试、已产出增量后不重试(避免重复计费),断流以 finish_reason=None 收尾。

为什么用真实 HTTP 而不是 httpx.MockTransport:MockTransport 会绕过真实连接、头部编码、
分块与断流行为,测不到「真的发了一个带 Authorization 头的请求」这件事本身。

不承诺:本文件不访问任何真实模型服务,不构成对真实上游兼容性的验证。
真实上游测试见 test_real_upstream_not_executed 的说明(标记为未执行,不伪造结果)。
"""
from __future__ import annotations

import json
import socket
import socketserver
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from app.middleware.config import ConfigError, Settings, _Env, _parse_providers
from app.middleware.errors import MiddlewareError
from app.middleware.providers.base import ChatRequest, ProviderConfig
from app.middleware.providers.openai_compat import OpenAICompatibleProvider
from app.middleware.providers.registry import build_registry

#: 形如真实密钥的假值:既能被 _scrub 的 sk- 规则命中,又不可能真的可用
FAKE_KEY = "sk-fake-000111222333444555666777888999"


# --------------------------------------------------------------------------- #
# 本机临时上游
# --------------------------------------------------------------------------- #
class _FastTCPServer(ThreadingHTTPServer):
    """跳过 HTTPServer.server_bind() 里的 socket.getfqdn() 反查 DNS。

    该反查对测试毫无用处,却会让每个测试服务器多花数百毫秒(本机实测约 0.5s)。
    """

    def server_bind(self):  # noqa: D102 — 语义同父类,仅去掉 DNS 反查
        socketserver.TCPServer.server_bind(self)
        self.server_name = "127.0.0.1"
        self.server_port = self.server_address[1]


class FakeUpstream:
    """可编排响应的本机 HTTP 上游(真实 socket,真实分块)。

    响应来源:先取 `push()` 的队列(先进先出),队列空则用 `always()` 的默认值,
    都没有则 500。支持 delay(模拟慢上游)与 chunks(模拟 SSE 分块到达)。
    """

    def __init__(self) -> None:
        self.requests: list[dict] = []
        self._queue: list[dict] = []
        self._default: dict | None = None
        self._lock = threading.Lock()
        self._server = _FastTCPServer(("127.0.0.1", 0), self._make_handler())
        self._server.daemon_threads = True
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    # ---------------- 对外 ----------------
    @property
    def base_url(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    @property
    def paths(self) -> list[str]:
        return [r["path"] for r in self.requests]

    def push(self, **spec) -> None:
        with self._lock:
            self._queue.append(spec)

    def always(self, **spec) -> None:
        self._default = spec

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)

    # ---------------- 内部 ----------------
    def _record(self, path: str, headers: dict, body: bytes) -> None:
        with self._lock:
            self.requests.append({"path": path, "headers": headers, "body": body})

    def _next(self) -> dict:
        with self._lock:
            if self._queue:
                return self._queue.pop(0)
        if self._default is not None:
            return self._default
        return {"status": 500, "body": {"error": {"message": "fake upstream: no script"}}}

    def _make_handler(self):
        upstream = self

        class _Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self):  # noqa: N802 — BaseHTTPRequestHandler 约定
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                upstream._record(self.path,
                                 {k.lower(): v for k, v in self.headers.items()}, raw)
                spec = upstream._next()
                delay = float(spec.get("delay") or 0.0)
                if delay:
                    time.sleep(delay)
                status = int(spec.get("status", 200))
                headers = dict(spec.get("headers") or {})
                chunks = spec.get("chunks")
                try:
                    if chunks is None:
                        self._send_body(status, headers, spec.get("body", b""))
                    else:
                        self._send_stream(status, headers, chunks)
                except OSError:
                    # 客户端提前断开(超时/取消)时写入会失败,属预期,不污染测试
                    pass
                self.close_connection = True

            def _send_body(self, status: int, headers: dict, body) -> None:
                if isinstance(body, str):
                    body = body.encode("utf-8")
                elif isinstance(body, (dict, list)):
                    body = json.dumps(body, ensure_ascii=False).encode("utf-8")
                ctype = headers.pop("Content-Type", headers.pop("content-type",
                                                                "application/json"))
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                for key, value in headers.items():
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _send_stream(self, status: int, headers: dict, chunks) -> None:
                ctype = headers.pop("Content-Type", headers.pop("content-type",
                                                                "text/event-stream"))
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                # 无 Content-Length,以关闭连接作为消息边界(与真实 SSE 上游一致)
                self.send_header("Connection", "close")
                for key, value in headers.items():
                    self.send_header(key, value)
                self.end_headers()
                for chunk in chunks:
                    self.wfile.write(chunk.encode("utf-8") if isinstance(chunk, str)
                                     else chunk)
                    self.wfile.flush()
                    time.sleep(0.005)

            def log_message(self, *args):  # noqa: ANN002 — 静音访问日志
                pass

        return _Handler


@pytest.fixture
def upstream():
    server = FakeUpstream()
    try:
        yield server
    finally:
        server.close()


# --------------------------------------------------------------------------- #
# 辅助
# --------------------------------------------------------------------------- #
def make_provider(server: FakeUpstream, **overrides) -> OpenAICompatibleProvider:
    kwargs = dict(
        name="fake", type="openai-compatible", base_url=server.base_url,
        api_key=FAKE_KEY, models=("fake-model",),
        timeout_connect=2.0, timeout_read=2.0, max_retries=0,
    )
    kwargs.update(overrides)
    return OpenAICompatibleProvider(ProviderConfig(**kwargs))


def chat_request(**overrides) -> ChatRequest:
    kwargs = dict(model="fake-model", messages=[{"role": "user", "content": "你好"}])
    kwargs.update(overrides)
    return ChatRequest(**kwargs)


#: 假上游自述的 model 名,与请求里的 model 名刻意不同 —— 真厂商常见
#: (请求 "deepseek-chat",响应里回一个带版本号/别名的名字)。
UPSTREAM_ADVERTISED_MODEL = "fake-model-upstream"


def completion_body(text: str = "你好", **message_extra) -> dict:
    message = {"role": "assistant", "content": text}
    message.update(message_extra)
    return {
        "id": "chatcmpl-fake", "object": "chat.completion",
        "model": UPSTREAM_ADVERTISED_MODEL,
        "choices": [{"index": 0, "message": message, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5},
    }


def sse(*payloads, done: bool = True) -> list[str]:
    """把若干 JSON 事件编成 SSE 分块;done=True 时补 `data: [DONE]`。"""
    out = [f"data: {json.dumps(p, ensure_ascii=False)}\n\n" for p in payloads]
    if done:
        out.append("data: [DONE]\n\n")
    return out


def text_delta(text: str, finish: str | None = None) -> dict:
    choice: dict = {"index": 0, "delta": {"content": text}}
    if finish is not None:
        choice["finish_reason"] = finish
    return {"object": "chat.completion.chunk", "choices": [choice]}


def drain(iterator) -> list:
    return list(iterator)


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


# --------------------------------------------------------------------------- #
# 密钥管理
# --------------------------------------------------------------------------- #
def test_key_is_sent_in_authorization_header_only(upstream):
    """密钥只出现在 Authorization 头:不在 URL、不在请求体。"""
    upstream.always(body=completion_body("ok"))
    provider = make_provider(upstream)

    provider.complete(chat_request())

    assert upstream.paths == ["/chat/completions"]
    sent = upstream.requests[-1]
    assert sent["headers"]["authorization"] == f"Bearer {FAKE_KEY}"
    assert FAKE_KEY not in sent["path"]
    assert FAKE_KEY not in sent["body"].decode("utf-8")


def test_base_url_path_prefix_is_preserved(upstream):
    """base_url 里带路径前缀(如自建网关 /v1)时必须原样保留。"""
    upstream.always(body=completion_body("ok"))
    provider = make_provider(upstream, base_url=f"{upstream.base_url}/v1")

    provider.complete(chat_request())

    assert upstream.paths == ["/v1/chat/completions"]


def test_upstream_error_body_cannot_leak_the_key(upstream):
    """上游错误回显了密钥(现实里常见)时,回给客户端的错误体必须已打码。"""
    upstream.always(status=400, body={"error": {
        "message": f"invalid api_key: {FAKE_KEY} (Authorization: Bearer {FAKE_KEY})"}})
    provider = make_provider(upstream)

    with pytest.raises(MiddlewareError) as excinfo:
        provider.complete(chat_request())

    error = excinfo.value
    assert error.kind == "upstream_4xx"
    assert FAKE_KEY not in error.detail
    assert "sk-" not in error.detail
    assert FAKE_KEY not in json.dumps(error.openai_body(), ensure_ascii=False)
    assert FAKE_KEY not in json.dumps(error.anthropic_body(), ensure_ascii=False)


def test_unconfigured_provider_fails_closed_without_touching_network(upstream):
    """缺密钥必须 fail-closed 且**一个请求都不发**(否则会把配置问题误报成认证失败)。"""
    provider = make_provider(upstream, api_key="")

    with pytest.raises(MiddlewareError) as excinfo:
        provider.complete(chat_request())
    assert excinfo.value.kind == "config"
    assert excinfo.value.http_status == 503

    # 流式同样在首次迭代就失败——不是「先建连再报错」
    with pytest.raises(MiddlewareError) as stream_exc:
        next(provider.stream(chat_request()))
    assert stream_exc.value.kind == "config"

    assert upstream.requests == []


def test_missing_base_url_also_fails_closed(upstream):
    provider = make_provider(upstream, base_url="")
    with pytest.raises(MiddlewareError) as excinfo:
        provider.complete(chat_request())
    assert excinfo.value.kind == "config"
    assert "base_url" in excinfo.value.detail
    assert upstream.requests == []


def test_health_view_never_contains_the_key(upstream):
    provider = make_provider(upstream)
    view = provider.health()
    assert view["has_key"] is True
    assert FAKE_KEY not in json.dumps(view, ensure_ascii=False)
    assert "api_key" not in view


# --------------------------------------------------------------------------- #
# 请求构造
# --------------------------------------------------------------------------- #
def test_payload_carries_supported_fields(upstream):
    upstream.always(body=completion_body("ok"))
    provider = make_provider(upstream)
    tools = [{"type": "function", "function": {"name": "get_time", "parameters": {}}}]

    provider.complete(chat_request(
        temperature=0.3, top_p=0.9, max_tokens=128, stop=["\n"],
        tools=tools, tool_choice="auto", presence_penalty=0.1,
        frequency_penalty=0.2, seed=7, user="agent-1"))

    payload = json.loads(upstream.requests[-1]["body"])
    assert payload["model"] == "fake-model"
    assert payload["messages"] == [{"role": "user", "content": "你好"}]
    assert payload["temperature"] == 0.3
    assert payload["top_p"] == 0.9
    assert payload["max_tokens"] == 128
    assert payload["stop"] == ["\n"]
    assert payload["tools"] == tools
    assert payload["tool_choice"] == "auto"
    assert payload["presence_penalty"] == 0.1
    assert payload["frequency_penalty"] == 0.2
    assert payload["seed"] == 7
    assert payload["user"] == "agent-1"
    # 未给 stream:绝不带 stream / stream_options(不臆造行为改变)
    assert "stream" not in payload
    assert "stream_options" not in payload


def test_absent_fields_are_omitted_not_defaulted(upstream):
    """没传的字段不得被填充默认值后发给上游(那会改变模型行为)。"""
    upstream.always(body=completion_body("ok"))
    make_provider(upstream).complete(chat_request())

    payload = json.loads(upstream.requests[-1]["body"])
    assert set(payload) == {"model", "messages"}


def test_token_limit_field_switch(upstream):
    """部分厂商只认 max_completion_tokens:按配置显式切换,不静默猜测。"""
    upstream.always(body=completion_body("ok"))
    provider = make_provider(upstream, token_limit_field="max_completion_tokens")

    provider.complete(chat_request(max_tokens=64))

    payload = json.loads(upstream.requests[-1]["body"])
    assert payload["max_completion_tokens"] == 64
    assert "max_tokens" not in payload


def test_stream_options_fall_back_to_provider_config(upstream):
    """流式时必须带厂商要求的 stream_options(如 DeepSeek 的 include_usage)。"""
    upstream.always(chunks=sse(text_delta("hi", "stop")))
    provider = make_provider(upstream, stream_options={"include_usage": True})

    drain(provider.stream(chat_request(stream=True)))

    payload = json.loads(upstream.requests[-1]["body"])
    assert payload["stream"] is True
    assert payload["stream_options"] == {"include_usage": True}

    # 非流式请求绝不带 stream_options
    upstream.always(body=completion_body("ok"))
    provider.complete(chat_request())
    assert "stream_options" not in json.loads(upstream.requests[-1]["body"])


# --------------------------------------------------------------------------- #
# 响应解析
# --------------------------------------------------------------------------- #
def test_completion_fields_are_mapped(upstream):
    upstream.always(body=completion_body(
        "答案", reasoning_content="思考中",
        tool_calls=[{"id": "call_1", "type": "function",
                     "function": {"name": "f", "arguments": '{"a":1}'}}]))
    completion = make_provider(upstream).complete(chat_request())

    assert completion.text == "答案"
    assert completion.reasoning == "思考中"
    assert [(c.id, c.name, c.arguments) for c in completion.tool_calls] == [
        ("call_1", "f", '{"a":1}')]
    assert completion.finish_reason == "stop"
    assert completion.usage["total_tokens"] == 5


def test_content_array_is_joined(upstream):
    upstream.always(body={"choices": [{"message": {
        "content": [{"type": "text", "text": "你"}, {"type": "text", "text": "好"}]},
        "finish_reason": "stop"}]})
    assert make_provider(upstream).complete(chat_request()).text == "你好"


@pytest.mark.parametrize("raw,expected", [
    ("function_call", "tool_calls"), ("length", "length"), ("stop", "stop"),
    ("content_filter", "content_filter"), ("weird_new_reason", "weird_new_reason"),
])
def test_finish_reason_mapping(upstream, raw, expected):
    upstream.always(body={"choices": [{"message": {"content": ""},
                                       "finish_reason": raw}]})
    assert make_provider(upstream).complete(chat_request()).finish_reason == expected


def test_non_json_success_body_is_protocol_error_and_not_retried(upstream):
    """上游 200 但返回非 JSON:分类为 protocol,且不重试(重试也只会再拿到同样的坏响应)。"""
    upstream.always(status=200, body=b"<html>gateway</html>")
    provider = make_provider(upstream, max_retries=3)

    with pytest.raises(MiddlewareError) as excinfo:
        provider.complete(chat_request())

    assert excinfo.value.kind == "protocol"
    assert len(upstream.requests) == 1


def test_missing_choices_is_protocol_error(upstream):
    upstream.always(body={"id": "x", "object": "chat.completion"})
    with pytest.raises(MiddlewareError) as excinfo:
        make_provider(upstream).complete(chat_request())
    assert excinfo.value.kind == "protocol"
    assert "choices" in excinfo.value.detail


def test_stream_parses_frames(upstream):
    upstream.always(chunks=sse(
        {"choices": [{"delta": {"reasoning_content": "想"}}]},
        text_delta("你"), text_delta("好"),
        {"choices": [{"delta": {"tool_calls": [
            {"index": 0, "id": "call_9", "function": {"name": "f", "arguments": "{}"}}]}}]},
        {"choices": [], "usage": {"total_tokens": 11}},
        text_delta("", "stop"),
    ))
    chunks = drain(make_provider(upstream).stream(chat_request(stream=True)))

    assert [c.kind for c in chunks] == ["reasoning", "text", "text", "tool_call",
                                        "usage", "done"]
    assert "".join(c.text for c in chunks if c.kind == "text") == "你好"
    assert chunks[3].tool_id == "call_9"
    assert chunks[4].usage == {"total_tokens": 11}
    assert chunks[-1].finish_reason == "stop"


def test_stream_without_done_marks_incomplete(upstream):
    """上游未发 [DONE] 就断流:以 done(finish_reason=None) 收尾,不假装正常结束。"""
    upstream.always(chunks=[f"data: {json.dumps(text_delta('半'))}\n\n"])  # 无 [DONE]
    chunks = drain(make_provider(upstream).stream(chat_request(stream=True)))

    assert [c.kind for c in chunks] == ["text", "done"]
    assert chunks[-1].finish_reason is None


def test_stream_tolerates_broken_frames(upstream):
    """坏帧/注释行/空行不得中断整条流(否则一次网络抖动就会截断用户回答)。"""
    upstream.always(chunks=[
        ": keep-alive\n\n",
        "data: {不是JSON\n\n",
        "data: \n\n",
        f"data: {json.dumps(text_delta('ok'))}\n\n",
        "data: [DONE]\n\n",
    ])
    chunks = drain(make_provider(upstream).stream(chat_request(stream=True)))
    assert [c.kind for c in chunks] == ["text", "done"]


# --------------------------------------------------------------------------- #
# 错误分类与有限重试
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("status,kind", [
    (401, "auth"), (403, "auth"), (404, "not_found"),
    (429, "rate_limit"), (400, "upstream_4xx"), (422, "upstream_4xx"),
    (500, "upstream_5xx"), (502, "upstream_5xx"), (503, "upstream_5xx"),
])
def test_status_classification(upstream, status, kind):
    upstream.always(status=status, body={"error": {"message": "上游说不行"}})
    with pytest.raises(MiddlewareError) as excinfo:
        make_provider(upstream).complete(chat_request())

    assert excinfo.value.kind == kind
    assert excinfo.value.upstream_status == status
    assert excinfo.value.detail == "上游说不行"


@pytest.mark.parametrize("status", [400, 401, 403, 404, 422])
def test_client_side_errors_are_not_retried(upstream, status):
    """4xx 是请求本身的问题:重试只会重复计费,必须立刻失败。"""
    upstream.always(status=status, body={"error": {"message": "bad"}})
    with pytest.raises(MiddlewareError):
        make_provider(upstream, max_retries=3).complete(chat_request())
    assert len(upstream.requests) == 1


def test_rate_limit_is_retried_then_succeeds(upstream):
    upstream.push(status=429, headers={"Retry-After": "0"},
                  body={"error": {"message": "slow down"}})
    upstream.always(body=completion_body("恢复"))
    completion = make_provider(upstream, max_retries=2).complete(chat_request())

    assert completion.text == "恢复"
    assert len(upstream.requests) == 2


def test_server_error_retries_are_bounded(upstream):
    """5xx 重试次数有硬上限:max_retries=2 → 最多 3 次请求,绝不无限重试烧钱。"""
    upstream.always(status=503, body={"error": {"message": "unavailable"}})
    with pytest.raises(MiddlewareError) as excinfo:
        make_provider(upstream, max_retries=2).complete(chat_request())

    assert excinfo.value.kind == "upstream_5xx"
    assert len(upstream.requests) == 3


def test_zero_retries_means_exactly_one_attempt(upstream):
    upstream.always(status=500, body={"error": {"message": "boom"}})
    with pytest.raises(MiddlewareError):
        make_provider(upstream, max_retries=0).complete(chat_request())
    assert len(upstream.requests) == 1


def test_transport_exceptions_are_classified():
    """传输层异常 → 中间件错误类别的映射(纯函数,平台无关)。

    映射正确性直接决定重试决策:只有 timeout/network/rate_limit/upstream_5xx 可重试。
    """
    import httpx

    cases = [
        (httpx.ConnectError("refused"), "network"),
        (httpx.ConnectTimeout("connect timeout"), "timeout"),
        (httpx.ReadTimeout("read timeout"), "timeout"),
        (httpx.RemoteProtocolError("peer closed"), "network"),
        (httpx.ProxyError("proxy"), "network"),
        (ValueError("unexpected"), "internal"),
    ]
    for exc, kind in cases:
        mapped = OpenAICompatibleProvider._classify_transport(exc)
        assert mapped.kind == kind, f"{type(exc).__name__} → {mapped.kind}"
    # 已是 MiddlewareError 的原样透传(不重复包装、不丢 upstream_status)
    original = MiddlewareError("rate_limit", "上游限流", upstream_status=429)
    assert OpenAICompatibleProvider._classify_transport(original) is original


def test_unreachable_upstream_fails_fast_and_bounded(upstream):
    """连不上的上游:归入网络类错误,不重试到天荒地老,且总耗时受连接超时约束。

    注 1:Windows 上连接被拒通常表现为 ConnectTimeout 而非 ECONNREFUSED,
    故此处接受 timeout/network 两者之一 —— 关键是「分类明确 + 次数有界 + 快速失败」。
    注 2:本断言成立的前提是 trust_env=False(默认)。若让 httpx 采纳系统代理,
    连接会被交给代理从而吃掉我们的 connect 超时(实测 0.4s 变 2.6s,且类别变成
    ReadTimeout)—— 这正是默认关闭 trust_env 的原因之一。
    """
    provider = make_provider(upstream, base_url=f"http://127.0.0.1:{free_port()}",
                             timeout_connect=0.4, max_retries=1)
    assert provider.config.trust_env is False

    started = time.monotonic()
    with pytest.raises(MiddlewareError) as excinfo:
        provider.complete(chat_request())
    elapsed = time.monotonic() - started

    assert excinfo.value.kind in ("network", "timeout")
    assert excinfo.value.http_status in (502, 504)
    assert FAKE_KEY not in excinfo.value.detail
    assert elapsed < 3.0                       # 2 次尝试 × 0.4s 连接超时,不应更久


def test_trust_env_is_forwarded_to_httpx_and_defaults_off(upstream):
    """出网路径必须显式:默认不采纳环境/系统代理,开启时才传给 httpx。

    代理能看到上游 Authorization 头与响应体,不能让它被环境变量悄悄打开。
    """
    import httpx

    upstream.always(body=completion_body("ok"))
    captured: list[dict] = []
    real_client = httpx.Client

    def spy(*args, **kwargs):
        captured.append(kwargs)
        return real_client(*args, **kwargs)

    original = httpx.Client
    httpx.Client = spy
    try:
        make_provider(upstream).complete(chat_request())
        make_provider(upstream, trust_env=True).complete(chat_request())
    finally:
        httpx.Client = original

    assert [kw.get("trust_env") for kw in captured] == [False, True]
    assert all(kw.get("timeout") is not None for kw in captured)


def test_read_timeout_is_classified_as_timeout(upstream):
    upstream.always(delay=1.5, body=completion_body("太慢了"))
    provider = make_provider(upstream, timeout_connect=0.3, timeout_read=0.2,
                             max_retries=0)

    started = time.monotonic()
    with pytest.raises(MiddlewareError) as excinfo:
        provider.complete(chat_request())

    assert excinfo.value.kind == "timeout"
    assert time.monotonic() - started < 1.2      # 没有傻等上游的 1.5s
    assert len(upstream.requests) == 1


def test_backoff_honors_retry_after_with_cap():
    """Retry-After 被采纳但有上限:上游要求等 999s 也不能拖死客户端连接。"""
    assert OpenAICompatibleProvider._backoff(0, {"retry-after": "2"}) == pytest.approx(
        2.0, abs=0.001)
    assert OpenAICompatibleProvider._backoff(0, {"retry-after": "999"}) <= 5.0
    assert OpenAICompatibleProvider._backoff(0, {"retry-after": "not-a-number"}) <= 0.7
    assert OpenAICompatibleProvider._backoff(3, None) <= 4.3


def test_stream_is_retried_before_first_byte(upstream):
    upstream.push(status=503, body={"error": {"message": "cold start"}})
    upstream.always(chunks=sse(text_delta("好", "stop")))
    chunks = drain(make_provider(upstream, max_retries=2).stream(
        chat_request(stream=True)))

    assert len(upstream.requests) == 2
    assert "".join(c.text for c in chunks if c.kind == "text") == "好"
    assert chunks[-1].finish_reason == "stop"


def test_stream_is_not_retried_after_partial_output(upstream):
    """已产出增量后绝不重试:重试会导致用户看到重复文本并对上游重复计费。"""
    upstream.always(chunks=[f"data: {json.dumps(text_delta('一半'))}\n\n"])  # 断流
    chunks = drain(make_provider(upstream, max_retries=3).stream(
        chat_request(stream=True)))

    assert len(upstream.requests) == 1
    assert [c.kind for c in chunks] == ["text", "done"]
    assert chunks[-1].finish_reason is None


def test_stream_error_body_is_parsed_not_reported_as_internal(upstream):
    """回归:流式响应的错误体必须先 read() 再解析。

    否则 httpx 抛 ResponseNotRead → 被归为 internal → 上游限流/5xx 还会变成不可重试。
    """
    upstream.always(status=429, headers={"Retry-After": "0"},
                    body={"error": {"message": "上游说太频繁了"}})
    provider = make_provider(upstream, max_retries=0)

    with pytest.raises(MiddlewareError) as excinfo:
        next(provider.stream(chat_request(stream=True)))

    assert excinfo.value.kind == "rate_limit"
    assert excinfo.value.upstream_status == 429
    assert excinfo.value.detail == "上游说太频繁了"
    assert excinfo.value.retryable is True


def test_stream_rate_limit_is_retried_before_first_byte(upstream):
    upstream.push(status=429, headers={"Retry-After": "0"},
                  body={"error": {"message": "slow down"}})
    upstream.always(chunks=sse(text_delta("好了", "stop")))

    chunks = drain(make_provider(upstream, max_retries=2).stream(
        chat_request(stream=True)))

    assert len(upstream.requests) == 2
    assert "".join(c.text for c in chunks if c.kind == "text") == "好了"


def test_stream_error_before_first_byte_raises_after_retries(upstream):
    upstream.always(status=401, body={"error": {"message": "bad key"}})
    provider = make_provider(upstream, max_retries=2)

    with pytest.raises(MiddlewareError) as excinfo:
        next(provider.stream(chat_request(stream=True)))

    assert excinfo.value.kind == "auth"
    assert excinfo.value.detail == "bad key"    # 错误体确实被读出来并解析了
    assert len(upstream.requests) == 1          # 认证错误不重试


# --------------------------------------------------------------------------- #
# 注册表与配置装配
# --------------------------------------------------------------------------- #
def _settings(**overrides) -> Settings:
    from app.middleware.config import ProviderSettings
    provider = ProviderSettings(
        name="up", type="openai-compatible", base_url="https://upstream.invalid",
        api_key_env="CG_TEST_UPSTREAM_KEY", models=("m1", "m2"),
    )
    kwargs = dict(providers=(provider,), default_provider="up", default_model="m2")
    kwargs.update(overrides)
    return Settings(**kwargs)


def test_registry_reads_key_from_environment(monkeypatch):
    monkeypatch.setenv("CG_TEST_UPSTREAM_KEY", FAKE_KEY)
    registry = build_registry(_settings())

    provider, upstream_model = registry.resolve("m1")
    assert upstream_model == "m1"
    assert provider.config.resolved_api_key == FAKE_KEY
    assert registry.health()["providers"][0]["has_key"] is True


def test_registry_has_key_is_false_without_environment(monkeypatch):
    monkeypatch.delenv("CG_TEST_UPSTREAM_KEY", raising=False)
    registry = build_registry(_settings())

    assert registry.health()["providers"][0]["has_key"] is False
    with pytest.raises(MiddlewareError) as excinfo:
        registry.get("up").complete(chat_request())
    assert excinfo.value.kind == "config"


def test_registry_unknown_model_is_rejected_with_available_list(monkeypatch):
    monkeypatch.setenv("CG_TEST_UPSTREAM_KEY", FAKE_KEY)
    registry = build_registry(_settings())

    with pytest.raises(MiddlewareError) as excinfo:
        registry.resolve("gpt-不存在")
    assert excinfo.value.kind == "not_found"
    assert "m1" in excinfo.value.detail and "m2" in excinfo.value.detail


def test_registry_alias_and_explicit_provider_prefix(monkeypatch):
    monkeypatch.setenv("CG_TEST_UPSTREAM_KEY", FAKE_KEY)
    registry = build_registry(_settings(model_aliases={"claude-sonnet-5-5": "up/m1"}))

    provider, upstream_model = registry.resolve("claude-sonnet-5-5")
    assert provider.name == "up" and upstream_model == "m1"
    assert registry.resolve("up/m2")[1] == "m2"
    # 前缀语法不绕过白名单
    with pytest.raises(MiddlewareError) as excinfo:
        registry.resolve("up/未声明模型")
    assert excinfo.value.kind == "not_found"


def test_registry_allow_unknown_models_passthrough(monkeypatch):
    monkeypatch.setenv("CG_TEST_UPSTREAM_KEY", FAKE_KEY)
    registry = build_registry(_settings(allow_unknown_models=True))

    provider, upstream_model = registry.resolve("任意未来模型")
    assert provider.name == "up" and upstream_model == "任意未来模型"


def test_trust_env_defaults_to_off_and_is_configurable(tmp_path, monkeypatch):
    """出网是否走代理是安全相关的显式决策:默认关闭,可在全局或单个提供商上开启。"""
    def parse(entries, defaults):
        monkeypatch.setenv("CG_PROVIDERS", json.dumps(entries))
        return _parse_providers(_Env(tmp_path / "nonexistent.env"), defaults)

    base = {"name": "up", "type": "openai-compatible",
            "base_url": "https://x.invalid", "models": ["m1"]}

    assert parse([base], (10.0, 120.0, 2, False))[0].trust_env is False
    assert parse([base], (10.0, 120.0, 2, True))[0].trust_env is True      # 全局默认
    assert parse([{**base, "trust_env": False}], (10.0, 120.0, 2, True))[
        0].trust_env is False                                              # 单提供商覆盖
    assert parse([{**base, "trust_env": True}], (10.0, 120.0, 2, False))[
        0].trust_env is True


def test_registry_forwards_trust_env(tmp_path, monkeypatch):
    from app.middleware.config import ProviderSettings
    settings = _settings(providers=(ProviderSettings(
        name="up", type="openai-compatible", base_url="https://upstream.invalid",
        api_key_env="CG_TEST_UPSTREAM_KEY", models=("m1",), trust_env=True),))
    monkeypatch.setenv("CG_TEST_UPSTREAM_KEY", FAKE_KEY)

    registry = build_registry(settings)
    assert registry.get("up").config.trust_env is True
    assert registry.health()["providers"][0]["trust_env"] is True


# --------------------------------------------------------------------------- #
# 真实上游:未执行
# --------------------------------------------------------------------------- #
@pytest.mark.skip(reason="未执行:当前环境无真实上游密钥/网络,不伪造成功结果。"
                         "真实厂商联调请显式设置 CG_REAL_UPSTREAM_KEY / "
                         "CG_REAL_UPSTREAM_URL / CG_REAL_MODEL 后运行 "
                         "tests/mw/test_real_http_e2e.py::test_real_vendor_upstream_opt_in,"
                         "边界与注意事项见 docs/GATEWAY_TESTS.md")
def test_real_upstream_not_executed():
    """占位:真实厂商(DeepSeek/OpenAI)连通性测试。

    本仓库的自动化测试只覆盖到本机 HTTP 上游与 Mock Provider;
    真实上游的连通性、模型名有效性与计费行为必须在有密钥的环境手动执行并记录结果。
    """
