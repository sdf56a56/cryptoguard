"""
OpenAI 兼容提供商 —— 覆盖 OpenAI / DeepSeek / 及一切实现 /chat/completions 的服务

安全目标:
  - 密钥只进 Authorization 头,绝不进 URL、日志、异常或响应体;
  - 有限重试:max_retries ∈ 0..5(配置层已强校验),指数退避 + 抖动,
    且只在「尚未向客户端产出任何字节」时重试流式请求,避免重复计费与重复 token;
  - 错误分类显式化:429→rate_limit、5xx→upstream_5xx、401/403→auth、
    其余 4xx→upstream_4xx、超时→timeout、连接失败→network、解析失败→protocol。

明确不承诺:
  - POST /chat/completions 非幂等:重试有产生重复计费的理论可能,故重试上限硬约束为 5,
    且默认仅 2 次,并只对「连接/超时/429/5xx」这类未产生可用结果的失败重试;
  - 不承诺上游对 stream_options / max_tokens 的字段兼容性(见 token_limit_field 配置)。
"""
from __future__ import annotations

import json
import logging
import random
import threading
import time
from collections.abc import Iterator
from typing import Any

import httpx

from ..errors import MiddlewareError, classify_upstream_status
from .base import ChatRequest, Completion, ModelProvider, ProviderConfig, StreamChunk, ToolCall

logger = logging.getLogger(__name__)

#: 退避上限:即使上游给 Retry-After 也不盲从超长等待(避免拖死客户端连接)
_MAX_BACKOFF_S = 4.0
_MAX_RETRY_AFTER_S = 5.0


class OpenAICompatibleProvider(ModelProvider):
    """`POST {base_url}/chat/completions` 提供商。"""

    TYPE = "openai-compatible"

    def __init__(self, config: ProviderConfig, *, transport: httpx.BaseTransport | None = None):
        super().__init__(config)
        self._transport = transport
        #: 该厂商使用的 token 上限字段名(max_tokens / max_completion_tokens)
        self._token_field = config.token_limit_field or "max_tokens"
        #: 复用的 HTTP 客户端(延迟创建;httpx.Client 本身线程安全)
        self._http: httpx.Client | None = None
        self._http_lock = threading.Lock()

    # ------------------------------------------------------------------ #
    # 传输
    # ------------------------------------------------------------------ #
    def _client(self) -> httpx.Client:
        """取复用的 HTTP 客户端(首次调用时创建)。

        为什么必须复用:构造 httpx.Client 会重建连接池(本机实测约 0.6s),
        且每次新建客户端都等于放弃 keep-alive —— 每次上游调用都要重做一次
        TCP(+TLS)握手。网关是长跑进程,这两种代价都不该按请求支付。
        """
        client = self._http
        if client is None:
            with self._http_lock:
                if self._http is None:
                    self._http = httpx.Client(
                        timeout=self._timeout(), transport=self._transport,
                        trust_env=self.config.trust_env)
                client = self._http
        return client

    def close(self) -> None:
        """释放连接池(进程退出时调用)。"""
        client, self._http = self._http, None
        if client is not None:
            try:
                client.close()
            except Exception as exc:  # noqa: BLE001 — 关闭失败不影响退出
                logger.warning("关闭上游连接池失败: %s", type(exc).__name__)

    def _url(self, path: str = "/chat/completions") -> str:
        return self.config.base_url.rstrip("/") + path

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        key = self.config.resolved_api_key
        if key:
            #: 密钥只进请求头;绝不进 URL(URL 会出现在上游访问日志与错误栈里)
            headers["Authorization"] = f"Bearer {key}"
        headers.update(self.config.extra_headers)
        return headers

    def _timeout(self) -> httpx.Timeout:
        return httpx.Timeout(
            connect=self.config.timeout_connect,
            read=self.config.timeout_read,
            write=self.config.timeout_read,
            pool=self.config.timeout_connect,
        )

    def _build_payload(self, req: ChatRequest) -> dict:
        payload: dict[str, Any] = {
            "model": req.model,
            "messages": list(req.messages),
        }
        if req.stream:
            payload["stream"] = True
            stream_options = req.stream_options or self.config.stream_options
            if stream_options:
                payload["stream_options"] = stream_options
        if req.max_tokens is not None:
            payload[self._token_field] = req.max_tokens
        for name in ("temperature", "top_p", "stop", "presence_penalty",
                     "frequency_penalty", "seed", "user"):
            value = getattr(req, name)
            if value is not None:
                payload[name] = value
        if req.tools is not None:
            payload["tools"] = req.tools
        if req.tool_choice is not None:
            payload["tool_choice"] = req.tool_choice
        payload.update(req.extra or {})
        return payload

    @staticmethod
    def _classify_transport(exc: BaseException) -> MiddlewareError:
        if isinstance(exc, MiddlewareError):
            return exc
        if isinstance(exc, httpx.TimeoutException):
            return MiddlewareError("timeout", f"上游请求超时: {type(exc).__name__}")
        if isinstance(exc, (httpx.NetworkError, httpx.RemoteProtocolError, httpx.ProxyError)):
            return MiddlewareError("network", f"上游连接失败: {type(exc).__name__}")
        return MiddlewareError("internal", f"上游调用内部错误: {type(exc).__name__}")

    def _raise_for_status(self, response: httpx.Response) -> None:
        if 200 <= response.status_code < 300:
            return
        kind = classify_upstream_status(response.status_code)
        detail = _error_detail(response)
        raise MiddlewareError(kind, detail or f"上游返回 HTTP {response.status_code}",
                              upstream_status=response.status_code,
                              headers=dict(response.headers))

    @staticmethod
    def _backoff(attempt: int, headers: dict | None = None) -> float:
        """第 attempt 次重试前的等待(0 起):指数 + 抖动,Retry-After 上限截断。"""
        delay = min(_MAX_BACKOFF_S, 0.4 * (2 ** attempt))
        delay += random.uniform(0, 0.2)
        retry_after = (headers or {}).get("retry-after")
        if retry_after:
            try:
                delay = max(delay, min(_MAX_RETRY_AFTER_S, float(retry_after)))
            except (TypeError, ValueError):
                pass
        return delay

    # ------------------------------------------------------------------ #
    # 非流式
    # ------------------------------------------------------------------ #
    def complete(self, req: ChatRequest) -> Completion:
        self.ensure_configured()
        payload = self._build_payload(req)
        attempts = self.config.max_retries + 1
        last: MiddlewareError | None = None
        for attempt in range(attempts):
            try:
                response = self._client().post(self._url(), headers=self._headers(),
                                               json=payload)
                self._raise_for_status(response)
                try:
                    body = response.json()
                except ValueError:
                    raise MiddlewareError("protocol", "上游返回非 JSON 响应") from None
                return _parse_completion(body, req.model)
            except MiddlewareError as exc:
                last = exc
                if not exc.retryable or attempt == attempts - 1:
                    raise
                delay = self._backoff(attempt, exc.headers)
                logger.warning("upstream_retry(complete): kind=%s attempt=%d/%d in %.2fs",
                               exc.kind, attempt + 1, attempts, delay)
                time.sleep(delay)
            except Exception as exc:  # noqa: BLE001 — 统一转分类错误,不泄露栈
                mapped = self._classify_transport(exc)
                last = mapped
                if not mapped.retryable or attempt == attempts - 1:
                    raise mapped from None
                time.sleep(self._backoff(attempt))
        raise last or MiddlewareError("internal", "上游调用未产生结果")

    # ------------------------------------------------------------------ #
    # 流式
    # ------------------------------------------------------------------ #
    def stream(self, req: ChatRequest) -> Iterator[StreamChunk]:
        """流式补全。首字节前失败按分类抛;中途断流以 done(finish_reason=None) 收尾。

        OpenAI 结束帧 `data: [DONE]` 到达时产出 done(finish_reason=上游值或 "stop")。
        """
        self.ensure_configured()
        payload = self._build_payload(req)
        attempts = self.config.max_retries + 1
        for attempt in range(attempts):
            emitted = False
            try:
                with self._client().stream("POST", self._url(), headers=self._headers(),
                                           json=payload) as response:
                    self._raise_for_status(response)
                    saw_done = False
                    finish_reason: str | None = None
                    for line in response.iter_lines():
                        for chunk in _parse_sse_line(line):
                            if chunk.kind == "done":
                                saw_done = True
                                finish_reason = chunk.finish_reason or finish_reason
                            else:
                                emitted = True
                                yield chunk
                    if saw_done:
                        yield StreamChunk("done", finish_reason=finish_reason or "stop")
                    else:
                        # 断流:不重试(可能已产生文案,重试会重复计费/重复 token)
                        yield StreamChunk("done", finish_reason=None)
                    return
            except MiddlewareError as exc:
                if emitted or not exc.retryable or attempt == attempts - 1:
                    raise
                delay = self._backoff(attempt, exc.headers)
                logger.warning("upstream_retry(stream): kind=%s attempt=%d/%d in %.2fs",
                               exc.kind, attempt + 1, attempts, delay)
                time.sleep(delay)
            except Exception as exc:  # noqa: BLE001
                mapped = self._classify_transport(exc)
                if emitted or not mapped.retryable or attempt == attempts - 1:
                    raise mapped from None
                time.sleep(self._backoff(attempt))
        return


# --------------------------------------------------------------------------- #
# 解析
# --------------------------------------------------------------------------- #
_FINISH_MAP = {
    "stop": "stop", "length": "length", "tool_calls": "tool_calls",
    "function_call": "tool_calls", "content_filter": "content_filter",
}


def _parse_completion(body: dict, fallback_model: str) -> Completion:
    choices = body.get("choices") or []
    if not choices:
        raise MiddlewareError("protocol", "上游响应缺少 choices 字段")
    choice = choices[0]
    message = choice.get("message") or {}
    content = message.get("content")
    if isinstance(content, list):
        # 少数网关返回分块文本数组;拼成纯文本,不猜结构化语义
        content = "".join(part.get("text", "") for part in content
                          if isinstance(part, dict))
    calls: list[ToolCall] = []
    for call in message.get("tool_calls") or []:
        if not isinstance(call, dict):
            continue
        fn = call.get("function") or {}
        calls.append(ToolCall(
            id=str(call.get("id") or f"call_{len(calls)}"),
            name=str(fn.get("name") or ""),
            arguments=str(fn.get("arguments") or "{}"),
        ))
    raw_finish = choice.get("finish_reason")
    return Completion(
        text=content if isinstance(content, str) else "",
        reasoning=str(message.get("reasoning_content") or ""),
        tool_calls=calls,
        finish_reason=_FINISH_MAP.get(str(raw_finish), raw_finish),
        model=str(body.get("model") or fallback_model),
        usage=body.get("usage") or {},
        raw=body,
    )


def _parse_sse_line(line: str) -> list[StreamChunk]:
    """一行 SSE → 中立增量列表(非 data 行/坏帧静默跳过,绝不因解析失败中断流)。"""
    if not line.startswith("data:"):
        return []
    payload = line[5:]
    if payload.startswith(" "):
        payload = payload[1:]
    if payload.strip() == "[DONE]":
        return [StreamChunk("done")]
    try:
        chunk = json.loads(payload)
    except ValueError:
        return []
    if not isinstance(chunk, dict):
        return []
    out: list[StreamChunk] = []
    if chunk.get("usage"):
        out.append(StreamChunk("usage", usage=chunk["usage"]))
    for choice in chunk.get("choices") or []:
        if not isinstance(choice, dict):
            continue
        delta = choice.get("delta") or {}
        if isinstance(delta.get("reasoning_content"), str) and delta["reasoning_content"]:
            out.append(StreamChunk("reasoning", text=delta["reasoning_content"]))
        content = delta.get("content")
        if isinstance(content, str) and content:
            out.append(StreamChunk("text", text=content))
        elif isinstance(content, list):
            merged = "".join(p.get("text", "") for p in content if isinstance(p, dict))
            if merged:
                out.append(StreamChunk("text", text=merged))
        for call in delta.get("tool_calls") or []:
            if not isinstance(call, dict):
                continue
            fn = call.get("function") or {}
            out.append(StreamChunk(
                "tool_call",
                tool_index=int(call.get("index") or 0),
                tool_id=str(call.get("id") or ""),
                tool_name=str(fn.get("name") or ""),
                tool_arguments=str(fn.get("arguments") or ""),
            ))
        if choice.get("finish_reason"):
            out.append(StreamChunk("done",
                                   finish_reason=_FINISH_MAP.get(
                                       str(choice["finish_reason"]),
                                       str(choice["finish_reason"]))))
    return out


def _error_detail(response: httpx.Response) -> str:
    """从上游错误体提取可读摘要(截断);调用方 MiddlewareError 会再 _scrub 一次。

    必须先 read():流式请求里响应体尚未读取,直接 json()/text 会抛 ResponseNotRead,
    结果把「上游限流/5xx」误报成内部错误,还会让本该重试的错误变成不可重试。
    """
    try:
        response.read()
    except Exception:  # noqa: BLE001 — 读不到就算了,退化为「上游返回 HTTP xxx」
        return ""
    try:
        payload = response.json()
    except ValueError:
        return (response.text or "").strip()[:200]
    if isinstance(payload, dict):
        error = payload.get("error")
        if isinstance(error, dict):
            return str(error.get("message") or error.get("type") or "")[:200]
        if error:
            return str(error)[:200]
        return str(payload.get("message") or "")[:200]
    return ""
