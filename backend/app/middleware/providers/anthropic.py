"""
Anthropic 原生提供商 —— `POST {base_url}/messages`

安全目标:
  - 密钥只进 `x-api-key` 头,绝不进 URL/日志/异常/响应;
  - 有限重试(max_retries ∈ 0..5),仅对连接/超时/429/5xx 且「未产出任何增量」时重试;
  - 协议差异全部收敛在本文件 + anthropic_proto.py,上层只见中立形态。

明确不承诺:
  - 不承诺 Anthropic 私有分块(cache_control / thinking)语义等价(见 anthropic_proto);
  - Anthropic 要求 max_tokens 必填,缺省时使用 DEFAULT_MAX_TOKENS。
"""
from __future__ import annotations

import json
import logging
import threading
import time
from collections.abc import Iterator

import httpx

from ..errors import MiddlewareError, classify_upstream_status
from .base import ChatRequest, Completion, ModelProvider, ProviderConfig, StreamChunk

logger = logging.getLogger(__name__)

_MAX_BACKOFF_S = 4.0
_MAX_RETRY_AFTER_S = 5.0


class AnthropicProvider(ModelProvider):
    """Anthropic Messages API 提供商(原生协议)。"""

    TYPE = "anthropic"

    def __init__(self, config: ProviderConfig, *, transport: httpx.BaseTransport | None = None):
        super().__init__(config)
        self._transport = transport
        version = config.extra_headers.get("anthropic-version") or "2023-06-01"
        self._version = version
        #: 复用的 HTTP 客户端(延迟创建;httpx.Client 本身线程安全)
        self._http: httpx.Client | None = None
        self._http_lock = threading.Lock()

    # ------------------------------------------------------------------ #
    def _client(self) -> httpx.Client:
        """取复用的 HTTP 客户端(理由同 openai_compat:避免每请求重建连接池)。"""
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
            except Exception as exc:  # noqa: BLE001
                logger.warning("关闭上游连接池失败: %s", type(exc).__name__)

    def _url(self) -> str:
        return self.config.base_url.rstrip("/") + "/messages"

    def _headers(self) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "anthropic-version": self._version,
        }
        key = self.config.resolved_api_key
        if key:
            headers["x-api-key"] = key
        for key, value in self.config.extra_headers.items():
            if key.lower() == "anthropic-version":
                continue
            headers[key] = value
        return headers

    def _timeout(self) -> httpx.Timeout:
        return httpx.Timeout(
            connect=self.config.timeout_connect,
            read=self.config.timeout_read,
            write=self.config.timeout_read,
            pool=self.config.timeout_connect,
        )

    def _payload(self, req: ChatRequest) -> dict:
        from ..anthropic_proto import to_anthropic_request
        body = to_anthropic_request(req)
        if req.stream:
            body["stream"] = True
        return body

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
        raise MiddlewareError(classify_upstream_status(response.status_code),
                              _error_detail(response)
                              or f"上游返回 HTTP {response.status_code}",
                              upstream_status=response.status_code,
                              headers=dict(response.headers))

    @staticmethod
    def _backoff(attempt: int, headers: dict | None = None) -> float:
        delay = min(_MAX_BACKOFF_S, 0.4 * (2 ** attempt))
        retry_after = (headers or {}).get("retry-after")
        if retry_after:
            try:
                delay = max(delay, min(_MAX_RETRY_AFTER_S, float(retry_after)))
            except (TypeError, ValueError):
                pass
        return delay

    # ------------------------------------------------------------------ #
    def complete(self, req: ChatRequest) -> Completion:
        from ..anthropic_proto import completion_from_anthropic
        self.ensure_configured()
        payload = self._payload(req)
        attempts = self.config.max_retries + 1
        for attempt in range(attempts):
            try:
                response = self._client().post(self._url(), headers=self._headers(),
                                               json=payload)
                self._raise_for_status(response)
                try:
                    body = response.json()
                except ValueError:
                    raise MiddlewareError("protocol", "上游返回非 JSON 响应") from None
                return completion_from_anthropic(body, req.model)
            except MiddlewareError as exc:
                if not exc.retryable or attempt == attempts - 1:
                    raise
                delay = self._backoff(attempt, exc.headers)
                logger.warning("upstream_retry(anthropic): kind=%s attempt=%d/%d in %.2fs",
                               exc.kind, attempt + 1, attempts, delay)
                time.sleep(delay)
            except Exception as exc:  # noqa: BLE001
                mapped = self._classify_transport(exc)
                if not mapped.retryable or attempt == attempts - 1:
                    raise mapped from None
                time.sleep(self._backoff(attempt))
        raise MiddlewareError("internal", "上游调用未产生结果")

    def stream(self, req: ChatRequest) -> Iterator[StreamChunk]:
        self.ensure_configured()
        payload = self._payload(req)
        attempts = self.config.max_retries + 1
        for attempt in range(attempts):
            emitted = False
            try:
                with self._client().stream("POST", self._url(), headers=self._headers(),
                                           json=payload) as response:
                    self._raise_for_status(response)
                    saw_stop = False
                    finish_reason: str | None = None
                    for line in response.iter_lines():
                        for chunk in _parse_anthropic_sse_line(line):
                            if chunk.kind == "done":
                                saw_stop = True
                                finish_reason = chunk.finish_reason or finish_reason
                            else:
                                emitted = True
                                yield chunk
                    yield StreamChunk("done",
                                      finish_reason=finish_reason if saw_stop else None)
                    return
            except MiddlewareError as exc:
                if emitted or not exc.retryable or attempt == attempts - 1:
                    raise
                time.sleep(self._backoff(attempt, exc.headers))
            except Exception as exc:  # noqa: BLE001
                mapped = self._classify_transport(exc)
                if emitted or not mapped.retryable or attempt == attempts - 1:
                    raise mapped from None
                time.sleep(self._backoff(attempt))
        return


def _parse_anthropic_sse_line(line: str) -> list[StreamChunk]:
    """Anthropic SSE 一行 → 中立增量(忽略 event: 行,以 data 内 type 为准)。"""
    if not line.startswith("data:"):
        return []
    payload = line[5:]
    if payload.startswith(" "):
        payload = payload[1:]
    try:
        event = json.loads(payload)
    except ValueError:
        return []
    if not isinstance(event, dict):
        return []
    etype = event.get("type")
    out: list[StreamChunk] = []
    if etype == "message_start":
        usage = ((event.get("message") or {}).get("usage")) or {}
        if usage:
            out.append(StreamChunk("usage", usage={
                "prompt_tokens": int(usage.get("input_tokens") or 0),
                "completion_tokens": int(usage.get("output_tokens") or 0),
            }))
    elif etype == "content_block_start":
        block = event.get("content_block") or {}
        if block.get("type") == "tool_use":
            out.append(StreamChunk("tool_call", tool_index=int(event.get("index") or 0),
                                   tool_id=str(block.get("id") or ""),
                                   tool_name=str(block.get("name") or "")))
        elif block.get("type") == "text" and block.get("text"):
            out.append(StreamChunk("text", text=str(block["text"])))
    elif etype == "content_block_delta":
        delta = event.get("delta") or {}
        if delta.get("type") == "text_delta" and delta.get("text"):
            out.append(StreamChunk("text", text=str(delta["text"])))
        elif delta.get("type") == "input_json_delta" and delta.get("partial_json"):
            out.append(StreamChunk("tool_call", tool_index=int(event.get("index") or 0),
                                   tool_arguments=str(delta["partial_json"])))
    elif etype == "message_delta":
        stop = (event.get("delta") or {}).get("stop_reason")
        usage = event.get("usage") or {}
        if usage.get("output_tokens") is not None:
            out.append(StreamChunk("usage", usage={
                "completion_tokens": int(usage.get("output_tokens") or 0)}))
        from ..anthropic_proto import _STOP_REASON_TO_OPENAI
        out.append(StreamChunk("done",
                               finish_reason=_STOP_REASON_TO_OPENAI.get(str(stop), "stop")))
    elif etype == "message_stop":
        out.append(StreamChunk("done", finish_reason=None))
    elif etype == "error":
        error = event.get("error") or {}
        raise MiddlewareError("upstream_4xx", str(error.get("message") or "上游错误"))
    return out


def _error_detail(response: httpx.Response) -> str:
    """同 openai_compat:流式响应必须先 read(),否则 ResponseNotRead 会遮蔽真实错误类别。"""
    try:
        response.read()
    except Exception:  # noqa: BLE001
        return ""
    try:
        payload = response.json()
    except ValueError:
        return (response.text or "").strip()[:200]
    if isinstance(payload, dict):
        error = payload.get("error")
        if isinstance(error, dict):
            return str(error.get("message") or error.get("type") or "")[:200]
        if isinstance(error, str):
            return error[:200]
    return ""
