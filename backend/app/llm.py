"""
LLM 网关 —— 失败三分类 + 流式双轨透传 + Mock 降级

安全目标：
  - 失败行为可预测(spec §3.2/§5)：network(超时/连接失败/5xx)降级 Mock 并显式标记
    degraded="mock"；protocol(4xx 含 429)直接抛出、绝不降级；stream(断流)保留已收
    内容并置 incomplete=True、绝不降级；未分类异常按 internal 处理、绝不降级(fail-closed)。
  - reasoning_content 不进多轮回传历史：模型内部思维链不成为后续 prompt 的侧信道。
    本模块仅透传/汇总 reasoning，绝不改写或追加 messages。
  - 双轨不串：reasoning_content 与 content 独立分发(on_token 第二参数区分)，
    互不混入对方轨道。

明确不承诺：
  - 不承诺 LLM 服务可用性、响应质量与时延(外部依赖)。
  - 不承诺超长 reasoning 的完整性：ReplyStream.reasoning_content 超过
    max_reasoning_chars 的部分被截断(on_token 流式回调仍完整透传)。
  - 不承诺 SSE 多行 data 帧拼接：按行独立解析 JSON 帧，无法解析的帧静默跳过。
  - Mock 降级仅在网络类故障时启用，模拟回复不代表真实模型输出。
"""
from __future__ import annotations

import json
import logging
from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace

import httpx

from .mock_llm import MockLLM

logger = logging.getLogger(__name__)

#: 流式回调(delta 文本, 是否为 reasoning 轨)
OnToken = Callable[[str, bool], None]

_FAILURE_KINDS = ("network", "protocol", "stream")


class LLMFailure(Exception):
    """LLM 调用失败。kind ∈ {"network","protocol","stream"}，对应 spec §5 三分类。"""

    def __init__(self, kind: str, detail: str = ""):
        if kind not in _FAILURE_KINDS:
            raise ValueError(f"非法失败类别: {kind!r}，仅允许 {_FAILURE_KINDS}")
        self.kind = kind
        super().__init__(detail or kind)


def classify_failure(exc: BaseException) -> str:
    """异常 → 失败类别(network/protocol/stream/internal)。

    映射(spec §3.2 三分类表)：
      - LLMFailure        → 透传自身 .kind
      - httpx 超时/连接/远端协议错误 → network
      - HTTPStatusError   → 5xx network；4xx protocol
      - 其余              → internal(不触发 mock 降级)
    """
    if isinstance(exc, LLMFailure):
        return exc.kind
    if isinstance(exc, httpx.HTTPStatusError):
        if exc.response.status_code >= 500:
            return "network"
        if 400 <= exc.response.status_code < 500:
            return "protocol"
        return "internal"
    if isinstance(exc, (httpx.TimeoutException, httpx.NetworkError, httpx.RemoteProtocolError)):
        return "network"
    return "internal"


@dataclass
class ReplyStream:
    """一次流式回复的最终汇总(含完整性/降级元信息)。

    字段语义：
      - output:            content 轨全文
      - reasoning_content: reasoning 轨全文(超 max_reasoning_chars 截断)，仅本地留存，
                           不得进入多轮回传 prompt
      - incomplete:        True 表示断流/未见终止帧，已收内容保留
      - degraded:          None 或 "mock"(MockChat 降级标记)
      - model:             实际应答模型名
    """

    output: str
    reasoning_content: str
    incomplete: bool
    degraded: str | None
    model: str


class MockChat:
    """Mock 聊天后端：末条 user 消息经 MockLLM 模板生成，分块回调模拟流式。

    明确不承诺：无 reasoning 轨(恒为空串)；不改写、不注入 messages。
    """

    def __init__(self, model: str = "CryptoGuard-Mock-LLM-v1", chunk_size: int = 4):
        self.model = model
        self.chunk_size = chunk_size

    def chat(self, messages: Sequence[dict], on_token: OnToken | None = None) -> ReplyStream:
        """取末条 role=="user" 的 content 生成模板回复，按 chunk_size 分块回调。"""
        redacted_input = ""
        for message in messages:
            if message.get("role") == "user":
                redacted_input = message.get("content") or ""
        output = MockLLM._generate(redacted_input)
        if on_token is not None:
            for start in range(0, len(output), self.chunk_size):
                on_token(output[start:start + self.chunk_size], False)
        return ReplyStream(
            output=output,
            reasoning_content="",
            incomplete=False,
            degraded=None,
            model=self.model,
        )


class MimoLLM:
    """MiMo 流式客户端(OpenAI 兼容 SSE)，reasoning_content/content 分轨透传。

    故障映射：4xx(含 429)→ LLMFailure("protocol")；5xx/连接错误 → LLMFailure("network")；
    读流中途断(任意读取异常或未见 `data: [DONE]` 终止帧)→ 保留已收内容 + incomplete=True，
    不抛异常、不降级(降级决策在 LLMGateway)。
    """

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://api.xiaomimimo.com/v1",
        model: str = "mimo-v2.6-flash",
        timeout: float = 60.0,
        max_reasoning_chars: int = 20000,
        *,
        max_completion_tokens: int = 1024,
        temperature: float = 1.0,
        top_p: float = 0.95,
        transport: httpx.BaseTransport | None = None,
    ):
        self.api_key = api_key
        self.model = model
        self.timeout = timeout
        self.max_reasoning_chars = max_reasoning_chars
        self.max_completion_tokens = max_completion_tokens
        self.temperature = temperature
        self.top_p = top_p
        self._url = base_url.rstrip("/") + "/chat/completions"
        self._transport = transport

    def chat(self, messages: Sequence[dict], on_token: OnToken | None = None) -> ReplyStream:
        """流式 POST 一次对话，返回双轨汇总 ReplyStream。

        messages 原样出站(reasoning 由调用方在持久化/回传层处理，本方法不注入)。
        """
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "api-key": self.api_key,
        }
        body = {
            "model": self.model,
            "messages": list(messages),
            "stream": True,
            "max_completion_tokens": self.max_completion_tokens,
            "temperature": self.temperature,
            "top_p": self.top_p,
        }
        output_parts: list[str] = []
        reasoning_parts: list[str] = []
        reasoning_len = 0
        incomplete = False
        saw_done = False

        try:
            with httpx.Client(timeout=self.timeout, transport=self._transport) as client:
                with client.stream("POST", self._url, headers=headers, json=body) as response:
                    status = response.status_code
                    if not 200 <= status < 300:
                        # 3xx/其余非 2xx 亦按 protocol 处理:直接报错不降级(fail-closed)
                        kind = "network" if status >= 500 else "protocol"
                        raise LLMFailure(kind, f"HTTP {status} {response.reason_phrase}")
                    try:
                        for line in response.iter_lines():
                            payload = _sse_payload(line)
                            if payload is None:
                                continue
                            if payload.strip() == "[DONE]":
                                saw_done = True
                                break
                            reasoning_delta, content_delta = _parse_frame(payload)
                            if reasoning_delta:
                                if reasoning_len < self.max_reasoning_chars:
                                    take = self.max_reasoning_chars - reasoning_len
                                    reasoning_parts.append(reasoning_delta[:take])
                                    reasoning_len += min(len(reasoning_delta), take)
                                if on_token is not None:
                                    on_token(reasoning_delta, True)
                            if content_delta:
                                output_parts.append(content_delta)
                                if on_token is not None:
                                    on_token(content_delta, False)
                    except LLMFailure:
                        raise
                    except Exception as exc:
                        # 读流中途断:保留已收内容,incomplete=True,不抛出、不降级
                        logger.warning("stream_interrupt: %s", exc)
                        incomplete = True
        except LLMFailure:
            raise
        except (httpx.TimeoutException, httpx.NetworkError, httpx.RemoteProtocolError) as exc:
            raise LLMFailure("network", f"{type(exc).__name__}: {exc}") from exc

        if not saw_done:
            incomplete = True

        return ReplyStream(
            output="".join(output_parts),
            reasoning_content="".join(reasoning_parts),
            incomplete=incomplete,
            degraded=None,
            model=self.model,
        )


class LLMGateway:
    """LLM 网关：MimoLLM 优先；network 类故障降级 MockChat 且 degraded="mock"。

    protocol/stream/未分类异常一律原样上抛、绝不降级；MimoLLM 断流不抛异常
    (incomplete=True 的 ReplyStream) 原样透传。降级触发条件为 classify_failure(exc)=="network"
    (即 timeout/连接失败/5xx，含 LLMFailure("network") 与等价原始异常)。
    """

    def __init__(self, mimo: MimoLLM | None, mock: MockChat):
        self.mimo = mimo
        self.mock = mock

    def chat(self, messages: Sequence[dict], on_token: OnToken | None = None) -> ReplyStream:
        if self.mimo is None:
            return self._degraded_mock(messages, on_token)
        try:
            return self.mimo.chat(messages, on_token)
        except Exception as exc:
            if classify_failure(exc) != "network":
                raise
            logger.warning("network_degrade: %s", exc)
            return self._degraded_mock(messages, on_token)

    def _degraded_mock(self, messages: Sequence[dict], on_token: OnToken | None) -> ReplyStream:
        result = self.mock.chat(messages, on_token)
        return replace(result, degraded="mock")


def _sse_payload(line: str) -> str | None:
    """提取 SSE `data:` 帧负载；非 data 行(空行/注释/event 等)返回 None。"""
    if not line.startswith("data:"):
        return None
    payload = line[5:]
    if payload.startswith(" "):
        payload = payload[1:]
    return payload


def _parse_frame(payload: str) -> tuple[str, str]:
    """解析单帧 JSON，返回 (reasoning_content, content) 双轨增量。

    无法解析或结构不符的帧静默跳过(返回空串对)；双轨独立取值绝不互串。
    """
    try:
        chunk = json.loads(payload)
        choices = chunk.get("choices") or []
        delta = choices[0].get("delta") or {}
        reasoning = delta.get("reasoning_content")
        content = delta.get("content")
    except (ValueError, AttributeError, TypeError, IndexError, KeyError):
        return "", ""
    return (
        reasoning if isinstance(reasoning, str) else "",
        content if isinstance(content, str) else "",
    )
