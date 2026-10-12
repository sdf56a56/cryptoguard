"""llm.py LLMGateway(T6):network 降级 Mock / protocol、stream、internal 不降级。

对应验收:
  ⑥ 400→LLMFailure("protocol") 且 Gateway 不降级
  ⑦ 500→Gateway 切 mock 且 degraded=="mock"
  另:断流结果(incomplete=True)原样透传不降级;未知异常不降级。
"""
import json

import httpx
import pytest

from app.llm import LLMFailure, LLMGateway, MimoLLM, MockChat
from app.mock_llm import MockLLM

MESSAGES = [{"role": "user", "content": "你好[NAME#a1]"}]


class SpyMock(MockChat):
    """统计调用次数的 MockChat,验证降级是否真的发生。"""

    def __init__(self):
        super().__init__()
        self.calls = 0

    def chat(self, messages, on_token=None):
        self.calls += 1
        return super().chat(messages, on_token)


class StubMimo:
    """替身 MimoLLM:可抛指定异常或返回指定 ReplyStream。"""

    def __init__(self, exc: Exception | None = None, reply=None):
        self.exc = exc
        self.reply = reply
        self.calls = 0

    def chat(self, messages, on_token=None):
        self.calls += 1
        if self.exc is not None:
            raise self.exc
        return self.reply


def mimo_with(handler) -> MimoLLM:
    return MimoLLM("key-123", transport=httpx.MockTransport(handler))


# ---------- 无 Mimo / network 降级(验收⑦) ----------

def test_gateway_without_mimo_falls_back_to_mock():
    tokens: list[tuple[str, bool]] = []
    gw = LLMGateway(mimo=None, mock=MockChat())
    result = gw.chat(MESSAGES, on_token=lambda d, r: tokens.append((d, r)))

    assert result.degraded == "mock"
    assert result.model == "CryptoGuard-Mock-LLM-v1"
    assert result.incomplete is False
    assert "".join(d for d, _ in tokens) == result.output


def test_gateway_500_falls_back_to_mock_with_degraded_flag():
    mimo = mimo_with(lambda req: httpx.Response(500, text="oops"))
    mock = SpyMock()
    gw = LLMGateway(mimo=mimo, mock=mock)

    result = gw.chat(MESSAGES)

    assert result.degraded == "mock"                            # 验收⑦
    assert mock.calls == 1
    assert result.output == MockLLM._generate("你好[NAME#a1]")


def test_gateway_llm_failure_network_falls_back_to_mock():
    mock = SpyMock()
    gw = LLMGateway(mimo=StubMimo(exc=LLMFailure("network", "timeout")), mock=mock)
    result = gw.chat(MESSAGES)
    assert result.degraded == "mock"
    assert mock.calls == 1


def test_gateway_raw_network_exception_falls_back_to_mock():
    """classify_failure 为 network 的原始异常(如连接错误)同样降级(spec §5 network 行)。"""
    mock = SpyMock()
    gw = LLMGateway(mimo=StubMimo(exc=httpx.ConnectError("refused")), mock=mock)
    result = gw.chat(MESSAGES)
    assert result.degraded == "mock"
    assert mock.calls == 1


# ---------- protocol 不降级(验收⑥) ----------

def test_gateway_400_raises_protocol_without_fallback():
    mimo = mimo_with(lambda req: httpx.Response(400, text="bad request"))
    mock = SpyMock()
    gw = LLMGateway(mimo=mimo, mock=mock)

    with pytest.raises(LLMFailure) as e:
        gw.chat(MESSAGES)

    assert e.value.kind == "protocol"                           # 验收⑥
    assert mock.calls == 0                                      # 不降级


def test_gateway_llm_failure_protocol_propagates():
    mock = SpyMock()
    gw = LLMGateway(mimo=StubMimo(exc=LLMFailure("protocol", "429")), mock=mock)
    with pytest.raises(LLMFailure) as e:
        gw.chat(MESSAGES)
    assert e.value.kind == "protocol"
    assert mock.calls == 0


# ---------- stream / internal 不降级 ----------

def test_gateway_mid_stream_break_passes_partial_through_without_fallback():
    def handler(request):
        def body():
            yield b'data: {"choices":[{"delta":{"content":"Hel"}}]}\n\n'
            raise httpx.ReadError("connection broken")
        return httpx.Response(200, content=body())

    mimo = mimo_with(handler)
    mock = SpyMock()
    gw = LLMGateway(mimo=mimo, mock=mock)

    result = gw.chat(MESSAGES)

    assert result.incomplete is True                            # 断流结果原样透传
    assert result.output == "Hel"
    assert result.degraded is None                              # 不降级
    assert mock.calls == 0


def test_gateway_llm_failure_stream_propagates_without_fallback():
    mock = SpyMock()
    gw = LLMGateway(mimo=StubMimo(exc=LLMFailure("stream", "cut")), mock=mock)
    with pytest.raises(LLMFailure) as e:
        gw.chat(MESSAGES)
    assert e.value.kind == "stream"
    assert mock.calls == 0


def test_gateway_unknown_exception_propagates_without_fallback():
    """未知异常 → internal,绝不触发 mock 降级(fail-closed)。"""
    mock = SpyMock()
    gw = LLMGateway(mimo=StubMimo(exc=RuntimeError("boom")), mock=mock)
    with pytest.raises(RuntimeError):
        gw.chat(MESSAGES)
    assert mock.calls == 0


# ---------- 降级语义细节 ----------

def test_gateway_fallback_reply_carries_mock_output_not_reasoning():
    mimo = mimo_with(lambda req: httpx.Response(503, text="unavailable"))
    gw = LLMGateway(mimo=mimo, mock=MockChat())
    result = gw.chat(MESSAGES)

    assert result.reasoning_content == ""                       # Mock 无 reasoning
    assert result.degraded == "mock"
    assert "reasoning_content" not in json.dumps(MESSAGES)      # 不污染历史
