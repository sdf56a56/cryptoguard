"""llm.py 契约层(T5):LLMFailure / classify_failure / ReplyStream / MockChat。

对应验收:
  ① 分类用例:TimeoutException→network、HTTPStatusError(400)→protocol、RuntimeError→internal
  ② MockChat 回调按块触发且拼接等于 output
  ③ ReplyStream 字段齐全
  ⑧ MockChat 不向 messages 注入 reasoning
"""
import copy
import json

import httpx
import pytest

from app.llm import LLMFailure, MockChat, ReplyStream, classify_failure
from app.mock_llm import MockLLM

URL = "https://api.xiaomimimo.com/v1/chat/completions"


def _status_error(status: int) -> httpx.HTTPStatusError:
    request = httpx.Request("POST", URL)
    response = httpx.Response(status, request=request)
    return httpx.HTTPStatusError(f"HTTP {status}", request=request, response=response)


# ---------- LLMFailure ----------

def test_llm_failure_kinds_valid():
    for kind in ("network", "protocol", "stream"):
        exc = LLMFailure(kind, "detail")
        assert exc.kind == kind
        assert isinstance(exc, Exception)


def test_llm_failure_rejects_unknown_kind():
    with pytest.raises(ValueError):
        LLMFailure("internal")


# ---------- classify_failure(验收①) ----------

def test_classify_timeout_exception_is_network():
    assert classify_failure(httpx.TimeoutException("timeout")) == "network"


def test_classify_http_status_error_400_is_protocol():
    assert classify_failure(_status_error(400)) == "protocol"


def test_classify_runtime_error_is_internal():
    assert classify_failure(RuntimeError("boom")) == "internal"


def test_classify_http_status_error_500_is_network():
    assert classify_failure(_status_error(500)) == "network"


def test_classify_connect_error_is_network():
    assert classify_failure(httpx.ConnectError("refused")) == "network"


def test_classify_remote_protocol_error_is_network():
    assert classify_failure(httpx.RemoteProtocolError("peer closed")) == "network"


def test_classify_llm_failure_passes_kind_through():
    assert classify_failure(LLMFailure("network")) == "network"
    assert classify_failure(LLMFailure("protocol", "400")) == "protocol"
    assert classify_failure(LLMFailure("stream", "cut")) == "stream"


# ---------- ReplyStream(验收③) ----------

def test_reply_stream_fields_complete():
    r = ReplyStream(
        output="out",
        reasoning_content="why",
        incomplete=False,
        degraded=None,
        model="m",
    )
    assert r.output == "out"
    assert r.reasoning_content == "why"
    assert r.incomplete is False
    assert r.degraded is None
    assert r.model == "m"


# ---------- MockChat(验收②⑧) ----------

def test_mock_chat_chunked_callbacks_concatenate_to_output():
    tokens: list[tuple[str, bool]] = []
    result = MockChat().chat(
        [{"role": "user", "content": "请处理[NAME#a1]与[AMT#b2]"}],
        on_token=lambda delta, reasoning: tokens.append((delta, reasoning)),
    )
    assert len(tokens) > 1                       # 确实按块触发
    assert "".join(d for d, _ in tokens) == result.output
    assert all(reasoning is False for _, reasoning in tokens)


def test_mock_chat_reply_stream_fields():
    result = MockChat().chat([{"role": "user", "content": "你好[NAME#a1]"}])
    assert result.output == MockLLM._generate("你好[NAME#a1]")
    assert result.reasoning_content == ""        # Mock 无 reasoning 轨
    assert result.incomplete is False
    assert result.degraded is None
    assert result.model == "CryptoGuard-Mock-LLM-v1"


def test_mock_chat_uses_last_user_message():
    result = MockChat().chat([
        {"role": "system", "content": "系统提示"},
        {"role": "user", "content": "第一问"},
        {"role": "assistant", "content": "答复"},
        {"role": "user", "content": "第二问[AMT#b2]"},
    ])
    assert result.output == MockLLM._generate("第二问[AMT#b2]")


def test_mock_chat_without_user_message_uses_empty_input():
    result = MockChat().chat([{"role": "system", "content": "系统提示"}])
    assert result.output == MockLLM._generate("")


def test_mock_chat_does_not_inject_reasoning_into_messages():
    messages = [
        {"role": "user", "content": "你好[NAME#a1]"},
        {"role": "assistant", "content": "答复"},
        {"role": "user", "content": "追问"},
    ]
    before = copy.deepcopy(messages)
    MockChat().chat(messages)
    assert messages == before                                  # 不改写入参
    assert "reasoning_content" not in json.dumps(messages)     # 不注入 reasoning
