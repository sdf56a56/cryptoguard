"""llm.py MimoLLM(T6):httpx.MockTransport 流式解析 / 双轨分发 / 断流 / 故障映射。

对应验收:
  ④ MockTransport 流式解析正确、reasoning/content 分轨不串
  ⑤ 断流→incomplete=True 且部分 output 保留
  ⑥ 400→LLMFailure("protocol")(MimoLLM 侧)
  ⑧ MimoLLM 不向 messages 注入 reasoning
"""
import json

import httpx
import pytest

from app.llm import LLMFailure, MimoLLM

MESSAGES = [{"role": "user", "content": "你好"}]


def chunk(content: str | None = None, reasoning: str | None = None) -> dict:
    delta: dict = {}
    if content is not None:
        delta["content"] = content
    if reasoning is not None:
        delta["reasoning_content"] = reasoning
    return {"choices": [{"delta": delta}]}


def frame(obj: dict | str) -> bytes:
    payload = obj if isinstance(obj, str) else json.dumps(obj, ensure_ascii=False)
    return f"data: {payload}\n\n".encode("utf-8")


def sse_body(frames: list[dict | str]) -> bytes:
    return b"".join(frame(f) for f in frames)


def mimo_with(handler, **kwargs) -> MimoLLM:
    return MimoLLM("key-123", transport=httpx.MockTransport(handler), **kwargs)


# ---------- 流式解析与双轨分发(验收④) ----------

def test_mimo_stream_parses_and_keeps_tracks_separate():
    frames = [
        chunk(reasoning="思"),
        chunk(reasoning="考中"),
        chunk(content="Hel"),
        chunk(content="lo"),
        "[DONE]",
    ]
    captured: list[tuple[str, bool]] = []
    mimo = mimo_with(lambda req: httpx.Response(200, content=sse_body(frames)))
    result = mimo.chat(MESSAGES, on_token=lambda d, r: captured.append((d, r)))

    assert result.output == "Hello"
    assert result.reasoning_content == "思考中"
    assert captured == [("思", True), ("考中", True), ("Hel", False), ("lo", False)]


def test_mimo_interleaved_chunks_do_not_cross_tracks():
    frames = [
        chunk(reasoning="R1"),
        chunk(content="C1"),
        chunk(reasoning="R2"),
        chunk(content="C2"),
        "[DONE]",
    ]
    captured: list[tuple[str, bool]] = []
    mimo = mimo_with(lambda req: httpx.Response(200, content=sse_body(frames)))
    result = mimo.chat(MESSAGES, on_token=lambda d, r: captured.append((d, r)))

    assert captured == [("R1", True), ("C1", False), ("R2", True), ("C2", False)]
    assert result.output == "C1C2"
    assert result.reasoning_content == "R1R2"


def test_mimo_single_frame_with_both_tracks_dispatches_independently():
    captured: list[tuple[str, bool]] = []
    mimo = mimo_with(lambda req: httpx.Response(200, content=sse_body([chunk(content="A", reasoning="R"), "[DONE]"])))
    result = mimo.chat(MESSAGES, on_token=lambda d, r: captured.append((d, r)))

    assert captured == [("R", True), ("A", False)]   # 分轨回调,绝不混轨
    assert result.output == "A"
    assert result.reasoning_content == "R"


def test_mimo_reply_stream_meta_fields():
    mimo = mimo_with(lambda req: httpx.Response(200, content=sse_body([chunk(content="x"), "[DONE]"])))
    result = mimo.chat(MESSAGES)
    assert result.model == "mimo-v2.6-flash"
    assert result.degraded is None
    assert result.incomplete is False


def test_mimo_reasoning_truncated_to_max_reasoning_chars():
    mimo = mimo_with(
        lambda req: httpx.Response(200, content=sse_body([chunk(reasoning="abcdef"), chunk(content="ok"), "[DONE]"])),
        max_reasoning_chars=4,
    )
    result = mimo.chat(MESSAGES)
    assert result.reasoning_content == "abcd"    # 截断
    assert result.output == "ok"                 # content 轨不受影响


# ---------- 断流(验收⑤) ----------

def test_mimo_mid_stream_break_keeps_partial_output():
    def handler(request):
        def body():
            yield frame(chunk(content="Hel"))
            yield frame(chunk(reasoning="思"))
            raise httpx.ReadError("connection broken")
        return httpx.Response(200, content=body())

    captured: list[tuple[str, bool]] = []
    mimo = mimo_with(handler)
    result = mimo.chat(MESSAGES, on_token=lambda d, r: captured.append((d, r)))

    assert result.incomplete is True
    assert result.output == "Hel"                 # 部分 output 保留
    assert result.reasoning_content == "思"
    assert result.degraded is None                # 断流不降级
    assert captured == [("Hel", False), ("思", True)]


def test_mimo_skips_malformed_frames_without_breaking_stream():
    """无法解析/结构不符的帧静默跳过，不得中断后续帧的解析。"""
    body = (
        frame(chunk(content="A"))
        + frame("not-json")
        + frame([1, 2, 3])
        + frame({"choices": []})
        + frame({"choices": [{"delta": {}}]})
        + frame(chunk(content="B"))
        + frame("[DONE]")
    )
    mimo = mimo_with(lambda req: httpx.Response(200, content=body))
    result = mimo.chat(MESSAGES)
    assert result.output == "AB"
    assert result.incomplete is False


def test_mimo_missing_done_marker_marks_incomplete():
    """未见 `data: [DONE]` 终止帧亦视为断流(不把截断回复当完整回复)。"""
    mimo = mimo_with(lambda req: httpx.Response(200, content=sse_body([chunk(content="x")])))
    result = mimo.chat(MESSAGES)
    assert result.incomplete is True
    assert result.output == "x"


# ---------- 故障映射 ----------

def test_mimo_400_raises_llm_failure_protocol():
    mimo = mimo_with(lambda req: httpx.Response(400, text="bad request"))
    with pytest.raises(LLMFailure) as e:
        mimo.chat(MESSAGES)
    assert e.value.kind == "protocol"


def test_mimo_429_raises_llm_failure_protocol():
    mimo = mimo_with(lambda req: httpx.Response(429, text="rate limited"))
    with pytest.raises(LLMFailure) as e:
        mimo.chat(MESSAGES)
    assert e.value.kind == "protocol"


def test_mimo_500_raises_llm_failure_network():
    mimo = mimo_with(lambda req: httpx.Response(500, text="oops"))
    with pytest.raises(LLMFailure) as e:
        mimo.chat(MESSAGES)
    assert e.value.kind == "network"


def test_mimo_connect_error_wrapped_as_network():
    def handler(request):
        raise httpx.ConnectError("connection refused")
    mimo = mimo_with(handler)
    with pytest.raises(LLMFailure) as e:
        mimo.chat(MESSAGES)
    assert e.value.kind == "network"


# ---------- 请求构造(双头认证 + 体参数) ----------

def test_mimo_request_double_auth_headers_and_body_fields():
    seen: dict = {}

    def handler(request):
        seen["headers"] = request.headers
        seen["body"] = json.loads(request.content)
        seen["path"] = request.url.path
        return httpx.Response(200, content=sse_body([chunk(content="x"), "[DONE]"]))

    mimo = mimo_with(handler)
    mimo.chat(MESSAGES)

    assert seen["headers"]["Authorization"] == "Bearer key-123"
    assert seen["headers"]["api-key"] == "key-123"          # 双头并存
    assert seen["path"] == "/v1/chat/completions"
    body = seen["body"]
    assert body["model"] == "mimo-v2.6-flash"
    assert body["stream"] is True
    assert body["max_completion_tokens"] == 1024
    assert body["temperature"] == 1.0
    assert body["top_p"] == 0.95
    assert body["messages"] == MESSAGES


def test_mimo_body_fields_constructor_configurable():
    seen: dict = {}

    def handler(request):
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, content=sse_body(["[DONE]"]))

    mimo = MimoLLM(
        "key-123",
        model="mimo-custom",
        max_completion_tokens=512,
        temperature=0.2,
        top_p=0.5,
        transport=httpx.MockTransport(handler),
    )
    mimo.chat(MESSAGES)
    assert seen["body"]["model"] == "mimo-custom"
    assert seen["body"]["max_completion_tokens"] == 512
    assert seen["body"]["temperature"] == 0.2
    assert seen["body"]["top_p"] == 0.5


# ---------- 历史 messages 不含 reasoning(验收⑧) ----------

def test_mimo_does_not_inject_reasoning_into_messages():
    seen: dict = {}
    frames = [chunk(reasoning="内心戏"), chunk(content="答复"), "[DONE]"]

    def handler(request):
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, content=sse_body(frames))

    history = [
        {"role": "system", "content": "系统提示"},
        {"role": "user", "content": "你好"},
    ]
    before = json.dumps(history, ensure_ascii=False)
    mimo = mimo_with(handler)
    result = mimo.chat(history)

    # 出站 messages 与输入一致,reasoning 不进历史
    assert seen["body"]["messages"] == history
    assert json.dumps(seen["body"]["messages"], ensure_ascii=False) == before
    assert "reasoning_content" not in json.dumps(seen["body"])
    # 双轨各自完整(不互串、不丢),但 reasoning 只留在 ReplyStream 字段
    assert result.output == "答复"
    assert result.reasoning_content == "内心戏"
