"""OpenAI Responses 入口（Codex 无状态子集）安全与协议形状测试。"""
from __future__ import annotations

PHONE = "13800138000"


def _auth(key: str) -> dict:
    return {"Authorization": f"Bearer {key}"}


def _body(**extra) -> dict:
    body = {"model": "mock-chat",
            "input": [{"type": "message", "role": "user",
                       "content": [{"type": "input_text",
                                    "text": f"手机号 {PHONE}"}]}]}
    body.update(extra)
    return body


def test_responses_non_stream_returns_output_and_protects_upstream(make_mw):
    state, client, key = make_mw(data_subdir="responses-basic")
    response = client.post("/v1/responses", headers=_auth(key), json=_body())
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["object"] == "response"
    assert payload["status"] == "completed"
    assert payload["output"][0]["type"] == "message"
    text = payload["output"][0]["content"][0]["text"]
    assert "受保护字段" in text
    assert payload["cryptoguard"]["detected"]["by_type"]["PHONE"] == 1

    upstream = state.registry.get("mock").seen[-1]
    sent = str(upstream.messages)
    assert PHONE not in sent
    assert "[PHONE_001]" in sent


def test_responses_stream_emits_expected_events(make_mw):
    _, client, key = make_mw(data_subdir="responses-stream")
    response = client.post("/v1/responses", headers=_auth(key),
                           json=_body(stream=True))
    assert response.status_code == 200, response.text
    for event in ("response.created", "response.in_progress",
                  "response.output_item.added", "response.content_part.added",
                  "response.output_text.delta", "response.output_text.done",
                  "response.content_part.done", "response.output_item.done",
                  "response.completed"):
        assert f"event: {event}" in response.text, event
    assert "sequence_number" in response.text


def test_responses_function_call_is_translated(make_mw):
    _, client, key = make_mw(data_subdir="responses-tool")
    body = {
        "model": "mock-chat",
        "input": "USE_TOOL 查一下时间",
        "tools": [{"type": "function", "name": "get_time",
                   "description": "time",
                   "parameters": {"type": "object", "properties": {}}}],
        "tool_choice": "auto",
    }
    response = client.post("/v1/responses", headers=_auth(key), json=body)
    assert response.status_code == 200, response.text
    item = response.json()["output"][0]
    assert item["type"] == "function_call"
    assert item["name"] == "get_time"
    assert item["call_id"] == "call_mock_1"


def test_responses_rejects_stateful_and_builtin_tool_features(make_mw):
    _, client, key = make_mw(data_subdir="responses-reject")
    for extra, needle in [
        ({"previous_response_id": "resp_x"}, "previous_response_id"),
        ({"store": True}, "store=true"),
        ({"background": True}, "background"),
        ({"metadata": {"user": "x"}}, "metadata"),
        ({"tools": [{"type": "web_search"}]}, "内置工具"),
    ]:
        response = client.post("/v1/responses", headers=_auth(key),
                               json=_body(**extra))
        assert response.status_code == 400, (extra, response.text)
        assert needle in response.text


def test_responses_image_rejected_by_default(make_mw):
    _, client, key = make_mw(data_subdir="responses-image")
    body = {"model": "mock-chat", "input": [{
        "type": "message", "role": "user", "content": [
            {"type": "input_text", "text": "看截图"},
            {"type": "input_image", "image_url": "data:image/png;base64,AAAA"},
        ]}]}
    response = client.post("/v1/responses", headers=_auth(key), json=body)
    assert response.status_code == 400, response.text
    assert "图片内容" in response.text


def test_responses_include_is_recorded_as_ignored(make_mw):
    _, client, key = make_mw(data_subdir="responses-include")
    response = client.post("/v1/responses", headers=_auth(key),
                           json=_body(include=["reasoning.encrypted_content"]))
    assert response.status_code == 200, response.text
    assert "include" in response.json()["cryptoguard"]["ignored_fields"]


def test_responses_accepts_function_call_output_history(make_mw):
    state, client, key = make_mw(data_subdir="responses-history")
    body = {
        "model": "mock-chat",
        "input": [
            {"type": "message", "role": "user", "content": "查一下"},
            {"type": "function_call", "call_id": "call_1",
             "name": "get_time", "arguments": "{}"},
            {"type": "function_call_output", "call_id": "call_1",
             "output": f"结果里的手机号 {PHONE}"},
        ],
    }
    response = client.post("/v1/responses", headers=_auth(key), json=body)
    assert response.status_code == 200, response.text
    sent = str(state.registry.get("mock").seen[-1].messages)
    assert PHONE not in sent
    assert "role" in sent and "tool" in sent


def test_responses_stream_text_then_tool_keeps_output_indexes_distinct():
    """文本项与工具项各自占一个 output_index，不能因为文本未收尾而重叠。"""
    from app.middleware.providers.base import StreamChunk
    from app.middleware.responses_proto import ResponsesStreamTranslator

    translator = ResponsesStreamTranslator(model="m", request_id="cg-x", created=1)
    events = translator.start()
    events += translator.feed(StreamChunk("text", text="先说话"))
    events += translator.feed(StreamChunk("tool_call", tool_index=0,
                                           tool_id="call_1", tool_name="t",
                                           tool_arguments='{"a":1}'))
    events += translator.feed(StreamChunk("done", finish_reason="tool_calls"))
    events += translator.finish()
    added = [payload for name, payload in events
             if name == "response.output_item.added"]
    indexes = [payload["output_index"] for payload in added]
    assert indexes == sorted(set(indexes)), indexes
