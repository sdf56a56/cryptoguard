"""内容面策略：图片/文档/cache_control/未知块不再静默放行或丢弃。"""
from __future__ import annotations

OPENAI_IMAGE_BODY = {
    "model": "mock-chat",
    "messages": [{
        "role": "user",
        "content": [
            {"type": "text", "text": "看这个截图,手机号 13800138000"},
            {"type": "image_url",
             "image_url": {"url": "data:image/png;base64,iVBORw0KGgo="}},
        ],
    }],
}


def _anthropic_headers(key: str) -> dict:
    return {"x-api-key": key}


def test_openai_image_rejected_by_default(client, auth):
    response = client.post("/v1/chat/completions", json=OPENAI_IMAGE_BODY,
                           headers=auth)
    assert response.status_code == 400, response.text
    assert "图片内容" in response.text
    assert response.json()["error"]["code"] == "invalid_request"


def test_openai_image_pass_is_explicitly_marked_unprotected(make_mw):
    mw, client, key = make_mw(image_policy="pass", data_subdir="image-pass")
    response = client.post("/v1/chat/completions", json=OPENAI_IMAGE_BODY,
                           headers={"Authorization": f"Bearer {key}"})
    assert response.status_code == 200, response.text
    meta = response.json()["cryptoguard"]
    assert meta["unprotected_content"]["images"] == 1
    assert meta["content_policy"]["images"] == "pass"
    assert "images=pass" in response.headers["X-CryptoGuard-Content-Policy"]
    # 上游确实收到了图片（这是显式接受的未保护面，不是声称已保护）
    provider = mw.registry.get("mock")
    assert provider.seen
    assert "image_url" in str(provider.seen[-1].messages)


def test_anthropic_document_rejected_by_default(make_mw):
    _, client, key = make_mw(data_subdir="doc-reject")
    response = client.post("/v1/messages", headers=_anthropic_headers(key), json={
        "model": "mock-chat", "max_tokens": 32,
        "messages": [{"role": "user", "content": [
            {"type": "text", "text": "看附件"},
            {"type": "document", "source": {
                "type": "base64", "media_type": "application/pdf",
                "data": "JVBERi0xLjQK"}},
        ]}],
    })
    assert response.status_code == 400, response.text
    assert response.json()["type"] == "error"
    assert "文档内容" in response.text


def test_anthropic_document_pass_is_marked_dropped(make_mw):
    _, client, key = make_mw(document_policy="pass", data_subdir="doc-pass")
    response = client.post("/v1/messages", headers=_anthropic_headers(key), json={
        "model": "mock-chat", "max_tokens": 32,
        "messages": [{"role": "user", "content": [
            {"type": "text", "text": "看附件"},
            {"type": "document", "source": {
                "type": "base64", "media_type": "application/pdf",
                "data": "JVBERi0xLjQK"}},
        ]}],
    })
    assert response.status_code == 200, response.text
    meta = response.json()["cryptoguard"]
    assert meta["unprotected_content"]["documents"] == 1
    assert meta["dropped_content"]["documents"] == 1


def test_anthropic_cache_control_is_stripped_and_recorded(make_mw):
    _, client, key = make_mw(data_subdir="cache-strip")
    response = client.post("/v1/messages", headers=_anthropic_headers(key), json={
        "model": "mock-chat", "max_tokens": 32,
        "system": [{"type": "text", "text": "系统提示",
                    "cache_control": {"type": "ephemeral"}}],
        "messages": [{"role": "user", "content": "hi"}],
    })
    assert response.status_code == 200, response.text
    assert "cache_control" in response.json()["cryptoguard"]["ignored_fields"]


def test_anthropic_cache_control_can_be_rejected(make_mw):
    _, client, key = make_mw(cache_control="reject", data_subdir="cache-reject")
    response = client.post("/v1/messages", headers=_anthropic_headers(key), json={
        "model": "mock-chat", "max_tokens": 32,
        "system": [{"type": "text", "text": "系统提示",
                    "cache_control": {"type": "ephemeral"}}],
        "messages": [{"role": "user", "content": "hi"}],
    })
    assert response.status_code == 400, response.text
    assert "cache_control" in response.text


def test_unknown_anthropic_block_is_recorded_not_silently_ignored(make_mw):
    _, client, key = make_mw(data_subdir="unknown-block")
    response = client.post("/v1/messages", headers=_anthropic_headers(key), json={
        "model": "mock-chat", "max_tokens": 32,
        "messages": [{"role": "user", "content": [
            {"type": "text", "text": "hi"},
            {"type": "server_tool_use", "id": "x", "name": "search"},
        ]}],
    })
    assert response.status_code == 200, response.text
    ignored = response.json()["cryptoguard"]["ignored_fields"]
    assert "block:server_tool_use" in ignored


def test_tool_schema_types_are_not_mistaken_for_unknown_blocks(make_mw):
    _, client, key = make_mw(data_subdir="tool-schema")
    response = client.post("/v1/messages", headers=_anthropic_headers(key), json={
        "model": "mock-chat", "max_tokens": 32,
        "messages": [{"role": "user", "content": "hi"}],
        "tools": [{"name": "t", "input_schema": {
            "type": "object",
            "properties": {"x": {"type": "string"}},
        }}],
        "tool_choice": {"type": "auto"},
    })
    assert response.status_code == 200, response.text
    ignored = response.json()["cryptoguard"]["ignored_fields"]
    assert not any(item.startswith("block:") for item in ignored), ignored
