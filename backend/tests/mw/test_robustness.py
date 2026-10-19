"""幂等键、SSE 心跳、413 协议形状。"""
from __future__ import annotations

import time

BODY = {
    "model": "mock-chat",
    "messages": [{"role": "user", "content": "手机号 13800138000"}],
}


def _auth(key: str) -> dict:
    return {"Authorization": f"Bearer {key}"}


def test_idempotency_replays_without_calling_upstream(make_mw):
    state, client, key = make_mw(data_subdir="idem-hit")
    headers = {**_auth(key), "Idempotency-Key": "retry-1"}

    first = client.post("/v1/chat/completions", json=BODY, headers=headers)
    assert first.status_code == 200, first.text
    provider = state.registry.get("mock")
    assert len(provider.seen) == 1

    second = client.post("/v1/chat/completions", json=BODY, headers=headers)
    assert second.status_code == 200, second.text
    assert len(provider.seen) == 1, "幂等重放不应再次调用上游"
    assert second.headers.get("X-CryptoGuard-Idempotent-Replay") == "1"
    assert first.json()["choices"] == second.json()["choices"]
    assert first.headers["X-CryptoGuard-Request-ID"] == second.headers["X-CryptoGuard-Request-ID"]

    records = state.audit.list(limit=20)["items"]
    assert any(r.get("outcome") == "idempotent_replay" for r in records)


def test_idempotency_conflict_on_different_body(make_mw):
    _, client, key = make_mw(data_subdir="idem-conflict")
    headers = {**_auth(key), "Idempotency-Key": "same-key"}
    assert client.post("/v1/chat/completions", json=BODY,
                       headers=headers).status_code == 200

    changed = {"model": "mock-chat",
               "messages": [{"role": "user", "content": "完全不同的问题"}]}
    response = client.post("/v1/chat/completions", json=changed, headers=headers)
    assert response.status_code == 409, response.text
    assert response.json()["error"]["code"] == "conflict"


def test_idempotency_key_is_rejected_for_streaming(make_mw):
    _, client, key = make_mw(data_subdir="idem-stream")
    response = client.post("/v1/chat/completions",
                           headers={**_auth(key), "Idempotency-Key": "stream"},
                           json={**BODY, "stream": True})
    assert response.status_code == 400, response.text
    assert "流式" in response.text


def test_no_idempotency_key_calls_upstream_twice(make_mw):
    state, client, key = make_mw(data_subdir="idem-none")
    for _ in range(2):
        assert client.post("/v1/chat/completions", json=BODY,
                           headers=_auth(key)).status_code == 200
    assert len(state.registry.get("mock").seen) == 2


def test_sse_heartbeat_is_emitted_while_waiting_for_upstream(make_mw):
    state, client, key = make_mw(sse_heartbeat_s=0.2, data_subdir="heartbeat")
    provider = state.registry.get("mock")
    original = provider.stream

    def slow_stream(req):
        time.sleep(0.9)
        yield from original(req)

    provider.stream = slow_stream

    response = client.post("/v1/chat/completions",
                           headers=_auth(key),
                           json={**BODY, "stream": True})
    assert response.status_code == 200, response.text
    assert ": ping" in response.text
    assert "chat.completion.chunk" in response.text


def test_413_shape_follows_the_entry_protocol(make_mw):
    _, client, key = make_mw(max_request_bytes=64 * 1024, data_subdir="body-limit")
    huge = b"x" * (65 * 1024)

    openai = client.post("/v1/chat/completions", content=huge,
                         headers={**_auth(key), "Content-Type": "application/json"})
    assert openai.status_code == 413
    assert openai.json()["error"]["code"] == "request_too_large"

    anthropic = client.post("/v1/messages", content=huge,
                            headers={"x-api-key": key,
                                     "Content-Type": "application/json"})
    assert anthropic.status_code == 413
    assert anthropic.json()["type"] == "error"
    assert anthropic.json()["error"]["type"] == "invalid_request_error"
