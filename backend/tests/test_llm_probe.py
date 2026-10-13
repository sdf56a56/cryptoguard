"""
probe_connection / classify_probe_status:真实连接测试的失败分类(第七阶段)。

覆盖:200 成功、401 无效密钥、402 余额不足、404 模型不存在、400 参数被拒、
429 限流、5xx 服务端错误、超时、连接失败、响应体非 JSON。
"""
from __future__ import annotations

import json

import httpx
import pytest

from app.llm import PROBE_ERRORS, classify_probe_status, probe_connection

BASE = "https://api.deepseek.com/v1"
MODEL = "deepseek-chat"


def probe(handler, **kwargs) -> dict:
    return probe_connection("sk-test-key", BASE, MODEL,
                            transport=httpx.MockTransport(handler), **kwargs)


# ---------- 状态码分类表 ----------

@pytest.mark.parametrize("status,expected", [
    (401, "invalid_key"),
    (403, "forbidden"),
    (402, "insufficient_balance"),
    (404, "model_not_found"),
    (400, "bad_request"),
    (422, "bad_request"),
    (429, "rate_limited"),
    (500, "server_error"),
    (503, "server_error"),
])
def test_classify_probe_status(status, expected):
    assert classify_probe_status(status) == expected


def test_every_category_has_user_facing_message():
    for category in set(PROBE_ERRORS):
        assert PROBE_ERRORS[category].strip()


# ---------- 成功 ----------

def test_probe_success_returns_model_and_excerpt():
    def handler(request):
        assert request.url.path == "/v1/chat/completions"
        assert request.headers["Authorization"] == "Bearer sk-test-key"
        body = json.loads(request.content)
        assert body["model"] == MODEL
        assert body["stream"] is False          # 探测走非流式
        assert body["max_tokens"] == 1          # 最小请求
        return httpx.Response(200, json={
            "model": "deepseek-chat",
            "choices": [{"message": {"content": "pong"}}],
        })

    result = probe(handler)

    assert result["ok"] is True
    assert result["category"] == "ok"
    assert result["model"] == "deepseek-chat"
    assert result["reply_excerpt"] == "pong"


def test_probe_success_without_choices_still_ok():
    result = probe(lambda r: httpx.Response(200, json={}))
    assert result["ok"] is True


# ---------- 失败分类 ----------

@pytest.mark.parametrize("status,category", [
    (401, "invalid_key"),
    (402, "insufficient_balance"),
    (404, "model_not_found"),
    (400, "bad_request"),
    (429, "rate_limited"),
    (500, "server_error"),
])
def test_probe_http_error_maps_to_category(status, category):
    result = probe(lambda r: httpx.Response(
        status, json={"error": {"message": "boom", "type": "invalid_request_error"}}))

    assert result["ok"] is False
    assert result["category"] == category
    assert result["status"] == status
    assert "boom" in result["message"]        # 服务端摘要透出,便于定位


def test_probe_error_body_non_json_is_handled():
    result = probe(lambda r: httpx.Response(502, text="<html>bad gateway</html>"))
    assert result["ok"] is False
    assert result["category"] == "server_error"


def test_probe_timeout_maps_to_timeout():
    def handler(request):
        raise httpx.ReadTimeout("timed out")

    result = probe(handler)

    assert result["ok"] is False
    assert result["category"] == "timeout"


def test_probe_connection_error_maps_to_network():
    def handler(request):
        raise httpx.ConnectError("connection refused")

    result = probe(handler)

    assert result["ok"] is False
    assert result["category"] == "network"
    assert result["status"] is None


def test_probe_non_json_success_body_is_bad_response():
    result = probe(lambda r: httpx.Response(200, text="not json"))
    assert result["ok"] is False
    assert result["category"] == "bad_response"


def test_probe_never_echoes_api_key_in_message():
    result = probe(lambda r: httpx.Response(
        401, json={"error": {"message": "Unauthorized"}}))
    assert "sk-test-key" not in json.dumps(result)
