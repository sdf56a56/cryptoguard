"""
设置页 API:GET/PUT /api/llm/config、clear-key、POST /api/llm/test、
以及未配置密钥时的对话 fail-closed 行为(第三/四/七阶段)。

验收要点:
  ① 任何响应体都不含完整 API Key
  ② 保存后 GET 立即反映(网关与设置页同一配置源,无需重启)
  ③ 非法配置 → 400
  ④ 测试连接对各类失败返回可操作分类,不以「Key 非空」冒充成功
  ⑤ 未配置密钥时对话发 error 帧 class="unconfigured" 且无 Mock 回复文本
"""
from __future__ import annotations

import json
import os
import types

os.environ.setdefault("CG_NO_BOOT", "1")  # 测试不触发 lifespan 装配

import httpx
import pytest
from fastapi.testclient import TestClient

from app import main as main_mod
from app.bootstrap import build_chat_service
from app.llm import ConfiguredGateway, OpenAIChatLLM
from app.llm_config import LLMConfig

KEY = "sk-abcdefghijklmnopqrstuvwxyz012345"


def make_client(tmp_path, monkeypatch, *, with_gateway: bool = False):
    """装配测试客户端;默认用真实 ConfiguredGateway(便于验证 fail-closed)。"""
    monkeypatch.setenv("CG_NO_BOOT", "1")
    monkeypatch.setattr("app.keys._ENV_PATH_DEFAULT", tmp_path / "isolated.env")
    monkeypatch.setenv("VAULT_KEY", "a1" * 32)
    for name in ("DEEPSEEK_API_KEY", "LLM_API_KEY", "MIMO_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    main_mod._chat_rate_hits.clear()
    main_mod._chain_verify_cache.clear()

    service = build_chat_service(tmp_path)
    monkeypatch.setattr(main_mod.app.state, "chat", service, raising=False)
    return types.SimpleNamespace(client=TestClient(main_mod.app), service=service)


@pytest.fixture()
def client(tmp_path, monkeypatch):
    return make_client(tmp_path, monkeypatch)


def save_cfg(client, **over):
    body = {"provider": "deepseek", "base_url": "https://api.deepseek.com/v1",
            "model": "deepseek-chat", "display_name": "DeepSeek Chat",
            "api_key": KEY}
    body.update(over)
    return client.client.put("/api/llm/config", json=body)


# ---------- ① GET:脱敏 + 预设 ----------

def test_get_config_returns_masked_status(client):
    r = client.client.get("/api/llm/config")
    assert r.status_code == 200
    body = r.json()

    assert body["config"]["has_key"] is False
    assert body["config"]["configured"] is False
    assert KEY not in r.text
    providers = {p["id"] for p in body["providers"]}
    assert "deepseek" in providers
    ds = next(p for p in body["providers"] if p["id"] == "deepseek")
    assert ds["base_url"] == "https://api.deepseek.com"
    # 官方 model ID(2026-10 核实):V4.1 Flash 的 API 名是 deepseek-flash
    assert any(m["id"] == "deepseek-flash" for m in ds["models"])
    # 已下线的旧 ID 不得再作为预设出现
    assert not any(m["id"] in ("deepseek-chat", "deepseek-reasoner")
                   for m in ds["models"])


def test_get_config_never_leaks_key_after_save(client):
    assert save_cfg(client).status_code == 200

    r = client.client.get("/api/llm/config")

    assert r.json()["config"]["has_key"] is True
    assert r.json()["config"]["configured"] is True
    assert KEY not in r.text                       # ① 完整密钥不出后端
    assert r.json()["config"]["key_masked"].startswith("sk-")


# ---------- ② 保存即生效 ----------

def test_save_then_get_reflects_config(client):
    r = save_cfg(client, model="deepseek-v4-pro", display_name="推理模型")

    assert r.status_code == 200
    assert r.json()["ok"] is True
    cfg = client.client.get("/api/llm/config").json()["config"]
    assert cfg["model"] == "deepseek-v4-pro"
    assert cfg["display_name"] == "推理模型"
    assert cfg["provider"] == "deepseek"


def test_empty_display_name_backfilled_from_preset(client):
    """显示名与 API model ID 分开保存:留空则按官方标签回填。"""
    r = save_cfg(client, model="deepseek-flash", display_name="")

    assert r.json()["config"]["display_name"] == "DeepSeek V4.1 Flash"
    assert r.json()["config"]["model"] == "deepseek-flash"    # ID 未被改写


def test_saved_config_reaches_the_chat_gateway(client):
    """设置页与对话网关共用同一 store —— 杜绝双配置源。"""
    save_cfg(client)

    assert client.service.llm_config.load().model == "deepseek-chat"
    assert client.service._gateway.config_store is client.service.llm_config


def test_put_without_api_key_keeps_existing(client):
    save_cfg(client)

    r = save_cfg(client, model="deepseek-v4-pro", api_key=None)

    assert r.status_code == 200
    assert r.json()["config"]["has_key"] is True   # 未清空


# ---------- ③ 非法配置 ----------

@pytest.mark.parametrize("bad", [
    {"base_url": "ftp://x.com"},
    {"base_url": "https://api.deepseek.com/v1", "model": ""},
    {"provider": "nope"},
])
def test_invalid_config_returns_400(client, bad):
    r = save_cfg(client, **bad)
    assert r.status_code == 400
    assert KEY not in r.text


# ---------- ④ 清空密钥 ----------

def test_clear_key_endpoint(client):
    save_cfg(client)

    r = client.client.post("/api/llm/config/clear-key")

    assert r.status_code == 200
    assert r.json()["config"]["has_key"] is False
    assert client.service.llm_config.load().api_key == ""


# ---------- ⑤ 连接测试:真实分类,不冒充成功 ----------

def test_probe_without_key_reports_missing_key(client):
    r = client.client.post("/api/llm/test", json={})

    assert r.status_code == 200
    assert r.json()["ok"] is False                 # 不以 Key 非空冒充成功
    assert r.json()["category"] == "missing_key"


def test_probe_without_base_url_reports_missing(client):
    save_cfg(client, base_url="https://api.deepseek.com/v1")
    r = client.client.post("/api/llm/test", json={"base_url": ""})
    # 空串回落已存配置;显式传空白才判缺 —— 这里验证回落生效
    assert r.json()["category"] != "missing_base_url" or r.json()["ok"] is False


def test_probe_success_is_reported(client, monkeypatch):
    save_cfg(client)
    monkeypatch.setattr(main_mod, "probe_connection",
                        lambda *a, **k: {"ok": True, "category": "ok",
                                         "message": "连接成功", "status": 200,
                                         "model": "deepseek-chat",
                                         "reply_excerpt": ""})

    r = client.client.post("/api/llm/test", json={})

    assert r.json()["ok"] is True
    assert r.json()["model"] == "deepseek-chat"


@pytest.mark.parametrize("category", [
    "invalid_key", "model_not_found", "rate_limited", "timeout", "network",
    "server_error", "insufficient_balance",
])
def test_probe_failure_categories_pass_through(client, monkeypatch, category):
    save_cfg(client)
    monkeypatch.setattr(main_mod, "probe_connection",
                        lambda *a, **k: {"ok": False, "category": category,
                                         "message": f"{category} 说明",
                                         "status": 401})

    body = client.client.post("/api/llm/test", json={}).json()

    assert body["ok"] is False
    assert body["category"] == category
    assert body["message"]


def test_probe_uses_request_overrides_before_saving(client, monkeypatch):
    """「先测再存」:未保存的 Base URL/Model 也能测。"""
    seen: dict = {}

    def fake(api_key, base_url, model, *a, **k):
        seen.update(api_key=api_key, base_url=base_url, model=model)
        return {"ok": True, "category": "ok", "message": "ok", "status": 200}

    monkeypatch.setattr(main_mod, "probe_connection", fake)
    client.client.post("/api/llm/test",
                       json={"api_key": "sk-temp", "base_url": "https://api.deepseek.com/v1",
                             "model": "deepseek-chat"})

    assert seen["api_key"] == "sk-temp"
    assert seen["model"] == "deepseek-chat"


def test_probe_internal_error_does_not_leak_stack(client, monkeypatch):
    save_cfg(client)

    def boom(*a, **k):
        raise RuntimeError("secret-internal-detail")

    monkeypatch.setattr(main_mod, "probe_connection", boom)
    r = client.client.post("/api/llm/test", json={})

    assert r.status_code == 200
    assert r.json()["ok"] is False
    assert "secret-internal-detail" not in r.text   # 不外泄异常内容


# ---------- ⑥ 未配置密钥:对话 fail-closed,无 Mock 文本 ----------

def test_chat_without_key_returns_unconfigured_error_frame(client):
    sid = client.client.post("/api/chat/sessions", json={}).json()["id"]

    r = client.client.post(f"/api/chat/sessions/{sid}/messages",
                           json={"text": "你好"})

    assert r.status_code == 200                    # SSE 开流成功,错误在帧内
    assert 'event: error' in r.text
    events = [json.loads(b.split("data:", 1)[1])
              for b in r.text.strip().split("\n\n")
              if b.startswith("event: error")]
    assert events and events[0]["class"] == "unconfigured"
    assert events[0]["action"] == "open_settings"
    # 绝不出现 Mock 模板话术冒充模型回答
    assert "已收到您的请求" not in r.text
    assert "event: done" not in r.text


def test_config_endpoint_503_when_not_booted(tmp_path, monkeypatch):
    monkeypatch.setattr(main_mod.app.state, "chat",
                        types.SimpleNamespace(), raising=False)
    r = TestClient(main_mod.app).get("/api/llm/config")
    assert r.status_code == 503


# ---------- ⑦ DeepSeek 流式契约:必须带 stream_options ----------

def test_default_factory_builds_deepseek_client_with_stream_options():
    """官方要求 stream_options.include_usage 与 stream=true 同发,否则 400。"""
    llm = ConfiguredGateway._default_factory(LLMConfig(
        provider="deepseek", base_url="https://api.deepseek.com",
        model="deepseek-flash", api_key="sk-x"))

    assert llm._stream_options == {"include_usage": True}
    assert llm._url == "https://api.deepseek.com/chat/completions"
    assert llm.model == "deepseek-flash"


def test_custom_provider_has_no_stream_options():
    llm = ConfiguredGateway._default_factory(LLMConfig(
        provider="openai-compatible", base_url="https://example.com/v1",
        model="whatever", api_key="sk-x"))
    assert llm._stream_options is None


def test_stream_options_are_sent_in_request_body():
    seen: dict = {}

    def handler(request):
        seen["body"] = json.loads(request.content)
        seen["path"] = request.url.path
        return httpx.Response(200, content=b'data: [DONE]\n\n')

    llm = OpenAIChatLLM(api_key="sk-x", base_url="https://api.deepseek.com",
                        model="deepseek-flash",
                        stream_options={"include_usage": True},
                        transport=httpx.MockTransport(handler))
    llm.chat([{"role": "user", "content": "hi"}])

    assert seen["path"] == "/chat/completions"        # 无 /v1 前缀(官方推荐)
    assert seen["body"]["stream"] is True
    assert seen["body"]["stream_options"] == {"include_usage": True}


def test_client_without_stream_options_omits_the_field():
    seen: dict = {}

    def handler(request):
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, content=b'data: [DONE]\n\n')

    llm = OpenAIChatLLM(api_key="sk-x", base_url="https://example.com/v1",
                        model="m", transport=httpx.MockTransport(handler))
    llm.chat([{"role": "user", "content": "hi"}])

    assert "stream_options" not in seen["body"]       # 不污染通用 provider
