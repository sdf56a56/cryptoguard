"""控制台托管 Provider：加密落盘、CRUD、热生效、权限与密钥不回显。"""
from __future__ import annotations

import json
import stat
from dataclasses import replace

import pytest

from app.keys import Vault
from app.middleware.config import ConfigError
from app.middleware.provider_config import ManagedProviderStore
from tests.mw.conftest import ADMIN_TOKEN

HEADERS = {"X-Admin-Token": ADMIN_TOKEN}
FAKE_MANAGED_KEY = "sk-managed-secret-0123456789abcdef"


def _auth(key: str) -> dict:
    return {"Authorization": f"Bearer {key}"}


def _names(payload: dict) -> set[str]:
    return {p["name"] for p in payload["providers"]}


def test_create_managed_mock_provider_is_hot_applied(make_mw):
    state, client, key = make_mw()
    auth = _auth(key)

    created = client.post("/admin/providers", headers=HEADERS, json={
        "name": "mock2", "type": "mock", "display_name": "Mock 2",
        "models": ["mock2-chat"],
    })
    assert created.status_code == 201, created.text
    body = created.json()
    provider = next(p for p in body["providers"] if p["name"] == "mock2")
    assert provider["source"] == "managed"
    assert provider["editable"] is True
    assert provider["has_key"] is True
    assert body["applied"] is True

    # 立即出现在模型列表，并且可直接调用（不需要重启）
    models = client.get("/v1/models", headers=auth).json()["data"]
    assert "mock2-chat" in {m["id"] for m in models}
    reply = client.post("/v1/chat/completions", headers=auth, json={
        "model": "mock2-chat",
        "messages": [{"role": "user", "content": "hi"}],
    })
    assert reply.status_code == 200, reply.text
    assert reply.json()["cryptoguard"]["provider"] == "mock2"

    # 控制面变更入审计（只记字段名，不记密钥）
    items = client.get("/admin/audit", headers=HEADERS).json()["items"]
    assert any(item.get("outcome") == "provider_config" for item in items)
    assert state.registry.get("mock2").models == ("mock2-chat",)


def test_managed_provider_key_never_leaks(make_mw):
    state, client, key = make_mw()
    payload = {
        "name": "up", "type": "openai-compatible",
        "base_url": "https://upstream.invalid", "models": ["m1"],
        "api_key": FAKE_MANAGED_KEY,
    }
    created = client.post("/admin/providers", headers=HEADERS, json=payload)
    assert created.status_code == 201, created.text
    provider = next(p for p in created.json()["providers"] if p["name"] == "up")
    assert provider["has_key"] is True
    assert provider["key_source"] == "managed"
    assert FAKE_MANAGED_KEY not in created.text

    for response in (
        client.get("/admin/providers", headers=HEADERS),
        client.get("/admin/security/policies", headers=HEADERS),
        client.get("/admin/dashboard", headers=HEADERS),
        client.get("/health"),
    ):
        assert response.status_code == 200, response.text
        assert FAKE_MANAGED_KEY not in response.text

    # 审计不含密钥
    audit = client.get("/admin/audit", headers=HEADERS)
    assert FAKE_MANAGED_KEY not in json.dumps(audit.json(), ensure_ascii=False)

    # 磁盘上只有密文；文件权限 0600
    path = state.provider_store.path
    assert path.is_file()
    assert FAKE_MANAGED_KEY not in path.read_text(encoding="utf-8")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600

    # 更新时不传 api_key = 保持原钥；显式清除后 has_key 变 false
    kept = client.patch("/admin/providers/up", headers=HEADERS,
                        json={"models": ["m1", "m2"]})
    assert kept.status_code == 200, kept.text
    assert next(p for p in kept.json()["providers"]
                if p["name"] == "up")["has_key"] is True
    cleared = client.patch("/admin/providers/up", headers=HEADERS,
                           json={"clear_api_key": True})
    assert cleared.status_code == 200, cleared.text
    view = next(p for p in cleared.json()["providers"] if p["name"] == "up")
    assert view["has_key"] is False
    assert view["key_source"] == "none"


def test_managed_provider_overrides_env_and_restores(make_mw):
    state, client, key = make_mw()
    auth = _auth(key)
    before = client.get("/v1/models", headers=auth).json()["data"]
    assert "mock-chat" in {m["id"] for m in before}

    created = client.post("/admin/providers", headers=HEADERS, json={
        "name": "mock", "type": "mock", "display_name": "Overridden",
        "models": ["override-chat"],
    })
    assert created.status_code == 201, created.text
    provider = next(p for p in created.json()["providers"] if p["name"] == "mock")
    assert provider["source"] == "managed"
    assert provider["overrides_env"] is True
    assert provider["models"] == ["override-chat"]

    during = client.get("/v1/models", headers=auth).json()["data"]
    ids = {m["id"] for m in during}
    assert "override-chat" in ids
    assert "mock-chat" not in ids

    deleted = client.delete("/admin/providers/mock", headers=HEADERS)
    assert deleted.status_code == 200, deleted.text
    provider = next(p for p in deleted.json()["providers"] if p["name"] == "mock")
    assert provider["source"] == "env"
    assert provider["models"] == ["mock-chat", "mock-tools"]
    restored = client.get("/v1/models", headers=auth).json()["data"]
    assert "mock-chat" in {m["id"] for m in restored}
    assert state.registry.get("mock").config.models == ("mock-chat", "mock-tools")


def test_provider_defaults_validation_and_apply(make_mw):
    state, client, _ = make_mw()
    created = client.post("/admin/providers", headers=HEADERS, json={
        "name": "mock2", "type": "mock", "models": ["m2"],
    })
    assert created.status_code == 201, created.text

    ok = client.put("/admin/provider-defaults", headers=HEADERS,
                    json={"default_provider": "mock2", "default_model": "m2"})
    assert ok.status_code == 200, ok.text
    assert state.registry.default_provider == "mock2"
    assert state.registry.default_model == "m2"

    bad_model = client.put("/admin/provider-defaults", headers=HEADERS,
                           json={"default_provider": "mock2",
                                 "default_model": "nope"})
    assert bad_model.status_code == 400, bad_model.text
    bad_provider = client.put("/admin/provider-defaults", headers=HEADERS,
                              json={"default_provider": "nope",
                                    "default_model": "m2"})
    assert bad_provider.status_code == 400, bad_provider.text

    # 默认项可以指向环境变量 Provider（mock/mock-chat）
    env_default = client.put("/admin/provider-defaults", headers=HEADERS,
                             json={"default_provider": "mock",
                                   "default_model": "mock-chat"})
    assert env_default.status_code == 200, env_default.text
    assert state.registry.default_provider == "mock"

    cleared = client.put("/admin/provider-defaults", headers=HEADERS,
                         json={"default_provider": "", "default_model": ""})
    assert cleared.status_code == 200, cleared.text
    assert state.registry.default_provider == "mock"


def test_provider_admin_requires_admin_token(make_mw):
    _, client, _ = make_mw()
    body = {"name": "mock2", "type": "mock", "models": ["m"]}
    assert client.post("/admin/providers", json=body).status_code == 401
    bad = {"X-Admin-Token": "wrong-token"}
    assert client.post("/admin/providers", headers=bad, json=body).status_code == 401
    assert client.get("/admin/dashboard").status_code == 401


def test_provider_invalid_payloads_and_env_only_not_editable(make_mw):
    _, client, _ = make_mw()
    base = {"type": "mock", "models": ["m"]}

    bad_name = client.post("/admin/providers", headers=HEADERS,
                           json={**base, "name": "bad name"})
    assert bad_name.status_code == 400, bad_name.text
    bad_type = client.post("/admin/providers", headers=HEADERS,
                           json={**base, "name": "x", "type": "openai"})
    assert bad_type.status_code == 400, bad_type.text
    bad_url = client.post("/admin/providers", headers=HEADERS, json={
        "name": "x", "type": "openai-compatible", "base_url": "ftp://x",
        "models": ["m"]})
    assert bad_url.status_code == 400, bad_url.text
    userinfo = client.post("/admin/providers", headers=HEADERS, json={
        "name": "x", "type": "openai-compatible",
        "base_url": "https://user:pass@upstream.invalid", "models": ["m"]})
    assert userinfo.status_code == 400, userinfo.text
    bad_retries = client.post("/admin/providers", headers=HEADERS,
                              json={**base, "name": "x", "max_retries": 9})
    assert bad_retries.status_code == 400, bad_retries.text

    first = client.post("/admin/providers", headers=HEADERS,
                        json={**base, "name": "x"})
    assert first.status_code == 201, first.text
    duplicate = client.post("/admin/providers", headers=HEADERS,
                            json={**base, "name": "x"})
    assert duplicate.status_code == 409, duplicate.text

    # 环境变量独有项：不能 PATCH/DELETE（可新建同名托管项覆盖）
    assert client.patch("/admin/providers/mock", headers=HEADERS,
                        json={"models": ["x"]}).status_code == 404
    assert client.delete("/admin/providers/mock", headers=HEADERS).status_code == 404


def test_provider_test_endpoint_uses_managed_provider(make_mw):
    _, client, _ = make_mw()
    created = client.post("/admin/providers", headers=HEADERS, json={
        "name": "mock2", "type": "mock", "models": ["m2"],
    })
    assert created.status_code == 201, created.text
    result = client.post("/admin/providers/mock2/test", headers=HEADERS)
    assert result.status_code == 200, result.text
    assert result.json()["ok"] is True
    assert result.json()["model"] == "m2"

    missing = client.post("/admin/providers", headers=HEADERS, json={
        "name": "up", "type": "openai-compatible",
        "base_url": "https://upstream.invalid", "models": ["m1"],
    })
    assert missing.status_code == 201, missing.text
    failed = client.post("/admin/providers/up/test", headers=HEADERS)
    assert failed.status_code == 200, failed.text
    assert failed.json()["ok"] is False
    assert failed.json()["category"] == "config"


def test_provider_config_decrypt_fails_with_other_vault(make_mw):
    state, client, _ = make_mw()
    created = client.post("/admin/providers", headers=HEADERS, json={
        "name": "up", "type": "openai-compatible",
        "base_url": "https://upstream.invalid", "models": ["m1"],
        "api_key": FAKE_MANAGED_KEY,
    })
    assert created.status_code == 201, created.text
    data_dir = state.provider_store.path.parent.parent
    other = Vault(mapping_key=b"\x01" * 32, chain_mac_key=b"\x02" * 32,
                  fingerprint="other")
    with pytest.raises(ConfigError):
        ManagedProviderStore(data_dir, other)


def test_production_cannot_delete_last_provider(make_mw):
    state, client, _ = make_mw(providers=(), default_provider="", default_model="")
    created = client.post("/admin/providers", headers=HEADERS, json={
        "name": "mock2", "type": "mock", "models": ["m2"],
    })
    assert created.status_code == 201, created.text
    # 模拟生产环境：没有环境变量 Provider，只剩这一个托管 Provider
    state.base_settings = replace(state.base_settings, env="production")
    state.settings = replace(state.settings, env="production")
    state.provider_store._production = True
    blocked = client.delete("/admin/providers/mock2", headers=HEADERS)
    assert blocked.status_code == 409, blocked.text
