"""控制台看板 /admin/dashboard：权限、零态、真实计数与不泄漏密钥。"""
from __future__ import annotations

from tests.mw.conftest import ADMIN_TOKEN, chat

HEADERS = {"X-Admin-Token": ADMIN_TOKEN}


def test_dashboard_requires_admin(make_mw):
    _, client, _ = make_mw()
    assert client.get("/admin/dashboard").status_code == 401
    assert client.get("/admin/dashboard",
                      headers={"X-Admin-Token": "wrong"}).status_code == 401


def test_dashboard_zero_state_is_honest(make_mw):
    _, client, _ = make_mw()
    response = client.get("/admin/dashboard", headers=HEADERS)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["requests"]["total"] == 0
    assert body["requests"]["errors"] == 0
    assert body["requests"]["by_status"] == {}
    assert body["durations"]["count"] == 0
    assert body["detections"]["total"] == 0
    assert body["upstream"]["total"] == 0
    assert body["audit"]["records"] == 0
    assert body["clients"]["total"] >= 1        # bootstrap 密钥
    assert any(p["name"] == "mock" and p["configured"] for p in body["providers"])
    assert body["defaults"]["provider"] == "mock"
    assert body["checks"]["providers"] is True


def test_dashboard_reflects_real_request_and_detections(make_mw):
    _, client, key = make_mw()
    auth = {"Authorization": f"Bearer {key}"}
    reply = chat(client, auth, "联系我 13800138000")
    assert reply.status_code == 200, reply.text
    meta = reply.json()["cryptoguard"]
    assert meta["detected"]["total"] >= 1

    response = client.get("/admin/dashboard", headers=HEADERS)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["requests"]["total"] >= 1
    assert body["durations"]["count"] >= 1
    assert body["durations"]["p95_ms"] >= 0
    assert body["detections"]["total"] >= 1
    assert body["detections"]["by_type"].get("PHONE", 0) >= 1
    assert body["upstream"]["by_provider"].get("mock", 0) >= 1
    assert body["upstream"]["by_outcome"].get("ok", 0) >= 1
    assert body["audit"]["records"] >= 1
    assert body["audit"]["tip_hash"]
    assert body["misc"]["sse_heartbeats_total"] == 0
    assert body["providers"][0]["has_key"] is True
    assert key not in response.text


def test_dashboard_does_not_expose_managed_key(make_mw):
    state, client, _ = make_mw()
    secret = "sk-dashboard-must-not-leak-0123456789"
    created = client.post("/admin/providers", headers=HEADERS, json={
        "name": "up", "type": "openai-compatible",
        "base_url": "https://upstream.invalid", "models": ["m1"],
        "api_key": secret,
    })
    assert created.status_code == 201, created.text
    response = client.get("/admin/dashboard", headers=HEADERS)
    assert response.status_code == 200, response.text
    assert secret not in response.text
    assert any(p["name"] == "up" and p["has_key"] for p in response.json()["providers"])
