"""管理面权限、客户端生命周期、provider 视图与连通性测试。"""
from __future__ import annotations

import time

from tests.mw.conftest import ADMIN_TOKEN

def test_metrics_requires_admin_by_default(make_mw):
    _, client, _ = make_mw()
    assert client.get("/metrics").status_code == 401
    ok = client.get("/metrics", headers={"X-Admin-Token": ADMIN_TOKEN})
    assert ok.status_code == 200
    assert "cryptoguard_requests_total" in ok.text


def test_ready_reports_checks(make_mw):
    _, client, _ = make_mw()
    response = client.get("/ready")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["ready"] is True
    assert body["checks"]["middleware"] is True
    assert body["checks"]["providers"] is True
    assert body["checks"]["audit_chain"] is True


def test_patch_client_updates_policy_without_rotating_key(make_mw):
    state, client, _ = make_mw()
    created = client.post("/admin/clients", headers={"X-Admin-Token": ADMIN_TOKEN},
                          json={"name": "agent", "models": []})
    assert created.status_code == 201, created.text
    client_id = created.json()["client"]["id"]
    key = created.json()["api_key"]
    headers = {"Authorization": f"Bearer {key}"}

    patched = client.patch(f"/admin/clients/{client_id}",
                           headers={"X-Admin-Token": ADMIN_TOKEN},
                           json={"models": ["mock-chat"], "rate_limit_per_min": 7,
                                 "protection_mode": "token"})
    assert patched.status_code == 200, patched.text
    view = patched.json()["client"]
    assert view["models"] == ["mock-chat"]
    assert view["rate_limit_per_min"] == 7
    assert view["protection_mode"] == "token"
    # 密钥材料未变：旧 key 仍然可用
    assert client.get("/v1/models", headers=headers).status_code == 200


def test_patch_client_rejects_high_risk_restore_category(make_mw):
    _, client, _ = make_mw()
    created = client.post("/admin/clients", headers={"X-Admin-Token": ADMIN_TOKEN},
                          json={"name": "bad"})
    client_id = created.json()["client"]["id"]
    response = client.patch(f"/admin/clients/{client_id}",
                            headers={"X-Admin-Token": ADMIN_TOKEN},
                            json={"restore_categories": ["PHONE"]})
    assert response.status_code == 400, response.text
    assert "PHONE" in response.text


def test_expired_client_key_is_rejected(make_mw):
    state, client, _ = make_mw()
    created = client.post("/admin/clients", headers={"X-Admin-Token": ADMIN_TOKEN},
                          json={"name": "short-lived", "expires_in_days": 1})
    assert created.status_code == 201, created.text
    client_id = created.json()["client"]["id"]
    assert created.json()["client"]["expires_epoch"] > time.time()
    key = created.json()["api_key"]
    headers = {"Authorization": f"Bearer {key}"}
    assert client.get("/v1/models", headers=headers).status_code == 200

    # 直接把过期时间改到过去（模拟到期），不改密钥材料
    state.clients.update(client_id, expires_epoch=time.time() - 1)
    expired = client.get("/v1/models", headers=headers)
    assert expired.status_code == 401, expired.text
    assert "过期" in expired.text


def test_provider_view_and_connectivity_test(make_mw):
    _, client, _ = make_mw()

    listing = client.get("/admin/providers", headers={"X-Admin-Token": ADMIN_TOKEN})
    assert listing.status_code == 200
    names = [p["name"] for p in listing.json()["providers"]]
    assert "mock" in names
    assert "api_key" not in listing.text

    result = client.post("/admin/providers/mock/test",
                         headers={"X-Admin-Token": ADMIN_TOKEN})
    assert result.status_code == 200, result.text
    body = result.json()
    assert body["ok"] is True and body["category"] == "ok"
    assert "text" not in body  # 不回显上游正文

    missing = client.post("/admin/providers/nope/test",
                          headers={"X-Admin-Token": ADMIN_TOKEN})
    assert missing.status_code == 404


def test_instance_lock_refuses_second_holder(tmp_path):
    from app.middleware.config import ConfigError
    from app.middleware.instance import InstanceLock

    path = tmp_path / "data" / ".cryptoguard.lock"
    first = InstanceLock(path)
    first.acquire()
    try:
        second = InstanceLock(path)
        try:
            second.acquire()
        except ConfigError as exc:
            assert "另一个 CryptoGuard 实例" in str(exc)
        else:  # pragma: no cover
            raise AssertionError("第二个实例不应拿到锁")
    finally:
        first.release()

    third = InstanceLock(path)
    third.acquire()
    assert third.held
    third.release()
