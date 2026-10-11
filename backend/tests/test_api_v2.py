"""
CG/2.0 API 路由测试 —— Task 14 brief 四测试 + _valid_query(裁定 R7)
"""
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def _valid_query():
    return {"schema_version": "CG/2.0", "text": "张三 13800138000 查询余额",
            "scenario": "medical"}


def test_upload_routes_evidence():
    r = client.post("/api/files/upload",
                    files={"file": ("scan.pdf", b"", "application/pdf")},
                    data={"filename_token_hint": "1"})
    assert r.status_code == 200
    assert r.json()["content_tier"] == "evidence"      # 空 PDF → 存证


def test_query2_rejects_bad_schema():
    r = client.post("/api/proxy/query2", json={"schema_version": "CG/1.0"})
    assert r.status_code == 422


def test_pack_now():
    client.post("/api/proxy/query2", json=_valid_query())
    r = client.post("/api/logs/pack")
    assert r.status_code == 200 and "merkle_root" in r.json()


def test_inject_reset():
    r = client.post("/api/attack/inject", json={"attack": "swap_token"})
    assert r.json()["ok"] is False
    assert client.post("/api/attack/reset").status_code == 200
