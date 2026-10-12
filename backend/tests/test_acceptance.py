"""
Task 12:acceptance.py —— 验收 API(/demo 抽屉数据源)。

验收标准:① golden 返回含 tp/fp/fn/p/r/fpr/p_ci/r_ci/fpr_ci/per_type 键
② 埋入 user_view 键的假行 → leaks 非空且含 file/line/path(SEC-STORE-1 演示按钮真报)
③ replay_report 于完好目录 ok=true 且计数正确 ④ degrade_demo 三类与 spec §5 表
逐格一致(SEC-DEGRADE-1)⑤ 未知 kind → 400。
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

os.environ.setdefault("CG_NO_BOOT", "1")  # 测试不触发 lifespan 装配

import pytest
from fastapi.testclient import TestClient

from app import main as main_mod
from app.bootstrap import build_chat_service
from app.llm import LLMGateway, MockChat

# run_golden 的 monkeypatch 目标:repo 根 tests/golden_gen(build_golden_set 由
# run_golden 每次调用时从该模块现取,补丁即生效)
_TESTS_DIR = Path(__file__).resolve().parents[2] / "tests"
if str(_TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(_TESTS_DIR))

import golden_gen  # noqa: E402


def iso_env(tmp_path, monkeypatch, vault_key: str | None = "b2" * 32):
    """隔离 backend/.env 回退路径 + 固定 VAULT_KEY(或删除模拟缺失)。"""
    monkeypatch.setattr("app.keys._ENV_PATH_DEFAULT", tmp_path / "isolated.env")
    if vault_key is None:
        monkeypatch.delenv("VAULT_KEY", raising=False)
    else:
        monkeypatch.setenv("VAULT_KEY", vault_key)
    monkeypatch.delenv("MIMO_API_KEY", raising=False)


def mock_service(tmp_path, monkeypatch):
    """tmp 数据目录上装配 MockChat 网关的 ChatService(写真实双视角数据)。"""
    iso_env(tmp_path, monkeypatch)
    return build_chat_service(tmp_path, gateway=LLMGateway(mimo=None, mock=MockChat()))


def plant_leak_file(directory: Path, name: str = "fake.ndjson") -> Path:
    """埋一份含明文泄漏键的假 ndjson(另有干净行 + 非 JSON 行)。"""
    directory.mkdir(parents=True, exist_ok=True)
    lines = [
        json.dumps({"type": "message", "llm_view": "[PHONE_1]",
                    "reasoning_ct": {"iv": "x"}, "mapping_delta_ct": "b64"}),
        json.dumps({"payload": {"nested": {"user_view": "13800138000"}},
                    "rows": [{"user_view": "张三"}]}),
        json.dumps({"reasoning_content": "模型思维链明文"}),
        json.dumps({"restore_map": {"a": "b"}, "mapping": {"c": "d"}}),
        "not-json",
    ]
    path = directory / name
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


# --------------------------------------------------------------------------- #
# ① golden:真实 400 集跑通,仅断言键与值类型(口径见 tests/detection_golden.py)
# --------------------------------------------------------------------------- #
def test_run_golden_real_keys_and_types():
    from app.acceptance import run_golden

    r = run_golden()
    assert set(r) == {"tp", "fp", "fn", "p", "r", "fpr",
                      "p_ci", "r_ci", "fpr_ci", "per_type", "n_neg_units"}
    assert all(isinstance(r[k], int) for k in ("tp", "fp", "fn", "n_neg_units"))
    assert r["n_neg_units"] > 0
    for k in ("p", "r", "fpr"):
        assert isinstance(r[k], float) and 0.0 <= r[k] <= 1.0
    for k in ("p_ci", "r_ci", "fpr_ci"):
        lo, hi = r[k]
        assert all(isinstance(v, float) for v in (lo, hi))
        assert 0.0 <= lo <= hi <= 1.0
    assert r["per_type"] and all(
        set(c) == {"TP", "FP", "FN"} and all(isinstance(v, int) for v in c.values())
        for c in r["per_type"].values())


def test_run_golden_zero_division_guards(monkeypatch):
    """空集 → 零分母全部兜 0.0(不抛 ZeroDivisionError)。"""
    monkeypatch.setattr(golden_gen, "build_golden_set", lambda: [])
    from app.acceptance import run_golden

    r = run_golden()
    assert (r["tp"], r["fp"], r["fn"]) == (0, 0, 0)
    assert (r["p"], r["r"], r["fpr"]) == (0.0, 0.0, 0.0)
    assert r["p_ci"] == r["r_ci"] == r["fpr_ci"] == [0.0, 0.0]
    assert r["per_type"] == {}
    assert r["n_neg_units"] == 0


# --------------------------------------------------------------------------- #
# ② store-scan:埋入 user_view/reasoning_content/mapping/restore_map → leaks 真报
# --------------------------------------------------------------------------- #
def test_scan_plaintext_leaks_flags_planted_keys(tmp_path):
    from app.acceptance import scan_plaintext_leaks

    plant_leak_file(tmp_path / "messages")
    r = scan_plaintext_leaks(tmp_path)

    assert r["checked_files"] == 1
    assert r["checked_lines"] == 5          # 非 JSON 行也计入扫描行数
    paths = {l["path"]: l for l in r["leaks"]}
    assert set(paths) == {"payload.nested.user_view", "rows[0].user_view",
                          "reasoning_content", "restore_map", "mapping"}
    for leak in r["leaks"]:
        assert set(leak) == {"file", "line", "path"}
        assert leak["file"] == "messages/fake.ndjson"
        assert isinstance(leak["line"], int)
    assert paths["payload.nested.user_view"]["line"] == 2
    assert paths["rows[0].user_view"]["line"] == 2
    assert paths["reasoning_content"]["line"] == 3
    assert paths["restore_map"]["line"] == 4
    assert paths["mapping"]["line"] == 4


def test_scan_plaintext_leaks_clean_sealed_keys_not_flagged(tmp_path):
    """精确键名口径:reasoning_ct / mapping_delta_ct / session_mapping_ct 均合法。"""
    from app.acceptance import scan_plaintext_leaks

    (tmp_path / "chain").mkdir(parents=True)
    (tmp_path / "chain" / "seg-000001.ndjson").write_text(
        json.dumps({"type": "chain", "reasoning_ct": {"iv": "x"},
                    "mapping_delta_ct": "b64", "session_mapping_ct": "b64",
                    "llm_view": "[NAME_1]"}) + "\n", encoding="utf-8")
    r = scan_plaintext_leaks(tmp_path)
    assert r["checked_files"] == 1
    assert r["checked_lines"] == 1
    assert r["leaks"] == []


def test_scan_plaintext_leaks_real_store_clean(tmp_path, monkeypatch):
    """SEC-STORE-1 端到端:真实双视角落盘后扫数据目录 leaks=[]。"""
    from app.acceptance import scan_plaintext_leaks

    svc = mock_service(tmp_path, monkeypatch)
    sid = svc.sessions.create_session("验收")["id"]
    svc.run_turn(sid, "张三的手机号是13800138000")
    svc.run_turn(sid, "继续")

    r = scan_plaintext_leaks(tmp_path)
    assert r["checked_files"] == 3        # chain + sessions + messages 各一段
    assert r["checked_lines"] == 8        # 链 2 + 会话 2 + 消息 4
    assert r["leaks"] == []


# --------------------------------------------------------------------------- #
# ③ replay_report:完好目录 ok=true 且链/会话/消息计数正确
# --------------------------------------------------------------------------- #
def test_replay_report_ok_on_healthy_dir(tmp_path, monkeypatch):
    from app.acceptance import replay_report

    svc = mock_service(tmp_path, monkeypatch)
    sid = svc.sessions.create_session("验收")["id"]
    svc.run_turn(sid, "张三的手机号是13800138000")
    svc.run_turn(sid, "继续")

    r = replay_report(tmp_path)
    assert r == {"ok": True, "chain_entries": 2, "sessions": 1, "messages": 4}


def test_replay_report_store_integrity_error(tmp_path, monkeypatch):
    from app.acceptance import replay_report

    svc = mock_service(tmp_path, monkeypatch)
    sid = svc.sessions.create_session("验收")["id"]
    svc.run_turn(sid, "你好")

    seg = sorted((tmp_path / "chain").glob("seg-*.ndjson"))[0]
    raw = seg.read_text(encoding="utf-8")
    seg.write_text(raw.replace('"payload_digest": "', '"payload_digest": "X', 1),
                   encoding="utf-8")

    r = replay_report(tmp_path)
    assert r["ok"] is False
    assert r["kind"] == "StoreIntegrityError"
    assert isinstance(r["error"], str) and r["error"]


def test_replay_report_vault_key_error(tmp_path, monkeypatch):
    from app.acceptance import replay_report

    svc = mock_service(tmp_path, monkeypatch)
    sid = svc.sessions.create_session("验收")["id"]
    svc.run_turn(sid, "你好")

    monkeypatch.delenv("VAULT_KEY", raising=False)   # 指纹在而 key 缺失
    r = replay_report(tmp_path)
    assert r["ok"] is False
    assert r["kind"] == "VaultKeyError"
    assert isinstance(r["error"], str) and r["error"]


# --------------------------------------------------------------------------- #
# ④ degrade_demo:三类故障注入与 spec §5 表逐格一致(SEC-DEGRADE-1)
# --------------------------------------------------------------------------- #
def test_degrade_demo_matches_spec_table():
    from app.acceptance import degrade_demo

    assert degrade_demo("network") == {
        "kind": "network", "ui_class": "yellow-degrade",
        "degraded": "mock", "incomplete": False}
    assert degrade_demo("protocol") == {
        "kind": "protocol", "ui_class": "red-error",
        "degraded": None, "incomplete": False}
    assert degrade_demo("stream") == {
        "kind": "stream", "ui_class": "yellow-incomplete",
        "degraded": None, "incomplete": True}


def test_degrade_demo_unknown_kind_raises():
    from app.acceptance import degrade_demo

    with pytest.raises(ValueError):
        degrade_demo("bogus")


# --------------------------------------------------------------------------- #
# ⑤ 路由:thin handler 接线 + 未知 kind 400
# --------------------------------------------------------------------------- #
def test_acceptance_golden_route():
    resp = TestClient(main_mod.app).get("/api/acceptance/golden")
    assert resp.status_code == 200
    data = resp.json()
    assert {"tp", "fp", "fn", "p", "r", "fpr",
            "p_ci", "r_ci", "fpr_ci", "per_type"} <= set(data)


def test_acceptance_store_scan_route_flags_planted(tmp_path, monkeypatch):
    plant_leak_file(tmp_path)
    monkeypatch.setattr(main_mod, "default_data_dir", lambda: tmp_path)

    resp = TestClient(main_mod.app).get("/api/acceptance/store-scan")
    assert resp.status_code == 200
    body = resp.json()
    assert body["checked_files"] == 1
    assert body["leaks"]


def test_acceptance_replay_route_ok(tmp_path, monkeypatch):
    svc = mock_service(tmp_path, monkeypatch)
    sid = svc.sessions.create_session("验收")["id"]
    svc.run_turn(sid, "张三的手机号是13800138000")
    svc.run_turn(sid, "继续")
    monkeypatch.setattr(main_mod, "default_data_dir", lambda: tmp_path)

    resp = TestClient(main_mod.app).get("/api/acceptance/replay")
    assert resp.status_code == 200
    assert resp.json() == {"ok": True, "chain_entries": 2, "sessions": 1,
                           "messages": 4}


def test_acceptance_degrade_route_three_kinds():
    client = TestClient(main_mod.app)
    expected = {
        "network": {"kind": "network", "ui_class": "yellow-degrade",
                    "degraded": "mock", "incomplete": False},
        "protocol": {"kind": "protocol", "ui_class": "red-error",
                     "degraded": None, "incomplete": False},
        "stream": {"kind": "stream", "ui_class": "yellow-incomplete",
                   "degraded": None, "incomplete": True},
    }
    for kind, want in expected.items():
        resp = client.post("/api/acceptance/degrade", json={"kind": kind})
        assert resp.status_code == 200
        assert resp.json() == want


def test_acceptance_degrade_route_unknown_kind_400():
    resp = TestClient(main_mod.app).post("/api/acceptance/degrade",
                                         json={"kind": "bogus"})
    assert resp.status_code == 400
