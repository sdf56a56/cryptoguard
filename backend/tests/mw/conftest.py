"""
中间件测试夹具 —— 离线(无网络、无真实密钥)装配一个完整的 CryptoGuard 中间件

设计:
  - 数据目录用 pytest 的 tmp_path:不触碰仓库里的 data/,每个测试独立信任根;
  - 提供商固定为 mock(确定性回显),真实上游的测试**不在此处伪造**,
    而是标记为 skip 并注明需要真实密钥(见 test_real_http_e2e.py 的可选用例);
  - 客户端密钥经 CG_BOOTSTRAP_KEY_FILE 落到临时文件,测试从文件读取(不猜格式)。
"""
from __future__ import annotations

import os

os.environ.setdefault("CG_NO_BOOT", "1")   # 不触发 lifespan 的自动装配

import pytest
from fastapi.testclient import TestClient

from app import main as main_mod
from app.middleware.config import ProviderSettings, Settings
from app.middleware.deps import build_middleware

ADMIN_TOKEN = "test-admin-token-0123456789"

#: 测试用的假上游密钥(形如真实密钥以便命中打码规则,但不可能可用)
FAKE_UPSTREAM_KEY = "sk-fake-000111222333444555666777888999"
UPSTREAM_KEY_ENV = "CG_TEST_UPSTREAM_KEY"


@pytest.fixture()
def settings_factory(tmp_path):
    """生成 Settings(可按用例覆盖字段);bootstrap 密钥写到临时文件。"""

    def make(**overrides) -> Settings:
        base = dict(
            env="development",
            host="127.0.0.1",
            port=0,
            admin_token=ADMIN_TOKEN,
            allow_anonymous=False,
            providers=(ProviderSettings(
                name="mock", type="mock", base_url="",
                api_key_env="", models=("mock-chat", "mock-tools"),
                display_name="Mock"),),
            default_provider="mock",
            default_model="mock-chat",
            model_aliases={},
            allow_unknown_models=False,
            protection_mode="placeholder",
            policy_version="cg-policy/test-1",
            detection_config_path="",
            restore_mode="categories",
            restore_categories=("EMAIL", "IP", "URL", "ORG"),
            block_on="critical",
            stable_tokens=False,
            vault_ttl_s=600,
            vault_max_requests=64,
            # 确认有效期必须 ≤ 金库 TTL,否则启动期会告警「映射先于确认过期」
            confirm_ttl_s=300,
            confirm_max_records=64,
            audit_retention_days=30,
            rate_limit_per_min=1000,
            max_concurrency=8,
            max_request_bytes=64 * 1024,
            stream_buffer_chars=32,
            response_scan="audit",
            bootstrap_client_name="test-client",
            bootstrap_key_file=str(tmp_path / "bootstrap.key"),
        )
        base.update(overrides)
        return Settings(**base)

    return make


@pytest.fixture()
def data_dir(tmp_path):
    """`mw` 夹具使用的数据目录(审计日志在 `<data_dir>/security/`)。"""
    from pathlib import Path
    return Path(tmp_path) / "data"


@pytest.fixture()
def mw(data_dir, settings_factory):
    """装配好的中间件(挂在 main.app.state.middleware 上,供 TestClient 使用)。"""
    settings = settings_factory()
    app_state = build_middleware(data_dir, settings=settings)
    main_mod.app.state.middleware = app_state
    yield app_state
    if hasattr(main_mod.app.state, "middleware"):
        delattr(main_mod.app.state, "middleware")


@pytest.fixture()
def client(mw) -> TestClient:
    return TestClient(main_mod.app)


@pytest.fixture()
def api_key(mw) -> str:
    """开发环境自动生成的客户端密钥(写在临时文件里,只出现一次)。"""
    path = mw.settings.bootstrap_key_file
    assert path and os.path.isfile(path), "bootstrap 密钥文件未生成"
    with open(path, encoding="utf-8") as handle:
        return handle.read().strip()


@pytest.fixture()
def auth(api_key) -> dict:
    return {"Authorization": f"Bearer {api_key}"}


@pytest.fixture()
def admin() -> dict:
    return {"X-Admin-Token": ADMIN_TOKEN}


@pytest.fixture()
def make_mw(tmp_path, settings_factory):
    """装配**另一个独立数据目录**的中间件,返回 (state, TestClient, bootstrap_key)。

    用途:真 HTTP 上游、不同保护模式、需要自定义 Settings 的用例。
    与 `mw` 夹具互斥使用 —— 两者各自持有独立的 data 目录与 bootstrap 密钥文件,
    否则两条审计链会写同一批文件(内存里的链尾会互相看不见)。
    """

    def make(**overrides):
        # data_subdir:同一用例里需要装配**两份互不相干的部署**(不同 VAULT_KEY)时,
        # 传不同的子目录名 —— 否则第二次会复用同一份信任根,测不出密钥隔离。
        subdir = overrides.pop("data_subdir", "data-mw")
        overrides.setdefault("bootstrap_key_file",
                             str(tmp_path / f"bootstrap-{subdir}.key"))
        settings = settings_factory(**overrides)
        state = build_middleware(tmp_path / subdir, settings=settings)
        main_mod.app.state.middleware = state
        key = ""
        path = settings.bootstrap_key_file
        if path and os.path.isfile(path):
            with open(path, encoding="utf-8") as handle:
                key = handle.read().strip()
        return state, TestClient(main_mod.app), key

    yield make
    if hasattr(main_mod.app.state, "middleware"):
        delattr(main_mod.app.state, "middleware")


@pytest.fixture()
def make_client(client, admin):
    """经管理员接口签发一个新客户端密钥(README:完整密钥只在签发时返回一次)。"""

    def make(name: str = "extra", *, protection_mode: str = "",
             models=None, restore_categories=None, rate_limit_per_min: int = 0):
        body: dict = {"name": name, "models": list(models or []),
                      "rate_limit_per_min": rate_limit_per_min}
        if protection_mode:
            body["protection_mode"] = protection_mode
        if restore_categories is not None:
            body["restore_categories"] = list(restore_categories)
        response = client.post("/admin/clients", json=body, headers=admin)
        assert response.status_code == 201, response.text
        data = response.json()
        key = data["api_key"]
        return {"id": data["client"]["id"], "key": key, "record": data["client"],
                "auth": {"Authorization": f"Bearer {key}"}}

    return make


# --------------------------------------------------------------------------- #
# 请求辅助
# --------------------------------------------------------------------------- #
def chat(client, headers, text: str, *, model: str = "mock-chat", **extra):
    """发一次非/流式补全(默认走 mock 提供商)。"""
    body: dict = {"model": model, "messages": [{"role": "user", "content": text}]}
    body.update(extra)
    return client.post("/v1/chat/completions", json=body, headers=headers)


def reply_text(response) -> str:
    return response.json()["choices"][0]["message"]["content"]


def meta_of(response) -> dict:
    return response.json()["cryptoguard"]


def mock_provider(mw):
    """取 mock 提供商实例(其 `.seen` 记录了**上游实际收到**的请求)。"""
    provider, _ = mw.registry.resolve(mw.settings.default_model)
    return provider


def upstream_seen_text(mw) -> str:
    """最近一次上游**实际收到**的请求体(JSON 文本,用于断言没有原始敏感数据)。"""
    import dataclasses
    import json as _json

    provider = mock_provider(mw)
    assert provider.seen, "上游一次都没被调用"
    return _json.dumps(dataclasses.asdict(provider.seen[-1]), ensure_ascii=False,
                       default=str)
