"""
第 4 阶段 · 任务 5 —— 真实 HTTP 上游端到端验证(三种保护模式)

与 `test_gateway_chain.py` 的区别:那条链路的上游是进程内的 Mock Provider,
「上游收到了什么」只能相信 provider 对象的自述。本文件把上游换成**真实的 HTTP
服务**(本机 127.0.0.1 上的 ThreadingHTTPServer,真实 socket、真实请求头、真实
分块),于是「上游实际收到什么」有了独立的观察面:服务端记录的原始字节。

核心手法 —— 一个**回声上游(EchoUpstream)**:
  它把「它实际收到的最后一条用户消息」原样回显成模型回答。这样「响应里能否还原出
  原文」就只取决于「上游手里有没有原文」:
    - 若上游收到的是令牌 → 回显的也是令牌 → 客户端侧还原得到原文(白名单类别);
    - 若上游收到的是原文 → 回显原文 → 断言立刻失败(证明脱敏没做)。
  这是**反证**:我们不让上游"配合保护数据",而是证明它根本拿不到数据。

诚实边界(必须写清楚,不得含糊):
  - 上游看到的是令牌,不是密文;本中间件不声称上游理解任何加密/AEAD 语义,
    模式 C 的机密性来自「上游拿不到明文」,不是「上游解不开密文」;
  - 真实厂商(DeepSeek/OpenAI/Anthropic)的连通性、模型名有效性与计费行为
    **本次未执行**(无网络/无付费授权),见文件末尾的 skip 用例;
  - 本文件不构成「系统已绝对安全」的结论,只证明这条链路上可复现的事实。
"""
from __future__ import annotations

import json
import os

import pytest
from starlette.testclient import TestClient

from app.middleware.config import ProviderSettings
from app.middleware.verification import response_digest
from tests.mw.conftest import FAKE_UPSTREAM_KEY, UPSTREAM_KEY_ENV
from tests.mw.test_upstream_provider import (UPSTREAM_ADVERTISED_MODEL, FakeUpstream,
                                             completion_body, sse, text_delta)

PHONE = "13800138000"
EMAIL = "zhangsan@corp.com.cn"
PROMPT = f"我的手机号是 {PHONE},邮箱是 {EMAIL}"

MODES = ("placeholder", "token", "encrypt")

#: 真实厂商密钥的环境变量名(存在时才跑那个用例;默认整条跳过)
REAL_KEY_ENV = "CG_REAL_UPSTREAM_KEY"
REAL_BASE_URL_ENV = "CG_REAL_UPSTREAM_URL"


# --------------------------------------------------------------------------- #
# 回声上游
# --------------------------------------------------------------------------- #
def _received_text(payload: dict) -> str:
    """从上游收到的请求体里取出最后一条用户消息的文本。"""
    messages = payload.get("messages") or []
    if not messages:
        return ""
    content = messages[-1].get("content")
    if isinstance(content, list):            # content 数组形态
        return "".join(str(part.get("text", "")) for part in content
                       if isinstance(part, dict))
    return content or ""


class EchoUpstream(FakeUpstream):
    """把「实际收到的内容」原样回显,并支持限流/超时/故障注入。"""

    delay_s: float = 0.0
    error_status: int | None = None
    fail_first: int = 0

    def _next(self) -> dict:  # noqa: D102 — 语义见类文档
        with self._lock:
            raw = self.requests[-1]["body"] if self.requests else b""
            attempt = len(self.requests)
        try:
            payload = json.loads(raw)
        except Exception:  # noqa: BLE001 — 收到坏 JSON 也照实回显为空
            payload = {}
        text = _received_text(payload)

        if self.error_status:
            # 上游(或其前置代理)常把收到的报文片段贴进错误信息 —— 这里刻意如此,
            # 用来证明「它贴不出自己没收到的东西」。
            return {"status": self.error_status,
                    "body": {"error": {"message": f"invalid request body: {text}"}}}
        if self.fail_first and attempt <= self.fail_first:
            return {"status": 503, "headers": {"Retry-After": "0"},
                    "body": {"error": {"message": "cold start"}}}
        if payload.get("stream"):
            return {"status": 200, "chunks": sse(text_delta(text, "stop"))}
        return {"status": 200, "body": completion_body(text), "delay": self.delay_s}


@pytest.fixture()
def upstream():
    server = EchoUpstream()
    try:
        yield server
    finally:
        server.close()


@pytest.fixture()
def http_env(upstream, make_mw, monkeypatch):
    """装配一个**真上游**中间件;返回 (mw, TestClient, 认证头, upstream)。

    `mode` 决定保护模式;额外关键字透传给 ProviderSettings(用于超时/重试用例)。
    """
    monkeypatch.setenv(UPSTREAM_KEY_ENV, FAKE_UPSTREAM_KEY)

    def make(*, mode: str = "placeholder", subdir: str = "", **provider_kw):
        kwargs = dict(
            name="fake", type="openai-compatible", base_url=upstream.base_url,
            api_key_env=UPSTREAM_KEY_ENV, models=("mock-chat",),
            display_name="Fake Real HTTP Upstream",
            timeout_connect=2.0, timeout_read=5.0, max_retries=0)
        kwargs.update(provider_kw)
        provider = ProviderSettings(**kwargs)
        mw, client, key = make_mw(protection_mode=mode,
                                  data_subdir=subdir or f"data-{mode}",
                                  providers=(provider,), default_provider="fake")
        return mw, client, {"Authorization": f"Bearer {key}"}, upstream

    return make


# --------------------------------------------------------------------------- #
# 辅助
# --------------------------------------------------------------------------- #
def _chat(client, headers, text=PROMPT, **extra):
    body = {"model": "mock-chat", "messages": [{"role": "user", "content": text}]}
    body.update(extra)
    return client.post("/v1/chat/completions", json=body, headers=headers)


def _reply_text(response) -> str:
    return response.json()["choices"][0]["message"]["content"]


def _sse_text(raw: str) -> str:
    """把 SSE 报文里的增量内容拼起来(忽略注释行、空行与 [DONE])。"""
    out = []
    for line in raw.splitlines():
        if not line.startswith("data:"):
            continue
        payload = line[len("data:"):].strip()
        if not payload or payload == "[DONE]":
            continue
        try:
            event = json.loads(payload)
        except json.JSONDecodeError:
            continue
        for choice in event.get("choices") or []:
            out.append((choice.get("delta") or {}).get("content") or "")
    return "".join(out)


def _sent_bodies(upstream) -> str:
    """上游收到的全部请求(路径 + 头 + 原始体)的文本化,用于断言「没收到什么」。"""
    return json.dumps([{"path": r["path"], "headers": r["headers"],
                        "body": r["body"].decode("utf-8", "replace")}
                       for r in upstream.requests], ensure_ascii=False)


def _files_text(root) -> str:
    return "".join(path.read_text(encoding="utf-8", errors="ignore")
                   for path in root.rglob("*") if path.is_file())


# --------------------------------------------------------------------------- #
# 1. 三种模式:上游收到的原始字节里没有敏感原文
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("mode", MODES)
def test_upstream_receives_no_original_values(http_env, mode, tmp_path):
    mw, client, headers, upstream = http_env(mode=mode)

    response = _chat(client, headers)
    assert response.status_code == 200, response.text
    assert len(upstream.requests) == 1

    sent = upstream.requests[-1]
    raw = sent["body"].decode("utf-8")
    assert sent["path"] == "/chat/completions"
    assert PHONE not in raw, "手机号原件出网了"
    assert EMAIL not in raw, "邮箱原件出网了"
    assert sent["headers"]["authorization"] == f"Bearer {FAKE_UPSTREAM_KEY}"

    # 出网的是令牌(逐模式形态不同),而不是任何形式的原文
    payload = json.loads(raw)
    protected = _received_text(payload)
    assert PHONE not in protected and EMAIL not in protected
    kind_marker = {"placeholder": "[EMAIL_001]", "token": "[CG_TOKEN_",
                   "encrypt": "[CG_ENC_v1_"}[mode]
    assert kind_marker in protected, f"{mode} 模式下的出站形态不符:{protected!r}"

    # 模式 C:密文与 nonce 也不得出网(出网的是令牌,不是可解材料)
    if mode == "encrypt":
        for token in mw.token_vault.tokens(
                response.headers["X-CryptoGuard-Request-ID"]):
            blob = mw.token_vault._records[          # noqa: SLF001 — 断言密文不长脚
                response.headers["X-CryptoGuard-Request-ID"]].entries[token]["sealed"]
            assert blob["ciphertext"] not in raw and blob["iv"] not in raw

    # 磁盘上同样没有原文
    assert PHONE not in _files_text(tmp_path / f"data-{mode}")


# --------------------------------------------------------------------------- #
# 2. 回声上游:还原行为逐模式一致且可解释
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("mode", MODES)
def test_echo_upstream_restores_only_what_policy_allows(http_env, mode):
    mw, client, headers, upstream = http_env(mode=mode)
    response = _chat(client, headers)
    assert response.status_code == 200, response.text

    text = _reply_text(response)
    meta = response.json()["cryptoguard"]
    # 上游回显的是令牌 → 白名单类别(EMAIL)在本地还原;高风险(PHONE)保持令牌
    assert EMAIL in text, f"{mode}:白名单类别未被还原"
    assert PHONE not in text, f"{mode}:高风险原文出现在响应里"
    assert "[PHONE_" in text or "[CG_TOKEN_" in text or "[CG_ENC_v1_" in text
    assert meta["protection_mode"] == mode
    assert "PHONE" in {entry["type"] for entry in meta["restore"]["withheld"]}
    assert "EMAIL" in {entry["type"] for entry in meta["restore"]["restored"]}
    # 审计里的响应摘要与客户端拿到的响应一致(可复算)
    record = mw.audit.get(response.headers["X-CryptoGuard-Request-ID"])
    assert record["outcome"] == "ok"
    assert record["response_digest"] == meta["digest"]["response"]


@pytest.mark.parametrize("mode", MODES)
def test_streaming_over_real_http_is_consistent_with_non_streaming(http_env, mode):
    mw, client, headers, upstream = http_env(mode=mode)
    response = _chat(client, headers, stream=True)
    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("text/event-stream")

    text = _sse_text(response.text)
    assert EMAIL in text
    assert PHONE not in text
    # 上游仍然只收到令牌(流式不改变出站内容)
    assert PHONE not in upstream.requests[-1]["body"].decode("utf-8")
    assert EMAIL not in upstream.requests[-1]["body"].decode("utf-8")
    assert mw.audit.get(
        response.headers["X-CryptoGuard-Request-ID"])["outcome"] == "ok"


# --------------------------------------------------------------------------- #
# 3. 错误 / 超时 / 重试:仍然不泄漏,且不误还原
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("mode", MODES)
def test_upstream_error_echoes_tokens_only(http_env, mode):
    """上游把收到的报文贴进错误体:客户端能看到的最多也只是令牌。"""
    mw, client, headers, upstream = http_env(mode=mode)
    upstream.error_status = 400

    response = _chat(client, headers)
    assert response.status_code == 502, response.text      # 上游 4xx 归类为上游错误
    assert response.json()["error"]["type"] == "upstream_error"
    body = response.text
    assert PHONE not in body and EMAIL not in body
    assert "invalid request body" in body          # 上游的错误确实被转达了
    assert UPSTREAM_KEY_ENV not in body            # 不泄漏配置细节
    assert FAKE_UPSTREAM_KEY not in body
    # 上游确实收到了内容,只是收到的是令牌(所以它只能贴出令牌)
    raw = upstream.requests[-1]["body"].decode("utf-8")
    assert PHONE not in raw and EMAIL not in raw
    assert mw.audit.get(response.json()["error"]["request_id"])["error_kind"] \
        == "upstream_4xx"


def test_read_timeout_does_not_leak_and_does_not_restore(http_env):
    mw, client, headers, upstream = http_env(mode="token", timeout_read=0.3,
                                             max_retries=0)
    upstream.delay_s = 1.5

    response = _chat(client, headers)
    assert response.status_code == 504, response.text
    assert PHONE not in response.text and EMAIL not in response.text
    # 上游在超时前已经收到了请求 —— 里面只有令牌
    assert len(upstream.requests) == 1
    raw = upstream.requests[-1]["body"].decode("utf-8")
    assert PHONE not in raw and EMAIL not in raw
    assert "[CG_TOKEN_" in raw
    # 拿不到上游答复时不得凭空还原(金库仍在,但没有可还原的来源)
    assert EMAIL not in response.text


def test_retry_still_protects_and_restores(http_env):
    """5xx 重试:每一次出网都必须是脱敏后的;重试成功后的还原照常。"""
    mw, client, headers, upstream = http_env(mode="token", max_retries=1)
    upstream.fail_first = 1

    response = _chat(client, headers)
    assert response.status_code == 200, response.text
    assert len(upstream.requests) == 2                 # 真的重试了一次
    for sent in upstream.requests:
        raw = sent["body"].decode("utf-8")
        assert PHONE not in raw and EMAIL not in raw   # 重试不放过任何一次出网
        assert "[CG_TOKEN_" in raw
    assert EMAIL in _reply_text(response)


def test_retries_are_bounded_over_real_http(http_env):
    mw, client, headers, upstream = http_env(mode="token", max_retries=2)
    upstream.fail_first = 99                            # 一直失败

    response = _chat(client, headers)
    assert response.status_code == 502
    assert len(upstream.requests) == 3                  # 1 + 2 次重试,绝不无限重试
    assert PHONE not in response.text and EMAIL not in response.text


# --------------------------------------------------------------------------- #
# 4. 密钥相互独立
# --------------------------------------------------------------------------- #
def test_upstream_key_and_client_key_are_independent(http_env, admin, tmp_path):
    mw, client, headers, upstream = http_env(mode="placeholder")
    client_key = headers["Authorization"].removeprefix("Bearer ")
    response = _chat(client, headers)
    assert response.status_code == 200

    seen = _sent_bodies(upstream)
    assert seen.count(FAKE_UPSTREAM_KEY) >= 1          # 上游密钥只给它自己
    assert client_key not in seen                      # 客户端密钥不出网
    assert "authorization" in seen

    # 上游密钥不回流到客户端:响应体、元数据、健康检查、审计、验证接口都没有
    surfaces = [response.text,
                json.dumps(client.get("/health").json(), ensure_ascii=False),
                json.dumps(client.get("/admin/audit", headers=admin).json(),
                           ensure_ascii=False),
                json.dumps(client.post("/v1/verify", headers=headers,
                                       json={"request_id": response.headers[
                                           "X-CryptoGuard-Request-ID"]}).json(),
                           ensure_ascii=False)]
    for surface in surfaces:
        assert FAKE_UPSTREAM_KEY not in surface
        assert client_key not in surface
    assert FAKE_UPSTREAM_KEY not in _files_text(tmp_path / "data-placeholder")


# --------------------------------------------------------------------------- #
# 5. 审计 / 验证 / 磁盘:全链路无原文
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("mode", MODES)
def test_audit_verify_and_disk_never_hold_original_values(http_env, admin,
                                                          tmp_path, mode):
    mw, client, headers, upstream = http_env(mode=mode)
    response = _chat(client, headers)
    rid = response.headers["X-CryptoGuard-Request-ID"]
    assert response.status_code == 200

    surfaces = {
        "/admin/audit": client.get("/admin/audit", headers=admin),
        f"/admin/audit/{rid}": client.get(f"/admin/audit/{rid}", headers=admin),
        "/admin/security/policies": client.get("/admin/security/policies",
                                               headers=admin),
        "/v1/verify": client.post("/v1/verify", headers=headers,
                                  json={"request_id": rid}),
    }
    for name, surface in surfaces.items():
        assert surface.status_code == 200, name
        body = json.dumps(surface.json(), ensure_ascii=False)
        assert PHONE not in body, f"{name} 泄漏手机号"
        assert EMAIL not in body, f"{name} 泄漏邮箱"

    # 验证接口如实回答「摘要是否匹配」,而不是回答「明文是什么」
    verified = surfaces["/v1/verify"].json()
    assert verified["response_digest_match"] is None     # 没提供待比对响应 → 不表态
    assert "plaintext" not in json.dumps(verified, ensure_ascii=False)

    disk = _files_text(tmp_path / f"data-{mode}")
    assert PHONE not in disk and EMAIL not in disk
    assert mw.audit.verify()["intact"] is True


def test_client_can_recompute_the_response_digest_from_what_it_received(http_env):
    """客户端用**自己收到的响应体**复算响应摘要,必须与记录一致。

    摘要规范(见 /v1/verify 返回的 digest_spec)写明:「对交付给客户端的响应计算,
    客户端可用收到的文本自行复算比对」。但真厂商常见「请求的 model 名 ≠ 响应体里
    advertised 的 model 名」,本文件的假上游正是如此。摘要若绑定上游 advertised 的
    名字,诚实客户端每次复算都会得到 mismatch —— 校验形同摆设(狼来了)。
    """
    mw, client, headers, _ = http_env(mode="placeholder",
                                      subdir="data-digest-recompute")
    response = _chat(client, headers)
    assert response.status_code == 200, response.text
    body = response.json()
    choice = body["choices"][0]
    text = choice["message"]["content"]

    verified = client.post("/v1/verify", headers=headers, json={
        "request_id": response.headers["X-CryptoGuard-Request-ID"],
        "response": {"text": text, "model": body["model"],
                     "finish_reason": choice["finish_reason"]},
    }).json()
    assert verified["found"] is True
    assert verified["failures"] == [], "客户端按交付内容复算摘要却报了不一致"
    assert verified["response_digest_match"] is True

    # 反空转保护:确认上游 advertised 的 model 与请求的 model **确实**不同,
    # 否则本用例证明不了「摘要绑定的是交付形态而非上游自述」。
    divergent = response_digest(text=text, model=UPSTREAM_ADVERTISED_MODEL,
                                finish_reason=choice["finish_reason"])
    assert divergent != verified["response_digest"], (
        "上游 advertised 的 model 与请求 model 未发生分歧,本用例失去意义")


# --------------------------------------------------------------------------- #
# 6. 真实厂商:显式可选,默认跳过
# --------------------------------------------------------------------------- #
@pytest.mark.skipif(not os.environ.get(REAL_KEY_ENV),
                    reason=f"未执行真实厂商联调:未设置 {REAL_KEY_ENV}。"
                           "自动化测试不依赖外网、不产生任何费用;"
                           "需要时显式设置密钥、"
                           f"{REAL_BASE_URL_ENV} 与 CG_REAL_MODEL 后单独运行本用例。")
def test_real_vendor_upstream_opt_in(tmp_path):  # pragma: no cover — 默认跳过
    """可选:真实厂商连通性(需显式提供密钥与模型名)。

    本仓库的自动化测试**从未**访问任何真实模型服务,因此不得把本套件的结果
    表述为「已在真实厂商上验证」。该用例只在运维显式设置密钥时执行,执行前请确认:
    已获得调用授权、报文里不含真实个人数据、且能接受相应的费用。
    """
    from app import main as main_mod
    from app.middleware.config import Settings
    from app.middleware.deps import build_middleware

    key = os.environ[REAL_KEY_ENV]
    base_url = os.environ[REAL_BASE_URL_ENV]
    model = os.environ.get("CG_REAL_MODEL", "")
    assert key and base_url and model, "必须显式提供密钥、base_url 与模型名"

    provider = ProviderSettings(name="real", type="openai-compatible",
                                base_url=base_url, api_key_env=REAL_KEY_ENV,
                                models=(model,))
    settings = Settings(providers=(provider,), default_provider="real",
                        default_model=model, protection_mode="token",
                        allow_anonymous=False,
                        bootstrap_key_file=str(tmp_path / "bootstrap.key"))
    state = build_middleware(tmp_path / "data-real", settings=settings)
    main_mod.app.state.middleware = state
    try:
        client = TestClient(main_mod.app)
        with open(settings.bootstrap_key_file, encoding="utf-8") as handle:
            client_key = handle.read().strip()
        headers = {"Authorization": f"Bearer {client_key}"}
        response = client.post("/v1/chat/completions", headers=headers, json={
            "model": model, "messages": [{"role": "user", "content": PROMPT}]})
        assert response.status_code == 200, response.text
        # 用假值(非真实个人数据)验证脱敏行为在真实链路上同样成立
        assert PHONE not in response.text and EMAIL not in response.text
        assert key not in response.text
    finally:
        delattr(main_mod.app.state, "middleware")
