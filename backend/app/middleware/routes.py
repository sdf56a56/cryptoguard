"""
HTTP 入口 —— /health、/v1/*、/admin/*

挂载方式(见 app/main.py):`middleware.routes.install(app)`。
演示平台已删除；本文件是后端唯一 HTTP 入口（`/v1/*`、`/admin/*`、健康/就绪/指标）。

端点:
  GET  /health                     健康与策略摘要(无需认证,不含任何密钥)
  GET  /v1/models                  OpenAI 兼容模型列表(需客户端认证,除非显式允许匿名)
  POST /v1/chat/completions        OpenAI 兼容补全(非流式/流式)
  POST /v1/messages                Anthropic Messages 入口(Claude Code 等原生客户端)
  POST /v1/responses               OpenAI Responses 入口(Codex 无状态子集)
  GET  /ready                      就绪检查
  GET  /metrics                    Prometheus 文本指标(默认需管理员令牌)
  POST /v1/verify                  校验一次请求的处理记录与摘要(本人或管理员)
  GET  /admin/security/policies    生效策略视图(管理员)
  GET  /admin/audit                审计分页(管理员)
  GET  /admin/audit/{request_id}   单条审计(管理员)
  POST /admin/audit/verify         审计链校验(管理员)
  POST /admin/audit/purge          按保留期清理(管理员,默认 dry_run)
  GET  /admin/clients              客户端密钥列表(管理员,只回显前缀)
  POST /admin/clients              签发客户端密钥(管理员;明文只回一次)
  POST /admin/clients/{id}/revoke  撤销(管理员)
  POST /admin/clients/{id}/rotate  轮换(管理员;明文只回一次)
  PATCH /admin/clients/{id}        更新客户端配置(管理员)
  GET  /admin/providers            提供商视图(管理员)
  POST /admin/providers/{name}/test 上游连通性测试(管理员)
  GET  /admin/dashboard            控制台看板快照(管理员;只读内存计数)
  POST /admin/providers            控制台托管 Provider 新增(热生效)
  PATCH/DELETE /admin/providers/{name} 更新/删除托管 Provider
  PUT  /admin/provider-defaults    设置默认 Provider/模型

安全约束(实现即按此执行):
  - 鉴权先于限流,限流先于上游调用:未认证请求不可能消耗上游额度
    (除显式 CG_ALLOW_ANONYMOUS=1 的开发模式);
  - 管理接口必须持 CG_ADMIN_TOKEN;未配置时 503(而不是放行);
  - 客户端响应与错误体绝不包含上游密钥、Authorization 头或原始敏感值;
  - /v1/verify 默认只允许查询**自己**发起的 request_id(防跨客户端探测);
  - 拒绝类请求的审计:仅对**已认证**的拒绝落审计 —— 否则任何人可用未认证请求
    往磁盘灌记录(DoS 放大),这一取舍在文档中明示。
"""
from __future__ import annotations

import json
import logging
import queue
import threading
import time
from typing import Any

import anyio
from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import ValidationError

from . import anthropic_proto, responses_proto
from .auth import ClientKey
from .confirmations import resolve_confirmation, validate_requested_tokens
from .content_policy import check_anthropic_request, check_openai_request
from .deps import MiddlewareApp, __version__
from .errors import MiddlewareError
from .openai_schemas import (AnthropicMessagesRequest, ChatCompletionRequest,
                             ConfirmationCreateRequest, CryptoGuardDirectiveIn,
                             VerifyRequest, validation_error)
from .metrics import aggregate_histograms, histogram_quantile
from .pipeline import RequestContext
from .policy import resolve_policy
from .provider_config import apply_candidate, managed_meta
from .providers.base import StreamChunk
from .verification import load_digest_spec, recompute_response_digest

logger = logging.getLogger(__name__)

router = APIRouter(tags=["cryptoguard-middleware"])

SSE_HEADERS = {
    "Cache-Control": "no-cache",
    "Connection": "keep-alive",
    "X-Accel-Buffering": "no",
}

#: 只允许透传给客户端的上游响应头(其余一律丢弃,避免信息泄漏)
_PASS_THROUGH_HEADERS = {"retry-after": "Retry-After"}

#: 客户端 last_used 的最小写入间隔(秒):避免每个请求都往客户端日志追加一条
_TOUCH_INTERVAL_S = 300.0
_touch_seen: dict[str, float] = {}
_touch_lock = threading.Lock()


# --------------------------------------------------------------------------- #
# 请求体积限制(只作用于 /v1/* 与 /admin/*)
# --------------------------------------------------------------------------- #
class BodyLimitMiddleware:
    """纯 ASGI 中间件:按 Content-Length 与累计字节数限制请求体。

    超限直接 413(不读完整请求体、不进识别流程)。上限在**请求时**从已装配的
    MiddlewareApp.settings 读取,因此中间件本身无需在装配前拿到配置。
    """

    DEFAULT_MAX_BYTES = 8_388_608

    def __init__(self, app, max_bytes: int | None = None,
                 prefixes: tuple[str, ...] = ("/v1/", "/admin/")):
        self.app = app
        self._fallback = max_bytes or self.DEFAULT_MAX_BYTES
        self.prefixes = prefixes

    def _limit(self, scope) -> int:
        state = getattr(scope.get("app"), "state", None)
        settings = getattr(getattr(state, "middleware", None), "settings", None)
        try:
            return max(1024, int(getattr(settings, "max_request_bytes", 0)
                                 or self._fallback))
        except (TypeError, ValueError):
            return self._fallback

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not str(scope.get("path", "")).startswith(
                self.prefixes):
            await self.app(scope, receive, send)
            return

        path = str(scope.get("path", ""))
        limit = self._limit(scope)
        for name, value in scope.get("headers") or []:
            if name == b"content-length":
                try:
                    if int(value) > limit:
                        await self._too_large(send, path)
                        return
                except ValueError:
                    break

        seen = 0
        started = False

        async def guarded_receive():
            nonlocal seen
            message = await receive()
            if message["type"] == "http.request":
                seen += len(message.get("body", b""))
                if seen > limit:
                    raise _BodyTooLarge()
            return message

        async def guarded_send(message):
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, guarded_receive, guarded_send)
        except _BodyTooLarge:
            if not started:
                await self._too_large(send, path)

    @staticmethod
    async def _too_large(send, path: str = "") -> None:
        """413 按入口协议返回正确形状：Anthropic /v1/messages 与 OpenAI 不同。"""
        message = "请求体超过网关上限（CG_MAX_REQUEST_BYTES）"
        if path.startswith("/v1/messages"):
            payload = {"type": "error", "error": {
                "type": "invalid_request_error", "message": message}}
        else:
            payload = {"error": {"message": message, "type": "invalid_request_error",
                                 "code": "request_too_large", "param": None}}
        body = json.dumps(payload, ensure_ascii=False)
        await send({"type": "http.response.start", "status": 413, "headers": [
            (b"content-type", b"application/json; charset=utf-8"),
            (b"connection", b"close"),
        ]})
        await send({"type": "http.response.body", "body": body.encode("utf-8")})


class _BodyTooLarge(Exception):
    """内部信号:请求体超限(由 BodyLimitMiddleware 捕获并转 413)。"""


# --------------------------------------------------------------------------- #
# 认证 / 限流 / 错误响应
# --------------------------------------------------------------------------- #
def _app(request: Request) -> MiddlewareApp:
    app: MiddlewareApp | None = getattr(request.app.state, "middleware", None)
    if app is None:
        raise MiddlewareError(
            "config",
            "中间件未装配:请检查启动日志(CG_NO_BOOT=1 时 /v1/* 不可用)")
    return app


def _presented_key(request: Request) -> str:
    """客户端凭证:OpenAI 风格 `Authorization: Bearer`,或 Anthropic 风格 `x-api-key`。"""
    header = request.headers.get("authorization") or ""
    if header.lower().startswith("bearer "):
        return header[7:].strip()
    return (request.headers.get("x-api-key") or "").strip()


def _require_client(request: Request, app: MiddlewareApp) -> ClientKey | None:
    """解析并校验客户端密钥;未认证且不允许匿名时抛 auth 错误。"""
    presented = _presented_key(request)
    if presented:
        return app.clients.authenticate(presented)
    if app.settings.allow_anonymous:
        return None
    raise MiddlewareError(
        "auth",
        "缺少客户端密钥:请在请求头 Authorization 中提供 Bearer <cgk_...>,"
        "或使用请求头 x-api-key(本部署未开启匿名调用)")


def _require_admin(request: Request, app: MiddlewareApp) -> str:
    """校验管理员令牌（单用户、全权；不存在只读角色）。"""
    return app.admin.require(request.headers.get("x-admin-token"))


def _limit_key(request: Request, client: ClientKey | None) -> str:
    if client is not None:
        return f"client:{client.id}"
    host = request.client.host if request.client else "unknown"
    return f"anon:{host}"


def _enforce_rate(app: MiddlewareApp, request: Request, client: ClientKey | None) -> None:
    limit = (client.rate_limit_per_min if client and client.rate_limit_per_min
             else app.settings.rate_limit_per_min)
    if limit <= 0:
        return
    allowed, retry_after = app.limiter.check(_limit_key(request, client), limit)
    if not allowed:
        raise MiddlewareError("rate_limit", f"请求过于频繁(上限 {limit}/分钟)",
                              headers={"Retry-After": f"{max(1, int(retry_after))}"})


def _error_headers(exc: MiddlewareError, ctx: RequestContext | None) -> dict:
    headers: dict[str, str] = {}
    for name, value in (exc.headers or {}).items():
        target = _PASS_THROUGH_HEADERS.get(str(name).lower())
        if target and value:
            headers[target] = str(value)
    if ctx is not None:
        headers["X-CryptoGuard-Request-ID"] = ctx.request_id
    return headers


def _fail(exc: MiddlewareError, *, anthropic: bool = False,
          ctx: RequestContext | None = None,
          app: MiddlewareApp | None = None) -> JSONResponse:
    """统一错误响应:错误体已分类、已脱敏;只透传 Retry-After。

    已认证的拒绝会落审计(audit_reject);未认证的拒绝**不落审计**,避免任何人
    用无效凭证往磁盘灌记录。
    """
    if app is not None and ctx is not None and ctx.client_id:
        try:
            app.pipeline.audit_reject(ctx, exc)
        except Exception as audit_exc:  # noqa: BLE001 — 审计失败不能掩盖原始错误
            logger.critical("audit_reject_failed(rid=%s): %s", ctx.request_id, audit_exc)
    if exc.kind in ("auth", "forbidden", "rate_limit", "blocked", "timeout", "network",
                    "upstream_4xx", "upstream_5xx", "protocol"):
        logger.warning("request_rejected: kind=%s rid=%s detail=%s", exc.kind,
                       getattr(ctx, "request_id", "-"), exc.detail)
    body = exc.anthropic_body() if anthropic else exc.openai_body()
    if anthropic:
        body["request_id"] = ctx.request_id if ctx else None
    else:
        body["error"]["request_id"] = ctx.request_id if ctx else None
    return JSONResponse(status_code=exc.http_status, content=body,
                        headers=_error_headers(exc, ctx))


async def _read_json(request: Request) -> dict:
    try:
        raw = await request.json()
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise MiddlewareError("invalid_request", "请求体不是合法 JSON") from None
    if not isinstance(raw, dict):
        raise MiddlewareError("invalid_request", "请求体必须是 JSON 对象")
    return raw


def _client_view(client: ClientKey | None) -> tuple[str, str]:
    if client is None:
        return "", "anonymous"
    return client.id, client.name


def _idempotency_scope(request: Request, app: MiddlewareApp,
                       client: ClientKey | None, raw: dict,
                       stream: bool) -> tuple[str, str] | None:
    """解析 Idempotency-Key；返回 (scope, digest) 或 None。

    只支持非流式：流式响应无法可靠重放，带 key 直接显式拒绝。
    """
    key = (request.headers.get("idempotency-key")
           or request.headers.get("x-idempotency-key") or "").strip()
    if not key:
        return None
    if len(key) > 200:
        raise MiddlewareError("invalid_request", "Idempotency-Key 长度不能超过 200")
    if stream:
        raise MiddlewareError(
            "invalid_request",
            "流式请求不支持 Idempotency-Key（无法可靠重放 SSE）；请改用非流式或去掉该头")
    if client is None:
        raise MiddlewareError("forbidden", "Idempotency-Key 需要具名客户端密钥")
    if app.idempotency is None:  # pragma: no cover - 装配期总会创建
        return None
    return (app.idempotency.scope(client.id, key),
            app.idempotency.request_digest(raw))


def _replay_cached(app: MiddlewareApp, ctx: RequestContext, cached: dict) -> Response:
    """返回已封缄的成功响应；不调用上游，写一条 replay 审计。"""
    headers = {key: value for key, value in (cached.get("headers") or {}).items()
               if key.lower() not in ("content-length", "content-type", "transfer-encoding")}
    headers["X-CryptoGuard-Idempotent-Replay"] = "1"
    app.metrics.inc("idempotent_replays_total")
    app.pipeline.audit_event(ctx, outcome="idempotent_replay", actions={
        "idempotent_replayed": True,
        "original_request_id": cached.get("request_id") or "",
        "note": "命中幂等缓存，未调用上游；响应由 AEAD 封缄缓存解密后原样返回",
    })
    return JSONResponse(status_code=int(cached.get("status") or 200),
                        content=cached.get("body") or {}, headers=headers)


def _touch_client(app: MiddlewareApp, client: ClientKey | None) -> None:
    """记录最近使用时间(节流:同一客户端 5 分钟内只写一次)。"""
    if client is None:
        return
    now = time.monotonic()
    with _touch_lock:
        last = _touch_seen.get(client.id, 0.0)
        if now - last < _TOUCH_INTERVAL_S:
            return
        if len(_touch_seen) > 4096:
            _touch_seen.clear()
        _touch_seen[client.id] = now
    app.clients.touch(client.id)


def _check_provider_params(provider, params: dict) -> None:
    """OpenAI 专有参数不能静默丢给 Anthropic 上游。"""
    if getattr(getattr(provider, "config", None), "type", "") != "anthropic":
        return
    unsupported = sorted(name for name, value in params.items() if value is not None)
    if unsupported:
        raise MiddlewareError(
            "invalid_request",
            f"参数 {unsupported} 仅支持 openai-compatible 上游；"
            "当前解析到 anthropic 上游，拒绝静默丢弃")


def _check_model_allowed(client: ClientKey | None, model: str) -> None:
    """客户端级模型白名单(管理员按 key 授予;空表示跟随全局)。"""
    if client is None or not client.models:
        return
    if model not in client.models:
        raise MiddlewareError(
            "forbidden",
            f"该客户端密钥不允许使用模型 {model!r}(允许: {sorted(client.models)})")


# --------------------------------------------------------------------------- #
# 健康与模型列表
# --------------------------------------------------------------------------- #
@router.get("/health")
def health(request: Request) -> Response:
    app: MiddlewareApp | None = getattr(request.app.state, "middleware", None)
    if app is None:
        startup_error = str(getattr(request.app.state, "middleware_error", "") or "")
        return JSONResponse(status_code=503, content={
            "status": "unavailable",
            "detail": startup_error or
                      "中间件未装配(见启动日志;CG_NO_BOOT=1 时 /v1/* 不可用)",
        })
    return JSONResponse(content=app.health())


@router.get("/ready")
def ready(request: Request) -> Response:
    """就绪检查：装配 / provider / 审计链（不调用上游、不返回密钥）。"""
    app: MiddlewareApp | None = getattr(request.app.state, "middleware", None)
    if app is None:
        return JSONResponse(status_code=503, content={
            "ready": False, "checks": {"middleware": False},
        })
    checks: dict = {"middleware": True}
    try:
        checks["providers"] = any(
            view.get("configured") for view in _provider_health(app))
    except Exception:  # noqa: BLE001 — 就绪检查自身不能 500
        checks["providers"] = False
    try:
        checks["audit_chain"] = bool(app.audit.verify(full=False).get("intact"))
    except Exception:  # noqa: BLE001
        checks["audit_chain"] = False
    lock = getattr(request.app.state, "instance_lock", None)
    checks["instance_lock"] = bool(getattr(lock, "held", False))
    # 测试/未走 lifespan 的装配没有锁；只在配置要求锁时把它作为提示，不因此判死。
    required = bool(app.settings.instance_lock)
    ok = checks["middleware"] and checks["providers"] and checks["audit_chain"]
    if required and not checks["instance_lock"]:
        checks["instance_lock_note"] = "lifespan 未运行或 CG_INSTANCE_LOCK=0"
    return JSONResponse(status_code=200 if ok else 503,
                        content={"ready": ok, "checks": checks})


@router.get("/metrics")
def metrics(request: Request) -> Response:
    """Prometheus 文本指标；默认需要管理员令牌。"""
    app: MiddlewareApp | None = None
    try:
        app = _app(request)
        if not app.settings.metrics_public:
            _require_admin(request, app)
    except MiddlewareError as exc:
        return _fail(exc, app=app)
    return Response(content=app.metrics.render(),
                    media_type="text/plain; version=0.0.4; charset=utf-8")


def _provider_health(app: MiddlewareApp) -> list[dict]:
    """provider 运行期视图（不触发上游调用）。"""
    return app.registry.health().get("providers") or []


@router.get("/v1/models")
def list_models(request: Request) -> Response:
    app: MiddlewareApp | None = None
    try:
        app = _app(request)
        client = _require_client(request, app)
        _enforce_rate(app, request, client)
        models = app.registry.models_view(created=int(time.time()))
        capabilities = {
            "streaming": True,
            "tools": True,
            "anthropic_messages": True,
            "responses": True,
            "images": app.settings.image_policy,
            "documents": app.settings.document_policy,
        }
        for model in models:
            model["capabilities"] = dict(capabilities)
        if client is not None and client.models:
            allowed = set(client.models)
            models = [m for m in models if m["id"] in allowed]
        return JSONResponse(content={
            "object": "list",
            "data": models,
            "cryptoguard": {"policy": app.settings.public_policy(),
                            "capabilities": capabilities},
        })
    except MiddlewareError as exc:
        return _fail(exc, app=app)


# --------------------------------------------------------------------------- #
# OpenAI 兼容补全
# --------------------------------------------------------------------------- #
@router.post("/v1/chat/completions")
async def chat_completions(request: Request) -> Response:
    ctx = RequestContext(endpoint="/v1/chat/completions")
    app: MiddlewareApp | None = None
    try:
        app = _app(request)
        client = _require_client(request, app)
        _enforce_rate(app, request, client)
        raw = await _read_json(request)
        try:
            body = ChatCompletionRequest.model_validate(raw)
        except ValidationError as exc:
            raise validation_error(exc) from None
        ignored = body.check_supported()
        content = check_openai_request(body.model_dump(), app.settings)
        ignored.extend(content.ignored)
        ctx.client_id, ctx.client_name = _client_view(client)
        ctx.requested_model = body.model
        ctx.stream = bool(body.stream)

        policy = resolve_policy(app.settings, body.cryptoguard, client)
        policy.ignored_fields = list(dict.fromkeys(ignored))
        policy.unprotected_content = dict(content.unprotected)
        policy.dropped_content = dict(content.dropped)
        ctx.policy_version = policy.policy_version
        ctx.protection_mode = policy.protection_mode
        _check_model_allowed(client, body.model)
        # 提前解析一次:模型不可用时立即 404,不必等进到 pipeline 才发现
        provider, _ = app.registry.resolve(body.model)
        _check_provider_params(provider, {
            "reasoning_effort": body.reasoning_effort,
            "verbosity": body.verbosity,
        })

        stream_options = (body.stream_options.model_dump(exclude_none=True)
                          if body.stream_options else None)
        neutral = body.to_neutral(model=body.model,
                                  max_tokens=body.effective_max_tokens(),
                                  stream_options=stream_options)
        if neutral.stream and neutral.stream_options is None:
            # 默认请求上游回 usage(只影响末帧是否带用量,不改变正文)
            neutral.stream_options = {"include_usage": True}
        idem = _idempotency_scope(request, app, client, raw, neutral.stream)
        if idem is not None:
            cached = app.idempotency.get(*idem)
            if cached is not None:
                return _replay_cached(app, ctx, cached)
    except MiddlewareError as exc:
        return _fail(exc, ctx=ctx, app=app)

    if not neutral.stream:
        return await _run_sync(app, ctx, neutral, policy, client, idem=idem)
    return _run_stream(app, ctx, neutral, policy, client)


@router.post("/v1/messages")
async def anthropic_messages(request: Request) -> Response:
    """Anthropic Messages 入口(Claude Code 等原生客户端)。"""
    ctx = RequestContext(endpoint="/v1/messages")
    app: MiddlewareApp | None = None
    try:
        app = _app(request)
        client = _require_client(request, app)
        _enforce_rate(app, request, client)
        raw = await _read_json(request)
        try:
            body = AnthropicMessagesRequest.model_validate(raw)
        except ValidationError as exc:
            raise validation_error(exc) from None
        ignored = body.check_supported(app.settings)
        content = check_anthropic_request(body.model_dump(), app.settings)
        ignored.extend(content.ignored)
        ctx.client_id, ctx.client_name = _client_view(client)
        ctx.requested_model = body.model
        ctx.stream = bool(body.stream)

        directive = None
        if isinstance(raw.get("cryptoguard"), dict):
            try:
                directive = CryptoGuardDirectiveIn.model_validate(raw["cryptoguard"])
            except ValidationError as exc:
                raise validation_error(exc) from None
        policy = resolve_policy(app.settings, directive, client)
        policy.ignored_fields = list(dict.fromkeys(ignored))
        policy.unprotected_content = dict(content.unprotected)
        policy.dropped_content = dict(content.dropped)
        ctx.policy_version = policy.policy_version
        ctx.protection_mode = policy.protection_mode
        _check_model_allowed(client, body.model)
        app.registry.resolve(body.model)

        neutral = body.to_neutral(model=body.model)
        if neutral.stream and neutral.stream_options is None:
            neutral.stream_options = {"include_usage": True}
        idem = _idempotency_scope(request, app, client, raw, neutral.stream)
        if idem is not None:
            cached = app.idempotency.get(*idem)
            if cached is not None:
                return _replay_cached(app, ctx, cached)
    except MiddlewareError as exc:
        return _fail(exc, anthropic=True, ctx=ctx, app=app)

    if not neutral.stream:
        return await _run_sync(app, ctx, neutral, policy, client, protocol="anthropic",
                               idem=idem)
    return _run_stream(app, ctx, neutral, policy, client, protocol="anthropic")


@router.post("/v1/responses")
async def openai_responses(request: Request) -> Response:
    """OpenAI Responses 入口（Codex 当前唯一协议；无状态最小子集）。"""
    ctx = RequestContext(endpoint="/v1/responses")
    app: MiddlewareApp | None = None
    try:
        app = _app(request)
        client = _require_client(request, app)
        _enforce_rate(app, request, client)
        raw = await _read_json(request)
        body = responses_proto.from_responses_request(raw)
        content = check_openai_request(raw, app.settings)
        ignored = list(body.ignored_fields) + list(content.ignored)

        ctx.client_id, ctx.client_name = _client_view(client)
        ctx.requested_model = body.model
        ctx.stream = bool(body.stream)

        directive = None
        if isinstance(raw.get("cryptoguard"), dict):
            try:
                directive = CryptoGuardDirectiveIn.model_validate(raw["cryptoguard"])
            except ValidationError as exc:
                raise validation_error(exc) from None
        policy = resolve_policy(app.settings, directive, client)
        policy.ignored_fields = list(dict.fromkeys(ignored))
        policy.unprotected_content = dict(content.unprotected)
        policy.dropped_content = dict(content.dropped)
        ctx.policy_version = policy.policy_version
        ctx.protection_mode = policy.protection_mode
        _check_model_allowed(client, body.model)
        provider, _ = app.registry.resolve(body.model)
        _check_provider_params(provider, {
            "reasoning_effort": body.reasoning_effort,
            "verbosity": body.verbosity,
            "prompt_cache_key": body.prompt_cache_key,
        })

        neutral = body.to_neutral(model=body.model)
        if neutral.stream and neutral.stream_options is None:
            neutral.stream_options = {"include_usage": True}
        idem = _idempotency_scope(request, app, client, raw, neutral.stream)
        if idem is not None:
            cached = app.idempotency.get(*idem)
            if cached is not None:
                return _replay_cached(app, ctx, cached)
    except MiddlewareError as exc:
        return _fail(exc, ctx=ctx, app=app)

    if not neutral.stream:
        return await _run_sync(app, ctx, neutral, policy, client,
                               protocol="responses", idem=idem)
    return _run_stream(app, ctx, neutral, policy, client, protocol="responses")


# --------------------------------------------------------------------------- #
# 非流式执行
# --------------------------------------------------------------------------- #
async def _run_sync(app: MiddlewareApp, ctx: RequestContext, neutral,
                    policy, client: ClientKey | None,
                    protocol: str = "openai",
                    idem: tuple[str, str] | None = None) -> Response:
    def work() -> tuple[dict, dict]:
        with app.concurrency:                      # 并发闸只罩住上游调用
            prepared = app.pipeline.prepare(ctx, neutral, policy)
            completion, meta = app.pipeline.complete(prepared)
        if protocol == "anthropic":
            payload = anthropic_proto.anthropic_response(
                completion, request_id=ctx.request_id, model=ctx.requested_model,
                cryptoguard=meta)
        elif protocol == "responses":
            payload = responses_proto.response_from_completion(
                completion, request_id=ctx.request_id, model=ctx.requested_model,
                created=ctx.created, cryptoguard=meta)
        else:
            payload = anthropic_proto.openai_response(
                completion, request_id=ctx.request_id, model=ctx.requested_model,
                created=ctx.created, cryptoguard=meta)
        return payload, _success_headers(meta, ctx)

    try:
        payload, headers = await anyio.to_thread.run_sync(work)
    except MiddlewareError as exc:
        return _fail(exc, anthropic=(protocol == "anthropic"), ctx=ctx, app=app)
    except Exception as exc:  # noqa: BLE001 — 兜底:不把栈透给客户端
        logger.exception("middleware_unhandled(rid=%s)", ctx.request_id)
        return _fail(MiddlewareError("internal", f"中间件内部错误: {type(exc).__name__}"),
                     anthropic=(protocol == "anthropic"), ctx=ctx, app=app)
    _touch_client(app, client)
    if idem is not None and app.idempotency is not None:
        try:
            app.idempotency.put(idem[0], idem[1], payload, status=200,
                                headers=headers, request_id=ctx.request_id)
        except Exception:  # noqa: BLE001 — 幂等缓存失败不能把成功响应变成 500
            logger.warning("idempotency_cache_failed", exc_info=True)
    return JSONResponse(content=payload, headers=headers)


def _success_headers(meta: dict, ctx: RequestContext) -> dict:
    digest = meta.get("digest") or {}
    audit = meta.get("audit") or {}
    return {
        "X-CryptoGuard-Request-ID": ctx.request_id,
        "X-CryptoGuard-Policy-Version": str(meta.get("policy_version") or ""),
        "X-CryptoGuard-Protection-Mode": str(meta.get("protection_mode") or ""),
        "X-CryptoGuard-Provider": str(meta.get("provider") or ""),
        "X-CryptoGuard-Upstream-Model": str(meta.get("upstream_model") or ""),
        "X-CryptoGuard-Request-Digest": str(digest.get("request") or ""),
        "X-CryptoGuard-Response-Digest": str(digest.get("response") or ""),
        "X-CryptoGuard-Audit-Seq": str(audit.get("seq") or ""),
        "X-CryptoGuard-Detected": str((meta.get("detected") or {}).get("total") or 0),
        "X-CryptoGuard-Content-Policy": _content_policy_header(meta.get("content_policy") or {}),
    }


def _content_policy_header(policy: dict) -> str:
    """内容面处置的单行摘要（ASCII，避免响应头编码问题）。"""
    if not isinstance(policy, dict) or not policy:
        return ""
    parts = []
    for key in ("images", "documents", "anthropic_thinking", "cache_control"):
        if key in policy:
            parts.append(f"{key}={policy[key]}")
    return ";".join(parts)


# --------------------------------------------------------------------------- #
# 流式执行
# --------------------------------------------------------------------------- #
def _run_stream(app: MiddlewareApp, ctx: RequestContext, neutral,
                policy, client: ClientKey | None,
                protocol: str = "openai") -> Response:
    """流式:准备(保护)同步完成后立即返回 SSE;上游在后台线程里跑。"""
    try:
        prepared = app.pipeline.prepare(ctx, neutral, policy)
    except MiddlewareError as exc:
        # 出站保护阶段的拒绝(阻断档/配置缺失)必须走统一错误体:
        # 此处**尚未发出任何 SSE 帧**,可以正常回 4xx,而不是 500 裸异常。
        return _fail(exc, anthropic=(protocol == "anthropic"), ctx=ctx, app=app)
    state = prepared.stream_state

    headers = {
        "Content-Type": "text/event-stream; charset=utf-8",
        "X-CryptoGuard-Request-ID": ctx.request_id,
        "X-CryptoGuard-Policy-Version": policy.policy_version,
        "X-CryptoGuard-Protection-Mode": policy.protection_mode,
        "X-CryptoGuard-Detected": str(prepared.detections.get("total") or 0),
        "X-CryptoGuard-Content-Policy": _content_policy_header(prepared.policy.content_policy),
        "X-CryptoGuard-Stream": "1",
        # 流式响应头在首字节前发出,此时摘要尚未产生;最终摘要随末帧元数据下发
        "X-CryptoGuard-Digest-Deferred": "1",
        **SSE_HEADERS,
    }

    def guarded_stream():
        with app.concurrency:
            yield from app.pipeline.stream(prepared)

    pump = _StreamPump(guarded_stream())
    if protocol == "anthropic":
        encoder = _AnthropicStreamEncoder(ctx, prepared)
    elif protocol == "responses":
        encoder = _ResponsesStreamEncoder(ctx, prepared)
    else:
        encoder = _OpenAIStreamEncoder(ctx, prepared)

    def finalize() -> dict | None:
        """算摘要 + 写审计;失败只记日志(调用方据 None 在正文里报不可验证)。"""
        try:
            return app.pipeline.finish_stream(prepared, state)
        except Exception as exc:  # noqa: BLE001
            logger.critical("stream_finalize_failed(rid=%s): %s", ctx.request_id, exc)
            return None

    async def event_source():
        finalized = False
        heartbeat = float(getattr(app.settings, "sse_heartbeat_s", 0) or 0)
        poll = min(1.0, heartbeat) if heartbeat > 0 else None
        last_ping = time.monotonic()
        try:
            yield encoder.start()
            while True:
                kind, item = await anyio.to_thread.run_sync(pump.next, poll)
                if kind == "timeout":
                    now = time.monotonic()
                    if heartbeat > 0 and now - last_ping >= heartbeat:
                        last_ping = now
                        app.metrics.inc("sse_heartbeats_total")
                        # SSE 注释帧：所有客户端都应忽略，代理/负载均衡则视为活跃
                        yield ": ping\n\n"
                    continue
                if kind == "end":
                    break
                if kind == "error":
                    raise item
                yield encoder.encode(item)
                if item.kind == "done":
                    break
            meta = finalize()
            finalized = True
            if meta is None:
                yield encoder.error(MiddlewareError(
                    "internal", "审计记录写入失败:本次响应不可验证(fail-closed)"))
            else:
                yield encoder.finish(state, meta)
        except anyio.get_cancelled_exc_class():
            # 客户端断开:关闭上游连接(停止继续计费),但仍要留审计
            pump.cancel()
            if not finalized:
                finalize()
                finalized = True
            _touch_client(app, client)
            raise
        except MiddlewareError as exc:
            logger.warning("stream_failed: kind=%s rid=%s", exc.kind, ctx.request_id)
            yield encoder.error(exc)
        except Exception as exc:  # noqa: BLE001
            logger.exception("stream_unhandled(rid=%s)", ctx.request_id)
            yield encoder.error(MiddlewareError("internal",
                                                f"流式内部错误: {type(exc).__name__}"))
        finally:
            pump.cancel()
            if not finalized:
                finalize()
            _touch_client(app, client)

    return StreamingResponse(event_source(), status_code=200, headers=headers)


class _StreamPump:
    """同步生成器 → 异步消费的有界队列泵;取消时关闭生成器以断开上游连接。

    取消语义:后台线程在生成器被 close() 时收到 GeneratorExit,provider 里
    `with client.stream(...)` 随之退出 → 上游 HTTP 连接被关闭(不再继续计费)。
    """

    def __init__(self, gen, maxsize: int = 64) -> None:
        self._gen = gen
        self._queue: queue.Queue = queue.Queue(maxsize=maxsize)
        self._cancelled = threading.Event()
        self._thread = threading.Thread(target=self._run, name="cg-mw-stream",
                                        daemon=True)
        self._thread.start()

    def _run(self) -> None:
        try:
            for item in self._gen:
                if self._cancelled.is_set():
                    break
                while not self._cancelled.is_set():
                    try:
                        self._queue.put(("item", item), timeout=0.2)
                        break
                    except queue.Full:
                        continue
                else:
                    break
        except BaseException as exc:  # noqa: BLE001 — 任何异常都转交异步侧
            self._queue.put(("error", exc))
        finally:
            try:
                self._gen.close()
            except BaseException:  # noqa: BLE001
                pass
            self._queue.put(("end", None))

    def cancel(self) -> None:
        self._cancelled.set()

    def next(self, timeout: float | None = None) -> tuple[str, Any]:
        """取下一项；timeout 秒内无数据返回 ("timeout", None)（供 SSE 心跳）。"""
        if timeout is None:
            return self._queue.get()
        try:
            return self._queue.get(timeout=max(0.01, float(timeout)))
        except queue.Empty:
            return ("timeout", None)


# --------------------------------------------------------------------------- #
# SSE 编码器(OpenAI / Anthropic 各一套,只负责把中立增量翻译成线格式)
# --------------------------------------------------------------------------- #
class _OpenAIStreamEncoder:
    """中立 StreamChunk → OpenAI `chat.completion.chunk` SSE。"""

    def __init__(self, ctx: RequestContext, prepared) -> None:
        self._ctx = ctx
        self._prepared = prepared

    def _frame(self, delta: dict, finish_reason: str | None = None,
               extra: dict | None = None) -> str:
        body: dict = {
            "id": self._ctx.request_id,
            "object": "chat.completion.chunk",
            "created": self._ctx.created,
            "model": self._ctx.requested_model,
            "choices": [{"index": 0, "delta": delta, "logprobs": None,
                         "finish_reason": finish_reason}],
            "system_fingerprint": None,
        }
        if extra:
            body.update(extra)
        return f"data: {json.dumps(body, ensure_ascii=False)}\n\n"

    def start(self) -> str:
        return self._frame({"role": "assistant", "content": ""})

    def encode(self, chunk: StreamChunk) -> str:
        if chunk.kind == "text":
            return self._frame({"content": chunk.text})
        if chunk.kind == "reasoning":
            return self._frame({"reasoning_content": chunk.text})
        if chunk.kind == "tool_call":
            call: dict = {"index": int(chunk.tool_index), "type": "function",
                          "function": {}}
            if chunk.tool_id:
                call["id"] = chunk.tool_id
            if chunk.tool_name:
                call["function"]["name"] = chunk.tool_name
            if chunk.tool_arguments:
                call["function"]["arguments"] = chunk.tool_arguments
            return self._frame({"tool_calls": [call]})
        if chunk.kind == "usage":
            return self._frame({}, extra={"usage": chunk.usage or {}})
        # done 帧不在此处宣告 finish_reason:末帧(写完审计后)统一给出,
        # 避免在尚无摘要时就发出结束标记
        return ""

    def error(self, exc: MiddlewareError) -> str:
        """流式错误:HTTP 头已发出,不能改状态码,改以错误对象 + [DONE] 收尾。"""
        body = {"error": {**exc.openai_body()["error"],
                          "request_id": self._ctx.request_id}}
        return f"data: {json.dumps(body, ensure_ascii=False)}\n\ndata: [DONE]\n\n"

    def finish(self, state, meta: dict) -> str:
        """末帧:finish_reason + usage + cryptoguard 元数据(含两侧摘要),随后 [DONE]。"""
        body: dict = {
            "id": self._ctx.request_id,
            "object": "chat.completion.chunk",
            "created": self._ctx.created,
            "model": self._ctx.requested_model,
            "choices": [{"index": 0, "delta": {}, "logprobs": None,
                         "finish_reason": state.finish_reason or "stop"}],
            "system_fingerprint": None,
            "usage": state.usage or {},
            "cryptoguard": meta,
        }
        return f"data: {json.dumps(body, ensure_ascii=False)}\n\ndata: [DONE]\n\n"


class _AnthropicStreamEncoder:
    """中立 StreamChunk → Anthropic Messages SSE(委托 anthropic_proto 翻译器)。"""

    def __init__(self, ctx: RequestContext, prepared) -> None:
        self._ctx = ctx
        self._prepared = prepared
        self._translator = anthropic_proto.AnthropicStreamTranslator(
            model=ctx.requested_model, request_id=ctx.request_id)

    @staticmethod
    def _events(events: list[tuple[str, dict]]) -> str:
        return "".join(anthropic_proto.sse_encode(name, payload)
                       for name, payload in events)

    def start(self) -> str:
        return self._events(self._translator.start())

    def encode(self, chunk: StreamChunk) -> str:
        return self._events(self._translator.feed(chunk))

    def error(self, exc: MiddlewareError) -> str:
        payload = {"type": "error", "error": exc.anthropic_body()["error"],
                   "request_id": self._ctx.request_id}
        return f"event: error\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n"

    def finish(self, state, meta: dict) -> str:
        self._translator.cryptoguard = meta
        return self._events(self._translator.finish(incomplete=not state.complete))


class _ResponsesStreamEncoder:
    """中立 StreamChunk → OpenAI Responses SSE(委托 responses_proto 翻译器)。"""

    def __init__(self, ctx: RequestContext, prepared) -> None:
        self._ctx = ctx
        self._translator = responses_proto.ResponsesStreamTranslator(
            model=ctx.requested_model, request_id=ctx.request_id,
            created=ctx.created)

    @staticmethod
    def _events(events: list[tuple[str, dict]]) -> str:
        return "".join(
            f"event: {name}\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n"
            for name, payload in events)

    def start(self) -> str:
        return self._events(self._translator.start())

    def encode(self, chunk: StreamChunk) -> str:
        return self._events(self._translator.feed(chunk))

    def error(self, exc: MiddlewareError) -> str:
        return self._events(self._translator.error(exc))

    def finish(self, state, meta: dict) -> str:
        self._translator.cryptoguard = meta
        return self._events(self._translator.finish(incomplete=not state.complete))


# --------------------------------------------------------------------------- #
# /v1/verify
# --------------------------------------------------------------------------- #
@router.post("/v1/verify")
async def verify(request: Request) -> Response:
    """校验一次请求的处理记录:存在性 / 摘要一致性 / 审计链完整性 / 所用策略版本。

    权限:默认只能查询自己发起的 request_id;持管理员令牌可查任意记录。
    """
    app: MiddlewareApp | None = None
    try:
        app = _app(request)
        client = _require_client(request, app)
        _enforce_rate(app, request, client)
        raw = await _read_json(request)
        try:
            body = VerifyRequest.model_validate(raw)
        except ValidationError as exc:
            raise validation_error(exc) from None
        admin = False
        if request.headers.get("x-admin-token"):
            _require_admin(request, app)
            admin = True
        record = app.audit.get(body.request_id)
    except MiddlewareError as exc:
        return _fail(exc, app=app)

    chain = _chain_view(app)
    if record is None:
        return JSONResponse(content={
            "found": False,
            "request_id": body.request_id,
            "reason": "审计日志中没有该 request_id(可能超出保留期,或从未经过本中间件)",
            "policy_version": None,
            "failures": ["not_found"],
            "chain": chain,
        })
    if not admin and (client is None or record.get("client_id") != client.id):
        return JSONResponse(status_code=403, content={
            "found": True,
            "request_id": body.request_id,
            "reason": "该记录不属于当前客户端密钥;如需查询请使用管理员令牌",
            "failures": ["forbidden"],
        })

    failures: list[str] = []
    request_digest_match: bool | None = None
    if body.request_digest:
        request_digest_match = body.request_digest == record.get("request_digest")
        if not request_digest_match:
            failures.append("request_digest_mismatch")

    response_digest_match: bool | None = None
    if body.response is not None:
        try:
            recomputed = recompute_response_digest(body.response)
        except MiddlewareError as exc:
            return _fail(exc, app=app)
        response_digest_match = recomputed == record.get("response_digest")
        if not response_digest_match:
            failures.append("response_digest_mismatch")
    elif body.response_digest:
        response_digest_match = body.response_digest == record.get("response_digest")
        if not response_digest_match:
            failures.append("response_digest_mismatch")

    if chain.get("intact") is False:
        failures.append("audit_chain_broken")

    return JSONResponse(content={
        "found": True,
        "request_id": body.request_id,
        "policy_version": record.get("policy_version"),
        "protection_mode": record.get("protection_mode"),
        "provider": record.get("provider"),
        "upstream_model": record.get("upstream_model"),
        "outcome": record.get("outcome"),
        "error_kind": record.get("error_kind") or None,
        "request_digest": record.get("request_digest"),
        "response_digest": record.get("response_digest"),
        "request_digest_match": request_digest_match,
        "response_digest_match": response_digest_match,
        "record_mac_valid": app.audit.mac_valid(record),
        "chain": chain,
        "detections": record.get("detections") or {},
        "actions": record.get("actions") or {},
        "restore": record.get("restored") or {},
        "audit": {"seq": record.get("seq"), "chain_hash": record.get("chain_hash"),
                  "prev_hash": record.get("prev_hash")},
        "failures": failures,
        "digest_spec": load_digest_spec(),
        "boundary": {
            "hash_meaning": "摘要只检测「是否被改动」;不证明模型回答的事实正确性",
            "provider_identity": "本记录由本地网关生成,不代表模型服务商的签名",
            "admin_tamper": "持 VAULT_KEY 的管理员可整链重写;检测该情形需外部锚点",
            "write_scope": "verify 只读审计日志,不重新调用上游",
        },
    })


def _chain_view(app: MiddlewareApp | None) -> dict:
    if app is None:
        return {"intact": False, "error": "middleware_not_built"}
    try:
        result = app.audit.verify()
    except Exception as exc:  # noqa: BLE001 — 校验不了就如实报告,不给「完整」结论
        return {"intact": False, "error": f"{type(exc).__name__}: {exc}"}
    return {"intact": result["intact"], "records": result["records"],
            "first_seq": result["first_seq"], "last_seq": result["last_seq"],
            "mac_verified": result["mac_verified"], "failures": result["failures"],
            "tip_hash": result["tip_hash"], "anchor": result["anchor"],
            "scope_note": result.get("scope_note", "")}


def _count_confirmation(app: MiddlewareApp, status: str) -> None:
    try:
        app.metrics.inc("confirmations_total", {"status": status})
    except Exception:  # noqa: BLE001 — 指标失败不影响控制面
        logger.debug("metrics_confirmation_failed", exc_info=True)


# --------------------------------------------------------------------------- #
# 人工确认(高风险数据的受控释放)
# --------------------------------------------------------------------------- #
def _confirmation_ctx(request: Request, client: ClientKey | None,
                      endpoint: str) -> RequestContext:
    ctx = RequestContext(endpoint=endpoint)
    ctx.client_id, ctx.client_name = _client_view(client)
    return ctx


def _own_record(app: MiddlewareApp, client: ClientKey, request_id: str) -> dict:
    """取回该客户端自己的审计记录;不存在或不属于本人一律同样拒绝(不区分)。"""
    record = app.audit.get(request_id)
    if record is None or record.get("client_id") != client.id:
        raise MiddlewareError(
            "forbidden",
            "该 request_id 不存在或不属于当前客户端密钥(拒绝,不区分两者)")
    return record


def _require_named_client(request: Request, app: MiddlewareApp) -> ClientKey:
    """确认流程必须有具名身份:匿名调用(即使是开发模式)一律拒绝。"""
    client = _require_client(request, app)
    if client is None:
        raise MiddlewareError(
            "forbidden", "人工确认需要可识别的客户端密钥,不接受匿名调用")
    return client


@router.post("/v1/confirmations")
async def create_confirmation(request: Request) -> Response:
    """申请对被扣留令牌的授权释放(由管理员批准后才可释放)。"""
    app: MiddlewareApp | None = None
    ctx: RequestContext | None = None
    try:
        app = _app(request)
        client = _require_named_client(request, app)
        _enforce_rate(app, request, client)
        ctx = _confirmation_ctx(request, client, "/v1/confirmations")
        raw = await _read_json(request)
        try:
            body = ConfirmationCreateRequest.model_validate(raw)
        except ValidationError as exc:
            raise validation_error(exc) from None
        _own_record(app, client, body.request_id)
        types = validate_requested_tokens(body.tokens, vault=app.token_vault,
                                          request_id=body.request_id)
        record = app.confirmations.create(
            client_id=client.id, client_name=client.name,
            request_id=body.request_id, tokens=body.tokens, token_types=types,
            reason=body.reason or "")
        _count_confirmation(app, "created")
        app.pipeline.audit_event(ctx, outcome="confirmation_pending", actions={
            "confirmation_id": record.id, "request_id": record.request_id,
            "tokens": list(record.tokens), "token_types": record.token_types,
            "token_count": len(record.tokens),
            "note": "已登记待确认:令牌形态与类别入审计,明文不落任何位置",
        })
        return JSONResponse(content=record.public_view())
    except MiddlewareError as exc:
        return _fail(exc, ctx=ctx, app=app)


@router.get("/v1/confirmations")
def list_own_confirmations(request: Request) -> Response:
    """列出本客户端发起的确认请求(不返回他人记录,不返回明文)。"""
    app: MiddlewareApp | None = None
    try:
        app = _app(request)
        client = _require_named_client(request, app)
        _enforce_rate(app, request, client)
        return JSONResponse(content={
            "object": "list",
            "data": app.confirmations.list(client_id=client.id),
        })
    except MiddlewareError as exc:
        return _fail(exc, app=app)


@router.get("/v1/confirmations/{confirmation_id}")
def get_confirmation(request: Request, confirmation_id: str) -> Response:
    """查询自己某次确认请求的状态。"""
    app: MiddlewareApp | None = None
    try:
        app = _app(request)
        client = _require_named_client(request, app)
        _enforce_rate(app, request, client)
        record = app.confirmations.get(confirmation_id)
        if record.client_id != client.id:
            raise MiddlewareError("forbidden", "该确认请求不属于当前客户端密钥")
        return JSONResponse(content=record.public_view())
    except MiddlewareError as exc:
        return _fail(exc, app=app)


@router.post("/v1/confirmations/{confirmation_id}/release")
async def release_confirmation(request: Request, confirmation_id: str) -> Response:
    """取回已批准确认所覆盖的明文(**唯一**的受控释放出口,只成功一次)。"""
    app: MiddlewareApp | None = None
    ctx: RequestContext | None = None
    try:
        app = _app(request)
        client = _require_named_client(request, app)
        _enforce_rate(app, request, client)
        ctx = _confirmation_ctx(request, client,
                                "/v1/confirmations/{id}/release")
        record = app.confirmations.authorize_release(confirmation_id,
                                                     client_id=client.id)
        secrets_out = resolve_confirmation(record, client_id=client.id,
                                           vault=app.token_vault)
        app.confirmations.consume(confirmation_id, client_id=client.id)
        _count_confirmation(app, "released")
        app.pipeline.audit_event(ctx, outcome="confirmation_released", actions={
            "confirmation_id": record.id, "request_id": record.request_id,
            "tokens": list(record.tokens), "token_types": record.token_types,
            "token_count": len(record.tokens),
            "note": "已按批准范围释放;审计只记令牌与类别,不记明文",
        })
        return JSONResponse(content={
            "confirmation_id": record.id,
            "request_id": record.request_id,
            "released_count": len(secrets_out),
            "secrets": secrets_out,
            "status": "consumed",
            "boundary": {
                "single_use": "该确认凭据已失效;再次调用会返回 403",
                "scope": "只包含本次批准覆盖的令牌,不含其它任何映射",
                "plaintext_warning": "返回值为敏感原文,请勿写入日志或提交到代码仓库",
            },
        })
    except MiddlewareError as exc:
        return _fail(exc, ctx=ctx, app=app)


@router.get("/admin/confirmations")
def admin_confirmations(request: Request, status: str = "", client_id: str = "",
                        limit: int = 100) -> Response:
    """待确认队列(管理员)。status 可筛 pending|approved|denied|expired|consumed。"""
    app: MiddlewareApp | None = None
    try:
        app = _app(request)
        _require_admin(request, app)
        return JSONResponse(content={
            "object": "list",
            "data": app.confirmations.list(client_id=client_id, status=status,
                                           limit=limit),
            "stats": app.confirmations.stats(),
        })
    except MiddlewareError as exc:
        return _fail(exc, app=app)


@router.post("/admin/confirmations/{confirmation_id}/approve")
def admin_approve_confirmation(request: Request, confirmation_id: str) -> Response:
    """批准一次确认(管理员)。批准的是**待确认项本身**,不接受任何范围改写。"""
    app: MiddlewareApp | None = None
    ctx: RequestContext | None = None
    try:
        app = _app(request)
        _require_admin(request, app)
        record = app.confirmations.get(confirmation_id)
        ctx = RequestContext(endpoint="/admin/confirmations/{id}/approve",
                             client_id=record.client_id,
                             client_name=record.client_name)
        record = app.confirmations.approve(confirmation_id, by="admin")
        _count_confirmation(app, "approved")
        app.pipeline.audit_event(ctx, outcome="confirmation_approved", actions={
            "confirmation_id": record.id, "request_id": record.request_id,
            "tokens": list(record.tokens), "token_types": record.token_types,
            "token_count": len(record.tokens), "decided_by": "admin",
            "note": "管理员显式批准:授权动作已认证,内容审阅责任在流程侧",
        })
        return JSONResponse(content=record.public_view())
    except MiddlewareError as exc:
        # 管理面的拒绝不写成「该客户端的失败请求」:审计归属由 audit_event 显式表达
        return _fail(exc, app=app)


@router.post("/admin/confirmations/{confirmation_id}/deny")
async def admin_deny_confirmation(request: Request, confirmation_id: str) -> Response:
    """拒绝一次确认(管理员);拒绝后该凭据为终态,释放接口一律失败。"""
    app: MiddlewareApp | None = None
    ctx: RequestContext | None = None
    try:
        app = _app(request)
        _require_admin(request, app)
        record = app.confirmations.get(confirmation_id)
        ctx = RequestContext(endpoint="/admin/confirmations/{id}/deny",
                             client_id=record.client_id,
                             client_name=record.client_name)
        reason = ""
        try:
            raw = await _read_json(request)
            reason = str(raw.get("reason") or "")[:200]
        except MiddlewareError:
            reason = ""                      # 拒绝接口允许空体(默认拒绝本身就是理由)
        record = app.confirmations.deny(confirmation_id, by="admin", reason=reason)
        _count_confirmation(app, "denied")
        app.pipeline.audit_event(ctx, outcome="confirmation_denied", actions={
            "confirmation_id": record.id, "request_id": record.request_id,
            "tokens": list(record.tokens), "token_count": len(record.tokens),
            "decided_by": "admin", "reason": reason,
        })
        return JSONResponse(content=record.public_view())
    except MiddlewareError as exc:
        return _fail(exc, app=app)


# --------------------------------------------------------------------------- #
# 管理接口
# --------------------------------------------------------------------------- #
@router.get("/admin/security/policies")
def admin_policies(request: Request) -> Response:
    app: MiddlewareApp | None = None
    try:
        app = _app(request)
        _require_admin(request, app)
    except MiddlewareError as exc:
        return _fail(exc, app=app)
    from .recognizers import EXTENDED_RULES, REVIEW_THRESHOLD
    detector = app.detector
    return JSONResponse(content={
        "policy": app.settings.public_policy(),
        "providers": app.effective_provider_views(),
        "providers_config": (managed_meta(app.provider_store)
                            if app.provider_store is not None else {}),
        "models": app.registry.list_model_ids(),
        "deployment": {
            "mode": "single-process",
            "instance_lock": bool(app.settings.instance_lock),
            "note": "多 worker/多副本不受支持；确认/金库/限流/审计为进程内状态",
        },
        "limits": {
            "rate_limit_per_min": app.settings.rate_limit_per_min,
            "max_concurrency": app.settings.max_concurrency,
            "max_request_bytes": app.settings.max_request_bytes,
            "sse_heartbeat_s": app.settings.sse_heartbeat_s,
            "idempotency_ttl_s": app.settings.idempotency_ttl_s,
            "idempotency_max": app.settings.idempotency_max,
        },
        "idempotency": app.idempotency.stats() if app.idempotency else {},
        "protection_modes": ["placeholder", "token", "encrypt"],
        "restore_modes": ["off", "confirm", "categories", "auto"],
        "detection": {
            "builtin_rules": [r.rule_id for r in EXTENDED_RULES],
            "config_path": app.settings.detection_config_path or None,
            "custom_rules": [r.rule_id for r in detector.custom_rules],
            "sensitive_words": len(detector.sensitive_words),
            "suppress_patterns": len(detector.suppress_patterns),
            "disabled_types": sorted(detector.disabled_types),
            "review_threshold": REVIEW_THRESHOLD,
            "note": "置信度低于 review_threshold 的命中不自动替换,而是标记为待人工确认",
        },
        "clients": [c.public_view() for c in app.clients.list_clients()],
        "audit": _chain_view(app),
        "boundary": {
            "client_cannot_expand": "客户端只能收紧策略:加强保护模式、收窄还原类别",
            "tokens_are_not_plaintext_to_model":
                "模型看到的是令牌而非原文;还原只影响交付给客户端的文本",
            "verification_scope":
                "证据仅覆盖本地网关记录;不证明上游服务商身份或回答正确性",
        },
    })


# --------------------------------------------------------------------------- #
# 控制台看板：一次请求返回全部实时计数（只读内存，不做整链校验）
# --------------------------------------------------------------------------- #
def _group_counter(counters: list[dict], name: str, field: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for item in counters:
        if item.get("name") != name:
            continue
        key = str((item.get("labels") or {}).get(field) or "")
        if not key:
            continue
        out[key] = out.get(key, 0) + int(float(item.get("value") or 0))
    return out


def _dashboard_payload(app: MiddlewareApp) -> dict:
    snapshot = app.metrics.snapshot()
    counters = snapshot.get("counters") or []
    # 看板只统计业务入口 /v1/*：把控制台自身（/admin/*、/health、/metrics）的
    # 轮询从「总请求 / 延迟 / 错误率」里剔除，否则看板会把轮询次数当成中转流量。
    def _is_v1(labels: dict | None) -> bool:
        return str((labels or {}).get("path") or "").startswith("/v1/")

    requests = [item for item in counters
                if item.get("name") == "requests_total" and _is_v1(item.get("labels"))]
    by_status: dict[str, int] = {}
    by_path: list[dict] = []
    for item in requests:
        labels = item.get("labels") or {}
        status = str(labels.get("status") or "")
        count = int(float(item.get("value") or 0))
        by_status[status] = by_status.get(status, 0) + count
        by_path.append({"path": str(labels.get("path") or ""),
                        "method": str(labels.get("method") or ""),
                        "status": status, "count": count})
    by_path.sort(key=lambda row: (-row["count"], row["path"], row["status"]))
    total = sum(by_status.values())
    errors = sum(value for status, value in by_status.items()
                 if status.isdigit() and int(status) >= 400)

    histogram = aggregate_histograms(
        [item for item in (snapshot.get("histograms") or [])
         if item.get("name") == "request_duration_seconds"
         and _is_v1(item.get("labels"))],
        "request_duration_seconds")
    if histogram:
        quantiles = {
            "count": histogram["count"],
            "sum_s": round(histogram["sum"], 4),
            "p50_ms": round(histogram_quantile(histogram["bounds"],
                                               histogram["counts"], 0.50) * 1000, 1),
            "p95_ms": round(histogram_quantile(histogram["bounds"],
                                               histogram["counts"], 0.95) * 1000, 1),
            "p99_ms": round(histogram_quantile(histogram["bounds"],
                                               histogram["counts"], 0.99) * 1000, 1),
        }
    else:
        quantiles = {"count": 0, "sum_s": 0.0, "p50_ms": 0.0,
                     "p95_ms": 0.0, "p99_ms": 0.0}

    detections = _group_counter(counters, "detections_total", "type")
    blocked = _group_counter(counters, "blocked_total", "type")
    restored = _group_counter(counters, "tokens_restored_total", "type")
    upstream_by_provider = _group_counter(counters, "upstream_requests_total", "provider")
    upstream_by_outcome = _group_counter(counters, "upstream_requests_total", "outcome")
    upstream_by_error = {key: value for key, value in _group_counter(
        counters, "upstream_requests_total", "error_kind").items()
        if key not in ("", "none")}

    try:
        audit_head = {
            "records": app.audit.count(),
            "tip_seq": app.audit.tip()["seq"],
            "tip_hash": app.audit.tip()["chain_hash"],
            "anchor": app.audit.tip().get("anchor") or "",
        }
    except Exception as exc:  # noqa: BLE001 — 看板不能因审计读取失败而 500
        logger.warning("dashboard_audit_head_failed: %s", type(exc).__name__)
        audit_head = {"records": 0, "tip_seq": 0, "tip_hash": "", "anchor": "",
                      "error": type(exc).__name__}

    providers = app.effective_provider_views()
    settings = app.settings
    return {
        "generated_at": time.time(),
        "uptime_s": round(float(snapshot.get("uptime_s") or 0.0), 1),
        "service": {"version": __version__, "env": settings.env,
                    "policy_version": settings.policy_version},
        "deployment": {"mode": "single-process",
                       "instance_lock": bool(settings.instance_lock),
                       "note": "确认/金库/限流/审计为进程内状态；不支持多 worker/多副本"},
        "requests": {"total": total, "errors": errors,
                     "error_rate": round(errors / total, 4) if total else 0.0,
                     "by_status": by_status, "by_path": by_path},
        "durations": quantiles,
        "detections": {"total": sum(detections.values()), "by_type": detections},
        "blocked": {"total": sum(blocked.values()), "by_type": blocked},
        "restored": {"total": sum(restored.values()), "by_type": restored},
        "upstream": {"total": sum(upstream_by_provider.values()),
                     "by_provider": upstream_by_provider,
                     "by_outcome": upstream_by_outcome,
                     "by_error_kind": upstream_by_error},
        "confirmations": app.confirmations.stats(),
        "vault": app.token_vault.stats(),
        "idempotency": (app.idempotency.stats()
                        if app.idempotency is not None else {}),
        "audit": audit_head,
        "clients": {"total": app.clients.count()},
        "providers": providers,
        "defaults": {"provider": app.registry.default_provider,
                     "model": app.registry.default_model},
        "policy": {
            "protection_mode": settings.protection_mode,
            "restore_mode": settings.restore_mode,
            "restore_categories": list(settings.restore_categories),
            "block_on": settings.block_on,
            "image_policy": settings.image_policy,
            "document_policy": settings.document_policy,
            "anthropic_thinking": settings.anthropic_thinking,
            "cache_control": settings.cache_control,
            "rate_limit_per_min": settings.rate_limit_per_min,
            "max_concurrency": settings.max_concurrency,
            "max_request_bytes": settings.max_request_bytes,
        },
        "misc": {
            "sse_heartbeats_total": sum(
                int(float(c.get("value") or 0)) for c in counters
                if c.get("name") == "sse_heartbeats_total"),
            "idempotent_replays_total": sum(
                int(float(c.get("value") or 0)) for c in counters
                if c.get("name") == "idempotent_replays_total"),
        },
        "checks": {
            "providers": any(bool(view.get("configured")) for view in providers),
            "instance_lock": bool(settings.instance_lock),
        },
    }


@router.get("/admin/dashboard")
def admin_dashboard(request: Request) -> Response:
    """控制台实时看板快照（单用户全权管理员；只读内存计数）。"""
    app: MiddlewareApp | None = None
    try:
        app = _app(request)
        _require_admin(request, app)
    except MiddlewareError as exc:
        return _fail(exc, app=app)
    try:
        return JSONResponse(content=_dashboard_payload(app))
    except Exception as exc:  # noqa: BLE001 — 不把栈透给客户端
        logger.exception("dashboard_failed")
        return _fail(MiddlewareError(
            "internal", f"看板数据生成失败: {type(exc).__name__}"), app=app)


@router.get("/admin/audit")
def admin_audit(request: Request, limit: int = 50, offset: int = 0,
                client_id: str = "", outcome: str = "", since: float = 0.0) -> Response:
    app: MiddlewareApp | None = None
    try:
        app = _app(request)
        _require_admin(request, app)
    except MiddlewareError as exc:
        return _fail(exc, app=app)
    page = app.audit.list(limit=limit, offset=offset, client_id=client_id,
                          outcome=outcome, since_epoch=since)
    return JSONResponse(content={
        "total": page["total"], "offset": page["offset"], "limit": page["limit"],
        "items": page["items"], "chain": _chain_view(app),
        "note": "审计记录不含原始 Prompt、原始敏感值与任何密钥;"
                "也不含可用于还原令牌的映射",
    })


@router.get("/admin/audit/{request_id}")
def admin_audit_one(request: Request, request_id: str) -> Response:
    app: MiddlewareApp | None = None
    try:
        app = _app(request)
        _require_admin(request, app)
    except MiddlewareError as exc:
        return _fail(exc, app=app)
    record = app.audit.get(request_id)
    if record is None:
        return JSONResponse(status_code=404, content={
            "found": False, "request_id": request_id, "reason": "未找到该记录"})
    return JSONResponse(content={"found": True, "record": record,
                                 "record_mac_valid": app.audit.mac_valid(record)})


@router.post("/admin/audit/verify")
def admin_audit_verify(request: Request, full: bool = True) -> Response:
    app: MiddlewareApp | None = None
    try:
        app = _app(request)
        _require_admin(request, app)
        result = app.audit.verify(full=full)
    except MiddlewareError as exc:
        return _fail(exc, app=app)
    except Exception as exc:  # noqa: BLE001 — 链损坏要如实报告而不是 500 堆栈
        return JSONResponse(content={
            "intact": False, "error": f"{type(exc).__name__}: {exc}",
            "note": "审计日志读取/校验失败,拒绝给出「完整」结论(fail-closed)",
        })
    return JSONResponse(content=result)


@router.post("/admin/audit/purge")
def admin_audit_purge(request: Request, dry_run: bool = True) -> Response:
    app: MiddlewareApp | None = None
    try:
        app = _app(request)
        _require_admin(request, app)
        result = app.audit.purge_expired(dry_run=dry_run)
    except MiddlewareError as exc:
        return _fail(exc, app=app)
    return JSONResponse(content=result)


@router.get("/admin/clients")
def admin_clients(request: Request) -> Response:
    app: MiddlewareApp | None = None
    try:
        app = _app(request)
        _require_admin(request, app)
    except MiddlewareError as exc:
        return _fail(exc, app=app)
    return JSONResponse(content={
        "clients": [c.public_view() for c in app.clients.list_clients()],
        "note": "只回显前缀与元数据;完整密钥仅在签发/轮换时返回一次",
    })


def _client_updates(app: MiddlewareApp, raw: dict) -> dict:
    """校验并收敛客户端配置字段（create/patch 共用）；越界显式 400。"""
    from .protection import NEVER_AUTO_RESTORE_TYPES

    updates: dict = {}
    if "name" in raw:
        name = str(raw.get("name") or "").strip()
        if not name:
            raise MiddlewareError("invalid_request", "name 不能为空")
        updates["name"] = name[:200]
    if "models" in raw:
        models = [str(m) for m in (raw.get("models") or [])]
        unknown = sorted(set(models) - set(app.registry.list_model_ids()))
        if unknown and not app.settings.allow_unknown_models:
            raise MiddlewareError(
                "invalid_request",
                f"models 含未声明的模型: {unknown}"
                f"(当前可用 {app.registry.list_model_ids()})")
        updates["models"] = models
    if "rate_limit_per_min" in raw:
        try:
            limit = int(raw.get("rate_limit_per_min") or 0)
        except (TypeError, ValueError):
            raise MiddlewareError("invalid_request", "rate_limit_per_min 必须是整数") from None
        if limit < 0:
            raise MiddlewareError("invalid_request", "rate_limit_per_min 不能为负数")
        updates["rate_limit_per_min"] = limit
    if "protection_mode" in raw:
        mode = str(raw.get("protection_mode") or "")
        if mode and mode not in ("placeholder", "token", "encrypt"):
            raise MiddlewareError(
                "invalid_request", "protection_mode 只能为 placeholder|token|encrypt")
        updates["protection_mode"] = mode
    if "restore_categories" in raw:
        categories = [str(c).upper() for c in (raw.get("restore_categories") or [])]
        illegal = sorted(set(categories) & NEVER_AUTO_RESTORE_TYPES)
        if illegal:
            raise MiddlewareError(
                "invalid_request",
                f"restore_categories 含禁止自动还原的高风险类别: {illegal}")
        updates["restore_categories"] = categories
    if "expires_in_days" in raw:
        try:
            days = int(raw.get("expires_in_days") or 0)
        except (TypeError, ValueError):
            raise MiddlewareError("invalid_request", "expires_in_days 必须是整数") from None
        if days < 0:
            raise MiddlewareError("invalid_request", "expires_in_days 不能为负数")
        updates["expires_epoch"] = time.time() + days * 86400.0 if days > 0 else 0.0
    return updates


@router.post("/admin/clients")
async def admin_create_client(request: Request) -> Response:
    app: MiddlewareApp | None = None
    try:
        app = _app(request)
        _require_admin(request, app)
        raw = await _read_json(request)
        fields = _client_updates(app, raw)
        days = (raw.get("expires_in_days")
                if "expires_in_days" in raw else app.settings.client_key_ttl_days)
        record, plaintext = app.clients.create(
            fields.get("name", str(raw.get("name") or "client")),
            models=fields.get("models", []),
            rate_limit_per_min=fields.get("rate_limit_per_min", 0),
            protection_mode=fields.get("protection_mode", ""),
            restore_categories=fields.get("restore_categories", []),
            expires_in_days=int(days or 0),
        )
    except MiddlewareError as exc:
        return _fail(exc, app=app)
    return JSONResponse(status_code=201, content={
        "client": record.public_view(),
        "api_key": plaintext,
        "note": "该密钥只显示这一次;服务端仅保存 HMAC 摘要,无法找回",
    })


@router.patch("/admin/clients/{client_id}")
async def admin_update_client(request: Request, client_id: str) -> Response:
    """更新客户端配置（名称/模型/限额/保护模式/还原类别/过期），不改变密钥材料。"""
    app: MiddlewareApp | None = None
    try:
        app = _app(request)
        _require_admin(request, app)
        raw = await _read_json(request)
        updates = _client_updates(app, raw)
        record = app.clients.update(client_id, **updates)
    except MiddlewareError as exc:
        return _fail(exc, app=app)
    return JSONResponse(content={"client": record.public_view(),
                                 "note": "密钥材料未变；如需换钥请用 rotate"})


@router.post("/admin/clients/{client_id}/revoke")
def admin_revoke_client(request: Request, client_id: str) -> Response:
    app: MiddlewareApp | None = None
    try:
        app = _app(request)
        _require_admin(request, app)
        record = app.clients.revoke(client_id)
    except MiddlewareError as exc:
        return _fail(exc, app=app)
    return JSONResponse(content={"client": record.public_view(), "revoked": True})


@router.post("/admin/clients/{client_id}/rotate")
def admin_rotate_client(request: Request, client_id: str) -> Response:
    app: MiddlewareApp | None = None
    try:
        app = _app(request)
        _require_admin(request, app)
        record, plaintext = app.clients.rotate(client_id)
    except MiddlewareError as exc:
        return _fail(exc, app=app)
    return JSONResponse(content={
        "client": record.public_view(), "api_key": plaintext,
        "note": "旧密钥立即失效;新密钥只显示这一次",
    })


# --------------------------------------------------------------------------- #
# 上游提供商视图与连通性测试（管理面；绝不回显密钥或上游正文）
# --------------------------------------------------------------------------- #
def _providers_payload(app: MiddlewareApp) -> dict:
    """Provider 视图（绝不包含密钥值/header 值/上游正文）。"""
    return {
        "providers": app.effective_provider_views(),
        "default_provider": app.registry.default_provider,
        "default_model": app.registry.default_model,
        "allow_unknown_models": bool(app.settings.allow_unknown_models),
        "models": app.registry.list_model_ids(),
        "managed": (managed_meta(app.provider_store)
                    if app.provider_store is not None else {}),
        "note": "只返回密钥来源与是否已配置；密钥值与 extra_headers 值永不回显",
    }


def _audit_provider_change(app: MiddlewareApp, operation: str, name: str, *,
                           changed_fields: list[str] | None = None,
                           key_updated: bool = False) -> None:
    """控制面审计：只记字段名与布尔值，绝不记密钥/header 值。"""
    ctx = RequestContext(endpoint="/admin/providers")
    app.pipeline.audit_event(ctx, outcome="provider_config", actions={
        "operation": operation,
        "provider": name,
        "changed_fields": sorted(changed_fields or []),
        "key_updated": bool(key_updated),
        "default_provider": app.registry.default_provider,
        "default_model": app.registry.default_model,
    })


def _require_provider_store(app: MiddlewareApp):
    if app.provider_store is None:
        raise MiddlewareError("config", "托管 Provider 配置未装配（控制台不可用）")
    return app.provider_store


@router.get("/admin/providers")
def admin_providers(request: Request) -> Response:
    app: MiddlewareApp | None = None
    try:
        app = _app(request)
        _require_admin(request, app)
    except MiddlewareError as exc:
        return _fail(exc, app=app)
    return JSONResponse(content=_providers_payload(app))


@router.post("/admin/providers")
async def admin_create_provider(request: Request) -> Response:
    """新增控制台托管的 Provider；保存后立即生效（无需重启）。"""
    app: MiddlewareApp | None = None
    try:
        app = _app(request)
        _require_admin(request, app)
        store = _require_provider_store(app)
        raw = await _read_json(request)
        name = str(raw.get("name") or "").strip()
        with app.provider_lock:
            candidate = store.candidate_upsert(raw, name=name, create=True)
            _settings, views = apply_candidate(app, candidate)
        _audit_provider_change(
            app, "create", name,
            changed_fields=[k for k in raw if k not in ("api_key", "clear_api_key")],
            key_updated=bool(str(raw.get("api_key") or "").strip()))
        payload = _providers_payload(app)
        payload.update({
            "provider": next((v for v in views if v["name"] == name), None),
            "applied": True,
        })
        return JSONResponse(status_code=201, content=payload)
    except MiddlewareError as exc:
        return _fail(exc, app=app)


@router.patch("/admin/providers/{name}")
async def admin_update_provider(request: Request, name: str) -> Response:
    """更新托管 Provider；环境变量独有项不可改（可新建同名托管项覆盖）。"""
    app: MiddlewareApp | None = None
    try:
        app = _app(request)
        _require_admin(request, app)
        store = _require_provider_store(app)
        raw = await _read_json(request)
        if raw.get("name") and str(raw.get("name")) != name:
            raise MiddlewareError("invalid_request", "Provider 名称不可修改")
        with app.provider_lock:
            candidate = store.candidate_upsert(raw, name=name, create=False)
            _settings, views = apply_candidate(app, candidate)
        _audit_provider_change(
            app, "update", name,
            changed_fields=[k for k in raw if k not in ("api_key", "clear_api_key")],
            key_updated=bool(str(raw.get("api_key") or "").strip())
                        or bool(raw.get("clear_api_key")))
        payload = _providers_payload(app)
        payload.update({
            "provider": next((v for v in views if v["name"] == name), None),
            "applied": True,
        })
        return JSONResponse(content=payload)
    except MiddlewareError as exc:
        return _fail(exc, app=app)


@router.delete("/admin/providers/{name}")
def admin_delete_provider(request: Request, name: str) -> Response:
    """删除托管 Provider；同名环境变量项会重新生效。"""
    app: MiddlewareApp | None = None
    try:
        app = _app(request)
        _require_admin(request, app)
        store = _require_provider_store(app)
        with app.provider_lock:
            candidate = store.candidate_delete(name)
            _settings, views = apply_candidate(app, candidate)
        _audit_provider_change(app, "delete", name)
        payload = _providers_payload(app)
        payload.update({"deleted": name, "applied": True})
        return JSONResponse(content=payload)
    except MiddlewareError as exc:
        return _fail(exc, app=app)


@router.put("/admin/provider-defaults")
async def admin_provider_defaults(request: Request) -> Response:
    """设置默认 Provider/模型；保存后立即生效。"""
    app: MiddlewareApp | None = None
    try:
        app = _app(request)
        _require_admin(request, app)
        store = _require_provider_store(app)
        raw = await _read_json(request)
        provider = str(raw.get("default_provider") or "").strip()
        model = str(raw.get("default_model") or "").strip()
        with app.provider_lock:
            candidate = store.candidate_defaults(provider, model)
            _settings, views = apply_candidate(app, candidate)
        _audit_provider_change(
            app, "defaults", provider,
            changed_fields=["default_provider", "default_model"])
        payload = _providers_payload(app)
        payload.update({"applied": True})
        return JSONResponse(content=payload)
    except MiddlewareError as exc:
        return _fail(exc, app=app)


@router.post("/admin/providers/{name}/test")
def admin_provider_test(request: Request, name: str) -> Response:
    """向上游发一次最小请求（max_tokens=1），返回分类结果；不返回上游正文。"""
    from .providers.base import ChatRequest

    app: MiddlewareApp | None = None
    ctx: RequestContext | None = None
    try:
        app = _app(request)
        _require_admin(request, app)
        provider = app.registry.get(name)
        model = provider.models[0] if provider.models else app.settings.default_model
        if not model:
            raise MiddlewareError("invalid_request", "该提供商未声明可用模型")
        ctx = RequestContext(endpoint="/admin/providers/{name}/test")
        started = time.monotonic()
        try:
            completion = provider.complete(ChatRequest(
                model=model, messages=[{"role": "user", "content": "ping"}],
                max_tokens=1))
        except MiddlewareError as exc:
            elapsed = (time.monotonic() - started) * 1000.0
            app.pipeline.audit_event(ctx, outcome="provider_test", actions={
                "provider": name, "ok": False, "error_kind": exc.kind,
                "latency_ms": round(elapsed, 2),
            })
            return JSONResponse(content={
                "ok": False, "provider": name, "category": exc.kind,
                "message": exc.detail, "latency_ms": round(elapsed, 2),
                "upstream_status": exc.upstream_status,
            })
        elapsed = (time.monotonic() - started) * 1000.0
        app.pipeline.audit_event(ctx, outcome="provider_test", actions={
            "provider": name, "ok": True, "latency_ms": round(elapsed, 2),
            "usage": completion.usage or {},
        })
        return JSONResponse(content={
            "ok": True, "provider": name, "category": "ok",
            "latency_ms": round(elapsed, 2), "model": model,
            "usage": completion.usage or {},
        })
    except MiddlewareError as exc:
        return _fail(exc, ctx=ctx, app=app)


# --------------------------------------------------------------------------- #
# 未实现的 /v1 路径:显式 404(而不是 HTML 或空响应)
# --------------------------------------------------------------------------- #
@router.api_route("/v1/{rest:path}",
                  methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
                  include_in_schema=False)
def v1_not_found(rest: str) -> Response:
    return JSONResponse(status_code=404, content={
        "error": {
            "message": f"/v1/{rest} 未实现。已实现: /v1/models, "
                       "/v1/chat/completions, /v1/messages, /v1/responses, "
                       "/v1/verify, /v1/confirmations；"
                       "/v1/messages/count_tokens 有意不实现(见文档)",
            "type": "not_found_error", "code": "not_found", "param": None,
        },
    })


def install(app) -> None:
    """挂载请求体限制、指标包装与网关路由(由 app/main.py 在启动前调用)。"""
    from .metrics import MetricsMiddleware

    app.add_middleware(BodyLimitMiddleware)
    app.add_middleware(MetricsMiddleware)
    app.include_router(router)
