"""
HTTP 入口 —— /health、/v1/*、/admin/*

挂载方式(见 app/main.py):`middleware.routes.install(app)`,
与既有 `/api/*`(敏感数据加密演示平台)并存,互不影响。

端点:
  GET  /health                     健康与策略摘要(无需认证,不含任何密钥)
  GET  /v1/models                  OpenAI 兼容模型列表(需客户端认证,除非显式允许匿名)
  POST /v1/chat/completions        OpenAI 兼容补全(非流式/流式)
  POST /v1/messages                Anthropic Messages 入口(Claude Code 等原生客户端)
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

from . import anthropic_proto
from .auth import ClientKey
from .confirmations import resolve_confirmation, validate_requested_tokens
from .deps import MiddlewareApp
from .errors import MiddlewareError
from .openai_schemas import (AnthropicMessagesRequest, ChatCompletionRequest,
                             ConfirmationCreateRequest, CryptoGuardDirectiveIn,
                             VerifyRequest, validation_error)
from .pipeline import RequestContext
from .policy import resolve_policy
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
# 请求体积限制(只作用于 /v1/* 与 /admin/*,不影响既有 /api/* 的文件上传)
# --------------------------------------------------------------------------- #
class BodyLimitMiddleware:
    """纯 ASGI 中间件:按 Content-Length 与累计字节数限制请求体。

    超限直接 413(不读完整请求体、不进识别流程)。上限在**请求时**从已装配的
    MiddlewareApp.settings 读取,因此中间件本身无需在装配前拿到配置。
    """

    DEFAULT_MAX_BYTES = 1_048_576

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

        limit = self._limit(scope)
        for name, value in scope.get("headers") or []:
            if name == b"content-length":
                try:
                    if int(value) > limit:
                        await self._too_large(send)
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
                await self._too_large(send)

    @staticmethod
    async def _too_large(send) -> None:
        body = json.dumps({
            "error": {"message": "请求体超过中间件上限", "type": "invalid_request_error",
                      "code": "request_too_large", "param": None},
        }, ensure_ascii=False)
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


def _require_admin(request: Request, app: MiddlewareApp) -> None:
    app.admin.require(request.headers.get("x-admin-token"))


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
        return JSONResponse(status_code=503, content={
            "status": "unavailable",
            "detail": "中间件未装配(见启动日志;CG_NO_BOOT=1 时 /v1/* 不可用)",
        })
    return JSONResponse(content=app.health())


@router.get("/v1/models")
def list_models(request: Request) -> Response:
    app: MiddlewareApp | None = None
    try:
        app = _app(request)
        client = _require_client(request, app)
        _enforce_rate(app, request, client)
        models = app.registry.models_view(created=int(time.time()))
        if client is not None and client.models:
            allowed = set(client.models)
            models = [m for m in models if m["id"] in allowed]
        return JSONResponse(content={
            "object": "list",
            "data": models,
            "cryptoguard": {"policy": app.settings.public_policy()},
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
        ctx.client_id, ctx.client_name = _client_view(client)
        ctx.requested_model = body.model
        ctx.stream = bool(body.stream)

        policy = resolve_policy(app.settings, body.cryptoguard, client)
        policy.ignored_fields = list(ignored)
        ctx.policy_version = policy.policy_version
        ctx.protection_mode = policy.protection_mode
        _check_model_allowed(client, body.model)
        # 提前解析一次:模型不可用时立即 404,不必等进到 pipeline 才发现
        app.registry.resolve(body.model)

        stream_options = (body.stream_options.model_dump(exclude_none=True)
                          if body.stream_options else None)
        neutral = body.to_neutral(model=body.model,
                                  max_tokens=body.effective_max_tokens(),
                                  stream_options=stream_options)
        if neutral.stream and neutral.stream_options is None:
            # 默认请求上游回 usage(只影响末帧是否带用量,不改变正文)
            neutral.stream_options = {"include_usage": True}
    except MiddlewareError as exc:
        return _fail(exc, ctx=ctx, app=app)

    if not neutral.stream:
        return await _run_sync(app, ctx, neutral, policy, client)
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
        ignored = body.check_supported()
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
        policy.ignored_fields = list(ignored)
        ctx.policy_version = policy.policy_version
        ctx.protection_mode = policy.protection_mode
        _check_model_allowed(client, body.model)
        app.registry.resolve(body.model)

        neutral = body.to_neutral(model=body.model)
        if neutral.stream and neutral.stream_options is None:
            neutral.stream_options = {"include_usage": True}
    except MiddlewareError as exc:
        return _fail(exc, anthropic=True, ctx=ctx, app=app)

    if not neutral.stream:
        return await _run_sync(app, ctx, neutral, policy, client, anthropic=True)
    return _run_stream(app, ctx, neutral, policy, client, anthropic=True)


# --------------------------------------------------------------------------- #
# 非流式执行
# --------------------------------------------------------------------------- #
async def _run_sync(app: MiddlewareApp, ctx: RequestContext, neutral,
                    policy, client: ClientKey | None,
                    anthropic: bool = False) -> Response:
    def work() -> tuple[dict, dict]:
        with app.concurrency:                      # 并发闸只罩住上游调用
            prepared = app.pipeline.prepare(ctx, neutral, policy)
            completion, meta = app.pipeline.complete(prepared)
        if anthropic:
            payload = anthropic_proto.anthropic_response(
                completion, request_id=ctx.request_id, model=ctx.requested_model,
                cryptoguard=meta)
        else:
            payload = anthropic_proto.openai_response(
                completion, request_id=ctx.request_id, model=ctx.requested_model,
                created=ctx.created, cryptoguard=meta)
        return payload, _success_headers(meta, ctx)

    try:
        payload, headers = await anyio.to_thread.run_sync(work)
    except MiddlewareError as exc:
        return _fail(exc, anthropic=anthropic, ctx=ctx, app=app)
    except Exception as exc:  # noqa: BLE001 — 兜底:不把栈透给客户端
        logger.exception("middleware_unhandled(rid=%s)", ctx.request_id)
        return _fail(MiddlewareError("internal", f"中间件内部错误: {type(exc).__name__}"),
                     anthropic=anthropic, ctx=ctx, app=app)
    _touch_client(app, client)
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
    }


# --------------------------------------------------------------------------- #
# 流式执行
# --------------------------------------------------------------------------- #
def _run_stream(app: MiddlewareApp, ctx: RequestContext, neutral,
                policy, client: ClientKey | None,
                anthropic: bool = False) -> Response:
    """流式:准备(保护)同步完成后立即返回 SSE;上游在后台线程里跑。"""
    try:
        prepared = app.pipeline.prepare(ctx, neutral, policy)
    except MiddlewareError as exc:
        # 出站保护阶段的拒绝(阻断档/配置缺失)必须走统一错误体:
        # 此处**尚未发出任何 SSE 帧**,可以正常回 4xx,而不是 500 裸异常。
        return _fail(exc, anthropic=anthropic, ctx=ctx, app=app)
    state = prepared.stream_state

    headers = {
        "Content-Type": "text/event-stream; charset=utf-8",
        "X-CryptoGuard-Request-ID": ctx.request_id,
        "X-CryptoGuard-Policy-Version": policy.policy_version,
        "X-CryptoGuard-Protection-Mode": policy.protection_mode,
        "X-CryptoGuard-Detected": str(prepared.detections.get("total") or 0),
        "X-CryptoGuard-Stream": "1",
        # 流式响应头在首字节前发出,此时摘要尚未产生;最终摘要随末帧元数据下发
        "X-CryptoGuard-Digest-Deferred": "1",
        **SSE_HEADERS,
    }

    def guarded_stream():
        with app.concurrency:
            yield from app.pipeline.stream(prepared)

    pump = _StreamPump(guarded_stream())
    encoder = (_AnthropicStreamEncoder(ctx, prepared) if anthropic
               else _OpenAIStreamEncoder(ctx, prepared))

    def finalize() -> dict | None:
        """算摘要 + 写审计;失败只记日志(调用方据 None 在正文里报不可验证)。"""
        try:
            return app.pipeline.finish_stream(prepared, state)
        except Exception as exc:  # noqa: BLE001
            logger.critical("stream_finalize_failed(rid=%s): %s", ctx.request_id, exc)
            return None

    async def event_source():
        finalized = False
        try:
            yield encoder.start()
            while True:
                kind, item = await anyio.to_thread.run_sync(pump.next)
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

    def next(self) -> tuple[str, Any]:
        return self._queue.get()


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
        "providers": app.settings.provider_public_view(),
        "models": app.registry.list_model_ids(),
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


@router.post("/admin/clients")
async def admin_create_client(request: Request) -> Response:
    app: MiddlewareApp | None = None
    try:
        app = _app(request)
        _require_admin(request, app)
        raw = await _read_json(request)
        name = str(raw.get("name") or "client")
        models = [str(m) for m in (raw.get("models") or [])]
        unknown = sorted(set(models) - set(app.registry.list_model_ids()))
        if unknown and not app.settings.allow_unknown_models:
            raise MiddlewareError(
                "invalid_request",
                f"models 含未声明的模型: {unknown}"
                f"(当前可用 {app.registry.list_model_ids()})")
        mode = str(raw.get("protection_mode") or "")
        if mode and mode not in ("placeholder", "token", "encrypt"):
            raise MiddlewareError(
                "invalid_request",
                "protection_mode 只能为 placeholder|token|encrypt")
        categories = [str(c).upper() for c in (raw.get("restore_categories") or [])]
        record, plaintext = app.clients.create(
            name, models=models,
            rate_limit_per_min=int(raw.get("rate_limit_per_min") or 0),
            protection_mode=mode, restore_categories=categories)
    except MiddlewareError as exc:
        return _fail(exc, app=app)
    return JSONResponse(status_code=201, content={
        "client": record.public_view(),
        "api_key": plaintext,
        "note": "该密钥只显示这一次;服务端仅保存 HMAC 摘要,无法找回",
    })


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
# 未实现的 /v1 路径:显式 404(而不是 HTML 或空响应)
# --------------------------------------------------------------------------- #
@router.api_route("/v1/{rest:path}",
                  methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
                  include_in_schema=False)
def v1_not_found(rest: str) -> Response:
    return JSONResponse(status_code=404, content={
        "error": {
            "message": f"/v1/{rest} 未实现。已实现: /v1/models, "
                       "/v1/chat/completions, /v1/messages, /v1/verify",
            "type": "not_found_error", "code": "not_found", "param": None,
        },
    })


def install(app) -> None:
    """挂载请求体限制与中间件路由(由 app/main.py 在启动前调用)。"""
    app.add_middleware(BodyLimitMiddleware)
    app.include_router(router)
