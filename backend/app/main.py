"""CryptoGuard —— LLM API 安全中转网关（唯一入口）

本模块只做三件事：
  1. 装配安全网关（配置 → 信任根 → 审计 / 客户端密钥 / 提供商 / 管线）；
  2. 挂载 `/v1/*`、`/admin/*`、`/health`、`/ready`、`/metrics`；
  3. 退出时释放上游连接池与实例锁。

演示平台的 `/api/*`、聊天查看器、密码学实验室、攻击沙箱与前端静态资源已全部移除；
本文件不再 import 任何演示模块。
"""
from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .middleware import routes as middleware_routes
from .middleware.config import load_cors_origins, load_settings
from .middleware.deps import build_middleware
from .middleware.errors import MiddlewareError
from .paths import default_data_dir

logger = logging.getLogger(__name__)


def _install_cors(origins: list[str]) -> None:
    """按显式配置挂 CORS；空列表 = 不挂（机器对机器调用的默认）。

    通配 `*` 会让任意网页脚本打到管理面，生产环境在 config 校验阶段拒绝。
    """
    if not origins:
        return
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
        allow_headers=[
            "Authorization", "Content-Type", "X-Admin-Token", "X-Api-Key",
            "Anthropic-Version", "Idempotency-Key",
        ],
        expose_headers=[
            "X-CryptoGuard-Request-ID", "X-CryptoGuard-Policy-Version",
            "X-CryptoGuard-Protection-Mode", "X-CryptoGuard-Provider",
            "X-CryptoGuard-Upstream-Model", "X-CryptoGuard-Request-Digest",
            "X-CryptoGuard-Response-Digest", "X-CryptoGuard-Audit-Seq",
            "X-CryptoGuard-Detected", "X-CryptoGuard-Stream",
            "X-CryptoGuard-Digest-Deferred", "X-CryptoGuard-Idempotent-Replay",
            "X-CryptoGuard-Content-Policy", "Retry-After",
        ],
    )


app = FastAPI(title="CryptoGuard Gateway", version="2.0.0")
# 路由先挂载；CORS 只读环境变量/`.env` 的 origin 列表，不做完整配置校验，
# 因此可以在 import 期安全完成（配置非法由 lifespan 统一 fail-fast）。
middleware_routes.install(app)
_install_cors(load_cors_origins())


@asynccontextmanager
async def _lifespan(app: FastAPI):
    """启动期装配；`CG_NO_BOOT=1` 时跳过（测试直挂 app.state.middleware）。"""
    if os.environ.get("CG_NO_BOOT") == "1":
        yield
        return

    settings = load_settings()
    try:
        workers = int(os.environ.get("WEB_CONCURRENCY")
                      or os.environ.get("UVICORN_WORKERS") or "1")
    except ValueError:
        workers = 1
    if workers > 1:
        raise RuntimeError(
            f"检测到 {workers} 个 worker：本网关的确认/金库/限流/审计为进程内状态，"
            "只支持单进程(--workers 1)。请勿用 gunicorn 多 worker 启动。")
    from .middleware.instance import InstanceLock

    lock = None
    if settings.instance_lock:
        lock = InstanceLock(default_data_dir() / ".cryptoguard.lock")
        try:
            lock.acquire()
        except MiddlewareError as exc:
            # 实例锁失败是部署错误，不能降级成“无锁继续跑”：那会让第二个进程
            # 与第一个进程分叉确认/金库/审计状态。无论开发/生产都直接拒绝启动。
            logger.critical("实例锁获取失败，拒绝启动: %s", exc.detail, exc_info=True)
            raise
        app.state.instance_lock = lock

    try:
        app.state.middleware = build_middleware(default_data_dir(), settings=settings)
        app.state.middleware_error = ""
        try:
            import anyio

            limiter = anyio.to_thread.current_default_thread_limiter()
            limiter.total_tokens = max(limiter.total_tokens, settings.max_concurrency)
        except Exception:  # noqa: BLE001 — 线程上限调整失败不影响启动
            logger.warning("调整 anyio 线程上限失败（并发闸仍按配置生效）")
    except MiddlewareError as exc:
        if settings.production:
            logger.critical("网关装配失败，生产环境拒绝启动: %s", exc.detail,
                            exc_info=True)
            if lock is not None:
                lock.release()
            raise
        app.state.middleware_error = str(exc.detail)
        logger.critical(
            "网关装配失败，/v1/* 与 /admin/* 将返回 503（修复配置后重启）: %s",
            exc.detail)
    except Exception:
        if lock is not None:
            lock.release()
        raise

    try:
        yield
    finally:
        middleware = getattr(app.state, "middleware", None)
        if middleware is not None:
            middleware.close()
        lock = getattr(app.state, "instance_lock", None)
        if lock is not None:
            lock.release()


app.router.lifespan_context = _lifespan
