"""
并发桥接 —— CPU 密集处理器经 run_in_executor 进 guard 线程池(R7)

async 路由处理器用 `await run_sync(fn, *args)` 把同步重活(query_v2、
文件抽取/存证、打包)丢进 guard._pool,不阻塞事件循环;多 worker 部署
见 backend/gunicorn_conf.py。
"""
from __future__ import annotations

import asyncio

from .proxy import guard


async def run_sync(fn, *args):
    """把同步 fn(*args) 提交 guard._pool 执行,await 结果(R7)。"""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(guard._pool, fn, *args)
