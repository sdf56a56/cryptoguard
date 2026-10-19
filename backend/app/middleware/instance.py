"""单实例锁 —— 同一 data 目录只允许一个网关进程

为什么需要它：确认状态、令牌映射金库、限流计数、客户端密钥缓存、审计链尾都是
**进程内状态**。多个 worker/副本同时持有同一 data 目录时会出现：
  - worker A 创建的待确认项，worker B 审批时找不到；
  - 限流按 worker 各算各的；
  - 两个进程同时往同一审计段追加，链尾与实际文件不一致。

因此本实现明确选择「单进程」为唯一受支持形态，并用文件锁把它变成启动期硬约束，
而不是文档里一句容易被忽略的告警。

跨平台：
  - POSIX：`fcntl.flock(LOCK_EX | LOCK_NB)`；
  - Windows：`msvcrt.locking(LK_NBLCK)`（锁 1 字节）；
  - 两者都不可用时 fail-closed（拒绝启动），不退化为「无锁运行」。
"""
from __future__ import annotations

import logging
import os
import time
from pathlib import Path

from .config import ConfigError

logger = logging.getLogger(__name__)

try:  # POSIX
    import fcntl as _fcntl
except ImportError:  # pragma: no cover - Windows
    _fcntl = None  # type: ignore[assignment]

try:  # Windows
    import msvcrt as _msvcrt
except ImportError:  # pragma: no cover - POSIX
    _msvcrt = None  # type: ignore[assignment]


class InstanceLock:
    """独占 data 目录的进程锁；`acquire()` 失败抛 ConfigError（启动期 fail-fast）。"""

    def __init__(self, path: Path | str, *, enabled: bool = True) -> None:
        self._path = Path(path)
        self._enabled = bool(enabled)
        self._fd: int | None = None
        self._held = False

    # ------------------------------------------------------------------ #
    @property
    def held(self) -> bool:
        return self._held

    @property
    def path(self) -> Path:
        return self._path

    def acquire(self) -> None:
        """获取锁；已被占用时抛 ConfigError（不等待）。"""
        if not self._enabled:
            return
        if self._held:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(self._path, os.O_CREAT | os.O_RDWR, 0o600)
        except OSError as exc:
            raise ConfigError(f"无法创建实例锁文件 {self._path}: {exc}") from None

        try:
            self._lock_fd(fd)
        except OSError as exc:
            owner = self._read_owner()
            os.close(fd)
            detail = f"另一个 CryptoGuard 实例正在使用该 data 目录({self._path})"
            if owner:
                detail += f"；持有者: {owner}"
            detail += (
                "。确认/金库/限流/审计都是进程内状态，本实现只支持单进程；"
                "如确认没有其它实例，请删除锁文件后重试。"
            )
            raise ConfigError(f"{detail}（{exc}）") from None

        # 锁已持有：写入 PID 与启动时间，便于人排错（不参与安全判定）
        try:
            os.ftruncate(fd, 0)
            os.lseek(fd, 0, os.SEEK_SET)
            os.write(fd, f"pid={os.getpid()} started={time.time():.0f}\n".encode())
            os.fsync(fd)
        except OSError as exc:  # 写元信息失败不放弃锁，但要让操作者看见
            logger.warning("写入实例锁元信息失败（锁仍有效）: %s", exc)

        self._fd = fd
        self._held = True
        logger.info("instance_lock_acquired: %s", self._path)

    def release(self) -> None:
        """释放锁（幂等）。"""
        fd, self._fd = self._fd, None
        self._held = False
        if fd is None:
            return
        try:
            self._unlock_fd(fd)
        except OSError:  # pragma: no cover - 释放失败不影响退出
            pass
        try:
            os.close(fd)
        except OSError:  # pragma: no cover
            pass
        logger.info("instance_lock_released: %s", self._path)

    # ------------------------------------------------------------------ #
    def _lock_fd(self, fd: int) -> None:
        if _fcntl is not None:
            _fcntl.flock(fd, _fcntl.LOCK_EX | _fcntl.LOCK_NB)
            return
        if _msvcrt is not None:  # pragma: no cover - Windows
            if os.fstat(fd).st_size == 0:
                os.write(fd, b"\0")
                os.fsync(fd)
            os.lseek(fd, 0, os.SEEK_SET)
            _msvcrt.locking(fd, _msvcrt.LK_NBLCK, 1)
            return
        raise ConfigError(
            "当前平台不支持文件锁：拒绝在无互斥保护的情况下启动（CG_INSTANCE_LOCK=0 可显式关闭）")

    def _unlock_fd(self, fd: int) -> None:
        if _fcntl is not None:
            _fcntl.flock(fd, _fcntl.LOCK_UN)
            return
        if _msvcrt is not None:  # pragma: no cover - Windows
            try:
                os.lseek(fd, 0, os.SEEK_SET)
                _msvcrt.locking(fd, _msvcrt.LK_UNLCK, 1)
            except OSError:
                pass

    def _read_owner(self) -> str:
        try:
            return self._path.read_text(encoding="utf-8", errors="replace").strip()[:200]
        except OSError:
            return ""

    # ------------------------------------------------------------------ #
    def __enter__(self) -> "InstanceLock":
        self.acquire()
        return self

    def __exit__(self, *exc_info) -> None:
        self.release()
