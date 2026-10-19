"""运行期路径 —— 只保留网关真正需要的那一份数据目录口径。

从演示平台的 `bootstrap.py` 迁出：网关与测试夹具都只依赖 `default_data_dir()`，
不再因为一个路径函数把整个聊天/查看器装配链拖进来。
"""
from __future__ import annotations

from pathlib import Path


def default_data_dir() -> Path:
    """默认数据目录：仓库根 `data/`（与既有 VAULT_KEY 指纹、审计、客户端日志同源）。"""
    return Path(__file__).resolve().parent.parent.parent / "data"
