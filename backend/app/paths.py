"""运行期路径 —— 只保留网关真正需要的那一份数据目录口径。

从演示平台的 `bootstrap.py` 迁出：网关与测试夹具都只依赖 `default_data_dir()`，
不再因为一个路径函数把整个聊天/查看器装配链拖进来。
"""
from __future__ import annotations

import os
from pathlib import Path


def default_data_dir() -> Path:
    """数据目录：默认仓库根 `data/`；可用 `CG_DATA_DIR` 显式覆盖（测试/多部署）。"""
    override = (os.environ.get("CG_DATA_DIR") or "").strip()
    if override:
        return Path(override).expanduser().resolve()
    return Path(__file__).resolve().parent.parent.parent / "data"
