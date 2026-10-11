"""
Merkle 树模块 —— 批量日志的防篡改证明

安全目标：
  - 抗篡改：改动任一叶子会导致根哈希变化。
  - 高效证明：可用 O(log n) 的证明路径证明某叶子属于根，无需全量数据。

明确不承诺：
  - 不承诺抗量子（SHA-256 非后量子）。
  - Merkle 树不提供机密性，仅提供完整性。

归约：安全性依赖 SHA-256 抗碰撞性。
"""
from __future__ import annotations

import hashlib


def _h(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


class MerkleTree:
    def __init__(self, leaves: list[str]):
        self.leaves = [x if isinstance(x, str) else str(x) for x in leaves]
        self.levels = self._build(self.leaves)

    def _build(self, leaves: list[str]) -> list[list[str]]:
        if not leaves:
            return [[_h("")]]
        level = [_h(l) for l in leaves]
        levels = [level]
        while len(level) > 1:
            nxt = []
            for i in range(0, len(level), 2):
                if i + 1 < len(level):
                    nxt.append(_h(level[i] + level[i + 1]))
                else:
                    nxt.append(level[i])  # 奇数节点上提（promote）
            level = nxt
            levels.append(level)
        return levels

    @property
    def root(self) -> str:
        return self.levels[-1][0]

    def proof(self, index: int) -> list[dict]:
        """返回从叶子到根的证明路径（sibling 及方向）。"""
        path = []
        idx = index
        for level in self.levels[:-1]:
            if idx % 2 == 0 and idx + 1 < len(level):
                path.append({"sibling": level[idx + 1], "node_left": True})
            elif idx % 2 == 1:
                path.append({"sibling": level[idx - 1], "node_left": False})
            # 否则为奇数上提节点，无兄弟贡献，直接向上
            idx //= 2
        return path

    def verify_proof(self, leaf: str, index: int, proof: list[dict], root: str) -> bool:
        h = _h(leaf)
        for p in proof:
            if p["node_left"]:  # 当前节点是左子，兄弟在右
                h = _h(h + p["sibling"])
            else:               # 当前节点是右子，兄弟在左
                h = _h(p["sibling"] + h)
        return h == root

    def to_dict(self) -> dict:
        """序列化整棵树用于前端可视化。"""
        return {
            "root": self.root,
            "leaves": self.leaves,
            "levels": self.levels,
            "leaf_count": len(self.leaves),
        }
