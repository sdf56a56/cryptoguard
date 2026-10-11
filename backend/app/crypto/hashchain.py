"""
哈希链模块 —— 抗篡改日志(Hash Chain)

安全目标:
  - 抗篡改:修改任意历史日志条目会导致后续所有哈希值变化,从而被根哈希检测。
  - 单向性:无法由当前哈希反推历史内容。
  - 条目类型绑定:entry_type 进哈希前映像(JCS 域分隔,spec §3.3),
    偷换条目类型(如 USER_OVERRIDE→QUERY)必然打穿链。

明确不承诺:
  - 哈希链只能检测篡改,不能阻止篡改(需配合签名/共识)。
  - 不承诺防拥有链尾写入权的进程写入伪造条目。

归约:安全性依赖 SHA-256 的抗第二原像性(Preimage / Second-preimage resistance)。
"""
from __future__ import annotations

import hashlib
import time

from ..canon import h_hex
from .merkle import MerkleTree

# entry_type 枚举(裁定 R21):QUERY=查询 / FILE_COMMIT=文件承诺 /
# USER_OVERRIDE=用户决策 / COMPUTE_GATE=计算网关指令(含拒绝)
ENTRY_TYPES = frozenset({"QUERY", "FILE_COMMIT", "USER_OVERRIDE", "COMPUTE_GATE"})

D_LOG = "CG/LOG/v2"

PACK_INTERVAL = 300.0   # 时间触发:距上次打包 ≥ 5 分钟


def sha256_hex(*parts: str) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(p.encode("utf-8"))
    return h.hexdigest()


class HashChain:
    """追加式哈希链,存储条目并提供根哈希。

    append(entry_type, payload_digest, timestamp)(裁定 R6):
    条目哈希 = h_hex({"d":"CG/LOG/v2","ty":entry_type,"p":payload_digest,
                      "ts":timestamp,"prev":prev})(JCS 域分隔,spec §3.3)。
    """

    PACK_EVERY = 10          # 每 10 条未打包条目触发 Merkle 打包(Task 12)

    def __init__(self):
        self.entries: list[dict] = []
        self._prev = "0" * 64  # 创世块前驱 = 全零
        self.packs: list[dict] = []   # 每包 {"merkle_root","range","ts"}
        self._packed = 0              # 已打包条目数(range 起点)
        self.last_pack_ts = 0.0       # 上次打包时刻(now 同口径,构造时 0.0)

    def append(self, entry_type: str, payload_digest: str, timestamp: str) -> dict:
        entry = {
            "index": len(self.entries),
            "entry_type": entry_type,
            "payload_digest": payload_digest,
            "timestamp": timestamp,
            "prev_hash": self._prev,
        }
        entry["hash"] = h_hex({
            "d": D_LOG, "ty": entry_type, "p": payload_digest,
            "ts": timestamp, "prev": self._prev,
        })
        self.entries.append(entry)
        self._prev = entry["hash"]
        # 计数触发自动打包(≥ PACK_EVERY 条未打包);时间触发只经 maybe_pack(now)
        if len(self.entries) - self._packed >= self.PACK_EVERY:
            self._pack(time.monotonic())
        return entry

    @property
    def root(self) -> str:
        return self._prev

    def verify(self) -> bool:
        """重算整条链,检测是否存在篡改(含 entry_type/payload_digest/时间戳)。"""
        prev = "0" * 64
        for e in self.entries:
            expected = h_hex({
                "d": D_LOG, "ty": e["entry_type"], "p": e["payload_digest"],
                "ts": e["timestamp"], "prev": prev,
            })
            if expected != e["hash"]:
                return False
            prev = expected
        return prev == self._prev

    # ------------------------------------------------------------------ #
    # Merkle 打包触发器(Task 12,SEC-PACK-1/2)
    # ------------------------------------------------------------------ #
    def maybe_pack(self, now: float, force: bool = False) -> dict | None:
        """打包触发:未打包条目 ≥ PACK_EVERY 或距上次打包 ≥ 300 秒;force 立即。

        无可打包条目返回 None。打包范围 = 未打包条目,Merkle 树叶子 = 各条目 hash。
        """
        unpacked = len(self.entries) - self._packed
        if unpacked <= 0:
            return None
        if force or unpacked >= self.PACK_EVERY or now - self.last_pack_ts >= PACK_INTERVAL:
            return self._pack(now)
        return None

    def _pack(self, now: float) -> dict:
        start = self._packed
        end = len(self.entries) - 1
        leaves = [e["hash"] for e in self.entries[start:end + 1]]
        pack = {
            "merkle_root": MerkleTree(leaves).root,
            "range": [start, end],
            "ts": now,
        }
        self.packs.append(pack)
        self._packed = end + 1
        self.last_pack_ts = now
        return pack
