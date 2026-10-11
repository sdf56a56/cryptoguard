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

# entry_type 枚举(裁定 R21):QUERY=查询 / FILE_COMMIT=文件承诺 /
# USER_OVERRIDE=用户决策 / COMPUTE_GATE=计算网关指令(含拒绝)
ENTRY_TYPES = frozenset({"QUERY", "FILE_COMMIT", "USER_OVERRIDE", "COMPUTE_GATE"})

D_LOG = "CG/LOG/v2"


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
