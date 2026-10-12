"""
存储模块 —— SealedNDJSON 封缄追加日志 + 哈希链回放

安全目标:
  - 完整性可检测:每行注入 entry_checksum(HMAC-SHA256 over JCS 规范化前映像),
    任何内容篡改在读取时被检测,fail-closed 抛 StoreIntegrityError(kind="corrupt")。
  - 链绑定:replay_chain 启动回放逐条重算 prev_hash→hash 链接(含 mid 前映像),
    持钥攻击者改内容并重算 entry_checksum 仍被链断(chain_break)捕获。
  - 无密钥泄漏:封缄行只含 HMAC 摘要,mac_key 明文不落盘。
  - 防路径注入:段名禁路径分隔符,段文件只能写在指定存储目录内。

明确不承诺:
  - 不承诺防持有 mac_key 的攻击者从创世块整链重写(重算全部链接与 checksum);
    检测整链重写需外部锚点(如签名根哈希/离线公证),不在本模块范围。
  - 同理不承诺检测尾段删除(截断):链尾写入权持有者可截断历史。
  - 不承诺多进程并发追加同一存储(单写者模型);不承诺崩溃撕裂写的自动恢复
    (撕裂行按 corrupt 拒绝,fail-closed)。

归约:entry_checksum 归约到 HMAC-SHA256 的 EUF-CMA;链回放归约到 SHA-256
抗第二原像性(同 hashchain.py)。
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
from pathlib import Path

from .canon import canon
from .crypto.hashchain import HashChain

DEFAULT_SEG_MAX_ENTRIES = 5000
DEFAULT_SEG_MAX_BYTES = 10 * 1024 * 1024  # 10MB


class StoreIntegrityError(RuntimeError):
    """存储完整性错误,kind ∈ {"corrupt", "chain_break"}。

    corrupt:行级校验失败(JSON 解析失败/非对象/entry_checksum 失配)。
    chain_break:链条目链接断裂(重算 prev_hash/hash 与存储不符或字段缺失)。
    """

    def __init__(self, kind: str, message: str) -> None:
        super().__init__(message)
        if kind not in ("corrupt", "chain_break"):
            raise ValueError(f"非法 kind: {kind!r}")
        self.kind = kind


def entry_checksum(mac_key: bytes, obj: dict) -> str:
    """封缄校验和:HMAC-SHA256(key=mac_key, msg=canon(obj 除去 entry_checksum))。

    前映像走 JCS(canon),键序无关;obj 内已有 entry_checksum 字段被排除,
    保证对封缄对象重算幂等(append 注入与读取验证同一公式)。
    """
    payload = {k: v for k, v in obj.items() if k != "entry_checksum"}
    return hmac.new(mac_key, canon(payload), hashlib.sha256).hexdigest()


class SealedNDJSON:
    """封缄 NDJSON 段式追加日志:单目录多段文件、逐行 checksum、按上限轮转。

    段命名 {name}-{i:06d}.ndjson(从 1 起)。append() 注入 entry_checksum 后写
    当前段;当前段 ≥ seg_max_entries 行或 ≥ seg_max_bytes 字节时追加前轮转新段。
    """

    def __init__(
        self,
        directory: Path,
        name: str,
        mac_key: bytes,
        seg_max_entries: int = DEFAULT_SEG_MAX_ENTRIES,
        seg_max_bytes: int = DEFAULT_SEG_MAX_BYTES,
    ) -> None:
        if not name or name in (".", "..") or "/" in name or "\\" in name:
            raise ValueError(f"非法段名(禁止路径分隔符): {name!r}")
        self._directory = directory
        self._name = name
        self._mac_key = mac_key
        self._seg_max_entries = seg_max_entries
        self._seg_max_bytes = seg_max_bytes
        self._seg_re = re.compile(re.escape(name) + r"-(\d{6})\.ndjson")
        self._tail: tuple[Path, int, int] | None = None  # 当前段(路径,行数,字节数)

    # ------------------------------------------------------------------ #
    # 段清单
    # ------------------------------------------------------------------ #
    def _seg_path(self, index: int) -> Path:
        return self._directory / f"{self._name}-{index:06d}.ndjson"

    def _segments(self) -> list[tuple[int, Path]]:
        """现有段 (序号, 路径) 列表,按序号升序;目录不存在返回 []。"""
        if not self._directory.is_dir():
            return []
        found: list[tuple[int, Path]] = []
        for p in self._directory.iterdir():
            m = self._seg_re.fullmatch(p.name)
            if m and p.is_file():
                found.append((int(m.group(1)), p))
        return sorted(found)

    def segment_paths(self) -> list[Path]:
        """全部段文件路径,按段序号升序;目录不存在返回 []。"""
        return [p for _, p in self._segments()]

    # ------------------------------------------------------------------ #
    # 追加与读取
    # ------------------------------------------------------------------ #
    def _tail_state(self) -> tuple[Path, int, int]:
        """当前段 (路径, 行数, 字节数);无段时指向 1 号新段,惰性统计。"""
        if self._tail is None:
            segs = self._segments()
            if segs:
                raw = segs[-1][1].read_bytes()
                self._tail = (segs[-1][1], raw.count(b"\n"), len(raw))
            else:
                self._tail = (self._seg_path(1), 0, 0)
        return self._tail

    def append(self, obj: dict) -> dict:
        """封缄并追加一行:复制 obj、注入 entry_checksum,写当前段(必要时轮转)。

        返回封缄对象(含 entry_checksum);入参 obj 不被修改。
        """
        sealed = dict(obj)
        sealed["entry_checksum"] = entry_checksum(self._mac_key, sealed)
        data = (json.dumps(sealed, ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")
        path, n_lines, n_bytes = self._tail_state()
        if n_lines >= self._seg_max_entries or n_bytes >= self._seg_max_bytes:
            segs = self._segments()
            path = self._seg_path(segs[-1][0] + 1 if segs else 1)
            n_lines, n_bytes = 0, 0
        self._directory.mkdir(parents=True, exist_ok=True)
        with path.open("ab") as f:
            f.write(data)
        self._tail = (path, n_lines + 1, n_bytes + len(data))
        return sealed

    def _read_rows(self) -> list[tuple[dict, str, int]]:
        """按段序读全部行并逐行验 entry_checksum,返回 (对象, 段名, 行号)。

        JSON 解析失败/非对象/checksum 失配均抛 StoreIntegrityError(kind="corrupt"),
        消息含段名与 1 起行号。checksum 比较用 compare_digest(常数时间)。
        """
        rows: list[tuple[dict, str, int]] = []
        for path in self.segment_paths():
            for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    raise StoreIntegrityError(
                        "corrupt", f"{path.name} 第 {line_no} 行 JSON 解析失败",
                    ) from None
                if not isinstance(obj, dict):
                    raise StoreIntegrityError(
                        "corrupt", f"{path.name} 第 {line_no} 行不是 JSON 对象",
                    )
                stored = obj.get("entry_checksum")
                if not isinstance(stored, str) or not hmac.compare_digest(
                    stored, entry_checksum(self._mac_key, obj)
                ):
                    raise StoreIntegrityError(
                        "corrupt", f"{path.name} 第 {line_no} 行 entry_checksum 校验失败",
                    )
                rows.append((obj, path.name, line_no))
        return rows

    def read_all(self) -> list[dict]:
        """按段序返回全部封缄对象(含 entry_checksum),逐行验校验,往返一致。"""
        return [obj for obj, _, _ in self._read_rows()]


def replay_chain(store: SealedNDJSON) -> HashChain:
    """启动链回放:逐行验 checksum → 重建 HashChain → 逐条验 prev_hash→hash 链接。

    重建走 HashChain.append 公开接口逐条重放(自动沿用 mid 前映像规则),重算的
    index/prev_hash/hash 与存储条目逐一比对;任何不符(含链条目字段缺失)抛
    StoreIntegrityError(kind="chain_break"),消息含段名、行号与条目 index。
    checksum/JSON 失配由读取侧抛 kind="corrupt"。返回的链 _prev/entries 已恢复,
    可继续 append。
    """
    chain = HashChain()
    for obj, seg_name, line_no in store._read_rows():
        index = obj.get("index")
        try:
            entry = chain.append(
                obj["entry_type"], obj["payload_digest"], obj["timestamp"],
                obj.get("message_id"),
            )
        except (KeyError, TypeError):
            raise StoreIntegrityError(
                "chain_break",
                f"{seg_name} 第 {line_no} 行链条目字段缺失,链无法重建(index={index})",
            ) from None
        if (entry["index"] != index or entry["prev_hash"] != obj.get("prev_hash")
                or entry["hash"] != obj.get("hash")):
            raise StoreIntegrityError(
                "chain_break",
                f"{seg_name} 第 {line_no} 行链接断裂(index={entry['index']}):"
                "重算 prev_hash/hash 与存储不符",
            )
    return chain
