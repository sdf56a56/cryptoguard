"""
安全审计 —— 复用既有封缄 NDJSON + 在其上补一层「记录级 HMAC + 链式绑定」

复用而非重建:存储层直接用既有的 `app.store.SealedNDJSON`(逐行 HMAC-SHA256
entry_checksum,段式轮转),这里只做三件增量:
  1. 每条记录追加前注入 seq / prev_hash / chain_hash / record_mac,使**记录之间**
     被链式绑定 —— 单纯删一行、换一行、重排两行都会破坏后继记录的链;
  2. record_mac 的密钥独立派生(`audit-mac/v1`),与封缄密钥(chain_mac_key)分离,
     也与保护密钥、客户端密钥分离:任一密钥泄漏不牵连其它域;
  3. 保留期清理:只能整段删除,删除前把「被删段最后一条的 chain_hash」写进
     独立的 checkpoint 日志作为锚点。删掉的内容本身不可恢复(这就是保留期),
     但「删之前的历史有没有被改过」仍可校验到锚点。

**边界(不得对外宣传为更强)**:
  - 持 VAULT_KEY 者可以整链重写(HMAC 密钥由它派生):本模块只检测**非持钥方**
    的篡改;检测整链重写需要外部锚点(离线公证/第三方时间戳);
  - 不检测链尾截断(最新若干条被删且无 checkpoint 时,链仍然「自洽」);
  - 审计写入失败一律向上抛:安全中间件遵循 fail-closed —— 记不了账就不服务。
"""
from __future__ import annotations

import json
import logging
import threading
import time
from pathlib import Path

from ..keys import Vault, hkdf_sha256
from ..store import SealedNDJSON, StoreIntegrityError
from .errors import MiddlewareError
from .verification import (RequestRecord, chain_hash_of, now_iso, record_mac,
                           verify_record_mac)

logger = logging.getLogger(__name__)

#: 中间件的审计目录(与既有 chain/ sessions/ messages/ 平级,互不干扰)
AUDIT_DIR_NAME = "security"
AUDIT_STORE_NAME = "audit"
CHECKPOINT_STORE_NAME = "audit-checkpoint"

_DEFAULT_RETENTION_DAYS = 30


class AuditStore:
    """中间件审计日志:封缄追加 + 链式绑定 + 保留期整段清理。"""

    def __init__(self, directory: Path, mac_key: bytes, *, pepper: bytes,
                 retention_days: int = _DEFAULT_RETENTION_DAYS,
                 seg_max_entries: int = 2000) -> None:
        self._dir = Path(directory)
        self._mac_key = mac_key
        self._pepper = pepper
        self._retention_days = max(0, int(retention_days))
        self._lock = threading.Lock()
        self._store = SealedNDJSON(self._dir, AUDIT_STORE_NAME, mac_key,
                                   seg_max_entries=seg_max_entries)
        self._checkpoints = SealedNDJSON(self._dir, CHECKPOINT_STORE_NAME, mac_key)
        self._tip: tuple[int, str] | None = None      # (seq, chain_hash)
        self._anchor: str | None = None               # 起始锚点(最近 checkpoint)
        self._count: int | None = None
        #: verify() 结果短时缓存:(时间, 结果)。写入/清理后立即失效。
        self._verify_cache: tuple[float, dict] | None = None
        self._verify_ttl = 5.0

    # ------------------------------------------------------------------ #
    @classmethod
    def build(cls, data_dir: Path, vault: Vault, *,
              retention_days: int = _DEFAULT_RETENTION_DAYS,
              seg_max_entries: int = 2000) -> "AuditStore":
        """在 `data_dir/security/` 下建立审计日志。

        密钥派生域(与既有域并列,互不可推):
          - 封缄行校验:直接复用 vault.chain_mac_key(与既有日志同源,便于统一轮换);
          - 记录级 HMAC:`hkdf_sha256(vault.chain_mac_key, "audit-mac/v1")`。
        """
        return cls(Path(data_dir) / AUDIT_DIR_NAME, vault.chain_mac_key,
                   pepper=hkdf_sha256(vault.chain_mac_key, "audit-mac/v1"),
                   retention_days=retention_days, seg_max_entries=seg_max_entries)

    # ------------------------------------------------------------------ #
    # 写入
    # ------------------------------------------------------------------ #
    def record(self, entry: RequestRecord) -> RequestRecord:
        """封缄并追加一条审计记录(就地补齐 seq/链字段后返回同一条)。

        写失败直接抛错(由调用方决定 fail-closed),不吞异常。
        """
        with self._lock:
            self._ensure_loaded_locked()
            assert self._tip is not None
            seq, prev = self._tip
            if not entry.ts:
                entry.ts = now_iso()
            if not entry.ts_epoch:
                entry.ts_epoch = time.time()
            entry.seq = seq + 1
            entry.prev_hash = prev
            entry.chain_hash = chain_hash_of(prev, entry.seq, entry.request_id,
                                             entry.request_digest,
                                             entry.response_digest, entry.ts)
            entry.record_mac = record_mac(self._pepper, entry)
            try:
                self._store.append(entry.to_dict())
            except OSError as exc:
                raise MiddlewareError("internal", f"审计写入失败: {exc}") from None
            self._tip = (entry.seq, entry.chain_hash)
            if self._count is not None:
                self._count += 1
            self._verify_cache = None       # 链已变化,旧结论立即失效
        return entry

    # ------------------------------------------------------------------ #
    # 读取
    # ------------------------------------------------------------------ #
    def get(self, request_id: str) -> dict | None:
        """按 request_id 取最后一条记录(同 id 重复只可能来自重试)。"""
        found = None
        for raw in self._rows():
            if raw.get("request_id") == request_id:
                found = raw
        return found

    def mac_valid(self, record: dict) -> bool:
        """校验单条记录的记录级 HMAC(供 /v1/verify 与管理员接口使用)。"""
        return verify_record_mac(self._pepper, record)

    def list(self, *, limit: int = 50, offset: int = 0, client_id: str = "",
             outcome: str = "", since_epoch: float = 0.0,
             order: str = "desc") -> dict:
        """分页列出审计元数据(不含任何明文,记录本就不含明文)。

        过滤条件:client_id / outcome / since_epoch;`order` 为 desc(默认,新在前)。
        """
        rows = self._rows()
        if client_id:
            rows = [r for r in rows if r.get("client_id") == client_id]
        if outcome:
            rows = [r for r in rows if r.get("outcome") == outcome]
        if since_epoch:
            rows = [r for r in rows if float(r.get("ts_epoch") or 0) >= since_epoch]
        if order == "desc":
            rows = list(reversed(rows))
        limit = max(1, min(int(limit), 500))
        offset = max(0, int(offset))
        page = rows[offset:offset + limit]
        return {"total": len(rows), "offset": offset, "limit": limit,
                "items": page}

    def count(self) -> int:
        with self._lock:
            self._ensure_loaded_locked()
            return int(self._count or 0)

    def tip(self) -> dict:
        """当前链尾(供外部锚定:把 tip_hash 抄到站外即可检测整链重写)。"""
        with self._lock:
            self._ensure_loaded_locked()
            assert self._tip is not None
            return {"seq": self._tip[0], "chain_hash": self._tip[1],
                    "anchor": self._anchor or ""}

    # ------------------------------------------------------------------ #
    # 校验
    # ------------------------------------------------------------------ #
    def verify(self, *, full: bool = True, fresh: bool = False) -> dict:
        """校验整条审计链,返回逐项结论与失败原因。

        检查项:
          a) 行级封缄(entry_checksum)—— 由 SealedNDJSON 读取侧完成,fail → kind=corrupt;
          b) seq 连续性(从 checkpoint 锚点之后的第一条起);
          c) prev_hash 链接 + chain_hash 自洽;
          d) record_mac(记录级 HMAC,密钥独立派生)。

        `full=False` 时只做 d) 与 c) 的自洽检查(不重算整链 prev 前缀),用于大日志的
        快速抽查。任何一项失败都如实写入 failures,不掩饰。

        结果按 5 秒 TTL 缓存(写入与清理时立即失效),避免健康检查/verify 接口把
        整链重算放大成 O(n)/次。`fresh=True` 强制绕过缓存(外部改动日志文件后
        需要立刻得到真实结论;缓存本身不感知进程外的写入)。
        """
        now = time.monotonic()
        cached = self._verify_cache
        if not fresh and cached is not None and now - cached[0] < self._verify_ttl:
            return cached[1]
        result = self._verify_uncached(full=full)
        self._verify_cache = (now, result)
        return result

    def _verify_uncached(self, *, full: bool = True) -> dict:
        failures: list[dict] = []
        checkpoints: list[dict] = []
        try:
            checkpoints = self._checkpoint_rows()
        except StoreIntegrityError as exc:
            failures.append({"kind": "corrupt", "scope": "checkpoint", "detail": str(exc)})

        try:
            rows = self._rows()
        except StoreIntegrityError as exc:
            return {"intact": False, "records": 0, "failures": [
                {"kind": "corrupt", "scope": "audit", "detail": str(exc)}],
                "checkpoints": checkpoints, "mac_verified": False}

        anchor = str(checkpoints[-1].get("anchor") or "") if checkpoints else ""
        expected_prev = anchor
        expected_seq = None
        for raw in rows:
            rid = raw.get("request_id", "?")
            try:
                seq = int(raw["seq"])
            except (KeyError, TypeError, ValueError):
                failures.append({"kind": "schema", "request_id": rid,
                                 "detail": "seq 字段缺失或非法"})
                continue
            if full:
                # 序号连续性与前驱链接:删除/重排任意条目都会在这里被抓住
                if expected_seq is None:
                    expected_seq = seq
                if seq != expected_seq:
                    failures.append({"kind": "sequence_gap", "request_id": rid, "seq": seq,
                                     "detail": f"期望 seq={expected_seq},实际 {seq}"
                                               "(条目被删或重排)"})
                    expected_seq = seq
                expected_seq += 1

                if str(raw.get("prev_hash") or "") != expected_prev:
                    failures.append({"kind": "chain_break", "request_id": rid, "seq": seq,
                                     "detail": "prev_hash 与上一条 chain_hash 不符"
                                               "(条目被删/换/重排)"})
            prev = str(raw.get("prev_hash") or "")
            want = chain_hash_of(prev, seq, str(raw.get("request_id") or ""),
                                 str(raw.get("request_digest") or ""),
                                 str(raw.get("response_digest") or ""),
                                 str(raw.get("ts") or ""))
            if str(raw.get("chain_hash") or "") != want:
                failures.append({"kind": "chain_break", "request_id": rid, "seq": seq,
                                 "detail": "chain_hash 与自身字段不符(记录被改写)"})
            expected_prev = str(raw.get("chain_hash") or "")

            if not verify_record_mac(self._pepper, raw):
                failures.append({"kind": "mac_mismatch", "request_id": rid, "seq": seq,
                                 "detail": "记录级 HMAC 校验失败(记录被改写或非本机写入)"})

        mac_ok = not any(f["kind"] == "mac_mismatch" for f in failures)
        return {
            "intact": not failures,
            "records": len(rows),
            "first_seq": int(rows[0]["seq"]) if rows else 0,
            "last_seq": int(rows[-1]["seq"]) if rows else 0,
            "tip_hash": str(rows[-1].get("chain_hash") or "") if rows else anchor,
            "anchor": anchor,
            "checkpoints": checkpoints,
            "mac_verified": mac_ok,
            "scope_note": "仅覆盖本地日志的完整性;不证明上游服务商身份,"
                          "也不防持 VAULT_KEY 者整链重写",
            "failures": failures,
        }

    # ------------------------------------------------------------------ #
    # 保留期
    # ------------------------------------------------------------------ #
    def purge_expired(self, *, now: float | None = None, dry_run: bool = False) -> dict:
        """按保留期删除**整段**过期审计(不足一段的等待下次)。

        删除前把被删段最后一条的 chain_hash 写进 checkpoint 作为锚点,
        之后的 verify() 会以该锚点为起点继续校验,不会被误判为链断裂。
        被删记录本身不可恢复 —— 这就是保留期的语义。
        """
        if self._retention_days <= 0:
            return {"purged_records": 0, "purged_segments": [], "dry_run": dry_run,
                    "reason": "保留期为 0 表示永不清理"}
        now = time.time() if now is None else now
        cutoff = now - self._retention_days * 86400.0
        with self._lock:
            paths = self._store.segment_paths()
            if len(paths) < 2:
                return {"purged_records": 0, "purged_segments": [], "dry_run": dry_run,
                        "reason": "仅有一个段,不做部分清理"}
            doomed: list[Path] = []
            last_chain_hash = ""
            removed = 0
            for path in paths[:-1]:                  # 永远保留最后一段
                try:
                    rows = [json.loads(line) for line in
                            path.read_text(encoding="utf-8").splitlines() if line.strip()]
                except (OSError, ValueError) as exc:
                    logger.error("审计保留期清理中止(段不可解析, fail-closed): %s", exc)
                    return {"purged_records": 0, "purged_segments": [], "dry_run": dry_run,
                            "reason": f"段 {path.name} 不可解析,已中止清理"}
                if not rows:
                    continue
                if max(float(r.get("ts_epoch") or 0) for r in rows) >= cutoff:
                    break                            # 段内还有未过期记录,后续段更晚
                doomed.append(path)
                removed += len(rows)
                last_chain_hash = str(rows[-1].get("chain_hash") or "")
            if not doomed:
                return {"purged_records": 0, "purged_segments": [], "dry_run": dry_run,
                        "reason": "无整段满足过期条件"}
            if dry_run:
                return {"purged_records": removed,
                        "purged_segments": [p.name for p in doomed],
                        "dry_run": True, "cutoff_epoch": cutoff}
            self._checkpoints.append({
                "type": "retention",
                "ts": now_iso(),
                "ts_epoch": now,
                "cutoff_epoch": cutoff,
                "removed_records": removed,
                "removed_segments": [p.name for p in doomed],
                "anchor": last_chain_hash,
                "retention_days": self._retention_days,
            })
            for path in doomed:
                try:
                    path.unlink()
                except OSError as exc:
                    logger.error("审计段删除失败(%s): %s", path.name, exc)
            # 状态失效,下次访问重新加载
            self._tip = None
            self._anchor = None
            self._count = None
            self._verify_cache = None
            logger.warning("审计保留期清理:删除 %d 条、%d 个段(锚点 %s…)",
                           removed, len(doomed), last_chain_hash[:12])
            return {"purged_records": removed,
                    "purged_segments": [p.name for p in doomed],
                    "dry_run": False, "cutoff_epoch": cutoff,
                    "anchor": last_chain_hash}

    # ------------------------------------------------------------------ #
    # 内部
    # ------------------------------------------------------------------ #
    def _rows(self) -> list[dict]:
        try:
            return self._store.read_all()
        except StoreIntegrityError:
            raise
        except OSError as exc:
            raise StoreIntegrityError("corrupt", f"审计日志读取失败: {exc}") from None

    def _checkpoint_rows(self) -> list[dict]:
        try:
            return self._checkpoints.read_all()
        except OSError as exc:
            raise StoreIntegrityError("corrupt", f"checkpoint 读取失败: {exc}") from None

    def _ensure_loaded_locked(self) -> None:
        """惰性加载链尾与条数(调用方需持锁)。"""
        if self._tip is not None:
            return
        rows = self._rows()
        checkpoints = self._checkpoint_rows()
        self._anchor = str(checkpoints[-1].get("anchor") or "") if checkpoints else ""
        if rows:
            last = rows[-1]
            self._tip = (int(last.get("seq") or 0), str(last.get("chain_hash") or ""))
        else:
            self._tip = (0, self._anchor or "")
        self._count = len(rows)
