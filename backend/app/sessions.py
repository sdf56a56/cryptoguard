"""
会话与双视角映射模块 —— session_mapping_ct / mapping_delta_ct 封缄与 user_view 动态还原

安全目标:
  - user_view 永不落盘:磁盘只存 llm_view(已脱敏文本)与封缄映射(mapping_delta_ct
    本轮增量、session_mapping_ct 会话全量);还原出的 user_view 仅存在于内存与
    响应体(SEC-STORE-1)。
  - 映射表两级绑定:消息级 mapping_delta_ct 供单条审计/令牌归因,会话级
    session_mapping_ct 每轮合并后重封缄(rev 递增、追加新行、latest rev 赢),
    跨轮共指可完整还原。
  - 跨会话拒绝:restore_view 作用域校验,消息记录 session_id 与传入会话不一致
    抛 ValueError;消息 user_view 一律用其 OWN 会话的映射还原。
  - 会话密钥只以封缄形态落盘:session_secrets_ct = {k_t1, session_salt, t2_key}
    (hex),经 AeadCipher 封缄;明文密钥不进日志。

明确不承诺:
  - 不承诺防持有 VAULT_KEY 的攻击者解封历史映射(密钥失窃即明文失窃)。
  - 不承诺映射值本身恰好包含其他替换形态时的歧义还原(替换按形态长度降序执行,
    仍可能双层嵌套歧义);不承诺并发写同一日志(单写者模型,同 store.py)。
  - 不承诺 user_view 还原语义等价于"原文逐字恢复"以外的任何 NLP 级理解。

归约:机密性/完整性归约到 AES-GCM(crypto/aead.py);封缄行完整性归约到
HMAC-SHA256 entry_checksum(store.py)。
"""
from __future__ import annotations

import secrets
import uuid
from collections.abc import Mapping
from datetime import datetime, timezone

from .crypto.aead import AeadCipher
from .detection import Tokenizers
from .keys import Vault
from .store import SealedNDJSON
from .tokens import T2Cipher

_TS_FMT = "%Y-%m-%dT%H:%M:%S.%fZ"  # ISO8601 UTC,同 proxy.py
_ROLES = frozenset({"user", "assistant"})
_MSG_ID_BYTES = 6  # "msg_" + 12 位小写十六进制


def _now_iso() -> str:
    """当前 UTC 时间,ISO8601 `%Y-%m-%dT%H:%M:%S.%fZ`(与 proxy.py 时间戳同格式)。"""
    return datetime.now(timezone.utc).strftime(_TS_FMT)


class SessionStore:
    """会话 + 双视角消息存储:两本 SealedNDJSON 追加日志 + 两把 AEAD 封缄。

    会话日志 append-only:session_mapping_ct 每轮重封缄时追加新版本行(rev 递增),
    读取时 latest rev 赢;消息日志一行一条消息,只存 llm_view + *_ct。
    构造参数 vault 提供 mapping_key(映射/会话密钥封缄)与 reasoning_key(reasoning 封缄);
    sessions_log/messages_log 由调用方按 data/sessions、data/messages 接线(段名 seg,
    mac_key=vault.chain_mac_key)。
    """

    def __init__(self, vault: Vault, sessions_log: SealedNDJSON, messages_log: SealedNDJSON):
        self.sessions_log = sessions_log
        self.messages_log = messages_log
        self._mapping_aead = AeadCipher(vault.mapping_key)     # 映射表 + 会话密钥聚合
        self._reasoning_aead = AeadCipher(vault.reasoning_key)  # reasoning_ct

    # ------------------------------------------------------------------ #
    # 会话
    # ------------------------------------------------------------------ #
    def create_session(self, title: str) -> dict:
        """新建会话:随机 Tokenizers 会话密钥封缄入 session_secrets_ct,映射为空。

        返回落盘会话记录(含 entry_checksum);session_id = uuid4().hex。
        """
        tok = Tokenizers.default()
        secrets_pt = {
            "k_t1": tok.k_t1.hex(),
            "session_salt": tok.session_salt.hex(),
            "t2_key": tok.t2.key_bytes.hex(),
        }
        record = {
            "type": "session",
            "id": uuid.uuid4().hex,
            "title": title,
            "created": _now_iso(),
            "rev": 0,
            "session_secrets_ct": self._mapping_aead.encrypt(secrets_pt),
            "session_mapping_ct": self._mapping_aead.encrypt({}),
        }
        return self.sessions_log.append(record)

    def list_sessions(self) -> list[dict]:
        """全部会话记录(latest rev 生效),按创建顺序;供会话侧栏/列表 API 消费。"""
        return list(self._latest_sessions().values())

    def _latest_sessions(self) -> dict[str, dict]:
        """id → 最新 rev 会话记录;同 id 多版本行时 latest rev 赢(按日志序)。"""
        latest: dict[str, dict] = {}
        for rec in self.sessions_log.read_all():
            sid = rec.get("id")
            if not isinstance(sid, str):
                continue
            prev = latest.get(sid)
            if prev is None or int(rec.get("rev", -1)) >= int(prev.get("rev", -1)):
                latest[sid] = rec
        return latest

    def _session_record(self, session_id: str) -> dict:
        rec = self._latest_sessions().get(session_id)
        if rec is None:
            raise ValueError(f"会话不存在: {session_id}")
        return rec

    def _mapping_for(self, session_id: str) -> dict[str, str]:
        """解封会话全量映射 {替换形态: 明文值};未知会话 ValueError。"""
        rec = self._session_record(session_id)
        blob = rec["session_mapping_ct"]
        return dict(self._mapping_aead.decrypt(blob["iv"], blob["ciphertext"]))

    # ------------------------------------------------------------------ #
    # 消息
    # ------------------------------------------------------------------ #
    def add_message(
        self,
        session_id: str,
        role: str,
        llm_view: str,
        mapping_delta: dict | None = None,
        reasoning_ct: dict | None = None,
        files: list | None = None,
        chain_refs: list | None = None,
        reply_meta: dict | None = None,
        verification: list | None = None,
        artifacts: dict | None = None,
    ) -> dict:
        """追加一条双视角消息,返回落盘消息记录(含 entry_checksum,无 user_view)。

        mapping_delta 为本轮 {替换形态: 明文值} 增量:消息级封缄存 mapping_delta_ct,
        并合并进会话全量映射(重封缄 session_mapping_ct、rev+1、追加新会话行)。
        reasoning_ct 为待封缄的 reasoning 字典(None → 落盘 null),以 reasoning_key
        封缄,明文 reasoning 不落盘、不进后续 prompt(Task 8 职责)。
        """
        if role not in _ROLES:
            raise ValueError(f"非法 role: {role!r}(仅 user|assistant)")
        latest = self._session_record(session_id)
        # 先合并映射(增量先持久化),再追加消息行
        if mapping_delta:
            merged = self._mapping_for(session_id)
            merged.update({str(k): str(v) for k, v in mapping_delta.items()})
            self.sessions_log.append({
                **{k: v for k, v in latest.items() if k != "entry_checksum"},  # 新行新校验和
                "rev": int(latest.get("rev", 0)) + 1,
                "session_mapping_ct": self._mapping_aead.encrypt(merged),
            })
        record = {
            "type": "message",
            "id": "msg_" + secrets.token_hex(_MSG_ID_BYTES),
            "session_id": session_id,
            "role": role,
            "ts": _now_iso(),
            "llm_view": llm_view,
            "mapping_delta_ct": self._mapping_aead.encrypt(
                {str(k): str(v) for k, v in (mapping_delta or {}).items()}
            ),
            "reasoning_ct": (
                self._reasoning_aead.encrypt(reasoning_ct) if reasoning_ct is not None else None
            ),
            "files": list(files or []),
            "chain_refs": list(chain_refs or []),
            "reply_meta": (
                dict(reply_meta) if reply_meta is not None
                else {"model": None, "incomplete": False, "degraded": None}
            ),
            "verification": list(verification or []),
            "artifacts": dict(artifacts or {}),
        }
        return self.messages_log.append(record)

    def get_message(self, message_id: str) -> dict:
        """按 id 取消息记录,并以消息 OWN 会话的映射动态补 user_view(仅内存)。"""
        for rec in self.messages_log.read_all():
            if rec.get("id") == message_id:
                return self._with_user_view(rec)
        raise ValueError(f"消息不存在: {message_id}")

    def list_messages(self, session_id: str) -> list[dict]:
        """本会话全部消息(日志序),每条动态补 user_view;未知会话 ValueError。"""
        self._session_record(session_id)
        out: list[dict] = []
        for rec in self.messages_log.read_all():
            if rec.get("session_id") != session_id:
                continue  # 作用域:消息 session_id 必须等于传入会话
            out.append(self._with_user_view(rec))
        return out

    def _with_user_view(self, record: dict) -> dict:
        """复制消息记录并动态补 user_view;不修改落盘对象。"""
        out = dict(record)
        out["user_view"] = self.restore_view(record["session_id"], record["llm_view"])
        return out

    # ------------------------------------------------------------------ #
    # 还原
    # ------------------------------------------------------------------ #
    def restore_view(self, session_id: str, llm_view: str | Mapping) -> str:
        """解封会话全量映射,把 llm_view 中替换形态逆向还原为明文(user_view)。

        llm_view 可为脱敏文本,或消息记录 dict(如 get_message 返回值):后者强制
        校验 record["session_id"] == session_id,跨会话/跨作用域抛 ValueError;
        未知会话同样 ValueError。替换按形态长度降序执行,保证长形态优先命中。
        """
        if isinstance(llm_view, Mapping):
            rec_session = llm_view.get("session_id")
            if rec_session != session_id:
                raise ValueError(
                    "跨会话还原被拒:消息 session_id 与传入会话不一致"
                    f"({rec_session!r} != {session_id!r})"
                )
            text = llm_view.get("llm_view")
            if not isinstance(text, str):
                raise ValueError("消息记录缺少 llm_view 文本,无法还原")
        else:
            text = llm_view
        mapping = self._mapping_for(session_id)  # 未知会话 → ValueError
        restored = text
        for form, value in sorted(mapping.items(), key=lambda kv: -len(kv[0])):
            restored = restored.replace(form, value)
        return restored

    def decrypt_reasoning(self, reasoning_ct: dict | None) -> dict | None:
        """解封 reasoning_ct → reasoning 字典;None 原样返回(用户消息无 reasoning)。"""
        if reasoning_ct is None:
            return None
        return self._reasoning_aead.decrypt(reasoning_ct["iv"], reasoning_ct["ciphertext"])

    # ------------------------------------------------------------------ #
    # 会话令牌密钥
    # ------------------------------------------------------------------ #
    def open_tokenizer(self, session_id: str) -> Tokenizers:
        """从 session_secrets_ct 重建本会话 Tokenizers(k_t1/session_salt/T2Cipher)。"""
        rec = self._session_record(session_id)
        blob = rec["session_secrets_ct"]
        sec = self._mapping_aead.decrypt(blob["iv"], blob["ciphertext"])
        return Tokenizers(
            k_t1=bytes.fromhex(sec["k_t1"]),
            session_salt=bytes.fromhex(sec["session_salt"]),
            t2=T2Cipher(bytes.fromhex(sec["t2_key"])),
        )
