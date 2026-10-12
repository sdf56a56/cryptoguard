"""
启动装配模块 —— Vault/三本封缄日志/链回放/网关组装(Task 11)

装配顺序(build_chat_service):
  Vault.load_or_init → 三本 SealedNDJSON(chain/sessions/messages)→
  replay_chain 链回放 → SessionStore → 双向索引核验 → ChatService。

安全目标:
  - fail-fast,不带病服务:指纹不符/key 缺失(VaultKeyError)、封缄损坏/链断
    (StoreIntegrityError)一律上抛,由 lifespan 记 logger.critical 后终止启动。
  - SEC-REPLAY 双向索引:每条消息 chain_refs 的 index 必须落在链上且
    条目 message_id == 消息 id;每条带 message_id 的链条目必须被对应消息的
    chain_refs 引用。任一不符 → StoreIntegrityError("chain_break")。
  - 网关密钥不落盘:MIMO_API_KEY 只从环境/backend/.env 读取;缺失时
    mimo=None(mock-only,恒降级 degraded="mock")。

明确不承诺:
  - 不承诺多进程并发启动同一数据目录(单写者模型,同 store.py);
  - 不承诺跨版本数据迁移:回放按当前 schema 严格校验。
"""
from __future__ import annotations

import logging
import os
from pathlib import Path

from .chat_service import ChatService
from .crypto.hashchain import HashChain
from .keys import Vault, _load_env_file
from .llm import LLMGateway, MimoLLM, MockChat
from .proxy import guard
from .sessions import SessionStore
from .store import (DEFAULT_SEG_MAX_BYTES, DEFAULT_SEG_MAX_ENTRIES,
                    SealedNDJSON, StoreIntegrityError, replay_chain)

logger = logging.getLogger(__name__)

_ENV_PATH_DEFAULT = Path(__file__).resolve().parent.parent / ".env"  # backend/.env


def default_data_dir() -> Path:
    """默认数据目录:repo 根 data/(lifespan 装配与验收 API 同一口径)。"""
    return Path(__file__).resolve().parent.parent.parent / "data"


def _mimo_api_key() -> str:
    """读取 MIMO_API_KEY:os.environ 优先,缺省回退 backend/.env;空值视为缺失。"""
    raw = os.environ.get("MIMO_API_KEY", "").strip()
    if not raw:
        raw = _load_env_file(_ENV_PATH_DEFAULT).get("MIMO_API_KEY", "").strip()
    return raw


def _cross_check(sessions: SessionStore, chain: HashChain) -> None:
    """SEC-REPLAY 双向索引核验 mid↔chain_refs,不符抛 chain_break。"""
    entries = chain.entries
    refs_by_id: dict[str, list] = {}
    for rec in sessions.messages_log.read_all():
        mid = rec.get("id")
        if not isinstance(mid, str):
            continue
        refs = list(rec.get("chain_refs") or [])
        refs_by_id[mid] = refs
        for i in refs:
            if (not isinstance(i, int) or i < 0 or i >= len(entries)
                    or entries[i].get("message_id") != mid):
                raise StoreIntegrityError(
                    "chain_break",
                    f"双向索引断裂:消息 {mid} 的 chain_refs[{i}] 与链条目不符",
                )
    for e in entries:
        mid = e.get("message_id")
        if mid is None:
            continue
        if mid not in refs_by_id or e["index"] not in refs_by_id[mid]:
            raise StoreIntegrityError(
                "chain_break",
                f"双向索引断裂:链条目 {e['index']} 的 message_id={mid} "
                "无对应消息引用",
            )


def build_chat_service(data_dir: Path, gateway: LLMGateway | None = None, *,
                       seg_max_entries: int = DEFAULT_SEG_MAX_ENTRIES,
                       seg_max_bytes: int = DEFAULT_SEG_MAX_BYTES) -> ChatService:
    """装配 ChatService(Vault → 三本封缄日志 → 链回放 → 双向核验 → 组装)。

    - VaultKeyError / StoreIntegrityError 原样上抛(启动 fail-fast);
    - gateway 为 None 时按 MIMO_API_KEY 组装:有钥 MimoLLM 优先,
      无钥 mimo=None(mock-only,恒降级 degraded="mock");
    - seg_max_entries / seg_max_bytes 仅供测试触发段轮转,生产走默认值。
    """
    vault = Vault.load_or_init(data_dir)
    chain_log = SealedNDJSON(data_dir / "chain", "seg", vault.chain_mac_key,
                             seg_max_entries=seg_max_entries,
                             seg_max_bytes=seg_max_bytes)
    sessions_log = SealedNDJSON(data_dir / "sessions", "seg", vault.chain_mac_key,
                                seg_max_entries=seg_max_entries,
                                seg_max_bytes=seg_max_bytes)
    messages_log = SealedNDJSON(data_dir / "messages", "seg", vault.chain_mac_key,
                                seg_max_entries=seg_max_entries,
                                seg_max_bytes=seg_max_bytes)
    chain = replay_chain(chain_log)      # corrupt / chain_break 上抛
    sessions = SessionStore(vault, sessions_log, messages_log)
    sessions.list_sessions()             # 载会话日志并逐行验封缄(损坏即启动失败)
    _cross_check(sessions, chain)        # SEC-REPLAY 双向索引核验

    if gateway is None:
        api_key = _mimo_api_key()
        mimo = MimoLLM(api_key=api_key) if api_key else None
        if mimo is None:
            logger.warning(
                "MIMO_API_KEY 缺失:网关仅 Mock(mimo=None),恒降级 degraded='mock'")
        gateway = LLMGateway(mimo=mimo, mock=MockChat())
    return ChatService(guard, sessions, gateway, chain, chain_log)
