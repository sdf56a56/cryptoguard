"""
单轮对话编排 —— 八阶段流水线 + provider 封缄 + 带 message_id 入链(Task 8)

数据流(每轮,spec §2.3/§5):
  detect → tokenize → package → hash → dispatch → verify → restore → persist
  每阶段经 on_event("stage", {stage, status, t_ms}) 上报;dispatch 期 token 经
  on_event("token", {delta, reasoning}) 分轨透传;收尾 on_event("done", 同返回值)。

安全目标:
  - 出站只见令牌:明文只进封缄映射(mapping_delta),prompt 历史只回传 llm_view;
    reasoning 一律只存 reasoning_ct,绝不进多轮回传(侧信道消除)。
  - provider 封缄恒执行(含 mock):response_hash(JCS 域分隔)绑定
    (output, input_hash, model_cert, nonce, timestamp),Ed25519 签名,
    回程走 guard._verify_v2 四层验证;断流时响应完整性行置「跳过(不完整)」。
  - 双向索引落盘:链条目带 message_id(用户消息 id),用户消息记录带
    chain_refs(条目 index);两向都持久化,不靠运行时遍历。

明确不承诺:
  - 不承诺检测召回率:漏检实体仍明文出站(检测模块边界)。
  - 不承诺编排层并发安全:同 store.py 单写者模型,同一会话串行调用。
  - 不承诺中途异常的成对落盘:验证后、落盘前抛错时本轮不产生任何持久化
    (调用方按错误事件处理);不承诺断流残缺输出的语义完整性。
  - chain_refs 在用户消息落盘时按当前链长预算 index(单写者下确定),
    入链后逐条核对,不符即 RuntimeError(状态被外部污染)。
"""
from __future__ import annotations

import time
import uuid
from collections.abc import Callable
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from .canon import canon
from .crypto.hashchain import HashChain
from .detection import detect_sensitive, tokenize_entities
from .llm import LLMGateway
from .mock_llm import MockLLM
from .schemas import OverrideEvent, build_outbound, verify_outbound
from .sessions import SessionStore
from .store import SealedNDJSON

if TYPE_CHECKING:  # pragma: no cover - 仅类型
    from .proxy import CryptoGuard

_TS_FMT = "%Y-%m-%dT%H:%M:%S.%fZ"  # ISO8601 UTC,同 proxy.py

#: 八阶段名(spec §3.4,顺序即流水线顺序)
STAGES = ("detect", "tokenize", "package", "hash",
          "dispatch", "verify", "restore", "persist")

#: 系统提示:私有数据已令牌化,占位符按不透明标识符对待
SYSTEM_PROMPT = (
    "You are a helpful assistant. Private data in this conversation has been "
    "replaced by opaque tokens such as [NAME#a1b2c3d4e5]. Treat every such "
    "placeholder as an opaque identifier: never guess or reconstruct the "
    "original values, never ask the user for them, and refer to them exactly "
    "as written."
)

#: 流式回调事件转发器:("stage", {...}) / ("token", {...}) / ("done", {...})
OnEvent = Callable[[str, dict], None]


class ChatService:
    """单轮编排器:检测→令牌→出站→网关→封缄验证→还原→落盘入链。

    安全目标/明确不承诺见模块 docstring;本类只做「一轮」的编排,
    会话生命周期、SSE 传输、限流由调用方(Task 9)负责。
    """

    def __init__(self, guard: "CryptoGuard", sessions: SessionStore,
                 gateway: LLMGateway, chain: HashChain,
                 chain_log: SealedNDJSON) -> None:
        self._guard = guard
        self._sessions = sessions
        self._gateway = gateway
        self._chain = chain          # 单链实例(T11 经 store.replay_chain 重建注入)
        self._chain_log = chain_log  # 链写穿日志(SealedNDJSON)
        #: 装配时由 bootstrap 注入的 LLM 配置存储;None 表示网关自带配置
        #: (测试直注入 StubGateway 的场景)。API 层经此读写设置页配置。
        self.llm_config = None

    # ------------------------------------------------------------------ #
    # 只读访问(Task 9/10 API 接线;写入仍经 run_turn)
    # ------------------------------------------------------------------ #
    @property
    def sessions(self) -> SessionStore:
        """会话存储只读访问(会话/查看器 API 消费)。"""
        return self._sessions

    @property
    def chain(self) -> HashChain:
        """哈希链只读访问(查看器 API 消费;入链仍经 run_turn)。"""
        return self._chain

    # ------------------------------------------------------------------ #
    # 主入口
    # ------------------------------------------------------------------ #
    def run_turn(self, session_id: str, text: str,
                 files: list | None = None,
                 on_event: OnEvent | None = None,
                 overrides: list | None = None) -> dict:
        """执行一轮对话(八阶段),返回收尾摘要(与 on_event("done") 同载荷)。

        - text 空白且无附件 → ValueError(调用方映射 400),不发事件、不落盘、不入链;
        - files:[{"filename": str, "data": bytes}](双通道由 guard._build_file_payloads 路由);
        - overrides:OverrideEvent 形状的用户决策列表(哈希进 input_hash 并入 USER_OVERRIDE 链);
        - on_event(kind, payload):kind ∈ {"stage","token","done"},可为 None。

        返回 {message_id, assistant_message_id, verification, chain_refs,
              incomplete, degraded, status}。
        """
        if (not text or not text.strip()) and not files:
            raise ValueError("空白输入被拒:text 无内容且无附件")
        emit = self._emitter(on_event)
        file_list = files or []

        # -- detect:敏感实体检测(按 guard 策略) ------------------------- #
        enabled = set(self._guard.policy["enabled_types"])
        mode = self._guard.policy["mode"]
        with self._stage(emit, "detect"):
            det = detect_sensitive(text, enabled_types=enabled, mode=mode)

        # -- tokenize:分级令牌 + 文内替换 + 映射增量 --------------------- #
        with self._stage(emit, "tokenize"):
            tok = self._sessions.open_tokenizer(session_id)
            nonce = uuid.uuid4().hex
            timestamp = datetime.now(timezone.utc).strftime(_TS_FMT)
            token_ents = tokenize_entities(det.entities, tok)
            redacted = self._guard._apply_tokens(text, det.entities, token_ents)
            mapping_delta = {te.replacement: te.value for te in token_ents}

        # -- package:文件双通道 + 令牌去重 + 映射合并 --------------------- #
        with self._stage(emit, "package"):
            file_payloads, file_commits, ftoken_ents = self._guard._build_file_payloads(
                file_list, tok, enabled)
            all_tokens = self._guard._dedup_tokens(token_ents + ftoken_ents)
            mapping_delta.update({te.replacement: te.value for te in ftoken_ents})
            ovs = [e if isinstance(e, OverrideEvent) else OverrideEvent(**e)
                   for e in (overrides or [])]
            file_records = [
                {"name": f["filename"], "file_hash": p.file_hash,
                 "channel": p.content_tier}
                for f, p in zip(file_list, file_payloads)
            ]

        # -- hash:出站包唯一拼装 + 网关三规则 ---------------------------- #
        with self._stage(emit, "hash"):
            req = build_outbound(
                session_id=session_id,
                redacted_text=redacted,
                file_payloads=file_payloads,
                token_index=[{"token": t.token, "type": t.type, "tier": t.tier,
                              "leak_class": t.leak_class} for t in all_tokens],
                override_events=[e.model_dump() for e in ovs],
                nonce=nonce,
                timestamp=timestamp,
            )
            violations = verify_outbound(
                req, tok.k_t1, tok.session_salt,
                {t.token: (t.type, t.value) for t in all_tokens})
            if violations:
                raise ValueError("出站包校验失败: " + "; ".join(violations))

        # -- dispatch:组 prompt([system]+历史 llm_view+新出站)并流式调用 -- #
        with self._stage(emit, "dispatch"):
            messages = self._build_messages(session_id, req.redacted_text)
            on_token = None
            if on_event is not None:
                def on_token(delta: str, reasoning: bool) -> None:
                    on_event("token", {"delta": delta, "reasoning": reasoning})
            reply = self._gateway.chat(messages, on_token)

        # -- verify:provider 封缄(恒执行)+ 回程四层验证 ------------------ #
        with self._stage(emit, "verify"):
            response_hash = MockLLM._response_hash(
                reply.output, req.input_hash, self._guard.model_cert,
                nonce, timestamp)
            signature = self._guard.llm.provider_signer.sign(
                response_hash.encode("utf-8"))
            resp = {
                "output": reply.output,
                "model_cert": self._guard.model_cert,
                "response_hash": response_hash,
                "signature": signature,
                "provider_public_key": self._guard.llm.provider_public_b64,
                "nonce": nonce,
                "timestamp": timestamp,
            }
            verification = self._guard._verify_v2(resp, req)
            if reply.incomplete:
                # 断流:响应完整性不可判定,覆写该行为「跳过(不完整)」
                verification = [
                    {"layer": "响应完整性", "ok": None, "detail": "跳过(不完整)"}
                    if v["layer"] == "响应完整性" else v
                    for v in verification
                ]
                status = "incomplete"
            else:
                status = "verified" if all(v["ok"] for v in verification) else "rejected"

        # -- restore:用户消息先落盘(映射增量入会话)→ 还原 assistant 视角 -- #
        reply_meta = {"model": reply.model, "incomplete": reply.incomplete,
                      "degraded": reply.degraded}
        with self._stage(emit, "restore"):
            chain_refs = self._predict_chain_refs(ovs, file_commits)
            user_rec = self._sessions.add_message(
                session_id, "user", req.redacted_text,
                mapping_delta=mapping_delta,
                reasoning_ct=None,
                files=file_records,
                chain_refs=chain_refs,
                reply_meta=reply_meta,
                verification=verification,
                artifacts={
                    "outbound": req.model_dump(),
                    "canonical_preimage": req.canonical_preimage,
                    "tokens": [{"token": t.token, "type": t.type, "tier": t.tier,
                                "leak_class": t.leak_class,
                                "replacement": t.replacement,
                                "pending": t.pending} for t in all_tokens],
                    "entities": [{"type": e.type, "start": e.start, "end": e.end,
                                  "value_len": len(e.value)} for e in det.entities],
                },
            )
            # 还原 assistant 视角:走记录形态启用 T7 跨会话作用域校验
            # (assistant 记录随后才落盘,故以等价记录形态传入;user_view 不落盘,
            # 读取侧 get_message/list_messages 动态还原)。
            self._sessions.restore_view(
                session_id, {"session_id": session_id, "llm_view": reply.output})

        # -- persist:assistant 落盘 + 入链写穿 + 回填双向索引 ------------- #
        with self._stage(emit, "persist"):
            assistant_rec = self._sessions.add_message(
                session_id, "assistant", reply.output,
                mapping_delta={},          # 本轮无新令牌
                reasoning_ct=({"reasoning_content": reply.reasoning_content}
                              if reply.reasoning_content else None),
                files=[],
                chain_refs=[],
                reply_meta=reply_meta,
                verification=verification,
                artifacts={"response_hash": response_hash,
                           "signature": signature},
            )
            entries = self._append_chain_entries(
                ovs, file_commits, req.input_hash, timestamp,
                user_rec["id"], chain_refs)

        result = {
            "message_id": user_rec["id"],
            "assistant_message_id": assistant_rec["id"],
            "verification": verification,
            "chain_refs": [e["index"] for e in entries],
            "incomplete": reply.incomplete,
            "degraded": reply.degraded,
            "model": reply.model,      # 实际应答模型(供前端状态栏/气泡展示)
            "status": status,
        }
        emit("done", result)
        return result

    # ------------------------------------------------------------------ #
    # 辅助
    # ------------------------------------------------------------------ #
    def _build_messages(self, session_id: str, redacted_text: str) -> list[dict]:
        """组 prompt:[system] + 历史(仅 llm_view)+ 新出站文本。

        历史只回传 content/llm_view:user_view(明文)与 reasoning(思维链)
        一律不进 messages,消除明文出站与令牌语义侧信道。
        """
        messages = [{"role": "system", "content": SYSTEM_PROMPT}]
        for rec in self._sessions.list_messages(session_id):
            messages.append({"role": rec["role"], "content": rec["llm_view"]})
        messages.append({"role": "user", "content": redacted_text})
        return messages

    def _predict_chain_refs(self, ovs: list, file_commits: list[str]) -> list[int]:
        """预算本轮链条目 index(单写者下确定):USER_OVERRIDE? + FILE_COMMIT* + QUERY。

        用户消息先落盘(add_message 不可回填),chain_refs 须在落盘时给出;
        入链后 _append_chain_entries 逐条核对实际 index 与预算一致。
        """
        n_entries = (1 if ovs else 0) + len(file_commits) + 1
        start = len(self._chain.entries)
        return list(range(start, start + n_entries))

    def _append_chain_entries(self, ovs: list, file_commits: list[str],
                              input_hash: str, timestamp: str,
                              message_id: str, expect_refs: list[int]) -> list[dict]:
        """入链(顺序同 proxy.query_v2:USER_OVERRIDE → FILE_COMMIT → QUERY)。

        每条:chain.append(带 message_id)→ chain_log.append 写穿 →
        guard.merkle_leaves 追加(镜像 guard._append_entry,但不代管打包)。
        """
        entries: list[dict] = []

        def _append(entry_type: str, payload_digest: str) -> None:
            entry = self._chain.append(entry_type, payload_digest, timestamp,
                                       message_id=message_id)
            self._chain_log.append(entry)               # 写穿封缄日志
            self._guard.merkle_leaves.append(entry["hash"])
            entries.append(entry)

        if ovs:
            _append("USER_OVERRIDE",
                    canon([e.model_dump() for e in ovs]).decode("utf-8"))
        for fc in file_commits:
            _append("FILE_COMMIT", fc)
        _append("QUERY", input_hash)

        refs = [e["index"] for e in entries]
        if refs != expect_refs:
            raise RuntimeError(
                f"链条目 index 与预算不一致: {refs} != {expect_refs}(链被并发写入?)")
        return entries

    @staticmethod
    def _emitter(on_event: OnEvent | None) -> OnEvent:
        return on_event if on_event is not None else (lambda kind, payload: None)

    @contextmanager
    def _stage(self, emit: OnEvent, name: str):
        """阶段计时上下文:start 事件 t_ms=0.0,done 事件 t_ms=真实耗时(ms)。"""
        emit("stage", {"stage": name, "status": "start", "t_ms": 0.0})
        t0 = time.perf_counter()
        yield
        emit("stage", {"stage": name, "status": "done",
                       "t_ms": (time.perf_counter() - t0) * 1000.0})
