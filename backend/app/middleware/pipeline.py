"""
请求编排 —— 检测 → 保护 → 转发 → 还原 → 审计(单次调用的唯一入口)

一次调用的固定顺序(顺序本身就是安全属性,不得调换):
  1. 解析模型 → 选提供商;2. 合成生效策略(只能收紧);
  3. **出站前**检测 + 保护(阻断档直接 fail-closed,不产出任何出站内容);
  4. 计算请求摘要(对**受保护后**的请求,绝不对明文算摘要);
  5. 调用上游(错误已分类、已脱敏;密钥不出现在任何异常/响应里);
  6. **回程**按策略还原本请求签发的令牌(伪造/跨请求令牌原样保留);
  7. 对**交付给客户端**的响应计算摘要;8. 写审计记录(链式绑定)。

工具调用安全:
  - 出站:只保护 `function.arguments`(按 JSON 结构深度遍历字符串叶子,不碰键名与
    结构)与工具定义的 `description`;绝不改写工具名、参数名、id,保证结构可解析;
  - 入站:`function.arguments` 同样深度遍历还原,还原值按 JSON 字符串转义,
    不会破坏 JSON;
  - **绝不执行**模型生成的工具调用:本中间件只做保护/转发/审计,不接入任何本地
    工具执行通道,也不把「模型生成了工具调用」当作「调用已执行」。

明确不承诺:
  - 不承诺识别器零漏报(见 recognizers 边界);
  - 不承诺上游确实遵守了我们转发的内容(上游可能自行改写)。响应摘要只说明
    「客户端收到的与网关记录的一致」,不说明内容正确或来自特定服务商。
"""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Iterator

from .audit import AuditStore
from .config import Settings
from .errors import MiddlewareError
from .policy import EffectivePolicy
from .protection import MappingEntry, ProtectionResult, TokenVault, protect_text
from .providers.base import ChatRequest, Completion, StreamChunk, ToolCall
from .providers.registry import ProviderRegistry
from .recognizers import DetectorConfig, Finding, detect_all
from .restore import RestorePolicy, StreamRestorer, restore_text, restore_view
from .verification import (RequestRecord, new_request_id, request_digest,
                           response_digest)

logger = logging.getLogger(__name__)

#: 响应侧检测模式:audit=只统计不回写(默认);off=关闭
RESPONSE_SCAN_MODES = ("audit", "off")


# --------------------------------------------------------------------------- #
# 请求上下文与已准备请求
# --------------------------------------------------------------------------- #
@dataclass
class RequestContext:
    """一次调用从入口到落审计的关联信息(审计与响应元数据都挂在它上面)。"""

    request_id: str = field(default_factory=new_request_id)
    created: int = field(default_factory=lambda: int(time.time()))
    endpoint: str = ""
    client_id: str = ""
    client_name: str = ""
    requested_model: str = ""
    stream: bool = False
    policy_version: str = ""
    protection_mode: str = ""


@dataclass
class _Collector:
    """跨消息累计的检测/保护结果。"""

    findings: list[Finding] = field(default_factory=list)
    entries: list[MappingEntry] = field(default_factory=list)
    blocked: list[Finding] = field(default_factory=list)
    pending: list[Finding] = field(default_factory=list)
    #: 模式 A 占位符计数器与令牌占用集:**整次请求共享**,保证跨消息同令牌不撞值
    #: (否则消息 1 的手机与消息 2 的手机都会叫 [PHONE_001],金库后写覆盖先写)。
    counters: dict[str, int] = field(default_factory=dict)
    used: set[str] = field(default_factory=set)

    def absorb(self, result: ProtectionResult) -> None:
        self.findings.extend(result.findings)
        self.entries.extend(result.entries)
        self.blocked.extend(result.blocked)
        self.pending.extend(result.pending)


@dataclass
class StreamState:
    """流式调用过程中累积的状态(生成器结束后由调用方取用并落审计)。"""

    text: list[str] = field(default_factory=list)
    reasoning: list[str] = field(default_factory=list)
    tool_calls: dict[int, dict] = field(default_factory=dict)
    usage: dict = field(default_factory=dict)
    finish_reason: str | None = None
    complete: bool = False
    restore: dict = field(default_factory=dict)
    response_scan: dict = field(default_factory=dict)
    error: MiddlewareError | None = None
    latency_ms: float = 0.0

    def joined_text(self) -> str:
        return "".join(self.text)


@dataclass
class PreparedRequest:
    """已完成出站保护、可以送给提供商的一次请求。"""

    ctx: RequestContext
    provider: Any
    request: ChatRequest                     # 受保护后的中立请求
    policy: EffectivePolicy
    request_digest: str = ""
    detections: dict = field(default_factory=dict)
    actions: dict = field(default_factory=dict)
    pending_count: int = 0
    has_mapping: bool = False
    protected_chars: int = 0
    stream_state: StreamState = field(default_factory=StreamState)


# --------------------------------------------------------------------------- #
# 主编排
# --------------------------------------------------------------------------- #
class Pipeline:
    """把「安全处理」与「提供商调用」编在一起;所有网络调用都在工作线程里同步执行。"""

    def __init__(self, settings: Settings, registry: ProviderRegistry,
                 vault: TokenVault, audit: AuditStore, keyring,
                 detector: DetectorConfig | None = None) -> None:
        self.settings = settings
        self.registry = registry
        self.vault = vault
        self.audit = audit
        self.keyring = keyring
        self.detector = detector or DetectorConfig.load(settings.detection_config_path)
        self.response_scan = getattr(settings, "response_scan", "audit")
        if self.response_scan not in RESPONSE_SCAN_MODES:
            raise MiddlewareError("config",
                                  f"CG_RESPONSE_SCAN={self.response_scan!r} 不支持"
                                  f"(可选 {'|'.join(RESPONSE_SCAN_MODES)})")

    # ------------------------------------------------------------------ #
    # 早失败:解析/策略/协议层面的拒绝也要留审计
    # ------------------------------------------------------------------ #
    def audit_reject(self, ctx: RequestContext, exc: MiddlewareError) -> None:
        """记录一次「未到达上游」的拒绝(含 4xx/403/429)。"""
        try:
            self.audit.record(RequestRecord(
                request_id=ctx.request_id, ts_epoch=time.time(),
                client_id=ctx.client_id, client_name=ctx.client_name,
                requested_model=ctx.requested_model, endpoint=ctx.endpoint,
                stream=ctx.stream, policy_version=ctx.policy_version,
                protection_mode=ctx.protection_mode,
                outcome="blocked" if exc.kind == "blocked" else "error",
                error_kind=exc.kind, upstream_status=exc.upstream_status,
            ))
        except Exception as audit_exc:  # noqa: BLE001 — 审计失败不能掩盖原始错误
            logger.critical("audit_write_failed(拒绝路径): %s", audit_exc)

    def audit_event(self, ctx: RequestContext, *, outcome: str, actions: dict,
                    error_kind: str = "", endpoint: str = "") -> RequestRecord | None:
        """记录一次「控制面」事件(确认申请/批准/拒绝/释放),同样入链封缄。

        `actions` 里**只允许出现令牌、类别与计数**,绝不允许出现明文或可解出明文的
        材料 —— 控制面审计与请求路径共用同一条链,不能成为绕过口令。
        """
        try:
            if endpoint:
                ctx.endpoint = endpoint
            return self.audit.record(RequestRecord(
                request_id=ctx.request_id, ts_epoch=time.time(),
                client_id=ctx.client_id, client_name=ctx.client_name,
                requested_model=ctx.requested_model, endpoint=ctx.endpoint,
                stream=ctx.stream, policy_version=ctx.policy_version,
                protection_mode=ctx.protection_mode,
                outcome=outcome, error_kind=error_kind, actions=dict(actions),
            ))
        except Exception as audit_exc:  # noqa: BLE001 — 审计失败不能掩盖控制面结果
            logger.critical("audit_write_failed(控制面): %s", audit_exc)
            return None

    # ------------------------------------------------------------------ #
    # 准备:检测 + 保护 + 摘要 + 金库
    # ------------------------------------------------------------------ #
    def prepare(self, ctx: RequestContext, neutral: ChatRequest,
                policy: EffectivePolicy) -> PreparedRequest:
        """对中立请求做检测与保护,返回可出站的 PreparedRequest。

        命中阻断档时:写审计(记下类别与位置,不记原值)后抛 `blocked`(fail-closed)。
        """
        provider, upstream_model = self.registry.resolve(ctx.requested_model)
        collector = _Collector()

        messages: list[dict] = []
        for index, message in enumerate(neutral.messages):
            messages.append(self._protect_message(message, index, policy, collector))

        tools = neutral.tools
        if tools:
            tools = [self._protect_tool(tool, policy, collector) for tool in tools]

        user = neutral.user
        if user:
            found = self._detect(user, policy)
            if found:
                result = self._protect(user, found, policy, collector)
                collector.absorb(result)
                user = result.text or user

        protected = ChatRequest(
            model=upstream_model,
            messages=messages,
            stream=neutral.stream,
            temperature=neutral.temperature,
            max_tokens=neutral.max_tokens,
            top_p=neutral.top_p,
            stop=neutral.stop,
            tools=tools,
            tool_choice=neutral.tool_choice,
            presence_penalty=neutral.presence_penalty,
            frequency_penalty=neutral.frequency_penalty,
            seed=neutral.seed,
            user=user,
            stream_options=neutral.stream_options,
            extra=neutral.extra,
        )

        detections = _detection_summary(collector.findings)
        actions = _action_summary(collector)
        if policy.release_requested_spans:
            # 如实登记:客户端请求过放行,但**没有**放行(见 policy.py / confirmations.py)
            actions["release_requested"] = len(policy.release_requested_spans)
            actions["release_requested_note"] = (
                "客户端请求放行若干命中:仅记入审计,未放行;"
                "实际还原须经确认流程审批")
        prepared = PreparedRequest(
            ctx=ctx, provider=provider, request=protected, policy=policy,
            detections=detections, actions=actions,
            pending_count=len(collector.pending),
            has_mapping=bool(collector.entries),
            protected_chars=sum(len(e.plaintext) for e in collector.entries),
        )

        if collector.blocked:
            self._record(prepared, outcome="blocked", error_kind="blocked")
            kinds = sorted({f"{f.type}({f.rule})" for f in collector.blocked})
            raise MiddlewareError(
                "blocked",
                f"请求命中阻断策略,已拒绝转发: {kinds}。"
                "如确需发送,请修正内容,或由管理员调整 CG_BLOCK_ON / 规则配置")

        if collector.entries:
            self.vault.store(ctx.request_id, collector.entries)

        prepared.request_digest = request_digest(
            model=protected.model, messages=protected.messages, tools=protected.tools,
            params=_digest_params(neutral))
        return prepared

    # ------------------------------------------------------------------ #
    # 非流式
    # ------------------------------------------------------------------ #
    def complete(self, prepared: PreparedRequest) -> tuple[Completion, dict]:
        """调用上游并完成回程还原 + 摘要 + 审计。返回 (交付给客户端的补全, 元数据)。"""
        started = time.monotonic()
        try:
            completion = prepared.provider.complete(prepared.request)
        except MiddlewareError as exc:
            self._record(prepared, outcome="error", error_kind=exc.kind,
                         upstream_status=exc.upstream_status,
                         latency_ms=_ms(started))
            raise
        except Exception as exc:  # noqa: BLE001 — 未知异常也留审计,不泄露栈
            mapped = MiddlewareError("internal", f"上游调用异常: {type(exc).__name__}")
            self._record(prepared, outcome="error", error_kind=mapped.kind,
                         latency_ms=_ms(started))
            raise mapped from None

        latency = _ms(started)
        delivered, restore_view_, scan = self._finalize(prepared, completion)
        # 摘要绑定的是**交付给客户端**的响应:文本用还原后的、model 用响应体里那个
        # (= 请求的 model,见 routes 的 _openai_response)。不能用 delivered.model ——
        # 那是上游自述的名字,真厂商常与请求名不同,客户端据此复算会次次 mismatch。
        digest = response_digest(
            text=delivered.text, tool_calls=[c.to_openai() for c in delivered.tool_calls],
            finish_reason=delivered.finish_reason, model=prepared.request.model)
        record = self._record(
            prepared, outcome="ok", latency_ms=latency,
            response_digest=digest, upstream_status=200,
            restore=restore_view_, response_scan=scan,
            usage=delivered.usage or {},
        )
        meta = self._meta(prepared, restore_view_, scan, digest, record)
        if prepared.policy.destroy_mapping:
            self.vault.drop(prepared.ctx.request_id)
        return delivered, meta

    # ------------------------------------------------------------------ #
    # 流式
    # ------------------------------------------------------------------ #
    def stream(self, prepared: PreparedRequest) -> Iterator[StreamChunk]:
        """流式转发:出站已保护;回程逐块还原(跨块令牌持留),并做响应侧检测。

        产出中立 StreamChunk(已完成还原);结束时把统计写进 `state`。
        上游中途断流:不做重试(可能已产出文案),以 done(finish_reason=None) 收尾
        并标记 complete=False,由调用方在响应里如实标注「不完整」。
        """
        state = prepared.stream_state
        started = time.monotonic()
        restorer = StreamRestorer(prepared.ctx.request_id, self.vault,
                                  prepared.policy.restore)
        # 工具参数按 index 各自持留:参数是 JSON 片段,令牌不能跨片段撕裂
        arg_restorers: dict[int, StreamRestorer] = {}
        scanner = _ResponseScanner(self, prepared) if self.response_scan == "audit" else None

        try:
            for chunk in prepared.provider.stream(prepared.request):
                if chunk.kind == "text" and chunk.text:
                    safe = restorer.feed(chunk.text)
                    if scanner:
                        scanner.feed(chunk.text)
                    if not safe:
                        continue
                    state.text.append(safe)
                    yield StreamChunk("text", text=safe)
                elif chunk.kind == "reasoning" and chunk.text:
                    safe = restorer.feed(chunk.text)
                    if not safe:
                        continue
                    state.reasoning.append(safe)
                    yield StreamChunk("reasoning", text=safe)
                elif chunk.kind == "tool_call":
                    index = int(chunk.tool_index)
                    slot = state.tool_calls.setdefault(
                        index, {"id": "", "name": "", "arguments": ""})
                    if chunk.tool_id:
                        slot["id"] = chunk.tool_id
                    if chunk.tool_name:
                        slot["name"] = chunk.tool_name
                    forward = ""
                    if chunk.tool_arguments:
                        helper = arg_restorers.setdefault(
                            index, StreamRestorer(prepared.ctx.request_id, self.vault,
                                                  prepared.policy.restore,
                                                  plaintext_transform=_json_fragment_escape))
                        forward = helper.feed(chunk.tool_arguments)
                        slot["arguments"] += forward
                    yield StreamChunk("tool_call", tool_index=index,
                                      tool_id=chunk.tool_id, tool_name=chunk.tool_name,
                                      tool_arguments=forward)
                elif chunk.kind == "usage":
                    if chunk.usage:
                        state.usage = dict(chunk.usage)
                    yield chunk
                elif chunk.kind == "done":
                    state.finish_reason = chunk.finish_reason
                    state.complete = chunk.finish_reason is not None
                    tail = restorer.flush()
                    if tail:
                        state.text.append(tail)
                        yield StreamChunk("text", text=tail)
                    for index, helper in sorted(arg_restorers.items()):
                        leftover = helper.flush()
                        if leftover:
                            state.tool_calls[index]["arguments"] += leftover
                            yield StreamChunk("tool_call", tool_index=index,
                                              tool_arguments=leftover)
                    yield chunk
        except MiddlewareError as exc:
            state.error = exc
            raise
        finally:
            state.latency_ms = _ms(started)
            state.restore = _merge_restore_views([restorer, *arg_restorers.values()])
            if scanner:
                # 必须先 close 再取视图:流结束时缓冲区里可能还压着「尾部尚无
                # 后续上下文」的命中(文本就以敏感值收尾时必然如此),close 才会
                # 把它们结算。顺序颠倒会让**结尾处的敏感值永远不被审计到**。
                scanner.close()
            state.response_scan = scanner.view() if scanner else {"mode": "off"}

    def finish_stream(self, prepared: PreparedRequest, state: StreamState) -> dict:
        """流结束后:算摘要、写审计、返回响应元数据(失败也留审计)。"""
        outcome = "error" if state.error else ("ok" if state.complete else "incomplete")
        calls = [{"name": c.get("name") or "", "arguments": c.get("arguments") or ""}
                 for _, c in sorted(state.tool_calls.items())]
        digest = response_digest(text=state.joined_text(), tool_calls=calls,
                                 finish_reason=state.finish_reason,
                                 model=prepared.request.model)
        record = self._record(
            prepared, outcome=outcome, latency_ms=state.latency_ms,
            response_digest=digest, upstream_status=None if state.error else 200,
            error_kind=state.error.kind if state.error else "",
            restore=state.restore, response_scan=state.response_scan,
            usage=state.usage or {})
        meta = self._meta(prepared, state.restore, state.response_scan, digest, record)
        meta["stream"] = {"complete": state.complete,
                          "note": ("上游流未正常结束,已按不完整收尾(不重试,"
                                   "避免重复计费与重复内容)")
                          if not state.complete else ""}
        if prepared.policy.destroy_mapping:
            self.vault.drop(prepared.ctx.request_id)
        return meta

    # ------------------------------------------------------------------ #
    # 检测与保护
    # ------------------------------------------------------------------ #
    def _detect(self, text: str, policy: EffectivePolicy) -> list[Finding]:
        if not text or not text.strip():
            return []
        return detect_all(text, config=self.detector, mode=policy.protection_mode)

    def _protect(self, text: str, findings: list[Finding], policy: EffectivePolicy,
                 collector: _Collector) -> ProtectionResult:
        return protect_text(text, findings, mode=policy.protection_mode,
                            keyring=self.keyring, stable_tokens=policy.stable_tokens,
                            block_on=policy.block_on,
                            policy_version=policy.policy_version,
                            counters=collector.counters, used=collector.used)

    def _protect_message(self, message: dict, index: int, policy: EffectivePolicy,
                         collector: _Collector) -> dict:
        """保护一条消息的文本与工具参数;不改动 role/name/id 等结构字段。"""
        out = dict(message)
        content = message.get("content")
        if isinstance(content, str):
            found = self._detect(content, policy)
            if found:
                result = self._protect(content, found, policy, collector)
                collector.absorb(result)
                out["content"] = result.text or content
        elif isinstance(content, list):
            parts: list[dict] = []
            for part in content:
                if isinstance(part, dict) and part.get("type") == "text":
                    text = str(part.get("text") or "")
                    found = self._detect(text, policy)
                    if found:
                        result = self._protect(text, found, policy, collector)
                        collector.absorb(result)
                        part = {**part, "text": result.text or text}
                parts.append(part)
            out["content"] = parts

        calls = message.get("tool_calls")
        if calls:
            new_calls = []
            for call in calls:
                if not isinstance(call, dict):
                    new_calls.append(call)
                    continue
                fn = dict(call.get("function") or {})
                arguments = fn.get("arguments")
                if isinstance(arguments, str) and arguments:
                    fn["arguments"] = self._protect_json(arguments, policy, collector)
                new_calls.append({**call, "function": fn})
            out["tool_calls"] = new_calls
        return out

    def _protect_tool(self, tool: dict, policy: EffectivePolicy,
                      collector: _Collector) -> dict:
        """只保护工具定义的 description(自然语言),不改动 name/parameters 结构。"""
        fn = dict(tool.get("function") or {})
        description = fn.get("description")
        if isinstance(description, str) and description:
            found = self._detect(description, policy)
            if found:
                result = self._protect(description, found, policy, collector)
                collector.absorb(result)
                fn["description"] = result.text or description
        return {**tool, "function": fn}

    def _protect_json(self, raw: str, policy: EffectivePolicy,
                      collector: _Collector) -> str:
        """按 JSON 结构深度遍历字符串叶子做保护;解析失败则按纯文本保护。

        不改变键名、结构与类型:只替换字符串**值**内部的片段,因此 JSON 始终可解析。
        """
        if len(raw) > 200_000:
            raise MiddlewareError("invalid_request",
                                  "单个 tool_call.arguments 超过 200000 字符上限")
        try:
            parsed = json.loads(raw)
        except ValueError:
            # 模型/客户端给的参数不是合法 JSON:按纯文本保护(不再破坏其结构)
            found = self._detect(raw, policy)
            if not found:
                return raw
            result = self._protect(raw, found, policy, collector)
            collector.absorb(result)
            return result.text or raw
        changed = False

        def walk(value: Any) -> Any:
            nonlocal changed
            if isinstance(value, str):
                found = self._detect(value, policy)
                if not found:
                    return value
                result = self._protect(value, found, policy, collector)
                collector.absorb(result)
                if result.text != value:
                    changed = True
                return result.text or value
            if isinstance(value, list):
                return [walk(v) for v in value]
            if isinstance(value, dict):
                return {k: walk(v) for k, v in value.items()}
            return value

        protected = walk(parsed)
        if not changed:
            return raw                      # 未命中就逐字节保持原样(零扰动)
        return json.dumps(protected, ensure_ascii=False, separators=(",", ":"))

    # ------------------------------------------------------------------ #
    # 回程还原
    # ------------------------------------------------------------------ #
    def _finalize(self, prepared: PreparedRequest, completion: Completion
                  ) -> tuple[Completion, dict, dict]:
        """还原文本/思考/工具参数,并做响应侧检测(仅统计)。"""
        rid = prepared.ctx.request_id
        policy = prepared.policy.restore
        raw_text = completion.text or ""

        if prepared.has_mapping:
            text_result = restore_text(raw_text, rid, self.vault, policy)
            reasoning_result = (restore_text(completion.reasoning, rid, self.vault, policy)
                                if completion.reasoning else None)
            calls = [self._restore_tool_call(call, rid, policy)
                     for call in completion.tool_calls]
            view = restore_view(
                text_result.restored + (reasoning_result.restored if reasoning_result else []),
                text_result.withheld + (reasoning_result.withheld if reasoning_result else []),
                text_result.foreign + (reasoning_result.foreign if reasoning_result else []))
        else:
            # 本次请求没有任何令牌映射:不做还原(也没有可还原的东西)
            text_result = None
            reasoning_result = None
            calls = completion.tool_calls
            view = restore_view([], [], [])

        scan = (self._scan_response(raw_text) if self.response_scan == "audit"
                else {"mode": "off"})
        delivered = Completion(
            text=text_result.text if text_result else raw_text,
            reasoning=(reasoning_result.text if reasoning_result else completion.reasoning),
            tool_calls=calls,
            finish_reason=completion.finish_reason,
            model=completion.model,
            usage=completion.usage,
            raw={},
        )
        return delivered, view, scan

    def _restore_tool_call(self, call: ToolCall, request_id: str,
                           policy: RestorePolicy) -> ToolCall:
        arguments = call.arguments
        if not arguments:
            return call
        try:
            parsed = json.loads(arguments)
        except ValueError:
            return ToolCall(call.id, call.name,
                            restore_text(arguments, request_id, self.vault, policy).text)

        def walk(value: Any) -> Any:
            if isinstance(value, str):
                return restore_text(value, request_id, self.vault, policy).text
            if isinstance(value, list):
                return [walk(v) for v in value]
            if isinstance(value, dict):
                return {k: walk(v) for k, v in value.items()}
            return value

        restored = walk(parsed)
        if restored == parsed:
            return call
        # 还原值由 json.dumps 统一转义,含引号/反斜杠的明文也不会破坏 JSON 结构
        return ToolCall(call.id, call.name,
                        json.dumps(restored, ensure_ascii=False, separators=(",", ":")))

    def _scan_response(self, text: str) -> dict:
        """响应侧检测(**只统计,不回写**):用于发现模型输出中夹带的其他敏感数据。

        为什么不回写:模型输出可能被客户端当作 JSON/代码/命令解析,替换其中片段会
        破坏语义,而这类「模型自己说出来的」内容并非本请求令牌,无法判断是否该改;
        因此默认只做审计与告警,并在需要更强控制时由策略层决定(见文档)。
        """
        if not text or not text.strip():
            return {"mode": "audit", "total": 0, "by_type": {}}
        findings = detect_all(text, config=self.detector, mode="placeholder")
        by_type: dict[str, int] = {}
        for finding in findings:
            by_type[finding.type] = by_type.get(finding.type, 0) + 1
        return {"mode": "audit", "total": len(findings), "by_type": by_type,
                "note": "响应侧仅统计不回写(避免破坏客户端对输出的解析)"}

    # ------------------------------------------------------------------ #
    # 审计与元数据
    # ------------------------------------------------------------------ #
    def _record(self, prepared: PreparedRequest, *, outcome: str,
                error_kind: str = "", upstream_status: int | None = None,
                response_digest: str = "", restore: dict | None = None,
                response_scan: dict | None = None, usage: dict | None = None,
                latency_ms: float = 0.0) -> RequestRecord:
        record = RequestRecord(
            request_id=prepared.ctx.request_id,
            ts_epoch=time.time(),
            client_id=prepared.ctx.client_id,
            client_name=prepared.ctx.client_name,
            requested_model=prepared.ctx.requested_model,
            provider=str(getattr(prepared.provider, "name", "")),
            upstream_model=prepared.request.model,
            endpoint=prepared.ctx.endpoint,
            stream=prepared.ctx.stream,
            policy_version=prepared.policy.policy_version,
            protection_mode=prepared.policy.protection_mode,
            request_digest=prepared.request_digest,
            response_digest=response_digest,
            upstream_status=upstream_status,
            outcome=outcome,
            error_kind=error_kind,
            latency_ms=round(latency_ms, 2),
            detections=prepared.detections,
            actions={**prepared.actions, "protected_chars": prepared.protected_chars},
            restored=restore or {},
            usage=_safe_usage(usage),
        )
        if response_scan is not None:
            record.actions["response_scan"] = response_scan
        try:
            self.audit.record(record)
        except Exception as exc:  # noqa: BLE001
            # 审计写不进去 = 无法留痕:fail-closed,让调用方拒绝本次请求
            logger.critical("audit_write_failed: %s", exc)
            raise MiddlewareError(
                "internal", "审计记录写入失败,已拒绝本次请求(fail-closed)") from None
        return record

    def _meta(self, prepared: PreparedRequest, restore: dict, scan: dict,
              digest: str, record: RequestRecord) -> dict:
        """随响应返回给客户端的 CryptoGuard 元数据(绝不含明文与密钥)。"""
        return {
            "request_id": prepared.ctx.request_id,
            "policy_version": prepared.policy.policy_version,
            "protection_mode": prepared.policy.protection_mode,
            "provider": str(getattr(prepared.provider, "name", "")),
            "upstream_model": prepared.request.model,
            "detected": prepared.detections,
            "pending_confirmations": prepared.pending_count,
            "restore": restore,
            "response_scan": scan,
            "ignored_fields": list(prepared.policy.ignored_fields),
            "digest": {
                "request": prepared.request_digest,
                "response": digest,
                "algorithm": "RFC 8785 (JCS) 规范化 + SHA-256",
                "verify": "POST /v1/verify 可复算并比对",
            },
            "audit": {"seq": record.seq, "chain_hash": record.chain_hash},
            "boundary": {
                "digest_meaning": "摘要只用于检测「是否被改动」",
                "not_provider_signature": "本摘要/签名由本地网关生成,不代表模型服务商对内容的签名",
                "not_truth_proof": "不证明模型回答的事实正确性;HTTPS 只保护传输链路",
                "tokens_are_not_plaintext_to_model": (
                    "模型收到的是令牌而非原文;令牌可还原仅表示本地金库中存在本次请求的映射"),
            },
        }


# --------------------------------------------------------------------------- #
# 响应侧跨块检测器(有界窗口)
# --------------------------------------------------------------------------- #
class _ResponseScanner:
    """流式响应侧的跨块检测:**有界窗口**内的识别 + 稳定区间计数。

    策略与代价(必须如实说明):
      - 每次对「上一次窗口尾部 + 本块」**整窗**做识别;窗口长度上限 =
        CG_STREAM_BUFFER_CHARS(默认 64 字符,下限 16),内存 O(buffer),与流长无关;
      - 命中**尾部必须已有 1 个字符的后续上下文**才计数(LOOKAHEAD_MARGIN),
        避免「因截断而恰好成形」的假命中:上游把 ``sk-abc...`` 这类**变长**值
        继续写下去时,半截命中会被推迟,最终以完整长度计一次;
      - 未通过该边界的命中只是**推迟**,不是丢弃:它在后续窗口里会被重新识别。
        因为窗口每轮滑动,一个长度 L 的值只有满足 ``L ≤ buffer - 1`` 才可能完整
        落进某个窗口 —— 即**长度超过 buffer-1 的值在窗口式审计下不可检出**,
        这是本设计的硬边界(如需覆盖超长值,须调大 CG_STREAM_BUFFER_CHARS);
      - 去重按 (类型, 绝对起始位置, 值指纹):相邻窗口对同一处命中只计一次,
        同一值在文本里出现 N 次则计 N 次;指纹只含长度与摘要,不含明文;
      - 仅统计,不回写(理由见 Pipeline._scan_response)。

    历史缺陷(第 4 阶段回归修复,勿再引入):曾只对「稳定区」计数
    (``finding.end ≤ len(text) - buffer``)。逐字符投喂时该条件恒不成立
    (稳定区长度恒为 1),于是把响应切成 1 字符一帧的上游可以让**任何**敏感值
    静默逃过响应侧审计 —— 一条可被上游刻意利用的规避路径。
    """

    #: 命中尾部必须获得的后续上下文字符数(1 即可判别「值是否还在继续」)
    LOOKAHEAD_MARGIN = 1

    def __init__(self, pipeline: Pipeline, prepared: PreparedRequest,
                 buffer_chars: int | None = None) -> None:
        self._pipeline = pipeline
        self._prepared = prepared
        self._buffer = max(16, int(buffer_chars or
                                   getattr(pipeline.settings, "stream_buffer_chars", 64)))
        self._carry = ""
        self._received = 0                   # 已收到的字符总数(绝对坐标基准)
        self._seen: set[tuple[str, int, str]] = set()
        self.by_type: dict[str, int] = {}
        self.total = 0

    def feed(self, delta: str) -> None:
        if not delta:
            return
        text = self._carry + delta
        self._received += len(delta)
        if len(text) > self._buffer:         # 窗口有界:只留最近 buffer 个字符
            text = text[-self._buffer:]
        self._carry = text
        self._count(text, base=self._received - len(text),
                    limit=len(text) - self.LOOKAHEAD_MARGIN)

    def close(self) -> None:
        """流结束:不会再有任何后续上下文,把缓冲里剩下的命中全部结算。"""
        if self._carry:
            self._count(self._carry, base=self._received - len(self._carry))
            self._carry = ""

    def _count(self, text: str, *, base: int, limit: int | None = None) -> None:
        findings = detect_all(text, config=self._pipeline.detector, mode="placeholder")
        for finding in findings:
            if limit is not None and finding.end > limit:
                continue                     # 尾部还没拿到后续上下文 → 下一轮再定
            # 绝对位置去重:窗口滑动时同一处命中会被反复识别,只计一次;
            # 起始位置不同 = 不同出现位置,各自计数。
            start = base + finding.start
            key = (finding.type, start,
                   _fingerprint(text, finding.start, finding.end))
            if key in self._seen:
                continue
            self._seen.add(key)
            self.by_type[finding.type] = self.by_type.get(finding.type, 0) + 1
            self.total += 1

    def view(self) -> dict:
        return {"mode": "audit", "total": self.total, "by_type": dict(self.by_type),
                "window_chars": self._buffer, "scanned_chars": self._received,
                "note": "窗口式跨块检测;仅统计不回写(避免破坏客户端对输出的解析)"}


def _fingerprint(text: str, start: int, end: int) -> str:
    """命中值指纹:长度 + 值摘要前 16 位(**不含明文**,用于窗口去重)。"""
    from .verification import digest_of_text
    return f"{end - start}:{digest_of_text(text[start:end])[:16]}"


# --------------------------------------------------------------------------- #
# 小工具
# --------------------------------------------------------------------------- #
def _ms(started: float) -> float:
    return (time.monotonic() - started) * 1000.0


def _digest_params(neutral: ChatRequest) -> dict:
    """摘要覆盖的生成参数子集(与「会不会改变回答」相关的那部分)。"""
    params: dict = {"stream": bool(neutral.stream),
                    "max_tokens": neutral.max_tokens if neutral.max_tokens is not None else 0}
    for name in ("temperature", "top_p", "presence_penalty", "frequency_penalty",
                 "seed", "tool_choice", "stop"):
        value = getattr(neutral, name)
        if value is not None:
            params[name] = value
    return params


#: 审计里最多保留的逐命中明细条数(计数统计不受此限制)
MAX_AUDIT_SPANS = 50


def _detection_summary(findings: list[Finding]) -> dict:
    """审计用检测摘要:只有类别/规则/位置/风险计数,**不含任何原值**。"""
    by_type: dict[str, int] = {}
    by_risk: dict[str, int] = {}
    by_action: dict[str, int] = {}
    rules: dict[str, int] = {}
    spans: list[dict] = []
    total = 0
    for finding in findings:
        if finding.suppressed:
            continue
        total += 1
        by_type[finding.type] = by_type.get(finding.type, 0) + 1
        by_risk[finding.risk] = by_risk.get(finding.risk, 0) + 1
        by_action[finding.suggested_action] = by_action.get(finding.suggested_action, 0) + 1
        rules[finding.rule] = rules.get(finding.rule, 0) + 1
        if len(spans) < MAX_AUDIT_SPANS:
            spans.append(finding.to_dict())
    return {"total": total, "by_type": by_type, "by_risk": by_risk,
            "by_action": by_action, "by_rule": rules, "spans": spans,
            "spans_truncated": total > len(spans)}


def _action_summary(collector: _Collector) -> dict:
    """本次请求的处置计数(阻断/替换/待确认)。"""
    replaced = sum(1 for e in collector.entries if e.kind != "allow")
    allowed = sum(1 for e in collector.entries if e.kind == "allow")
    return {"replaced": replaced, "explicitly_allowed": allowed,
            "blocked": len(collector.blocked), "pending": len(collector.pending),
            "mappings_stored": len(collector.entries)}


def _merge_restore_views(restorers: list[StreamRestorer]) -> dict:
    restored: list[dict] = []
    withheld: list[dict] = []
    foreign: list[dict] = []
    for restorer in restorers:
        restored.extend(restorer.restored)
        withheld.extend(restorer.withheld)
        foreign.extend(restorer.foreign)
    return restore_view(restored, withheld, foreign)


def _json_fragment_escape(text: str) -> str:
    """把还原出的明文转义为 JSON 字符串**内部**可用的片段(不破坏 JSON 结构)。"""
    return json.dumps(text, ensure_ascii=False)[1:-1]


_SAFE_USAGE_KEYS = ("prompt_tokens", "completion_tokens", "total_tokens", "estimated")


def _safe_usage(usage: dict | None) -> dict:
    """用量字段白名单:不透传上游可能夹带的其它字段(避免意外落盘无关数据)。"""
    if not isinstance(usage, dict):
        return {}
    return {k: usage[k] for k in _SAFE_USAGE_KEYS if k in usage}
