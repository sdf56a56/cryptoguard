"""OpenAI Responses API ⇄ 中立 Chat Completions 语义

当前 Codex CLI 只讲 Responses API。本模块提供**无状态最小子集**的协议翻译，
复用现有 `pipeline` / `provider` / 审计 / 保护 / 还原，不复制任何中间件逻辑。

明确不实现（显式拒绝，不静默降级）：
  - `previous_response_id` 有状态会话（网关不保存跨请求上下文）；
  - `store=true`（不在上游留存响应）；
  - `background` 后台任务、`truncation`、内置工具（web_search/file_search/
    computer_use/code_interpreter/image_generation/mcp）；
  - 文件/音频输入；图片按 `CG_IMAGE_POLICY` 处理（默认拒绝）。

流式事件覆盖文本与函数调用；不返回 reasoning 条目（思考块在本网关默认 strip，
避免把模型自由生成的思考内容当作可验证回答的一部分）。
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from typing import Any

from .errors import MiddlewareError
from .providers.base import ChatRequest, Completion, StreamChunk, ToolCall

#: 允许的 Responses 内置工具名（一律拒绝：网关不代理模型侧工具执行）
_BUILTIN_TOOLS = frozenset({
    "web_search", "web_search_preview", "file_search", "computer_use_preview",
    "computer_use", "code_interpreter", "image_generation", "mcp",
    "local_shell", "custom",
})
_ALLOWED_ROLES = frozenset({"user", "assistant", "system", "developer"})
_ALLOWED_TEXT_FORMATS = frozenset({"text", "json_object", "json_schema"})


def _bad(detail: str) -> MiddlewareError:
    return MiddlewareError("invalid_request", detail)


# --------------------------------------------------------------------------- #
# 请求 → 中立
# --------------------------------------------------------------------------- #
def _content_parts(content: Any) -> list[dict]:
    """Responses content → 中立 content parts（只允许 text / image）。"""
    if isinstance(content, str):
        return [{"type": "text", "text": content}]
    if not isinstance(content, list):
        raise _bad("Responses input.content 必须是字符串或数组")
    parts: list[dict] = []
    for block in content:
        if not isinstance(block, dict):
            raise _bad("Responses content 分块必须是对象")
        btype = block.get("type")
        if btype in ("input_text", "output_text", "text"):
            parts.append({"type": "text", "text": str(block.get("text") or "")})
        elif btype == "input_image":
            url = str(block.get("image_url") or "")
            if not url:
                raise _bad("input_image 缺少 image_url")
            parts.append({"type": "image_url", "image_url": {"url": url}})
        elif btype in ("input_file", "input_audio"):
            # 内容面策略会按 document/音频规则拒绝；这里先保留结构让策略统一判定
            parts.append({"type": btype, "raw": block})
        else:
            raise _bad(f"Responses content 分块类型 {btype!r} 不受支持")
    return parts or [{"type": "text", "text": ""}]


def _input_items(value: Any) -> list[dict]:
    """Responses `input` → 中立 messages。"""
    if isinstance(value, str):
        return [{"role": "user", "content": value}]
    if not isinstance(value, list) or not value:
        raise _bad("Responses input 必须是非空数组或字符串")

    messages: list[dict] = []
    for item in value:
        if not isinstance(item, dict):
            raise _bad("Responses input 的元素必须是对象")
        itype = item.get("type")
        if itype in (None, "message") and item.get("role") in _ALLOWED_ROLES:
            role = str(item["role"])
            content = item.get("content")
            parts = _content_parts(content)
            # 纯文本消息收敛为字符串，避免上游对数组形态的支持差异
            if all(part.get("type") == "text" for part in parts):
                text = "\n".join(str(part.get("text") or "") for part in parts)
                messages.append({"role": role, "content": text})
            else:
                messages.append({"role": role, "content": parts})
        elif itype == "function_call_output":
            call_id = str(item.get("call_id") or "")
            if not call_id:
                raise _bad("function_call_output 缺少 call_id")
            output = item.get("output")
            if isinstance(output, list):
                output = "\n".join(str(part.get("text") or "") for part in output
                                   if isinstance(part, dict))
            messages.append({"role": "tool", "tool_call_id": call_id,
                             "content": str(output or "")})
        elif itype == "function_call":
            call_id = str(item.get("call_id") or "")
            name = str(item.get("name") or "")
            if not call_id or not name:
                raise _bad("function_call 缺少 call_id/name")
            messages.append({
                "role": "assistant", "content": None,
                "tool_calls": [{
                    "id": call_id, "type": "function",
                    "function": {"name": name,
                                 "arguments": str(item.get("arguments") or "{}")},
                }],
            })
        elif itype == "reasoning":
            # 思考项不是可验证回答的一部分；显式登记为 ignored（不注入提示词）
            continue
        else:
            raise _bad(f"Responses input 项类型 {itype!r} 不受支持")
    return messages


def _tools(tools: Any) -> list[dict] | None:
    if not tools:
        return None
    out: list[dict] = []
    for tool in tools:
        if not isinstance(tool, dict):
            raise _bad("tools 的元素必须是对象")
        ttype = tool.get("type")
        if ttype in _BUILTIN_TOOLS:
            raise _bad(f"Responses 内置工具 {ttype!r} 不受支持：网关不代理模型侧工具执行")
        if ttype not in (None, "function"):
            raise _bad(f"工具类型 {ttype!r} 不受支持（仅 function）")
        name = str(tool.get("name") or "")
        if not name:
            raise _bad("function 工具缺少 name")
        fn: dict = {"name": name,
                    "parameters": tool.get("parameters")
                    or {"type": "object", "properties": {}}}
        if tool.get("description") is not None:
            fn["description"] = str(tool["description"])
        if tool.get("strict") is not None:
            fn["strict"] = bool(tool["strict"])
        out.append({"type": "function", "function": fn})
    return out or None


def _tool_choice(choice: Any) -> str | dict | None:
    if choice is None:
        return None
    if isinstance(choice, str):
        if choice not in ("auto", "none", "required"):
            raise _bad("tool_choice 只能为 auto|none|required 或 function 对象")
        return choice
    if isinstance(choice, dict):
        if choice.get("type") == "function" and choice.get("name"):
            return {"type": "function",
                    "function": {"name": str(choice["name"])}}
        raise _bad("tool_choice 对象只支持 {type:'function', name:'...'}")
    raise _bad("tool_choice 形态非法")


def _response_format(text: Any) -> tuple[dict | None, str | None]:
    """Responses `text` → (response_format, verbosity)。"""
    if text is None:
        return None, None
    if not isinstance(text, dict):
        raise _bad("text 必须是对象")
    verbosity = text.get("verbosity")
    if verbosity is not None and verbosity not in ("low", "medium", "high"):
        raise _bad("text.verbosity 只能为 low|medium|high")
    fmt = text.get("format")
    if fmt is None:
        return None, verbosity
    if not isinstance(fmt, dict) or fmt.get("type") not in _ALLOWED_TEXT_FORMATS:
        raise _bad("text.format 只支持 text|json_object|json_schema")
    out: dict = {"type": fmt["type"]}
    if fmt.get("json_schema") is not None:
        out["json_schema"] = fmt["json_schema"]
    return out, verbosity


@dataclass
class ResponsesRequest:
    """已通过 Pydantic 形态校验后的 Responses 请求（由 openai_schemas 构造）。"""

    model: str
    messages: list[dict]
    stream: bool = False
    max_tokens: int | None = None
    temperature: float | None = None
    top_p: float | None = None
    tools: list[dict] | None = None
    tool_choice: str | dict | None = None
    parallel_tool_calls: bool | None = None
    response_format: dict | None = None
    reasoning_effort: str | None = None
    verbosity: str | None = None
    prompt_cache_key: str | None = None
    ignored_fields: list[str] = field(default_factory=list)

    def to_neutral(self, *, model: str) -> ChatRequest:
        extra: dict = {}
        if self.parallel_tool_calls is not None:
            extra["parallel_tool_calls"] = self.parallel_tool_calls
        if self.response_format is not None:
            extra["response_format"] = self.response_format
        if self.verbosity is not None:
            extra["verbosity"] = self.verbosity
        if self.reasoning_effort is not None:
            extra["reasoning_effort"] = self.reasoning_effort
        if self.prompt_cache_key is not None:
            extra["prompt_cache_key"] = self.prompt_cache_key
        return ChatRequest(
            model=model,
            messages=list(self.messages),
            stream=bool(self.stream),
            max_tokens=self.max_tokens,
            temperature=self.temperature,
            top_p=self.top_p,
            tools=self.tools,
            tool_choice=self.tool_choice,
            extra=extra,
        )


def from_responses_request(body: dict) -> ResponsesRequest:
    """把 Responses 请求体翻译成 `ResponsesRequest`（再转中立 ChatRequest）。"""
    model = str(body.get("model") or "").strip()
    if not model:
        raise _bad("缺少 model 字段")

    # 显式拒绝有状态/后台/留存语义
    if body.get("previous_response_id"):
        raise _bad("previous_response_id 不受支持：网关不保存跨请求会话状态")
    if body.get("store") is True:
        raise _bad("store=true 不受支持：网关不在上游留存响应")
    if body.get("background") is True:
        raise _bad("background 后台任务不受支持")
    if body.get("truncation") not in (None, "disabled"):
        raise _bad("truncation 不受支持（网关不截断上下文）")
    if body.get("metadata"):
        raise _bad("metadata 不受支持：可能夹带未经保护的用户标识")
    if body.get("safety_identifier"):
        raise _bad("safety_identifier 不受支持")
    if body.get("service_tier"):
        raise _bad("service_tier 不受支持（会改变路由与计费）")

    messages: list[dict] = []
    instructions = body.get("instructions")
    if instructions is not None:
        if not isinstance(instructions, str):
            raise _bad("instructions 必须是字符串")
        if instructions.strip():
            messages.append({"role": "system", "content": instructions})
    messages.extend(_input_items(body.get("input")))

    reasoning = body.get("reasoning")
    effort = None
    if reasoning is not None:
        if not isinstance(reasoning, dict):
            raise _bad("reasoning 必须是对象")
        effort = reasoning.get("effort")
        if effort is not None and effort not in ("low", "medium", "high"):
            raise _bad("reasoning.effort 只能为 low|medium|high")

    response_format, verbosity = _response_format(body.get("text"))
    max_tokens = body.get("max_output_tokens")
    if max_tokens is not None:
        try:
            max_tokens = int(max_tokens)
        except (TypeError, ValueError):
            raise _bad("max_output_tokens 必须是整数") from None
        if max_tokens <= 0:
            raise _bad("max_output_tokens 必须为正数")

    ignored: list[str] = []
    if body.get("include"):
        ignored.append("include")
    if reasoning is not None and reasoning.get("summary") is not None:
        ignored.append("reasoning.summary")

    return ResponsesRequest(
        model=model,
        messages=messages,
        stream=bool(body.get("stream")),
        max_tokens=max_tokens,
        temperature=body.get("temperature"),
        top_p=body.get("top_p"),
        tools=_tools(body.get("tools")),
        tool_choice=_tool_choice(body.get("tool_choice")),
        parallel_tool_calls=body.get("parallel_tool_calls"),
        response_format=response_format,
        reasoning_effort=effort,
        verbosity=verbosity,
        prompt_cache_key=body.get("prompt_cache_key"),
        ignored_fields=ignored,
    )


# --------------------------------------------------------------------------- #
# 中立 → Responses
# --------------------------------------------------------------------------- #
def _usage(completion_usage: dict | None) -> dict:
    usage = completion_usage or {}
    prompt = int(usage.get("prompt_tokens") or 0)
    completion = int(usage.get("completion_tokens") or 0)
    return {
        "input_tokens": prompt,
        "input_tokens_details": {"cached_tokens": 0},
        "output_tokens": completion,
        "output_tokens_details": {"reasoning_tokens": 0},
        "total_tokens": int(usage.get("total_tokens") or (prompt + completion)),
    }


def _response_object(*, request_id: str, model: str, created: int,
                     output: list[dict], usage: dict,
                     finish_reason: str | None,
                     cryptoguard: dict | None = None,
                     status: str = "completed",
                     reasoning_effort: str | None = None) -> dict:
    incomplete = None
    if status == "incomplete":
        reason = "max_output_tokens" if finish_reason == "length" else "content_filter"
        incomplete = {"reason": reason}
    body = {
        "id": request_id,
        "object": "response",
        "created_at": created,
        "status": status,
        "error": None,
        "incomplete_details": incomplete,
        "model": model,
        "output": output,
        "parallel_tool_calls": True,
        "previous_response_id": None,
        "reasoning": {"effort": reasoning_effort, "summary": None},
        "store": False,
        "temperature": None,
        "text": {"format": {"type": "text"}},
        "tool_choice": "auto",
        "tools": [],
        "top_p": None,
        "truncation": "disabled",
        "usage": usage,
    }
    if cryptoguard:
        body["cryptoguard"] = cryptoguard
    return body


def _message_item(text: str, *, item_id: str | None = None) -> dict:
    return {
        "type": "message",
        "id": item_id or f"msg_{uuid.uuid4().hex[:16]}",
        "status": "completed",
        "role": "assistant",
        "content": [{"type": "output_text", "annotations": [], "text": text}],
    }


def _function_item(call: ToolCall, *, item_id: str | None = None) -> dict:
    return {
        "type": "function_call",
        "id": item_id or f"fc_{uuid.uuid4().hex[:16]}",
        "call_id": call.id,
        "name": call.name,
        "arguments": call.arguments,
        "status": "completed",
    }


def response_from_completion(completion: Completion, *, request_id: str, model: str,
                             created: int, reasoning_effort: str | None = None,
                             cryptoguard: dict | None = None) -> dict:
    """中立 Completion → Responses 响应对象。"""
    output: list[dict] = []
    if completion.text:
        output.append(_message_item(completion.text))
    for call in completion.tool_calls:
        output.append(_function_item(call))
    status = "completed"
    if completion.finish_reason == "length":
        status = "incomplete"
    elif completion.finish_reason == "content_filter":
        status = "incomplete"
    return _response_object(
        request_id=request_id, model=model, created=created, output=output,
        usage=_usage(completion.usage), finish_reason=completion.finish_reason,
        cryptoguard=cryptoguard, status=status, reasoning_effort=reasoning_effort)


# --------------------------------------------------------------------------- #
# 流式翻译
# --------------------------------------------------------------------------- #
@dataclass
class ResponsesStreamTranslator:
    """中立增量 → Responses SSE 事件（文本 + function_call）。"""

    model: str
    request_id: str
    created: int
    reasoning_effort: str | None = None
    cryptoguard: dict | None = None
    sequence: int = 0
    text: list[str] = field(default_factory=list)
    tool_calls: dict[int, dict] = field(default_factory=dict)
    usage: dict = field(default_factory=dict)
    finish_reason: str | None = None
    _started: bool = False
    _text_item_id: str = ""
    _text_open: bool = False
    _text_part_open: bool = False
    _tool_open: dict[int, bool] = field(default_factory=dict)
    _tool_item_ids: dict[int, str] = field(default_factory=dict)
    _output: list[dict] = field(default_factory=list)

    def _event(self, name: str, payload: dict) -> tuple[str, dict]:
        payload = {"type": name, "sequence_number": self.sequence, **payload}
        self.sequence += 1
        return name, payload

    def _in_progress_response(self) -> dict:
        return _response_object(
            request_id=self.request_id, model=self.model, created=self.created,
            output=[], usage=_usage({}), finish_reason=None,
            cryptoguard=self.cryptoguard, status="in_progress",
            reasoning_effort=self.reasoning_effort)

    def start(self) -> list[tuple[str, dict]]:
        if self._started:
            return []
        self._started = True
        response = self._in_progress_response()
        return [self._event("response.created", {"response": response}),
                self._event("response.in_progress", {"response": response})]

    def _open_text(self) -> list[tuple[str, dict]]:
        if self._text_open:
            return []
        self._text_item_id = f"msg_{uuid.uuid4().hex[:16]}"
        self._text_open = True
        out = [self._event("response.output_item.added", {
            "output_index": len(self._output),
            "item": {"type": "message", "id": self._text_item_id,
                     "status": "in_progress", "role": "assistant", "content": []},
        })]
        self._text_part_open = True
        out.append(self._event("response.content_part.added", {
            "item_id": self._text_item_id, "output_index": len(self._output),
            "content_index": 0,
            "part": {"type": "output_text", "annotations": [], "text": ""},
        }))
        return out

    def _close_text(self) -> list[tuple[str, dict]]:
        if not self._text_open:
            return []
        text = "".join(self.text)
        out = []
        if self._text_part_open:
            out.append(self._event("response.output_text.done", {
                "item_id": self._text_item_id, "output_index": len(self._output),
                "content_index": 0, "text": text,
            }))
            out.append(self._event("response.content_part.done", {
                "item_id": self._text_item_id, "output_index": len(self._output),
                "content_index": 0,
                "part": {"type": "output_text", "annotations": [], "text": text},
            }))
            self._text_part_open = False
        out.append(self._event("response.output_item.done", {
            "output_index": len(self._output), "item": _message_item(
                text, item_id=self._text_item_id),
        }))
        self._output.append(_message_item(text, item_id=self._text_item_id))
        self._text_open = False
        return out

    def _open_tool(self, index: int, name: str, call_id: str) -> list[tuple[str, dict]]:
        if self._tool_open.get(index):
            return []
        item_id = f"fc_{uuid.uuid4().hex[:16]}"
        self._tool_item_ids[index] = item_id
        self._tool_open[index] = True
        self.tool_calls.setdefault(index, {"id": call_id, "name": name, "arguments": ""})
        return [self._event("response.output_item.added", {
            "output_index": len(self._output) + len(self.tool_calls) - 1,
            "item": {"type": "function_call", "id": item_id, "call_id": call_id,
                     "name": name, "arguments": "", "status": "in_progress"},
        })]

    def _close_tool(self, index: int) -> list[tuple[str, dict]]:
        if not self._tool_open.get(index):
            return []
        call = self.tool_calls.get(index) or {}
        item_id = self._tool_item_ids.get(index, "")
        output_index = len(self._output) + index
        out = [
            self._event("response.function_call_arguments.done", {
                "item_id": item_id, "output_index": output_index,
                "arguments": call.get("arguments") or "",
            }),
            self._event("response.output_item.done", {
                "output_index": output_index,
                "item": {"type": "function_call", "id": item_id,
                         "call_id": call.get("id") or "",
                         "name": call.get("name") or "",
                         "arguments": call.get("arguments") or "",
                         "status": "completed"},
            }),
        ]
        self._tool_open[index] = False
        call["_done"] = True
        return out

    def feed(self, chunk: StreamChunk) -> list[tuple[str, dict]]:
        out = self.start()
        if chunk.kind == "text" and chunk.text:
            out += self._open_text()
            self.text.append(chunk.text)
            out.append(self._event("response.output_text.delta", {
                "item_id": self._text_item_id, "output_index": len(self._output),
                "content_index": 0, "delta": chunk.text,
            }))
        elif chunk.kind == "tool_call":
            index = int(chunk.tool_index)
            out += self._open_tool(index, chunk.tool_name, chunk.tool_id)
            call = self.tool_calls[index]
            if chunk.tool_id:
                call["id"] = chunk.tool_id
            if chunk.tool_name:
                call["name"] = chunk.tool_name
            if chunk.tool_arguments:
                call["arguments"] += chunk.tool_arguments
                out.append(self._event("response.function_call_arguments.delta", {
                    "item_id": self._tool_item_ids.get(index, ""),
                    "output_index": len(self._output) + index,
                    "delta": chunk.tool_arguments,
                }))
        elif chunk.kind == "usage" and chunk.usage:
            self.usage = dict(chunk.usage)
        elif chunk.kind == "done":
            self.finish_reason = chunk.finish_reason
            out += self._close_text()
            for index in sorted(self._tool_open):
                out += self._close_tool(index)
        return out

    def finish(self, *, incomplete: bool = False) -> list[tuple[str, dict]]:
        out: list[tuple[str, dict]] = []
        out += self._close_text()
        for index in sorted(self._tool_open):
            out += self._close_tool(index)
        output = list(self._output)
        # 工具项在关闭时已发 output_item.done，这里补进最终对象
        for index in sorted(self.tool_calls):
            call = self.tool_calls[index]
            if call.get("_done"):
                output.append({
                    "type": "function_call",
                    "id": self._tool_item_ids.get(index, ""),
                    "call_id": call.get("id") or "",
                    "name": call.get("name") or "",
                    "arguments": call.get("arguments") or "",
                    "status": "completed",
                })
        status = "completed"
        if incomplete or self.finish_reason is None:
            status = "incomplete"
        elif self.finish_reason in ("length", "content_filter"):
            status = "incomplete"
        response = _response_object(
            request_id=self.request_id, model=self.model, created=self.created,
            output=output, usage=_usage(self.usage),
            finish_reason=self.finish_reason, cryptoguard=self.cryptoguard,
            status=status, reasoning_effort=self.reasoning_effort)
        out.append(self._event("response.completed", {"response": response}))
        return out

    def error(self, exc: MiddlewareError) -> list[tuple[str, dict]]:
        return [self._event("error", {"error": {
            "type": "invalid_request_error", "message": exc.detail,
        }})]
