"""
协议转换 —— Anthropic Messages API ⇄ 中立形态(OpenAI Chat Completions 语义)

用途有两处(共用同一份转换,避免两套逻辑漂移):
  1. AnthropicProvider:中立请求 → Anthropic Messages 出站,响应 → 中立;
  2. /v1/messages 入口:Anthropic 请求 → 中立 → (任意提供商)→ Anthropic 响应,
     使 Claude Code 这类只说原生 Messages API 的客户端可以直接把 Base URL 指向本中间件。

覆盖:system prompt、多轮消息、文本分块、图片分块、tool_use / tool_result、
工具定义、tool_choice、stop_sequences、max_tokens、usage、stop_reason、流式事件。

明确不承诺:
  - 不承诺两端所有私有字段的语义等价(如 cache_control、thinking 块仅做保留/丢弃,
    并在文档中列明);未知分块按「文本」保守处理或不透传;
  - 不承诺长上下文窗口上限一致(由上游模型决定,中间件不做截断);
  - Anthropic 要求 max_tokens 必填:请求未给时使用 DEFAULT_MAX_TOKENS 并显式回显。
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field

from .errors import MiddlewareError
from .providers.base import ChatRequest, Completion, StreamChunk, ToolCall

DEFAULT_MAX_TOKENS = 4096
ANTHROPIC_VERSION = "2023-06-01"

#: OpenAI finish_reason → Anthropic stop_reason
_STOP_REASON_TO_ANTHROPIC = {
    "stop": "end_turn",
    "length": "max_tokens",
    "tool_calls": "tool_use",
    "content_filter": "refusal",
    None: "end_turn",
}
#: Anthropic stop_reason → OpenAI finish_reason
_STOP_REASON_TO_OPENAI = {
    "end_turn": "stop",
    "stop_sequence": "stop",
    "max_tokens": "length",
    "tool_use": "tool_calls",
    "refusal": "content_filter",
    "pause_turn": "stop",
}


# --------------------------------------------------------------------------- #
# Anthropic → 中立
# --------------------------------------------------------------------------- #
def from_anthropic_request(body: dict) -> ChatRequest:
    """Anthropic Messages 请求体 → 中立 ChatRequest。"""
    if not isinstance(body, dict):
        raise MiddlewareError("invalid_request", "请求体必须是 JSON 对象")
    messages = body.get("messages")
    if not isinstance(messages, list) or not messages:
        raise MiddlewareError("invalid_request", "messages 必须是非空数组")
    max_tokens = body.get("max_tokens")
    if max_tokens is None:
        max_tokens = DEFAULT_MAX_TOKENS
    try:
        max_tokens = int(max_tokens)
    except (TypeError, ValueError):
        raise MiddlewareError("invalid_request", "max_tokens 必须是整数") from None

    neutral: list[dict] = []
    system = _system_text(body.get("system"))
    if system:
        neutral.append({"role": "system", "content": system})
    for message in messages:
        neutral.extend(_anthropic_message_to_neutral(message))

    return ChatRequest(
        model=str(body.get("model") or ""),
        messages=neutral,
        stream=bool(body.get("stream")),
        temperature=body.get("temperature"),
        max_tokens=max_tokens,
        top_p=body.get("top_p"),
        stop=list(body.get("stop_sequences") or []) or None,
        tools=_anthropic_tools_to_openai(body.get("tools")),
        tool_choice=_anthropic_tool_choice_to_openai(body.get("tool_choice")),
    )


def _system_text(system) -> str:
    """system 可以是字符串或分块数组;只取文本块,拼接为一条 system 消息。"""
    if isinstance(system, str):
        return system
    if isinstance(system, list):
        parts = [b.get("text", "") for b in system
                 if isinstance(b, dict) and b.get("type") == "text"]
        return "\n".join(p for p in parts if p)
    return ""


def _anthropic_message_to_neutral(message: dict) -> list[dict]:
    """单条 Anthropic 消息 → 一条或多条中立消息(tool_result 拆成 role=tool)。"""
    if not isinstance(message, dict):
        raise MiddlewareError("invalid_request", "messages 的元素必须是对象")
    role = str(message.get("role") or "")
    if role not in ("user", "assistant"):
        raise MiddlewareError("invalid_request",
                              f"不支持的 role={role!r}(仅 user|assistant)")
    content = message.get("content")
    if isinstance(content, str):
        return [{"role": role, "content": content}]
    if not isinstance(content, list):
        raise MiddlewareError("invalid_request", "消息 content 必须是字符串或分块数组")

    texts: list[str] = []
    parts: list[dict] = []
    tool_calls: list[dict] = []
    tool_results: list[dict] = []
    for block in content:
        if not isinstance(block, dict):
            continue
        btype = block.get("type")
        if btype == "text":
            texts.append(str(block.get("text") or ""))
            parts.append({"type": "text", "text": str(block.get("text") or "")})
        elif btype == "image":
            source = block.get("source") or {}
            if source.get("type") == "base64":
                url = f"data:{source.get('media_type','image/png')};base64,{source.get('data','')}"
            else:
                url = str(source.get("url") or "")
            parts.append({"type": "image_url", "image_url": {"url": url}})
        elif btype == "tool_use":
            tool_calls.append({
                "id": str(block.get("id") or f"call_{len(tool_calls)}"),
                "type": "function",
                "function": {
                    "name": str(block.get("name") or ""),
                    "arguments": json.dumps(block.get("input") or {}, ensure_ascii=False),
                },
            })
        elif btype == "tool_result":
            tool_results.append({
                "role": "tool",
                "tool_call_id": str(block.get("tool_use_id") or ""),
                "content": _tool_result_text(block.get("content")),
            })
        # 其余类型(thinking / redacted_thinking / cache_control 等)不透传到上游提示词,
        # 避免把厂商私有语义错误地注入到另一个厂商的上下文里。

    out: list[dict] = []
    if role == "assistant":
        payload: dict = {"role": "assistant", "content": "\n".join(t for t in texts if t)}
        if tool_calls:
            payload["tool_calls"] = tool_calls
        out.append(payload)
    else:
        if len(parts) > 1 or any(p["type"] != "text" for p in parts):
            out.append({"role": "user", "content": parts})
        elif texts:
            out.append({"role": "user", "content": "\n".join(texts)})
    out.extend(tool_results)
    return out


def _tool_result_text(content) -> str:
    """tool_result.content 可为字符串或分块数组;统一收敛为纯文本。"""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for block in content:
            if isinstance(block, dict) and block.get("type") == "text":
                parts.append(str(block.get("text") or ""))
            elif isinstance(block, str):
                parts.append(block)
        return "\n".join(p for p in parts if p)
    return "" if content is None else json.dumps(content, ensure_ascii=False)


def _anthropic_tools_to_openai(tools) -> list[dict] | None:
    if not tools:
        return None
    out: list[dict] = []
    for tool in tools:
        if not isinstance(tool, dict):
            continue
        name = str(tool.get("name") or "")
        if not name:
            raise MiddlewareError("invalid_request", "工具定义缺少 name")
        out.append({
            "type": "function",
            "function": {
                "name": name,
                "description": str(tool.get("description") or ""),
                "parameters": tool.get("input_schema") or {"type": "object", "properties": {}},
            },
        })
    return out or None


def _anthropic_tool_choice_to_openai(choice):
    if not isinstance(choice, dict):
        return None
    ctype = choice.get("type")
    if ctype == "auto":
        return "auto"
    if ctype == "any":
        return "required"
    if ctype == "none":
        return "none"
    if ctype == "tool":
        return {"type": "function",
                "function": {"name": str(choice.get("name") or "")}}
    return None


# --------------------------------------------------------------------------- #
# 中立 → Anthropic(出站与入口响应共用)
# --------------------------------------------------------------------------- #
def to_anthropic_request(req: ChatRequest) -> dict:
    """中立 ChatRequest → Anthropic Messages 请求体。"""
    system_parts: list[str] = []
    messages: list[dict] = []
    for message in req.messages:
        role = message.get("role")
        if role == "system":
            text = _content_text(message.get("content"))
            if text:
                system_parts.append(text)
            continue
        converted = _neutral_message_to_anthropic(message)
        if converted is not None:
            messages.append(converted)
    if not messages:
        raise MiddlewareError("invalid_request", "除 system 外没有可发送的消息")
    body: dict = {
        "model": req.model,
        "messages": _merge_adjacent(messages),
        "max_tokens": int(req.max_tokens or DEFAULT_MAX_TOKENS),
    }
    if system_parts:
        body["system"] = "\n".join(system_parts)
    if req.stream:
        body["stream"] = True
    for name in ("temperature", "top_p"):
        value = getattr(req, name)
        if value is not None:
            body[name] = value
    if req.stop:
        body["stop_sequences"] = list(req.stop)
    if req.tools:
        body["tools"] = _openai_tools_to_anthropic(req.tools)
    if req.tool_choice is not None:
        body["tool_choice"] = _openai_tool_choice_to_anthropic(req.tool_choice)
    return body


def _content_text(content) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(str(p.get("text") or "") for p in content
                         if isinstance(p, dict) and p.get("type") == "text")
    return "" if content is None else str(content)


def _neutral_message_to_anthropic(message: dict) -> dict | None:
    role = message.get("role")
    if role == "tool":
        return {
            "role": "user",
            "content": [{
                "type": "tool_result",
                "tool_use_id": str(message.get("tool_call_id") or ""),
                "content": _content_text(message.get("content")),
            }],
        }
    if role == "assistant":
        blocks: list[dict] = []
        text = _content_text(message.get("content"))
        if text:
            blocks.append({"type": "text", "text": text})
        for call in message.get("tool_calls") or []:
            if not isinstance(call, dict):
                continue
            fn = call.get("function") or {}
            blocks.append({
                "type": "tool_use",
                "id": str(call.get("id") or f"toolu_{uuid.uuid4().hex[:12]}"),
                "name": str(fn.get("name") or ""),
                "input": _parse_arguments(fn.get("arguments")),
            })
        return {"role": "assistant", "content": blocks or [{"type": "text", "text": ""}]}
    if role == "user":
        content = message.get("content")
        if isinstance(content, list):
            blocks = []
            for part in content:
                if not isinstance(part, dict):
                    continue
                if part.get("type") == "text":
                    blocks.append({"type": "text", "text": str(part.get("text") or "")})
                elif part.get("type") == "image_url":
                    blocks.append(_openai_image_to_anthropic(part.get("image_url") or {}))
            return {"role": "user", "content": blocks or [{"type": "text", "text": ""}]}
        return {"role": "user", "content": [{"type": "text", "text": _content_text(content)}]}
    raise MiddlewareError("invalid_request", f"不支持的中立 role={role!r}")


def _openai_image_to_anthropic(image_url: dict) -> dict:
    """data: URL → Anthropic base64 source;http(s) URL 原样透传(上游自行抓取)。"""
    url = str(image_url.get("url") or "")
    if url.startswith("data:"):
        header, _, data = url.partition(",")
        media = header[5:].split(";")[0] or "image/png"
        return {"type": "image",
                "source": {"type": "base64", "media_type": media, "data": data}}
    return {"type": "image", "source": {"type": "url", "url": url}}


def _parse_arguments(raw) -> dict:
    if isinstance(raw, dict):
        return raw
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError):
        # 工具参数不是合法 JSON:不猜语义,包成原始串交给上游(上游会自行报错)
        return {"__raw_arguments": str(raw)}
    return parsed if isinstance(parsed, dict) else {"value": parsed}


def _merge_adjacent(messages: list[dict]) -> list[dict]:
    """相邻同 role 消息合并:Anthropic 要求 user/assistant 交替。"""
    merged: list[dict] = []
    for message in messages:
        if merged and merged[-1]["role"] == message["role"]:
            merged[-1]["content"] = list(merged[-1]["content"]) + list(message["content"])
        else:
            merged.append({"role": message["role"], "content": list(message["content"])})
    return merged


def _openai_tools_to_anthropic(tools: list[dict]) -> list[dict]:
    out: list[dict] = []
    for tool in tools:
        if not isinstance(tool, dict):
            continue
        fn = tool.get("function") or {}
        name = str(fn.get("name") or "")
        if not name:
            raise MiddlewareError("invalid_request", "tools 元素缺少 function.name")
        out.append({
            "name": name,
            "description": str(fn.get("description") or ""),
            "input_schema": fn.get("parameters") or {"type": "object", "properties": {}},
        })
    return out


def _openai_tool_choice_to_anthropic(choice):
    if isinstance(choice, str):
        return {"auto": {"type": "auto"}, "required": {"type": "any"},
                "none": {"type": "none"}}.get(choice, {"type": "auto"})
    if isinstance(choice, dict):
        fn = choice.get("function") or {}
        return {"type": "tool", "name": str(fn.get("name") or "")}
    return {"type": "auto"}


# --------------------------------------------------------------------------- #
# Anthropic 响应 → 中立 / 中立 → 两家响应体
# --------------------------------------------------------------------------- #
def completion_from_anthropic(body: dict, fallback_model: str) -> Completion:
    """Anthropic Messages 响应体 → 中立 Completion。"""
    if not isinstance(body, dict):
        raise MiddlewareError("protocol", "Anthropic 响应不是 JSON 对象")
    texts: list[str] = []
    calls: list[ToolCall] = []
    for block in body.get("content") or []:
        if not isinstance(block, dict):
            continue
        if block.get("type") == "text":
            texts.append(str(block.get("text") or ""))
        elif block.get("type") == "tool_use":
            calls.append(ToolCall(
                id=str(block.get("id") or f"call_{len(calls)}"),
                name=str(block.get("name") or ""),
                arguments=json.dumps(block.get("input") or {}, ensure_ascii=False),
            ))
    stop = body.get("stop_reason")
    usage = body.get("usage") or {}
    return Completion(
        text="".join(texts),
        tool_calls=calls,
        finish_reason=_STOP_REASON_TO_OPENAI.get(str(stop), "stop"),
        model=str(body.get("model") or fallback_model),
        usage={
            "prompt_tokens": int(usage.get("input_tokens") or 0),
            "completion_tokens": int(usage.get("output_tokens") or 0),
            "total_tokens": int(usage.get("input_tokens") or 0)
            + int(usage.get("output_tokens") or 0),
        },
        raw=body,
    )


def openai_response(completion: Completion, *, request_id: str, model: str,
                    created: int, cryptoguard: dict | None = None) -> dict:
    """中立 Completion → OpenAI ChatCompletion 对象。"""
    message: dict = {"role": "assistant", "content": completion.text or None}
    if completion.tool_calls:
        message["tool_calls"] = [c.to_openai() for c in completion.tool_calls]
        if not completion.text:
            message["content"] = None
    if completion.reasoning:
        message["reasoning_content"] = completion.reasoning
    body = {
        "id": request_id,
        "object": "chat.completion",
        "created": created,
        "model": model,
        "choices": [{
            "index": 0,
            "message": message,
            "logprobs": None,
            "finish_reason": completion.finish_reason or "stop",
        }],
        "usage": completion.usage or {},
        "system_fingerprint": None,
    }
    if cryptoguard:
        body["cryptoguard"] = cryptoguard
    return body


def anthropic_response(completion: Completion, *, request_id: str, model: str,
                       cryptoguard: dict | None = None) -> dict:
    """中立 Completion → Anthropic Messages 响应体。"""
    content: list[dict] = []
    if completion.text:
        content.append({"type": "text", "text": completion.text})
    for call in completion.tool_calls:
        content.append({
            "type": "tool_use",
            "id": call.id if call.id.startswith("toolu_") else f"toolu_{call.id}",
            "name": call.name,
            "input": _parse_arguments(call.arguments),
        })
    if not content:
        content.append({"type": "text", "text": ""})
    usage = {
        "input_tokens": int((completion.usage or {}).get("prompt_tokens") or 0),
        "output_tokens": int((completion.usage or {}).get("completion_tokens") or 0),
    }
    body = {
        "id": request_id,
        "type": "message",
        "role": "assistant",
        "model": model,
        "content": content,
        "stop_reason": _STOP_REASON_TO_ANTHROPIC.get(completion.finish_reason, "end_turn"),
        "stop_sequence": None,
        "usage": usage,
    }
    if cryptoguard:
        body["cryptoguard"] = cryptoguard
    return body


# --------------------------------------------------------------------------- #
# 流式:中立 StreamChunk → Anthropic SSE 事件序列
# --------------------------------------------------------------------------- #
@dataclass
class AnthropicStreamTranslator:
    """中立增量 → Anthropic SSE 事件的**有状态**转换器。

    职责:块开合管理(text 块 / tool_use 块各一个 index)、stop_reason 映射、
    message_start/message_stop 边界。事件以 (event_name, payload) 形式返回,
    由调用方负责 `event: X\\ndata: {...}\\n\\n` 编码。
    """

    model: str
    request_id: str
    input_tokens: int = 0
    cryptoguard: dict | None = None
    _next_index: int = 0
    _open_index: int | None = None
    _open_kind: str | None = None
    _stop_reason: str = "end_turn"
    _started: bool = False
    _stopped: bool = False
    _output_tokens: int = 0
    _tool_index: int = 0
    _tool_open: bool = False
    _tool_block_index: int | None = None
    events: list = field(default_factory=list)

    # -- 生命周期 -------------------------------------------------------- #
    def start(self) -> list[tuple[str, dict]]:
        if self._started:
            return []
        self._started = True
        message = {
            "id": self.request_id,
            "type": "message",
            "role": "assistant",
            "model": self.model,
            "content": [],
            "stop_reason": None,
            "stop_sequence": None,
            "usage": {"input_tokens": self.input_tokens, "output_tokens": 0},
        }
        if self.cryptoguard:
            message["cryptoguard"] = self.cryptoguard
        return [("message_start", {"type": "message_start", "message": message})]

    def _close_block(self) -> list[tuple[str, dict]]:
        if self._open_index is None:
            return []
        out = [("content_block_stop",
                {"type": "content_block_stop", "index": self._open_index})]
        self._open_index = None
        self._open_kind = None
        return out

    def _open_text(self) -> list[tuple[str, dict]]:
        if self._open_kind == "text":
            return []
        out = self._close_block()
        self._open_index = self._next_index
        self._open_kind = "text"
        self._next_index += 1
        out.append(("content_block_start", {
            "type": "content_block_start", "index": self._open_index,
            "content_block": {"type": "text", "text": ""},
        }))
        return out

    def _open_tool(self, name: str, tool_id: str) -> list[tuple[str, dict]]:
        out = self._close_block()
        self._tool_block_index = self._next_index
        self._open_index = self._next_index
        self._open_kind = "tool_use"
        self._next_index += 1
        self._tool_open = True
        out.append(("content_block_start", {
            "type": "content_block_start", "index": self._open_index,
            "content_block": {
                "type": "tool_use",
                "id": tool_id or f"toolu_{uuid.uuid4().hex[:16]}",
                "name": name,
                "input": {},
            },
        }))
        return out

    # -- 增量 ------------------------------------------------------------ #
    def feed(self, chunk: StreamChunk) -> list[tuple[str, dict]]:
        out = self.start()
        if chunk.kind == "text" and chunk.text:
            out += self._open_text()
            out.append(("content_block_delta", {
                "type": "content_block_delta", "index": self._open_index,
                "delta": {"type": "text_delta", "text": chunk.text},
            }))
            self._output_tokens += max(1, len(chunk.text) // 4)
        elif chunk.kind == "tool_call":
            if not self._tool_open:
                out += self._open_tool(chunk.tool_name, chunk.tool_id)
            if chunk.tool_arguments:
                out.append(("content_block_delta", {
                    "type": "content_block_delta", "index": self._open_index,
                    "delta": {"type": "input_json_delta",
                              "partial_json": chunk.tool_arguments},
                }))
        elif chunk.kind == "usage" and chunk.usage:
            self._output_tokens = int(chunk.usage.get("completion_tokens")
                                      or self._output_tokens)
            self.input_tokens = int(chunk.usage.get("prompt_tokens") or self.input_tokens)
        elif chunk.kind == "done":
            out += self._close_block()
            self._tool_open = False
            self._stop_reason = _STOP_REASON_TO_ANTHROPIC.get(chunk.finish_reason,
                                                              "end_turn")
            if chunk.finish_reason is None:
                # 断流:用 end_turn 收尾但在 cryptoguard 元数据里标注不完整(见 finish)
                self._stop_reason = "end_turn"
        return out

    def finish(self, *, incomplete: bool = False) -> list[tuple[str, dict]]:
        if self._stopped:
            return []
        out = self.start()
        out += self._close_block()
        self._stopped = True
        delta: dict = {"stop_reason": self._stop_reason, "stop_sequence": None}
        payload: dict = {
            "type": "message_delta",
            "delta": delta,
            "usage": {"output_tokens": self._output_tokens},
        }
        if self.cryptoguard:
            payload["cryptoguard"] = {**self.cryptoguard, "incomplete": incomplete}
        out.append(("message_delta", payload))
        out.append(("message_stop", {"type": "message_stop"}))
        return out


def sse_encode(event: str, payload: dict) -> str:
    """Anthropic SSE 编码(事件名 + 单行 JSON)。"""
    return f"event: {event}\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n"
