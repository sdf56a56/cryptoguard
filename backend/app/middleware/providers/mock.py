"""
Mock 提供商 —— 离线可复现的确定性上游(自动化测试与链路演练用)

安全目标:
  - 无网络、无密钥、零外部依赖,使「Agent → CryptoGuard → Provider → CryptoGuard → Agent」
    全链路可在无真实模型 API 的环境下自动化验证(不伪造真实上游的成功结果);
  - 回显受保护占位符,使「令牌恢复」链路可被真实观察到(不是空实现)。

明确不承诺:MockProvider 的输出不代表任何真实模型的行为或质量。
"""
from __future__ import annotations

import json
import re
from collections.abc import Iterator

from ..errors import MiddlewareError
from .base import ChatRequest, Completion, ModelProvider, ProviderConfig, StreamChunk, ToolCall

#: 与 schemas.py 的正典令牌形态一致:[TYPE#token] / [CG_TOKEN_xxx] / [PHONE_001]
_PLACEHOLDER_RE = re.compile(r"\[[A-Za-z0-9_]+(?:#[A-Za-z0-9]+)?\]")


class MockProvider(ModelProvider):
    """确定性 Echo 提供商。"""

    TYPE = "mock"

    def __init__(self, config: ProviderConfig, *, chunk_size: int = 8):
        super().__init__(config)
        self.chunk_size = max(1, chunk_size)
        #: 测试钩子:置非 None 时所有调用按该错误失败(不做真实网络)
        self.fail_with: MiddlewareError | None = None
        #: 测试钩子:记录每次实际收到的请求,用于断言「上游只看到占位符/令牌」
        #: (只保存最近 16 次,避免长跑测试堆积内存)
        self.seen: list[ChatRequest] = []

    # ------------------------------------------------------------------ #
    def _reply(self, req: ChatRequest) -> Completion:
        self.seen.append(req)
        del self.seen[:-16]
        if self.fail_with is not None:
            raise self.fail_with
        if not req.messages:
            raise MiddlewareError("invalid_request", "messages 为空,无法生成回复")
        last_user = ""
        for message in req.messages:
            if message.get("role") == "user":
                content = message.get("content")
                last_user = content if isinstance(content, str) else json.dumps(
                    content, ensure_ascii=False)
        if req.tools and "USE_TOOL" in last_user:
            tool = req.tools[0].get("function") or {}
            name = str(tool.get("name") or "tool")
            call = ToolCall(id="call_mock_1", name=name,
                            arguments=json.dumps({"echo": last_user}, ensure_ascii=False))
            return Completion(
                text="", tool_calls=[call], finish_reason="tool_calls",
                model=req.model, usage=_usage(req, ""),
                raw={"mock": True, "tool_calls": [call.to_openai()]},
            )
        placeholders = _PLACEHOLDER_RE.findall(last_user)
        if placeholders:
            text = (f"已收到请求(含 {len(placeholders)} 个受保护字段:"
                    f"{', '.join(placeholders[:5])}),结果已安全返回。")
        else:
            text = "已收到请求,结果已安全返回。"
        return Completion(text=text, finish_reason="stop", model=req.model,
                          usage=_usage(req, text), raw={"mock": True})

    def complete(self, req: ChatRequest) -> Completion:
        return self._reply(req)

    def stream(self, req: ChatRequest) -> Iterator[StreamChunk]:
        completion = self._reply(req)
        for call in completion.tool_calls:
            yield StreamChunk("tool_call", tool_index=0, tool_id=call.id,
                              tool_name=call.name, tool_arguments=call.arguments)
        for start in range(0, len(completion.text), self.chunk_size):
            yield StreamChunk("text", text=completion.text[start:start + self.chunk_size])
        if completion.usage:
            yield StreamChunk("usage", usage=completion.usage)
        yield StreamChunk("done", finish_reason=completion.finish_reason or "stop")


def _usage(req: ChatRequest, text: str) -> dict:
    """粗略 token 估算(仅 Mock 用,标注为估算值,不冒充真实计费口径)。"""
    prompt = sum(len(str(m.get("content") or "")) for m in req.messages)
    return {
        "prompt_tokens": max(1, prompt // 4),
        "completion_tokens": max(1, len(text) // 4),
        "total_tokens": max(2, (prompt + len(text)) // 4),
        "estimated": True,
    }
