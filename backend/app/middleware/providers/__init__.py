"""上游模型提供商适配层(可扩展:新增协议只加一个 Provider 实现 + 注册)。"""
from __future__ import annotations

from .base import (ChatRequest, Completion, ModelProvider, ProviderConfig,
                   StreamChunk, ToolCall)
from .registry import ProviderRegistry, build_registry

__all__ = [
    "ChatRequest", "Completion", "ModelProvider", "ProviderConfig",
    "StreamChunk", "ToolCall", "ProviderRegistry", "build_registry",
]
