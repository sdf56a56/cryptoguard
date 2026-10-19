"""内容面策略 —— 图片 / 文档 / thinking / cache_control 的显式处置

原则：**不静默放行，也不静默丢弃**。
  - 图片：默认拒绝（内容不经过检测）；显式 `pass` 时放行，但登记为未保护。
  - 文档：默认拒绝（未做抽取/检测）；显式 `pass` 时接受，但协议转换通常无法
    把它等价转发，结果会登记为 dropped/unprotected，绝不假装已保护。
  - thinking：默认 strip（接受请求但不转发思考配置、不返回思考块），登记 ignored；
    `reject` 时显式 400。
  - cache_control：默认 strip（只影响 prompt caching，不影响安全），登记 ignored；
    `reject` 时显式 400。
  - 其余匿名私有块：登记 ignored，不再静默 continue。

这些函数只读请求体，不接触金库、不写审计；审计登记由 routes/pipeline 完成。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .errors import MiddlewareError

#: 递归扫描 cache_control 的最大深度（防御异常深嵌套）
_MAX_DEPTH = 32


@dataclass
class ContentPolicyResult:
    """一次请求的内容面处置结果。"""

    ignored: list[str] = field(default_factory=list)
    unprotected: dict[str, int] = field(default_factory=dict)
    dropped: dict[str, int] = field(default_factory=dict)

    def note(self, key: str) -> None:
        if key not in self.ignored:
            self.ignored.append(key)

    def count(self, bucket: dict[str, int], key: str) -> None:
        bucket[key] = bucket.get(key, 0) + 1

    def view(self) -> dict:
        return {
            "ignored_fields": list(self.ignored),
            "unprotected": dict(self.unprotected),
            "dropped": dict(self.dropped),
        }


def _reject(feature: str, setting: str, detail: str) -> MiddlewareError:
    return MiddlewareError(
        "invalid_request",
        f"{feature} 当前被策略拒绝（{setting}）。{detail}"
        "如确认接受未保护内容，请由管理员显式调整该配置；网关不会静默放行或丢弃。")


def _walk_images_and_documents(node: Any, *, image_policy: str,
                               document_policy: str, result: ContentPolicyResult,
                               depth: int = 0) -> None:
    """递归扫描 Anthropic/OpenAI 请求里的图片与文档块。"""
    if depth > _MAX_DEPTH:
        return
    if isinstance(node, dict):
        btype = node.get("type")
        if btype in ("image", "image_url", "input_image"):
            if image_policy == "reject":
                raise _reject("图片内容", "CG_IMAGE_POLICY=reject",
                              "图片无法可靠检测其中的敏感信息（截图可能含身份证/手机号）。")
            result.count(result.unprotected, "images")
        elif btype in ("document", "input_file"):
            if document_policy == "reject":
                raise _reject("文档内容", "CG_DOCUMENT_POLICY=reject",
                              "文档未做抽取与敏感数据检测，不能保证等价保护。")
            result.count(result.unprotected, "documents")
            result.count(result.dropped, "documents")
        elif btype == "input_audio":
            raise _reject("音频内容", "当前不支持", "音频无法在中立协议层等价转发。")
        for value in node.values():
            _walk_images_and_documents(value, image_policy=image_policy,
                                       document_policy=document_policy,
                                       result=result, depth=depth + 1)
    elif isinstance(node, list):
        for item in node:
            _walk_images_and_documents(item, image_policy=image_policy,
                                       document_policy=document_policy,
                                       result=result, depth=depth + 1)


def _walk_cache_control(node: Any, *, policy: str, result: ContentPolicyResult,
                        depth: int = 0) -> None:
    if depth > _MAX_DEPTH:
        return
    if isinstance(node, dict):
        if "cache_control" in node:
            if policy == "reject":
                raise _reject("cache_control", "CG_CACHE_CONTROL=reject",
                              "该字段只影响上游 prompt caching，剥离不影响安全。")
            result.note("cache_control")
        for value in node.values():
            _walk_cache_control(value, policy=policy, result=result, depth=depth + 1)
    elif isinstance(node, list):
        for item in node:
            _walk_cache_control(item, policy=policy, result=result, depth=depth + 1)


def _walk_unknown_blocks(node: Any, *, result: ContentPolicyResult,
                         depth: int = 0) -> None:
    """登记会被协议转换丢弃的 Anthropic 私有块（不静默 continue）。"""
    if depth > _MAX_DEPTH:
        return
    known = {"text", "image", "document", "tool_use", "tool_result"}
    if isinstance(node, dict):
        if node.get("type") in ("thinking", "redacted_thinking"):
            result.note("thinking_blocks")
        elif node.get("type") == "cache_control":
            pass
        elif node.get("type") not in known and node.get("type") is not None \
                and isinstance(node.get("type"), str):
            result.note(f"block:{node.get('type')}")
        for value in node.values():
            _walk_unknown_blocks(value, result=result, depth=depth + 1)
    elif isinstance(node, list):
        for item in node:
            _walk_unknown_blocks(item, result=result, depth=depth + 1)


def check_openai_request(body: dict, settings) -> ContentPolicyResult:
    """OpenAI Chat 入口：图片是最常见、最容易被忽略的未保护面。"""
    result = ContentPolicyResult()
    for key in ("messages", "input"):
        if key in body:
            _walk_images_and_documents(body.get(key), image_policy=settings.image_policy,
                                       document_policy=settings.document_policy,
                                       result=result)
    return result


def check_anthropic_request(body: dict, settings) -> ContentPolicyResult:
    """Anthropic Messages 入口：图片/文档/thinking/cache_control 全部显式处置。"""
    result = ContentPolicyResult()

    thinking = body.get("thinking")
    if thinking:
        if settings.anthropic_thinking == "reject":
            raise _reject("thinking（扩展思考）", "CG_ANTHROPIC_THINKING=reject",
                          "思考块可能回显令牌，且跨协议转换无法保证语义等价。")
        result.note("thinking")

    _walk_cache_control(body, policy=settings.cache_control, result=result)
    _walk_images_and_documents(body, image_policy=settings.image_policy,
                               document_policy=settings.document_policy, result=result)
    _walk_unknown_blocks(body, result=result)
    return result
