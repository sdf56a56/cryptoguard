"""
Provider Adapter 抽象 —— 与厂商协议解耦的中立请求/响应模型

设计要点:
  - 中间件内部只认「中立形态」(ChatRequest/Completion/StreamChunk),各协议
    差异全部收敛在 Provider 实现里;新增厂商 = 新增一个 ModelProvider 子类。
  - ChatRequest 的 messages 采用 OpenAI 形态作为公共语言(工具调用、system、
    tool_result 都有对应表达),Anthropic 侧由 anthropic.py 双向转换。
  - 密钥只存在于 ProviderConfig.api_key(内存),绝不进日志/异常/响应。

明确不承诺:
  - 不承诺任意厂商私有扩展字段的语义等价(未知/不支持字段在网关入口即显式报错);
  - 不承诺中间立在所有厂商上的行为完全一致(如 reasoning_content 仅部分厂商有)。
"""
from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Iterator

from ..errors import MiddlewareError


@dataclass(frozen=True)
class ProviderConfig:
    """一个已装配好的提供商(密钥已解析到内存)。

    密钥只来自 `api_key_env` 指向的环境变量,启动期读入 `api_key`;只存在于内存,
    绝不序列化/日志/回显。改钥需重启进程（这是有意的：少一条运行时密钥路径）。
    """

    name: str
    type: str                      # openai-compatible | anthropic | mock
    base_url: str = ""
    api_key: str = ""              # 仅内存;绝不序列化/日志
    #: 密钥来自哪个环境变量(仅变量名,不是密钥本身;供排错与 health 展示)
    api_key_env: str = ""
    models: tuple[str, ...] = ()
    display_name: str = ""
    timeout_connect: float = 10.0
    timeout_read: float = 120.0
    max_retries: int = 2
    #: 是否让 httpx 采纳环境/系统代理(HTTP_PROXY、Windows 注册表代理)。默认 False:
    #: 代理能看到 Authorization 头与上游响应体,且会改变连接超时的实际生效行为,
    #: 必须由部署者显式开启(CG_UPSTREAM_TRUST_ENV / CG_PROVIDERS[].trust_env)。
    trust_env: bool = False
    extra_headers: dict = field(default_factory=dict)
    stream_options: dict | None = None
    #: 该厂商使用哪个字段承载 token 上限:max_tokens(默认)或
    #: max_completion_tokens(部分新模型只认后者)。显式配置,不做静默猜测。
    token_limit_field: str = "max_tokens"

    @property
    def resolved_api_key(self) -> str:
        """当前生效的上游密钥（启动期从环境变量读入，只存在于内存）。"""
        return (self.api_key or "").strip()

    @property
    def configured(self) -> bool:
        """mock 无需密钥;其余类型必须有 base_url 与密钥才算可用。"""
        if self.type == "mock":
            return True
        return bool(self.base_url and self.resolved_api_key)


@dataclass
class ToolCall:
    """一次工具调用(中立形态)。

    arguments 为 JSON 字符串(与 OpenAI 一致);Anthropic 的 input 对象在
    anthropic.py 里序列化/反序列化,不留差异到上层。
    """

    id: str
    name: str
    arguments: str = "{}"

    def to_openai(self) -> dict:
        return {
            "id": self.id,
            "type": "function",
            "function": {"name": self.name, "arguments": self.arguments},
        }


@dataclass
class ChatRequest:
    """一次补全请求的中立形态(字段名沿用 OpenAI,便于两端映射)。

    仅包含网关显式支持的字段;上游 payload 由各 Provider 按自己的协议组装。
    """

    model: str
    messages: list[dict] = field(default_factory=list)
    stream: bool = False
    temperature: float | None = None
    max_tokens: int | None = None
    top_p: float | None = None
    stop: list[str] | None = None
    tools: list[dict] | None = None
    tool_choice: str | dict | None = None
    presence_penalty: float | None = None
    frequency_penalty: float | None = None
    seed: int | None = None
    user: str | None = None
    stream_options: dict | None = None
    #: 非敏感的业务透传(如厂商附加参数);已在上游 payload 层白名单化
    extra: dict = field(default_factory=dict)


@dataclass
class Completion:
    """一次非流式补全的中立结果。"""

    text: str = ""
    reasoning: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    finish_reason: str | None = None       # stop|length|tool_calls|content_filter
    model: str = ""
    usage: dict = field(default_factory=dict)
    #: 上游原始响应体(已剔除任何认证信息);供审计摘要使用
    raw: dict = field(default_factory=dict)


@dataclass
class StreamChunk:
    """流式增量(中立形态)。

    kind ∈ {"text","reasoning","tool_call","usage","done"}
      - text/reasoning: 文本增量
      - tool_call:      tool_* 三段增量(index/id/name/arguments 片段)
      - usage:          末尾用量(部分厂商需 stream_options 才回)
      - done:           finish_reason 收尾(不携带文本)
    """

    kind: str
    text: str = ""
    tool_index: int = 0
    tool_id: str = ""
    tool_name: str = ""
    tool_arguments: str = ""
    usage: dict | None = None
    finish_reason: str | None = None


class ModelProvider(abc.ABC):
    """上游模型提供商接口。实现必须:不漏密钥、不无限重试、错误可分类。"""

    def __init__(self, config: ProviderConfig):
        self.config = config

    # ------------------------------------------------------------------ #
    def ensure_configured(self) -> None:
        """调用前的 fail-closed 校验:缺 base_url 或密钥时**绝不出网**。

        为什么必须在这里而不是只靠上游返回 401:无密钥的请求会真实发出,
        既浪费一次往返,又会把「本部署没配好」误报成「上游认证失败」,排错方向错误。
        """
        if self.config.configured:
            return
        missing = []
        if not self.config.base_url:
            missing.append("base_url")
        if not self.config.resolved_api_key:
            missing.append(
                f"密钥(环境变量 {self.config.api_key_env or '<未指定 api_key_env>'})")
        raise MiddlewareError(
            "config",
            f"提供商 {self.name!r} 未配置完整,缺少 " + "、".join(missing) + ",已拒绝调用上游")

    @property
    def name(self) -> str:
        return self.config.name

    @property
    def models(self) -> tuple[str, ...]:
        return self.config.models

    @abc.abstractmethod
    def complete(self, req: ChatRequest) -> Completion:
        """非流式补全。失败抛 MiddlewareError(已分类、已脱敏)。"""

    @abc.abstractmethod
    def stream(self, req: ChatRequest) -> Iterator[StreamChunk]:
        """流式补全。首字节前的失败抛 MiddlewareError;中途断流以 done 收尾并置
        finish_reason=None 且不抛(调用方据 done 是否到达判断完整性)。"""

    def close(self) -> None:
        """释放持有长连接的资源(默认无操作);进程退出时由注册表统一调用。"""

    def health(self) -> dict:
        """提供商健康摘要(不含任何密钥);用于 /health 与 /v1/models 管理视图。

        has_key 只回答「当前是否取得到密钥」(布尔),不泄露密钥本体、长度或前缀。
        """
        return {
            "name": self.name,
            "type": self.config.type,
            "base_url": self.config.base_url,
            "configured": self.config.configured,
            "has_key": bool(self.config.resolved_api_key) or self.config.type == "mock",
            "key_env": self.config.api_key_env,
            "trust_env": self.config.trust_env,
            "models": list(self.models),
        }
