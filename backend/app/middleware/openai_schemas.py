"""
入口协议模型 —— OpenAI Chat Completions(严格)与 Anthropic Messages(显式拒收)

设计原则(对应任务要求「不得静默丢弃影响行为的参数」):
  - **支持并转发**的字段:显式建模,逐一映射到中立 ChatRequest;
  - **收到但明确不处理**的字段:一律拒绝并给出可读原因(unsupported_parameter),
    绝不静默丢弃 —— 未知字段由 extra="forbid" 兜住;
  - **安全配置不可由请求覆盖**:`cryptoguard` 指令只能「收紧」策略(见 policy.py),
    在模型层只做形态校验,越权判断在 pipeline 里做并给出明确错误。

明确不承诺:
  - 不承诺与 OpenAI 全量参数面等價(仅覆盖上表所列;其余显式报错);
  - 不承诺 Anthropic 客户端所有私有字段(thinking/container 等)可用:显式报错。
"""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .errors import MiddlewareError
from .providers.base import ChatRequest

# --------------------------------------------------------------------------- #
# 规模上限(防御恶意/超大请求:在协议层就拦住,不让其进入识别与转发流程)
# --------------------------------------------------------------------------- #
MAX_MESSAGES = 500
MAX_TOOLS = 200
MAX_TEXT_CHARS = 2_000_000        # 单次请求全部文本合计上限
MAX_TOOL_ARG_CHARS = 200_000      # 单个工具参数串上限
MAX_STOP_SEQUENCES = 16

_FORBID = ConfigDict(extra="forbid")


# --------------------------------------------------------------------------- #
# OpenAI 请求
# --------------------------------------------------------------------------- #
class FunctionCallIn(BaseModel):
    model_config = _FORBID
    name: str = Field(min_length=1, max_length=200)
    arguments: str = ""


class ToolCallIn(BaseModel):
    model_config = _FORBID
    id: str = Field(min_length=1, max_length=200)
    type: Literal["function"] = "function"
    function: FunctionCallIn

    def to_neutral(self) -> dict:
        return {"id": self.id, "type": "function",
                "function": {"name": self.function.name,
                             "arguments": self.function.arguments}}


class ImageUrlIn(BaseModel):
    model_config = _FORBID
    url: str = Field(min_length=1)
    detail: str | None = None


class ContentPartIn(BaseModel):
    """多模态分块:只支持 text / image_url;其余类型显式报错。"""

    model_config = _FORBID
    type: str
    text: str | None = None
    image_url: ImageUrlIn | None = None

    def check_supported(self) -> None:
        if self.type not in ("text", "image_url"):
            raise MiddlewareError(
                "invalid_request",
                f"内容分块类型 {self.type!r} 不受支持(仅支持 text|image_url);"
                "音频/文件等分块当前不处理,以免静默改变语义")
        if self.type == "text" and self.text is None:
            raise MiddlewareError("invalid_request", "text 分块缺少 text 字段")
        if self.type == "image_url" and self.image_url is None:
            raise MiddlewareError("invalid_request", "image_url 分块缺少 image_url 字段")


class ChatMessageIn(BaseModel):
    model_config = _FORBID
    role: str
    content: str | list[ContentPartIn] | None = None
    name: str | None = Field(default=None, max_length=200)
    tool_calls: list[ToolCallIn] | None = None
    tool_call_id: str | None = Field(default=None, max_length=200)
    refusal: str | None = None                 # 仅历史回放:原样透传,不改写

    def check_supported(self) -> None:
        if self.role == "function":
            raise MiddlewareError(
                "invalid_request",
                "role='function' 已废弃,请改用 role='tool' + tool_call_id")
        if self.role not in ("system", "developer", "user", "assistant", "tool"):
            raise MiddlewareError(
                "invalid_request",
                f"不支持的 role={self.role!r}(支持 system|developer|user|assistant|tool)")
        if self.role == "tool" and not self.tool_call_id:
            raise MiddlewareError("invalid_request", "role='tool' 的消息必须带 tool_call_id")
        if self.role == "assistant" and self.tool_calls and self.content is None:
            self.content = None                    # 合法:仅工具调用的助手消息
        if isinstance(self.content, list):
            for part in self.content:
                part.check_supported()
        if self.role != "assistant" and self.tool_calls:
            raise MiddlewareError("invalid_request",
                                  f"role={self.role!r} 不允许携带 tool_calls")

    def to_neutral(self) -> dict:
        """转换为中立消息(dict),键只保留 OpenAI 公共语义,不做任何静默改名。"""
        out: dict = {"role": self.role}
        if isinstance(self.content, list):
            parts: list[dict] = []
            for part in self.content:
                if part.type == "text":
                    parts.append({"type": "text", "text": part.text or ""})
                else:
                    image: dict = {"url": part.image_url.url if part.image_url else ""}
                    if part.image_url and part.image_url.detail:
                        image["detail"] = part.image_url.detail
                    parts.append({"type": "image_url", "image_url": image})
            out["content"] = parts
        else:
            out["content"] = self.content
        if self.name:
            out["name"] = self.name
        if self.tool_calls:
            out["tool_calls"] = [c.to_neutral() for c in self.tool_calls]
        if self.tool_call_id:
            out["tool_call_id"] = self.tool_call_id
        if self.refusal is not None and self.role == "assistant":
            out["refusal"] = self.refusal
        return out


class FunctionDefIn(BaseModel):
    model_config = _FORBID
    name: str = Field(min_length=1, max_length=200)
    description: str | None = None
    parameters: dict | None = None
    strict: bool | None = None


class ToolDefIn(BaseModel):
    model_config = _FORBID
    type: Literal["function"] = "function"
    function: FunctionDefIn

    def to_neutral(self) -> dict:
        fn: dict = {"name": self.function.name,
                    "parameters": self.function.parameters
                    or {"type": "object", "properties": {}}}
        if self.function.description is not None:
            fn["description"] = self.function.description
        if self.function.strict is not None:
            fn["strict"] = self.function.strict
        return {"type": "function", "function": fn}


class ToolChoiceFunctionIn(BaseModel):
    model_config = _FORBID
    name: str = Field(min_length=1, max_length=200)


class ToolChoiceIn(BaseModel):
    model_config = _FORBID
    type: Literal["function"] = "function"
    function: ToolChoiceFunctionIn


class StreamOptionsIn(BaseModel):
    model_config = _FORBID
    include_usage: bool | None = None
    #: 仅影响 SSE 填充字节,不影响语义;接受但按上游默认处理(在响应中如实注明)
    include_obfuscation: bool | None = None


class ResponseFormatIn(BaseModel):
    model_config = _FORBID
    type: Literal["text", "json_object", "json_schema"] = "text"
    json_schema: dict | None = None


class FindingRefIn(BaseModel):
    """人工确认:显式放行某次识别命中(不替换,但留下审计记录)。"""

    model_config = _FORBID
    type: str = Field(min_length=1, max_length=40)
    start: int = Field(ge=0)
    end: int = Field(gt=0)


class CryptoGuardDirectiveIn(BaseModel):
    """CryptoGuard 私有指令:只允许「收紧」策略,越权由 pipeline 拒绝。"""

    model_config = _FORBID
    protection_mode: Literal["placeholder", "token", "encrypt"] | None = None
    restore_mode: Literal["off", "confirm", "categories", "auto"] | None = None
    restore_categories: list[str] | None = None
    acknowledged: bool = False
    allow_spans: list[FindingRefIn] | None = None
    destroy_mapping: bool = False      # 处理完即焚:不保留映射,响应中的令牌不可还原


class ChatCompletionRequest(BaseModel):
    """`POST /v1/chat/completions` 的请求体(未列出的字段一律报错)。"""

    model_config = _FORBID

    model: str = Field(min_length=1, max_length=200)
    messages: list[ChatMessageIn] = Field(min_length=1)
    temperature: float | None = Field(default=None, ge=0, le=2)
    top_p: float | None = Field(default=None, ge=0, le=1)
    max_tokens: int | None = Field(default=None, gt=0, le=1_000_000)
    max_completion_tokens: int | None = Field(default=None, gt=0, le=1_000_000)
    stop: str | list[str] | None = None
    stream: bool = False
    stream_options: StreamOptionsIn | None = None
    tools: list[ToolDefIn] | None = None
    tool_choice: str | ToolChoiceIn | None = None
    parallel_tool_calls: bool | None = None
    presence_penalty: float | None = Field(default=None, ge=-2, le=2)
    frequency_penalty: float | None = Field(default=None, ge=-2, le=2)
    seed: int | None = None
    user: str | None = Field(default=None, max_length=200)
    response_format: ResponseFormatIn | None = None
    #: 新参数显式建模并透传给 openai-compatible 上游；anthropic 上游会显式拒绝
    reasoning_effort: Literal["low", "medium", "high"] | None = None
    verbosity: Literal["low", "medium", "high"] | None = None
    cryptoguard: CryptoGuardDirectiveIn | None = None

    # -- 以下字段显式建模只为给出明确错误(绝不静默忽略) ------------------ #
    n: int | None = None
    logprobs: bool | None = None
    top_logprobs: int | None = None
    logit_bias: dict | None = None
    modalities: list[str] | None = None
    audio: dict | None = None
    prediction: dict | None = None
    metadata: dict | None = None
    store: bool | None = None
    service_tier: str | None = None
    function_call: Any = None
    functions: Any = None

    # ------------------------------------------------------------------ #
    def check_supported(self) -> list[str]:
        """校验「收到但无法正确处理」的字段;返回被显式忽略的字段名列表。"""
        if self.n is not None and self.n != 1:
            raise MiddlewareError(
                "invalid_request",
                f"n={self.n} 不受支持:中间件不生成多个候选(如需多候选请分多次请求)")
        if self.logprobs:
            raise MiddlewareError(
                "invalid_request",
                "logprobs 不受支持:逐 token 概率会绕过敏感数据保护(无法审计与控制)")
        if self.top_logprobs is not None:
            raise MiddlewareError("invalid_request",
                                  "top_logprobs 不受支持(同上:逐 token 概率不可保护)")
        if self.logit_bias:
            raise MiddlewareError(
                "invalid_request",
                "logit_bias 不受支持:词表偏移依赖上游 tokenizer,无法在中立层保证一致性")
        if self.modalities:
            raise MiddlewareError("invalid_request",
                                  "modalities 不受支持:当前只处理文本/图片输入与文本输出")
        if self.audio:
            raise MiddlewareError("invalid_request", "audio 输出不受支持")
        if self.prediction:
            raise MiddlewareError("invalid_request", "prediction(推测解码)不受支持")
        if self.metadata:
            raise MiddlewareError(
                "invalid_request",
                "metadata 不受支持:该字段可能携带未经保护的用户标识,拒绝透传给上游")
        if self.service_tier:
            raise MiddlewareError(
                "invalid_request",
                "service_tier 不受支持:该字段会改变上游路由与计费语义,不静默忽略")
        if self.function_call is not None or self.functions is not None:
            raise MiddlewareError(
                "invalid_request",
                "function_call/functions 已废弃,请改用 tools + tool_choice")
        if self.tools is not None and len(self.tools) > MAX_TOOLS:
            raise MiddlewareError("invalid_request",
                                  f"tools 数量超过上限 {MAX_TOOLS}")
        if len(self.messages) > MAX_MESSAGES:
            raise MiddlewareError("invalid_request",
                                  f"messages 数量超过上限 {MAX_MESSAGES}")

        ignored: list[str] = []
        if self.store is not None:
            # 隐私相关:不向上游请求「留存本次补全」;如实登记为被忽略而非静默丢弃
            ignored.append("store")
        if self.stream_options and self.stream_options.include_obfuscation is not None:
            ignored.append("stream_options.include_obfuscation")
        return ignored

    # ------------------------------------------------------------------ #
    def to_neutral(self, *, model: str, max_tokens: int | None,
                   stream_options: dict | None) -> ChatRequest:
        """转换为中立 ChatRequest。`model` 为已解析的上游模型名。"""
        tools = [t.to_neutral() for t in self.tools] if self.tools else None
        return ChatRequest(
            model=model,
            messages=[m.to_neutral() for m in self.messages],
            stream=bool(self.stream),
            temperature=self.temperature,
            max_tokens=max_tokens,
            top_p=self.top_p,
            stop=normalize_stop(self.stop),
            tools=tools,
            tool_choice=normalize_tool_choice(self.tool_choice),
            presence_penalty=self.presence_penalty,
            frequency_penalty=self.frequency_penalty,
            seed=self.seed,
            user=self.user,
            stream_options=stream_options,
            extra=self._extra_passthrough(),
        )

    def _extra_passthrough(self) -> dict:
        """仅「语义等价、与厂商无关」的少量字段走 extra;其余一律显式处理。"""
        extra: dict = {}
        if self.parallel_tool_calls is not None:
            extra["parallel_tool_calls"] = self.parallel_tool_calls
        if self.response_format is not None:
            fmt: dict = {"type": self.response_format.type}
            if self.response_format.json_schema is not None:
                fmt["json_schema"] = self.response_format.json_schema
            extra["response_format"] = fmt
        if self.reasoning_effort is not None:
            extra["reasoning_effort"] = self.reasoning_effort
        if self.verbosity is not None:
            extra["verbosity"] = self.verbosity
        return extra

    def effective_max_tokens(self) -> int | None:
        """max_tokens 与 max_completion_tokens 的合并口径(两者都给时报错)。"""
        if self.max_tokens is not None and self.max_completion_tokens is not None:
            raise MiddlewareError(
                "invalid_request",
                "max_tokens 与 max_completion_tokens 不能同时给出,请只用一个")
        return self.max_tokens if self.max_tokens is not None else self.max_completion_tokens


def normalize_stop(stop: str | list[str] | None) -> list[str] | None:
    if stop is None:
        return None
    values = [stop] if isinstance(stop, str) else list(stop)
    if len(values) > MAX_STOP_SEQUENCES:
        raise MiddlewareError("invalid_request",
                              f"stop 序列数量超过上限 {MAX_STOP_SEQUENCES}")
    if any(not isinstance(v, str) for v in values):
        raise MiddlewareError("invalid_request", "stop 必须是字符串或字符串数组")
    return values or None


def normalize_tool_choice(choice: str | ToolChoiceIn | None) -> str | dict | None:
    if choice is None:
        return None
    if isinstance(choice, ToolChoiceIn):
        return {"type": "function", "function": {"name": choice.function.name}}
    if choice not in ("auto", "none", "required"):
        raise MiddlewareError(
            "invalid_request",
            f"tool_choice={choice!r} 不受支持(auto|none|required 或指定函数对象)")
    return choice


# --------------------------------------------------------------------------- #
# Anthropic Messages 入口(Claude Code 等原生客户端)
# --------------------------------------------------------------------------- #
class AnthropicMessagesRequest(BaseModel):
    """Anthropic Messages 请求体的**最小严格**校验层。

    只做「字段是否可被本中间件正确处理」的判断;结构转换仍由 anthropic_proto
    完成(那边覆盖 system/messages/tools 的细节)。这里拒收会影响行为但无法
    等价映射的字段(thinking / top_k / container 等),避免静默降级。
    """

    model_config = ConfigDict(extra="allow")   # 未知字段由 check_supported 显式报错

    model: str = Field(min_length=1, max_length=200)
    messages: list[dict] = Field(min_length=1)
    system: Any = None
    max_tokens: int | None = None
    temperature: float | None = None
    top_p: float | None = None
    top_k: int | None = None
    stop_sequences: list[str] | None = None
    stream: bool = False
    tools: list[dict] | None = None
    tool_choice: dict | None = None
    thinking: dict | None = None
    metadata: dict | None = None
    service_tier: str | None = None
    container: Any = None
    mcp_servers: Any = None

    def check_supported(self, settings=None) -> list[str]:
        ignored: list[str] = []
        if self.thinking:
            mode = getattr(settings, "anthropic_thinking", "strip") if settings else "strip"
            if mode == "reject":
                raise MiddlewareError(
                    "invalid_request",
                    "thinking(扩展思考)当前被策略拒绝(CG_ANTHROPIC_THINKING=reject):"
                    "思考块可能回显令牌,且跨协议转换无法保证语义等价")
            ignored.append("thinking")
        if self.top_k is not None:
            raise MiddlewareError(
                "invalid_request",
                "top_k 不受支持:OpenAI 兼容上游无等价参数,拒绝静默丢弃")
        if self.container is not None:
            raise MiddlewareError("invalid_request", "container 参数不受支持")
        if self.mcp_servers is not None:
            raise MiddlewareError(
                "invalid_request",
                "mcp_servers 不受支持:中间件不代理模型侧 MCP 调用(避免未经授权的工具执行)")
        if self.service_tier:
            raise MiddlewareError("invalid_request", "service_tier 不受支持(会改变路由与计费)")
        if self.metadata:
            ignored.append("metadata")
        if len(self.messages) > MAX_MESSAGES:
            raise MiddlewareError("invalid_request", f"messages 数量超过上限 {MAX_MESSAGES}")
        return ignored

    def to_neutral(self, *, model: str):
        """委托 anthropic_proto 做结构转换(保持单一转换实现)。"""
        from . import anthropic_proto
        body = self.model_dump(exclude_none=False)
        body["model"] = model
        return anthropic_proto.from_anthropic_request(body)


# --------------------------------------------------------------------------- #
# /v1/verify 请求
# --------------------------------------------------------------------------- #
class VerifyRequest(BaseModel):
    model_config = _FORBID
    request_id: str = Field(min_length=1, max_length=200)
    #: 客户端收到的响应内容(可选):给出即复算摘要并与之比对
    response: dict | None = None
    #: 客户端持有的摘要(可选):给出即与记录比对
    response_digest: str | None = Field(default=None, max_length=128)
    request_digest: str | None = Field(default=None, max_length=128)


class ConfirmationCreateRequest(BaseModel):
    """人工确认申请:客户端对**自己某次请求**中被扣留的令牌申请授权释放。

    只接受令牌(不是明文),且必须在该次请求的映射金库中确实存在 —— 因此
    这个接口不能被用来探测「别人手里有哪些令牌」。
    """

    model_config = _FORBID
    request_id: str = Field(min_length=1, max_length=200)
    tokens: list[str] = Field(min_length=1, max_length=32)
    reason: str | None = Field(default=None, max_length=200)


# --------------------------------------------------------------------------- #
# 错误体
# --------------------------------------------------------------------------- #
def _digest_param(err: dict) -> str:
    loc = err.get("loc") or ()
    return ".".join(str(x) for x in loc if x != "body")


def validation_error(exc: ValidationError) -> MiddlewareError:
    """Pydantic 校验错误 → 保留字段定位与原因的 invalid_request。"""
    for err in exc.errors():
        param = _digest_param(err)
        if err.get("type") == "extra_forbidden":
            return MiddlewareError(
                "invalid_request",
                f"不支持的参数 {param!r}:中间件不静默丢弃无法处理的字段"
                "(可用 GET /v1/models 或 /health 查看支持面)")
        return MiddlewareError(
            "invalid_request",
            f"参数 {param or '<body>'} 非法: {err.get('msg', '校验失败')}")
    return MiddlewareError("invalid_request", "请求体校验失败")


def openai_error_body(message: str, *, code: str, param: str | None = None,
                      err_type: str = "invalid_request_error",
                      request_id: str | None = None) -> dict:
    body = {"error": {"message": message, "type": err_type, "code": code,
                      "param": param}}
    if request_id:
        body["error"]["request_id"] = request_id
    return body


def anthropic_error_body(message: str, *, err_type: str = "invalid_request_error") -> dict:
    return {"type": "error", "error": {"type": err_type, "message": message}}


#: 错误类别 → HTTP 状态(与 errors._HTTP_STATUS 保持一致的公开口径)
def http_status_for(kind: str) -> int:
    from .errors import MiddlewareError as _MW
    return _MW(kind).http_status
