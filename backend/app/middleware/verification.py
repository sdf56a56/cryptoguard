"""
可验证响应 —— 请求/响应规范化摘要、记录级 HMAC、审计哈希链

本模块把「可验证」落到可测试的三件事上,并**明确划清**它不能证明什么。

能做:
  1. 请求/响应摘要(JCS 规范化 + SHA-256):检查数据是否被改动过;
  2. 记录级 HMAC(HMAC-SHA256,密钥独立于封缄密钥):持钥方可校验记录未被改动;
  3. 审计哈希链(prev_hash → hash,并带 seq 连续性):检测条目被删/被换/被重排;
  4. /v1/verify:按 request_id 取回上述证据并给出逐项结论与失败原因。

不能做(**不得对外宣传为已具备**):
  - 哈希/签名都不能证明「响应来自指定模型服务商」:本中间件签的是**本地网关**看到的
    内容,不是服务商对内容的签名。要证明来源需要服务商侧的可验证凭证(如厂商签名/
    证明),当前上游 API 普遍不提供,故本项目不声称具备该能力;
  - 本地日志(哪怕 HMAC + 哈希链)不能单独证明「未被持有密钥的管理员篡改」:
    持钥者可整链重写;要检测整链重写需要外部锚点(离线公证/时间戳服务/独立审计方),
    本项目只实现到「检测非持钥方的篡改」这一步,并在文档中明示边界;
  - HTTPS 只保护传输链路,不证明模型回答的事实正确性;
  - 摘要一致只能说明「客户端收到的字节与网关记录的一致」,不代表内容真的正确。
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

from ..canon import canon, h_hex
from .errors import MiddlewareError

logger = logging.getLogger(__name__)

D_REQUEST = "CG/MW/REQ/v1"
D_RESPONSE = "CG/MW/RESP/v1"
D_RECORD = "CG/MW/RECORD/v1"
D_CHAIN = "CG/MW/AUDIT_LINK/v1"

_TS_FMT = "%Y-%m-%dT%H:%M:%S.%fZ"


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime(_TS_FMT)


def new_request_id() -> str:
    """请求 ID:带前缀的随机标识(前缀便于日志检索,随机避免可预测)。"""
    return f"cg-{uuid.uuid4().hex}"


# --------------------------------------------------------------------------- #
# 摘要
# --------------------------------------------------------------------------- #
def _normalize_message(message: dict) -> dict:
    """把一条消息收敛为可规范化的确定性形状(用于摘要计算)。"""
    content = message.get("content")
    if isinstance(content, list):
        content = [part if isinstance(part, dict) else str(part) for part in content]
    calls = []
    for call in message.get("tool_calls") or []:
        if isinstance(call, dict):
            fn = call.get("function") or {}
            calls.append({"name": str(fn.get("name") or ""),
                          "arguments": str(fn.get("arguments") or "")})
    out: dict = {"role": str(message.get("role") or ""), "content": content}
    if calls:
        out["tool_calls"] = calls
    if message.get("tool_call_id"):
        out["tool_call_id"] = str(message["tool_call_id"])
    return out


def request_digest(*, model: str, messages: list[dict], tools: list[dict] | None,
                   params: dict) -> str:
    """对**受保护后**的出站请求计算摘要(绝不对明文原文计算,避免摘要泄漏结构)。

    前映像(公开、可复现):
      {"d":"CG/MW/REQ/v1","m":<model>,"msgs":[{role,content,tool_calls?,tool_call_id?}],
       "tools":[<工具定义原样>],"p":<支持的参数子集,按键排序>}
    """
    return h_hex({
        "d": D_REQUEST,
        "m": str(model),
        "msgs": [_normalize_message(m) for m in messages],
        "tools": list(tools or []),
        "p": {str(k): params[k] for k in sorted(params)},
    })


def tool_call_pair(call) -> list[str]:
    """把任意形态的工具调用归一成 `[name, arguments]`。

    接受三种形态,因为同一次交付在链路上有三种写法:
      - `{"name":…, "arguments":…}`                      —— 流式增量与审计内部形态;
      - `{"id":…, "type":"function", "function": {...}}` —— 交付给客户端的 OpenAI 形态;
      - `["name", "arguments"]`                          —— 摘要前映像里记的紧凑形态。
    归一很重要:若不看 `function` 子对象,OpenAI 形态会被算成 `["",""]`,
    于是「改了工具参数」与「原样」摘要相同 —— 完整性校验形同虚设。
    """
    if isinstance(call, (list, tuple)):
        name = call[0] if len(call) > 0 else ""
        args = call[1] if len(call) > 1 else ""
        return [str(name or ""), str(args or "")]
    if not isinstance(call, dict):
        return ["", ""]
    fn = call.get("function")
    fn = fn if isinstance(fn, dict) else {}
    name = call.get("name") or fn.get("name") or ""
    args = call.get("arguments") or fn.get("arguments") or ""
    return [str(name), str(args)]


def response_digest(*, text: str, tool_calls: list[dict] | None = None,
                    finish_reason: str | None = None, model: str = "") -> str:
    """对**交付给客户端**的响应计算摘要(客户端可自行复算是本机制的价值所在)。

    前映像:{"d":"CG/MW/RESP/v1","m":<model>,"t":<text>, "tc":[[name,arguments],…],
             "fr":<finish_reason>}

    `model` 用**响应体里的 model**(= 请求的 model),不是上游自述的模型名:
    客户端只能拿到前者,用它复算才对得上。
    """
    return h_hex({
        "d": D_RESPONSE,
        "m": str(model or ""),
        "t": str(text or ""),
        "tc": [tool_call_pair(c) for c in (tool_calls or [])],
        "fr": "" if finish_reason is None else str(finish_reason),
    })


def recompute_response_digest(payload: dict) -> str:
    """供 /v1/verify 复算:接受 `{"text","tool_calls","finish_reason","model"}`。

    `tool_calls` 项可以是交付形态(OpenAI 的 `{"function":{…}}`)、内部形态
    (`{"name","arguments"}`)或紧凑形态(`["name","arguments"]`),经 `tool_call_pair` 归一。
    """
    if not isinstance(payload, dict):
        raise MiddlewareError("invalid_request", "response.payload 必须是 JSON 对象")
    calls = []
    for call in payload.get("tool_calls") or []:
        if isinstance(call, dict):
            calls.append(call)
        elif isinstance(call, (list, tuple)) and len(call) == 2:
            calls.append({"name": call[0], "arguments": call[1]})
    return response_digest(text=str(payload.get("text") or ""),
                           tool_calls=calls,
                           finish_reason=payload.get("finish_reason"),
                           model=str(payload.get("model") or ""))


# --------------------------------------------------------------------------- #
# 审计记录
# --------------------------------------------------------------------------- #
@dataclass
class RequestRecord:
    """一次中间件调用的审计记录。

    安全约束:**绝不含原始 prompt、原始敏感值、API Key、Authorization 头**;
    只记录类别计数、摘要、状态与决策。
    """

    request_id: str
    seq: int = 0
    ts: str = ""
    ts_epoch: float = 0.0
    client_id: str = ""
    client_name: str = ""
    requested_model: str = ""
    provider: str = ""
    upstream_model: str = ""
    endpoint: str = ""
    stream: bool = False
    policy_version: str = ""
    protection_mode: str = ""
    request_digest: str = ""
    response_digest: str = ""
    upstream_status: int | None = None
    outcome: str = ""               # ok | error | blocked | incomplete
    error_kind: str = ""
    latency_ms: float = 0.0
    detections: dict = field(default_factory=dict)   # {by_type:{}, by_risk:{}, total:int}
    actions: dict = field(default_factory=dict)      # 决策计数:blocked/allowed/pending
    restored: dict = field(default_factory=dict)     # RestoreResult.public_view()
    usage: dict = field(default_factory=dict)
    prev_hash: str = ""
    chain_hash: str = ""
    record_mac: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    def payload_for_mac(self) -> dict:
        """record_mac 的前映像:除 record_mac 外的全部字段(含链哈希)。"""
        data = self.to_dict()
        data.pop("record_mac", None)
        return data

    def public_view(self) -> dict:
        """对外(管理员)视图:与落盘记录一致(本就不含明文)。"""
        return self.to_dict()


#: RequestRecord 声明的字段名集合(校验时用于剔除存储层注入的额外键)
_RECORD_FIELDS = frozenset(RequestRecord.__dataclass_fields__)


def chain_hash_of(prev_hash: str, seq: int, request_id: str,
                  request_digest: str, response_digest: str, ts: str) -> str:
    """审计链链接哈希:绑定位置上邻、序号、请求 ID 与两侧摘要。"""
    return h_hex({
        "d": D_CHAIN,
        "prev": prev_hash,
        "seq": seq,
        "rid": request_id,
        "rq": request_digest,
        "rs": response_digest,
        "ts": ts,
    })


def record_mac(key: bytes, record: RequestRecord) -> str:
    """记录级 HMAC(HMAC-SHA256 over JCS 规范化记录)。"""
    return hmac.new(key, canon(record.payload_for_mac()), hashlib.sha256).hexdigest()


def verify_record_mac(key: bytes, raw: dict) -> bool:
    """校验记录级 HMAC(常数时间比较);字段缺失/多余键即视为不通过。

    存储层会在落盘时注入 entry_checksum 字段(那是文件行级封缄,不属于记录语义),
    因此这里只取 RequestRecord 声明的字段参与重算,其余键一律忽略。
    """
    try:
        stored = str(raw["record_mac"])
        record = RequestRecord(**{k: v for k, v in raw.items() if k in _RECORD_FIELDS})
    except (KeyError, TypeError):
        return False
    return hmac.compare_digest(stored, record_mac(key, record))


def verify_chain_link(raw: dict) -> bool:
    """校验单条记录的链哈希是否与其字段自洽(不含对前驱的信任)。"""
    try:
        expected = chain_hash_of(str(raw["prev_hash"]), int(raw["seq"]),
                                 str(raw["request_id"]), str(raw["request_digest"]),
                                 str(raw["response_digest"]), str(raw["ts"]))
    except (KeyError, TypeError, ValueError):
        return False
    return hmac.compare_digest(expected, str(raw.get("chain_hash") or ""))


def digest_of_text(text: str) -> str:
    """通用文本摘要(SHA-256 hex),用于日志相关性比对。"""
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()


def canonical_json(obj) -> str:
    """对外展示的规范化 JSON(与摘要用的 JCS 同源,便于客户端复现)。"""
    return canon(obj).decode("utf-8")


def load_digest_spec() -> dict:
    """摘要前映像的机器可读说明(/v1/verify 的响应里回给客户端,便于复算)。"""
    return {
        "request_digest": {
            "preimage": {
                "d": D_REQUEST, "m": "<model>",
                "msgs": [{"role": "…", "content": "…", "tool_calls": "<可选>"}],
                "tools": "<工具定义数组或 []>",
                "p": "<支持的参数子集,键排序>",
            },
            "note": "对受保护后的出站请求计算,不涉及任何明文原值",
            "algorithm": "RFC 8785 (JCS) 规范化 + SHA-256 hex",
        },
        "response_digest": {
            "preimage": {"d": D_RESPONSE, "m": "<model>", "t": "<交付文本>",
                         "tc": [["<tool_name>", "<arguments_json>"]], "fr": "<finish_reason>"},
            "note": "对交付给客户端的响应计算:客户端可用收到的文本自行复算比对",
            "algorithm": "RFC 8785 (JCS) 规范化 + SHA-256 hex",
        },
        "audit_link": {
            "preimage": {"d": D_CHAIN, "prev": "<上一条 chain_hash>", "seq": "<序号>",
                         "rid": "<request_id>", "rq": "<request_digest>",
                         "rs": "<response_digest>", "ts": "<ISO8601 UTC>"},
            "note": "链式绑定,删除/改写/重排任意条目都会打断链",
            "algorithm": "RFC 8785 (JCS) 规范化 + SHA-256 hex",
        },
        "record_mac": {
            "note": "HMAC-SHA256(密钥 = VAULT_KEY 派生的 audit-mac/v1,不对外暴露)",
            "verify": "仅管理员可校验;客户端可用摘要做无密钥一致性比对",
        },
    }


def json_dumps_compact(obj) -> str:
    """紧凑 JSON(审计导出用,避免把对象 repr 拼进日志)。"""
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), default=str)
