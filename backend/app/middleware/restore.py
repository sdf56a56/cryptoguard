"""
令牌恢复 —— 策略受控的「令牌 → 明文」回填(默认保守)

安全铁律(全部为可测试的硬约束):
  1. 只认本请求金库:token 必须在 (request_id, token) 上有映射;跨请求、模型自行
     生成的令牌一律不还原(既不报错也不猜测,原样留给客户端);
  2. 高风险类别永不自动还原:私钥/口令/云密钥/连接串/身份证/银行卡/手机号等
     由 protection.NEVER_AUTO_RESTORE 兜底,即使被写进白名单也不生效;
  3. 默认保守:restore_mode=off 时一个都不还原;categories 模式只还原白名单内类别;
     confirm 模式还需要客户端在本次请求里显式 ack;
  4. 还原绝不改变未命中令牌:输出里保留令牌原样,由客户端决定如何处理。

**必须说清的三件事**:
  - 令牌恢复 ≠ 可验证响应:还原只说明「这个令牌是本次请求签发的」,不证明模型
    回答的事实正确性,也不证明响应体里没有别的隐私泄露形式;
  - 还原发生在本地,与「模型看到了什么」无关:模型始终只看到令牌;
  - 模式 A 的占位符是可枚举的([PHONE_001]/[PHONE_002]…),模型可能猜中本次请求
    已签发的编号从而触发还原;由于响应只回到签发它的同一客户端,风险有限,但
    如需更强保证应使用模式 B/C(随机令牌)。
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

from .protection import NEVER_AUTO_RESTORE_TYPES, TokenVault, find_tokens

logger = logging.getLogger(__name__)

RESTORE_OFF = "off"
RESTORE_AUTO = "auto"
RESTORE_CATEGORIES = "categories"
RESTORE_CONFIRM = "confirm"
RESTORE_MODES = (RESTORE_OFF, RESTORE_AUTO, RESTORE_CATEGORIES, RESTORE_CONFIRM)


@dataclass
class RestorePolicy:
    """一次请求生效的恢复策略。"""

    mode: str = RESTORE_CATEGORIES
    categories: tuple[str, ...] = ()
    acknowledged: bool = False          # confirm 模式下客户端显式 ack

    def allows(self, entity_type: str) -> tuple[bool, str]:
        """判断某类别是否允许还原;返回 (允许, 拒绝原因)。"""
        if entity_type in NEVER_AUTO_RESTORE_TYPES:
            return False, "高风险类别,禁止自动还原(需走显式人工确认流程)"
        if self.mode == RESTORE_OFF:
            return False, "本次策略已关闭自动还原"
        if self.mode == RESTORE_CONFIRM and not self.acknowledged:
            return False, "confirm 模式:客户端未在本次请求中显式确认"
        if self.mode == RESTORE_AUTO:
            return True, ""
        if entity_type in self.categories:
            return True, ""
        return False, f"类别 {entity_type} 不在还原白名单 {list(self.categories)} 内"


@dataclass
class RestoreResult:
    """还原结果(含逐令牌的处置说明,便于审计与客户端提示)。"""

    text: str
    restored: list[dict] = field(default_factory=list)
    withheld: list[dict] = field(default_factory=list)
    foreign: list[dict] = field(default_factory=list)

    def public_view(self) -> dict:
        """对外元数据:不含任何明文。"""
        return restore_view(self.restored, self.withheld, self.foreign)


def restore_view(restored: list[dict], withheld: list[dict],
                 foreign: list[dict]) -> dict:
    """还原处置的对外视图(与 RestoreResult.public_view 同源,流式复用)。"""
    return {
        "restored_count": len(restored),
        "withheld_count": len(withheld),
        "foreign_token_count": len(foreign),
        "restored": [{"token": r["token"], "type": r["type"]} for r in restored],
        "withheld": withheld,
        "foreign": foreign,
    }


def _resolve(text: str, request_id: str, vault: TokenVault, policy: RestorePolicy,
             out_restored: list[dict], out_withheld: list[dict],
             out_foreign: list[dict], transform=None) -> str:
    """把 `text` 内所有完整令牌按策略还原;处置结果追加到三个累加列表。

    `transform` 只作用于**被还原出来的明文**,用于工具参数这类必须保持 JSON 可解析
    的场景(按 JSON 字符串转义);默认 None 表示原样插入。
    """
    tokens = find_tokens(text)
    if not tokens:
        return text
    replacements: list[tuple[int, int, str]] = []
    for start, end, token in tokens:
        entry = vault.lookup(request_id, token)
        if entry is None:
            out_foreign.append({
                "token": token,
                "reason": "不在本次请求的映射金库中(伪造/跨请求/模型自造)",
            })
            continue
        allowed, reason = policy.allows(entry.type)
        if not allowed:
            out_withheld.append({"token": token, "type": entry.type,
                                 "risk": entry.risk, "reason": reason})
            continue
        plaintext = transform(entry.plaintext) if transform else entry.plaintext
        replacements.append((start, end, plaintext))
        out_restored.append({"token": token, "type": entry.type, "risk": entry.risk})
    for start, end, plaintext in sorted(replacements, key=lambda r: r[0], reverse=True):
        text = text[:start] + plaintext + text[end:]
    return text


def restore_text(text: str, request_id: str, vault: TokenVault,
                 policy: RestorePolicy) -> RestoreResult:
    """按策略把 `text` 中本次请求签发的令牌还原为明文。

    未命中金库的令牌(伪造/跨请求/模型自造)原样保留,并计入 foreign 供审计。
    """
    result = RestoreResult(text=text)
    result.text = _resolve(text, request_id, vault, policy, result.restored,
                           result.withheld, result.foreign)
    return result


# --------------------------------------------------------------------------- #
# 流式还原:跨数据块令牌的持留与还原
# --------------------------------------------------------------------------- #
#: 令牌最长可能长度(超出即判定不是令牌):模式 B 约 35 字符,留两倍余量
MAX_TOKEN_LEN = 96


class StreamRestorer:
    """流式令牌还原器 —— 保证令牌不会因为分块而被撕裂。

    策略(可预测、有界):
      - 维护一个未决缓冲 `buffer`;每次收到增量后,输出**最后一个可能的令牌起点
        之前**的全部内容(已还原),从该起点起持留;
      - 持留期间若出现 `]` 且内容形态像令牌 → 视作一个完整令牌处理(还原或原样保留);
      - 若 `[` 之后超过 MAX_TOKEN_LEN 字符仍无 `]` → 判定不是令牌,原样输出该 `[`
        并继续;
      - 流结束时 `flush()` 把剩余持留内容按同一规则还原后输出。

    代价(必须说明):每个流最多多缓冲 MAX_TOKEN_LEN 个字符,即「令牌还原」引入的
    额外首字节延迟上限为一个令牌长度;内存开销 O(MAX_TOKEN_LEN) 与流长无关。
    不会为了「看起来实时」而放弃持留:提前输出半截令牌会让客户端看到 `[CG_TOK`,
    且还原失败。
    """

    def __init__(self, request_id: str, vault: TokenVault, policy: RestorePolicy,
                 max_token_len: int = MAX_TOKEN_LEN, plaintext_transform=None) -> None:
        self._request_id = request_id
        self._vault = vault
        self._policy = policy
        self._max = max(8, int(max_token_len))
        self._transform = plaintext_transform
        self._buffer = ""
        self.restored: list[dict] = []
        self.withheld: list[dict] = []
        self.foreign: list[dict] = []

    # ------------------------------------------------------------------ #
    def feed(self, delta: str) -> str:
        """喂入一段增量,返回可以立即下发的文本(已完成还原)。"""
        if not delta:
            return self._drain(final=False)
        self._buffer += delta
        return self._drain(final=False)

    def flush(self) -> str:
        """流结束:把持留内容全部输出(此时不再等待 `]`)。"""
        return self._drain(final=True)

    def view(self) -> dict:
        return restore_view(self.restored, self.withheld, self.foreign)

    # ------------------------------------------------------------------ #
    def _drain(self, *, final: bool) -> str:
        out: list[str] = []
        while self._buffer:
            start = self._buffer.find("[")
            if start < 0:
                out.append(self._resolve_plain(self._buffer))
                self._buffer = ""
                break
            if start > 0:
                out.append(self._resolve_plain(self._buffer[:start]))
                self._buffer = self._buffer[start:]
            candidate, rest, complete = self._split_candidate()
            if not complete:
                if final:
                    # 流已结束仍不完整:不再持留,原样输出(不猜、不还原)
                    out.append(self._resolve_plain(self._buffer))
                    self._buffer = ""
                break
            out.append(self._resolve_plain(candidate))
            self._buffer = rest
        return "".join(out)

    def _split_candidate(self) -> tuple[str, str, bool]:
        """从 buffer(以 `[` 开头)中切出一个候选片段。

        返回 (候选, 剩余, 是否已完整)。不完整时保持 buffer 原样(继续持留);
        判定「不是令牌」时,候选只取一个字符 `[`,让后续内容继续按普通文本处理。
        """
        from .protection import looks_like_token
        close = self._buffer.find("]")
        if close < 0:
            if len(self._buffer) > self._max:
                return self._buffer[:1], self._buffer[1:], True
            return "", self._buffer, False
        candidate = self._buffer[:close + 1]
        if looks_like_token(candidate) or len(candidate) <= self._max:
            return candidate, self._buffer[close + 1:], True
        # 形如 `[很长的普通文本...]`:不是令牌长度范围内的形态,逐个字符放行
        return self._buffer[:1], self._buffer[1:], True

    def _resolve_plain(self, text: str) -> str:
        if not text:
            return text
        return _resolve(text, self._request_id, self._vault, self._policy,
                        self.restored, self.withheld, self.foreign, self._transform)
