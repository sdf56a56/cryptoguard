"""
敏感数据识别扩展 —— 在既有 13 类识别器之上补齐凭证/私钥/连接串/自定义规则

复用而非重写:基础 13 类实体仍由 app.detection.detect_sensitive 完成(正则 + 词典 +
Luhn/校验位 + 置信度),本模块只做三件事:
  1. 补齐高风险管理面:私钥、云厂商/平台令牌、JWT、Bearer、数据库连接串、密码赋值;
  2. 统一输出为 Finding(类型/命中位置/风险等级/命中规则/处理建议),并携带
     confidence 与 pending 标记以支持「低置信度人工确认」;
  3. 误报抑制:文档示例值、占位符、哈希/版本号语境、Git SHA 等一律降级或抑制,
     避免把每一个像密钥的普通字符串都当成真凭证(规则可配置)。

明确不承诺:
  - 规则/正则识别仍存在误报与漏报,不承诺对抗性变形输入(同音字、零宽字符、
    分片拼接)下的完整检测;
  - 不承诺抑制规则覆盖全部语境差异,抑制清单本身是显式可配置、可审计的。
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

from ..detection import ENTITY_META, DEFAULT_ENABLED, detect_sensitive
from .errors import MiddlewareError

logger = logging.getLogger(__name__)

#: 风险等级序(越大越高)
RISK_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}

#: 基础实体 sensitivity → 风险等级
_SENSITIVITY_TO_RISK = {"low": "low", "medium": "medium", "high": "high"}

#: 处理建议(默认动作)。实际生效动作由保护模式 + 客户端策略决定,此处只给「建议」。
DEFAULT_ACTIONS: dict[str, str] = {
    # 必须阻断:私钥/口令本体一旦出站即等同于凭据泄漏
    "PRIVATE_KEY": "block",
    "PASSWORD": "block",
    "CREDENTIAL": "block",
    # 令牌化:可保持可用性但需隐藏原值
    "APIKEY": "token",
    "JWT": "token",
    "BEARER_TOKEN": "token",
    "DB_URL": "token",
    "ID": "token", "CARD": "token", "PHONE": "token",
    "PHI": "token", "PII": "token",
    # 脱敏:低敏感但需去标识
    "EMAIL": "placeholder", "ADDRESS": "placeholder", "NAME": "placeholder",
    "ORG": "placeholder", "PROJECT": "placeholder", "IP": "placeholder",
    "URL": "placeholder", "CUSTOM": "placeholder",
}

#: 风险等级(用于排序与策略;基础实体按 sensitivity 映射,新增类型按此表)
_TYPE_RISK: dict[str, str] = {
    "PRIVATE_KEY": "critical", "PASSWORD": "critical", "CREDENTIAL": "critical",
    "APIKEY": "high", "JWT": "high", "BEARER_TOKEN": "high", "DB_URL": "high",
    "ID": "high", "CARD": "high", "PHONE": "high", "PHI": "high", "PII": "high",
    "EMAIL": "medium", "ADDRESS": "medium", "NAME": "medium", "PROJECT": "medium",
    "IP": "low", "URL": "low", "ORG": "low", "CUSTOM": "medium",
}

#: 低置信度阈值:低于此值的命中标记 pending(交人工确认),默认按保守动作处理
REVIEW_THRESHOLD = 0.6


# --------------------------------------------------------------------------- #
# 扩展识别规则(每条:类型 / 规则 id / 正则 / 取值分组)
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class ExtendedRule:
    type: str
    rule_id: str
    pattern: re.Pattern
    group: int = 0
    confidence: float = 0.9
    method: str = "正则"


def _rule(type_: str, rule_id: str, pattern: str, **kw) -> ExtendedRule:
    return ExtendedRule(type_, rule_id, re.compile(pattern), **kw)


EXTENDED_RULES: tuple[ExtendedRule, ...] = (
    _rule("PRIVATE_KEY", "PK-PEM",
          r"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----[\s\S]{0,8000}?-----END (?:[A-Z]+ )*PRIVATE KEY-----",
          confidence=0.99, method="正则(PEM 块)"),
    _rule("JWT", "JWT-3SEG",
          r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b",
          confidence=0.92, method="正则(JWT 三段)"),
    _rule("BEARER_TOKEN", "AUTH-BEARER",
          r"(?i)\bbearer\s+([A-Za-z0-9._\-]{16,})", group=1, confidence=0.9),
    _rule("DB_URL", "DB-CONN",
          r"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|"
          r"amqp|mssql|oracle|clickhouse|elasticsearch)://[^\s\"'<>|,;]{6,}",
          confidence=0.93, method="正则(连接串)"),
    _rule("APIKEY", "KEY-VENDOR",
          r"\b(?:sk-[A-Za-z0-9_\-]{16,}|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|"
          r"AIza[0-9A-Za-z_\-]{35}|ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,}|"
          r"glpat-[A-Za-z0-9_\-]{20}|xox[baprs]-[A-Za-z0-9\-]{10,}|"
          r"sk_live_[A-Za-z0-9]{16,}|rk_live_[A-Za-z0-9]{16,}|"
          r"SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,})\b",
          confidence=0.95, method="正则(厂商前缀)"),
    _rule("PASSWORD", "PWD-KV",
          r"(?i)\b(?:password|passwd|pwd|passphrase|secret|client[_-]?secret|"
          r"access[_-]?key|secret[_-]?key|private[_-]?key|auth[_-]?token)\b"
          r"\s*[:=]\s*[\"']?([^\s\"',;]{6,})",
          group=1, confidence=0.85, method="正则(键值赋值)"),
)

#: 语境抑制:命中值本身是示例/占位/文档形态时,一律不作为真实凭证
_PLACEHOLDER_TOKENS = (
    "example", "your_", "your-", "yours", "xxxx", "****", "placeholder",
    "redacted", "dummy", "sample", "changeme", "replace", "todo", "foobar",
    "<", ">", "${", "{{", "…", "...", "hidden", "masked", "notreal",
)

#: 哈希/Git 语境:32/64 位十六进制串多为摘要而非密钥,需有上下文才判为凭证
_HASH_CONTEXT = re.compile(
    r"(?i)\b(?:sha1|sha224|sha256|sha384|sha512|md5|hash|digest|checksum|"
    r"commit|blob|tree|parent|etag|integrity)\b[\s:=#]{0,3}$")

#: 版本号语境:形如 IPv4 的版本串 "1.2.3.4" 前有 v/version 即抑制
_VERSION_CONTEXT = re.compile(r"(?i)\b(?:v|version|ver\.?|版本)\s*[:=]?\s*$")

#: URL 语境:命中落在 URL 内部时不重复计数(URL 规则自身会覆盖)
_URL_CONTEXT = re.compile(r"(?i)https?://[^\s\"'<>]*$")


@dataclass
class Finding:
    """一次敏感数据命中。"""

    type: str
    value: str
    start: int
    end: int
    risk: str = "medium"
    rule: str = ""
    suggested_action: str = "placeholder"
    confidence: float = 1.0
    method: str = ""
    pending: bool = False
    suppressed: bool = False
    suppress_reason: str = ""

    def to_dict(self) -> dict:
        """审计/元数据视图:默认**不含明文 value**(需要时显式 value_preview)。"""
        return {
            "type": self.type,
            "start": self.start,
            "end": self.end,
            "length": self.end - self.start,
            "risk": self.risk,
            "rule": self.rule,
            "suggested_action": self.suggested_action,
            "confidence": round(self.confidence, 3),
            "method": self.method,
            "pending": self.pending,
        }


# --------------------------------------------------------------------------- #
# 可配置扩展(CG_DETECTION_CONFIG 指向的 JSON)
# --------------------------------------------------------------------------- #
@dataclass
class DetectorConfig:
    """识别器扩展配置(全部字段可缺省)。"""

    custom_rules: list[ExtendedRule] = field(default_factory=list)
    sensitive_words: list[str] = field(default_factory=list)
    suppress_patterns: list[re.Pattern] = field(default_factory=list)
    disabled_types: set[str] = field(default_factory=set)

    @classmethod
    def load(cls, path: str | Path | None) -> "DetectorConfig":
        """从 JSON 文件加载;文件缺失返回空配置,内容非法抛 config 错误。"""
        if not path:
            return cls()
        file = Path(path)
        if not file.is_file():
            logger.warning("CG_DETECTION_CONFIG 指向的文件不存在,按默认规则运行: %s", file)
            return cls()
        import json
        try:
            raw = json.loads(file.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise MiddlewareError("config", f"检测规则文件解析失败: {exc}") from None
        if not isinstance(raw, dict):
            raise MiddlewareError("config", "检测规则文件必须是 JSON 对象")
        rules: list[ExtendedRule] = []
        for item in raw.get("custom_rules") or []:
            if not isinstance(item, dict) or not item.get("pattern"):
                raise MiddlewareError("config", "custom_rules 每项需含 pattern")
            try:
                compiled = re.compile(str(item["pattern"]))
            except re.error as exc:
                raise MiddlewareError(
                    "config", f"自定义规则 {item.get('id')!r} 正则非法: {exc}") from None
            rules.append(ExtendedRule(
                type=str(item.get("type") or "CUSTOM").upper(),
                rule_id=str(item.get("id") or f"CUSTOM-{len(rules) + 1}"),
                pattern=compiled,
                group=int(item.get("group") or 0),
                confidence=float(item.get("confidence") or 0.8),
                method="自定义正则",
            ))
        suppress: list[re.Pattern] = []
        for item in raw.get("suppress_patterns") or []:
            pattern = item.get("pattern") if isinstance(item, dict) else item
            if not pattern:
                continue
            try:
                suppress.append(re.compile(str(pattern)))
            except re.error as exc:
                raise MiddlewareError("config", f"抑制规则正则非法: {exc}") from None
        return cls(
            custom_rules=rules,
            sensitive_words=[str(w) for w in (raw.get("sensitive_words") or []) if str(w)],
            suppress_patterns=suppress,
            disabled_types={str(t).upper() for t in (raw.get("disabled_types") or [])},
        )


# --------------------------------------------------------------------------- #
# 主入口
# --------------------------------------------------------------------------- #
def detect_all(text: str, *, config: DetectorConfig | None = None,
               enabled_types: set[str] | None = None,
               mode: str = "placeholder") -> list[Finding]:
    """在当前文本上运行全部识别器,返回去重后、按位置排序的 Finding 列表。

    合并规则:区间重叠时保留「更长 / 风险更高 / 置信度更高」的一条(与既有
    detection.detect_sensitive 的去重口径一致),避免同一片段被多规则重复计数。
    """
    config = config or DetectorConfig()
    enabled = set(DEFAULT_ENABLED if enabled_types is None else enabled_types)
    enabled -= config.disabled_types

    found: list[Finding] = []

    # 1) 基础 13 类(复用既有实现;其内部已做区间去重)
    base = detect_sensitive(text, enabled_types=enabled, mode=mode)
    for entity in base.entities:
        if entity.type in config.disabled_types:
            continue
        risk = _TYPE_RISK.get(entity.type,
                              _SENSITIVITY_TO_RISK.get(
                                  ENTITY_META.get(entity.type, {}).get("sensitivity", "medium"),
                                  "medium"))
        found.append(Finding(
            type=entity.type, value=entity.value, start=entity.start, end=entity.end,
            risk=risk, rule=f"BASE-{entity.type}",
            suggested_action=DEFAULT_ACTIONS.get(entity.type, "placeholder"),
            confidence=entity.confidence, method=entity.method,
        ))

    # 2) 扩展规则(凭证/私钥/连接串)
    for rule in (*EXTENDED_RULES, *config.custom_rules):
        for match in rule.pattern.finditer(text):
            try:
                start, end = match.span(rule.group)
            except (IndexError, re.error):
                # 分组不存在(规则写错)不致命:跳过该命中并留痕,不中断整次检测
                logger.warning("识别规则 %s 的 group=%d 不存在,已跳过", rule.rule_id, rule.group)
                continue
            if start < 0 or end <= start:
                continue
            value = text[start:end]
            if not value.strip():
                continue
            if rule.type in config.disabled_types:
                continue
            found.append(Finding(
                type=rule.type, value=value, start=start, end=end,
                risk=_TYPE_RISK.get(rule.type, "medium"), rule=rule.rule_id,
                suggested_action=DEFAULT_ACTIONS.get(rule.type, "token"),
                confidence=rule.confidence, method=rule.method,
            ))

    # 3) 自定义敏感词(词典式,全字面匹配)
    for word in config.sensitive_words:
        for match in re.finditer(re.escape(word), text):
            found.append(Finding(
                type="CUSTOM", value=word, start=match.start(), end=match.end(),
                risk="medium", rule="WORD-LIST", suggested_action="placeholder",
                confidence=0.8, method="敏感词表",
            ))

    merged = _merge_overlaps(found)
    for finding in merged:
        _apply_suppression(text, finding, config)
    return merged


def _merge_overlaps(findings: list[Finding]) -> list[Finding]:
    """重叠区间只保留一条:更长 > 风险更高 > 置信度更高。"""
    ordered = sorted(findings, key=lambda f: (
        f.start, -(f.end - f.start), -RISK_RANK.get(f.risk, 0), -f.confidence))
    accepted: list[Finding] = []
    for finding in ordered:
        if any(other.start < finding.end and finding.start < other.end
               for other in accepted):
            continue
        accepted.append(finding)
    return sorted(accepted, key=lambda f: f.start)


def _apply_suppression(text: str, finding: Finding, config: DetectorConfig) -> None:
    """误报抑制与低置信度标记(就地修改 finding)。"""
    lowered = finding.value.lower()
    context = text[max(0, finding.start - 40):finding.start]

    # 显式配置的抑制正则
    for pattern in config.suppress_patterns:
        if pattern.search(finding.value):
            _suppress(finding, "匹配配置的抑制规则")
            return

    # 示例/占位值(如 your-api-key、sk-xxxxxxxx、<token>)
    if any(token in lowered for token in _PLACEHOLDER_TOKENS):
        _suppress(finding, "疑似示例/占位值")
        return

    # 哈希/Git 语境下的 32/64 位十六进制
    if finding.type == "APIKEY" and re.fullmatch(r"[0-9a-fA-F]{32,64}", finding.value):
        if _HASH_CONTEXT.search(context):
            _suppress(finding, "哈希/摘要语境")
            return
        finding.confidence = min(finding.confidence, 0.55)
        finding.rule = f"{finding.rule}(无上下文)"

    # 版本号语境下的 IPv4 形态
    if finding.type == "IP" and _VERSION_CONTEXT.search(context):
        _suppress(finding, "版本号语境")
        return

    # URL 内部的命中(URL 规则本身已覆盖整串),避免重复计数
    if finding.type not in ("URL",) and _URL_CONTEXT.search(context):
        _suppress(finding, "URL 内部命中")

    # 低置信度 → 待人工确认
    if finding.confidence < REVIEW_THRESHOLD:
        finding.pending = True


def _suppress(finding: Finding, reason: str) -> None:
    finding.suppressed = True
    finding.suppress_reason = reason


def risk_of(type_: str) -> str:
    """实体类型 → 风险等级(策略模块用)。"""
    return _TYPE_RISK.get(type_, "medium")
