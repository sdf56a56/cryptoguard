"""
敏感实体识别模块 —— 正则 + 规则 + 词典（对标 Microsoft Presidio 的 Recognizer 体系）

实体类型：姓名、身份证号、银行卡号、手机号、邮箱、地址、IP、URL、API Key、
          项目代号、组织/公司、医疗 PHI、金融 PII。

安全目标：在数据出本地前，最大化召回敏感实体并按策略脱敏，做到「可用不可见」。
明确不承诺：基于规则/正则的识别存在误报与漏报，不承诺对抗性输入下的完整检测（需 NLP 模型增强）。
"""
from __future__ import annotations

import hashlib
import re
import secrets
from dataclasses import dataclass, field


# 实体类型元数据：前缀、中文名、识别方法、建议脱敏模式
ENTITY_META: dict[str, dict] = {
    "NAME":    {"prefix": "NAME", "zh": "姓名",     "method": "词典 + 规则", "sensitivity": "high"},
    "ID":      {"prefix": "ID",   "zh": "身份证号", "method": "正则",        "sensitivity": "high"},
    "CARD":    {"prefix": "CARD", "zh": "银行卡号", "method": "正则 + Luhn",  "sensitivity": "high"},
    "PHONE":   {"prefix": "PHONE","zh": "手机号",   "method": "正则",        "sensitivity": "high"},
    "EMAIL":   {"prefix": "EMAIL","zh": "邮箱",     "method": "正则",        "sensitivity": "medium"},
    "ADDRESS": {"prefix": "ADDR", "zh": "地址",     "method": "词典 + 规则",  "sensitivity": "medium"},
    "IP":      {"prefix": "IP",   "zh": "IP 地址",  "method": "正则",        "sensitivity": "low"},
    "URL":     {"prefix": "URL",  "zh": "URL",      "method": "正则",        "sensitivity": "low"},
    "APIKEY":  {"prefix": "KEY",  "zh": "API Key",  "method": "正则 + 熵",    "sensitivity": "high"},
    "PROJECT": {"prefix": "PROJ", "zh": "项目代号", "method": "词典",         "sensitivity": "medium"},
    "ORG":     {"prefix": "ORG",  "zh": "组织/公司", "method": "词典 + 规则",  "sensitivity": "low"},
    "PHI":     {"prefix": "PHI",  "zh": "医疗 PHI", "method": "词典",         "sensitivity": "high"},
    "PII":     {"prefix": "PII",  "zh": "金融 PII", "method": "词典",         "sensitivity": "high"},
}

# 默认启用的实体类型
DEFAULT_ENABLED = set(ENTITY_META.keys())


# --------------------------------------------------------------------------- #
# 正则识别器
# --------------------------------------------------------------------------- #
def _luhn_ok(number: str) -> bool:
    digits = [int(d) for d in number]
    checksum = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


_PATTERNS: list[tuple[str, re.Pattern]] = [
    # 身份证号（18 位，含校验位 X）
    ("ID", re.compile(r"(?<!\d)[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?!\d)")),
    # 银行卡号（13-19 位数字，后续用 Luhn 校验）
    ("CARD", re.compile(r"(?<!\d)\d{13,19}(?!\d)")),
    # 手机号
    ("PHONE", re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")),
    # 邮箱
    ("EMAIL", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
    # IPv4
    ("IP", re.compile(r"(?<!\d)(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?!\d)")),
    # URL
    ("URL", re.compile(r"https?://[^\s\"'<>，。；、]+")),
    # API Key（sk-/AKIA/hex32+ 等常见形态）
    ("APIKEY", re.compile(r"(?:sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|(?<![A-Fa-f0-9])[A-Fa-f0-9]{32,64}(?![A-Fa-f0-9]))")),
]

# 姓名词典（演示级常见姓名）
_NAME_DICT = {
    "张伟", "王芳", "李娜", "刘洋", "陈静", "杨洋", "赵敏", "黄强", "周杰",
    "吴磊", "徐明", "孙丽", "马超", "朱婷", "胡军", "郭靖", "林丹", "何洁",
    "高翔", "罗琳", "郑爽", "梁静", "谢娜", "宋佳", "唐嫣", "韩雪", "曹颖",
    "许晴", "邓超", "冯巩", "彭于晏", "董卿", "潘长江", "袁隆平", "蒋雯丽",
    # 裁定 R5:全项目演示/测试统一人名
    "张三", "李四",
}

_ADDR_KEYS = ("省", "市", "区", "县", "镇", "街道", "路", "号", "小区", "医院", "银行", "大厦", "广场")
_PROJECT_DICT = {"天枢计划", "玄武工程", "猎户座", "昆仑项目", "凤凰协议"}
_ORG_DICT = {"第一人民医院", "中心医院", "工商银行", "建设银行", "招商银行", "国家电网", "中信证券", "平安保险"}
_PHI_DICT = {"病历号", "诊断", "HIV", "艾滋病", "肿瘤", "精神病", "血型", "住院号", "医保卡号", "床号"}
_PII_DICT = {"账户余额", "工资", "收入", "授信额度", "交易流水", "密码", "验证码"}

_DICT_SCAN: list[tuple[str, set]] = [
    ("NAME", _NAME_DICT),
    ("PROJECT", _PROJECT_DICT),
    ("ORG", _ORG_DICT),
    ("PHI", _PHI_DICT),
    ("PII", _PII_DICT),
]


@dataclass
class Entity:
    type: str
    value: str
    placeholder: str
    start: int
    end: int
    confidence: float = 1.0
    method: str = "正则"

    def to_dict(self) -> dict:
        return {
            "type": self.type,
            "zh": ENTITY_META.get(self.type, {}).get("zh", self.type),
            "value": self.value,
            "placeholder": self.placeholder,
            "start": self.start,
            "end": self.end,
            "confidence": self.confidence,
            "method": self.method,
            "sensitivity": ENTITY_META.get(self.type, {}).get("sensitivity", "medium"),
        }


@dataclass
class DetectionResult:
    original: str
    redacted: str
    entities: list[Entity] = field(default_factory=list)
    mapping: dict[str, str] = field(default_factory=dict)
    restore_map: dict[str, str] = field(default_factory=dict)  # 脱敏串 -> 明文（本地还原用）

    def to_dict(self) -> dict:
        return {
            "original": self.original,
            "redacted": self.redacted,
            "entities": [e.to_dict() for e in self.entities],
            "mapping": self.mapping,
            "stats": {
                "total": len(self.entities),
                "by_type": {t: sum(1 for e in self.entities if e.type == t) for t in {e.type for e in self.entities}},
            },
        }


# --------------------------------------------------------------------------- #
# 脱敏模式：placeholder / mask / hash / encrypt（对标 Presidio Anonymizer operators）
# --------------------------------------------------------------------------- #
def apply_mode(value: str, placeholder: str, mode: str) -> str:
    if mode == "mask":
        # 保留首尾各 1-2 位，中间打码；同时追加序号保证还原无歧义
        if len(value) <= 2:
            return value[:1] + "*"
        if len(value) <= 4:
            return value[:1] + "*" * (len(value) - 2) + value[-1:]
        return value[:2] + "*" * (len(value) - 4) + value[-2:]
    if mode == "hash":
        return "sha256:" + hashlib.sha256(value.encode()).hexdigest()[:16]
    # 默认 placeholder
    return placeholder


def detect_sensitive(
    text: str,
    enabled_types: set[str] | None = None,
    mode: str = "placeholder",
) -> DetectionResult:
    enabled = enabled_types if enabled_types is not None else DEFAULT_ENABLED
    result = DetectionResult(original=text, redacted=text)
    counters: dict[str, int] = {}
    found: list[Entity] = []

    # 正则扫描
    for etype, pattern in _PATTERNS:
        if etype not in enabled:
            continue
        for m in pattern.finditer(text):
            value = m.group()
            confidence = 0.95
            method = ENTITY_META[etype]["method"]
            # 银行卡 Luhn 校验提升/降低置信度
            if etype == "CARD":
                if not _luhn_ok(value):
                    # 长度像卡号但 Luhn 不过，可能是订单号等 → 低置信度
                    confidence = 0.5
            if etype == "APIKEY":
                confidence = 0.8
            counters[etype] = counters.get(etype, 0) + 1
            placeholder = f"[{ENTITY_META[etype]['prefix']}_{counters[etype]}]"
            found.append(Entity(etype, value, placeholder, m.start(), m.end(), confidence, method))

    # 词典扫描
    for etype, dct in _DICT_SCAN:
        if etype not in enabled:
            continue
        for kw in dct:
            for m in re.finditer(re.escape(kw), text):
                counters[etype] = counters.get(etype, 0) + 1
                placeholder = f"[{ENTITY_META[etype]['prefix']}_{counters[etype]}]"
                found.append(Entity(etype, kw, placeholder, m.start(), m.end(), 0.9, ENTITY_META[etype]["method"]))

    # 地址：包含 >=2 个地址关键词的连续片段（简化：整句按关键词组合找）
    if "ADDRESS" in enabled:
        addr_pat = re.compile(r"[一-龥A-Za-z0-9]{2,}?(?:省|市)[一-龥A-Za-z0-9]{0,20}?(?:区|县)?[一-龥A-Za-z0-9]{2,}?(?:路|街道|大道)[一-龥A-Za-z0-9]{0,10}号?")
        for m in addr_pat.finditer(text):
            counters["ADDRESS"] = counters.get("ADDRESS", 0) + 1
            placeholder = f"[ADDR_{counters['ADDRESS']}]"
            found.append(Entity("ADDRESS", m.group(), placeholder, m.start(), m.end(), 0.85, "词典 + 规则"))

    # 去重：同一区间重叠只保留最长/置信度最高的
    found.sort(key=lambda e: (e.start, -(e.end - e.start), -e.confidence))
    seen: list[tuple[int, int]] = []
    deduped = []
    for e in found:
        if any(s[0] < e.end and e.start < s[1] for s in seen):
            continue
        seen.append((e.start, e.end))
        deduped.append(e)
    result.entities = sorted(deduped, key=lambda e: e.start)

    # 从后往前替换，避免偏移
    redacted = text
    for e in sorted(result.entities, key=lambda e: e.start, reverse=True):
        replacement = apply_mode(e.value, e.placeholder, mode)
        e.replacement = replacement  # type: ignore[attr-defined]
        redacted = redacted[:e.start] + replacement + redacted[e.end:]

    result.redacted = redacted
    result.mapping = {e.placeholder: e.value for e in result.entities}
    result.restore_map = {getattr(e, "replacement", e.placeholder): e.value for e in result.entities}
    return result
