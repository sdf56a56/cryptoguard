"""
敏感数据保护 —— 模式 A 脱敏 / 模式 B 令牌化 / 模式 C 加密保护 + 请求级映射金库

三种模式(处理建议由 recognizers.DEFAULT_ACTIONS 给出,最终动作由策略决定):
  模式 A 脱敏   :`我的手机号是 13800138000` → `我的手机号是 [PHONE_001]`
                 —— 请求级稳定占位符,同值同号,便于模型与用户对齐;
  模式 B 令牌化 :→ `[CG_TOKEN_a81f…]` —— 随机不可推断,同值默认不同令牌
                 (可配置 stable_tokens 让同值同令牌以便模型共指);
  模式 C 加密   :→ `[CG_ENC_v1_a81f…]` —— 明文以 AES-256-GCM 封缄存入服务端金库,
                 令牌携带密钥版本号,支持密钥轮换(旧版本保留可解,新写入用新版本)。

密码学要点(全部使用成熟库 cryptography,不自研算法):
  - AEAD = AES-256-GCM;每次封缄用 96-bit 随机 nonce(os.urandom),不重用;
  - 认证标签由 GCM 在解密时校验,任何篡改导致解密失败(不返回明文);
  - 密钥独立 + 版本化:KeyRing 持有 {version: key},均由 VAULT_KEY 经 HKDF 按
    "protection-enc/v{n}" 域派生;轮换只增版本,历史密文仍可解。

**关键事实(不得含糊)**:令牌化/加密都无法让大模型"既看到原文又完全不泄露"。
模型看到的是令牌,不是原文;因此模式 B/C 下模型的回答里也不会包含原文语义。
只有在策略允许、且金库中确实存在该请求的映射时,中间件才会在**回程**把令牌还原为
明文交给客户端——还原发生在本地,与"模型看到了什么"是两件事。

明确不承诺:
  - 不承诺防持有 VAULT_KEY + 数据目录的攻击者(可解封金库密文);
  - 不承诺「低置信度漏检实体」不出站(识别器的召回边界);
  - 不承诺令牌在模型输出中的语义稳定性(模型可能改写/猜测令牌形态)。
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import re
import secrets
import threading
import time
from dataclasses import dataclass, field

from ..crypto.aead import AeadCipher
from ..detection import ENTITY_META
from ..keys import Vault, hkdf_sha256
from .errors import MiddlewareError
from .recognizers import Finding, RISK_RANK

logger = logging.getLogger(__name__)

MODE_PLACEHOLDER = "placeholder"
MODE_TOKEN = "token"
MODE_ENCRYPT = "encrypt"
MODES = (MODE_PLACEHOLDER, MODE_TOKEN, MODE_ENCRYPT)

#: 客户端可见的令牌形态(与 schemas.py 的正典文法兼容:[TYPE#token] / [A-Za-z0-9_]+)
_TOKEN_RE = re.compile(r"\[([A-Za-z0-9_]+)(?:#([A-Za-z0-9]+))?\]")
_ENCRYPT_RE = re.compile(r"^\[CG_ENC_v(\d+)_([0-9a-f]{16,})\]$")
_TOKEN_MARK_RE = re.compile(r"^\[CG_TOKEN_([0-9a-f]{16,})\]$")

#: 阻断策略等级:达到或超过该等级的动作建议为 block 时拒绝转发
_BLOCK_LEVELS = {"none": 0, "critical": 4, "high": 3}

#: 永不自动还原的高风险类别(策略白名单也覆盖不了;唯一来源,config/restore 共用)
NEVER_AUTO_RESTORE_TYPES = frozenset({
    "PRIVATE_KEY", "APIKEY", "CREDENTIAL", "DB_URL", "JWT", "BEARER_TOKEN",
    "PASSWORD", "ID", "CARD", "PHONE", "PHI", "PII",
})


# --------------------------------------------------------------------------- #
# 密钥环(版本化 + 轮换)
# --------------------------------------------------------------------------- #
class KeyRing:
    """版本化 AEAD 密钥环:`{version: bytes}`,新写入用当前版本,历史版本保留可解。"""

    def __init__(self, keys: dict[int, bytes], current: int,
                 label_key: bytes | None = None):
        if current not in keys:
            raise ValueError("当前密钥版本不在密钥环中")
        self._keys = dict(keys)
        self._current = current
        self._lock = threading.Lock()
        #: 模式 B 稳定令牌的标签密钥(服务端秘密)。**不得**用公开常量当密钥:
        #: 值域可枚举的敏感数据(如手机号)若用公开参数派生标签,任何人都能离线
        #: 枚举候选值并算出同一标签,从而把「不可读的令牌」变回「可校验的哈希」。
        self._label_key = label_key

    @classmethod
    def from_vault(cls, vault: Vault, *, versions: int = 1) -> "KeyRing":
        """由 Vault 派生 1..versions 版本的保护密钥(默认只有 v1)。"""
        keys = {
            version: hkdf_sha256(vault.mapping_key, f"protection-enc/v{version}")
            for version in range(1, versions + 1)
        }
        return cls(keys, current=versions,
                   label_key=hkdf_sha256(vault.mapping_key, "token-label/v1"))

    @property
    def label_key(self) -> bytes | None:
        """稳定令牌标签密钥(未配置时为 None → 稳定令牌被拒绝,不静默降级)。"""
        return self._label_key

    @property
    def current_version(self) -> int:
        with self._lock:
            return self._current

    def versions(self) -> list[int]:
        with self._lock:
            return sorted(self._keys)

    def cipher(self, version: int | None = None) -> tuple[int, AeadCipher]:
        """取 (版本, 加解密器);version=None 用当前版本,未知版本抛 config 错误。"""
        with self._lock:
            wanted = self._current if version is None else int(version)
            key = self._keys.get(wanted)
            if key is None:
                raise MiddlewareError(
                    "config", f"保护密钥版本 v{wanted} 不存在于密钥环"
                    f"(可用 {sorted(self._keys)})")
            return wanted, AeadCipher(key)

    def rotate(self, new_key: bytes) -> int:
        """加入新版本并置为当前(滚动轮换);返回新版本号。"""
        with self._lock:
            version = max(self._keys) + 1
            self._keys[version] = new_key
            self._current = version
            logger.warning("protection_key_rotated: 新版本 v%d(历史版本仍可解密)", version)
            return version


# --------------------------------------------------------------------------- #
# 映射条目与金库
# --------------------------------------------------------------------------- #
@dataclass
class MappingEntry:
    """一条「文内令牌 → 明文」映射。明文只在金库解密路径上短暂出现。"""

    token: str          # 文内替换形态
    type: str
    risk: str
    plaintext: str
    kind: str = MODE_PLACEHOLDER     # placeholder | token | encrypt
    key_version: int | None = None   # 仅 encrypt 模式有值
    pending: bool = False

    def public_view(self) -> dict:
        """审计视图:不含明文。"""
        return {
            "token": self.token,
            "type": self.type,
            "risk": self.risk,
            "kind": self.kind,
            "key_version": self.key_version,
            "plaintext_length": len(self.plaintext),
            "pending": self.pending,
        }


@dataclass
class _VaultRecord:
    """金库中的一次请求映射:密文条目 + 元信息。"""

    created: float
    entries: dict[str, dict] = field(default_factory=dict)   # token → {sealed, meta}


class TokenVault:
    """请求级映射金库(服务端受保护存储)。

    - 所有明文一律以 AES-256-GCM 封缄后驻留内存,金库本身不含明文;
    - 按 request_id 隔离:跨请求令牌在还原阶段天然无法命中(见 restore.py);
    - 有界:TTL + 请求数上限,LRU 淘汰,避免长跑进程无界增长;
    - 线程安全:中间件在工作线程里编排,金库可被多线程同时访问。
    """

    def __init__(self, vault: Vault, *, ttl_s: float = 3600.0, max_requests: int = 4096,
                 keyring: "KeyRing | None" = None):
        #: 模式 A/B 的通用封缄密钥(mapping 域);模式 C 走 KeyRing 的版本化密钥,
        #: 二者域分离,任一泄漏都不牵连另一域。
        self._cipher = AeadCipher(vault.mapping_key)
        self._keyring = keyring
        self._records: dict[str, _VaultRecord] = {}
        self._ttl = ttl_s
        self._max = max_requests
        self._lock = threading.Lock()
        self._hits = 0
        self._misses = 0

    # ------------------------------------------------------------------ #
    def store(self, request_id: str, entries: list[MappingEntry]) -> None:
        """封缄并保存本次请求的映射(覆盖同 id)。"""
        sealed: dict[str, dict] = {}
        for entry in entries:
            sealed[entry.token] = {
                "sealed": self._seal(entry),
                "type": entry.type,
                "risk": entry.risk,
                "kind": entry.kind,
                "key_version": entry.key_version,
                "pending": entry.pending,
            }
        with self._lock:
            self._records[request_id] = _VaultRecord(created=time.monotonic(),
                                                     entries=sealed)
            self._evict_locked()

    def _seal(self, entry: MappingEntry) -> dict:
        """按条目类型选封缄密钥:模式 C 用 KeyRing 的版本化密钥,其余用 mapping 域。

        模式 C 的密钥版本必须**真的**决定密文,否则「版本化/轮换」只是标签。
        """
        if entry.kind == MODE_ENCRYPT and entry.key_version is not None \
                and self._keyring is not None:
            return self._keyring.cipher(entry.key_version)[1].encrypt(entry.plaintext)
        return self._cipher.encrypt(entry.plaintext)

    def _unseal(self, raw: dict) -> str:
        """解封条目;任何失败(篡改/换钥/版本缺失)都抛异常,由调用方 fail-closed。"""
        sealed = raw["sealed"]
        if raw.get("kind") == MODE_ENCRYPT and self._keyring is not None:
            version = raw.get("key_version")
            if version is None:
                raise ValueError("mode-C 条目缺少 key_version,拒绝解封")
            return str(self._keyring.cipher(int(version))[1].decrypt(
                sealed["iv"], sealed["ciphertext"]))
        return str(self._cipher.decrypt(sealed["iv"], sealed["ciphertext"]))

    def tokens(self, request_id: str) -> set[str]:
        """本次请求签发过的全部令牌形态(还原白名单的**唯一**来源)。"""
        with self._lock:
            record = self._records.get(request_id)
            return set(record.entries) if record else set()

    def lookup(self, request_id: str, token: str) -> MappingEntry | None:
        """严格按 (request_id, token) 取映射;不存在返回 None(绝不跨请求回退)。"""
        with self._lock:
            record = self._records.get(request_id)
            raw = record.entries.get(token) if record else None
        if raw is None:
            with self._lock:
                self._misses += 1
            return None
        try:
            plaintext = self._unseal(raw)
        except Exception:  # noqa: BLE001 — 解封失败(换钥/损坏/版本缺失)视同无映射
            logger.error("vault_unseal_failed: 条目解封失败,按无映射处理(不还原)")
            with self._lock:
                self._misses += 1
            return None
        with self._lock:
            self._hits += 1
        return MappingEntry(
            token=token, type=raw["type"], risk=raw["risk"],
            plaintext=str(plaintext), kind=raw["kind"],
            key_version=raw["key_version"], pending=bool(raw["pending"]),
        )

    def entries(self, request_id: str) -> dict[str, dict]:
        """本次请求的映射元信息(token → 审计视图,不含明文)。"""
        with self._lock:
            record = self._records.get(request_id)
            if record is None:
                return {}
            snapshot = dict(record.entries)
        return {
            token: {
                "type": raw["type"], "risk": raw["risk"], "kind": raw["kind"],
                "key_version": raw["key_version"], "pending": bool(raw["pending"]),
            }
            for token, raw in snapshot.items()
        }

    def drop(self, request_id: str) -> None:
        """显式销毁一次请求的映射(用于高风险请求处理完毕即焚)。"""
        with self._lock:
            self._records.pop(request_id, None)

    def stats(self) -> dict:
        with self._lock:
            return {"tracked_requests": len(self._records), "ttl_s": self._ttl,
                    "max_requests": self._max, "unseal_hits": self._hits,
                    "unseal_misses": self._misses}

    def _evict_locked(self) -> None:
        now = time.monotonic()
        expired = [rid for rid, rec in self._records.items()
                   if now - rec.created > self._ttl]
        for rid in expired:
            self._records.pop(rid, None)
        while len(self._records) > self._max:
            oldest = min(self._records, key=lambda r: self._records[r].created)
            self._records.pop(oldest, None)


# --------------------------------------------------------------------------- #
# 保护结果
# --------------------------------------------------------------------------- #
@dataclass
class ProtectionResult:
    """一次文本保护的结果。"""

    text: str                                 # 受保护文本(出站用)
    entries: list[MappingEntry] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    blocked: list[Finding] = field(default_factory=list)
    pending: list[Finding] = field(default_factory=list)
    mode: str = MODE_PLACEHOLDER
    policy_version: str = ""

    @property
    def entity_count(self) -> int:
        return len(self.findings)

    def stats_by_type(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for finding in self.findings:
            out[finding.type] = out.get(finding.type, 0) + 1
        return out


def _placeholder_name(finding: Finding, counters: dict[str, int]) -> str:
    """模式 A 的稳定占位符:类型前缀 + 请求内序号。"""
    prefix = ENTITY_META.get(finding.type, {}).get("prefix") or finding.type
    counters[prefix] = counters.get(prefix, 0) + 1
    return f"[{prefix}_{counters[prefix]:03d}]"


def _type_prefix(type_: str) -> str:
    return ENTITY_META.get(type_, {}).get("prefix") or type_


def protect_text(text: str, findings: list[Finding], *, mode: str,
                 keyring: KeyRing | None = None,
                 stable_tokens: bool = False,
                 block_on: str = "critical",
                 policy_version: str = "",
                 counters: dict[str, int] | None = None,
                 used: set[str] | None = None) -> ProtectionResult:
    """按模式对文本做保护,返回受保护文本与映射条目。

    - `counters` / `used`:**必须由调用方在整次请求内共享**,否则两条消息里的
      不同明文会各自从 `[PHONE_001]` 起编号,产生同令牌不同值的映射碰撞
      (模型无法区分、金库后写覆盖先写)。不传则退化为「本段文本内唯一」;
    - `block_on`:风险等级达到该档且建议动作为 block 时,拒绝转发(不产出受保护文本);
    - 替换从后往前执行,避免偏移错位。

    **不存在「客户端说放行就放行」的旁路**:请求体里的放行请求只作为审计意图记录
    (见 policy.py),要真正拿回受保护内容必须走带身份校验与服务端审批的确认流程
    (见 confirmations.py)。
    """
    if mode not in MODES:
        raise MiddlewareError("config", f"未知保护模式: {mode!r}(可选 {list(MODES)})")
    blocked = [f for f in findings
               if f.suggested_action == "block" and not f.suppressed
               and RISK_RANK.get(f.risk, 0) >= _BLOCK_LEVELS.get(block_on, 4)]
    if blocked:
        # fail-closed:命中阻断档即不产出受保护文本,由调用方转 400 并记审计
        return ProtectionResult(text="", findings=list(findings), blocked=blocked,
                                mode=mode, policy_version=policy_version)

    counters = {} if counters is None else counters
    used = set() if used is None else used
    entries: list[MappingEntry] = []
    replacements: list[tuple[int, int, str]] = []
    #: 模式 C 的密钥版本在本次调用内固定(避免轮换与生成之间出现版本错位)
    enc_version = keyring.current_version if (
        mode == MODE_ENCRYPT and keyring is not None) else None

    for finding in sorted(findings, key=lambda f: f.start):
        if finding.suppressed or finding.suggested_action == "allow":
            continue
        token = _make_token(finding, mode, counters, keyring, used, stable_tokens,
                            enc_version)
        used.add(token)
        replacements.append((finding.start, finding.end, token))
        entries.append(MappingEntry(
            token=token, type=finding.type, risk=finding.risk,
            plaintext=finding.value,
            kind=mode,
            key_version=enc_version if mode == MODE_ENCRYPT else None,
            pending=finding.pending,
        ))

    protected = text
    for start, end, token in sorted(replacements, key=lambda r: r[0], reverse=True):
        protected = protected[:start] + token + protected[end:]

    return ProtectionResult(
        text=protected,
        entries=entries,
        findings=list(findings),
        pending=[f for f in findings if f.pending and not f.suppressed],
        mode=mode,
        policy_version=policy_version,
    )


def _make_token(finding: Finding, mode: str, counters: dict[str, int],
                keyring: KeyRing | None, used: set[str],
                stable_tokens: bool, enc_version: int | None) -> str:
    """生成文内令牌(保证本次请求内唯一)。"""
    if mode == MODE_PLACEHOLDER:
        while True:
            token = _placeholder_name(finding, counters)
            if token not in used:
                return token
    if mode == MODE_TOKEN:
        if stable_tokens:
            # 同值同令牌:标签由**服务端秘密**导出。用公开常量当密钥会让值域可枚举
            # 的数据(手机号/身份证)被离线枚举比对,令牌即等价于可校验哈希。
            label_key = keyring.label_key if keyring is not None else None
            if not label_key:
                raise MiddlewareError(
                    "config", "稳定令牌(CG_STABLE_TOKENS=1)需要服务端标签密钥,"
                    "当前未装配 KeyRing")
            digest = hmac.new(label_key,
                              f"{finding.type}|{finding.value}".encode("utf-8"),
                              hashlib.sha256).hexdigest()
            return f"[CG_TOKEN_{digest[:24]}]"
        while True:
            token = f"[CG_TOKEN_{secrets.token_hex(12)}]"
            if token not in used:
                return token
    if keyring is None or enc_version is None:
        raise MiddlewareError("config", "模式 C(加密保护)需要 KeyRing")
    while True:
        token = f"[CG_ENC_v{enc_version}_{secrets.token_hex(8)}]"
        if token not in used:
            return token


def parse_token(token: str) -> dict | None:
    """解析文内令牌形态 → {kind, version, id};非令牌返回 None。

    正典形态:模式 A `[PHONE_001]`、模式 B `[CG_TOKEN_hex]`、模式 C `[CG_ENC_v1_hex]`。
    """
    if not isinstance(token, str):
        return None
    match = _ENCRYPT_RE.fullmatch(token)
    if match:
        return {"kind": "encrypt", "version": int(match.group(1)),
                "prefix": "CG_ENC", "id": match.group(2)}
    match = _TOKEN_MARK_RE.fullmatch(token)
    if match:
        return {"kind": "token", "version": None, "prefix": "CG_TOKEN",
                "id": match.group(1)}
    match = _TOKEN_RE.fullmatch(token)
    if match:
        return {"kind": "placeholder", "version": None,
                "prefix": match.group(1), "id": match.group(2) or ""}
    return None


def find_tokens(text: str) -> list[tuple[int, int, str]]:
    """扫描文本中全部令牌形态,返回 (start, end, token)。

    只返回「形态上确实像本中间件令牌」的片段(见 looks_like_token),避免把模型
    输出里普通的方括号内容(如 `[1]`、`[注意]`)计入令牌统计。
    """
    return [(m.start(), m.end(), m.group(0)) for m in _TOKEN_RE.finditer(text)
            if looks_like_token(m.group(0))]


#: 模式 A 占位符:全大写前缀 + 下划线 + 1..6 位序号
_PLACEHOLDER_TOKEN_RE = re.compile(r"^[A-Z][A-Z0-9]*_\d{1,6}$")
#: 模式 B/C 令牌前缀
_MARK_PREFIXES = ("CG_TOKEN_", "CG_ENC_")


def looks_like_token(text: str) -> bool:
    """判断一段文本是否是中间件令牌形态(严格模式,用于还原与审计统计)。

    接受:`[TYPE#token]`(既有工程的引用形态)、`[CG_TOKEN_hex]`、`[CG_ENC_v1_hex]`、
    `[UPPER_001]`。其余方括号内容一律不算令牌 —— 宁可漏统计,也不把普通文本
    误当成「模型伪造的令牌」。
    """
    if not isinstance(text, str) or not text.startswith("[") or not text.endswith("]"):
        return False
    match = _TOKEN_RE.fullmatch(text)
    if match is None:
        return False
    name = match.group(1)
    if match.group(2) is not None:
        return bool(name)                        # [TYPE#token] 形态
    if name.startswith(_MARK_PREFIXES):
        return True
    return bool(_PLACEHOLDER_TOKEN_RE.match(name))
