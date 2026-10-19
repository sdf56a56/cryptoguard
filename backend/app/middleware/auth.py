"""
客户端认证与管理员认证 —— 严格区分「客户端凭证」与「上游服务商凭证」

安全目标:
  - 客户端密钥只以 HMAC-SHA256 摘要落盘(密钥 = VAULT_KEY 派生的 client-key/v1 子密钥
    作 pepper)。摘要不可逆,且没有本地 pepper 时无法对泄漏的摘要做离线爆破;
  - 明文密钥只在创建/轮换的响应里出现一次,此后任何接口都不回显;
  - 上游密钥与客户端密钥不同源、不同存储、不同代码路径(上游密钥在 ProviderConfig
    内存里,客户端密钥在本模块的封缄日志里),任一泄漏不牵连另一;
  - 校验用 compare_digest 常数时间比较,且对未知前缀做等价计算以弱化时序差;
  - 管理员接口必须持 CG_ADMIN_TOKEN,缺失即 503(fail-closed),绝不默认放行。

明确不承诺:
  - 不承诺抵抗持有 VAULT_KEY + 数据目录的攻击者(可离线枚举候选密钥);
  - 不承诺多进程并发写同一客户端日志(单写者模型,同 store.py)。
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import threading
import time
import uuid
from dataclasses import dataclass, field

from ..keys import Vault, hkdf_sha256
from ..store import SealedNDJSON
from .errors import MiddlewareError

logger = logging.getLogger(__name__)

KEY_PREFIX = "cgk"
_SECRET_BYTES = 24          # 192-bit 随机密钥主体
_PREFIX_BYTES = 6           # 48-bit 公开查找前缀
_MIN_SECRET_HEX = 32        # 低于此长度的密钥一律视为格式非法


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def generate_client_key() -> tuple[str, str, str]:
    """生成客户端密钥,返回 (明文密钥, prefix, secret)。

    形态:`cgk_<prefix12hex>_<secret48hex>`;prefix 明文可存(仅用于查找),
    secret 只在创建响应中出现一次。
    """
    prefix = secrets.token_hex(_PREFIX_BYTES)
    secret = secrets.token_hex(_SECRET_BYTES)
    return f"{KEY_PREFIX}_{prefix}_{secret}", prefix, secret


def split_client_key(key: str) -> tuple[str, str] | None:
    """解析密钥 → (prefix, secret);格式非法返回 None(不抛,避免把输入回显进栈)。"""
    if not isinstance(key, str):
        return None
    parts = key.strip().split("_")
    if len(parts) != 3 or parts[0] != KEY_PREFIX:
        return None
    prefix, secret = parts[1], parts[2]
    if len(prefix) != _PREFIX_BYTES * 2 or len(secret) < _MIN_SECRET_HEX:
        return None
    if not all(c in "0123456789abcdef" for c in prefix):
        return None
    return prefix, secret


def key_digest(pepper: bytes, prefix: str, secret: str) -> str:
    """密钥校验材料:HMAC-SHA256(pepper, "cgk/v1|<prefix>|<secret>")。"""
    message = f"cgk/v1|{prefix}|{secret}".encode("utf-8")
    return hmac.new(pepper, message, hashlib.sha256).hexdigest()


@dataclass
class ClientKey:
    """一个客户端凭证(rev 递增,latest 生效)。"""

    id: str
    name: str = ""
    prefix: str = ""
    key_hash: str = ""
    created: str = ""
    revoked: bool = False
    rev: int = 0
    last_used: str | None = None
    #: 空列表 = 不限制;非空 = 只允许这些客户端模型名
    models: list[str] = field(default_factory=list)
    #: 0 = 跟随全局
    rate_limit_per_min: int = 0
    #: 空 = 跟随全局策略
    protection_mode: str = ""
    restore_categories: list[str] = field(default_factory=list)
    #: 过期时间(epoch 秒);0 = 永不过期。新增字段对旧记录默认 0,保持兼容。
    expires_epoch: float = 0.0

    @property
    def expired(self) -> bool:
        return bool(self.expires_epoch) and time.time() >= self.expires_epoch

    def public_view(self) -> dict:
        """对外视图:绝不包含 key_hash 与明文密钥。"""
        return {
            "id": self.id,
            "name": self.name,
            "prefix": self.prefix,
            "created": self.created,
            "revoked": self.revoked,
            "last_used": self.last_used,
            "models": list(self.models),
            "rate_limit_per_min": self.rate_limit_per_min,
            "protection_mode": self.protection_mode,
            "restore_categories": list(self.restore_categories),
            "expires_epoch": self.expires_epoch,
        }


class ClientKeyStore:
    """客户端密钥存储(封缄 NDJSON,append-only + rev 折叠)。

    **线程安全**:底层 `SealedNDJSON` 自身不做互斥(其文档明确要求调用方串行化),
    而 `routes._touch_client` 会在**每个已认证请求结束**时写一次 `last_used` ——
    即请求处理线程会并发读写同一份日志。若不互斥,读侧会读到另一个线程写了一半的
    行,被 `SealedNDJSON` 判为 corrupt(fail-closed),把一次正常请求变成 500。
    第 5 阶段实测:不同密钥的并发首请求下,全量跑约 1/25 次命中
    (`StoreIntegrityError: seg-000001.ndjson 第 8 行 JSON 解析失败`)。
    故本类自带可重入锁,把 `_latest()` 的读与 `_append_revision()` 的写串行化。
    """

    def __init__(self, log: SealedNDJSON, pepper: bytes):
        self._log = log
        self._pepper = pepper
        self._cache: dict[str, ClientKey] | None = None
        self._lock = threading.RLock()     # 可重入:create/touch → get → _latest

    @classmethod
    def build(cls, data_dir, vault: Vault, *, seg_max_entries: int = 5000,
              seg_max_bytes: int = 10 * 1024 * 1024) -> "ClientKeyStore":
        # Vault 不保留根密钥明文(仅有 HKDF 按用途域派生的子密钥),故从 chain_mac_key
        # 再经一层 HKDF 派生本模块专用 pepper:仍不接触根密钥,且与封缄密钥域分离。
        pepper = hkdf_sha256(vault.chain_mac_key, "client-key/v1")
        log = SealedNDJSON(data_dir / "clients", "seg", vault.chain_mac_key,
                           seg_max_entries=seg_max_entries, seg_max_bytes=seg_max_bytes)
        return cls(log, pepper)

    # ------------------------------------------------------------------ #
    def _latest(self) -> dict[str, ClientKey]:
        with self._lock:
            if self._cache is not None:
                return self._cache
            latest: dict[str, ClientKey] = {}
            for rec in self._log.read_all():
                if rec.get("type") != "client":
                    continue
                cid = rec.get("id")
                if not isinstance(cid, str):
                    continue
                prev = latest.get(cid)
                if prev is None or int(rec.get("rev", -1)) >= prev.rev:
                    latest[cid] = ClientKey(
                        id=cid,
                        name=str(rec.get("name") or ""),
                        prefix=str(rec.get("prefix") or ""),
                        key_hash=str(rec.get("key_hash") or ""),
                        created=str(rec.get("created") or ""),
                        revoked=bool(rec.get("revoked")),
                        rev=int(rec.get("rev", 0)),
                        last_used=rec.get("last_used"),
                        models=list(rec.get("models") or []),
                        rate_limit_per_min=int(rec.get("rate_limit_per_min") or 0),
                        protection_mode=str(rec.get("protection_mode") or ""),
                        restore_categories=list(rec.get("restore_categories") or []),
                        expires_epoch=float(rec.get("expires_epoch") or 0.0),
                    )
            self._cache = latest
            return latest

    def _append_revision(self, key: ClientKey, **changes) -> ClientKey:
        merged = ClientKey(**{**key.__dict__, **changes, "rev": key.rev + 1})
        with self._lock:
            self._log.append({
                "type": "client",
                "id": merged.id,
                "name": merged.name,
                "prefix": merged.prefix,
                "key_hash": merged.key_hash,
                "created": merged.created,
                "revoked": merged.revoked,
                "rev": merged.rev,
                "last_used": merged.last_used,
                "models": merged.models,
                "rate_limit_per_min": merged.rate_limit_per_min,
                "protection_mode": merged.protection_mode,
                "restore_categories": merged.restore_categories,
                "expires_epoch": merged.expires_epoch,
            })
            self._cache = None
        return merged

    # ------------------------------------------------------------------ #
    def list_clients(self) -> list[ClientKey]:
        return list(self._latest().values())

    def get(self, client_id: str) -> ClientKey:
        key = self._latest().get(client_id)
        if key is None:
            raise MiddlewareError("not_found", f"客户端不存在: {client_id}")
        return key

    def count(self) -> int:
        return len(self._latest())

    def create(self, name: str, *, models: list[str] | None = None,
               rate_limit_per_min: int = 0, protection_mode: str = "",
               restore_categories: list[str] | None = None,
               expires_in_days: int = 0) -> tuple[ClientKey, str]:
        """创建客户端密钥;返回 (记录, 明文密钥)。明文只此一次。"""
        plaintext, prefix, secret = generate_client_key()
        expires_epoch = (time.time() + int(expires_in_days) * 86400.0
                         if int(expires_in_days or 0) > 0 else 0.0)
        record = {
            "type": "client",
            "id": uuid.uuid4().hex,
            "name": (name or "").strip() or "client",
            "prefix": prefix,
            "key_hash": key_digest(self._pepper, prefix, secret),
            "created": _now_iso(),
            "revoked": False,
            "rev": 0,
            "last_used": None,
            "models": list(models or []),
            "rate_limit_per_min": int(rate_limit_per_min or 0),
            "protection_mode": protection_mode or "",
            "restore_categories": list(restore_categories or []),
            "expires_epoch": expires_epoch,
        }
        with self._lock:
            self._log.append(record)
            self._cache = None
        return self.get(record["id"]), plaintext

    def revoke(self, client_id: str) -> ClientKey:
        key = self.get(client_id)
        if key.revoked:
            return key
        return self._append_revision(key, revoked=True)

    def rotate(self, client_id: str) -> tuple[ClientKey, str]:
        """轮换密钥:同一客户端 id/名称/限额,换新密钥材料,旧密钥立即失效。"""
        key = self.get(client_id)
        plaintext, prefix, secret = generate_client_key()
        updated = self._append_revision(
            key, prefix=prefix, key_hash=key_digest(self._pepper, prefix, secret),
            revoked=False)
        return updated, plaintext

    def update(self, client_id: str, **changes) -> ClientKey:
        """更新客户端配置（PATCH）；只接受显式列出的字段，rev 递增。"""
        key = self.get(client_id)
        allowed = {"name", "models", "rate_limit_per_min", "protection_mode",
                   "restore_categories", "expires_epoch"}
        clean = {field: value for field, value in changes.items() if field in allowed}
        if not clean:
            return key
        return self._append_revision(key, **clean)

    def touch(self, client_id: str) -> None:
        """记录最近使用时间(不递增权限相关字段;失败静默,不影响请求)。

        整个「读旧值 → 写新值」持锁,避免两次并发 touch 互相覆盖。
        """
        try:
            with self._lock:
                key = self.get(client_id)
                self._append_revision(key, last_used=_now_iso())
        except MiddlewareError:
            pass

    # ------------------------------------------------------------------ #
    def authenticate(self, presented: str) -> ClientKey:
        """校验出示的客户端密钥;失败抛 MiddlewareError("auth")。

        对未知前缀也计算一次等价的 HMAC,弱化「前缀是否存在」的时序差异。
        """
        parsed = split_client_key(presented or "")
        if parsed is None:
            # 假比较:保持与命中路径近似的工作量
            key_digest(self._pepper, "0" * (_PREFIX_BYTES * 2), "0" * _MIN_SECRET_HEX)
            raise MiddlewareError("auth", "客户端密钥格式非法或缺失")
        prefix, secret = parsed
        candidate = key_digest(self._pepper, prefix, secret)
        match: ClientKey | None = None
        for key in self._latest().values():
            if hmac.compare_digest(key.prefix, prefix) and hmac.compare_digest(
                    key.key_hash, candidate):
                match = key
                break
        if match is None:
            raise MiddlewareError("auth", "客户端密钥无效")
        if match.revoked:
            raise MiddlewareError("auth", "客户端密钥已被撤销")
        if match.expired:
            raise MiddlewareError("auth", "客户端密钥已过期,请向管理员申请新密钥")
        return match


# --------------------------------------------------------------------------- #
# 管理员认证
# --------------------------------------------------------------------------- #
class AdminAuthenticator:
    """管理员接口认证:单用户、全权令牌,常数时间比较。

    平台只有一个管理员用户，不存在只读角色。未配置令牌时开发环境返回明确 503，
    生产环境启动期已 fail-fast。
    """

    def __init__(self, token: str, *, production: bool = False):
        self._token = (token or "").strip()
        self._production = production

    @property
    def configured(self) -> bool:
        return bool(self._token)

    def require(self, presented: str | None) -> str:
        """校验管理员凭证;成功返回 "admin"。"""
        presented = str(presented or "").strip()
        if not self._token:
            raise MiddlewareError(
                "config",
                "管理员接口未启用:请设置 CG_ADMIN_TOKEN 后重启"
                "(开发环境也需显式配置,避免无凭证的管理面)")
        if not presented:
            raise MiddlewareError("auth", "缺少管理员令牌(X-Admin-Token)")
        if hmac.compare_digest(presented, self._token):
            return "admin"
        logger.warning("admin_auth_failed: 令牌不匹配")
        raise MiddlewareError("auth", "管理员令牌无效")

def now_epoch() -> float:
    """便于测试注入的当前时间(秒)。"""
    return time.time()
