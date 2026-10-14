"""
第 4 阶段 · 任务 3 —— 模式 C(AES-256-GCM 加密保护)端到端安全验证

先把两个概念分清楚,后面所有断言都以此为准:
  - **出站脱敏(transport redaction)**:送到上游的内容里,敏感片段被替换为
    `[CG_ENC_v{n}_<hex>]`。上游看到的是这个令牌,**不是密文**,也不理解任何
    AEAD 语义 —— 本中间件不声称上游具备任何解密能力;
  - **应用内加密(in-app encryption)**:明文以 AES-256-GCM 封缄后驻留在本进程的
    请求级金库中(内存,`{iv, ciphertext}`),只有本中间件用 VAULT_KEY 派生的
    子密钥能解封。

本文件验证的密码学属性(全部确定性可复现):
  1. 算法与密钥长度:AES-256-GCM,子密钥 32 字节,由 VAULT_KEY 经 HKDF 域分离派生;
  2. nonce:每次封缄独立随机 96-bit,绝不复用、无计数器/固定值;
  3. 认证:篡改 ciphertext / iv / tag 任一,或密钥版本缺失/错版,解封一律失败
     (fail-closed 返回「无映射」,绝不返回明文、绝不抛栈给客户端);
  4. 轮换:KeyRing 加版本后旧密文仍可解,新写入用新版本,令牌版本号与实际密钥一致;
  5. 出站内容里既没有明文也没有密文;
  6. 密钥材料与密文不出现在审计、日志、管理接口里。

诚实边界(不得据此宣称「系统已绝对安全」):
  - 不防持有 VAULT_KEY + 数据目录的攻击者(可解封金库);
  - 封缄未使用 AAD:密文不额外绑定 `(request_id, token)`。金库仅存在于内存、
    以该二元组为键,「搬移密文」需要先能改写进程内存 —— 那种攻击者已可直接读取
    明文,故此处不构成额外暴露;如需跨进程/落盘存储,应先补 AAD 绑定;
  - 上游看到的是令牌,不证明上游理解或遵守了任何加密语义。
"""
from __future__ import annotations

import base64
import json

import pytest

from app.crypto.aead import AeadCipher
from app.middleware.errors import MiddlewareError
from app.middleware.protection import (MODE_ENCRYPT, KeyRing, TokenVault,
                                       parse_token, protect_text)
from app.middleware.recognizers import detect_all
from tests.mw.conftest import chat, meta_of, mock_provider, reply_text

EMAIL = "zhangsan@corp.com.cn"
PHONE = "13800138000"
SECRET = "zhangsan@corp.com.cn"


@pytest.fixture()
def crypto_env(tmp_path):
    """(Vault, KeyRing, TokenVault) 三件套:真实密钥派生,不 mock 密码学。"""
    from app.keys import Vault

    vault = Vault.load_or_init(tmp_path / "data", env_path=tmp_path / "v.env")
    ring = KeyRing.from_vault(vault)
    token_vault = TokenVault(vault, ttl_s=600.0, max_requests=16, keyring=ring)
    return vault, ring, token_vault


@pytest.fixture()
def encrypt_env(make_mw):
    """模式 C 的整套环境:(中间件, TestClient, 认证头)。"""
    mw, client, key = make_mw(protection_mode="encrypt")
    return mw, client, {"Authorization": f"Bearer {key}"}


def _seal_one(token_vault, ring, request_id: str, value: str = SECRET) -> str:
    findings = detect_all(value, mode=MODE_ENCRYPT)
    result = protect_text(value, findings, mode=MODE_ENCRYPT, keyring=ring)
    token_vault.store(request_id, result.entries)
    return result.entries[0].token


def _sealed(token_vault, request_id: str, token: str) -> dict:
    return token_vault._records[request_id].entries[token]["sealed"]  # noqa: SLF001


def _flip(blob_b64: str, index: int) -> str:
    raw = bytearray(base64.b64decode(blob_b64))
    raw[index % len(raw)] ^= 0x01
    return base64.b64encode(bytes(raw)).decode()


# --------------------------------------------------------------------------- #
# 1. 算法与密钥
# --------------------------------------------------------------------------- #
def test_key_is_256_bit_and_algorithm_is_aes_gcm(crypto_env):
    vault, ring, _ = crypto_env
    version, cipher = ring.cipher()
    assert version == 1
    assert len(cipher._key) == 32                       # noqa: SLF001 — 被测密钥长度
    assert cipher._key != vault.mapping_key             # 域分离:mapping 与 protection-enc
    assert len(vault.mapping_key) == 32

    # 非 128/192/256 位的密钥必须被底层直接拒绝(不静默补零/截断)
    for bad in (b"", b"short", b"x" * 31):
        with pytest.raises(ValueError):
            AeadCipher(bad)


def test_derived_key_is_not_the_root_key(crypto_env, tmp_path):
    from app.keys import Vault, hkdf_sha256

    vault = Vault.load_or_init(tmp_path / "data2", env_path=tmp_path / "v2.env")
    ring = KeyRing.from_vault(vault, versions=3)
    v1, _ = ring.cipher(1)
    v2, _ = ring.cipher(2)
    v3, _ = ring.cipher(3)
    keys = {ring._keys[v] for v in (v1, v2, v3)}        # noqa: SLF001 — 校验派生结果
    assert len(keys) == 3                               # 每个版本一把不同的密钥
    assert all(key != vault.mapping_key for key in keys)
    assert hkdf_sha256(vault.mapping_key, "protection-enc/v1") in keys


# --------------------------------------------------------------------------- #
# 2. nonce 不得重用
# --------------------------------------------------------------------------- #
def test_nonce_is_random_96_bit_and_never_reused(crypto_env):
    _, ring, _ = crypto_env
    _, cipher = ring.cipher()
    ivs = [base64.b64decode(cipher.encrypt(SECRET)["iv"]) for _ in range(500)]
    assert all(len(iv) == 12 for iv in ivs)
    assert len(set(ivs)) == len(ivs), "同一密钥下 nonce 重用会摧毁 GCM 的安全性"
    # 不是计数器(相邻 iv 不递增)
    assert all(int.from_bytes(b, "big") - int.from_bytes(a, "big") != 1
               for a, b in zip(ivs, ivs[1:]))


def test_repeated_encryption_of_same_plaintext_yields_different_ciphertext(crypto_env):
    _, ring, _ = crypto_env
    _, cipher = ring.cipher()
    blobs = {cipher.encrypt(SECRET)["ciphertext"] for _ in range(50)}
    assert len(blobs) == 50, "确定性密文会暴露「两个请求里是同一个值」"


# --------------------------------------------------------------------------- #
# 3. 认证失败一律 fail-closed
# --------------------------------------------------------------------------- #
def test_tampered_ciphertext_fails_closed(crypto_env):
    _, ring, token_vault = crypto_env
    token = _seal_one(token_vault, ring, "cg-a")
    assert token_vault.lookup("cg-a", token).plaintext == SECRET

    _sealed(token_vault, "cg-a", token)["ciphertext"] = _flip(
        _sealed(token_vault, "cg-a", token)["ciphertext"], 0)
    assert token_vault.lookup("cg-a", token) is None


def test_tampered_nonce_fails_closed(crypto_env):
    _, ring, token_vault = crypto_env
    token = _seal_one(token_vault, ring, "cg-b")
    _sealed(token_vault, "cg-b", token)["iv"] = _flip(
        _sealed(token_vault, "cg-b", token)["iv"], 0)
    assert token_vault.lookup("cg-b", token) is None


def test_tampered_auth_tag_fails_closed(crypto_env):
    """GCM 的认证标签是密文尾部 16 字节:改动它必须导致解密失败。"""
    _, ring, token_vault = crypto_env
    token = _seal_one(token_vault, ring, "cg-c")
    blob = _sealed(token_vault, "cg-c", token)
    raw = base64.b64decode(blob["ciphertext"])
    assert len(raw) > 16, "密文应包含 16 字节认证标签"
    blob["ciphertext"] = _flip(blob["ciphertext"], len(raw) - 1)
    assert token_vault.lookup("cg-c", token) is None


def test_missing_key_version_fails_closed(crypto_env):
    """模式 C 条目缺少版本号时拒绝解封(绝不猜一个版本去试)。"""
    _, ring, token_vault = crypto_env
    token = _seal_one(token_vault, ring, "cg-d")
    token_vault._records["cg-d"].entries[token]["key_version"] = None  # noqa: SLF001
    assert token_vault.lookup("cg-d", token) is None


def test_unknown_key_version_fails_closed(crypto_env):
    _, ring, token_vault = crypto_env
    token = _seal_one(token_vault, ring, "cg-e")
    token_vault._records["cg-e"].entries[token]["key_version"] = 99  # noqa: SLF001
    assert token_vault.lookup("cg-e", token) is None


def test_wrong_key_fails_closed(crypto_env, tmp_path):
    """换一把密钥(模拟轮换出错/跨部署混用)无法解出明文。"""
    from app.keys import Vault

    _, ring, token_vault = crypto_env
    token = _seal_one(token_vault, ring, "cg-f")

    other_vault = Vault.load_or_init(tmp_path / "other", env_path=tmp_path / "o.env")
    other_ring = KeyRing.from_vault(other_vault)
    assert other_ring._keys[1] != ring._keys[1]         # noqa: SLF001

    token_vault._keyring = other_ring                   # noqa: SLF001 — 等价于「换钥后读旧密文」
    assert token_vault.lookup("cg-f", token) is None


def test_malformed_ciphertext_and_encoding_fail_closed(crypto_env):
    _, ring, token_vault = crypto_env
    token = _seal_one(token_vault, ring, "cg-g")
    blob = _sealed(token_vault, "cg-g", token)

    for broken in ("!!!not-base64!!!", "", base64.b64encode(b"short").decode()):
        blob["ciphertext"] = broken
        assert token_vault.lookup("cg-g", token) is None
    blob["ciphertext"] = base64.b64encode(b"\x00" * 40).decode()
    assert token_vault.lookup("cg-g", token) is None
    blob["iv"] = base64.b64encode(b"\x01" * 12).decode()
    assert token_vault.lookup("cg-g", token) is None


def test_missing_sealed_fields_fail_closed(crypto_env):
    _, ring, token_vault = crypto_env
    token = _seal_one(token_vault, ring, "cg-h")
    entry = token_vault._records["cg-h"].entries[token]     # noqa: SLF001
    for key in ("iv", "ciphertext"):
        stash = entry["sealed"].pop(key)
        assert token_vault.lookup("cg-h", token) is None
        entry["sealed"][key] = stash


# --------------------------------------------------------------------------- #
# 4. 版本化与轮换
# --------------------------------------------------------------------------- #
def test_rotation_keeps_old_ciphertext_readable_and_uses_new_version(crypto_env):
    _, ring, token_vault = crypto_env
    old_token = _seal_one(token_vault, ring, "cg-old")
    assert parse_token(old_token)["version"] == 1

    new_version = ring.rotate(b"\x11" * 32)
    assert new_version == 2 and ring.current_version == 2

    new_token = _seal_one(token_vault, ring, "cg-new")
    assert parse_token(new_token)["version"] == 2
    # 历史密文仍可解(轮换不丢数据),新写入用新版本
    assert token_vault.lookup("cg-old", old_token).plaintext == SECRET
    assert token_vault.lookup("cg-new", new_token).plaintext == SECRET
    assert token_vault._records["cg-old"].entries[old_token]["key_version"] == 1
    assert token_vault._records["cg-new"].entries[new_token]["key_version"] == 2


def test_vault_entry_uses_keyring_key_not_mapping_key(crypto_env):
    """回归:模式 C 的版本化密钥必须**真的**决定密文,否则「轮换」只是标签。

    修复前 `KeyRing.cipher()` 从未被调用,所有模式 C 条目都用 mapping 域密钥封缄,
    `[CG_ENC_v1_…]` 里的版本号纯属装饰(换钥后旧数据根本解不开,版本号也无意义)。
    """
    vault, ring, token_vault = crypto_env
    token = _seal_one(token_vault, ring, "cg-kv")
    blob = _sealed(token_vault, "cg-kv", token)

    _, ring_cipher = ring.cipher(1)
    assert ring_cipher.decrypt(blob["iv"], blob["ciphertext"]) == SECRET
    with pytest.raises(Exception):                      # noqa: B017 — 任何失败都算通过
        AeadCipher(vault.mapping_key).decrypt(blob["iv"], blob["ciphertext"])


def test_encrypt_mode_requires_keyring(crypto_env):
    _, _, _ = crypto_env
    findings = detect_all(f"联系 {EMAIL}", mode=MODE_ENCRYPT)
    with pytest.raises(MiddlewareError) as excinfo:
        protect_text(f"联系 {EMAIL}", findings, mode=MODE_ENCRYPT, keyring=None)
    assert excinfo.value.kind == "config"
    assert "KeyRing" in excinfo.value.detail


# --------------------------------------------------------------------------- #
# 5. 出站内容:既无明文也无密文
# --------------------------------------------------------------------------- #
def test_upstream_sees_token_neither_plaintext_nor_ciphertext(encrypt_env):
    mw, client, headers = encrypt_env
    response = chat(client, headers, f"联系 {EMAIL},电话 {PHONE}")
    assert response.status_code == 200, response.text

    rid = response.headers["X-CryptoGuard-Request-ID"]
    seen = mock_provider(mw).seen[-1]
    sent = json.dumps(seen.messages, ensure_ascii=False)
    assert EMAIL not in sent and PHONE not in sent

    for token in mw.token_vault.tokens(rid):
        blob = token_vault_blob(mw, rid, token)
        assert token in sent
        # 令牌里的 hex 是随机标识,与密文/iv 的任何片段都不相同
        assert blob["ciphertext"] not in sent
        assert blob["iv"] not in sent
        assert parse_token(token)["kind"] == "encrypt"
        assert parse_token(token)["version"] == 1

    text = reply_text(response)
    meta = meta_of(response)
    assert EMAIL in text                       # 白名单类别在本地还原
    assert PHONE not in text                   # 高风险类别保持令牌
    assert meta["protection_mode"] == "encrypt"


def token_vault_blob(mw, rid: str, token: str) -> dict:
    return mw.token_vault._records[rid].entries[token]["sealed"]   # noqa: SLF001


def test_ciphertext_is_not_decryptable_without_the_vault_key(encrypt_env, tmp_path):
    """只有「金库 + 派生密钥」能解封:模型/上游拿到的令牌不携带任何可解材料。"""
    mw, client, headers = encrypt_env
    response = chat(client, headers, f"联系 {EMAIL}")
    rid = response.headers["X-CryptoGuard-Request-ID"]
    token = sorted(mw.token_vault.tokens(rid))[0]
    blob = token_vault_blob(mw, rid, token)

    # 令牌本身不含密文:只有 8 字节随机标识
    assert token == f"[CG_ENC_v1_{parse_token(token)['id']}]"
    assert len(parse_token(token)["id"]) == 16

    # 换一把密钥解不开(等价于「攻击者只拿到密文与令牌」的情形)
    from app.keys import Vault

    other = Vault.load_or_init(tmp_path / "attacker", env_path=tmp_path / "atk.env")
    with pytest.raises(Exception):                      # noqa: B017 — 解不开就是结论
        AeadCipher(other.mapping_key).decrypt(blob["iv"], blob["ciphertext"])


# --------------------------------------------------------------------------- #
# 6. 密钥与密文不得出现在审计 / 日志 / 管理接口
# --------------------------------------------------------------------------- #
def test_key_material_and_ciphertext_never_appear_in_surfaces(encrypt_env, admin,
                                                              tmp_path):
    mw, client, headers = encrypt_env
    response = chat(client, headers, f"联系 {EMAIL}")
    rid = response.headers["X-CryptoGuard-Request-ID"]
    token = sorted(mw.token_vault.tokens(rid))[0]
    blob = token_vault_blob(mw, rid, token)

    surfaces = [json.dumps({**client.get("/health").json()}, ensure_ascii=False),
                json.dumps(client.get("/admin/audit", headers=admin).json(),
                           ensure_ascii=False),
                json.dumps(client.get(f"/admin/audit/{rid}", headers=admin).json(),
                           ensure_ascii=False)]
    on_disk = "".join(path.read_text(encoding="utf-8", errors="ignore")
                      for path in (tmp_path / "data-mw").rglob("*") if path.is_file())

    for label, text in (("surface", " ".join(surfaces)), ("disk", on_disk)):
        assert EMAIL not in text, f"{label} 出现了明文"
        assert blob["ciphertext"] not in text, f"{label} 出现了密文"
        assert blob["iv"] not in text, f"{label} 出现了 nonce"
        for version in mw.keyring.versions():
            key_hex = mw.keyring._keys[version].hex()   # noqa: SLF001 — 断言密钥不落盘
            assert key_hex not in text, f"{label} 出现了保护密钥"
            assert key_hex[:32] not in text
    assert mw.vault.mapping_key.hex() not in on_disk
