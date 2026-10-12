"""
keys.py 测试 —— HKDF 派生确定性 + VAULT_KEY 指纹启动规则

覆盖验收标准 ①-⑤ 与启动规则 (a)-(e) 的边界分支：
  (a) 指纹在而 key 缺失/为空 → VaultKeyError（禁止静默生成）
  (b) key 与指纹不符 → VaultKeyError("密钥已变更，历史数据将不可解封")
  (c) key 在而指纹缺失：data/ 有 *.ndjson → 拒绝；全新空目录 → 补写指纹继续
  (d) 两者皆无 → 首次生成，key 落 backend/.env、指纹落 data/vault_key_fingerprint.txt
  (e) 两者皆在且相符 → 正常加载
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from app.keys import Vault, VaultKeyError, fingerprint_of, hkdf_sha256

# 64 位小写十六进制（32 字节）测试密钥
KEY_A = "a1" * 32
KEY_B = "b2" * 32

# 独立参考实现（cryptography HKDF 直接调用）算出的已知答案，防算法/参数漂移
KAT_ROOT = bytes(range(32))
KAT_HKDF = {
    "mapping/v1": "0ac8c63f2120fe150c4dccdf2761d9817ee49b63e472a52d81d8f50a237bf465",
    "reasoning/v1": "4737a6ef417bbd080d101feca1d4f221ff4b3a45fd406f716232b65c6323e61e",
    "chain-mac/v1": "35027b5568168d86f0706745991eca7706fa262ecfbc8d731c8838badabb0777",
    "chain-mac/demo/v1": "f296fa8cf08290735e6fe1cf744a201eb7b493544dd8fcf4d52db38ab3c93e41",
}
KAT_FP = "6557dd5f8bee8679044b9d683404c8141bf094ebc5a0a831eccc58b357ee773f"


@pytest.fixture
def ctx(tmp_path, monkeypatch) -> SimpleNamespace:
    """隔离的 data 目录 + .env 路径；确保 os.environ 不带 VAULT_KEY。"""
    monkeypatch.delenv("VAULT_KEY", raising=False)
    return SimpleNamespace(data_dir=tmp_path / "data", env_path=tmp_path / ".env")


def write_fingerprint(data_dir: Path, key_hex: str) -> str:
    """按规范公式写入指纹文件，返回指纹。"""
    fp = fingerprint_of(bytes.fromhex(key_hex))
    data_dir.mkdir(parents=True, exist_ok=True)
    (data_dir / "vault_key_fingerprint.txt").write_text(fp + "\n", encoding="utf-8")
    return fp


# ---------- ① 派生确定性 ----------

def test_hkdf_deterministic_and_info_separated():
    root = KAT_ROOT
    assert hkdf_sha256(root, "mapping/v1") == hkdf_sha256(root, "mapping/v1")
    infos = ["mapping/v1", "reasoning/v1", "chain-mac/v1", "chain-mac/demo/v1"]
    outs = {info: hkdf_sha256(root, info) for info in infos}
    assert len(set(outs.values())) == len(infos)   # info 不同 → 输出不同
    assert all(len(v) == 32 for v in outs.values())


def test_hkdf_known_answer():
    for info, expected_hex in KAT_HKDF.items():
        assert hkdf_sha256(KAT_ROOT, info).hex() == expected_hex
    # length 参数生效，且满足 HKDF 前缀性质（短输出是长输出的前缀）
    full = hkdf_sha256(KAT_ROOT, "mapping/v1")
    out16 = hkdf_sha256(KAT_ROOT, "mapping/v1", length=16)
    assert len(out16) == 16
    assert out16 == full[:16]


def test_fingerprint_formula_known_answer():
    assert fingerprint_of(KAT_ROOT) == KAT_FP


# ---------- ② 首次启动生成 key + 指纹并落盘 ----------

def test_first_boot_generates_key_and_fingerprint(ctx):
    vault = Vault.load_or_init(ctx.data_dir, env_path=ctx.env_path)
    env_text = ctx.env_path.read_text(encoding="utf-8")
    fp_text = (ctx.data_dir / "vault_key_fingerprint.txt").read_text(encoding="utf-8")
    generated = [ln.split("=", 1)[1] for ln in env_text.splitlines() if ln.startswith("VAULT_KEY=")]
    assert generated and len(generated[0]) == 64
    key_bytes = bytes.fromhex(generated[0])
    assert fp_text.strip() == fingerprint_of(key_bytes)
    assert vault.fingerprint == fingerprint_of(key_bytes)
    # 重启后应从落盘状态恢复同一把 key（规则 e 路径）
    vault2 = Vault.load_or_init(ctx.data_dir, env_path=ctx.env_path)
    assert vault2.fingerprint == vault.fingerprint
    assert vault2.mapping_key == vault.mapping_key
    assert vault2.reasoning_key == vault.reasoning_key
    assert vault2.chain_mac_key == vault.chain_mac_key
    assert vault2.demo_chain_mac_key == vault.demo_chain_mac_key


def test_first_boot_appends_or_replaces_env_line(ctx):
    # .env 已存在但没有 VAULT_KEY 行 → 追加
    ctx.env_path.write_text("MIMO_API_KEY=sk-test\n", encoding="utf-8")
    Vault.load_or_init(ctx.data_dir, env_path=ctx.env_path)
    lines = ctx.env_path.read_text(encoding="utf-8").splitlines()
    assert "MIMO_API_KEY=sk-test" in lines
    assert sum(ln.startswith("VAULT_KEY=") for ln in lines) == 1

    # .env 有空的 VAULT_KEY= 占位行 → 原地替换，不产生重复行
    ctx2_data = ctx.data_dir.parent / "data2"
    ctx2_env = ctx.data_dir.parent / ".env2"
    ctx2_env.write_text("VAULT_KEY=\n", encoding="utf-8")
    Vault.load_or_init(ctx2_data, env_path=ctx2_env)
    lines2 = ctx2_env.read_text(encoding="utf-8").splitlines()
    assert sum(ln.startswith("VAULT_KEY=") for ln in lines2) == 1
    assert len(lines2[0].split("=", 1)[1]) == 64


# ---------- ③ 指纹在而 key 缺失 → 拒绝（禁静默生成） ----------

def test_fingerprint_without_key_refuses(ctx):
    write_fingerprint(ctx.data_dir, KEY_A)
    with pytest.raises(VaultKeyError) as exc:
        Vault.load_or_init(ctx.data_dir, env_path=ctx.env_path)
    assert "禁止静默生成" in str(exc.value)
    # 拒绝后不得改写指纹
    assert (ctx.data_dir / "vault_key_fingerprint.txt").read_text(encoding="utf-8").strip() == fingerprint_of(bytes.fromhex(KEY_A))


def test_fingerprint_without_key_empty_env_refuses(ctx):
    write_fingerprint(ctx.data_dir, KEY_A)
    ctx.env_path.write_text("VAULT_KEY=\n", encoding="utf-8")  # 空值视为缺失
    with pytest.raises(VaultKeyError) as exc:
        Vault.load_or_init(ctx.data_dir, env_path=ctx.env_path)
    assert "禁止静默生成" in str(exc.value)


# ---------- ④ key 与指纹不符 → 拒绝 ----------

def test_key_fingerprint_mismatch_refuses(ctx):
    write_fingerprint(ctx.data_dir, KEY_A)
    ctx.env_path.write_text(f"VAULT_KEY={KEY_B}\n", encoding="utf-8")
    with pytest.raises(VaultKeyError) as exc:
        Vault.load_or_init(ctx.data_dir, env_path=ctx.env_path)
    assert str(exc.value) == "密钥已变更，历史数据将不可解封"


def test_key_fingerprint_mismatch_from_environ(ctx, monkeypatch):
    write_fingerprint(ctx.data_dir, KEY_A)
    monkeypatch.setenv("VAULT_KEY", KEY_B)
    with pytest.raises(VaultKeyError):
        Vault.load_or_init(ctx.data_dir, env_path=ctx.env_path)


def test_environ_takes_precedence_over_env_file(ctx, monkeypatch):
    fp = write_fingerprint(ctx.data_dir, KEY_A)
    ctx.env_path.write_text(f"VAULT_KEY={KEY_B}\n", encoding="utf-8")  # 与 env 不符，应被忽略
    monkeypatch.setenv("VAULT_KEY", KEY_A)
    vault = Vault.load_or_init(ctx.data_dir, env_path=ctx.env_path)
    assert vault.fingerprint == fp


def test_malformed_key_rejected(ctx, monkeypatch):
    for bad in ["xyz", "ab" * 16, "A1" * 32, KEY_A[:-1]]:
        monkeypatch.setenv("VAULT_KEY", bad)
        with pytest.raises(VaultKeyError):
            Vault.load_or_init(ctx.data_dir, env_path=ctx.env_path)
    assert not (ctx.data_dir / "vault_key_fingerprint.txt").exists()


# ---------- 规则 (c) 边界：key 在而指纹缺失 ----------

def test_key_without_fingerprint_and_history_refuses(ctx, monkeypatch):
    ctx.data_dir.mkdir(parents=True)
    (ctx.data_dir / "messages.ndjson").write_text('{"type":"message"}\n', encoding="utf-8")
    monkeypatch.setenv("VAULT_KEY", KEY_A)
    with pytest.raises(VaultKeyError):
        Vault.load_or_init(ctx.data_dir, env_path=ctx.env_path)
    assert not (ctx.data_dir / "vault_key_fingerprint.txt").exists()  # 失败不留指纹


def test_key_without_fingerprint_initializes_when_no_history(ctx, monkeypatch):
    monkeypatch.setenv("VAULT_KEY", KEY_A)
    vault = Vault.load_or_init(ctx.data_dir, env_path=ctx.env_path)  # data 目录不存在 → 创建
    assert vault.fingerprint == fingerprint_of(bytes.fromhex(KEY_A))
    assert (ctx.data_dir / "vault_key_fingerprint.txt").read_text(encoding="utf-8").strip() == vault.fingerprint
    # 非 .ndjson 的杂项文件不视为历史数据
    ctx2_data = ctx.data_dir.parent / "data3"
    ctx2_data.mkdir()
    (ctx2_data / "notes.txt").write_text("x", encoding="utf-8")
    vault2 = Vault.load_or_init(ctx2_data, env_path=ctx.data_dir.parent / ".env3")
    assert vault2.fingerprint == fingerprint_of(bytes.fromhex(KEY_A))


# ---------- ⑤ SEC-STORE 前置：生成物不含明文 key ----------

def test_artifacts_contain_no_plaintext_key(ctx):
    vault = Vault.load_or_init(ctx.data_dir, env_path=ctx.env_path)
    key_hex = ctx.env_path.read_text(encoding="utf-8").split("VAULT_KEY=", 1)[1].strip()
    key_bytes = bytes.fromhex(key_hex)
    fp_text = (ctx.data_dir / "vault_key_fingerprint.txt").read_text(encoding="utf-8")
    assert key_hex not in fp_text                      # 指纹文件不含明文 key
    assert vault.fingerprint != key_hex                # 指纹 ≠ key
    derived = [vault.mapping_key, vault.reasoning_key, vault.chain_mac_key, vault.demo_chain_mac_key]
    assert all(d != key_bytes for d in derived)        # 派生密钥 ≠ 根密钥
    assert len(set(derived)) == 4                      # 四把派生密钥互不相同
    assert all(isinstance(d, bytes) and len(d) == 32 for d in derived)
