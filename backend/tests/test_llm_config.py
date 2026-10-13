"""
LLMConfigStore:加密落盘 / 掩码 / 校验 / 清空 / 环境回退(第六阶段安全要求)。

验收要点:
  ① API Key 明文绝不落盘(文件内不含密钥串)
  ② 换新实例仍能解密读回(持久化有效)
  ③ 对外视图只给掩码与布尔,不含完整密钥
  ④ 非法 Base URL / 空 Model / 未知 provider → LLMConfigError,不落盘
  ⑤ api_key=None 保持原密钥;api_key="" 显式清空
  ⑥ 无落盘文件时回退环境变量密钥
"""
from __future__ import annotations

import json

import pytest

from app.crypto.aead import AeadCipher
from app.llm_config import (DEFAULT_PROVIDER, LLMConfigError, LLMConfigStore,
                            mask_key)

KEY = "sk-abcdefghijklmnopqrstuvwxyz012345"


def make_store(tmp_path, env_api_key: str = "") -> LLMConfigStore:
    return LLMConfigStore(tmp_path, AeadCipher(b"k" * 32), env_api_key=env_api_key)


def save_default(store: LLMConfigStore, api_key: str | None = KEY):
    return store.save(provider="deepseek", base_url="https://api.deepseek.com/v1",
                      model="deepseek-chat", display_name="DeepSeek Chat",
                      api_key=api_key)


# ---------- ① 明文不落盘 ----------

def test_api_key_never_written_in_plaintext(tmp_path):
    store = make_store(tmp_path)
    save_default(store)

    raw = store.path.read_text(encoding="utf-8")

    assert KEY not in raw                      # 明文密钥不在文件里
    assert "api_key_enc" in raw
    blob = json.loads(raw)["api_key_enc"]
    assert blob["iv"] and blob["ciphertext"]   # 密文形态存在


def test_saved_config_reports_key_present(tmp_path):
    cfg = save_default(make_store(tmp_path))
    assert cfg.has_key is True
    assert cfg.configured is True


# ---------- ② 持久化:换实例仍可读回 ----------

def test_new_store_instance_decrypts_same_key(tmp_path):
    save_default(make_store(tmp_path))

    reloaded = make_store(tmp_path).load()

    assert reloaded.api_key == KEY
    assert reloaded.model == "deepseek-chat"
    assert reloaded.base_url == "https://api.deepseek.com/v1"
    assert reloaded.display_name == "DeepSeek Chat"


def test_wrong_master_key_yields_no_key_not_crash(tmp_path):
    """换 VAULT_KEY(密文无法解密)时按「无密钥」处理,不抛异常、不复活旧钥。"""
    save_default(make_store(tmp_path))

    other = LLMConfigStore(tmp_path, AeadCipher(b"z" * 32)).load()

    assert other.api_key == ""
    assert other.has_key is False


# ---------- ③ 对外只给掩码 ----------

def test_public_view_hides_full_key(tmp_path):
    view = save_default(make_store(tmp_path)).public_view()

    assert view["has_key"] is True
    assert view["key_masked"] == mask_key(KEY)
    assert KEY not in json.dumps(view)         # 整个视图序列化后也不含密钥
    assert "api_key" not in view               # 字段本身不出现


def test_mask_key_keeps_prefix_and_suffix():
    assert mask_key("sk-1234567890abcdef") == "sk-***cdef"
    assert mask_key("short") == "*****"        # 过短全掩码
    assert mask_key("") == ""


# ---------- ④ 校验失败不落盘 ----------

@pytest.mark.parametrize("kwargs", [
    {"base_url": "ftp://x.com", "model": "m"},          # 非 http(s)
    {"base_url": "not-a-url", "model": "m"},            # 无主机名
    {"base_url": "https://api.deepseek.com/v1", "model": ""},   # 空 model
    {"base_url": "https://api.deepseek.com/v1?x=1", "model": "m"},  # 带 query
])
def test_invalid_config_rejected_without_writing(tmp_path, kwargs):
    store = make_store(tmp_path)
    with pytest.raises(LLMConfigError):
        store.save(provider=DEFAULT_PROVIDER, api_key=KEY, display_name="", **kwargs)
    assert not store.path.exists()


def test_unknown_provider_rejected(tmp_path):
    store = make_store(tmp_path)
    with pytest.raises(LLMConfigError):
        store.save(provider="nope", base_url="https://x.com", model="m",
                   api_key=KEY)
    assert not store.path.exists()


# ---------- ⑤ 密钥更新语义 ----------

def test_none_keeps_existing_key(tmp_path):
    store = make_store(tmp_path)
    save_default(store)

    cfg = store.save(provider="deepseek", base_url="https://api.deepseek.com/v1",
                     model="deepseek-reasoner", api_key=None)

    assert cfg.api_key == KEY                  # 未改动密钥
    assert cfg.model == "deepseek-reasoner"    # 其余字段已更新


def test_empty_string_clears_key(tmp_path):
    store = make_store(tmp_path)
    save_default(store)

    cfg = store.save(provider="deepseek", base_url="https://api.deepseek.com/v1",
                     model="deepseek-chat", api_key="")

    assert cfg.api_key == ""
    assert make_store(tmp_path).load().api_key == ""     # 清空已落盘


def test_clear_key_keeps_endpoint_fields(tmp_path):
    store = make_store(tmp_path)
    save_default(store)

    cfg = store.clear_key()

    assert cfg.api_key == ""
    assert cfg.base_url == "https://api.deepseek.com/v1"  # 端点保留
    assert cfg.model == "deepseek-chat"


# ---------- ⑥ 环境变量回退 ----------

def test_env_fallback_used_when_no_file(tmp_path, monkeypatch):
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    monkeypatch.delenv("MIMO_API_KEY", raising=False)

    cfg = make_store(tmp_path, env_api_key="sk-from-dotenv").load()

    assert cfg.api_key == "sk-from-dotenv"
    assert cfg.configured is True
    assert make_store(tmp_path).persisted is False        # 未被自动写盘


def test_os_environ_wins_over_env_file_fallback(tmp_path, monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-from-environ")
    cfg = make_store(tmp_path, env_api_key="sk-from-dotenv").load()
    assert cfg.api_key == "sk-from-environ"


def test_persisted_config_wins_over_env(tmp_path, monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-from-environ")
    store = make_store(tmp_path, env_api_key="sk-from-dotenv")
    save_default(store)

    assert make_store(tmp_path, env_api_key="sk-from-dotenv").load().api_key == KEY


# ---------- 损坏文件容错 ----------

def test_corrupt_file_falls_back_to_defaults(tmp_path):
    store = make_store(tmp_path)
    store.path.write_text("{ not json", encoding="utf-8")

    cfg = store.load()

    assert cfg.api_key == ""                   # 不崩溃,按未配置处理
    assert cfg.base_url                       # 回落官方默认 Base URL
