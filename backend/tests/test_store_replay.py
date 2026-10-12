"""
Task 4:store.py —— replay_chain 链回放(启动验链)。

验收标准:① append N 条 → replay → verify()=True 且可继续追加
② 持钥攻击者改 payload 并重算 checksum(链断)→ kind="chain_break"
③ 改一字节 → kind="corrupt" ④ 跨轮转段回放全通。
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.crypto.hashchain import HashChain
from app.store import SealedNDJSON, StoreIntegrityError, entry_checksum, replay_chain

MAC_KEY = bytes(range(32))  # 32 字节测试密钥


def make_store(tmp_path: Path, **kw) -> SealedNDJSON:
    return SealedNDJSON(tmp_path / "chain", "seg", MAC_KEY, **kw)


def build_sealed_chain(tmp_path: Path, n: int = 5, **kw):
    """构造 n 条混合(带/不带 message_id)哈希链条目并逐条封缄落盘。"""
    chain = HashChain()
    store = make_store(tmp_path, **kw)
    for i in range(n):
        entry = chain.append(
            "QUERY", f"digest-{i}", f"2026-10-12T00:00:0{i}Z",
            message_id=f"m-{i}" if i % 2 else None,
        )
        store.append(entry)
    return chain, store


def load_rows(seg: Path) -> list[dict]:
    return [json.loads(ln) for ln in seg.read_text(encoding="utf-8").splitlines()]


def rewrite_rows(seg: Path, rows: list[dict]) -> None:
    seg.write_text(
        "\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n",
        encoding="utf-8",
    )


def test_replay_verify_and_appendable(tmp_path):
    """① 追加 N 条 → replay → verify()=True、根一致、可继续追加且仍全绿。"""
    chain, store = build_sealed_chain(tmp_path, n=5)
    replayed = replay_chain(store)
    assert replayed.verify() is True
    assert replayed.root == chain.root
    assert [e["hash"] for e in replayed.entries] == [e["hash"] for e in chain.entries]
    e = replayed.append("USER_OVERRIDE", "digest-x", "2026-10-12T00:00:59Z", message_id="m-x")
    assert e["prev_hash"] == chain.root  # 接着链尾继续
    assert replayed.verify() is True


def test_replay_empty_store(tmp_path):
    """空存储回放得空链,从创世块可继续追加。"""
    store = make_store(tmp_path)
    chain = replay_chain(store)
    assert chain.entries == []
    chain.append("QUERY", "d0", "2026-10-12T00:00:00Z")
    assert chain.verify() is True


def test_payload_tamper_with_recomputed_checksum_breaks_chain(tmp_path):
    """② 改 payload_digest 并重算 entry_checksum(持钥、HMAC 有效)→ chain_break(含段名/行号/index)。"""
    chain, store = build_sealed_chain(tmp_path, n=5)
    seg = store.segment_paths()[0]
    rows = load_rows(seg)
    rows[2]["payload_digest"] = "evil-digest"  # 改内容
    rows[2]["entry_checksum"] = entry_checksum(MAC_KEY, rows[2])  # 重算 HMAC(模拟持钥攻击者)
    rewrite_rows(seg, rows)
    with pytest.raises(StoreIntegrityError) as ei:
        replay_chain(store)
    assert ei.value.kind == "chain_break"
    assert "seg-000001.ndjson" in str(ei.value)
    assert "第 3 行" in str(ei.value)
    assert "index=2" in str(ei.value)


def test_stale_prev_hash_breaks_link(tmp_path):
    """改 prev_hash 并重算 checksum → 前后链接断裂,chain_break 落在该条目 index。"""
    chain, store = build_sealed_chain(tmp_path, n=5)
    seg = store.segment_paths()[0]
    rows = load_rows(seg)
    rows[3]["prev_hash"] = "f" * 64  # 切断与上一条的链接
    rows[3]["entry_checksum"] = entry_checksum(MAC_KEY, rows[3])
    rewrite_rows(seg, rows)
    with pytest.raises(StoreIntegrityError) as ei:
        replay_chain(store)
    assert ei.value.kind == "chain_break"
    assert "index=3" in str(ei.value)


def test_one_byte_tamper_corrupt(tmp_path):
    """③ 改一字节(值内单字符,JSON 仍可解析)→ kind="corrupt"。"""
    chain, store = build_sealed_chain(tmp_path, n=4)
    seg = store.segment_paths()[0]
    raw = seg.read_bytes()
    assert raw.count(b"digest-1") == 1
    tampered = raw.replace(b"digest-1", b"digest-2", 1)  # 单字节差异
    assert len(tampered) == len(raw)
    seg.write_bytes(tampered)
    with pytest.raises(StoreIntegrityError) as ei:
        replay_chain(store)
    assert ei.value.kind == "corrupt"


def test_broken_json_line_corrupt(tmp_path):
    """行损坏到无法解析 JSON 同样 fail-closed:kind="corrupt"。"""
    chain, store = build_sealed_chain(tmp_path, n=3)
    seg = store.segment_paths()[0]
    raw = seg.read_bytes()
    seg.write_bytes(raw.replace(b"{", b"[", 1))  # 首行改坏 JSON
    with pytest.raises(StoreIntegrityError) as ei:
        replay_chain(store)
    assert ei.value.kind == "corrupt"


def test_missing_chain_fields_break(tmp_path):
    """链条目字段缺失(hash/prev_hash/index 等)→ 链无法重建,chain_break。"""
    chain, store = build_sealed_chain(tmp_path, n=3)
    seg = store.segment_paths()[0]
    rows = load_rows(seg)
    del rows[1]["hash"]
    rows[1]["entry_checksum"] = entry_checksum(MAC_KEY, rows[1])
    rewrite_rows(seg, rows)
    with pytest.raises(StoreIntegrityError) as ei:
        replay_chain(store)
    assert ei.value.kind == "chain_break"


def test_replay_across_rotated_segments(tmp_path):
    """④ seg_max_entries=3 跨 3 段(3/3/1)回放全通:verify()=True、顺序完整、可继续追加。"""
    chain, store = build_sealed_chain(tmp_path, n=7, seg_max_entries=3)
    assert len(store.segment_paths()) == 3
    replayed = replay_chain(store)
    assert replayed.verify() is True
    assert len(replayed.entries) == 7
    assert [e["hash"] for e in replayed.entries] == [e["hash"] for e in chain.entries]
    replayed.append("QUERY", "digest-more", "2026-10-12T00:01:00Z")
    assert replayed.verify() is True
