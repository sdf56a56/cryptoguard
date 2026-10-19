"""
Task 3:store.py —— SealedNDJSON 封缄追加(entry_checksum)+ 段轮转。

验收标准:① append→read_all 往返一致 ② 篡改任一行 → StoreIntegrityError(kind="corrupt")
③ seg_max_entries=3 轮转出多段、read_all 跨段有序 ④ 无明文 key 泄漏到文件内容。
"""
from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path

import pytest

from app.canon import canon
from app.store import SealedNDJSON, StoreIntegrityError, entry_checksum

MAC_KEY = bytes(range(32))  # 32 字节测试密钥


def make_store(tmp_path: Path, **kw) -> SealedNDJSON:
    return SealedNDJSON(tmp_path / "chain", "seg", MAC_KEY, **kw)


def test_entry_checksum_formula():
    """entry_checksum = HMAC-SHA256(mac_key, canon(obj 除去 entry_checksum)) 十六进制。"""
    obj = {"a": 1, "b": "文本", "entry_checksum": "old"}
    expected = hmac.new(MAC_KEY, canon({"a": 1, "b": "文本"}), hashlib.sha256).hexdigest()
    assert entry_checksum(MAC_KEY, obj) == expected


def test_append_read_all_roundtrip(tmp_path):
    """① append 返回封缄对象(注入 entry_checksum),read_all 按序逐行还原,往返一致。"""
    store = make_store(tmp_path)
    assert store.read_all() == []  # 空存储
    objs = [
        {"index": 0, "entry_type": "QUERY", "payload_digest": "d0"},
        {"index": 1, "payload": {"nested": [1, 2, {"x": "y"}]}, "文本": "中文"},
    ]
    sealed = [store.append(o) for o in objs]
    for orig, s in zip(objs, sealed):
        assert s["entry_checksum"] == entry_checksum(MAC_KEY, s)  # 注入的校验和
        assert all(s[k] == v for k, v in orig.items())  # 原字段保留
    assert store.read_all() == sealed  # 往返一致(含 entry_checksum)


def test_segment_paths_layout(tmp_path):
    """段命名 {name}-{i:06d}.ndjson 从 1 起;无段时返回 []。"""
    store = make_store(tmp_path)
    assert store.segment_paths() == []
    store.append({"n": 0})
    store.append({"n": 1})
    assert [p.name for p in store.segment_paths()] == ["seg-000001.ndjson"]


def test_reject_path_like_name(tmp_path):
    """段名禁路径分隔符(防写出存储目录外)。"""
    with pytest.raises(ValueError):
        SealedNDJSON(tmp_path / "chain", "../evil", MAC_KEY)


@pytest.mark.parametrize("line_idx", [0, 1, 2])
def test_tamper_any_line_corrupt(tmp_path, line_idx):
    """② 篡改任一行内容(不重算 checksum)→ kind="corrupt",消息含段名与行号。"""
    store = make_store(tmp_path)
    for i in range(3):
        store.append({"i": i, "secret": "payload"})
    seg = store.segment_paths()[0]
    rows = [json.loads(ln) for ln in seg.read_text(encoding="utf-8").splitlines()]
    rows[line_idx]["secret"] = "tampered"  # 篡改内容,校验和失效
    seg.write_text(
        "\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(StoreIntegrityError) as ei:
        store.read_all()
    assert ei.value.kind == "corrupt"
    assert "seg-000001.ndjson" in str(ei.value)
    assert f"第 {line_idx + 1} 行" in str(ei.value)


def test_rotation_by_entries(tmp_path):
    """③ seg_max_entries=3:7 条轮转出 3 段(3/3/1),read_all 跨段有序。"""
    store = make_store(tmp_path, seg_max_entries=3)
    sealed = [store.append({"n": i}) for i in range(7)]
    assert [p.name for p in store.segment_paths()] == [
        "seg-000001.ndjson", "seg-000002.ndjson", "seg-000003.ndjson",
    ]
    counts = [len(p.read_text(encoding="utf-8").splitlines()) for p in store.segment_paths()]
    assert counts == [3, 3, 1]
    assert store.read_all() == sealed  # 跨段有序、往返一致


def test_rotation_by_bytes(tmp_path):
    """轮转触发二:当前段字节数 ≥ seg_max_bytes 同样换段,跨段往返一致。"""
    store = make_store(tmp_path, seg_max_entries=1000, seg_max_bytes=400)
    sealed = [store.append({"n": i, "pad": "x" * 200}) for i in range(6)]
    assert len(store.segment_paths()) >= 2
    assert store.read_all() == sealed


def test_no_key_material_in_files(tmp_path):
    """④ 段文件内容不含 mac_key 明文(原字节或十六进制形态)。"""
    store = make_store(tmp_path, seg_max_entries=2)
    store.append({"payload_digest": "d0", "message": "你好"})
    store.append({"payload_digest": "d1"})
    store.append({"payload_digest": "d2"})
    for p in store.segment_paths():
        raw = p.read_bytes()
        assert MAC_KEY not in raw
        assert MAC_KEY.hex().encode("ascii") not in raw
        assert MAC_KEY.hex().upper().encode("ascii") not in raw
