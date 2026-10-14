"""
并发访问客户端密钥存储的回归测试(第 5 阶段实测发现的既有缺陷)

**发现经过**:`test_stream_boundaries.py::test_concurrent_confirmations_stay_bound_to_their_client`
在全量跑里偶发失败(约 1/25 次),异常是

    app.store.StoreIntegrityError: seg-000001.ndjson 第 8 行 JSON 解析失败

它不是测试本身的问题,而是**客户端密钥存储的读写竞争**:

  - 每个已认证请求结束时会调 `ClientKeyStore.touch()` → `SealedNDJSON.append()`
    (同一客户端 5 分钟内节流一次,所以**不同密钥的并发首请求**会真的并发写);
  - `SealedNDJSON.append()` 内部是 `with path.open("ab") as f: f.write(data)`;
  - 同一时刻另一个请求走 `_latest()` → `read_all()` → 逐行 `json.loads`;
  - 读恰好落在写**写到一半**的瞬间时,最后一行是半截 JSON → 抛 StoreIntegrityError
    (fail-closed)→ 该请求 500。

修复:`SealedNDJSON` 自身**有意**不做互斥(见其模块文档:要求调用方串行化,审计存储
`AuditStore` 就是自带锁的),所以修在**调用方** `ClientKeyStore`(见
`app/middleware/auth.py`):给它加实例级 `RLock`,把 `_latest()` 的读与
`_append_revision()` 的写串行化。**未改动 `app/store.py` 的行为**,fail-closed 语义
原样保留(见下面第二个用例:真正损坏的存储仍然照旧报 corrupt)。

原生竞争窗口很窄(随机跑几十次未必命中),因此第一个用例**确定性地**把一次写拆成两段、
在两段之间放行读者,精确复现「读者看见半截行」的瞬间。
"""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from app.middleware.auth import ClientKeyStore
from app.store import SealedNDJSON
from tests.mw.conftest import reply_text

PROMPT = "并发测试:我的手机号是 13800138000"

#: 拆分点之后的停顿:足够读者线程跑完一次读取
_PAUSE_S = 0.3


class _TornWriter:
    """按需把一次 `write` 拆成两半,中间留出一个可观测的窗口。

    这**不是伪造**:写侧仍是真实的文件写入,只是把现实中本就存在、但极窄的
    「另一个线程恰好在此刻读到半截行」的中间态拉长到可稳定复现。
    """

    def __init__(self, real, on_torn) -> None:
        self._real = real
        self._on_torn = on_torn

    def write(self, data):
        if len(data) > 2:
            half = len(data) // 2
            self._real.write(data[:half])
            self._real.flush()             # 半截行真的落到磁盘上
            self._on_torn()                # ← 现实竞争里「另一个线程恰好在此读」的时刻
            self._real.write(data[half:])
        else:
            self._real.write(data)
        return len(data)

    def __enter__(self) -> "_TornWriter":
        self._real.__enter__()
        return self

    def __exit__(self, *exc) -> object:
        return self._real.__exit__(*exc)

    def __getattr__(self, name):
        return getattr(self._real, name)


@pytest.fixture()
def clients_dir(tmp_path):
    return tmp_path / "clients"


def _install_torn_hook(monkeypatch, target: Path, *, on_append: int,
                       ready: threading.Event):
    """只对 `target` 的第 `on_append` 次追加生效;进入窗口时 set(ready)。"""
    real_open = Path.open
    seen = [0]

    def hook() -> None:
        ready.set()
        threading.Event().wait(_PAUSE_S)   # 保持窗口打开,让读者有机会闯进来

    def patched_open(self, *args, **kwargs):
        handle = real_open(self, *args, **kwargs)
        mode = args[0] if args else kwargs.get("mode", "")
        if self == target and isinstance(mode, str) and "a" in mode:
            seen[0] += 1
            if seen[0] == on_append:
                return _TornWriter(handle, hook)
        return handle

    monkeypatch.setattr(Path, "open", patched_open)
    return seen


# --------------------------------------------------------------------------- #
# 1. `touch()`(写)与 `_latest()`(读)并发:读不得把中间态当成损坏
# --------------------------------------------------------------------------- #
def test_read_during_touch_does_not_report_corruption(clients_dir, monkeypatch):
    """一个请求正在写 `last_used`,另一个请求同时读客户端表:必须成功。"""
    log = SealedNDJSON(clients_dir, "seg", b"k" * 32)
    store = ClientKeyStore(log, b"p" * 32)
    key, _ = store.create("acct")

    torn_ready = threading.Event()
    target = clients_dir / "seg-000001.ndjson"
    # 钩子在 create() 之后才装上,所以计数从 1 开始:这次 touch() 被拆成两段,
    # 制造出「写到一半」的窗口。
    seen = _install_torn_hook(monkeypatch, target, on_append=1, ready=torn_ready)

    failure: list[BaseException] = []

    def writer() -> None:
        store.touch(key.id)            # 在窗口里停住

    thread = threading.Thread(target=writer, daemon=True)
    thread.start()
    assert torn_ready.wait(timeout=10), "没有进入「写到一半」的窗口,用例失去意义"

    try:
        # 竞态里,读侧正是在**缓存刚被另一次写清空**之后去读文件的
        # (`_append_revision` 每写一次就置空缓存),这里把该状态显式摆出来 ——
        # 否则读会命中内存缓存、根本碰不到文件,用例就成了空转。
        store._cache = None            # noqa: SLF001 — 复现的是真实可达的状态
        store.list_clients()           # ← 竞态里另一个请求此刻正在读
    except BaseException as exc:  # noqa: BLE001 — 交给断言报告
        failure.append(exc)
    finally:
        thread.join(timeout=10)

    assert seen[0] >= 1, "钩子没有拦到预期的追加次数,用例失去意义"
    assert failure == [], (
        f"读到了写了一半的行并被判成存储损坏:{failure[0]!r}(这正是偶发 500 的成因)")


# --------------------------------------------------------------------------- #
# 2. 反证:真正损坏的存储仍然照旧 fail-closed
# --------------------------------------------------------------------------- #
def test_sequential_integrity_still_fails_closed(tmp_path):
    """手工写坏一行(模拟崩溃残留)必须**照旧**被判为 corrupt,不能被修没了。"""
    from app.store import StoreIntegrityError

    directory = tmp_path / "logs"
    store = SealedNDJSON(directory, "seg", b"k" * 32)
    store.append({"i": 0})
    with (directory / "seg-000001.ndjson").open("a", encoding="utf-8") as handle:
        handle.write('{"i": 1, "trunc')            # 崩溃残留:半截行

    with pytest.raises(StoreIntegrityError):
        store.read_all()


# --------------------------------------------------------------------------- #
# 3. 端到端:不同密钥的并发首请求全部成功
# --------------------------------------------------------------------------- #
def test_concurrent_requests_from_distinct_clients_all_succeed(client, make_client, auth):
    """每个密钥的**首次**请求都会写一次 `last_used`;并发时必须全部 200。

    不同 client_id 不共享节流窗口,所以它们的 `touch()` 会真的同时落盘 ——
    这正是那个偶发失败的形态。
    """
    boat = [auth] + [make_client(f"race{i}")["auth"] for i in range(1, 7)]
    body = {"model": "mock-chat",
            "messages": [{"role": "user", "content": PROMPT}]}

    def call(headers: dict) -> None:
        response = client.post("/v1/chat/completions", json=body, headers=headers)
        assert response.status_code == 200, response.text
        assert "13800138000" not in reply_text(response)

    with ThreadPoolExecutor(max_workers=len(boat)) as pool:
        list(pool.map(call, boat))
