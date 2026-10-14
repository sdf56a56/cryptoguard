"""
第 4 阶段 · 任务 6 —— 流式边界与并发隔离

流式是本项目最容易出事的地方:令牌会被切成两半、UTF-8 多字节字符会跨网络块、
SSE 事件边界会落在半截 JSON 上、上游会中途断流、客户端会突然挂断。本文件逐条
验证这些边界,并且**只用真实 HTTP + 真实分块**来构造它们(见 SseUpstream)。

本文件验证:
  1. 敏感令牌跨 SSE 块/网络块被切开 → 仍然完整识别与还原,且任何一次下发都
     不含半截令牌(半截令牌既泄露形态,也让客户端无法处理);
  2. UTF-8 多字节字符跨网络块被切开 → 文本不被损坏(不出现 U+FFFD);
  3. SSE 事件边界:整帧被切开、坏帧、usage 帧、结束标记 [DONE] 的处理;
  4. 有界缓冲:持留窗口不得超过 MAX_TOKEN_LEN,响应侧检测窗口有界且不重复计数;
  5. 上游中途断流:如实标注「不完整」,不重试、不重复输出、不误还原;
  6. 取消/断开:上游生成器被关闭(停止继续计费),resources 有界;
  7. 并发流式请求之间映射/还原互不串味;并发的确认释放互不越权。

诚实边界:
  - 持留带来的代价是真实的:首个字节最多多等一个令牌长度(MAX_TOKEN_LEN=96 字符),
    这是「不吐半截令牌」的必然代价,不是缺陷;
  - `TestClient` 的断开语义与真实 ASGI 服务器不完全一致,因此「断开释放资源」
    一条以**泵/生成器**的确定性单测为准(见 test_cancel_closes_...);
  - 本文件不验证真实厂商的流式分块行为(未执行,见 test_real_http_e2e.py 的说明)。
"""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from app.keys import Vault
from app.middleware.config import ProviderSettings
from app.middleware.pipeline import _ResponseScanner
from app.middleware.protection import (MODE_PLACEHOLDER, TokenVault, find_tokens,
                                       protect_text)
from app.middleware.recognizers import detect_all
from app.middleware.restore import (MAX_TOKEN_LEN, RESTORE_CATEGORIES,
                                    RestorePolicy, StreamRestorer)
from app.middleware.routes import _StreamPump
from tests.mw.conftest import FAKE_UPSTREAM_KEY, UPSTREAM_KEY_ENV
from tests.mw.test_real_http_e2e import _received_text
from tests.mw.test_upstream_provider import FakeUpstream

PHONE = "13800138000"
EMAIL = "zhangsan@corp.com.cn"
PROMPT = f"我的手机号是 {PHONE},邮箱是 {EMAIL}"

MODES = ("placeholder", "token", "encrypt")
TOKEN_MARKER = {"placeholder": "[PHONE_001]",
                "token": "[CG_TOKEN_",
                "encrypt": "[CG_ENC_v1_"}


# --------------------------------------------------------------------------- #
# 上游:把回显内容切碎到任意粒度
# --------------------------------------------------------------------------- #
def _sse_body(text: str, *, per_char: bool = True, usage: bool = False,
              done: bool = True, mark_finish: bool = True) -> bytes:
    """把一段文本编成 SSE(可以逐字符一帧,用来制造令牌跨帧)。"""
    if per_char:
        frames = [{"choices": [{"index": 0, "delta": {"content": ch}}]}
                  for ch in text]
    else:
        frames = [{"choices": [{"index": 0, "delta": {"content": text}}]}]
    if frames and mark_finish:
        frames[-1]["choices"][0]["finish_reason"] = "stop"
    out = "".join(f"data: {json.dumps(f, ensure_ascii=False)}\n\n" for f in frames)
    if usage:
        out += f"data: {json.dumps({'choices': [], 'usage': {'total_tokens': 9}})}\n\n"
    if done:
        out += "data: [DONE]\n\n"
    return out.encode("utf-8")


def _slice(body: bytes, mode: str, size: int) -> list[bytes]:
    """把整段 SSE 字节按指定粒度切成多次网络写入。"""
    if mode == "byte":                       # 固定字节数 → 必然切开帧与多字节字符
        return [body[i:i + size] for i in range(0, len(body), size)]
    if mode == "half-frame":                 # 每帧再切成两半 → 切开事件边界
        parts = [p + b"\n\n" for p in body.split(b"\n\n")[:-1]]
        out: list[bytes] = []
        for part in parts:
            half = max(1, len(part) // 2)
            out.extend([part[:half], part[half:]])
        return out
    parts = [p + b"\n\n" for p in body.split(b"\n\n")[:-1]]   # 一帧一次写入
    return parts or [body]


class SseUpstream(FakeUpstream):
    """按脚本分裂 SSE 的回声上游(真实 socket、真实分块)。"""

    chunk_mode: str = "frame"
    chunk_bytes: int = 8
    per_char: bool = True
    emit_usage: bool = False
    omit_done: bool = False
    mark_finish: bool = True
    noise_prefix: bytes = b""
    #: 非 None 时改用这段文本作答(模拟「上游自己把敏感原文说出来」)
    override_text: str | None = None

    def _next(self) -> dict:  # noqa: D102 — 语义见类文档
        with self._lock:
            raw = self.requests[-1]["body"] if self.requests else b""
        try:
            payload = json.loads(raw)
        except Exception:  # noqa: BLE001
            payload = {}
        text = _received_text(payload)
        if self.override_text is not None:
            text = self.override_text
        if not payload.get("stream"):
            from tests.mw.test_upstream_provider import completion_body

            return {"status": 200, "body": completion_body(text)}
        body = _sse_body(text, per_char=self.per_char,
                         usage=self.emit_usage, done=not self.omit_done,
                         mark_finish=self.mark_finish)
        chunks = _slice(body, self.chunk_mode, self.chunk_bytes)
        if self.noise_prefix:
            chunks = [self.noise_prefix, *chunks]
        return {"status": 200, "chunks": chunks}


@pytest.fixture()
def upstream():
    server = SseUpstream()
    try:
        yield server
    finally:
        server.close()


@pytest.fixture()
def http_env(upstream, make_mw, monkeypatch):
    """真上游中间件;mode 决定保护模式,其余关键字透传给 ProviderSettings。"""
    monkeypatch.setenv(UPSTREAM_KEY_ENV, FAKE_UPSTREAM_KEY)

    def make(*, mode: str = "placeholder", subdir: str = "", **provider_kw):
        kwargs = dict(
            name="fake", type="openai-compatible", base_url=upstream.base_url,
            api_key_env=UPSTREAM_KEY_ENV, models=("mock-chat",),
            timeout_connect=2.0, timeout_read=5.0, max_retries=0)
        kwargs.update(provider_kw)
        mw, client, key = make_mw(protection_mode=mode,
                                  data_subdir=subdir or f"data-{mode}",
                                  providers=(ProviderSettings(**kwargs),),
                                  default_provider="fake")
        return mw, client, {"Authorization": f"Bearer {key}"}, upstream

    return make


# --------------------------------------------------------------------------- #
# 辅助
# --------------------------------------------------------------------------- #
def _chat(client, headers, text=PROMPT, **extra):
    body = {"model": "mock-chat", "messages": [{"role": "user", "content": text}]}
    body.update(extra)
    return client.post("/v1/chat/completions", json=body, headers=headers)


def _frames(raw: str) -> list:
    """把 SSE 正文解析成帧列表(JSON 对象或字符串 "[DONE]")。"""
    out: list = []
    for line in raw.splitlines():
        if not line.startswith("data:"):
            continue
        payload = line[len("data:"):].strip()
        if not payload:
            continue
        out.append("[DONE]" if payload == "[DONE]" else json.loads(payload))
    return out


def _deltas(raw: str) -> list[str]:
    out = []
    for frame in _frames(raw):
        if frame == "[DONE]":
            continue
        for choice in frame.get("choices") or []:
            content = (choice.get("delta") or {}).get("content")
            if content:
                out.append(content)
    return out


def _text_of(raw: str) -> str:
    return "".join(_deltas(raw))


def _assert_no_torn_token(deltas: list[str]) -> None:
    """任何一次下发都不得含半截令牌:每个 `[`/`]` 都必须属于一个完整令牌。"""
    for delta in deltas:
        assert delta.count("[") == len(find_tokens(delta)), f"出现半截令牌:{delta!r}"
        assert delta.count("]") == len(find_tokens(delta)), f"出现半截令牌:{delta!r}"


def _token_vault(tmp_path, name: str = "v") -> TokenVault:
    return TokenVault(Vault.load_or_init(tmp_path / name), ttl_s=600.0,
                      max_requests=8)


# --------------------------------------------------------------------------- #
# 1. 令牌跨块:真实 HTTP 分块 + 逐字符 SSE 帧
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("chunk_mode", ("frame", "half-frame", "byte"))
def test_token_split_across_chunks_is_reassembled(http_env, mode, chunk_mode):
    mw, client, headers, upstream = http_env(mode=mode, subdir=f"d-{mode}-{chunk_mode}")
    upstream.chunk_mode = chunk_mode

    response = _chat(client, headers, stream=True)
    assert response.status_code == 200, response.text
    deltas = _deltas(response.text)
    assert deltas, "流式响应没有任何增量"

    _assert_no_torn_token(deltas)
    text = "".join(deltas)
    assert EMAIL in text, f"{mode}/{chunk_mode}:跨块令牌未被还原"
    assert PHONE not in text, f"{mode}/{chunk_mode}:高危原文出现在流里"
    assert TOKEN_MARKER[mode] in text        # 被扣留的值以完整令牌形态下发

    # 上游收到的仍然只有令牌
    sent = upstream.requests[-1]["body"].decode("utf-8")
    assert PHONE not in sent and EMAIL not in sent


def test_multibyte_characters_survive_byte_level_splitting(http_env):
    """UTF-8 多字节字符跨网络块被切开:不得出现替换字符或截断。"""
    mw, client, headers, upstream = http_env(mode="token", subdir="data-utf8")
    upstream.chunk_mode = "byte"
    upstream.chunk_bytes = 5                 # 5 字节必然切断 3/4 字节的汉字与 emoji

    response = _chat(client, headers, "说明:中文😀与代理对 𝄞 混排,邮箱是 "
                                      f"{EMAIL}", stream=True)
    assert response.status_code == 200, response.text
    text = _text_of(response.text)
    assert "�" not in text, "出现 U+FFFD:多字节字符被撕断"
    assert "中文😀与代理对 𝄞 混排" in text
    assert EMAIL in text


def test_upstream_receives_intact_multibyte_over_the_wire(http_env):
    """出站方向同样不能被撕断:上游收到的 UTF-8 必须能被完整解码。"""
    mw, client, headers, upstream = http_env(mode="token", subdir="data-utf8-out")
    response = _chat(client, headers, "中文😀 𝄞 " + EMAIL)
    assert response.status_code == 200

    raw = upstream.requests[-1]["body"]
    decoded = raw.decode("utf-8")            # 解码失败会直接抛错(字节级被撕断)
    payload = json.loads(decoded)            # 报文本身必须是合法 JSON
    # 出站 JSON 可能用 \uXXXX 转义(ensure_ascii),所以断言解析**之后**的文本:
    # 多字节字符必须逐个完好,不能被按字节切碎成 U+FFFD。
    sent_text = payload["messages"][-1]["content"]
    assert "中文😀 𝄞" in sent_text
    assert "�" not in sent_text         # 无替换字符 = 没有被撕断
    assert EMAIL not in sent_text and "[CG_TOKEN_" in sent_text


# --------------------------------------------------------------------------- #
# 2. SSE 事件边界 / usage / 结束标记
# --------------------------------------------------------------------------- #
def test_final_frames_carry_usage_meta_and_done(http_env):
    mw, client, headers, upstream = http_env(mode="token", subdir="data-final")
    upstream.per_char = False
    upstream.emit_usage = True

    response = _chat(client, headers, stream=True)
    frames = _frames(response.text)
    assert frames[-1] == "[DONE]"                     # 结束标记是最后一帧
    finish = frames[-2]
    assert finish["choices"][0]["finish_reason"] == "stop"
    assert finish["usage"] == {"total_tokens": 9}
    meta = finish["cryptoguard"]
    assert meta["stream"]["complete"] is True
    assert meta["digest"]["response"] and meta["digest"]["request"]
    assert meta["protection_mode"] == "token"
    # 客户端侧:白名单类别被还原(明文只回到签发它的那个客户端),高风险仍为令牌
    assert EMAIL in response.text
    assert PHONE not in response.text
    assert "[CG_ENC_" not in response.text and "[CG_TOKEN_" in response.text


def test_usage_frame_is_forwarded_as_its_own_event(http_env):
    mw, client, headers, upstream = http_env(mode="token", subdir="data-usage")
    upstream.per_char = False
    upstream.emit_usage = True

    frames = _frames(_chat(client, headers, stream=True).text)
    usage_frames = [f for f in frames
                    if f != "[DONE]" and f.get("usage") and not f.get("cryptoguard")]
    assert usage_frames, "usage 帧被吞掉了"


def test_broken_and_unknown_frames_do_not_break_the_stream(http_env):
    """坏帧/注释行混进流里时不得中断整条流,也不得让还原逻辑错位。"""
    mw, client, headers, upstream = http_env(mode="token", subdir="data-broken")
    upstream.per_char = False
    upstream.chunk_mode = "half-frame"
    upstream.noise_prefix = b": keep-alive\n\ndata: {oops\n\ndata: \n\n"

    response = _chat(client, headers, stream=True)
    assert response.status_code == 200
    deltas = _deltas(response.text)
    _assert_no_torn_token(deltas)
    text = "".join(deltas)
    assert EMAIL in text                     # 噪声没有让还原错位
    assert PHONE not in text
    assert response.text.rstrip().endswith("data: [DONE]")


# --------------------------------------------------------------------------- #
# 3. 有界缓冲:持留窗口与检测窗口
# --------------------------------------------------------------------------- #
def test_restorer_holds_at_most_one_token_length(tmp_path):
    restorer = StreamRestorer("cg-x", _token_vault(tmp_path),
                              RestorePolicy(mode=RESTORE_CATEGORIES,
                                            categories=("EMAIL",)))
    assert restorer.feed("[" + "x" * (MAX_TOKEN_LEN - 1)) == ""   # 持留等待 `]`
    assert len(restorer._buffer) == MAX_TOKEN_LEN                 # noqa: SLF001

    released = restorer.feed("x" * 200)          # 超过上限 → 判定不是令牌,立即放行
    assert len(released) >= 200, "超过持留上限后必须放行,不能无界缓冲"
    assert len(restorer._buffer) <= MAX_TOKEN_LEN + 1             # noqa: SLF001


def test_flush_releases_the_remainder_without_guessing(tmp_path):
    """流结束时若仍持留半截令牌:原样输出,**不做任何还原**(不猜)。"""
    restorer = StreamRestorer("cg-x", _token_vault(tmp_path),
                              RestorePolicy(mode=RESTORE_CATEGORIES,
                                            categories=("EMAIL",)))
    # 最后一个可能成为令牌起点的 `[` 之前的内容可以立即下发
    assert restorer.feed("联系 [EMAIL_0") == "联系 "
    assert restorer._buffer == "[EMAIL_0"           # noqa: SLF001 — 持留部分
    # 流到此处结束:半截令牌原样吐出(它是明文,不是映射里的令牌),绝不猜测还原
    assert restorer.flush() == "[EMAIL_0"
    view = restorer.view()
    assert view["restored_count"] == 0 and view["foreign_token_count"] == 0


def test_no_partial_token_is_emitted_when_fed_char_by_char(tmp_path):
    token_vault = _token_vault(tmp_path)
    result = protect_text(f"邮箱 {EMAIL}", detect_all(f"邮箱 {EMAIL}",
                                                      mode=MODE_PLACEHOLDER),
                          mode=MODE_PLACEHOLDER)
    token_vault.store("cg-x", result.entries)
    token = result.entries[0].token
    assert token == "[EMAIL_001]"

    restorer = StreamRestorer("cg-x", token_vault,
                              RestorePolicy(mode=RESTORE_CATEGORIES,
                                            categories=("EMAIL",)))
    deltas = [restorer.feed(ch) for ch in f"看 {token} 完"]
    deltas.append(restorer.flush())
    emitted = [d for d in deltas if d]
    _assert_no_torn_token(emitted)
    assert "".join(emitted) == f"看 {EMAIL} 完"


def test_response_scanner_window_is_bounded_and_counts_once(mw):
    """响应侧检测:窗口有界;跨块的敏感值被完整识别且只计一次。"""
    scanner = _ResponseScanner(mw.pipeline, None, buffer_chars=16)
    for char in f"编号是 {PHONE} 完毕,再见再见再见再见再见再见再见":
        scanner.feed(char)
    scanner.close()

    view = scanner.view()
    assert view["window_chars"] == 16                # 有界:与流长无关(下限 16)
    assert view["by_type"].get("PHONE") == 1, "跨块敏感值被漏计或重复计数"
    assert view["total"] >= 1
    assert PHONE not in json.dumps(view, ensure_ascii=False)


def test_response_scan_cannot_be_evaded_by_one_char_frames(http_env):
    """回归(P0):上游把响应切成「一帧一个字符」时,响应侧审计仍须识别到敏感值。

    这不是学术边界 —— 只要上游把输出切得比敏感值还碎,旧实现(仅对稳定区计数)
    的稳定区长度恒为 1,于是**任何**值都永远「未定稿」,响应侧检测被整体规避。
    上游因此可以靠分块方式关掉本中间件的审计能力。修复后:
      - 命中只要拿到 1 个字符的后续上下文就结算,跨多少帧都能被识别;
      - 仍按绝对位置去重,同一处命中只计一次。
    同时如实记录边界:响应侧检测**只统计不回写**,上游若自己吐原文,客户端仍会
    看到它 —— 本中间件不会篡改模型输出,这一点不因本修复而改变。
    """
    mw, client, headers, upstream = http_env(mode="token", subdir="data-scan-evade")
    upstream.per_char = True                          # 一帧一个字符
    upstream.override_text = f"pong: {PHONE}"         # 上游自己把原文说了出来

    response = _chat(client, headers, stream=True)
    assert response.status_code == 200, response.text
    frames = _frames(response.text)
    scan = frames[-2]["cryptoguard"]["response_scan"]   # 倒数第二帧:结束帧
    assert scan["by_type"].get("PHONE") == 1, "逐字符分块让响应侧审计漏计了"
    assert scan["total"] == 1, "同一处命中被重复计数"
    assert PHONE not in json.dumps(scan, ensure_ascii=False)
    assert PHONE not in json.dumps(
        mw.audit.get(response.headers["X-CryptoGuard-Request-ID"]),
        ensure_ascii=False)


# --------------------------------------------------------------------------- #
# 4. 断流与取消
# --------------------------------------------------------------------------- #
def test_truncated_stream_is_marked_incomplete_and_not_duplicated(http_env):
    mw, client, headers, upstream = http_env(mode="token", subdir="data-trunc")
    upstream.per_char = False
    upstream.mark_finish = False
    upstream.omit_done = True                # 上游没发结束标记也没发 [DONE] 就断流

    response = _chat(client, headers, stream=True)
    frames = _frames(response.text)
    finish = frames[-2]
    meta = finish["cryptoguard"]
    assert meta["stream"]["complete"] is False
    assert "不完整" in meta["stream"]["note"]
    text = _text_of(response.text)
    assert text.count(EMAIL) == 1, "断流后出现重复内容"
    assert mw.audit.get(response.headers["X-CryptoGuard-Request-ID"])[
        "outcome"] == "incomplete"
    assert len(upstream.requests) == 1, "已产出内容后不得重试(会重复计费)"


def test_cancel_closes_the_upstream_generator():
    """取消(客户端断开)必须关闭上游生成器 —— 这是「停止继续计费」的机制。"""
    state = {"closed": False, "produced": 0}

    def gen():
        try:
            for index in range(10000):
                state["produced"] += 1
                yield index
                time.sleep(0.005)
        finally:
            state["closed"] = True

    pump = _StreamPump(gen())
    assert pump.next() == ("item", 0)
    pump.cancel()
    for _ in range(200):                     # 最多等 4 秒
        if state["closed"]:
            break
        time.sleep(0.02)
    assert state["closed"], "取消后上游生成器仍未被关闭(会继续读到流末尾)"
    produced = state["produced"]
    time.sleep(0.1)
    assert state["produced"] <= produced + 2, "取消后仍在继续向上游索取数据"


# --------------------------------------------------------------------------- #
# 5. 并发隔离
# --------------------------------------------------------------------------- #
def test_concurrent_streams_do_not_cross_restore(http_env):
    mw, client, headers, upstream = http_env(mode="token", subdir="data-conc")
    emails = [f"user{index}@corp.com.cn" for index in range(6)]

    def run(email: str) -> str:
        response = _chat(client, headers, f"联系 {email}", stream=True)
        assert response.status_code == 200, response.text
        return _text_of(response.text)

    with ThreadPoolExecutor(max_workers=len(emails)) as pool:
        texts = list(pool.map(run, emails))

    for own, text in zip(emails, texts):
        present = [email for email in emails if email in text]
        assert present == [own], f"并发流之间串味:{present}"


def test_concurrent_streams_never_expose_other_requests_tokens(http_env):
    """并发下「本请求的令牌」必须只在本请求可还原:金库按 request_id 分区。"""
    mw, client, headers, upstream = http_env(mode="token", subdir="data-conc2")

    def run(index: int) -> tuple[str, str]:
        response = _chat(client, headers, f"联系 user{index}@corp.com.cn",
                         stream=True)
        rid = response.headers["X-CryptoGuard-Request-ID"]
        token = sorted(mw.token_vault.tokens(rid))[0]
        return rid, token

    with ThreadPoolExecutor(max_workers=4) as pool:
        pairs = list(pool.map(run, range(4)))

    assert len({rid for rid, _ in pairs}) == 4          # 请求互不相同
    assert len({token for _, token in pairs}) == 4      # 令牌互不相同
    for rid, token in pairs:
        others = [other for other_rid, other in pairs if other_rid != rid]
        assert token not in others
        assert mw.token_vault.tokens(rid) == {token}


def test_concurrent_confirmations_stay_bound_to_their_client(http_env, make_client,
                                                             admin):
    """并发确认:每个客户端只拿得到自己那次请求的值。"""
    from tests.mw.test_confirmations import _approve, _confirmation, _release

    mw, client, headers, upstream = http_env(mode="token", subdir="data-conc3")
    boat = [headers] + [make_client(f"cc{index}")["auth"] for index in range(1, 4)]
    body = {"model": "mock-chat", "messages": [
        {"role": "user", "content": f"我的手机号是 {PHONE}"}]}

    def run(auth: dict) -> dict:
        response = client.post("/v1/chat/completions", json=body, headers=auth)
        assert response.status_code == 200, response.text
        rid = response.headers["X-CryptoGuard-Request-ID"]
        token = sorted(mw.token_vault.tokens(rid))[0]
        cid = _confirmation(client, auth, rid, [token]).json()["confirmation_id"]
        assert _approve(client, admin, cid).status_code == 200
        return _release(client, auth, cid).json()

    with ThreadPoolExecutor(max_workers=len(boat)) as pool:
        results = list(pool.map(run, boat))

    for payload in results:
        assert payload["status"] == "consumed"
        assert list(payload["secrets"].values()) == [PHONE]   # 各自拿到各自的值
        assert payload["released_count"] == 1
