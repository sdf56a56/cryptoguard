"""
CryptoGuard —— 面向大模型应用的敏感数据加密与防泄漏平台

FastAPI 主应用：提供密码学 API + 托管前端静态资源。
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import os
import queue
import time
from contextlib import asynccontextmanager

from fastapi import (FastAPI, File, Form, HTTPException, Request, UploadFile,
                     WebSocket, WebSocketDisconnect)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, StreamingResponse

from .acceptance import (degrade_demo, replay_report, run_golden,
                         scan_plaintext_leaks)
from .bootstrap import build_chat_service, default_data_dir
from .canon import h_hex
from .concurrency import run_sync
from .crypto.merkle import MerkleTree
from .files import evidence_bundle
from .gateway import GatewayReject, aggregate, validate_directive
from .keys import VaultKeyError
from .llm import LLMFailure
from .proxy import guard
from .sandbox import ATTACKS, AttackSandbox
from .schemas import (
    DetectRequest, QueryRequest, SSESearchRequest, HEStatsRequest, PolicyUpdate,
    QueryV2Request, AttackInjectRequest, ComputeRequest,
    ChatSessionCreate, ChatMessageRequest, PreimageVerifyRequest,
    DegradeRequest,
)
from .store import StoreIntegrityError

logger = logging.getLogger(__name__)


@asynccontextmanager
async def _lifespan(app_: FastAPI):
    """启动接线(Task 11):装配 ChatService 挂 app.state.chat。

    VaultKeyError/StoreIntegrityError → logger.critical + 终止启动(fail-fast,
    不带病服务);CG_NO_BOOT=1 时跳过装配(测试直挂 app.state.chat)。
    """
    if os.environ.get("CG_NO_BOOT") == "1":
        yield
        return
    try:
        app_.state.chat = build_chat_service(default_data_dir())
    except (VaultKeyError, StoreIntegrityError):
        logger.critical("启动失败:信任根/存储回放校验未通过,拒绝带病服务",
                        exc_info=True)
        raise
    yield


app = FastAPI(title="CryptoGuard", version="1.0.0", lifespan=_lifespan)

# 模块级唯一攻击沙箱(R9/SEC-ISO):attack/reset 都走它
sandbox = AttackSandbox(guard)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "CryptoGuard", "time": time.time()}


@app.post("/api/detect")
def detect(req: DetectRequest):
    from .detection import detect_sensitive
    result = detect_sensitive(req.text, mode=req.mode or guard.policy["mode"])
    return result.to_dict()


@app.get("/api/entities")
def entities():
    """实体类型目录（对标 Presidio Recognizer Catalog）。"""
    from .detection import ENTITY_META
    policy = guard.get_policy()
    return {
        "types": [
            {**meta, "type": t, "enabled": t in policy["enabled_types"]}
            for t, meta in ENTITY_META.items()
        ],
        "policy": policy,
    }


@app.get("/api/policy")
def get_policy():
    return guard.get_policy()


@app.post("/api/policy")
def set_policy(req: PolicyUpdate):
    try:
        return guard.set_policy(req.mode, req.enabled_types)
    except ValueError as e:
        return {"error": str(e)}


@app.get("/api/stats")
def stats():
    return guard.get_stats()


@app.post("/api/proxy/query")
def proxy_query(req: QueryRequest):
    result = guard.query(
        req.text,
        scenario=req.scenario,
        attributes=req.attributes,
        attack=req.attack,
    )
    return result


# ------------------------------------------------------------------ #
# CG/2.0 路由(Task 14):CPU 密集处理器经 run_in_executor(run_sync)
# ------------------------------------------------------------------ #

@app.post("/api/proxy/query2")
async def proxy_query2(req: QueryV2Request):
    """CG/2.0 主入口(裁定 R7):校验 → run_in_executor(query_v2)。"""
    files = None
    if req.files:
        files = [{"filename": f.filename,
                  "data": base64.b64decode(f.content_b64)} for f in req.files]
    try:
        result = await run_sync(guard.query_v2, req.text, files,
                                req.overrides, req.scenario, req.directive)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return result


@app.post("/api/files/upload")
async def files_upload(file: UploadFile = File(...),
                       filename_token_hint: str = Form("")):
    """文件双通道上传:extract → route → evidence_bundle / readable 摘要。"""
    from .detection import Tokenizers, filename_token

    data = await file.read()
    filename = file.filename or "upload.bin"

    def _process():
        from .files import extract_text, route_file
        text, extractor = extract_text(data, filename)
        tier = route_file(filename, text)
        ftok = filename_token_hint or filename_token(filename, Tokenizers.default())
        if tier == "evidence":
            bundle = evidence_bundle(data, filename, guard.aead,
                                     filename_token=ftok)
            return {"content_tier": "evidence", "extractor": extractor,
                    **{k: bundle[k] for k in ("file_hash", "file_content_hash",
                                              "vault_ct", "filename_token")}}
        return {"content_tier": "readable", "extractor": extractor,
                "filename_token": ftok,
                "file_hash": hashlib.sha256(data).hexdigest(),
                "text_excerpt": text[:200], "text_chars": len(text)}

    return await run_sync(_process)


@app.post("/api/attack/inject")
async def attack_inject(req: AttackInjectRequest):
    """注入一种攻击(沙箱副本上模拟,主状态零污染,R9)。"""
    if req.attack not in ATTACKS:
        raise HTTPException(status_code=404,
                            detail=f"未知攻击名(可选 {ATTACKS})")
    return await run_sync(sandbox.attack, req.attack)


@app.post("/api/attack/reset")
async def attack_reset():
    """恢复沙箱快照(SEC-ISO-2)。"""
    def _reset():
        sandbox.reset()
        return {"ok": True, "restored": True}
    return await run_sync(_reset)


@app.post("/api/logs/pack")
async def logs_pack():
    """强制立即 Merkle 打包(Task 12 force 触发)。"""
    def _pack():
        pack = guard.chain.maybe_pack(time.monotonic(), force=True)
        root = (pack or {}).get("merkle_root") or guard.logs()["merkle"]["root"]
        return {"merkle_root": root,
                "range": (pack or {}).get("range")}
    return await run_sync(_pack)


@app.post("/api/gateway/compute")
async def gateway_compute(req: ComputeRequest):
    """计算网关演示:白名单校验 + 聚合(spec §3.4)。"""
    def _compute():
        tiers = req.token_tiers or {t: "T3" for t in req.tokens}
        try:
            d = validate_directive(
                {"op": req.op, "tokens": req.tokens,
                 "result_ref": req.result_ref}, tiers)
        except GatewayReject as ex:
            return {"accepted": False, "reason": ex.reason}
        vals = [(req.values or {}).get(t, 0) for t in d.tokens]
        return {"accepted": True, "op": d.op, "result_ref": d.result_ref,
                "result": aggregate(d.op, vals), "tokens": list(d.tokens)}
    return await run_sync(_compute)


@app.get("/api/logs")
def logs():
    return guard.logs()


@app.post("/api/logs/tamper")
def tamper_log(index: int = 0):
    return guard.tamper_log(index)


@app.post("/api/sse/search")
def sse_search(req: SSESearchRequest):
    return guard.sse_search(req.keyword)


@app.post("/api/he/stats")
def he_stats(req: HEStatsRequest):
    return guard.he_stats(req.values)


@app.get("/api/zkp/info")
def zkp_info():
    from .crypto.zkp import _PRIME
    proof = guard.prover.prove(aux=b"CryptoGuard-request")
    from .crypto.zkp import verify_proof
    return {
        "public_y": hex(guard.prover.y),
        "prime_bits": _PRIME.bit_length(),
        "proof": proof,
        "valid": verify_proof(guard.prover.y, proof, aux=b"CryptoGuard-request"),
    }


@app.get("/api/perf")
def perf():
    """性能预算对照（md 中的目标值），供仪表盘展示。"""
    return {
        "targets": [
            {"op": "nonce/hash", "target_ms": 1},
            {"op": "AES-GCM", "target_ms": 5},
            {"op": "Ed25519 签名", "target_ms": 1},
            {"op": "Ed25519 验签", "target_ms": 2},
            {"op": "Merkle", "target_ms": 5},
            {"op": "CP-ABE (5 attr)", "target_ms": 15},
            {"op": "SSE 单关键词", "target_ms": 20},
            {"op": "端到端", "target_ms": 500},
        ],
        "provider_public_key": guard.llm.provider_public_b64,
        "auditor_public_key": guard.auditor.auditor_public_b64,
        "aead_key_b64": guard.aead.key_b64,
        "model_cert": guard.model_cert,
    }


@app.websocket("/ws/pipeline")
async def ws_pipeline(ws: WebSocket):
    """实时推送流水线步骤（演示用）。"""
    await ws.accept()
    try:
        while True:
            data = await ws.receive_text()
            req = json.loads(data)
            result = guard.query(
                req.get("text", ""),
                scenario=req.get("scenario", "medical"),
                attributes=req.get("attributes"),
                attack=req.get("attack"),
            )
            # 逐步推送
            for step in result["pipeline"]:
                await ws.send_json({"type": "step", "data": step})
                time.sleep(0.05)
            await ws.send_json({"type": "done", "data": result})
    except WebSocketDisconnect:
        pass


# ------------------------------------------------------------------ #
# 聊天/查看器 API(Task 9/10):会话 CRUD、SSE 单流、链查看、独立复算
# ------------------------------------------------------------------ #

#: 会话级滑动窗口限流(单 worker,模块级即可):10 条 / 60 秒
_RATE_MAX = 10
_RATE_WINDOW_S = 60.0
_chat_rate_hits: dict[str, list[float]] = {}

#: /api/chain 的 verify() 结果缓存,(条数, root) 键变即失效(Task 10)
_chain_verify_cache: dict[tuple[int, str], bool] = {}

#: SSE 泵入器收尾哨兵
_SENTINEL = object()


def _rate_limited(session_id: str) -> bool:
    """会话级滑动窗口限流:窗口内 ≥ _RATE_MAX 次则拒绝(计本次)。"""
    now = time.monotonic()
    hits = [t for t in _chat_rate_hits.get(session_id, [])
            if now - t < _RATE_WINDOW_S]
    if len(hits) >= _RATE_MAX:
        _chat_rate_hits[session_id] = hits
        return True
    hits.append(now)
    _chat_rate_hits[session_id] = hits
    return False


def _chain_valid_cached(service) -> bool:
    """verify() 结果按 (条数, root) 缓存;入链即键变失效,免逐次重算整链。"""
    key = (len(service.chain.entries), service.chain.root)
    if key not in _chain_verify_cache:
        _chain_verify_cache.clear()
        _chain_verify_cache[key] = service.chain.verify()
    return _chain_verify_cache[key]


def _sse_frame(kind: str, data: dict) -> str:
    """SSE 单帧:`event: <kind>` + `data: <json>`(UTF-8,可含中文)。"""
    return f"event: {kind}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"


def _run_turn_pump(service, session_id: str, text: str, files: list,
                   q: "queue.Queue") -> None:
    """线程侧泵:run_turn 事件入队;异常映射 error 帧(fail-closed);哨兵收尾。"""
    def on_event(kind: str, data: dict) -> None:
        q.put((kind, data))

    try:
        service.run_turn(session_id, text, files, on_event)
    except LLMFailure as exc:
        logger.error("protocol_error: %s", exc)  # spec §5:不降级,直接报错
        q.put(("error", {"class": "protocol" if exc.kind == "protocol"
                         else "internal", "message": str(exc)}))
    except Exception as exc:  # noqa: BLE001 — 未分类异常 fail-closed,不外泄栈
        logger.error("chat_turn_failed: %s", exc, exc_info=True)
        q.put(("error", {"class": "internal",
                         "message": str(exc) or type(exc).__name__}))
    finally:
        q.put(_SENTINEL)


@app.post("/api/chat/sessions")
async def chat_create_session(request: Request,
                              req: ChatSessionCreate | None = None):
    """新建会话:title 可选,缺省「新会话」。"""
    title = req.title if req and req.title is not None else "新会话"
    return await run_sync(request.app.state.chat.sessions.create_session, title)


@app.get("/api/chat/sessions")
async def chat_list_sessions(request: Request):
    """会话列表(创建顺序,latest rev 生效)。"""
    return await run_sync(request.app.state.chat.sessions.list_sessions)


@app.get("/api/chat/sessions/{sid}")
async def chat_get_session(sid: str, request: Request):
    """会话详情:{session, messages},消息动态还原 user_view;未知 404。"""
    service = request.app.state.chat
    try:
        session = await run_sync(service.sessions.get_session, sid)
        messages = await run_sync(service.sessions.list_messages, sid)
    except ValueError:
        raise HTTPException(status_code=404, detail=f"会话不存在: {sid}")
    return {"session": session, "messages": messages}


@app.post("/api/chat/sessions/{sid}/messages")
async def chat_send_message(sid: str, req: ChatMessageRequest, request: Request):
    """发消息(SSE 单流):on_event 经 queue 泵入生成器;限流在开流前拒绝。

    帧格式 `event: stage|token|done|error` + `data: <json>`;done/error 为终帧。
    空白 text 且无附件 → 400;未知会话 → 404;超限 → 429。
    """
    service = request.app.state.chat
    try:
        files = [{"filename": f.filename,
                  "data": base64.b64decode(f.content_b64)}
                 for f in (req.files or [])]
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"附件解码失败: {e}")
    if (not req.text or not req.text.strip()) and not files:
        raise HTTPException(status_code=400,
                            detail="空白输入被拒:text 无内容且无附件")
    try:
        await run_sync(service.sessions.get_session, sid)
    except ValueError:
        raise HTTPException(status_code=404, detail=f"会话不存在: {sid}")
    if _rate_limited(sid):
        raise HTTPException(status_code=429,
                            detail="限流:每会话每分钟最多 10 条")

    q: queue.Queue = queue.Queue()
    loop = asyncio.get_running_loop()
    loop.run_in_executor(None, _run_turn_pump, service, sid, req.text, files, q)

    def _frames():
        while True:
            item = q.get()
            if item is _SENTINEL:        # 兜底收尾(正常以 done/error 终止)
                return
            kind, data = item
            yield _sse_frame(kind, data)
            if kind in ("done", "error"):   # 终帧
                return

    return StreamingResponse(_frames(), media_type="text/event-stream")


@app.get("/api/messages/{mid}/pipeline")
async def message_pipeline(mid: str, request: Request):
    """查看器一次取全:message(含动态 user_view)+ artifacts + verification +
    chain_entries(按 chain_refs 解析)+ files;未知 404。"""
    service = request.app.state.chat
    try:
        rec = await run_sync(service.sessions.get_message, mid)
    except ValueError:
        raise HTTPException(status_code=404, detail=f"消息不存在: {mid}")
    entries = service.chain.entries
    chain_entries = [entries[i] for i in rec.get("chain_refs") or []]
    return {
        "message": rec,
        "artifacts": rec.get("artifacts") or {},
        "verification": rec.get("verification") or [],
        "chain_entries": chain_entries,
        "files": rec.get("files") or [],
    }


@app.get("/api/chain")
async def chain_state(request: Request):
    """链状态:entries + verify(缓存)+ root + 全链 Merkle + 条数。"""
    service = request.app.state.chat
    entries = service.chain.entries
    merkle = await run_sync(MerkleTree, [e["hash"] for e in entries])
    return {
        "chain": entries,
        "chain_valid": _chain_valid_cached(service),
        "chain_root": service.chain.root,
        "merkle": merkle.to_dict(),
        "count": len(entries),
    }


@app.get("/api/chain/entry/{index}/proof")
async def chain_entry_proof(index: int, request: Request):
    """Merkle 单条证明(全链叶子集建树):{index, leaf, proof, root, verified}。"""
    entries = request.app.state.chat.chain.entries
    if index < 0 or index >= len(entries):
        raise HTTPException(status_code=404, detail=f"链条目不存在: {index}")
    tree = MerkleTree([e["hash"] for e in entries])
    proof = tree.proof(index)
    leaf = entries[index]["hash"]
    return {"index": index, "leaf": leaf, "proof": proof, "root": tree.root,
            "verified": tree.verify_proof(leaf, index, proof, tree.root)}


@app.post("/api/verify/preimage")
async def verify_preimage(req: PreimageVerifyRequest):
    """preimage 独立复算:纯数据返回,服务端不下验证结论(UI 中性表述)。"""
    recomputed = h_hex(req.preimage)
    return {"preimage": req.preimage,
            "expected_hash": req.expected_hash,
            "recomputed_hash": recomputed,
            "match": recomputed == req.expected_hash}


# ------------------------------------------------------------------ #
# 验收 API(Task 12):/demo 验收抽屉数据源(spec §6.2/§6.3)
# ------------------------------------------------------------------ #

@app.get("/api/acceptance/golden")
async def acceptance_golden():
    """Golden Set 400 实测指标(混淆矩阵 + Wilson CI);CPU 密集走线程池。"""
    return await run_sync(run_golden)


@app.get("/api/acceptance/store-scan")
async def acceptance_store_scan():
    """SEC-STORE-1:扫数据目录明文泄漏键(user_view/reasoning_content/mapping)。"""
    return await run_sync(scan_plaintext_leaks, default_data_dir())


@app.get("/api/acceptance/replay")
async def acceptance_replay():
    """SEC-REPLAY-1:对活数据目录只读重建回放,返回计数或错误类别。"""
    return await run_sync(replay_report, default_data_dir())


@app.post("/api/acceptance/degrade")
async def acceptance_degrade(req: DegradeRequest):
    """SEC-DEGRADE-1:三选一故障注入,返回 spec §5 行为三元组;未知 kind → 400。"""
    try:
        return await run_sync(degrade_demo, req.kind)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# 托管前端构建产物（若存在）
_FRONTEND_DIST = os.path.join(os.path.dirname(__file__), "..", "..", "frontend", "dist")
if os.path.isdir(_FRONTEND_DIST):
    app.mount("/assets", StaticFiles(directory=os.path.join(_FRONTEND_DIST, "assets")), name="assets")

    @app.get("/{full_path:path}")
    def spa(full_path: str):
        target = os.path.join(_FRONTEND_DIST, full_path)
        if full_path and os.path.isfile(target):
            return FileResponse(target)
        return FileResponse(os.path.join(_FRONTEND_DIST, "index.html"))
