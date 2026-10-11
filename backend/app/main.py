"""
CryptoGuard —— 面向大模型应用的敏感数据加密与防泄漏平台

FastAPI 主应用：提供密码学 API + 托管前端静态资源。
"""
from __future__ import annotations

import base64
import hashlib
import json
import time

from fastapi import (FastAPI, File, Form, HTTPException, UploadFile,
                     WebSocket, WebSocketDisconnect)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from .concurrency import run_sync
from .files import evidence_bundle
from .gateway import GatewayReject, aggregate, validate_directive
from .proxy import guard
from .sandbox import ATTACKS, AttackSandbox
from .schemas import (
    DetectRequest, QueryRequest, SSESearchRequest, HEStatsRequest, PolicyUpdate,
    QueryV2Request, AttackInjectRequest, ComputeRequest,
)

app = FastAPI(title="CryptoGuard", version="1.0.0")

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


# 托管前端构建产物（若存在）
import os
_FRONTEND_DIST = os.path.join(os.path.dirname(__file__), "..", "..", "frontend", "dist")
if os.path.isdir(_FRONTEND_DIST):
    app.mount("/assets", StaticFiles(directory=os.path.join(_FRONTEND_DIST, "assets")), name="assets")

    @app.get("/{full_path:path}")
    def spa(full_path: str):
        target = os.path.join(_FRONTEND_DIST, full_path)
        if full_path and os.path.isfile(target):
            return FileResponse(target)
        return FileResponse(os.path.join(_FRONTEND_DIST, "index.html"))
