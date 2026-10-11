"""
CryptoGuard —— 面向大模型应用的敏感数据加密与防泄漏平台

FastAPI 主应用：提供密码学 API + 托管前端静态资源。
"""
from __future__ import annotations

import json
import time

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from .proxy import guard
from .schemas import (
    DetectRequest, QueryRequest, SSESearchRequest, HEStatsRequest, PolicyUpdate,
)

app = FastAPI(title="CryptoGuard", version="1.0.0")

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
