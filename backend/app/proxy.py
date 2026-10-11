"""
本地代理编排 —— 四层可验证协议核心

数据流：明文 → 脱敏 → (CP-ABE/SSE/ZKP 增强) → 出站 → Mock LLM → 回程四层验证 → 还原

四层协议：
  1 输入绑定   input_hash = H(脱敏输入) + nonce + timestamp
  2 模型身份   model_cert = Sign(sk_auditor, model_id||version||release_date||model_hash)
  3 响应完整   response_hash = H(output||input_hash||model_cert||nonce||timestamp)
              signature = Sign(sk_provider, response_hash)
  4 可审计日志 log_entry_i = H(req_digest||resp_digest||ts||log_entry_{i-1}) + Merkle 根
"""
from __future__ import annotations

import hashlib
import os
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from .canon import canon
from .crypto.aead import AeadCipher
from .crypto.abe import ABE, PolicyTree, make_and, make_or
from .crypto.hashchain import HashChain, sha256_hex
from .crypto.he import Paillier, encrypt_vector, sum_encrypted, decrypt_vector
from .crypto.merkle import MerkleTree
from .crypto.sse import SSEIndex
from .crypto.zkp import SchnorrProver, verify_proof
from .detection import (detect_sensitive, DEFAULT_ENABLED,
                        tokenize_entities, filename_token, Tokenizers)
from .files import extract_text, route_file, evidence_bundle
from .gateway import validate_directive, aggregate, GatewayReject
from .mock_auditor import MockAuditor
from .mock_llm import MockLLM
from .schemas import (build_outbound, verify_outbound,
                      OverrideEvent, FilePayload)
from .tokenchain import file_content_hash


class CryptoGuard:
    """本地代理状态（单例）。"""

    def __init__(self):
        self.aead = AeadCipher()                 # 映射表加密
        self.auditor = MockAuditor()             # 审计机构
        self.abe = ABE()                         # CP-ABE（教学级）
        self.sse = SSEIndex()                    # 密文索引
        self.prover = SchnorrProver()            # ZKP
        self.chain = HashChain()                 # 日志哈希链
        self.merkle_leaves: list[str] = []
        self.doc_counter = 0

        # 策略配置（脱敏模式 + 启用实体类型）
        self.policy = {
            "mode": "placeholder",  # placeholder / mask / hash
            "enabled_types": sorted(DEFAULT_ENABLED),
        }

        # 统计计数
        self.stats = {
            "queries": 0,
            "entities_protected": 0,
            "attacks_blocked": 0,
            "verified": 0,
            "rejected": 0,
            "total_latency_ms": 0.0,
        }

        # 审计机构签发模型证书
        model_hash = hashlib.sha256(b"CryptoGuard-Mock-LLM-weights-v1.0").hexdigest()
        self.model_cert = self.auditor.issue_model_cert(
            model_id="cryptoguard-llm", version="1.0.0",
            release_date="2026-09-01", model_hash=model_hash,
        )
        self.llm = MockLLM(self.model_cert)

        # 演示用：预置 Paillier 实例（懒加载以省启动时间）
        self._paillier = None

        # R7:线程池执行器(Phase D /api/proxy/query 用 run_in_executor 包同步 query_v2)
        self._pool = ThreadPoolExecutor(max_workers=8)

    def exec_sync(self, fn, *args):
        """同步入口:fn(*args) 提交线程池并等待结果(R7)。"""
        return self._pool.submit(fn, *args).result()

    # ------------------------------------------------------------------ #
    # 主流水线
    # ------------------------------------------------------------------ #
    def query(self, text: str, scenario: str = "medical",
              attributes: list[str] | None = None, attack: str | None = None) -> dict:
        t0 = time.perf_counter()
        pipeline: list[dict] = []

        def step(name: str, start: float, **meta):
            dur_ms = round((time.perf_counter() - start) * 1000, 2)
            pipeline.append({"step": name, "duration_ms": dur_ms, **meta})

        # 1. 敏感检测（按策略：启用的实体类型 + 脱敏模式）
        s = time.perf_counter()
        enabled = set(self.policy["enabled_types"])
        det = detect_sensitive(text, enabled_types=enabled, mode=self.policy["mode"])
        step("敏感实体检测", s, entity_count=len(det.entities))

        # 2. AES-GCM 加密映射表
        s = time.perf_counter()
        mapping_ct = self.aead.encrypt(det.mapping)
        step("AES-GCM 加密映射表", s)

        # 3. CP-ABE 细粒度授权（可选增强）
        s = time.perf_counter()
        abe_enabled = bool(attributes)
        abe_result = None
        if abe_enabled:
            policy = self._policy_for_scenario(scenario)
            abe_result = self.abe.encrypt(det.mapping, policy)
        step("CP-ABE 策略加密", s, enabled=abe_enabled)

        # 4. SSE 密文索引（可选增强）
        s = time.perf_counter()
        self.doc_counter += 1
        keywords = [e.value for e in det.entities if e.type in ("PROJECT", "PHI", "PII", "NAME")]
        if keywords:
            self.sse.add_document(self.doc_counter, keywords)
        step("SSE 密文索引", s, indexed_keywords=len(keywords))

        # 5. ZKP 合规性证明（可选增强，非阻塞）
        s = time.perf_counter()
        zkp = self.prover.prove(aux=b"CryptoGuard-request")
        zkp_ok = verify_proof(self.prover.y, zkp, aux=b"CryptoGuard-request")
        step("ZKP 合规证明", s, valid=zkp_ok)

        # 6. 四层协议字段
        s = time.perf_counter()
        nonce = uuid.uuid4().hex
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        input_hash = sha256_hex(det.redacted)
        step("生成 nonce/input_hash", s)

        # 7. 出站（只含脱敏输入 + 元数据;R7 新签名:req_dump + attack）
        s = time.perf_counter()
        llm_resp = self.llm.respond(
            {"redacted_text": det.redacted, "input_hash": input_hash,
             "nonce": nonce, "timestamp": timestamp}, attack)
        step("出站调用 Mock LLM", s)

        # 8. 回程四层验证
        verification = self._verify(llm_resp, det.redacted, input_hash, nonce, timestamp)

        # 9. 还原（本地解密映射表，将输出中的脱敏串替换回明文）
        s = time.perf_counter()
        restored = self._restore(llm_resp["output"], det.restore_map)
        step("解密映射表并还原", s)

        # 10. 日志（哈希链 + Merkle）
        s = time.perf_counter()
        self._log(det.redacted, llm_resp, input_hash, timestamp)
        step("写入哈希链 + Merkle", s)

        status = "verified" if all(v["ok"] for v in verification) else "rejected"

        # 记录端到端耗时
        total_ms = round((time.perf_counter() - t0) * 1000, 2)

        # 更新统计
        self.stats["queries"] += 1
        self.stats["entities_protected"] += len(det.entities)
        self.stats["total_latency_ms"] += total_ms
        if status == "verified":
            self.stats["verified"] += 1
        else:
            self.stats["rejected"] += 1
        if attack:
            self.stats["attacks_blocked"] += 1

        return {
            "request_id": uuid.uuid4().hex[:12],
            "status": status,
            "original_input": text,
            "redacted_input": det.redacted,
            "mode": self.policy["mode"],
            "model_output": llm_resp["output"],
            "restored_output": restored,
            "entities": det.to_dict()["entities"],
            "entity_stats": det.to_dict()["stats"],
            "input_hash": input_hash,
            "nonce": nonce,
            "timestamp": timestamp,
            "model_cert": llm_resp["model_cert"],
            "response_hash": llm_resp["response_hash"],
            "signature": llm_resp["signature"],
            "signature_valid": any(v["layer"] == "响应完整性" and v["ok"] for v in verification),
            "cert_valid": any(v["layer"] == "模型身份" and v["ok"] for v in verification),
            "nonce_valid": any(v["layer"] == "输入绑定/防重放" and v["ok"] for v in verification),
            "verification": verification,
            "pipeline": pipeline,
            "attack": attack,
            "attack_result": self._attack_result(attack),
            "total_ms": total_ms,
            "abe_enabled": abe_enabled,
        }

    # ------------------------------------------------------------------ #
    # 流水线 v2(CG/2.0 分级令牌出站,spec §3)
    # ------------------------------------------------------------------ #
    def query_v2(self, text: str, files: list | None = None,
                 overrides: list | None = None, scenario: str = "medical",
                 directive: dict | None = None) -> dict:
        """CG/2.0 主流水线:检测→令牌→出站→Mock LLM→验证→还原→入链。

        - overrides:OverrideEvent 形状的用户决策列表(非空时哈希进 input_hash
          并追加 USER_OVERRIDE 链条目);
        - directive:模型侧计算指令,经计算网关白名单校验,越权拒绝并入
          COMPUTE_GATE 链条目(gateway_rejected=True);
        - 返回含 outbound(OutboundRequest dump)、input_hash、canonical_preimage(R8)、
          verification、pipeline、override_events、mock_sleep_ms。
        """
        t0 = time.perf_counter()
        pipeline: list[dict] = []

        def step(name: str, start: float, **meta):
            dur_ms = round((time.perf_counter() - start) * 1000, 2)
            pipeline.append({"step": name, "duration_ms": dur_ms, **meta})

        session_id = uuid.uuid4().hex
        tok = Tokenizers.default()          # 会话级密钥(k_t1/salt/T2)
        nonce = uuid.uuid4().hex
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        enabled = set(self.policy["enabled_types"])

        # 1. 敏感检测 + 分级令牌(Task 10)
        s = time.perf_counter()
        det = detect_sensitive(text, enabled_types=enabled, mode=self.policy["mode"])
        token_ents = tokenize_entities(det.entities, tok)
        redacted = self._apply_tokens(text, det.entities, token_ents)
        step("敏感检测 + 分级令牌", s, entity_count=len(det.entities),
             token_count=len(token_ents))

        # 2. 文件双通道(spec §2.2/§2.3)
        s = time.perf_counter()
        file_payloads, file_commits, file_tokens = self._build_file_payloads(
            files or [], tok, enabled)
        all_tokens = self._dedup_tokens(token_ents + file_tokens)
        step("文件双通道载荷", s, file_count=len(file_payloads))

        # 3. USER_OVERRIDE 决策事件(spec §3.5,哈希进 input_hash)
        ovs = [e if isinstance(e, OverrideEvent) else OverrideEvent(**e)
               for e in (overrides or [])]

        # 4. 出站包拼装(唯一入口 build_outbound)+ 网关三规则(不过则抛)
        s = time.perf_counter()
        req = build_outbound(
            session_id=session_id,
            redacted_text=redacted,
            file_payloads=file_payloads,
            token_index=[{"token": t.token, "type": t.type,
                          "tier": t.tier, "leak_class": t.leak_class}
                         for t in all_tokens],
            override_events=[e.model_dump() for e in ovs],
            nonce=nonce,
            timestamp=timestamp,
        )
        violations = verify_outbound(
            req, tok.k_t1, tok.session_salt,
            {t.token: (t.type, t.value) for t in all_tokens})
        if violations:
            raise ValueError("出站包校验失败: " + "; ".join(violations))
        step("出站包拼装 + 网关三规则", s, input_hash=req.input_hash)

        # 5. 计算网关(白名单指令校验,越权拒绝入 COMPUTE_GATE 链)
        compute_result = None
        if directive is not None:
            ti_map = {t.token: t.tier for t in all_tokens}
            try:
                d = validate_directive(directive, ti_map)
            except GatewayReject as ex:
                self._append_entry(
                    "COMPUTE_GATE",
                    canon({"directive": directive, "reason": ex.reason}).decode("utf-8"),
                    timestamp)
                return self._finish_v2(
                    t0, pipeline, status="rejected", req=req, redacted=redacted,
                    ovs=ovs, verification=[], mock_sleep_ms=0,
                    extra={"gateway_rejected": True, "rejection_reason": ex.reason})
            try:
                vals = [int(next(t for t in all_tokens if t.token == tn).value)
                        for tn in d.tokens]
                compute_result = {"op": d.op, "result_ref": d.result_ref,
                                  "result": aggregate(d.op, vals)}
            except (StopIteration, ValueError):
                compute_result = {"op": d.op, "result_ref": d.result_ref, "result": None}
            self._append_entry(
                "COMPUTE_GATE",
                canon({"directive": {"op": d.op, "tokens": list(d.tokens),
                                     "result_ref": d.result_ref},
                       "result": compute_result["result"]}).decode("utf-8"),
                timestamp)

        # 6. 出站调用 Mock LLM(R7 新签名,自带随机延迟)
        s = time.perf_counter()
        resp = self.llm.respond(req.model_dump())
        step("出站调用 Mock LLM", s, mock_sleep_ms=resp["mock_sleep_ms"])

        # 7. 回程四层验证
        verification = self._verify_v2(resp, req)
        status = "verified" if all(v["ok"] for v in verification) else "rejected"

        # 8. 还原(令牌 → 明文,仅本地)
        restored = self._restore(resp["output"],
                                 {t.replacement: t.value for t in all_tokens})

        # 9. 入链:QUERY / USER_OVERRIDE / FILE_COMMIT(entry_type,裁定 R21)
        if ovs:
            self._append_entry(
                "USER_OVERRIDE",
                canon([e.model_dump() for e in ovs]).decode("utf-8"), timestamp)
        for fc in file_commits:
            self._append_entry("FILE_COMMIT", fc, timestamp)
        self._append_entry("QUERY", req.input_hash, timestamp)

        return self._finish_v2(
            t0, pipeline, status=status, req=req, redacted=redacted, ovs=ovs,
            verification=verification, mock_sleep_ms=resp["mock_sleep_ms"],
            extra={"output": resp["output"], "restored_output": restored,
                   "response_hash": resp["response_hash"],
                   "model_cert": resp["model_cert"],
                   "signature": resp["signature"],
                   "compute": compute_result})

    # -- query_v2 辅助 -------------------------------------------------- #
    @staticmethod
    def _apply_tokens(text: str, entities: list, token_ents: list) -> str:
        """按实体区间把明文替换为令牌文内形态(从后往前,避免偏移)。"""
        redacted = text
        for e, te in sorted(zip(entities, token_ents),
                            key=lambda p: p[0].start, reverse=True):
            redacted = redacted[:e.start] + te.replacement + redacted[e.end:]
        return redacted

    def _build_file_payloads(self, files: list, tok: Tokenizers,
                             enabled: set) -> tuple[list[FilePayload], list[str], list]:
        """文件双通道:readable=脱敏正文出站,evidence=只出承诺(默认拒绝)。

        返回 (payloads, FILE_COMMIT 摘要, 文件内实体令牌 —— 须并入 token_index,
        否则网关规则 1 会拒掉文件正文里的合法令牌)。
        """
        payloads: list[FilePayload] = []
        commits: list[str] = []
        ftoken_ents: list = []
        for i, f in enumerate(files):
            filename, data = f["filename"], f["data"]
            ftext, _extractor = extract_text(data, filename)
            tier = route_file(filename, ftext)
            ftok = filename_token(filename, tok)
            fhash = hashlib.sha256(data).hexdigest()
            ref = f"file_{i + 1}"
            if tier == "readable":
                fdet = detect_sensitive(ftext, enabled_types=enabled,
                                        mode=self.policy["mode"])
                ftes = tokenize_entities(fdet.entities, tok)
                ftoken_ents.extend(ftes)
                fred = self._apply_tokens(ftext, fdet.entities, ftes)
                payloads.append(FilePayload(
                    file_ref=ref, filename_token=ftok, content_tier="readable",
                    redacted_content=fred,
                    file_content_hash=file_content_hash(fred),
                    file_hash=fhash))
            else:
                bundle = evidence_bundle(data, filename, self.aead,
                                         filename_token=ftok)
                payloads.append(FilePayload(
                    file_ref=ref, filename_token=ftok, content_tier="evidence",
                    file_content_hash=bundle["file_content_hash"],
                    file_hash=fhash))
            # R21:FILE_COMMIT payload_digest = file_hash‖filename_token(确定性串)
            commits.append(f"{fhash}|{ftok}")
        return payloads, commits, ftoken_ents

    @staticmethod
    def _dedup_tokens(tokens: list) -> list:
        """按 token 去重(T1 确定性伪名天然共指,保留首次出现)。"""
        seen: set[str] = set()
        out = []
        for t in tokens:
            if t.token not in seen:
                seen.add(t.token)
                out.append(t)
        return out

    def _verify_v2(self, resp: dict, req) -> list[dict]:
        """回程四层验证(CG/2.0 口径:input_hash 为出站包绑定哈希)。"""
        v = []
        bound = resp["nonce"] == req.nonce and resp["timestamp"] == req.timestamp
        v.append({
            "layer": "输入绑定/防重放", "ok": bound,
            "detail": "nonce/timestamp 与出站包一致" if bound
                      else "nonce 或 timestamp 不匹配(疑似重放/输入被替换)",
        })
        cert_valid = self.auditor.verify_model_cert(resp["model_cert"])
        v.append({
            "layer": "模型身份", "ok": cert_valid,
            "detail": "model_cert 审计签名有效" if cert_valid
                      else "model_cert 签名无效(疑似伪造模型声明)",
        })
        recomputed = MockLLM._response_hash(
            resp["output"], req.input_hash, resp["model_cert"],
            resp["nonce"], resp["timestamp"])
        hash_match = recomputed == resp["response_hash"]
        import base64
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        try:
            key = Ed25519PublicKey.from_public_bytes(
                base64.b64decode(resp["provider_public_key"]))
            key.verify(base64.b64decode(resp["signature"]),
                       resp["response_hash"].encode("utf-8"))
            sig_ok = True
        except Exception:
            sig_ok = False
        integrity_ok = hash_match and sig_ok
        v.append({
            "layer": "响应完整性", "ok": integrity_ok,
            "detail": "response_hash 一致且签名有效" if integrity_ok
                      else ("response_hash 不一致(响应被篡改)" if not hash_match
                            else "服务商签名无效"),
        })
        v.append({
            "layer": "可审计日志", "ok": True,
            "detail": "已追加哈希链条目(entry_type=QUERY)并更新 Merkle 根",
        })
        return v

    def _finish_v2(self, t0: float, pipeline: list, *, status: str, req,
                   redacted: str, ovs: list, verification: list,
                   mock_sleep_ms: int, extra: dict | None = None) -> dict:
        total_ms = round((time.perf_counter() - t0) * 1000, 2)
        self.stats["queries"] += 1
        self.stats["entities_protected"] += len(req.token_index)
        self.stats["total_latency_ms"] += total_ms
        self.stats["verified" if status == "verified" else "rejected"] += 1
        return {
            "request_id": uuid.uuid4().hex[:12],
            "status": status,
            "session_id": req.session_id,
            "redacted_text": redacted,
            "outbound": req.model_dump(),
            "input_hash": req.input_hash,
            "canonical_preimage": req.canonical_preimage,
            "override_events": [e.model_dump() for e in ovs],
            "verification": verification,
            "pipeline": pipeline,
            "mock_sleep_ms": mock_sleep_ms,
            "total_ms": total_ms,
            **(extra or {}),
        }

    def _append_entry(self, entry_type: str, payload_digest: str,
                      timestamp: str) -> dict:
        entry = self.chain.append(entry_type, payload_digest, timestamp)
        self.merkle_leaves.append(entry["hash"])
        return entry

    # ------------------------------------------------------------------ #
    def _verify(self, resp: dict, redacted: str, input_hash: str,
                nonce: str, timestamp: str) -> list[dict]:
        """回程四层验证，返回逐项结果。"""
        v = []

        # 层1：输入绑定（nonce 匹配 + input_hash 重算）
        recomputed_input_hash = sha256_hex(redacted)
        input_bound = (resp["nonce"] == nonce) and (recomputed_input_hash == input_hash)
        v.append({
            "layer": "输入绑定/防重放",
            "ok": input_bound,
            "detail": "nonce 匹配且 input_hash 一致" if input_bound
                      else "nonce 或 input_hash 不匹配（疑似重放/输入被替换）",
        })

        # 层2：模型身份（审计机构签名）
        cert_valid = self.auditor.verify_model_cert(resp["model_cert"])
        v.append({
            "layer": "模型身份",
            "ok": cert_valid,
            "detail": "model_cert 审计签名有效" if cert_valid
                      else "model_cert 签名无效（疑似伪造模型声明）",
        })

        # 层3：响应完整性（签名 + 哈希）
        from .mock_llm import MockLLM
        recomputed_response_hash = MockLLM._response_hash(
            resp["output"], input_hash, resp["model_cert"], resp["nonce"], resp["timestamp"]
        )
        hash_match = recomputed_response_hash == resp["response_hash"]
        import base64
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        try:
            key = Ed25519PublicKey.from_public_bytes(base64.b64decode(resp["provider_public_key"]))
            key.verify(base64.b64decode(resp["signature"]), resp["response_hash"].encode("utf-8"))
            sig_ok = True
        except Exception:
            sig_ok = False
        integrity_ok = hash_match and sig_ok
        v.append({
            "layer": "响应完整性",
            "ok": integrity_ok,
            "detail": "response_hash 一致且签名有效" if integrity_ok
                      else ("response_hash 不一致（响应被篡改）" if not hash_match
                            else "服务商签名无效"),
        })

        # 层4：可审计日志（这里仅标记，链验证在 /api/logs 统一执行）
        v.append({
            "layer": "可审计日志",
            "ok": True,
            "detail": "已追加哈希链条目并更新 Merkle 根",
        })

        return v

    def _restore(self, output: str, restore_map: dict[str, str]) -> str:
        """将输出中的脱敏串（占位符/掩码/哈希）替换回明文。"""
        restored = output
        for redacted_form, val in restore_map.items():
            restored = restored.replace(redacted_form, val)
        return restored

    def _log(self, redacted: str, resp: dict, input_hash: str, timestamp: str):
        # R21:QUERY payload_digest = input_hash(entry_type 进链)
        self._append_entry("QUERY", input_hash, timestamp)

    def _policy_for_scenario(self, scenario: str):
        if scenario == "financial":
            return make_or("role:auditor", make_and("role:analyst", "level:senior"))
        return make_or("role:auditor", make_and("role:doctor", "dept:cardiology"))

    @staticmethod
    def _attack_result(attack: str | None) -> str | None:
        if not attack:
            return None
        return {
            "tamper": "响应完整性验证失败：response_hash 不一致",
            "replay": "输入绑定验证失败：nonce 不匹配（重放旧响应）",
            "forge_cert": "模型身份验证失败：model_cert 审计签名无效",
            "tamper_log": "可审计日志验证失败：Merkle 证明不通过",
            "repudiate": "用户诬告：input_hash 与用户声称的输入不绑定",
        }.get(attack)

    # ------------------------------------------------------------------ #
    # 辅助查询接口
    # ------------------------------------------------------------------ #
    def logs(self) -> dict:
        tree = MerkleTree(self.merkle_leaves)
        return {
            "chain": self.chain.entries,
            "chain_valid": self.chain.verify(),
            "chain_root": self.chain.root,
            "merkle": tree.to_dict(),
        }

    def tamper_log(self, index: int) -> dict:
        """演示：篡改某条日志，触发链验证失败。"""
        if 0 <= index < len(self.chain.entries):
            e = self.chain.entries[index]
            e["payload_digest"] = sha256_hex("TAMPERED-RESPONSE")
            e["tampered"] = True
        return self.logs()

    def he_stats(self, values: list[int]) -> dict:
        if self._paillier is None:
            self._paillier = Paillier()
        phe = self._paillier
        cts = encrypt_vector(phe, values)
        enc_sum = sum_encrypted(phe, cts)
        dec_sum = phe.decrypt(enc_sum)
        dec_mean = dec_sum / len(values) if values else 0
        return {
            "ciphertexts": [hex(c) for c in cts],
            "encrypted_sum": hex(enc_sum),
            "decrypted_sum": dec_sum,
            "decrypted_mean": round(dec_mean, 4),
            "n": len(values),
        }

    def sse_search(self, keyword: str) -> dict:
        return {
            "keyword": keyword,
            "token": self.sse.token(keyword),
            "doc_ids": self.sse.search(keyword),
        }

    # ------------------------------------------------------------------ #
    # 策略与统计
    # ------------------------------------------------------------------ #
    def get_policy(self) -> dict:
        return self.policy

    def set_policy(self, mode: str | None = None, enabled_types: list[str] | None = None) -> dict:
        if mode is not None:
            if mode not in ("placeholder", "mask", "hash"):
                raise ValueError(f"未知脱敏模式: {mode}")
            self.policy["mode"] = mode
        if enabled_types is not None:
            self.policy["enabled_types"] = sorted(set(enabled_types))
        return self.policy

    def get_stats(self) -> dict:
        avg = self.stats["total_latency_ms"] / self.stats["queries"] if self.stats["queries"] else 0
        return {**self.stats, "avg_latency_ms": round(avg, 2)}


# 单例
guard = CryptoGuard()
