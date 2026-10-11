# 字段对照表(spec §6.4-B,双向勾稽)

约定:ProVerif `fun` 元数 == 代码哈希前映像字段数(代码函数显式参数 + 域分隔
常量 `d`/链游标 `prev`);协议字段变更时本表与代码须同 PR 内改完。

| 协议字段 | ProVerif 构造(元数) | 代码实现 | 公式出处 |
|---|---|---|---|
| `token_root` | `fun tokroot(bitstring, bitstring): bitstring` 链式(2 元:`prev`, `token`) | `backend/app/tokenchain.py::token_chain(session_id, tokens)`(2 参数,顺序累加链 `chain_i = H({"d":"CG/TOKEN_CHAIN/v2","prev","t","k"})`) | §3.1 |
| `input_hash` | `fun inputhash(bitstring, bitstring, bitstring, bitstring, bitstring, bitstring, bitstring): bitstring`(7 元:`d, t, f, r, o, n, ts`) | `backend/app/tokenchain.py::input_hash(redacted_text, file_hashes, token_root, override_h, nonce, timestamp)`(6 参数 + 域常量 `d="CG/INPUT/v2"`;精确前映像见 `input_hash_preimage()` 的 7 字段 dict) | §3.1 |
| `model_cert` | `fun cert(bitstring, bitstring, bitstring, bitstring): bitstring`(4 元:`model_id, version, release_date, model_hash`) | `backend/app/mock_auditor.py::MockAuditor.issue_model_cert(model_id, version, release_date, model_hash)`(4 参数,载荷经 `Sign(sk_auditor, ·)`) | §3.3 |
| `response_hash` | `fun resp_hash(bitstring, bitstring, bitstring, bitstring, bitstring, bitstring): bitstring`(6 元:`d, out, ih, cert, n, ts`) | `backend/app/mock_llm.py::MockLLM._response_hash(output, input_hash, cert, nonce, timestamp)`(5 参数 + 域常量 `d="CG/RESP/v2"`,委托 `tokenchain.response_hash`) | §3.1 |
| `log_entry` | `fun logent(bitstring, bitstring, bitstring, bitstring, bitstring): bitstring` 链(5 元:`d, ty, p, ts, prev`) | `backend/app/crypto/hashchain.py::HashChain.append(entry_type, payload_digest, timestamp)`(3 参数 + 域常量 `d="CG/LOG/v2"` + `prev` 链游标;前映像 5 字段) | §3.3 |

## 附:模型其余构造与代码对应

| ProVerif | 代码 | 说明 |
|---|---|---|
| `fun sign/sk_provider` | `crypto/signatures.py::Ed25519Signer`(provider) | 层3 响应签名(EUF-CMA) |
| `fun sign/sk_auditor` | `mock_auditor.py::MockAuditor.signer` | 层2 model_cert 签名 |
| `fun senc/vault_key` | `crypto/aead.py`(AES-GCM 映射表保险库) | 映射表本地加密,密钥不出本地 |
| `fun hmac/k_t1` | `tokens.py::t1_pseudonym`(HMAC-SHA256 截断 128-bit) | T1 伪名(建模以 hmac 表意) |
| `table acceptedNonce` | `mock_llm.py::MockLLM._nonce_store` + 回程 nonce 比对 | 防重放:nonce 单次使用 |
| `logent(...)` 私有通道输出 | `hashchain.py::HashChain` 条目追加 + Merkle 打包 | 层4 前向完整性 |
