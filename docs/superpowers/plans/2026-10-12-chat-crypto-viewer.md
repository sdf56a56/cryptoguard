# 对话式前端与密码过程查看器 · 实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 为 CryptoGuard 增加 ChatGPT 式聊天界面（真实 LLM mimo-v2.6-flash）、单页双视角密码过程查看器（隐私/审计），后端 NDJSON 落盘持久化。

**Architecture:** 后端新增 keys/store/llm/sessions/chat_service 五模块，复用 CG/2.0 流水线（detection/tokens/build_outbound/hashchain）；SSE 单流推送阶段事件与 LLM token；前端三路由 /chat /inspect /demo。

**Tech Stack:** Python 3.13 + FastAPI + httpx（流式）+ cryptography（HKDF/AES-GCM/HMAC）；React 18 + Vite + Tailwind + vitest。

**Spec:** `docs/superpowers/specs/2026-10-12-chat-crypto-viewer-design.md`

**代码约定（用户裁定）:** 每任务只列接口契约与验收标准，实现代码在执行时按 spec § 展开；执行者须先读 spec 对应节再写码。

## Global Constraints

- UI 零自算：前端不生成任何哈希/密文，只渲染后端字段（spec §2.4）
- user_view / reasoning 明文永不落盘：磁盘只存 `llm_view` + `*_ct`（spec §3.3）
- LLM 失败三分类：network 切 Mock / protocol 报错不降级 / stream 保部分 + incomplete（spec §5）
- `entry_checksum` 仅损坏检测，防篡改归哈希链（spec §3.3 边界声明）
- 现有 109 用例全绿是合入前提；BIND/SEC/PERF 族原样重跑（spec §6.2）
- 数据目录 `data/`：链 `data/chain/seg-*.ndjson`（5000 条或 10MB 轮转）、`data/sessions/`、`data/messages/`
- 消息限流 10 条/分钟/会话，超限 429（spec §3.5）
- 状态色语义：绿=通过 黄=降级·不完整 红=失败 灰=无数据（spec §4.0）

## Review Focus

1. **多轮共指还原** — 第二轮消息引用第一轮实体时 user_view 必须还原完整（session_mapping_ct 累积）→ Task 7 测试
2. **流式中断落盘** — 断流后已收内容落盘 + incomplete=true，刷新页面可见 → Task 8 测试
3. **链跨段轮转回放** — 轮转后 replay verify() 全通，checksum 损坏与链断报错可区分 → Task 4 测试
4. **空/空白输入** — 拒绝发送（400），不入链不发 LLM → Task 9 测试
5. **reasoning/content 分轨** — 交错 chunk 不串轨，且 reasoning 不进多轮回传 prompt → Task 6 测试

---

## 任务（每任务 6 字段：名/输入/输出/验收/依赖/工作量）

### Task 1: `keys.py` — HKDF 派生 + VAULT_KEY 指纹检测

- **输入:** `backend/.env`（可选 `MIMO_API_KEY`、`VAULT_KEY=64 hex`）；`data/` 目录
- **输出:** `backend/app/keys.py`：`hkdf_sha256(root: bytes, info: str, length=32) -> bytes`；`Vault.load_or_init(data_dir: Path)` 属性 `mapping_key / reasoning_key / chain_mac_key / demo_chain_mac_key`（bytes）+ `fingerprint: str`；`VaultKeyError(RuntimeError)`。指纹 = `sha256(b"vault-fp/v1" + key_bytes).hexdigest()` 存 `data/vault_key_fingerprint.txt`
- **验收标准:** ① 派生确定性（同 root+info 同输出，info 不同输出不同）② 首次启动生成 key+指纹并落盘 ③ 指纹在而 key 缺失 → `VaultKeyError`（禁静默生成）④ key 与指纹不符 → `VaultKeyError("密钥已变更…")` ⑤ SEC-STORE 前置：生成物不含明文 key
- **依赖:** 无
- **工作量:** S（0.5 天）

### Task 2: `hashchain.py` — 条目 message_id 双向索引

- **输入:** 现有 `HashChain.append(entry_type, payload_digest, timestamp)`（`crypto/hashchain.py:57`）
- **输出:** `append(..., message_id: str | None = None)`：非空时 entry 加 `message_id` 字段、哈希前映像加 `"mid"`；`verify()` 按条目有无 `message_id` 选用前映像（无 mid 旧条目向后兼容，现有测试不改）
- **验收标准:** ① 无 mid 条目哈希与改动前逐字节一致 ② 带 mid 条目 verify()=True ③ 篡改 mid → verify()=False ④ 现有 109 用例全绿
- **依赖:** 无
- **工作量:** S（0.5 天）

### Task 3: `store.py` — SealedNDJSON（封缄追加 + entry_checksum + 轮转）

- **输入:** `canon.canon`（JCS）；`keys.Vault.chain_mac_key`
- **输出:** `backend/app/store.py`：`entry_checksum(mac_key, obj) -> str`（HMAC-SHA256 over `canon(obj 除去 entry_checksum 字段)`）；`SealedNDJSON(directory: Path, name: str, mac_key: bytes, seg_max_entries=5000, seg_max_bytes=10MB)`：`append(obj) -> dict`（注入 entry_checksum 写当前段）、`read_all() -> list[dict]`（按序读全部段并逐行验 checksum）、`segment_paths() -> list[Path]`（段命名 `{name}-{i:06d}.ndjson`）；`StoreIntegrityError(RuntimeError)` 带 `.kind in {"corrupt","chain_break"}`
- **验收标准:** ① append→read_all 往返一致 ② 篡改任一行 → `StoreIntegrityError(kind="corrupt")` ③ 按 `seg_max_entries=3` 轮转出多段、read_all 跨段有序 ④ 无明文 key 泄漏到文件内容
- **依赖:** Task 1
- **工作量:** M（1 天）

### Task 4: `store.py` — replay_chain 链回放（启动验链）

- **输入:** Task 3 `SealedNDJSON`；Task 2 `HashChain`（支持 mid）
- **输出:** `replay_chain(store: SealedNDJSON) -> HashChain`：逐行验 checksum → 重建 entries → 逐条验 `prev_hash→hash` 链接（含 mid 前映像）→ 返回可继续 append 的 HashChain（恢复 `_prev`/`entries`）；checksum 失配抛 `kind="corrupt"`、链接断抛 `kind="chain_break"`，异常信息含段名与行号
- **验收标准:** ① append N 条 → replay → verify()=True 且可继续追加 ② 改 payload 但重算 checksum（模拟持钥攻击者）→ `chain_break` ③ 改一字节 → `corrupt` ④ 跨轮转段回放全通
- **依赖:** Task 2、Task 3
- **工作量:** M（1 天）

### Task 5: `llm.py` — classify_failure + ReplyStream + MockChat

- **输入:** 现有 `MockLLM._generate`（`mock_llm.py:83`）；spec §3.2 三分类表
- **输出:** `backend/app/llm.py`：`LLMFailure(Exception)` 带 `.kind in {"network","protocol","stream"}`；`classify_failure(exc) -> "network"|"protocol"|"stream"|"internal"`（httpx 超时/连接/5xx→network，LLMFailure 透传，其余→internal）；`@dataclass ReplyStream: output:str; reasoning_content:str; incomplete:bool; degraded:str|None; model:str`；`MockChat.chat(messages, on_token) -> ReplyStream`（末条 user content 经 `_generate`，分块回调 `on_token(delta, reasoning=False)`）
- **验收标准:** ① 分类用例：TimeoutException→network、HTTPStatusError(400)→protocol、RuntimeError→internal ② MockChat 回调按块触发且拼接等于 output ③ ReplyStream 字段齐全
- **依赖:** 无
- **工作量:** S（0.5 天）

### Task 6: `llm.py` — MimoLLM 流式客户端 + LLMGateway 降级

- **输入:** spec §3.2（端点 `https://api.xiaomimimo.com/v1/chat/completions`、双头认证、`reasoning_content`/`content` 分轨、`max_reasoning_chars`）；Task 5 契约
- **输出:** `MimoLLM(api_key, base_url="https://api.xiaomimimo.com/v1", model="mimo-v2.6-flash", timeout=60.0, max_reasoning_chars=20000)`：httpx 流式 POST（`Authorization: Bearer` + `api-key` 双头），解析 `data:` 帧 `choices[0].delta.{content,reasoning_content}`；4xx→`LLMFailure("protocol")`，5xx/连接错→`LLMFailure("network")`，断流→返回已收内容 `incomplete=True`；`LLMGateway(mimo: MimoLLM|None, mock: MockChat).chat(messages, on_token)`：network 失败切 mock 并 `degraded="mock"`，protocol/internal 透传不降级
- **验收标准:** ① MockTransport 流式解析正确、reasoning/content 分轨不串 ② 断流→incomplete=True 且部分 output 保留 ③ 400→LLMFailure(protocol) 且 Gateway 不降级 ④ 500→Gateway 切 mock 且 degraded="mock" ⑤ 历史 messages 只含 content 不含 reasoning
- **依赖:** Task 5
- **工作量:** M（1 天）

### Task 7: `sessions.py` — 会话 + 双视角映射（session_mapping_ct / mapping_delta_ct）

- **输入:** `AeadCipher(key).encrypt/decrypt`（`crypto/aead.py:37/:47`）；`Tokenizers.default()`（`detection.py:277`：k_t1/session_salt/t2=T2Cipher(key)）；spec §3.3
- **输出:** `backend/app/sessions.py`：`SessionStore(vault, sessions_log: SealedNDJSON, messages_log: SealedNDJSON)`：`create_session(title)->dict`（session_id=uuid4().hex；`session_secrets_ct`=封缄 `{k_t1,session_salt,t2_key}` hex；空 `session_mapping_ct`）；`add_message(session_id, role, llm_view, mapping_delta, reasoning_ct, files, chain_refs, reply_meta, verification, artifacts)->dict`（msg_id="msg_"+hex12；`mapping_delta_ct`=封缄本轮 `{replacement:value}`；session_mapping_ct 合并后重封缄，追加式写 sessions log 新版本行）；`restore_view(session_id, llm_view)->str`（解封全量映射做替换还原，跨会话抛 `ValueError`）；`list_messages(session_id)`（动态还原 user_view）；`get_message(message_id)`；`open_tokenizer(session_id)->Tokenizers`
- **验收标准:** ① 加密往返还原一致 ② **多轮共指**：轮 2 引用轮 1 实体可还原（Review Focus 1）③ 跨会话 restore 被拒 ④ 序列化记录无 `user_view` 键、明文值不出现在落盘字符串（SEC-STORE-1 主断言）⑤ 重启后（重建 SessionStore）可继续 add_message 且 T1 共指稳定
- **依赖:** Task 1、Task 3
- **工作量:** M（1.5 天）

### Task 8: `chat_service.py` — 单轮编排 + provider 封缄 + 入链

- **输入:** `guard._apply_tokens`（`proxy.py:357`）、`guard._build_file_payloads`（:365）、`guard._dedup_tokens`（:405）、`guard._verify_v2`（:415）、`guard.model_cert`、`guard.llm.provider_signer`、`MockLLM._response_hash`；`build_outbound`/`verify_outbound`（`schemas.py:259/:298`）；Task 4/6/7
- **输出:** `backend/app/chat_service.py`：`ChatService(guard, sessions: SessionStore, gateway: LLMGateway, chain: HashChain, chain_log: SealedNDJSON)`；`run_turn(session_id, text, files, on_event)->dict` 八阶段：detect→tokenize→package→hash→dispatch→verify→restore→persist，每阶段 `on_event("stage", {stage,status,t_ms})`；dispatch 组 `[system]+历史(llm_view/content only)+新出站文本` 并把 token 转 `on_event("token", {delta,reasoning})`；provider 封缄 = `response_hash=MockLLM._response_hash(output, req.input_hash, guard.model_cert, nonce, ts)` + `signature=provider_signer.sign(...)`；verification=`guard._verify_v2(resp, req)`（incomplete 时响应完整性行置 `ok=None, detail="跳过(不完整)"`，status="incomplete"）；入链 USER_OVERRIDE/FILE_COMMIT/QUERY 带 message_id，`chain_log.append(entry)` 写穿，回填 `chain_refs`；返回 `{message_id, verification, chain_refs, incomplete, degraded}`
- **验收标准:** ① 全轮（MockChat）产出双视角消息 + 带 mid 链条目 + chain_refs 双向一致 ② 空白输入抛 ValueError 不入链 ③ 断流（stub gateway）→ 已收内容落盘 + incomplete + Review Focus 2 断言 ④ degraded="mock" 透传到 reply_meta ⑤ reasoning 只存 reasoning_ct 不进下一轮 prompt
- **依赖:** Task 2、4、6、7
- **工作量:** L（2 天）

### Task 9: `main.py` — 会话 API + SSE 单流 + 限流

- **输入:** Task 8 `run_turn`/`on_event`；FastAPI `StreamingResponse`；spec §3.4/§3.5
- **输出:** 路由：`POST/GET /api/chat/sessions`、`GET /api/chat/sessions/{sid}`、`POST /api/chat/sessions/{sid}/messages`（body `{text, files:[{filename,content_b64}]}`，响应 SSE 单流：`event: stage|token|done|error`，`data:` JSON，`on_event` 经 `queue.Queue` + executor 泵入生成器）；限流：会话级滑窗 10 条/分钟 → 429；空白 text → 400；`LLMFailure(protocol)` → `event: error {class:"protocol"}`，未分类 → `{class:"internal"}`（fail-closed）
- **验收标准:** ① TestClient 收到的 SSE 帧序列 stage×8→token*→done ② 第 11 条 429（Review Focus 4：空输入 400）③ protocol 错误不出 mock 回复 ④ done 帧含 message_id/chain_refs/verification
- **依赖:** Task 8
- **工作量:** M（1 天）

### Task 10: 查看器 API（pipeline / chain / proof / preimage）

- **输入:** Task 7/8 消息记录（含 `artifacts`：outbound dump、canonical_preimage、tokens、entities）；`MerkleTree.proof/verify_proof`（`merkle.py:48/:61`）；`h_hex`（`canon.py:44`）
- **输出:** 路由：`GET /api/messages/{id}/pipeline` → `{message, user_view, artifacts, verification, chain_entries(by chain_refs), files}`；`GET /api/chain` → `{chain(含 message_id), chain_valid, chain_root, merkle, count}`（verify 结果按 `(len(entries), root)` 缓存，入链失效）；`GET /api/chain/entry/{i}/proof` → `{index, leaf, proof, root, verified}`（全链叶子集建树）；`POST /api/verify/preimage` body `{preimage: dict, expected_hash: str}` → **纯数据** `{preimage, expected_hash, recomputed_hash, match}`（UI 中性表述，不下结论）
- **验收标准:** ① pipeline 一次取全且 user_view 动态还原 ② proof 经 `verify_proof` 数据自洽 ③ preimage 端点四字段返回且 `match` 仅是两值比较布尔 ④ 链缓存：连续两次调用第二次免重算、入链后失效
- **依赖:** Task 8
- **工作量:** M（1 天）

### Task 11: 启动接线（bootstrap + lifespan + 失败路径）

- **输入:** Task 1/3/4/7/8；`guard` 单例（`proxy.py:648`）
- **输出:** `backend/app/bootstrap.py`：`build_chat_service(data_dir: Path, gateway: LLMGateway|None=None) -> ChatService`（顺序：Vault.load_or_init → 建三个 SealedNDJSON（chain/sessions/messages）→ `replay_chain` → 载 sessions/messages（校验双向索引 mid↔chain_refs）→ 组 ChatService）；`main.py` lifespan 调用并挂 `app.state.chat`；启动三失败（指纹不符/key 缺失/回放不匹配）→ **启动终止 + logger.critical**，不带病服务
- **验收标准:** ① tmp 目录 build→写数条→重建实例→会话/链/消息可还原（SEC-REPLAY-1 主断言）② 篡改链一字节 → `StoreIntegrityError` 且构建抛出 ③ 指纹不匹配 → `VaultKeyError` ④ 跨段轮转后启动回放通过
- **依赖:** Task 1、3、4、7、8
- **工作量:** M（1 天）

### Task 12: `acceptance.py` + 验收 API（/demo 抽屉数据源）

- **输入:** `tests/detection_golden.py` 的 `evaluate()`/`wilson_ci()` + `tests/golden_gen.py` 的 `build_golden_set()`（repo 根 tests/）；spec §6.2/§6.3
- **输出:** `backend/app/acceptance.py`：`run_golden()->dict`（evaluate + P/R/FPR + Wilson CI，含 per-type）；`scan_plaintext_leaks(data_dir)->dict`（扫 *.ndjson 逐行 JSON，递归键名查 `user_view`/`reasoning_content`/裸 `mapping`，返回 `{checked_files, leaks:[]}`）；`replay_report()->dict`（尝试 build_chat_service，返回 `{ok, chain_entries, sessions, messages}` 或 `{ok:false, error}`）；`degrade_demo(kind)->dict`（stub Mimo 抛三类故障经真 LLMGateway，返回 `{kind, ui_class, degraded, incomplete}` 行为三元组）；路由 `GET /api/acceptance/{golden|store-scan|replay}`、`POST /api/acceptance/degrade {kind}`
- **验收标准:** ① golden 返回含 tp/fp/fn/p/r/fpr/ci 键 ② 埋入 `user_view` 键的假行 → leaks 非空（SEC-STORE-1 演示按钮真报）③ replay_report 于完好目录 ok=true ④ degrade_demo 三类与 spec §5 表逐格一致（SEC-DEGRADE-1）
- **依赖:** Task 11
- **工作量:** M（1 天）

### Task 13: 前端骨架（AppShell + 三路由 + api.js SSE 客户端）

- **输入:** 现有 `frontend/src/api.js` `req()`、`App.jsx`、Tailwind 配置；spec §4.0
- **输出:** `App.jsx`：路由 `/chat`(默认)、`/inspect/:messageId?`、`/demo`(现有 Console 包一层沙箱徽章壳)、`*`→`/chat`；`AppShell.jsx`：极简顶栏（Logo + 三入口切换，主色靛蓝、浅底大留白、密码学数据等宽字体的全局 CSS 约定）；`api.js` 增 `createSession/listSessions/getSession/sendMessageSSE(messagePipeline/chainStatus/chainEntryProof/verifyPreimage/acceptanceRun`：`sendMessageSSE(sessionId, payload, handlers)` 用 fetch+ReadableStream 解析 `event:/data:` 帧分发到 handlers（vitest 覆盖：多帧粘包、reasoning 轨、error 帧）
- **验收标准:** ① 三路由可达、顶栏切换正常 ② SSE 解析器 vitest：粘包/分轨/error 帧三用例全绿 ③ `npx vitest run` 全绿（含现有 console 测试）
- **依赖:** Task 9、10（端点契约已定即可并行开发，真后端联调归 Task 17）
- **工作量:** M（1 天）

### Task 14: `/chat` 聊天页

- **输入:** Task 13 骨架与 SSE 客户端；spec §4.1
- **输出:** `frontend/src/chat/`：`ChatPage.jsx`（会话侧栏 + 消息流 + 输入区）、`PrivacyStatusBar.jsx`（常驻：检测引擎/通道 MiMo|Mock降级黄/哈希链 N条·校验/vault 状态）、`UserBubble.jsx`（user_view 明文 + 300ms debounce 检测高亮下划线 + 文件卡片 + 复制/查看过程）、`AssistantBubble.jsx`（折叠 reasoning 标"仅本地显示·不参与后续对话" + 降级黄条/不完整黄徽章）、`Composer.jsx`、`SendProgress.jsx`（八阶段节点由 stage 事件点亮，token 事件逐字渲染）
- **验收标准:** ① 发送→八节点依次点亮→回复逐字出现→"查看过程"跳 `/inspect/:id` ② 敏感片段发送前高亮 ③ 三失败态内联（protocol 红条/network 黄条/stream 黄徽章）④ 刷新后会话与消息仍在（持久化联通）⑤ vitest：SendProgress 状态机 + UserBubble 高亮渲染
- **依赖:** Task 13
- **工作量:** L（2 天）

### Task 15: `/inspect` 双视角查看器

- **输入:** spec §4.2 区块表与六失败态；Task 10 端点
- **输出:** `frontend/src/inspect/`：`InspectPage.jsx`（视角 Tab + 消息定位条 + 直接访问时"最近消息"列表）、`PrivacyView.jsx`（明文/出站并排 Diff、出站包收据、T1-T4 令牌清单+泄漏函数悬停、"LLM 视角原始 JSON"折叠面板）、`AuditView.jsx`（八阶段时间线、链窗口高亮 chain_refs 双向跳转、Merkle 证明面板、独立复算面板三值中性比对+复制、四层验证+归约徽章、reasoning 密文解封仅本地）、`states.jsx`（骨架屏/消息不存在/链条目缺失红框/校验失败红态/不完整黄条/降级黄徽章）
- **验收标准:** ① 从聊天点入与 URL 直达两路径可用 ② 隐私视角只显加密后内容+本地明文对照 ③ 审计视角 proof/preimage 数据齐全且无"验证结论"措辞 ④ 六失败态全覆盖（vitest 逐态渲染）
- **依赖:** Task 13、14
- **工作量:** L（2 天）

### Task 16: `/demo` 验收清单抽屉 + 沙箱徽章

- **输入:** 现有 `console/AppendixDrawer.jsx` 模式、Step1-6 按钮；Task 12 验收 API；spec §6.3 映射表
- **输出:** `DemoPage.jsx` 壳（"演示沙箱"徽章 + 顶栏提示"此模式写入沙箱链，不影响真实审计数据"）；`AcceptanceDrawer.jsx`：每行 = 验收项|达标线|实测值|▶运行按钮——Golden Set→`/api/acceptance/golden` 混淆矩阵卡；PERF→TimingBar+跑 PERF；BIND→Step3 篡改按钮组；SEC-ATK/ISO/PACK→现有 Step5/6 按钮跳转；SEC-STORE→`/api/acceptance/store-scan`；SEC-REPLAY→`/api/acceptance/replay`；SEC-DEGRADE→`/api/acceptance/degrade`（三选一注入）
- **验收标准:** ① spec §6.3 表 11 行全部有可点击入口 ② 三条新用例按钮返回真结果 ③ 现有 Console 六步功能零回归（`npx vitest run` + 手点冒烟）
- **依赖:** Task 12、13
- **工作量:** M（1.5 天）

### Task 17: 全量回归 + README + 交付收尾

- **输入:** 全部前序任务；spec §6（引用前置 spec 指标）
- **输出:** ① `cd backend && py -m pytest tests/ -q` 全绿（109 基线 + 各任务新用例）② `cd frontend && npx vitest run` 全绿 ③ 手动冒烟：`start.bat`→聊天全流程（含文件）→查看器双视角→/demo 验收抽屉逐条点 ④ README 增"对话模式/查看器/持久化"章节与 `data/` 布局说明 ⑤ 附录 A 修正 18 条全部落实对照清单 ⑥ commit + 交付
- **验收标准:** 两套测试全绿；SEC-STORE-1/REPLAY-1/DEGRADE-1 三用例落地并通过；README 与实现一致；无明文落盘（store-scan 实跑 leaks=[]）
- **依赖:** 全部
- **工作量:** M（1 天）

---

## 依赖图

```
T1 keys ──┬─► T3 store ──► T4 replay ──┐
T2 chain(mid) ────────────────────────┤
                                      ├─► T8 chat_service ──► T9 API(SSE) ──┐
T5 llm 契约 ──► T6 MimoLLM/Gateway ────┤                                     │
T7 sessions(依赖 T1,T3) ──────────────┘                                     │
                                                                            ▼
T10 viewer API(依赖 T8) ──► T11 bootstrap(依赖 T1,3,4,7,8) ──► T12 acceptance ──┐
                                                                                │
T13 前端骨架(依赖 T9,T10 契约) ──► T14 /chat ──► T15 /inspect                    │
                                     └────► T16 /demo 抽屉(依赖 T12) ◄───────────┘
                                                          └─► T17 全量回归
```

**并行建议（subagent-driven）:** T1/T2/T5 可三路并行；T3/T6 次波；T7/T8 串行关键路径；T13 与 T11/T12 可并行；T14/T15 顺序（复用组件）；T16 与 T15 可并行。

**总计:** 17 任务 · 约 16 人日 · 关键路径 T1→T3→T7→T8→T9→T13→T14→T15→T17。
