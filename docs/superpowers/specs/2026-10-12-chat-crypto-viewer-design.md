# CryptoGuard 对话式前端与密码过程查看器 · 设计 Spec

> **历史归档（2026-10）**：本文描述的是已删除的演示平台（聊天查看器、LLM 配置页、
> `/demo` 等），不代表当前实现，也不应作为部署依据。当前网关文档见
> [GATEWAY.md](../../GATEWAY.md)。

> 前置 spec:`2026-10-11-crypto-token-upgrade-design.md`(CG/2.0)。本 spec **不改动** CG/2.0 的协议、令牌方案与验收指标;新增:会话层、真实 LLM 网关、双视角过程查看器、轻量持久化。
> 状态:**待审阅**。日期:2026-10-12。

## 0. 问题与目标

CryptoGuard 现状是"六步控制台"式单次提交演示:流水线完整,但不是 agent 体验。本 spec 交付三件事:

1. **`/chat`** — ChatGPT 式对话:会话列表、消息气泡、文件卡片、真实大模型(mimo-v2.6-flash)流式回复;
2. **`/inspect/:messageId`** — 单页双视角"密码过程查看器":隐私视角看"加密后到底发给了大模型什么",审计视角看"哈希链等背后逻辑";
3. **`/demo`** — 现有六步控制台原样保留,降级为演示导览,写入独立沙箱链。

成功标准:比赛演示时,评委能直观看到 **对话在跑、隐私被保护、过程可审计** 三件事,且验收清单每项在 /demo 有可点击入口。

## 1. 决策记录(需求澄清)

| # | 决策 |
|---|---|
| 1 | 聊天为主路由;六步控制台保留为 `/demo` 演示模式,新旧内容不重复建设 |
| 2 | LLM 接真实 API:mimo-v2.6-flash,OpenAI 兼容 `https://api.xiaomimimo.com/v1/chat/completions`;key 只在 `backend/.env`,前端零接触;MockLLM 仅作网络层降级 |
| 3 | 查看器单页双视角(隐私/审计 Tab),从聊天消息"查看过程"点入 |
| 4 | 后端轻量落盘(NDJSON),会话与哈希链重启不丢 |
| 5 | 总体方案 A:后端会话化 + 双视角历史 + LLM 网关 + 查看器验证 API |

**核心概念:同一段对话有两份真相。** `llm_view`(token 空间,模型实际收到)与 `user_view`(本地还原明文)。聊天历史与查看器都围绕双视角组织;LLM 多轮上下文只喂 `llm_view`,明文永不出本地。

## 2. 总体架构

### 2.1 路由(前端三入口,顶栏极简切换)

| 路由 | 内容 | 受众 |
|---|---|---|
| `/chat` | 对话主页(默认首页) | 所有人 |
| `/inspect/:messageId` | 过程查看器(单页双视角) | 隐私用户 / 审计员 |
| `/demo` | 现有六步控制台 + 沙箱徽章 | 比赛讲解 |

### 2.2 新增模块(其余复用 CG/2.0 流水线)

- **`llm.py`** — LLM 网关:`MimoLLM`(真实 API,流式)+ `MockLLM`(现有,仅网络层降级)。失败三分类见 §3.2。
- **`sessions.py`** — 会话与双视角消息:每条消息存 `llm_view` + 加密映射增量,`user_view` 动态还原,永不落盘。
- **`store.py`** — NDJSON 落盘(`data/`)、启动回放验链、链轮转、双向索引。

### 2.3 单轮消息数据流("实时"关键路径)

```
用户输入(+文件) ──► POST /api/chat/sessions/{sid}/messages   (SSE 单流)
  ① 文件本地抽取→检测→令牌化→存证三件套,然后才组出站包(原文不出本地)
  ② 敏感检测→令牌化→出站包(llm_view)→input_hash→入哈希链
       └── event: stage 各阶段推送 ──► 前端八节点进度动效
  ③ LLM 网关:[system]+历史(llm_view)+新出站文本 ──► MiMo 流式
       └── event: token(reasoning/content 分轨) ──► 前端逐字渲染
  ④ 回程四层验证→本地还原(user_view)→双视角落盘(含双向索引)
       └── event: done ──► 挂"查看过程"入口
```

### 2.4 查看器数据流

`GET /api/messages/{id}/pipeline` 一次取全该消息产物(检测命中、令牌分级、出站包、canonical preimage、验证结果、链条目);审计视角追加 `GET /api/chain/entry/{i}/proof`(Merkle 单条证明,`merkle.py:proof/verify_proof` 首次 API 化)与独立复算数据。**UI 零自算**:前端只渲染后端字段,不生成任何哈希。

## 3. 后端组件

### 3.1 密钥与信任根(`backend/.env`)

```
MIMO_API_KEY=sk-…            # 真实 LLM key(用户提供)
VAULT_KEY=<32B hex>          # 根密钥,仅首次启动生成
```

| 派生密钥 | HKDF info | 用途 |
|---|---|---|
| `mapping_key` | `mapping/v1` | AES-GCM 封缄映射表(`session_mapping_ct` / `mapping_delta_ct`) |
| `reasoning_key` | `reasoning/v1` | AES-GCM 封缄 `reasoning_ct` |
| `chain_mac_key` | `chain-mac/v1` | `entry_checksum`(见 §3.3 边界声明);沙箱链用 `chain-mac/demo/v1` |

- `.env` 进 `.gitignore`。
- **VAULT_KEY 变更检测**:`data/vault_key_fingerprint.txt = SHA-256("vault-fp/v1" ‖ key)`。启动比对:**指纹在而 key 缺失 → 启动失败**(禁止静默生成);**key 在而指纹不符 → 启动失败 + 报错"密钥已变更,历史数据将不可解封"**;仅两者皆无才首次生成并同时写入。

### 3.2 `llm.py` — LLM 网关(失败三分类)

```
LLMGateway.chat(messages, on_stage) -> ReplyStream
├── MimoLLM   # OpenAI 兼容,stream=True
└── MockLLM   # 现有模板引擎,仅 network 类降级时启用
```

- **调用**:`POST https://api.xiaomimimo.com/v1/chat/completions`,`model=mimo-v2.6-flash`,默认 `max_completion_tokens=1024, temperature=1.0, top_p=0.95`(可配)。认证:**双头并存**——`Authorization: Bearer <key>`(OpenAI SDK 标准)与 `api-key: <key>`(经 `default_headers` 附加)同时携带,无须探测服务端接受哪一种。
- **入参**:`[system] + 历史(仅 llm_view/content) + 新出站文本`。
- **流式**:`reasoning_content` 与 `content` 分轨透传,**两者完整落盘**(`reasoning_content` 落 `reasoning_ct`);历史轮 reasoning **不进后续 prompt**(只回传 content),消除令牌语义侧信道;`max_reasoning_chars` 截断上限防异常长。
- **`classify_failure(exc) -> network | protocol | stream`**,行为逐格见 §5 表:**network 切 Mock 降级;protocol(4xx 含 429)直接报错不降级;stream 保留已收 token + `incomplete=true` 不切 Mock**。

### 3.3 `sessions.py` + `store.py` — 双视角存储与落盘

**消息记录(NDJSON 一行,行级 `entry_checksum` 同法封缄)**:

```json
{ "type": "message", "id": "msg_…", "session_id": "ses_…", "role": "user|assistant",
  "ts": …, "llm_view": "…", "mapping_delta_ct": "b64(nonce|ct|tag)",
  "reasoning_ct": "…|null",
  "files": [{"name": "…", "file_hash": "…", "channel": "readable|evidence"}],
  "chain_refs": [12, 13],
  "reply_meta": {"model": "mimo-v2.6-flash", "incomplete": false, "degraded": null},
  "verification": {"input": "pass", "model_id": "pass", "response": "pass", "audit": "pass"} }
```

- **`user_view` 不落盘**:`llm_view` 已是脱敏文本;读取时解封 `session_mapping_ct` 对 `llm_view` 逆向还原出 `user_view`,仅存在于内存与响应体。
- **映射表两级**:**会话级 `session_mapping_ct`**(本会话全量映射,每轮合并后重封缄,跨轮共指可还原)+ **消息级 `mapping_delta_ct`**(本轮增量,用于令牌归属/链条目归因/单条审计)。解封必须校验 `session_id`,**跨会话拒绝**。
- **双向索引落盘**:消息写入时先入链、回填 `chain_refs[]`;链条目同步写 `message_id`。两向都持久化,不靠运行时遍历。
- **启动回放 `store.replay()`**:按 index 扫全部链段,逐条验 `prev_hash→hash` 链接 + 逐条验 `entry_checksum`;**任一不匹配 → 启动失败 + `logger.critical` 告警**,拒绝带病服务。
- **`entry_checksum` 边界声明**:`entry_checksum = HMAC-SHA256(chain_mac_key, JCS(entry 除 checksum 外))`,**仅声明为"损坏检测"**(bit-rot、半截写入、误截断),报错可区分"文件损坏"vs"链断";**不声称防恶意篡改**——能写数据目录者必能读 .env 伪造 MAC。防篡改声明完全由哈希链(链接校验)承担,信任根为 Merkle 打包 root 的**导出锚点**(审计员自行留存比对)。UI/文档一律称"文件校验和(损坏检测)"。
- **链轮转**:`chain.ndjson` 按 5000 条或 10MB 轮转至 `data/chain/seg-*.ndjson` 归档;链跨段连续(entry 自带完整 `prev_hash`);回放按 index 扫全段。
- **文件**:上传后本地 `extract_text → detect → tokenize → evidence_bundle`,**然后**才组出站包;原文不落盘不出本地。

### 3.4 SSE 协议(单流,`POST /api/chat/sessions/{sid}/messages`)

阶段事件与 LLM token 走**同一路 SSE**,`event:` 字段区分,不开第二通道:

| event | 载荷 | 用途 |
|---|---|---|
| `stage` | `{stage: detect→tokenize→package→hash→dispatch→verify→restore→persist, status, t_ms}` | 八阶段实时动效 |
| `token` | `{delta, reasoning}` | 逐字渲染(reasoning/content 分轨) |
| `done` | `{message_id, chain_refs, verification, incomplete, degraded}` | 收尾,挂"查看过程" |
| `error` | `{class: protocol|internal, message}` | 协议层错误直接报错 |

### 3.5 API 一览(新增为主,旧端点保留给 /demo)

| 端点 | 说明 |
|---|---|
| `POST/GET /api/chat/sessions` · `GET /api/chat/sessions/{sid}` | 会话创建/列表/详情,消息列表(动态还原 user_view) |
| `POST /api/chat/sessions/{sid}/messages` | 发消息,SSE 单流;**限流**:令牌桶默认每会话 10 条/分钟(可配),超限 429 |
| `GET /api/messages/{id}/pipeline` | 查看器全量产物(§2.4) |
| `GET /api/chain` | 链状态;**verify() 结果按链头条数+末哈希缓存**,入链即失效 |
| `GET /api/chain/entry/{i}/proof` | Merkle 单条证明 + verify_proof 数据 |
| `POST /api/verify/preimage` | **纯数据返回** `{preimage, expected_hash, recomputed_hash, match}`;UI 中性表述"两值一致/不一致",明示以审计员独立工具复算为准,服务端不下"验证结论" |

### 3.6 /demo 沙箱链

`AttackSandbox` 注入、篡改、/demo 全部写操作进入**沙箱链**(内存 + 可选 `data/demo-chain.ndjson`),与生产链物理隔离;checksum 密钥派生 info 标签独立(`chain-mac/demo/v1`),杜绝串写。SEC-ISO 保证不变。

## 4. 前端组件与信息设计

### 4.0 设计基调与组件树

简洁大方:浅色底、系统字体、大留白、单一主色(靛蓝系);**密码学数据一律等宽字体**(哈希/密文/preimage/JSON dump)可一键复制。状态色语义全局统一:绿=通过 / 黄=降级·不完整 / 红=失败 / 灰=无数据。**UI 零自算**。

```
AppShell(极简顶栏: Logo + /chat /inspect /demo 切换)
├── ChatPage
│   ├── PrivacyStatusBar(常驻)   ├── SessionSidebar   ├── MessageList
│   │   ├── UserBubble(实时检测高亮 · 文件卡片 · 查看过程)
│   │   └── AssistantBubble(折叠 reasoning · 降级/不完整徽章 · 查看过程)
│   ├── Composer(多行输入 + 附件 + 发送)   └── SendProgress(八阶段,单 SSE 驱动)
├── InspectPage(双视角)   └── DemoPage(现有 Console + 沙箱徽章 + 验收清单抽屉)
```

### 4.1 /chat

- **隐私状态栏(顶部常驻)**:`检测引擎 ON·13类 | 通道: MiMo / Mock降级(黄) | 哈希链: N条·校验通过 | vault: 已解封`。
- **消息流**:user 气泡 = `user_view` 明文,发送前 300ms debounce 实时检测高亮(复用现有检测),敏感片段下划线;assistant 气泡含可折叠"思考过程"(标注"仅本地显示·不参与后续对话")。
- **文件卡片**:发送前显示本地处理进度(抽取→检测→通道判定);气泡内卡片 = 文件名 + 哈希短显 + 通道徽章。
- **发送实时感**:单 SSE 驱动八阶段节点依次点亮,随后回复逐字渲染。
- **失败态内联**:protocol 红条(不降级)/ network 黄条"已切换模拟回复" / stream 黄徽章"回复不完整"。
- 每条消息操作行:`复制 · 查看过程(→/inspect/:messageId)`。

### 4.2 /inspect(单页双视角)

顶部:视角 Tab **【隐私视角】【审计视角】** + 消息定位条(会话/轮次/角色/时间);直接访问 URL 时先显示"最近消息"选择列表。

**隐私视角 —— "加密后到底发给了大模型什么"**

| 区块 | 内容 |
|---|---|
| 明文/出站对照 | 左 `user_view`(仅本地)| 右 `llm_view`(模型实际收到),并排 Diff |
| 出站包收据 | token_root、input_hash、nonce+5 分钟窗、file_payloads 双通道徽章 |
| 令牌清单 | T1-T4 分级芯片 + 泄漏函数声明(悬停卡) |
| LLM 视角原始 JSON | 完整出站包 dump(mono、可复制)"这就是大模型看到的全部" |

**审计视角 —— "背后逻辑"**

| 区块 | 内容 |
|---|---|
| 流水线时间线 | 八阶段耗时 + 各阶段输入/输出摘要,点击展开 |
| 哈希链定位 | `chain_refs` 高亮链窗口(前后各 N 条,四色 entry_type),消息↔链双向跳转 |
| Merkle 证明 | 单条 proof 路径 + root + verify_proof 数据 |
| 独立复算面板 | canonical preimage 全文 + `expected_hash / recomputed_hash / match` 三值中性比对 + "复制复算材料";明示以独立工具为准 |
| 四层验证 | 输入绑定/模型身份/响应完整/审计日志 + 归约徽章 |
| reasoning 密文 | `reasoning_ct` 解封仅本地展示,标注"不参与多轮回传" |

**六种失败态线框**:载入中(骨架屏)/ 消息不存在(空态+返回)/ 链条目缺失(红框定位缺失 index)/ 校验失败(红态定位到层)/ 不完整回复(黄条)/ Mock 降级(黄徽章)。

### 4.3 /demo

现有六步控制台**原样迁入,零重写**;仅加"演示沙箱"徽章 + 顶栏提示"此模式写入沙箱链,不影响真实审计数据",并新增**"验收清单"抽屉**(§6.3)。

## 5. 错误处理汇总(与 §3.2 classify_failure 逐格对齐)

| 分类 | 判定 | UI 表现 | 日志/落盘 | 降级? |
|---|---|---|---|---|
| **network** | 超时/连接失败/5xx | 状态栏转黄"Mock 降级中";气泡黄条"已切换模拟回复";/inspect 挂"Mock 降级"黄徽章 | `logger.warning(network_degrade)`;`reply_meta.degraded="mock"` | **✅ 切 Mock** |
| **protocol** | 400/401/429 等 4xx | 气泡内红条(429→"请稍后再试");无 assistant 回复体;状态栏不变 | `logger.error(protocol_error)`;SSE `event: error {class:"protocol"}` | **❌ 不降级** |
| **stream** | 读流中途断 | 已收 token 保留渲染 + 黄徽章"回复不完整";验证层标"跳过(不完整)" | `logger.warning(stream_interrupt)`;`reply_meta.incomplete=true` | **❌ 不切 Mock** |

**其余错误通道**(同表风格,不与三分类交叉):内部未分类异常 → `event: error {class:"internal"}` + 红条,fail-closed;限流 429 属 protocol 类;启动三失败(回放验链不匹配 / VAULT_KEY 指纹不符 / 指纹在而 key 缺失)→ **启动终止 + 明确报错**,不带病服务。

## 6. 测试与验收(引用 CG/2.0 Spec §6,零新造指标)

### 6.1 指标口径全部沿用

准确率/召回/FPR(Golden Set 400,前置 spec §6.1)、密码开销 <20ms / 端到端 <500ms / 吞吐 >100 QPS(PERF-BUDGET-1..3)、防重放/无伪造/出站无明文(§6.5)。**本 spec 不定义新达标线**。

### 6.2 回归即验收

chat 出站包走同一 `build_outbound`/JCS 路径 → **BIND-1..6 原样重跑**;沙箱链沿用 `AttackSandbox` → **SEC-ATK-1..9、SEC-ISO-1/2/3、SEC-PACK-1..3 原样重跑**;现有 109 用例全绿是合入前提。**PERF 口径不变**:本地段预算照旧,MiMo 外呼时延单列"外部依赖"观测行,不计入 PERF-BUDGET。

**仅三条新增用例**(沿用前置 spec §6.2 命名族与断言风格,非新指标轴):

| # | 断言 |
|---|---|
| SEC-STORE-1 | 消息落盘后扫描数据目录,无 `user_view` / reasoning 明文(只允许 `llm_view`、`*_ct`) |
| SEC-REPLAY-1 | 篡改链文件任一字节 → 重启报"链断/损坏"且启动失败;完好文件 → 回放通过、会话可还原 |
| SEC-DEGRADE-1 | 三种故障注入(network/protocol/stream)→ 行为与 §5 表逐格一致 |

### 6.3 验收清单 ↔ /demo 按钮映射(评委逐条可点)

/demo 新增**"验收清单"抽屉**(复用 AppendixDrawer 模式):每行 = 验收项 | 达标线 | 实测值 | **▶ 运行按钮**:

| 验收项(前置 spec §6) | /demo 入口 |
|---|---|
| Golden Set 400(§6.1) | ▶ 跑 Golden Set → 页内混淆矩阵卡 |
| PERF-BUDGET-1/2/3、PERF-TRUTH-1 | TimingBar 计时条(现有)+ ▶ 跑 PERF |
| PERF-FF1-1 | Step2 T2 悬停卡(FF1 单价 + 降级横幅演示) |
| PERF-LEAK-1 | Step2 泄漏徽章全览(现有) |
| BIND-1..6 | Step3 收据 ▶ 篡改按钮组 |
| SEC-ATK-1..9 | Step5 九攻击一键注入(现有) |
| SEC-ISO-1/2/3 | Step5 ▶ 重置 + 主链 verify 状态条(现有) |
| SEC-PACK-1/2/3 | Step6 ▶ 立即打包/倒计时/篡改打包区间(现有) |
| SEC-STORE-1 | ▶ 验落盘无明文(新) |
| SEC-REPLAY-1 | ▶ 重启回放验链(新) |
| SEC-DEGRADE-1 | ▶ 三分类降级演示(新) |

沿用前置 spec §6.5 诚实边界原文:回答质量双盲评仍为人工项"未执行";ProVerif 待装实跑——清单如实标注,不造数。

## 7. 明确不承诺清单(在前置 spec §7 基础上新增)

1. **`entry_checksum` 不防恶意篡改**——仅损坏检测;能写数据目录的攻击者可伪造。防恶意篡改 = 哈希链 + 外部锚点比对(审计员自行留存打包 root)。
2. **MiMo 外呼时延与可用性**是外部依赖,不入性能预算;限流/配额错误按 protocol 类报错,不吞不降级。
3. **reasoning 侧信道防护**限于"加密落盘 + 不回传历史";不承诺流量分析等带外侧信道防护。
4. **真实模型回复质量**由 mimo-v2.6-flash 决定,本系统只保证脱敏与可验证,不保证回答正确性。
5. **持久化防的是磁盘损坏与意外丢失**,不承诺对抗拥有主机读写权限的攻击者(密钥与密文同机)。

## 附录 A:修正决策记录(设计评审两轮)

**第一轮(6 风险 + 4 细节)**:① user_view 不明文落盘(只存 llm_view + 加密映射,动态还原);② 单 SSE 流(event: 区分);③ MiMo 降级三分类(network 切 Mock / protocol 报错 / stream 保部分)+ reasoning_content 完整回传;④ 回放验链 + 校验和,失败即启动失败;⑤ 双向索引落盘(chain_refs ↔ message_id);⑥ /demo 独立沙箱链。细节:文件本地先行、/inspect 六失败态、映射表按会话隔离、/chat 隐私状态栏。

**第二轮(1 密码学矛盾 + 4 工程硬伤 + 3 细节)**:① MAC 边界显式声明(改名 entry_checksum,只防损坏,防篡改归哈希链);② reasoning 加密落盘 + 不进多轮回传;③ 映射表改 session_mapping_ct + mapping_delta_ct(跨轮共指可还原);④ /api/verify/preimage 纯数据返回,服务端不下结论;⑤ VAULT_KEY 指纹文件,变更即启动失败,禁止静默生成。细节:消息端点限流、链日志轮转、/api/chain 验证结果缓存。
