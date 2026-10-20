# CryptoGuard-LLM 分级令牌化升级 · 设计 Spec

> **历史归档（2026-10）**：本文描述的是已删除的演示平台（`/api/*`、文件上传、
> 密码学实验室等），不代表当前实现，也不应作为部署依据。当前网关文档见
> [GATEWAY.md](../../GATEWAY.md)。

日期:2026-10-11
状态:待用户审阅
范围:把占位符替换从"正则脱敏"升级为"密码学令牌管道",覆盖文件上传,UI 收敛为协议叙事单线。

---

## 0. 问题与目标

**现状缺陷**:`detection.py` 产出 `[NAME_1]` 式占位符,替换一步零密码学含量(可预测、可枚举、无绑定性)。评委质疑靶心:"这不就是正则替换吗?"另外:①令牌化后数值无法计算;②文件上传内容(含文件名)不在保护范围;③UI 存在为展示而展示的页面。

**目标**:每个脱敏产物都是密码学对象(PRF 伪名 / FF1 密文 / 保序编码 / 同态密文),每层泄漏显式声明,文件纳入同一管道,每个 UI 元素标注其证明的安全性质。

**成功标准**:
1. 面对"这不就是正则替换吗",能指着令牌方案给出归约(PRF / 强 PRP / 泄漏函数声明 / 抗第二原像绑定);
2. 模型侧可计算:共指、格式校验、比较排序、算术统计各有路径;
3. 文件链路覆盖:文本脱敏 + 整文件存证必做,OCR + 密文检索演示可选;
4. UI 无冗余:无安全语义的元素不渲染;
5. 性能承诺:密码学开销 <20ms(P95),端到端 <500ms(P95),吞吐 ≥100 QPS。

**术语修正(写入答辩口径)**:HMAC 伪名**不是**承诺方案(无 hiding/binding 打开语义)。正确表述:**PRF 伪名 + 令牌链哈希绑定进 input_hash**,防张冠李戴的性质由**抗第二原像**归约承担。

---

## 1. 分级令牌方案(核心)

### 1.1 分层定位

- **必做核心**:T1 不透明伪名、T2 格式保留加密;
- **可选增强**:T3 保序令牌、T4 同态密文——演示限数据量(≤20 个数值),不达标不影响主链路。

### 1.2 密钥层级(全本地)

```
master_key (本地随机 256-bit,不出内存)
 ├─ HKDF → k_T1 (伪名密钥)     ├─ HKDF → k_T2 (FF1 密钥)
 ├─ HKDF → k_T3 (保序密钥)     └─ HKDF → k_T4 → Paillier 密钥对
session_salt: 每对话会话随机 128-bit(伪名跨会话不可关联)
vault: 映射表 AES-GCM(vault_key)加密;vault_key 可被 CP-ABE 策略包裹
       (沿用现有 Shamir 门限教学级实现,继续诚实标注"非配对群 CP-ABE")
```

### 1.3 令牌构造

**T1 不透明伪名**(姓名/组织/项目代号/PHI 词/地址/文件名):

```
raw  = HMAC-SHA256(k_T1, type ‖ 0x00 ‖ value ‖ 0x00 ‖ session_salt)   # 域分隔用 0x00
token = Base32(raw[:16]).lower()                                       # 128-bit 截断,26 字符
展示形: [NAME#a3f9b2c1d0]  (token 前 10 字符;全量 token 参与比对与绑定)
```

- 截断 **128-bit**(非 64-bit):共指碰撞概率降至 2⁻⁶⁴ 量级;会话内查表兜底,碰撞则加长后缀。
- 同会话同值 → 同令牌(共指消解);跨会话换 salt → 不可关联。
- **归约**:PRF 安全。**不承诺**:不抗同值频率统计(同名出现次数可见)。

**T2 格式保留加密**(身份证/手机/银行卡):

```
身份证: 前 17 位 FF1 加密,校验位按 ISO 7064 MOD 11-2 重算
卡号:   前 15 位 FF1 加密,Luhn 校验位重算
手机:   首段 1[3-9] 不动,后 9 位 FF1(泄漏:首 2 位,声明)
```

- **库选型:调用标准 FF1/FF3 库(`ff3` 或 `pyffx`,锁版本),禁止手写 Feistel**。
- 模型可校验 18 位/11 位/Luhn —— 格式可计算。
- **归约**:强 PRP。**显式泄漏**:长度、字符类、(手机)首段。
- **实测校准义务**:FF1 单价必须实测;若 P95 >2ms/个,降级为"格式校验演示"(演示令牌 ≤5 个),降级横幅常驻步骤②顶部,不静默降级(见 §6.3)。

**T3 保序令牌**(金额/年龄/日期,可选增强):

```
简化 OPE: 值 v ↦ 秩 + 随机间隔(几何分布采样,单调保序)
确定性同值同密文;状态表本地保存
静态集合边界: 仅支持演示前固定的 ≤20 个数值,不支持动态插入(OPE 动态插入是开放难题,不冒充解决)
降级路径: 分桶保序模拟(约 50 行,桶边界公开声明)
```

- **UI 强制徽章 `⚠️ 泄漏:序关系`**(含等值性),无此徽章的 T3 元素不渲染。
- **归约**:泄漏函数显式声明(序关系 + 等值性)。

**T4 同态密文**(需算术/统计的数值,可选增强):

```
c = Paillier.Enc(pk, v)  随文本出站
模型输出结构化计算指令(不信任自由输出,见 §3.4):
  { op: "sum"|"mean"|"count"|"min"|"max", tokens: [...], result_ref: "c_01" }
计算网关(本地)白名单校验 → 同态聚合
聚合结果默认只回显给用户;用户显式勾选授权后才回传模型继续对话
```

- **归约**:DCR。**泄漏**:密文形态零泄漏;聚合结果回传是用户显式决策。

### 1.4 还原路径(仅本地)

| 层 | 还原方式 |
|---|---|
| T1 | 查加密映射表(AES-GCM 解密) |
| T2 | FF1 逆变换 + 校验位恢复 |
| T3 | 查 OPE 状态表 |
| T4 | Paillier 私钥本地解密 |

**映射表记录结构**:`token → {type, value, tier, leak_class}`,整表 AES-GCM 加密。

---

## 2. 文件双通道

### 2.1 策略路由(默认拒绝)

**可读通道的准入条件是"检测可信",不是"文件类型支持"。**

| 文件类型 | 路由 | 依据 |
|---|---|---|
| TXT / MD / CSV / DOCX / 含文本层 PDF | 可读通道(必做) | 抽取可靠,检测召回有保障 |
| 扫描版 PDF / 图片 | 默认只走存证通道;OCR 为可选演示开关 | OCR 漏检 = 明文泄露 |
| 二进制(zip/exe/加密 PDF) | 只走存证通道 | 无法检测,零可读承诺 |
| 超限(>5MB / >50k 字符) | 拒绝 + 明确报错 | 演示环境边界 |

### 2.2 可读通道(必做)

```
extract_text():  python-docx / pypdf / csv(表格按行展开)
extract_meta():  文件名本身走 T1 令牌化 ← 文件名常含患者姓名
detect_sensitive(): 同一检测器、同一 session_salt → 跨模态共指
T1-T4 令牌化  → redacted_content 随出站请求内联
```

**跨模态共指**:同一会话内聊天与文件共享 `k_T1 ‖ session_salt`,「张三」在聊天和病历里生成同一个令牌。

**FilePayload 结构**(入 OutboundRequest):

```
{ file_ref: "f_01", filename_token: "[FNAME#7c2a…]", content_tier: "readable"|"evidence",
  redacted_content: str|null,        # evidence 级恒 null
  file_content_hash: hex|null,       # readable 级必填(预哈希,见 §3.1)
  file_hash: hex }                   # 必填 = SHA-256(raw_bytes)
```

### 2.3 存证通道(必做)

```
file_hash   = SHA-256(raw_bytes)                     # 原始文件,永不出本地
vault_ct    = AES-GCM(vault_key, raw_bytes‖filename) # 本地存证
log_entry   = H("FILE_COMMIT" ‖ filename_token ‖ file_hash ‖ prev_entry)  # 入哈希链
```

**与四层协议的绑定**:`file_content_hash` 进 `input_hash`(§3.1)。改文件内容 → `file_content_hash` 失配;换文件内令牌 → `token_root` 失配;两者打穿 `input_hash` → 层 3 响应签名绑定失效。**文件篡改成为层 3 可检测事件,不需要新协议层。**

**争议双向可验**:用户出示 vault 明文重算 `file_hash` 对链(防"我没传过");服务商出示签名的 `response_hash`(防"你偷换了我的文件回应")。

### 2.4 可选演示(不接主链路)

| 模块 | 形态 | 诚实边界 |
|---|---|---|
| 图片 OCR | `pytesseract` 抽文本→同套检测→令牌化**独立预览面板** | 误检/漏检传导至脱敏质量;演示限预置清晰样张;**不回流主链路** |
| 文件密文检索 | 文件关键词 → 现有 SSE 索引 | 访问模式泄漏沿用现有声明 |

**OCR 异步隔离时序**:

```
主线(同步,<500ms): 上传扫描件 → 路由=存证 → file_hash 入链 → 前端立即「🔒 已锁定为存证文件,模型不可读」
旁路(fire-and-forget): OCR worker 池 → 抽文本→检测→令牌化 → 完成后弹独立预览面板
预览不回流、不修改已发请求、不参与 input_hash
```

### 2.5 错误处理

| 故障 | 处理 |
|---|---|
| 抽取失败(损坏/加密) | 拒可读通道,降级存证 + 前端明示"已按存证处理,模型不可读" |
| 抽取文本为空(纯图) | 同上,提示"疑似扫描件,可开 OCR 演示" |
| 低置信度实体(<0.6) | 待确认清单,三选一(放行/手动替换/强制脱敏)+ `user_ack` 强制勾选;**不静默放行** |
| 文件名纯符号 | 文件名原样进存证,不进可读通道 |

### 2.6 明确不承诺

1. 可读通道保密性 = **检测召回率的函数**——漏检实体以明文出站,这是 NLP 路线固有边界;
2. 文件版式(合并单元格/页眉页脚)抽取时丢失;
3. OCR 不承诺医疗级精度。

---

## 3. 协议定稿

### 3.1 哈希前映像标准(JCS,修正:不裸用 json.dumps)

**唯一规范化函数**:`jcs` 或 `canonicaljson` 库(RFC 8785 JSON Canonicalization Scheme),锁版本。禁止手写 TLV,禁止裸用 `json.dumps` 做哈希前映像。

```
canon(obj) = jcs.canonicalize(obj)          # bytes, RFC 8785
H_hex(obj) = sha256(canon(obj)).hexdigest()
```

**令牌绑定链(顺序累加,线性无树)**:

```
chain_0 = H_hex({"d": "CG/TOKEN_CHAIN/v2", "prev": null, "sid": session_id})
chain_i = H_hex({"d": "CG/TOKEN_CHAIN/v2", "prev": chain_{i-1}, "t": type_i, "k": token_i})
token_root = chain_n                          # n 个令牌 = n 次哈希
```
(所有哈希前映像统一 JCS 化,无字节拼接、无歧义。)

**文件内容预哈希**(大文件不进总哈希):

```
file_content_hash = H_hex({"d": "CG/FILE_CONTENT/v2", "c": redacted_content})
```

**override 绑定(简化:数组直哈希,无并行链)**:

```
override_hash = H_hex({"d": "CG/OVERRIDE/v2", "e": override_events})   # 空数组同样有确定哈希
```

**总绑定**:

```
input_hash = H_hex({
  "d": "CG/INPUT/v2",
  "t": H_hex({"d": "CG/TEXT/v2", "x": redacted_text}),
  "f": [file_content_hash_1, …, file_content_hash_k],
  "r": token_root,
  "o": override_hash,
  "n": nonce,
  "ts": timestamp })
```

大文本/大文件一律先预哈希再入总哈希——主链路哈希前映像恒为小对象,杜绝大文件哈希超时。

**response_hash**(结构不变,仅域分隔标签升级):

```
response_hash = H_hex({"d": "CG/RESP/v2", "out": output, "ih": input_hash,
                       "cert": model_cert, "n": nonce, "ts": timestamp})
sig = Ed25519.Sign(sk_provider, response_hash)
```

### 3.2 出站请求 Schema(后端模板拼装,强约束)

出站包由**后端模板组装**,任何字段不来自自由文本拼接。Pydantic 严格模型(禁 `extra`):

```
OutboundRequest {
  schema_version:  "CG/2.0"            # 常量;不匹配则网关拒绝
  session_id:      hex32
  redacted_text:   str
  file_payloads:   [FilePayload]       # 0..8
  token_index:     [TokenRef]          # 出站令牌全集(白名单)
  override_events: [OverrideEvent]     # 可空
  token_root:      hex64
  input_hash:      hex64
  nonce:           hex32
  timestamp:       ISO8601(UTC, μs 精度)
}
TokenRef    { token, type, tier: "T1"|"T2"|"T3"|"T4", leak_class }
OverrideEvent { event_id, entity_span: [start,end], entity_type,
                original_token, action: "force_allow"|"manual_replace"|"force_redact",
                replacement: str|null, user_ack: bool, ts }
```

**网关校验规则**(违反即拒 + 记审计事件):

1. 正文/文件中出现的所有令牌 ⊆ `token_index`;
2. 每个令牌的 HMAC/FF1 重算值与声明一致(防中间层塞私货令牌);
3. `input_hash` 重算一致才放行出站。

### 3.3 四层协议映射(字段级)

| 层 | 字段 | 覆盖攻击 | 归约 |
|---|---|---|---|
| 1 输入绑定 | `input_hash`(含 token_root + file_content_hash + override_hash)、`nonce`(128-bit)、`timestamp`(5 分钟窗) | 重放、输入替换、令牌张冠李戴、文件偷换、抵赖放行决策 | 抗第二原像 + 新鲜性 |
| 2 模型身份 | `model_cert = Sign(sk_auditor, model_id‖version‖release_date‖model_hash)` | 伪造模型声明 | EUF-CMA(审计机构) |
| 3 响应完整 | `response_hash`(§3.1)+ Ed25519 签名 | 篡改响应(含文件回应) | EUF-CMA(服务商) |
| 4 可审计日志 | `log_entry_i = H_hex({"d":"CG/LOG/v2","ty":entry_type,"p":payload_digest,"ts":ts,"prev":log_entry_{i-1}})` + 周期 Merkle | 日志篡改、抵赖 | 抗第二原像 |

层 4 `entry_type` 枚举:`QUERY`(→input_hash) / `FILE_COMMIT`(→file_hash‖filename_token) / `USER_OVERRIDE`(→override_events) / `COMPUTE_GATE`(→指令‖结果摘要/拒绝原因)。用户决策、文件存证、计算网关动作全部成为链上不可抵赖事件。

**Merkle 打包触发器(显式)**:每 **10 条日志或 5 分钟**(先到者)打包一次;步骤⑥提供**「立即打包」按钮**(<50ms 出根),演示不等定时器。

### 3.4 计算网关(不信任模型自由输出)

```
ComputeDirective { op: "sum"|"mean"|"count"|"min"|"max",   # 白名单枚举
                   tokens: [str],    # 必须 ⊆ token_index 且 tier ∈ {T3,T4}
                   result_ref: "c_01" }
```

- Pydantic 校验 + 枚举白名单 + tokens 越权检查(引用不在 `token_index` 的令牌 → 拒绝 + `COMPUTE_GATE` 事件入链,含拒绝原因);
- 演示指令由**预置 Mock JSON 模板注入**,模型自由生成部分只有自然语言输出与选填字段——解析失败在演示中不存在;
- Mock 文件 JSON 负载同样强 Schema 约束(§3.2),后端模板拼装。

### 3.5 USER_OVERRIDE 事件流(不可抵赖的隐私决策)

低置信度实体(<0.6)→ 待确认清单 → 用户三选一 + `user_ack` 强制勾选 → 事件入 `override_events` 数组 → 数组整体哈希进 `input_hash`(§3.1)→ 链上落 `USER_OVERRIDE` 条目。

**双向不可抵赖**:用户说"我没允许发"→ 链上有 `force_allow` + `user_ack=true` + 已绑定进被签名的 `input_hash`,诬告被证伪;用户说"系统偷发"→ 链上无事件而出明文,系统责任可证。

---

## 4. UI 单线协议叙事

### 4.0 形态:一路由 · 六步 · 一抽屉

```
┌────────────────────────────────────────────────────────────────┐
│ 常驻横幅:威胁模型四角色 │ 明确不承诺 ×3 │ [附录抽屉▾]          │
├────────────────────────────────────────────────────────────────┤
│ ①输入 → ②令牌化 → ③出站包 → ④四层验证 → ⑤攻击注入 → ⑥审计链    │
├────────────────────────────────────────────────────────────────┤
│ 当前步骤视图(单一活动区)                                        │
├────────────────────────────────────────────────────────────────┤
│ 计时条(真实时间戳,无模拟动画)                                    │
└────────────────────────────────────────────────────────────────┘
```

- 单路由 + `useReducer` 步进状态机(答辩不切页);步骤事件走 `/ws/pipeline`;
- **UI 零自算**:不自行计算任何哈希/签名,只渲染后端返回值;`schema_version` 不匹配整页拒绝渲染;
- **计时条真值**:直接渲染 WebSocket 推送的真实时间戳;Mock 延迟由**后端 sleep 50–100ms** 模拟,帧内携带 `mock_sleep_ms` 字段,前端如实标注"Mock 模拟延迟",不做模拟动画。

### 4.1 铁律:无徽章不渲染

任何 UI 元素必须能回答"展示哪条安全性质",答不出就砍。

| 徽章 | 语义 | 归约 |
|---|---|---|
| `🔒 PRF` | 伪名不可区分 | HMAC PRF |
| `🔒 强PRP` | 格式保留加密 | FF1(泄漏显式列出) |
| `⚠️ 泄漏:序关系` | OPE 固有泄漏 | 泄漏函数声明 |
| `🔒 DCR` | 同态密文 | Paillier |
| `🔗 抗第二原像` | 绑定/不可偷换 | 哈希链 |
| `✍️ EUF-CMA` | 不可伪造签名 | Ed25519 |
| `🛡 审计签名` | 模型声明可信 | 审计机构 |
| `⏱ 防重放` | 5 分钟窗 + nonce | 新鲜性 |
| `📄 完整性存证` | 文件承诺 | SHA-256 |
| `👤 不可抵赖` | 用户决策入链 | USER_OVERRIDE |
| `⚠️ NLP·非密码学` | 诚实标注检测层 | — |

### 4.2 六步要点

**① 输入**(对话 / 文件 Tab):实时高亮(徽章 `⚠️ NLP·非密码学`——主动戳破"这不就是正则",叙事接"检测是正则,产物从这一步起进入密码学管道,请看②");文件拖放即时路由徽章(`📄 可读通道` / `🔒 存证通道`);待确认清单 + `user_ack`;override 芯片条(标注"数组整体哈希→input_hash");文件名预览(`🔒 PRF`)。

**② 令牌化**:四级令牌芯片(蓝T1/紫T2/橙T3/绿T4,各带泄漏徽章);跨模态共指连线演示;token_root 顺序链滚动动画(`🔗 抗第二原像`);映射表保险库(AES-GCM 块 + CP-ABE 策略树);芯片悬停卡(归约 + 泄漏函数全文);FF1 降级横幅(如触发,常驻顶部)。

**③ 出站包**:Wireshark 风格收据块;**前映像面板**——JCS 规范化字符串放在**可折叠、可滚动代码块,支持复制,默认折叠**(修正:防撑爆页面),配 `input_hash` 计算式实值代入(徽章 `🔗 可复算`,评委可现场重算);明文/出站 Diff 切换(`🔒 出站无明文`);nonce/时间窗可视化(`⏱`)。

**④ 四层验证**:逐项打勾动画(公式实值 + 归约徽章);计时条展开为分段瀑布(真实值);还原预览四行分列(`🔒 还原仅本地`);五态状态机(正常→验证中→通过绿✓→失败红✕→告警橙⚠)。

**⑤ 攻击注入**(8 攻击,**沙箱化**):

| # | 攻击 | 拦截 | 徽章 |
|---|---|---|---|
| 1 | 篡改响应 | 层 3 哈希失配 | ✍️ |
| 2 | 重放 | 层 1 nonce/时间窗 | ⏱ |
| 3 | 伪造 cert | 层 2 审计签名 | 🛡 |
| 4 | 篡改日志 | 链断 + Merkle 路径失败 | 🔗 |
| 5a | 用户诬告(声称错误输入) | input_hash 重算失配 | 🔗 可复算 |
| 5b | 服务商抵赖(否认收到该输入) | 签名覆盖的 input_hash 与链上一致 | ✍️ |
| 6 | 令牌张冠李戴 | token_root 失配 | 🔗 |
| 7 | 文件内容偷换 | file_content_hash 失配 | 📄 |
| 8 | 注入非法令牌 | 计算网关白名单拒 → COMPUTE_GATE 入链 | 👤 |

- **沙箱隔离(修正)**:攻击注入走独立"被篡改快照"状态,**绝不污染主哈希链与会话状态**;一键重置按钮恢复;主链在 8 攻击全注入后 `verify()` 仍为真。
- **攻击 8 闭环(修正)**:「注入非法令牌」按钮由前端手动构造越权令牌(如 `[FAKE#deadbeef]`),触发网关拒绝并写入 `COMPUTE_GATE` 审计事件(含拒绝原因),断言闭环。
- 每攻击:注入 → 红闪 → **失败传播动画**(断点沿协议链回溯)→ 话术卡(答辩台词)。

**⑥ 审计链**:哈希链滚动视图(四色 entry_type);打包触发器徽章(倒计时 + **「立即打包」按钮**);Merkle 树 + **篡改完整动画**(点篡改→链断红闪→路径逐节点变红,动画由真实验证结果驱动);争议解决面板(双向验真)。

### 4.3 砍除清单(12 页 → 1 控制台 + 1 抽屉)

| 现有页面 | 处置 |
|---|---|
| Home.jsx | 降级为常驻横幅 |
| Chat.jsx + Detect.jsx | 合并 → 步骤① |
| Entities.jsx | 并入步骤② |
| Pipeline.jsx + Outbound.jsx + Verify.jsx | 重组 → ②③④ |
| Attack.jsx / Audit.jsx | → ⑤ / ⑥(补 3 攻击、2 动画) |
| CryptoLab.jsx | 删独立页;SSE/HE/ZKP → 附录抽屉"可选增强" |
| Perf.jsx | 删独立页;计时条内嵌④ + 抽屉"性能实测"面板 |
| Compliance.jsx | 删独立页;抽屉"HIPAA/PCI-DSS 映射" |

### 4.4 动效白名单

实体→令牌形变(替换发生)/ token_root 链环滚动(绑定)/ 四层打勾(逐层验证)/ 攻击失败传播(断点定位)/ Merkle 路径变红(篡改定位)。转场渐变、粒子背景、视差滚动全删。

---

## 5. 性能预算与实测校准

### 5.1 预算(密码学 <20ms 硬指标)

| 操作 | 单价 | 30 令牌/请求 | 归属 |
|---|---|---|---|
| T1 HMAC(128-bit 截断) | <0.01ms | ~0.3ms | 核心 |
| T2 FF1(标准库) | **实测,预算 2ms/个** | ~5ms(10 个) | 核心 |
| T3 OPE | ~0.05ms/个 | ≤1ms | 可选 |
| T4 Paillier | ~5ms/个 | **异步旁路**,不进主预算 | 可选 |
| token_root 顺序链 | ~0.01ms/个 | ~0.3ms | 核心 |
| input_hash(JCS 小对象) | <0.05ms | 恒定 | 核心 |
| file_content_hash(≤50k 字符) | ~0.2ms/文件 | ~0.4ms | 核心 |
| AES-GCM vault | <1ms | ~1ms | 核心 |
| Ed25519 签+验 | <1ms | ~1ms | 核心 |
| 哈希链追加 | <0.05ms | ~0.05ms | 核心 |
| **核心合计** | | **≈8–10ms,2 倍余量** | <20ms |

端到端 <500ms:密码学 ~10ms + 检测 ~15ms + Mock 50–100ms + 序列化/传输。吞吐(架构定稿,修正):CPU 密集密码学会阻塞 asyncio 事件循环,**单进程承诺作废**——密码学/检测走 `run_in_executor` 线程池,uvicorn 多 worker(`--workers`,按 CPU 核数)部署;≥100 QPS 由**多 worker + 线程池**架构承载,vault/哈希链用细粒度锁。

### 5.2 降级预案(写死在代码)

- FF1 实测 P95 >2ms/个 → 降级"格式校验演示",演示令牌 ≤5 个,横幅常驻步骤②;
- T3 超预算 → 分桶保序;
- T4 不启用不影响主链路;
- 文件超限 → 截断报错,不静默慢哈希。

### 5.3 测试环境规格(所有性能数字的前提)

| 项 | 规格 |
|---|---|
| CPU | AMD Ryzen 7 7735H (8C/16T) |
| RAM | 16 GB |
| OS | Windows 11 Home China 26200 |
| Python | 3.13.14 (MSC v.1944, AMD64) |
| cryptography | 43.0.1 |
| FastAPI / uvicorn / pydantic | 0.115.0 / 0.30.6 / 2.9.2 |
| FF1 库 | 首选 `ff3`(FF3-1);装不上降级 `pyffx`。实现首日实测定选,锁版本 |
| JCS 库 | `pip install jcs canonicaljson` **首日双装实测**;`canonicaljson` 必须先过 RFC 8785 符合性测试(浮点序列化、Unicode NFC/NFD、字符串转义),不过则用 `jcs`;定选后锁版本 |

---

## 6. 测试与验收

### 6.1 检测指标(Golden Set 400 单元)

**指标口径**:

```
准确率 Precision = TP/(TP+FP)  > 95%     召回率 Recall = TP/(TP+FN)  > 90%
误报率 FPR      = FP/(FP+TN)  <  5%     (片段 = 分句单元)
```

**Golden Set 构成(400 文本单元)**:

| 子集 | 规模 | 作用 |
|---|---|---|
| 模板生成(真值自动已知) | 120 | 13 类实体×变体铺满(校验位合法/非法对、Luhn 通过/不过对) |
| 人工标注自然文本 | 100 | 医疗/金融病历、流水单;实体共现、嵌套 |
| **对抗性负例** | **150** | 订单号似卡号(Luhn 挂)、日期似手机号、版本号似 IP、长小数似证件号——FPR 主战场 |
| 跨模态变体 | 30 | 同一实体置于聊天/CSV/DOCX/PDF 文本层 |

**统计显著性(修正)**:对抗负例 150 单元提供 ≥400 个非敏感分句,使 FPR 的 Wilson 95% 置信区间半宽 **≤±3%**;报告给出点估计 + CI,不给裸数。

**跑法**:`tests/detection_golden.py` 全量回归,输出 per-type 与 overall 混淆矩阵;指标不达标 CI 红。诚实边界:指标是**该测试集上的实测值**,不承诺对抗性变形输入(同音字、零宽字符)。文件链路单列"抽取损耗"行(抽取丢字归因抽取器,不算检测器,如实展示)。

### 6.2 安全测试用例

**A. 协议绑定属性**(pytest,断言到具体公式):

| # | 用例 | 断言 |
|---|---|---|
| BIND-1 | 换 `token_index` 任一令牌 | `input_hash` 重算失配,网关拒 |
| BIND-2 | JCS 稳定性:同数据不同键序/空白 | 规范化字节串逐字节相等 |
| BIND-3 | 改文件 `redacted_content` 一字节 | `file_content_hash` 失配拒绝 |
| BIND-4 | 声称无放行但链上有 `force_allow` | `override_hash` 与 `input_hash` 不符,诬告证伪 |
| BIND-5 | 空数组/全空格/Unicode NFC-NFD | 无异常、哈希稳定 |
| BIND-6 | JCS RFC 8785 符合性测试向量(浮点 1.0/1e3/小数、Unicode NFC/NFD、引号/反斜杠/控制字符转义) | 规范化输出与 RFC 8785 官方测试向量逐字节一致;`jcs` 与 `canonicaljson` 双库交叉验证一致才定选 |

**B. 八攻击回归**(沙箱内执行,即演示脚本自动化):

SEC-ATK-1 篡改响应→层3红;2 重放→层1拒;3 伪造cert→层2拒;4 篡改日志→链断+Merkle 路径红;**5a 用户诬告**(声称错误输入)→ input_hash 重算失配、争议面板出示链上证据;**5b 服务商抵赖**(否认收到该输入)→ 用户侧 vault+redacted_text 重算出的 input_hash 与服务商签名覆盖的 response_hash 内含 input_hash 一致,抵赖证伪;6 令牌张冠李戴→token_root 失配;7 文件偷换→file_content_hash 失配;**8 注入非法令牌**→ 前端按钮构造越权令牌 → 网关白名单拒 → `COMPUTE_GATE` 事件入链、`payload_digest = H(指令‖拒绝原因)` 可查。

**C. 沙箱隔离**:

| # | 断言 |
|---|---|
| SEC-ISO-1 | 8 攻击全注入后主链 `verify() == True`,被篡改仅存在于 snapshot 对象 |
| SEC-ISO-2 | 一键重置后状态(链/token_root/统计)与攻击前 dump 逐字段相等 |
| SEC-ISO-3 | 会话 A 攻击中,会话 B 正常查询不受污染 |

**D. 打包与审计**:

| # | 断言 |
|---|---|
| SEC-PACK-1 | 「立即打包」<50ms 出根、根上链、membership 路径验证通过 |
| SEC-PACK-2 | 满 10 条自动打包;5 分钟定时(假时钟) |
| SEC-PACK-3 | 篡改已打包区间 → 叶到根路径逐节点验证失败,动画由真实结果驱动 |

**E. 密码原语回归**:AES-GCM 篡改拒、Ed25519 负例、哈希链逐环、FF1 逆变换+校验位(身份证 MOD 11-2 / 卡号 Luhn 正反例)、OPE 序保持(静态集合内全对比较 `a<b ⟹ E(a)<E(b)`,≤20 值 → ≤190 对全验)、Paillier 同态正确性、SSE 召回。

### 6.3 性能与真值测试

| # | 用例 | 方法 | 达标线 |
|---|---|---|---|
| PERF-TRUTH-1 | 计时条真值 | **三处统一保留 2 位小数**(后端计时值→WS 帧→DOM 同源格式化);断言一:三处字符串逐字节相等;**断言二:后端原始值与帧值差 <0.01ms**;`mock_sleep_ms` 字段必须存在且与帧内 LLM 段一致 | 双断言全过 |
| PERF-BUDGET-1 | 密码学开销 | 去掉 Mock sleep,P95 | <20ms |
| PERF-BUDGET-2 | 端到端 | 含 Mock 50–100ms,P95 | <500ms |
| PERF-BUDGET-3 | 吞吐 | Locust 100 VU × 60s | ≥100 QPS |
| PERF-FF1-1 | FF1 实测校准 | 1000 次加密 P95;超 2ms/个**自动触发降级横幅**,测试同时验证降级路径被真实触发 | ≤2ms/个 或降级可观测 |
| PERF-LEAK-1 | 泄漏标注完备 | 遍历所有 T2/T3 令牌,UI 必含泄漏徽章 | 100%,无徽章即 fail |

### 6.4 ProVerif 模型与代码对齐

**A. 建模范围**(诚实边界):

| 建模 | 不建模(文档明示) |
|---|---|
| 层1 输入绑定(token_root/file_hash/override_hash) | NLP 检测质量 |
| 层2 model_cert 签名链 | T3 泄漏(声明的泄漏函数,非攻击面) |
| 层3 响应签名 + 域分隔 | T4 与计算网关 |
| 层4 哈希链前向完整性 | 侧信道、密钥托管、OCR |
| 防重放(nonce+时间窗) | 服务商主动调包(既有不承诺) |

**B. 字段对照表**(双向勾稽;ProVerif `fun` 元数 == 代码函数参数数;协议字段变更两处同 PR 内改完):

| 协议字段 | ProVerif 构造 | 代码实现 | 公式出处 |
|---|---|---|---|
| `token_root` | `fun tokroot(bitstring,bitstring):bitstring` 链式 | `proxy.py::token_chain()` | §3.1 |
| `input_hash` | `fun inputhash(...)` 7 元(d,t,f,r,o,n,ts) | `proxy.py::input_hash()` | §3.1 |
| `model_cert` | `fun cert(...)` 4 元 | `mock_auditor.py` | §3.3 |
| `response_hash` | `fun resp_hash(...)` 6 元(d,out,ih,cert,n,ts) | `mock_llm.py::_response_hash` | §3.1 |
| `log_entry` | `fun logent(...)` 5 元(d,ty,p,ts,prev) 链 | `hashchain.py` | §3.3 |

**C. 验证查询(合法 ProVerif 语法 + 预期 RESULT 字符串,修正)**:

```proverif
(* 1. 无服务商私钥不能伪造响应:接受响应 ⇒ 服务商确实签过 *)
query attacker(sk_provider).
(* 预期: RESULT not attacker(sk_provider) is true. *)

query x: bitstring; event(resp_accept(x)) ==> event(provider_sign(x)).
(* 预期: RESULT event(resp_accept(x)) ==> event(provider_sign(x)) is true. *)

(* 2. 无审计机构私钥不能伪造模型声明 *)
query x: bitstring; event(cert_accept(x)) ==> event(cert_issued(x)).
(* 预期: RESULT event(cert_accept(x)) ==> event(cert_issued(x)) is true. *)

(* 3. 重放被检测:nonce 单次使用状态建模,断言 nonce 复用不可达 *)
query n: bitstring; event(nonce_reused(n)).
(* 预期: RESULT not event(nonce_reused(n)) is true.
   (部分 ProVerif 版本输出 "RESULT event(nonce_reused(n)) is false." —— 同为通过,
    以实装版本输出为准,原样归档 /formal/) *)

(* 4. 映射表密钥不出本地 *)
query attacker(vault_key).
(* 预期: RESULT not attacker(vault_key) is true. *)

(* 5. 出站包无明文敏感数据 *)
query attacker(plain_secret).
(* 预期: RESULT not attacker(plain_secret) is true. *)
```

注:`==>` 为合法对应关系语法;不使用 `== false` / `⟹ 矛盾` 等伪语法。每条查询产出:ProVerif 源码 + 原始输出(含预期 RESULT 行)+ 一句话人话解释,归档 `/formal/`,截图入答辩卡。

### 6.5 验收矩阵

| 承诺 | 验证 | 达标线 |
|---|---|---|
| 准确率 >95% / 召回率 >90% / 误报率 <5% | Golden Set 400(§6.1) | 实测值 + Wilson CI(FPR ±3%) |
| 密码开销 <20ms | PERF-BUDGET-1 | P95 |
| 端到端 <500ms | PERF-BUDGET-2 | P95 |
| 吞吐 >100 QPS | PERF-BUDGET-3 | 实测 |
| 防重放 5 分钟窗 | SEC-ATK-2 + 假时钟边界 | 窗内拒/窗外拒 |
| 无伪造响应 | ProVerif 查询 1 + SEC-ATK-1/3/6 | RESULT 符合预期 |
| 出站无明文 | BIND 族 + ProVerif 查询 5 | 双重验证 |
| 回答质量下降 <5% | 双盲人工评:同题原始 vs 令牌化各 **50 题**,Likert 5 级量表评分,标注**「小样本探索性评测」**(不冒充统计学显著结论);评测表随提交包 | 均分差 <5% |

---

## 7. 明确不承诺清单

1. 不证明大模型内部实际计算了什么(非 zkML);
2. 不承诺防服务商主动调包(除非加 TEE);
3. 不承诺防服务商偷懒计算;
4. 可读通道保密性 = 检测召回率的函数,漏检即泄露(NLP 路线固有边界);
5. T3 显式泄漏序关系与等值性;T2 显式泄漏长度/字符类/手机首段;T1 不抗同值频率统计;
6. SSE 访问模式泄漏沿用既有声明;
7. 文件版式不保真;OCR 不承诺医疗级精度;
8. 指标为指定测试集与测试环境(§5.3)上的实测值。

---

## 附录 A:实现要点与依赖变更

**新增依赖**(锁版本):`ff3` 或 `pyffx`(FF1)、`jcs` 或 `canonicaljson`(JCS)、`pytesseract`(OCR,可选)、`pypdf`、`python-docx`(抽取)、`locust`(压测)。

**改动面**:`detection.py` 输出升级为带 tier 的令牌;`proxy.py` 哈希公式换 JCS + 顺序链;`schemas.py` 新 OutboundRequest/FilePayload/TokenRef/OverrideEvent/ComputeDirective;`mock_llm.py` 模板拼装 + 50–100ms sleep + mock_sleep_ms 字段;前端 12 页重组为六步控制台 + 附录抽屉;新增文件上传 API 与 OCR worker。

**不改动**:四层协议骨架、`model_cert`/`response_hash` 结构、CP-ABE/SSE/Paillier/ZKP 模块、攻击演示总体形态。

## 附录 B:本 Spec 的决策记录

| 决策 | 出处 | 理由 |
|---|---|---|
| 伪名≠承诺,归约改口 | 术语修正 | 答辩严谨性 |
| T1 截断 128-bit | 用户修正 | 共指碰撞 2⁻⁶⁴ |
| T2 标准 FF1 库 + 实测校准降级 | 用户修正 | 不手写密码;性能不撒谎 |
| T4 网关白名单 + 预置 Mock 指令 | 用户修正 | 不信任模型自由输出 |
| 绑定用顺序哈希链,不用 MerkleRoot | 用户修正 | 主链路零树开销;Merkle 留给日志层 |
| 默认拒绝路由 + 文件名令牌化 | 第 2 节决策 | 答辩标准答案 + 真实泄露点 |
| USER_OVERRIDE 入链绑定 | 用户修正 | 用户决策不可抵赖 |
| 哈希前映像用 JCS 库 | 用户修正 | 消灭拼接歧义与字节序 bug |
| override_events 数组直哈希 | 用户修正 | 降状态机复杂度 |
| Mock 延迟 50–100ms 后端 sleep | 用户修正 | 端到端演示流畅,前端不撒谎 |
| Merkle 每 10 条/5 分钟 + 立即打包 | 用户修正 | 演示不等定时器 |
| 攻击沙箱化 + 一键重置 | 用户修正 | 演示鲁棒性,不污染主链 |
| 计时条真值 2 位小数 + <0.01ms 断言 | 用户修正 | 可复现 |
| ProVerif 合法语法 + 预期 RESULT | 用户修正 | 语法正确性 |
| Golden Set 400 + 对抗负例 150 | 用户修正 | 统计显著性 FPR ±3% |
| SEC-ATK-5 拆 5a/5b | 用户修正 | 诬告与抵赖是两个方向 |
| 吞吐改 run_in_executor 线程池 + uvicorn 多 worker | 用户修正 | asyncio 单进程被 CPU 密集密码学阻塞,是伪承诺 |
| ProVerif 查询 1 改 provider_sign 对应、查询 3 改 nonce 单次使用状态建模 | 用户修正 | 语法合法且与实现语义一致 |
| JCS 双库首日实测 + RFC 8785 符合性向量(BIND-6) | 用户修正 | canonicaljson 不保证严格 RFC 8785 |
| token_root 链全 JCS 化 | 用户修正 | 所有哈希前映像统一,消灭拼接歧义残留 |
| T3 明确静态集合边界 ≤20 个数值,不支持动态插入 | 用户修正 | OPE 动态插入是开放难题,不冒充解决 |
| 质量评测扩 50 题 + Likert 量表 + 「小样本探索性」标注 | 用户修正 | 20 题样本量不配称评测 |
