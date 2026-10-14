# LLM 安全中间件(CryptoGuard Middleware)—— 架构与配置

> 状态:第 4 阶段交付物。本文只描述 `backend/app/middleware/` 这一层的**实际实现**,
> 并明确标注它**不**承诺什么。测试证据与运行方式见 [MIDDLEWARE_TESTS.md](MIDDLEWARE_TESTS.md);
> 上层的演示平台(四层验证协议等)见仓库根 README.md 与 [ACCEPTANCE.md](ACCEPTANCE.md)。

## 1. 它解决什么问题

在 Agent(Codex / Claude Code 等)与模型服务商之间插一层网关:

```
Agent ──▶ CryptoGuard ──▶ Provider ──▶ CryptoGuard ──▶ Agent
           出站:识别+保护            回程:受控还原
```

- **出站**:识别请求里的敏感数据,按策略替换为占位符 / 令牌 / 密文令牌,再出网;
- **回程**:模型返回的令牌在**本请求自己的映射**下还原,高风险类别默认扣留;
- **全程**:每次调用写一条不含明文的审计记录,并提供 `/v1/verify` 让客户端自查。

关键点:**上游永远拿不到明文**;令牌只对签发它的那次请求有意义。本网关不声称上游
理解任何加密语义 —— 模式 C 的机密性来自「上游拿不到明文」,而不是「上游解不开密文」。

## 2. 三种保护模式

| 模式 | 配置值 | 出站形态 | 可还原性 | 适用 |
|---|---|---|---|---|
| A 占位符 | `placeholder` | `[PHONE_001]`、`[EMAIL_002]` | 本请求内可还原 | 可读性最好,形态可被嗅探者识别 |
| B 令牌 | `token` | `[CG_TOKEN_…]`(不可预测) | 本请求内可还原 | 不泄漏实体类型与序号 |
| C 加密 | `encrypt` | `[CG_ENC_v1_<seq>_<mac>]` | 本请求内可还原(映射以 AES-256-GCM 封缄) | 落盘/传输的映射不可解 |

三种模式的差别在**出站形态与映射的封缄方式**,不在「还原与否」——还原策略由
`CG_RESTORE_MODE` / `CG_RESTORE_CATEGORIES` 与风险等级共同决定,与模式正交。

**模式 C 的实现要点**(见 `app/crypto/aead.py`、`app/middleware/protection.py`):

- AES-256-GCM,32 字节密钥,96 位随机 nonce(`os.urandom(12)`),**每个值每次加密都不复用**;
- 认证标签由 GCM 自带,篡改密文/nonce/标签会导致解密失败(抛异常,不返回垃圾明文);
- 无 AAD(有意为之:密文封存的是值本身,不额外绑定上下文;这一点不提供「绑定到请求」
  的保证,请求级绑定由金库按 `request_id` 隔离来提供);
- 密钥来自 `VAULT_KEY` 经 HKDF-SHA256 的用途域 `protection-enc/v{n}`,不在任何地方另存明文副本。

**明确区分**(不得混用措辞):

- **脱敏(transport redaction)**:把明文换成令牌再出网 —— 这是本中间件的功能;
- **应用内数据加密(in-app encryption)**:把数据以密文形态落盘/在库内使用 —— 模式 C
  的映射封缄属于这一类(映射表以密文保存),但它**不是**「给上游的密文」。

## 3. 配置项

全部通过环境变量(`backend/.env`);完整示例见 [`backend/.env.example`](../backend/.env.example)。

| 变量 | 默认 | 说明 |
|---|---|---|
| `VAULT_KEY` | 无(必填,首次启动生成并写 `.env`) | 64 位十六进制信任根;所有子密钥由 HKDF 派生 |
| `CG_PROTECTION_MODE` | `placeholder` | `placeholder` / `token` / `encrypt` |
| `CG_RESTORE_MODE` | `categories` | `off` / `confirm` / `categories` / `auto` |
| `CG_RESTORE_CATEGORIES` | `EMAIL,IP,URL,ORG` | 允许自动还原的类别白名单 |
| `CG_BLOCK_ON` | `critical` | `none` / `high` / `critical`:达到该风险且建议阻断 → 拒发 |
| `CG_STABLE_TOKENS` | `0` | 1 = 模式 B 下同值复用同一令牌(便于共指,代价是等值泄漏) |
| `CG_VAULT_TTL_S` | `3600` | 请求级映射保留时长 |
| `CG_VAULT_MAX_REQUESTS` | `4096` | 同时保留映射的请求数上限(LRU 淘汰) |
| `CG_RESPONSE_SCAN` | `audit` | `audit`(响应侧只统计不回写)/ `off` |
| `CG_STREAM_BUFFER_CHARS` | `64` | 跨块检测窗口长度;决定计数滞后上限与内存占用 |
| `CG_CONFIRM_TTL_S` | `900` | 人工确认凭据有效期(必须 ≤ `CG_VAULT_TTL_S`) |
| `CG_CONFIRM_MAX_RECORDS` | `2048` | 进程内确认记录上限 |
| `CG_AUDIT_RETENTION_DAYS` | `30` | 审计保留期(0 = 永不清理) |
| `CG_ADMIN_TOKEN` | 无 | 管理接口令牌;未配置时管理接口一律 503(fail-closed) |
| `CG_BOOTSTRAP_KEY_FILE` | 无 | 开发环境首个客户端密钥写入的文件(勿提交) |

**客户端密钥与上游密钥严格分离**:客户端密钥只用于本网关认证,上游密钥只随出网请求
发往 provider;两者互不出现在对方的可见面里(有专测)。

## 4. 高风险数据的处理与人工确认

- **默认扣留**:风险等级高且类别不在白名单时,回程**不还原**(输出里保留令牌),
  并在响应元数据 `cryptoguard.restore.withheld` 里说明类别与原因;
- **受控释放**:客户端(必须是**同一次请求的发起者**)申请 → 管理员审批 → 一次性凭据 → 释放。
  状态机:`pending → approved → released(consumed)` / `denied` / `expired`;
- **铁律**:
  - 模型在回答里「请求还原」不等于批准(`acknowledged` 只是文本,不是授权);
  - 释放要求**身份认证 + 权限检查 + 请求上下文检查**,凭据绑定到客户端 / 请求 / 令牌集合;
  - 过期、复用、伪造、跨请求重放的凭据一律失败;
  - 一次申请多令牌是**全有或全无**(缺任一映射则整批失败,不部分释放);
  - 未确认 / 被拒 / 超时一律**安全失败**(保持扣留);
  - 审计记录 `pending / approved / released` 事件,只记令牌,**不记明文**;
- **诚实边界**:
  - 本实现不提供「已由人看过并同意」的密码学证明 —— 审批是**管理员信任边界**内的操作,
    审计只能证明「谁在什么时候批准了哪个凭据」;
  - 确认状态在**进程内**(重启即失效);单次使用的语义因此只在单进程内有效,
    多进程部署需要把凭据与状态外置到共享存储(本阶段未做);
  - 释放接口按设计返回明文(这正是它的用途),因此必须持有效凭据且单次使用。

## 5. 流式(SSE)处理与边界

- **令牌跨块**:回程用有界持留窗口(`MAX_TOKEN_LEN = 96` 字符)重组可能被切开的令牌;
  任何一次下发的增量都**不含半截令牌**。代价:首个字节最多多等一个令牌长度;
- **UTF-8 边界**:按字符(而非字节)切分与重组,多字节字符跨网络块不会被撕成 U+FFFD;
- **响应侧检测**:有界窗口(默认 64 字符)**整窗**识别;命中需拿到 1 个字符的后续上下文
  才计数(避免截断假命中),按「类型 + 绝对起始位置 + 值指纹」去重,同一处只计一次。
  **长度超过「窗口 − 1」的值在窗口式审计下不可检出** —— 这是本设计的硬边界;
- **只统计不回写**:模型输出可能被客户端当 JSON/代码解析,替换其中片段会破坏语义,
  因此响应侧检测只计数与告警。**上游若自己吐出明文,客户端仍会看到** —— 本中间件不篡改模型输出;
- **断流**:上游中断时以 `finish_reason=null` 收尾并标记 `complete: false`,不重试(可能已产出文案)、
  不重复输出、不凭金库凭空还原;
- **取消**:客户端断开 → 取消事件 → 关闭上游生成器(停止继续计费),资源有界。

## 6. 验证与审计

| 接口 | 权限 | 作用 |
|---|---|---|
| `POST /v1/verify` | 客户端(默认只能查自己发起的记录) | 校验某次调用的记录:存在性 / 摘要是否一致 / 记录 MAC / 审计链 |
| `GET /admin/audit`、`/admin/audit/{rid}` | 管理员 | 审计分页与单条 |
| `POST /admin/audit/verify` | 管理员 | 整链校验(full 可关闭以加速) |
| `POST /admin/audit/purge` | 管理员 | 按保留期清理(默认 dry-run) |
| `GET /health` | 公开 | 健康摘要,含审计链是否完整(不含任何密钥) |

**必须区分的三个结论**(任何一件成立都不蕴含另一件):

1. **记录完整性有效** —— 行级封缄(HMAC)、记录级 MAC(HKDF 域 `audit-mac/v1`)、哈希链自洽;
   它**不**代表上游没收到明文(记录里本来就不含明文,只记摘要与计数);
2. **响应摘要匹配** —— 客户端手里的字节与网关记录一致;它只说「没被改动」,
   不代表内容正确或安全;没提供待比对响应时结论是 `None`(不表态),不是 `true`。
   前映像覆盖**交付给客户端的响应**:文本、`finish_reason`、工具调用的
   `name` + `arguments`,以及**响应体里的 `model`**(即请求的 model —— 不是上游
   自述的模型名,后者客户端拿不到,用它复算会次次不一致);
3. **敏感数据保护成功** —— 上游收到的是令牌、明文的还原受策略限制。
   这由响应元数据 `restore` / 上游实际收到的报文来证明,`/v1/verify` **不**给这个结论。

**审计记录的硬约束**:绝不含原始 Prompt、原始敏感值、API Key、Authorization 头,
也没有任何可用于还原令牌的映射;`detections` 只记类别计数。

**如实标注的能力边界**(写在接口返回里,也写在这里):

- 哈希/HMAC/链只能证明「本地网关写下的东西没被改」,**不证明响应来自某个模型服务商**;
- **持 `VAULT_KEY` 者可整链重写**(重算封缄与 MAC),本地日志自校验会如实报告「完整」;
  检测整链重写需要站外锚点(`AuditStore.tip()` 给出的 `seq` + `chain_hash` 抄到别处);
- **尾段截断**同样不可由本地日志自证(实现文档已声明);
- 拒绝类请求只对**已认证**的调用落审计(否则任何人都能往磁盘灌记录,DoS 放大)。

## 7. 代码结构

```
backend/app/middleware/
├── deps.py            # 装配:Vault → 各子密钥 → registry / keyring / vault / audit / ...
├── config.py          # Settings / ProviderSettings(环境变量解析与校验)
├── routes.py          # /v1/*、/admin/* 全部端点(鉴权先于限流先于上游)
├── pipeline.py        # 出站保护 → 上游调用 → 回程还原 / 响应侧检测 / 审计
├── recognizers.py     # 检测:13 类基础规则 + 扩展规则(凭证/私钥/连接串)+ 敏感词
├── policy.py          # 策略合成(不可信输入只能收紧:不可放宽模式/还原范围/阻断线)
├── protection.py      # 令牌生成(A/B/C 三形态)、TokenVault(请求级映射,TTL+LRU)
├── restore.py         # 还原策略与流式还原(有界持留)
├── confirmations.py   # 人工确认状态机(pending/approved/released/denied/expired)
├── verification.py    # JCS 摘要、记录 MAC、审计链哈希
├── audit.py           # 审计存储:封缄 NDJSON、段轮换、checkpoint 锚点、保留期清理
├── auth.py            # 客户端密钥(封缄日志 + 轮换/撤销)、管理员令牌
├── ratelimit.py       # 滑动窗口限流 + 并发闸门
└── providers/         # 上游适配(openai-compatible / mock),httpx 连接池、超时、有限重试
```

## 8. 本地运行

```bash
cd backend
python -m venv .venv && . .venv/Scripts/activate      # Windows;Linux 用 .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env                                   # 填入 VAULT_KEY / CG_ADMIN_TOKEN / 上游密钥
python -m uvicorn app.main:app --host 127.0.0.1 --port 8100
```

首次启动会把生成的客户端密钥写到 `CG_BOOTSTRAP_KEY_FILE`(或打印到 stderr,只显示一次)。
调用示例:

```bash
curl -s localhost:8100/health
curl -s -H "Authorization: Bearer <客户端密钥>" localhost:8100/v1/models
curl -s -H "Authorization: Bearer <客户端密钥>" -H 'Content-Type: application/json' \
  -d '{"model":"deepseek-chat","messages":[{"role":"user","content":"手机号 13800138000"}]}' \
  localhost:8100/v1/chat/completions
```

## 9. 明确不承诺

- 不承诺「系统绝对安全」:测试通过只说明**这些用例**在这些实现路径上成立;
- 不承诺抗侧信道、不承诺防本地进程被攻破、不承诺防持 `VAULT_KEY` 者的整链重写与尾段截断;
- 不承诺识别零宽字符/同音字等对抗变形输入;
- 不承诺上游会遵守任何约束 —— 保护来自「拿不到明文」,不是「承诺不用」;
- 多进程/多实例部署下的确认凭据、限流与金库需要外置共享状态(本阶段为单进程设计)。
  **单进程内的多线程访问已串行化**(客户端密钥存储 `ClientKeyStore` 自带可重入锁,
  审计存储 `AuditStore` 自带锁);底层 `store.py::SealedNDJSON` 仍不做互斥,
  它要求调用方自行串行化 —— 新增调用方时须照此约束。
