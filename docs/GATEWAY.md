# CryptoGuard 安全中转网关 —— 架构与配置

> 本文只描述 `backend/app/` 的**实际实现**，并明确标注不承诺什么。
> 测试证据见 [GATEWAY_TESTS.md](GATEWAY_TESTS.md)；接入见
> [AGENT_INTEGRATION.md](AGENT_INTEGRATION.md)。

## 1. 定位

```
Agent / SDK ──▶ CryptoGuard ──▶ Provider ──▶ CryptoGuard ──▶ Agent / SDK
                 出站:检测 + 保护            回程:受控还原 + 响应侧检测
                 全程:摘要 + 审计链 + 策略决策
```

- 上游**永远拿不到明文**：出站只发送占位符/令牌；
- 令牌只在**本次请求**的映射金库内可还原；
- 高风险类别默认扣留，需要「客户端申请 → 管理员批准 → 一次性释放」；
- 每次调用写一条不含原文/密钥/可还原映射的审计记录。

演示平台（`/api/*`、聊天查看器、密码学实验室、攻击沙箱、验收 API、SPA 托管）
已全部删除；`app/main.py` 只装配网关。

## 2. 保护模式

| 模式 | 配置 | 出站形态 | 适用 |
|---|---|---|---|
| A 占位符 | `placeholder` | `[PHONE_001]`、`[EMAIL_002]` | 可读性最好，形态可被嗅探 |
| B 令牌 | `token`（默认） | `[CG_TOKEN_<hex>]` | 不泄漏实体类型与序号 |
| C 加密 | `encrypt` | `[CG_ENC_v1_<hex>]` | 映射以 AES-256-GCM 封缄 |

三种模式的差别在出站形态与映射封缄方式，**不在**「还原与否」；还原策略由
`CG_RESTORE_MODE` / `CG_RESTORE_CATEGORIES` 与风险等级共同决定。

**关键事实**：模式 B/C 下模型看到的是令牌，不是原文；模型回答里也不会包含原文
语义。还原发生在本地，与「模型看到了什么」是两件事。

## 3. 配置

完整示例见 [`backend/.env.example`](../backend/.env.example)。核心变量：

| 变量 | 默认 | 说明 |
|---|---|---|
| `VAULT_KEY` | 无（首次启动生成） | 64 位十六进制信任根；所有子密钥由 HKDF 派生 |
| `CG_ENV` | `development` | `production` 时强制管理员令牌、禁匿名、禁示例密钥 |
| `CG_ADMIN_TOKEN` | 空 | 管理接口全权令牌；空 = 503 |
| `CG_DATA_DIR` | 空 | 覆盖数据目录（默认仓库根 `data/`） |
| `CG_INSTANCE_LOCK` | `1` | 同 `data/` 目录只允许一个进程 |
| `CG_CORS_ORIGINS` | 空 | 浏览器 CORS 白名单；空 = 不挂；生产禁 `*` |
| `CG_PROVIDERS` | `[]` | 上游 JSON 数组；密钥只写 `api_key_env` 变量名 |
| `CG_PROTECTION_MODE` | `token` | `placeholder`/`token`/`encrypt` |
| `CG_RESTORE_MODE` | `categories` | `off`/`confirm`/`categories`/`auto`（客户端只能收紧） |
| `CG_RESTORE_CATEGORIES` | `EMAIL,IP,URL,ORG` | 允许自动还原的类别 |
| `CG_BLOCK_ON` | `critical` | 达到该风险且建议阻断 → 拒发 |
| `CG_STABLE_TOKENS` | `0` | 1 = 模式 B 同值同令牌（便于共指，代价是等值泄漏） |
| `CG_IMAGE_POLICY` | `reject` | 图片默认拒绝；`pass` = 显式接受未保护 |
| `CG_DOCUMENT_POLICY` | `reject` | 文档默认拒绝 |
| `CG_ANTHROPIC_THINKING` | `strip` | 接受 thinking 但不转发/不返回；`reject` = 400 |
| `CG_CACHE_CONTROL` | `strip` | 剥离并登记；`reject` = 400 |
| `CG_SSE_HEARTBEAT_S` | `15` | 等待上游首 token 时发 `: ping`；0 = 关闭 |
| `CG_IDEMPOTENCY_TTL_S` / `MAX` | `600` / `1024` | 非流式幂等缓存（AEAD 封缄内存） |
| `CG_RATE_LIMIT_PER_MIN` | `600` | 按客户端滑动窗口 |
| `CG_MAX_CONCURRENCY` | `32` | 全局在途上游调用上限 |
| `CG_MAX_REQUEST_BYTES` | `8388608` | 请求体上限（8 MiB） |
| `CG_CLIENT_KEY_TTL_DAYS` | `0` | 新建客户端密钥默认有效期；0 = 永不过期 |
| `CG_METRICS_PUBLIC` | `0` | 1 = `/metrics` 允许匿名（生产告警） |

**客户端密钥与上游密钥严格分离**：客户端密钥只用于网关认证；上游密钥只随出网
请求发往 provider；两者互不出现在对方的可见面。

### 3.1 运行时 Provider 配置（控制台托管）

除了 `CG_PROVIDERS`，管理员可以在控制台「上游配置」里新增/编辑/删除 Provider，
保存后**立即生效，无需重启**：

- 托管配置整体用 AES-256-GCM 加密落盘：`<data_dir>/config/provider-config.enc.json`
  （目录 0700、文件 0600、原子替换）；密钥由 `VAULT_KEY` 经 HKDF 派生
  （用途域 `provider-config/v1`）；
- 接口只返回 `has_key` / `key_source` / `key_env` 等非敏感字段，**永不回显**
  API Key 或 `extra_headers` 的值；审计只记字段名与 `key_updated` 布尔值；
- 同名托管项**覆盖**环境变量项；删除托管项后环境变量项恢复；
- 默认 Provider / 模型可以指向环境变量项或托管项；非法默认值返回 400；
- 热切换只影响新请求；在途请求继续使用旧 registry，旧连接池在进程退出时关闭；
- `VAULT_KEY` 变更会导致托管配置无法解密：启动 fail-closed，需恢复原 `VAULT_KEY`
  或移走配置文件后重新配置；
- 管理面可把上游指向任意 http(s) 地址，这是管理员权限的一部分；控制台会提示只填
  可信上游。

## 4. 人工确认（高风险数据的受控释放）

状态机：`pending → approved → consumed` / `denied` / `expired`。

- 客户端只能申请与查询，**不能自我批准**；批准必须持全权管理员令牌；
- 凭据绑定 `(client_id, request_id, tokens, expires_epoch)`；换客户端、换请求、
  改令牌集合、过期、重放都不成立；
- 释放是**一次性**的；缺任一映射则整批失败，不做部分释放；
- 审计只记令牌与类别，**不记明文**；
- 确认状态在进程内（重启即失效），与单进程部署假设一致。

## 5. 流式与幂等

- **SSE 心跳**：等待上游首 token 期间每 `CG_SSE_HEARTBEAT_S` 秒发 `: ping\n\n`，
  避免代理按空闲超时切断；
- **跨块令牌**：回程有界持留（`MAX_TOKEN_LEN=96`），任何一次下发都不含半截令牌；
- **断流**：上游中断以 `finish_reason=null` 收尾并标记不完整，不重试（避免重复计费）；
- **幂等键**：仅非流式；`Idempotency-Key` 头按客户端隔离；命中直接返回封缄缓存的
  原响应，不调用上游；同 key 不同 body → 409 conflict；流式带 key → 400。

## 6. 协议覆盖

| 入口 | 说明 |
|---|---|
| `POST /v1/chat/completions` | OpenAI Chat；严格字段校验；未知字段 400 |
| `POST /v1/messages` | Anthropic Messages；Claude Code 可用；`thinking` 默认 strip |
| `POST /v1/responses` | Responses 无状态子集：文本、function 工具、流式；拒绝 `previous_response_id`/`store=true`/`background`/内置工具 |
| `POST /v1/messages/count_tokens` | **有意不实现**（404）：精确计数需要把明文发给上游 tokenizer |

OpenAI Chat 额外接受 `reasoning_effort` / `verbosity` 并透传给 openai-compatible
上游；若解析到 anthropic 上游则显式 400，不静默丢弃。

## 7. 审计与验证

| 接口 | 权限 | 作用 |
|---|---|---|
| `POST /v1/verify` | 客户端（只能查自己的 request_id） | 记录存在性 / 摘要一致性 / 记录 MAC / 审计链 |
| `GET /admin/audit` | 管理员 | 分页 |
| `POST /admin/audit/verify` | 管理员 | 整链校验 |
| `POST /admin/audit/purge` | 管理员 | 按保留期清理（默认 dry-run） |
| `GET /admin/dashboard` | 管理员 | 看板快照（只读内存计数，不做整链校验） |
| `GET /ready` | 公开 | 装配/provider/审计链就绪 |
| `GET /metrics` | 管理员（或 `CG_METRICS_PUBLIC=1`） | Prometheus 文本 |

**必须区分的三个结论**：记录完整性、响应摘要匹配、敏感数据保护成功。任何一件
成立都不蕴含另一件。审计记录不含原始 Prompt、原始敏感值、密钥或可还原映射。

**明确边界**：

- 哈希/HMAC/链只证明本地记录未被改，不证明响应来自某服务商；
- 持 `VAULT_KEY` 者可整链重写；检测整链重写需要站外锚点（`tip_hash`）；
- 尾段截断不可由本地日志自证；
- 拒绝类请求只对**已认证**调用落审计（避免未认证请求灌盘）。

## 8. 部署形态：单进程

确认、令牌金库、限流、客户端存储、审计链尾都是进程内状态。因此：

- 同一 `data/` 目录只允许一个网关进程（`InstanceLock`，POSIX `flock` /
  Windows `msvcrt.locking`）；
- 不支持 gunicorn / uvicorn 多 worker、多副本；
- 水平扩展需要先把 confirmations / token vault / rate limit / 审计写入外置到
  共享存储（当前未实现）。

## 9. 代码结构

```
backend/app/
├── main.py                 # 入口：lifespan / CORS / 路由挂载
├── paths.py                # data/ 目录
├── keys.py / store.py / canon.py / detection.py / crypto/aead.py
└── middleware/
    ├── routes.py           # /v1/* /admin/* /health /ready /metrics
    ├── pipeline.py         # 检测→保护→转发→还原→审计
    ├── config.py           # CG_* 解析与生产校验
    ├── errors.py           # 错误分类 / 脱敏 / 协议错误体
    ├── auth.py             # 客户端密钥 + 单用户全权管理员
    ├── ratelimit.py        # 滑动窗口 + 并发闸
    ├── protection.py       # A/B/C 三模式 + TokenVault
    ├── restore.py          # 受控还原 + 流式持留
    ├── policy.py           # 策略只能收紧
    ├── content_policy.py   # 图片/文档/thinking/cache_control
    ├── recognizers.py      # 扩展识别规则
    ├── confirmations.py    # 人工确认状态机
    ├── audit.py            # 封缄审计 + 链
    ├── verification.py     # 摘要 / MAC / 链哈希
    ├── idempotency.py      # 幂等键缓存
    ├── metrics.py          # Prometheus 指标 + 看板 JSON 快照 + ASGI 包装
    ├── provider_config.py  # 托管 Provider：加密落盘 / 校验 / 热生效
    ├── instance.py         # 单实例锁
    ├── responses_proto.py  # Responses ⇄ 中立协议
    ├── openai_schemas.py   # OpenAI/Anthropic 入口模型
    ├── anthropic_proto.py  # Anthropic ⇄ 中立转换
    └── providers/           # openai-compatible / anthropic / mock
```

## 10. 明确不承诺

- 不承诺「系统绝对安全」；测试通过只说明这些用例在这些实现路径上成立；
- 不承诺识别器零漏报，也不承诺对抗同音字/零宽字符/分片拼接；
- 不承诺上游遵守任何约束——保护来自「拿不到明文」，不是「承诺不用」；
- 不承诺多进程/多副本一致性；
- 不承诺内置 TLS/mTLS；跨主机请置于受信反向代理之后。
