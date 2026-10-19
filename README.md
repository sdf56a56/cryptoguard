# CryptoGuard · LLM API 安全中转网关

> Agent / SDK / Claude Code / Codex 与模型服务商之间的**单进程安全网关**：
> 出站识别并保护敏感数据，回程按策略受控还原，全程写不含明文的可验证审计。
>
> 本仓库的后端已经收敛为只做这件事。原演示平台（`/api/*`、聊天查看器、密码学
> 实验室、攻击沙箱、验收面板、前端静态托管）已全部删除；`frontend/` 目录保留但
> 与当前后端**不再兼容**，需要另立项目删除或重写。

## 它能做什么

```
Agent / SDK ──▶ CryptoGuard ──▶ Provider ──▶ CryptoGuard ──▶ Agent / SDK
                 出站:识别 + 保护            回程:受控还原 + 响应侧检测
                 全程:摘要 + 审计链 + 策略决策
```

- **协议入口**：`/v1/chat/completions`（OpenAI Chat）、`/v1/messages`（Anthropic
  Messages / Claude Code）、`/v1/responses`（OpenAI Responses / Codex 无状态子集）；
- **三种保护模式**：`placeholder`（可读占位符）、`token`（随机令牌，默认）、
  `encrypt`（AES-256-GCM 封缄映射）；
- **默认扣留高风险数据**：手机号/身份证/银行卡/私钥/口令/连接串等不会自动还原；
  需要时走「客户端申请 → 管理员批准 → 一次性释放」；
- **可验证审计**：请求/响应 JCS 摘要、记录级 HMAC、哈希链、`/v1/verify`；
- **运维面**：`/health`、`/ready`、`/metrics`（Prometheus 文本）、provider 连通性
  测试、客户端密钥签发/撤销/轮换/更新/过期。

## 快速启动

```bash
cd backend
python -m venv .venv && . .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
# 至少填写 VAULT_KEY / CG_ADMIN_TOKEN / CG_PROVIDERS 与上游密钥环境变量
python -m uvicorn app.main:app --host 127.0.0.1 --port 8100 --workers 1
```

> **升级提示**：已有 `backend/.env` 会覆盖新默认值（例如旧的
> `CG_PROTECTION_MODE=placeholder` / `CG_MAX_REQUEST_BYTES=1048576`）。请对照
> `.env.example` 更新，尤其是内容策略、请求体上限与单实例锁。

首次启动（开发环境）会生成一个客户端密钥，写到 `CG_BOOTSTRAP_KEY_FILE` 或打印到
stderr，**只显示一次**。生产环境不自动生成，请用管理员令牌显式签发：

```bash
curl -s -X POST localhost:8100/admin/clients \
  -H "X-Admin-Token: $CG_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"claude-code","models":["deepseek-chat"],"expires_in_days":30}'
```

调用示例：

```bash
curl -s localhost:8100/health
curl -s -H "Authorization: Bearer $CLIENT_KEY" localhost:8100/v1/models
curl -s -H "Authorization: Bearer $CLIENT_KEY" -H 'Content-Type: application/json' \
  -d '{"model":"deepseek-chat","messages":[{"role":"user","content":"手机号 13800138000"}]}' \
  localhost:8100/v1/chat/completions
```

Claude Code：

```bash
export ANTHROPIC_BASE_URL=http://127.0.0.1:8100
export ANTHROPIC_AUTH_TOKEN=$CLIENT_KEY
export ANTHROPIC_MODEL=deepseek-chat
export ANTHROPIC_SMALL_FAST_MODEL=deepseek-chat
claude -p "你的问题"
```

默认 `CG_ANTHROPIC_THINKING=strip`：接受 Claude Code 的 `thinking` 参数但不转发、
不返回思考块，并在响应元数据里显式登记为 `ignored`；需要直接 400 时设为 `reject`。

Codex / Responses：

```bash
# 客户端把 base_url 指到 http://127.0.0.1:8100/v1，协议用 responses
# 仅支持无状态子集：文本、function 工具、流式；不支持 previous_response_id /
# store=true / background / 内置工具（会显式 400，不静默降级）。
```

## 安全边界（必须读）

- **上游永远拿不到明文**：出站只发送占位符/令牌；模式 C 的机密性来自这一点，
  不是「上游解不开密文」。
- **默认拒绝未检测内容**：图片默认 400；文档默认 400；`cache_control` 默认剥离并
  登记；`thinking` 默认剥离并登记。显式 `pass` 等于接受未保护面，审计会记录。
- **审计只证明本地记录未被改**：持 `VAULT_KEY` 者仍可整链重写；要检测整链重写
  需要外部锚点（把 `/admin/audit/verify` 的 `tip_hash` 抄到站外）。
- **单进程**：确认、令牌金库、限流、客户端存储、审计链尾都是进程内状态。同一
  `data/` 目录启动第二个进程会被实例锁拒绝；**不支持**多 worker / 多副本。
  需要横向扩展时，必须先把这些状态外置到共享存储（当前未实现）。
- **图片/文档不做 OCR 抽取检测**：默认拒绝，而不是假装保护。
- **不执行模型生成的工具调用**：网关只做保护 / 转发 / 审计。

## 接口

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/health` | 健康摘要（无认证、无密钥） |
| GET | `/ready` | 就绪：装配 / provider / 审计链 |
| GET | `/metrics` | Prometheus 文本（默认需管理员令牌） |
| GET | `/v1/models` | 模型列表 + 能力（streaming/tools/responses/images） |
| POST | `/v1/chat/completions` | OpenAI Chat（非流式 / SSE） |
| POST | `/v1/messages` | Anthropic Messages（Claude Code） |
| POST | `/v1/responses` | OpenAI Responses（Codex 无状态子集） |
| POST | `/v1/verify` | 校验自己的请求记录与摘要 |
| GET/POST | `/v1/confirmations` | 人工确认申请 / 列表 |
| GET | `/v1/confirmations/{id}` | 查询状态 |
| POST | `/v1/confirmations/{id}/release` | 一次性释放（需管理员批准） |
| GET | `/admin/security/policies` | 生效策略视图 |
| GET | `/admin/audit`、`/admin/audit/{rid}` | 审计分页 / 单条 |
| POST | `/admin/audit/verify`、`/admin/audit/purge` | 链校验 / 保留期清理 |
| GET/POST | `/admin/clients` | 客户端密钥列表 / 签发 |
| PATCH | `/admin/clients/{id}` | 更新名称/模型/限额/模式/过期 |
| POST | `/admin/clients/{id}/revoke`、`/rotate` | 撤销 / 轮换 |
| GET/POST | `/admin/confirmations` | 待确认队列 / 批准 / 拒绝 |
| GET | `/admin/providers` | provider 配置视图（无密钥） |
| POST | `/admin/providers/{name}/test` | 上游连通性测试 |

`/v1/messages/count_tokens` **有意不实现**（显式 404）：精确计数需要把未保护文本
发给上游 tokenizer，违背「上游拿不到明文」的核心承诺。

## 目录

```
backend/
├── app/
│   ├── main.py              # 唯一入口：lifespan + CORS + 路由挂载
│   ├── paths.py             # data/ 目录口径
│   ├── keys.py              # VAULT_KEY / HKDF / 指纹（信任根）
│   ├── store.py             # SealedNDJSON（逐行 HMAC 封缄）
│   ├── canon.py             # RFC 8785 JCS 规范化
│   ├── detection.py         # 13 类敏感实体识别
│   ├── crypto/aead.py       # AES-256-GCM
│   └── middleware/          # 网关核心（保护/还原/策略/审计/提供商/协议）
├── tests/
│   ├── core/                # keys / store / canon / detection
│   └── mw/                  # 网关契约与安全测试
├── requirements.txt
├── pyproject.toml
└── .env.example
docs/
├── GATEWAY.md               # 架构、配置、协议与边界
├── GATEWAY_TESTS.md         # 测试证据与运行方式
└── AGENT_INTEGRATION.md     # Claude Code / OpenAI SDK / Codex 接入
```

## 测试

```bash
cd backend
python -m pytest tests -q
```

## 明确不承诺

- 不承诺「系统绝对安全」；测试通过只说明这些用例在这些实现路径上成立；
- 不承诺识别器零漏报，也不承诺对抗同音字/零宽字符/分片拼接等变形输入；
- 不承诺上游遵守任何约束——保护来自「拿不到明文」，不是「承诺不用」；
- 不承诺多进程/多副本下的确认、金库、限流与审计一致性；
- 不承诺内置 TLS/mTLS；跨主机部署请置于受信反向代理之后。
