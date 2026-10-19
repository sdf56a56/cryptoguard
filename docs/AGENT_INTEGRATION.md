# 把 Agent 接到 CryptoGuard 上

> 配套 [GATEWAY.md](GATEWAY.md)（架构与配置）、[GATEWAY_TESTS.md](GATEWAY_TESTS.md)（测试证据）。
> 本文只讲怎么配，并如实标注哪些是实测过的、哪些只是协议上应当可行。

## 1. 网关侧三个前提

| 前提 | 怎么设 | 为什么 |
|---|---|---|
| 上游提供商 | `CG_PROVIDERS`（JSON 数组）或控制台托管配置 | 决定受保护后的请求发给谁 |
| 客户端密钥 | `CG_BOOTSTRAP_KEY_FILE`（开发环境自动生成）或 `POST /admin/clients`（生产显式签发） | Agent 用它认证，**不是**厂商密钥 |
| 保护/还原策略 | `CG_PROTECTION_MODE` / `CG_RESTORE_MODE` / `CG_RESTORE_CATEGORIES` | 决定出站形态与回程还原范围 |

**上游密钥与客户端密钥是两套东西**：上游密钥（`api_key_env` 指向的环境变量）只随
出网请求发往 provider；客户端密钥（`cgk_…`）只用于本网关认证。不要把上游密钥配给 Agent。

```bash
cd backend
export VAULT_KEY=<64 位十六进制>
export CG_ADMIN_TOKEN=<管理接口令牌>
export CG_BOOTSTRAP_KEY_FILE=./bootstrap.key
export CG_PROTECTION_MODE=token
export CG_RESTORE_CATEGORIES=EMAIL,IP,URL,ORG
export CG_PROVIDERS='[{"name":"deepseek","type":"openai-compatible",
  "base_url":"https://api.deepseek.com/v1","api_key_env":"DEEPSEEK_API_KEY",
  "models":["deepseek-chat"],"display_name":"DeepSeek"}]'
python -m uvicorn app.main:app --host 127.0.0.1 --port 8100 --workers 1
```

## 2. Claude Code

```bash
export ANTHROPIC_BASE_URL=http://127.0.0.1:8100     # 只到端口，不要带 /v1
export ANTHROPIC_AUTH_TOKEN=$(cat bootstrap.key)   # 即 CG_BOOTSTRAP_KEY_FILE 指向的文件
export ANTHROPIC_MODEL=deepseek-chat                # 必须在 Provider 的 models 白名单
export ANTHROPIC_SMALL_FAST_MODEL=deepseek-chat
claude -p "你的问题"
```

**关于 thinking**：Claude Code 默认会带 `thinking`。本网关默认
`CG_ANTHROPIC_THINKING=strip`：接受请求、不转发思考配置、不返回思考块，并在
`cryptoguard.ignored_fields` 与 `X-CryptoGuard-Content-Policy` 中显式登记。
不再需要 `MAX_THINKING_TOKENS=0`。若希望这种行为直接 400，设
`CG_ANTHROPIC_THINKING=reject`。

**关于 cache_control**：默认 `strip`（只影响 prompt caching，不影响安全），并登记
为 ignored；`CG_CACHE_CONTROL=reject` 可改为显式 400。

**count_tokens**：`/v1/messages/count_tokens` 有意返回 404；Claude Code 的单次调用
实测不依赖它。其他 SDK 若强依赖该接口，需要单独评估（精确计数会把明文发给上游）。

## 3. 通用 OpenAI 兼容 Agent

```python
from openai import OpenAI
client = OpenAI(base_url="http://127.0.0.1:8100/v1",
                api_key=open("/path/to/bootstrap.key").read().strip())
resp = client.chat.completions.create(
    model="deepseek-chat", messages=[{"role": "user", "content": "…"}])
```

- 认证：`Authorization: Bearer cgk_…` 或 `x-api-key: cgk_…`；
- 流式：`stream=true`，SSE 以 `data: [DONE]` 收尾；等待首 token 期间可能收到
  `: ping` 注释帧（客户端应忽略）；
- 工具调用：`tools` / `tool_choice` 经中立层转换后转给上游，回程 `tool_calls` 在响应摘要覆盖范围内；
- 模型名必须在 `CG_PROVIDERS` 或控制台托管 Provider 的 `models` 白名单里，否则 404
  （不会静默落到别的模型）；
- `reasoning_effort` / `verbosity` 仅对 openai-compatible 上游透传；anthropic 上游会 400。

## 4. Codex / OpenAI Responses

客户端把 base URL 指到 `http://127.0.0.1:8100/v1`，协议使用 Responses。
本网关提供**无状态最小子集**：

| 支持 | 不支持（显式 400） |
|---|---|
| `input`（字符串 / message / function_call / function_call_output） | `previous_response_id`（不保存跨请求会话） |
| `instructions`、`max_output_tokens`、`temperature`、`top_p` | `store=true`、`background` |
| function 工具、`tool_choice`、`parallel_tool_calls` | `web_search`/`file_search`/`computer_use`/`code_interpreter`/`image_generation`/`mcp` 等内置工具 |
| `text.format`（text/json_object/json_schema）、`text.verbosity`、`reasoning.effort`、`prompt_cache_key` | `metadata`、`safety_identifier`、`service_tier` |
| `truncation=disabled` 或 `auto`（`auto` 只登记 ignored，网关不截断） | 其它 `truncation` 值 |
| 流式 `response.*` 事件（文本 + function_call） | 音频输入；文件输入默认按 `CG_DOCUMENT_POLICY` 拒绝（显式 `pass` 时登记为 dropped） |

`include` 与 `reasoning.summary` 会被接受并登记为 `ignored_fields`，但不会转发，
也不会改变响应内容。`truncation=auto` 同样只登记 ignored，不静默截断上下文。
图片输入按 `CG_IMAGE_POLICY` 处理：默认 400；显式 `pass` 时放行并登记为未保护面。

**不声称真实 Codex CLI 已联调**：本机未安装 CLI 时，自动化测试只验证协议形状与
安全链路（上游回声不含原文、工具调用可翻译、拒绝项显式 400）。

## 5. 错误与重试

| 类别 | HTTP | 客户端动作 |
|---|---|---|
| `invalid_request` / `not_supported` / `blocked` | 400 | 修正请求或内容；不要原样重试 |
| `auth` | 401 | 检查/更换客户端密钥或管理员令牌 |
| `forbidden` | 403 | 权限不足（模型白名单 / 跨客户端记录 / 策略越权收紧） |
| `not_found` | 404 | 模型或确认凭据不存在；检查 `models` 白名单 |
| `conflict` | 409 | 幂等键被用于不同请求体 |
| `rate_limit` | 429 | 按 `Retry-After` 退避 |
| `timeout` / `network` / `upstream_*` | 502/504 | 可有限重试；带幂等键可避免重复计费 |
| `config` | 503 | 网关配置缺失（如未配 `CG_ADMIN_TOKEN` 或上游密钥） |
| `internal` | 500 | 网关内部错误；可重试一次，持续失败请查网关日志 |

重试建议：非流式请求带 `Idempotency-Key`；流式请求不要带（显式 400）。

## 6. 接上之后的自查

```bash
# 本次调用发生了什么（客户端只能查自己发起的 request_id）
curl -s -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
  -d '{"request_id":"cg-…"}' localhost:8100/v1/verify
# 整条审计链（管理员）
curl -s -H "X-Admin-Token: $CG_ADMIN_TOKEN" -X POST localhost:8100/admin/audit/verify
# 指标
curl -s -H "X-Admin-Token: $CG_ADMIN_TOKEN" localhost:8100/metrics
```

`/v1/verify` 返回记录存在性、记录 MAC 与审计链、请求/响应摘要是否匹配，以及
本次的策略与处置（`detections` / `actions` / `restore`）。这些是互相独立的结论，
**不**给出「上游没收到明文」这个结论——那要靠上游侧实际报文证明。

## 7. 本文不声称什么

- 不声称接入 Agent 后系统就安全了：保护来自「上游拿不到明文」，不来自厂商承诺；
- 不声称真实厂商上游可用（自动化测试使用本机回声上游 / Mock provider）；
- 不声称 Codex 已真实联调；
- 不声称多进程/多副本可用：本网关是单进程，实例锁会在启动期拒绝第二个进程。
