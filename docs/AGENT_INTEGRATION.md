# 把 Agent 接到 CryptoGuard 上

> 配套 [MIDDLEWARE.md](MIDDLEWARE.md)(架构与配置)、[MIDDLEWARE_TESTS.md](MIDDLEWARE_TESTS.md)(测试证据)。
> 本文只讲**怎么配**,并如实标注哪些是**实测过的**、哪些只是**协议上应当可行**。
> 本阶段**没有新增任何生产代码**:所有接入都复用已有的 `/v1/messages`、
> `/v1/chat/completions`、客户端密钥、保护链路、审计与 `/v1/verify`。

## 1. 网关侧:先确认三个前提

| 前提 | 怎么设 | 为什么 |
|---|---|---|
| 上游提供商 | `CG_PROVIDERS`(JSON 数组) | 决定 middleware 把受保护后的请求发给谁 |
| 客户端密钥 | 首次启动写入 `CG_BOOTSTRAP_KEY_FILE`,或用 `POST /admin/clients` 签发 | Agent 用它认证,**不是**厂商密钥 |
| 保护模式 | `CG_PROTECTION_MODE` = `placeholder` / `token` / `encrypt` | 决定出站形态;还原策略另由 `CG_RESTORE_MODE` / `CG_RESTORE_CATEGORIES` 决定 |

**上游密钥与客户端密钥是两套东西**:上游密钥(`api_key_env` 指向的环境变量,如
`DEEPSEEK_API_KEY`)只随出网请求发往 provider;客户端密钥(`cgk_…`)只用于本网关认证。
不要把上游密钥配给 Agent —— Agent 只需要客户端密钥。

```bash
cd backend
export VAULT_KEY=<64 位十六进制>                      # 信任根;丢了映射就解不开
export CG_ADMIN_TOKEN=<管理接口令牌>
export CG_BOOTSTRAP_KEY_FILE=./bootstrap.key          # 首个客户端密钥写到哪(勿提交)
export CG_PROTECTION_MODE=token
export CG_RESTORE_CATEGORIES=EMAIL,IP,URL,ORG         # 允许自动还原的类别白名单
export CG_PROVIDERS='[{"name":"deepseek","type":"openai-compatible",
  "base_url":"https://api.deepseek.com/v1","api_key_env":"DEEPSEEK_API_KEY",
  "models":["deepseek-chat"],"display_name":"DeepSeek"}]'
python -m uvicorn app.main:app --host 127.0.0.1 --port 8100
```

首次启动后 `bootstrap.key` 里就是客户端密钥(形如 `cgk_<id>_<secret>`),只写这一次。

> 想在本机离线验证而不花钱:把 `CG_PROVIDERS` 换成
> `[{"name":"mock","type":"mock","base_url":"","api_key_env":"","models":["mock-chat"]}]`,
> 它会把收到的内容确定性地回显,用来验证「链路通了、且上游只见令牌」。

## 2. Claude Code

**已实测**:Claude Code `2.1.150`(Windows)通过本网关完成了一次真实的
`-p` 调用,拿到回答,且上游只见令牌(见 §5 的证据)。

### 配置

```bash
export ANTHROPIC_BASE_URL=http://127.0.0.1:8100     # 只填到端口,不要带 /v1
export ANTHROPIC_AUTH_TOKEN=$(cat backend/bootstrap.key)
export ANTHROPIC_MODEL=deepseek-chat                # 必须是 CG_PROVIDERS 白名单里的名字
export ANTHROPIC_SMALL_FAST_MODEL=deepseek-chat     # 后台小任务用同一个,否则会请求未配置的模型
export MAX_THINKING_TOKENS=0                        # 见下方「必须知道的一条」
claude -p "你的问题"
```

### 必须知道的一条:扩展思考要先关掉

Claude Code 默认会在 `/v1/messages` 请求里带 `thinking` 参数。本网关**明确拒绝**它:

```
API Error: 400 thinking(扩展思考)当前不支持:无法保证思考块在跨协议转换中的
语义与敏感数据保护一致,拒绝静默降级为普通回答
```

这是**有意的 fail-closed**,不是缺陷:思考块是模型自由生成的文本,既可能回显令牌,
又无法保证跨协议翻译后语义不变,静默丢弃会让人误以为「思考也被保护过了」。
因此接入前必须显式 `MAX_THINKING_TOKENS=0`。若确实需要保留思考过程,
那属于**新功能**(需要在流式翻译器里加 `thinking_delta` 并重新做保护语义分析),
不在本阶段范围内 —— 需要时请单独提出。

### 协议事实(实测)

| 事实 | 取值 |
|---|---|
| 实际发出的请求 | `POST /v1/messages?beta=true`(一次 `-p` 调用只发这一条) |
| 认证头 | `x-api-key: cgk_…`;本网关也接受 `Authorization: Bearer cgk_…` |
| `anthropic-version` 头 | 客户端会带,本网关不校验取值 |
| `/v1/messages/count_tokens` | **未实现**(返回显式 404);实测本次调用**没有**提交它,不影响连通 |
| `/v1/responses` | 未实现(与 Claude Code 无关,见 §4) |

## 3. 通用 OpenAI 兼容 Agent

任何讲 OpenAI Chat Completions 的 Agent/SDK 都能直接接(实测见
`backend/tests/mw/test_agent_clients.py`):

```python
from openai import OpenAI
client = OpenAI(base_url="http://127.0.0.1:8100/v1",   # 这个带 /v1
                api_key=open("backend/bootstrap.key").read().strip())
resp = client.chat.completions.create(
    model="deepseek-chat", messages=[{"role": "user", "content": "…"}])
```

- 认证:`Authorization: Bearer cgk_…` 或 `x-api-key: cgk_…`;
- 流式:`stream=true`,SSE 以 `data: [DONE]` 收尾;末帧带 `usage` 与 `cryptoguard` 元数据;
- 工具调用:`tools` / `tool_choice` 原样转给上游,回程的 `tool_calls` 在响应摘要覆盖范围内;
- 模型名必须在 `CG_PROVIDERS` 的白名单里,否则返回 404 `not_found`(不会静默落到别的模型)。

## 4. Codex:**当前版本不能靠改 Base URL 接入**

必须先说清楚检查结果,不能假定兼容:

| 项 | 结论 |
|---|---|
| OpenAI 兼容模式(`wire_api = "chat"`) | 当前 Codex CLI 已移除,只剩 Responses API |
| Responses API(`/v1/responses`) | 本仓库**未实现**;请求会落到显式 JSON 404 |
| 本机实测 | **未执行** —— 本机未安装 `codex` CLI,无法给出真实协议证据 |

因此「把 `base_url` 指向 CryptoGuard」这条路,对当前 Codex 版本是走不通的。
可选方案(需要你决定,本阶段**没有**动工):

1. **明说不要 Codex**:保持现状,本文件如实记录该缺口;
2. **加一层薄的 Responses 适配**:新增 `/v1/responses` 入口,把 Responses 的
   `input`/`output` 与 SSE 事件(含 `response.output_text.delta` 等)译成中立的
   `ChatRequest`/`StreamChunk`,**复用**现有 `pipeline` 与 `provider`,不复制中间件逻辑;
   代价是新增一个模块 + 一批测试,且**在没有真实 Codex 客户端的情况下只能验到「协议形状」**
   这一层,不能声称已完成真实 Codex 联调。

在 (2) 被明确要求并配好可运行的 Codex 之前,本文档不声称 Codex 可用。

## 5. 实测证据(Claude Code 2.1.150,本机)

命令(本机回环,未访问任何真实厂商):

```bash
claude --bare -p "复述:手机号 13800138000,邮箱 zhangsan@corp.com.cn"
```

客户端拿到:

```
已收到请求(含 2 个受保护字段:[CG_TOKEN_a5aa2516c8dc229c708a1b88], zhangsan@corp.com.cn),结果已安全返回。
```

可复现的事实:

- 上游回显的是 `[CG_TOKEN_…]` 而不是 `13800138000` —— **上游手里没有手机号原文**;
- 白名单类别 `EMAIL` 在回程被还原,高风险 `PHONE` 按策略**扣留**(所以手机号在回答里仍是令牌);
- 审计记录(管理员接口可查):

```
endpoint=/v1/messages  stream=True  outcome=ok  protection_mode=token  upstream_status=200
detections={total:2, by_type:{PHONE:1, EMAIL:1}}
restored={restored_count:1, withheld_count:1,
          restored:[{token:"[CG_TOKEN_…]", type:"EMAIL"}],
          withheld:[{token:"[CG_TOKEN_…]", type:"PHONE", risk:"high",
                     reason:"高风险类别,禁止自动还原(需走显式人工确认流程)"}]}
```

- 审计记录里**没有**原文、没有客户端密钥、没有上游密钥(有专测断言)。

## 6. 接上之后可以做的自查

```bash
# 这次调用到底发生了什么(客户端可查自己的记录)
curl -s -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
  -d '{"request_id":"cg-…"}' localhost:8100/v1/verify
# 整条审计链是否完整(管理员)
curl -s -H "X-Admin-Token: $CG_ADMIN_TOKEN" -X POST localhost:8100/admin/audit/verify
```

`/v1/verify` 只会给出三个**互相独立**的结论(记录完整性 / 摘要一致性 / 策略决策),
它**不**给出「上游没收到明文」这个结论 —— 那要靠上游侧的实际报文来证明(见 §5)。

## 7. 本文不声称什么

- 不声称「接入 Agent 之后系统就安全了」:保护来自「上游拿不到明文」,不来自厂商的承诺;
- §5 的上游是**本机回环的测试服务**,不是真实厂商;真实厂商连通性需要你显式配好
  `CG_REAL_UPSTREAM_KEY` / `CG_REAL_UPSTREAM_URL` / `CG_REAL_MODEL` 后单独跑,默认跳过;
- 不声称 Codex 可用(见 §4),不声称已做过 Codex 真实联调;
- 不声称多进程部署下的确认凭据、限流与请求级映射可用(本实现为单进程设计)。
