# 网关测试与验收

> 配套 [GATEWAY.md](GATEWAY.md)。这里记录**实际可运行**的测试与手工验收命令；
> 不把「应当可行」写成「已经验证」。

## 1. 运行

```bash
cd backend
python -m pytest tests -q
```

- `tests/core/`：信任根、封缄存储、JCS 规范化、敏感实体识别；
- `tests/mw/`：网关契约与安全测试（认证、保护/还原、审计、流式、确认、
  内容策略、幂等、心跳、413 形状、管理面权限、Responses、实例锁）。
- 当前收集到 **336** 个用例（2026-10 重构后）；真实厂商用例默认 skip。
- 真实厂商上游测试沿用 `tests/mw/test_real_http_e2e.py::test_real_vendor_upstream_opt_in`，
  默认跳过；需要 `CG_REAL_UPSTREAM_KEY` / `CG_REAL_UPSTREAM_URL` / `CG_REAL_MODEL`。

## 2. 测试矩阵（关键项）

| 关注点 | 测试文件 | 断言要点 |
|---|---|---|
| 上游拿不到原文 | `test_real_http_e2e.py` | 真实 socket 回声上游收到的字节里没有手机号/邮箱，只有令牌 |
| 三种保护模式 | `test_mode_a/b/c_*.py` | 出站形态、映射封缄、跨请求不可还原 |
| 受控还原 | `test_mode_*`、`test_confirmations.py` | 白名单类别可还原；高风险扣留；确认需管理员批准且一次性 |
| 审计完整性 | `test_verification_audit.py` | 摘要/MAC/链；旧记录在新增默认字段后仍可校验 |
| 流式边界 | `test_stream_boundaries.py` | 跨块令牌、UTF-8、断流、取消 |
| 上游适配 | `test_upstream_provider.py` | 密钥只进头、超时/重试边界、错误分类、trust_env |
| Agent 接入 | `test_agent_clients.py` | OpenAI/Anthropic/Responses 客户端形状；count_tokens 显式 404 |
| 内容面 | `test_content_policy.py` | 图片/文档默认拒绝；pass 登记未保护；cache_control/thinking 显式 ignored |
| 幂等/心跳/413 | `test_robustness.py` | 重放不二次调用上游；409；`: ping`；Anthropic 413 形状 |
| Responses | `test_responses_api.py` | 文本/流式/function_call；拒绝有状态与内置工具 |
| 管理面权限 | `test_admin_rbac.py` | 只读令牌只读；客户端过期；PATCH；provider 测试；实例锁 |
| 演示平台已删除 | `test_no_demo_routes.py` | 路由表无 `/api/*`、无静态挂载/SPA catch-all |

## 3. 手工验收

```bash
cd backend
python -m uvicorn app.main:app --host 127.0.0.1 --port 8100 --workers 1

curl -s localhost:8100/health
curl -s localhost:8100/ready
curl -s -H "X-Admin-Token: $CG_ADMIN_TOKEN" localhost:8100/metrics | head

# 演示端点应全部 404
curl -s -o /dev/null -w '%{http_code}\n' localhost:8100/api/health
curl -s -o /dev/null -w '%{http_code}\n' localhost:8100/

# 同 data/ 目录第二个进程应失败退出
python -m uvicorn app.main:app --host 127.0.0.1 --port 8101
```

## 4. 不声称的验证

- 不声称真实 Codex CLI 已联调：本机若未安装 Codex，只验证协议形状与安全链路；
- 不声称真实厂商上游可用：自动化测试使用本机 HTTP 回声上游 / Mock provider；
- 不声称多 worker / 多副本一致：该形态不受支持，实例锁会在启动期拒绝。
