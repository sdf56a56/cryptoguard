"""
CryptoGuard LLM API 安全网关 —— 包入口

本包是后端唯一业务层：Agent ↔ 模型服务商之间的保护 / 转发 / 审计网关。
演示平台（`/api/*`、聊天查看器、密码学实验室、前端静态托管）已全部移除。

模块划分:
  config.py        —— 集中式环境配置(CG_* 前缀),启动期校验,生产禁匿名
  errors.py        —— 中间件错误类型 → OpenAI/Anthropic 错误体映射
  auth.py          —— 客户端 API Key(仅存 HMAC 摘要)+ 管理员令牌
  ratelimit.py     —— 客户端级滑动窗口限流 + 并发闸
  recognizers.py   —— 敏感数据识别扩展(凭证/私钥/DB URL/自定义规则)+ 误报抑制
  protection.py    —— 保护模式 A(脱敏)/B(令牌化)/C(加密)+ 请求级映射金库
  restore.py       —— 策略受控的令牌恢复(默认保守)
  providers/       —— ModelProvider / ProviderConfig / ProviderRegistry 适配层
  openai_schemas.py—— /v1/chat/completions 请求/响应模型(含不支持字段显式报错)
  anthropic_proto.py —— Anthropic Messages ⇄ OpenAI Chat Completions 协议转换
  verification.py  —— 请求/响应规范化摘要 + HMAC 封缄 + 审计哈希链 + /v1/verify
  audit.py         —— 审计记录(封缄 NDJSON,复用既有 SealedNDJSON)
  pipeline.py      —— 单次调用的编排(检测→保护→转发→恢复→审计)
  routes.py        —— 统一 API 路由
  deps.py          —— 装配(从 data/ 的 Vault 派生密钥)
  content_policy.py—— 图片/文档/thinking/cache_control 的显式处置
  idempotency.py   —— 幂等键缓存（AEAD 封缄内存）
  metrics.py       —— Prometheus 文本指标 + ASGI 包装
  instance.py      —— 单实例锁（单进程部署硬约束）
  responses_proto.py—— OpenAI Responses ⇄ 中立协议（Codex 无状态子集）
"""
from __future__ import annotations

__all__ = ["__version__"]

#: 中间件自身版本(进入审计记录与 /health,便于区分「哪版策略处理了这次请求」)
__version__ = "1.0.0"
