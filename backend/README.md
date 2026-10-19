# CryptoGuard 后端

单进程 LLM API 安全中转网关。入口 `app.main:app`。

```bash
cd backend
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env          # 填 VAULT_KEY / CG_ADMIN_TOKEN / CG_PROVIDERS
python -m uvicorn app.main:app --host 127.0.0.1 --port 8100 --workers 1
```

- 配置与边界：`../docs/GATEWAY.md`
- 测试：`python -m pytest tests -q`；证据：`../docs/GATEWAY_TESTS.md`
- Agent 接入：`../docs/AGENT_INTEGRATION.md`

注意：不支持多 worker / 多副本；同一 `data/` 目录只允许一个实例。
