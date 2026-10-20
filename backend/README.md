# CryptoGuard 后端

单进程 LLM API 安全中转网关。入口 `app.main:app`。

```bash
cd backend
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env          # 建议填 VAULT_KEY / CG_ADMIN_TOKEN（无历史数据时首次启动自动生成 VAULT_KEY）
python -m uvicorn app.main:app --host 127.0.0.1 --port 8100 --workers 1
```

- 上游 Provider：可在 `.env` 的 `CG_PROVIDERS` 配置，也可登录控制台在「上游配置」
  创建；托管配置加密落盘在 `data/config/provider-config.enc.json`，保存即生效。
- 控制台：另开终端 `cd ../frontend && npm install && npm run dev`，打开
  <http://127.0.0.1:5173>，用 `CG_ADMIN_TOKEN` 登录。
- 配置与边界：`../docs/GATEWAY.md`
- 测试：`python -m pytest tests -q`；证据：`../docs/GATEWAY_TESTS.md`
- Agent 接入：`../docs/AGENT_INTEGRATION.md`

注意：不支持多 worker / 多副本；同一 `data/` 目录只允许一个实例。
更换 `VAULT_KEY` 会导致托管 Provider 配置无法解密、历史审计无法通过 MAC/链校验。
