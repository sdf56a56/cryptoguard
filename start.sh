#!/usr/bin/env bash
# CryptoGuard 安全中转网关 —— 单进程启动脚本（不含前端）
set -e
cd "$(dirname "$0")/backend"

PY="${PYTHON:-python}"
if [ -x .venv/bin/python ]; then
  PY=".venv/bin/python"
fi

if ! "$PY" -c "import fastapi, uvicorn, cryptography, pydantic" >/dev/null 2>&1; then
  echo "安装后端依赖..."
  "$PY" -m pip install -r requirements.txt -q
fi

HOST="${CG_HOST:-127.0.0.1}"
PORT="${CG_PORT:-8100}"

echo "============================================"
echo "  CryptoGuard 安全中转网关（单进程）"
echo "  监听: http://${HOST}:${PORT}"
echo "  注意: 不支持多 worker；同 data/ 目录只允许一个实例"
echo "============================================"

exec "$PY" -m uvicorn app.main:app --host "$HOST" --port "$PORT" --workers 1
