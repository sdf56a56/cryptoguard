#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

echo "============================================"
echo "  CryptoGuard 一键启动脚本"
echo "============================================"
echo

echo "[1/3] 安装后端依赖..."
cd backend
pip install -r requirements.txt -q

echo "[2/3] 构建前端..."
cd ../frontend
if [ ! -d node_modules ]; then
  echo "首次运行，安装前端依赖..."
  npm install
fi
npm run build

echo "[3/3] 启动服务..."
cd ../backend
echo "服务已启动: http://localhost:8000"
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
