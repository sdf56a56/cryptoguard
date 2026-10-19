#!/usr/bin/env bash
# CryptoGuard 控制台 —— 独立 Vite 前端（通过代理访问网关）
set -e
cd "$(dirname "$0")/frontend"

if [ ! -d node_modules ]; then
  echo "安装前端依赖..."
  npm install
fi

export CG_API_TARGET="${CG_API_TARGET:-http://127.0.0.1:8100}"
echo "============================================"
echo "  CryptoGuard 控制台"
echo "  地址: http://127.0.0.1:5173"
echo "  代理: ${CG_API_TARGET}"
echo "  登录令牌: 后端 CG_ADMIN_TOKEN"
echo "============================================"
exec npm run dev
