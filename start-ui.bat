@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0frontend"

if not defined CG_API_TARGET set "CG_API_TARGET=http://127.0.0.1:8100"
if not exist node_modules (
    echo 安装前端依赖...
    call npm install
    if errorlevel 1 (
        echo [错误] 前端依赖安装失败
        pause
        exit /b 1
    )
)

echo ============================================
echo   CryptoGuard 控制台
echo   地址: http://127.0.0.1:5173
echo   代理: %CG_API_TARGET%
echo   登录令牌: 后端 CG_ADMIN_TOKEN
echo ============================================
echo.
call npm run dev

echo.
echo 控制台已停止。
pause
