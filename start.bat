@echo off
chcp 65001 >nul
echo ============================================
echo   CryptoGuard 一键启动脚本
echo   面向大模型应用的敏感数据加密与防泄漏平台
echo ============================================
echo.

cd /d "%~dp0"

echo [1/3] 检查后端依赖...
cd backend
pip install -r requirements.txt -q
if errorlevel 1 (
    echo 后端依赖安装失败
    pause
    exit /b 1
)

echo [2/3] 构建前端...
cd ..\frontend
if not exist node_modules (
    echo 首次运行，安装前端依赖（约 1-3 分钟）...
    call npm install
)
call npm run build
if errorlevel 1 (
    echo 前端构建失败
    pause
    exit /b 1
)

echo [3/3] 启动服务...
cd ..\backend
echo.
echo 服务已启动，请打开浏览器访问: http://localhost:8000
echo 按 Ctrl+C 停止服务
echo.
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000

pause
