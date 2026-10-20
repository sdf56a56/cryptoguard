@echo off
chcp 65001 >nul
setlocal EnableDelayedExpansion
cd /d "%~dp0\backend"

echo ============================================
echo   CryptoGuard 安全中转网关（单进程）
echo   注意: 不支持多 worker；同 data\ 目录只允许一个实例
echo   控制台: start-ui.bat  (http://127.0.0.1:5173)
echo ============================================
echo.

rem ---- Python 解释器:优先 py(本机 python 可能是 WindowsApps 坏桩)----
set "PY="
where py >nul 2>nul && set "PY=py"
if not defined PY (
    where python >nul 2>nul && set "PY=python"
)
if not defined PY (
    echo [错误] 未找到 Python,请安装 Python 3.13+
    pause
    exit /b 1
)

echo [1/2] 检查后端依赖...
%PY% -c "import fastapi, uvicorn, cryptography, pydantic, rfc8785" >nul 2>nul
if errorlevel 1 (
    echo       首次运行,安装后端依赖...
    %PY% -m pip install -r requirements.txt -q
    if errorlevel 1 (
        echo [错误] 后端依赖安装失败
        pause
        exit /b 1
    )
)

echo [2/2] 启动服务...
if not defined CG_HOST set "CG_HOST=127.0.0.1"
if not defined CG_PORT set "CG_PORT=8100"
echo       监听: http://%CG_HOST%:%CG_PORT%
echo       按 Ctrl+C 停止服务
echo.
%PY% -m uvicorn app.main:app --host %CG_HOST% --port %CG_PORT% --workers 1

echo.
echo 服务已停止。
pause
