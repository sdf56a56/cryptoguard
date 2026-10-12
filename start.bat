@echo off
chcp 65001 >nul
setlocal EnableDelayedExpansion
cd /d "%~dp0"

echo ============================================
echo   CryptoGuard-LLM 一键启动
echo   双击运行,启动后自动打开浏览器
echo   用法: start.bat [--rebuild]   (--rebuild 强制重建前端)
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

rem ---- [1/3] 后端依赖(已满足则秒过)----
echo [1/3] 检查后端依赖...
cd backend
%PY% -c "import fastapi, uvicorn, cryptography, pydantic, rfc8785, ff3, pypdf, docx" >nul 2>nul
if errorlevel 1 (
    echo       首次运行,安装后端依赖...
    %PY% -m pip install -r requirements.txt -q
    if errorlevel 1 (
        echo [错误] 后端依赖安装失败
        pause
        exit /b 1
    )
)

rem ---- [2/3] 前端构建(有产物则跳过)----
echo [2/3] 检查前端构建...
cd ..\frontend
if not exist node_modules (
    echo       首次运行,安装前端依赖(约 1-3 分钟^)...
    call npm install
    if errorlevel 1 (
        echo [错误] 前端依赖安装失败
        pause
        exit /b 1
    )
)
if /i "%1"=="--rebuild" (
    echo       强制重建前端...
    call npm run build
) else (
    if exist dist\index.html (
        echo       已有构建产物,跳过(代码有改动请用 start.bat --rebuild^)
    ) else (
        echo       构建前端...
        call npm run build
    )
)
if errorlevel 1 (
    echo [错误] 前端构建失败
    pause
    exit /b 1
)

rem ---- [3/3] 启动服务,3 秒后自动开浏览器 ----
echo [3/3] 启动服务...
cd ..\backend
start "" /b cmd /c "timeout /t 3 /nobreak >nul & start http://localhost:8000"
echo.
echo       浏览器将自动打开;手动访问 http://localhost:8000
echo       按 Ctrl+C 停止服务
echo.
%PY% -m uvicorn app.main:app --host 0.0.0.0 --port 8000

echo.
echo 服务已停止。
pause
