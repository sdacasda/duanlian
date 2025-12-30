@echo off
setlocal enableextensions
set DIR=%1
if "%DIR%"=="" set DIR=duanlian
set REPO=https://github.com/sdacasda/duanlian.git

where git >nul 2>nul
if errorlevel 1 (
  echo [d] git 未找到，请先安装 Git for Windows.
  exit /b 1
)
where docker >nul 2>nul
if errorlevel 1 (
  echo [d] docker 未找到，请先安装 Docker Desktop.
  exit /b 1
)

if exist "%DIR%\\.git" (
  echo [d] 更新仓库...
  git -C "%DIR%" pull --ff-only
) else (
  echo [d] 克隆仓库到 %DIR% ...
  git clone --depth=1 "%REPO%" "%DIR%"
)

pushd "%DIR%" >nul

if not exist ".env" (
  if exist ".env.example" (
    copy /Y ".env.example" ".env" >nul
    echo [d] 已生成 .env（来自 .env.example），请按需修改。
  ) else (
    echo [d] 未找到 .env.example，请手动创建 .env
  )
)

if not exist data mkdir data
if not exist backups mkdir backups
if not exist static mkdir static
if not exist templates mkdir templates

if not exist "docker-compose_v2.yml" (
  echo [d] 未找到 docker-compose_v2.yml
  popd >nul
  exit /b 1
)

echo [d] 启动容器...
docker compose -f docker-compose_v2.yml up -d

popd >nul
echo [d] 完成，可访问 /admin 登录。
endlocal
