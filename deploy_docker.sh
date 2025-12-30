#!/usr/bin/env bash
set -euo pipefail

REPO_URL="https://github.com/sdacasda/duanlian.git"
WORKDIR="${1:-duanlian}"

if ! command -v git >/dev/null 2>&1; then
  echo "git 未安装，请先安装 git。" >&2
  exit 1
fi
if ! command -v docker >/dev/null 2>&1; then
  echo "docker 未安装，请先安装 docker 与 docker compose。" >&2
  exit 1
fi

if [ ! -d "$WORKDIR/.git" ]; then
  echo "克隆仓库: $REPO_URL -> $WORKDIR"
  git clone --depth=1 "$REPO_URL" "$WORKDIR"
else
  echo "已存在仓库目录 $WORKDIR，执行更新..."
  git -C "$WORKDIR" pull --ff-only
fi

cd "$WORKDIR"

if [ ! -f ".env" ] && [ -f ".env.example" ]; then
  cp .env.example .env
  echo "已生成 .env（来自 .env.example），请按需修改。"
fi

mkdir -p data backups static templates

if [ ! -f "docker-compose_v2.yml" ]; then
  echo "未找到 docker-compose_v2.yml" >&2
  exit 1
fi

echo "启动容器..."
docker compose -f docker-compose_v2.yml up -d

# 安装全局 d 快捷命令（若有权限）
if [ -w "/usr/local/bin" ]; then
  ln -sf "$(pwd)/d" /usr/local/bin/d
  echo "已安装全局快捷命令: d"
else
  echo "提示：/usr/local/bin 无写权限，跳过安装快捷命令 d。可手动运行：sudo ln -sf \"$(pwd)/d\" /usr/local/bin/d"
fi

echo "完成。请访问服务器 /admin 进行登录。"
