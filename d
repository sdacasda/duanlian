#!/usr/bin/env bash
set -euo pipefail

DEPLOY_URL="https://raw.githubusercontent.com/sdacasda/duanlian/main/deploy_docker.sh"
INSTALL_URL="https://raw.githubusercontent.com/sdacasda/duanlian/main/install_v3.sh"

# 优先本地安装器，其次本地部署脚本，再次远程
if [ -f "install_v3.sh" ]; then
  exec bash install_v3.sh
elif [ -f "deploy_docker.sh" ]; then
  exec bash deploy_docker.sh
else
  # 默认拉取远程安装器，安装器内含菜单
  exec bash <(curl -fsSL "$INSTALL_URL")
fi
