#!/usr/bin/env bash
set -euo pipefail

DEPLOY_URL="https://raw.githubusercontent.com/sdacasda/duanlian/main/deploy_docker.sh"

# 优先本地脚本，其次远程一键部署脚本
if [ -f "deploy_docker.sh" ]; then
  exec bash deploy_docker.sh
else
  exec bash <(curl -fsSL "$DEPLOY_URL")
fi
