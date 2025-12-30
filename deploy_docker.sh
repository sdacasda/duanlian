#!/usr/bin/env bash
set -euo pipefail

INSTALL_URL="https://raw.githubusercontent.com/sdacasda/duanlian/main/install_v3.sh"

tmp_script=""
cleanup() { [ -n "$tmp_script" ] && rm -f "$tmp_script"; }
trap cleanup EXIT

if [ -f "install_v3.sh" ]; then
  bash install_v3.sh
else
  tmp_script=$(mktemp)
  curl -fsSL "$INSTALL_URL" -o "$tmp_script"
  chmod +x "$tmp_script"
  bash "$tmp_script"
fi

# 安装全局 d 快捷命令（若有权限且文件存在）
if [ -f "./d" ] && [ -w "/usr/local/bin" ]; then
  ln -sf "$(pwd)/d" /usr/local/bin/d
  echo "已安装全局快捷命令: d"
fi
