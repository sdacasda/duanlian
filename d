#!/usr/bin/env bash
set -euo pipefail

INSTALL_URL="https://raw.githubusercontent.com/sdacasda/duanlian/main/install_v3.sh"

if [ -f "install_v3.sh" ]; then
  exec bash install_v3.sh
else
  exec bash <(curl -sL "$INSTALL_URL")
fi
