#!/usr/bin/env bash
set -euo pipefail

if ! command -v docker >/dev/null 2>&1; then
  echo "docker 未安装，请先安装 docker 与 docker compose。" >&2
  exit 1
fi

if [ ! -f ".env" ]; then
cat > .env <<'EOF'
# 复制自 .env.example，可按需修改
SECRET_KEY=$(openssl rand -hex 16)
COOKIE_SECURE=False
DB_PATH=data/shortlink.db
DEEPL_API_KEY=
DEEPL_API_URL=https://api-free.deepl.com/v2/translate
DEEPL_CACHE_MAX=2000
DEEPL_CACHE_TTL=86400
DEEPL_TIMEOUT=8
DEEPL_RETRIES=1
LOGIN_MAX_ATTEMPTS=5
LOGIN_WINDOW=300
CAPTCHA_MAX_PER_WINDOW=30
CAPTCHA_WINDOW=300
TIKTOK_TIMEOUT=10
TIKTOK_RETRIES=2
TZ=Asia/Shanghai
EOF
  echo "已生成默认 .env，请检查后再次运行脚本或直接继续。"
fi

mkdir -p data backups static templates

if [ ! -f "docker-compose_v2.yml" ]; then
  echo "未找到 docker-compose_v2.yml" >&2
  exit 1
fi

echo "启动容器..."
docker compose -f docker-compose_v2.yml up -d

echo "完成。可访问 /admin 进行登录。"
