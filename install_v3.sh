#!/bin/bash

BASE_URL="https://gist.githubusercontent.com/sdacasda/7dde7d536650aba99fddf5e28a3e3b71/raw/"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}请使用 root 用户运行此脚本！${NC}"
  exit 1
fi

if ! pwd >/dev/null 2>&1; then
  cd /root 2>/dev/null || exit 1
fi

get_input() {
    if [ -t 0 ]; then read -p "$1" value; else read -p "$1" value < /dev/tty; fi
    echo "$value"
}

get_secret_input() {
    if [ -t 0 ]; then
        read -s -p "$1" value
        printf "\n" > /dev/tty
    else
        read -s -p "$1" value < /dev/tty
        printf "\n" > /dev/tty
    fi
    printf "%s" "$value"
}

download_file() {
    local filename=$1
    local target_path=$2
    local url="${BASE_URL}${filename}?t=$(date +%s)"
    local tmp_path="${target_path}.tmp"

    mkdir -p "$(dirname "$target_path")" >/dev/null 2>&1 || true
    if [ -d "$target_path" ]; then
        rm -rf "$target_path" >/dev/null 2>&1 || true
    fi

    echo -e "正在下载: ${YELLOW}${filename}${NC} ..."
    curl -fsSL --retry 3 --connect-timeout 8 --max-time 60 "$url" -o "$tmp_path" >/dev/null 2>&1

    if [ $? -ne 0 ] || [ ! -s "$tmp_path" ]; then
        rm -f "$tmp_path" >/dev/null 2>&1 || true
        echo -e "${RED}下载失败: $filename${NC}"
        echo -e "下载地址: $url"
        return 1
    fi

    case "$filename" in
        *.html|*.htm)
            ;;
        *)
            if head -c 256 "$tmp_path" | grep -qi "<html\|<!doctype"; then
                rm -f "$tmp_path" >/dev/null 2>&1 || true
                echo -e "${RED}下载失败: $filename${NC}"
                echo -e "下载地址: $url"
                return 1
            fi
            ;;
    esac

    mv -f "$tmp_path" "$target_path"
}

download_vendor_one() {
    local out_path=$1
    shift
    local tmp_path="${out_path}.tmp"

    mkdir -p "$(dirname "$out_path")" >/dev/null 2>&1 || true

    for u in "$@"; do
        curl -fsSL --retry 3 --connect-timeout 8 --max-time 60 "$u" -o "$tmp_path" >/dev/null 2>&1
        if [ $? -eq 0 ] && [ -s "$tmp_path" ]; then
            if head -c 256 "$tmp_path" | grep -qi "<html\|<!doctype"; then
                rm -f "$tmp_path" >/dev/null 2>&1
                continue
            fi
            mv -f "$tmp_path" "$out_path"
            return 0
        fi
    done

    rm -f "$tmp_path" >/dev/null 2>&1 || true
    return 1
}

download_vendor_assets() {
    mkdir -p static/vendor >/dev/null 2>&1

    download_vendor_one "static/vendor/vue.global.prod.js" \
        "https://registry.npmmirror.com/vue/3.3.4/files/dist/vue.global.prod.js" \
        "https://cdn.jsdelivr.net/npm/vue@3.3.4/dist/vue.global.prod.js" \
        "https://unpkg.com/vue@3.3.4/dist/vue.global.prod.js" \
        "https://cdn.staticfile.org/vue/3.3.4/vue.global.prod.min.js" || true

    download_vendor_one "static/vendor/axios.min.js" \
        "https://registry.npmmirror.com/axios/1.4.0/files/dist/axios.min.js" \
        "https://cdn.jsdelivr.net/npm/axios@1.4.0/dist/axios.min.js" \
        "https://unpkg.com/axios@1.4.0/dist/axios.min.js" \
        "https://cdn.staticfile.org/axios/1.4.0/axios.min.js" || true

    download_vendor_one "static/vendor/echarts.min.js" \
        "https://registry.npmmirror.com/echarts/5.4.3/files/dist/echarts.min.js" \
        "https://cdn.jsdelivr.net/npm/echarts@5.4.3/dist/echarts.min.js" \
        "https://unpkg.com/echarts@5.4.3/dist/echarts.min.js" \
        "https://cdn.staticfile.org/echarts/5.4.3/echarts.min.js" || true

    download_vendor_one "static/vendor/world.js" \
        "https://registry.npmmirror.com/echarts/4.9.0/files/map/js/world.js" \
        "https://cdn.jsdelivr.net/npm/echarts@4.9.0/map/js/world.js" \
        "https://unpkg.com/echarts@4.9.0/map/js/world.js" \
        "https://cdn.staticfile.org/echarts/4.9.0/map/js/world.js" || true

    download_vendor_one "static/vendor/sweetalert2.all.min.js" \
        "https://registry.npmmirror.com/sweetalert2/11.7.12/files/dist/sweetalert2.all.min.js" \
        "https://cdn.jsdelivr.net/npm/sweetalert2@11/dist/sweetalert2.all.min.js" \
        "https://unpkg.com/sweetalert2@11/dist/sweetalert2.all.min.js" \
        "https://cdn.staticfile.org/sweetalert2/11.7.12/sweetalert2.all.min.js" || true
}

install_base() {
    echo -e "${BLUE}=== 部署 / 修复系统 (保留数据) ===${NC}"

    local INSTALL_DIR="/root/smart_tds"
    local IS_UPDATE=false
    local DOMAIN=""
    local ADMIN_USER=""
    local ADMIN_PASS=""

    if [ -f "$INSTALL_DIR/.env" ]; then
        IS_UPDATE=true
        DOMAIN=$(grep DOMAIN /root/.tds_info 2>/dev/null | cut -d= -f2)
        if [ -z "$DOMAIN" ]; then DOMAIN=$(cat /root/.tds_domain 2>/dev/null); fi
    else
        DOMAIN=$(get_input "请输入您的域名 (例如 baidu.com): ")
        ADMIN_USER=$(get_input "设置管理员用户名: ")
        ADMIN_PASS=$(get_secret_input "设置管理员密码: ")

        if [ -z "$DOMAIN" ] || [ -z "$ADMIN_USER" ] || [ -z "$ADMIN_PASS" ]; then
            echo -e "${RED}错误：必须填写所有信息！${NC}"
            return
        fi

        echo "$DOMAIN" > /root/.tds_domain
        cat > /root/.tds_info <<EOF
DOMAIN=$DOMAIN
ADMIN_USER=$ADMIN_USER
EOF
    fi

    mkdir -p "$INSTALL_DIR/data" "$INSTALL_DIR/backups" "$INSTALL_DIR/nginx/conf" "$INSTALL_DIR/certbot/conf" "$INSTALL_DIR/certbot/www" "$INSTALL_DIR/certbot/log" "$INSTALL_DIR/certbot/lib" "$INSTALL_DIR/templates" "$INSTALL_DIR/static/vendor"
    cd "$INSTALL_DIR" || return

    if ! command -v docker >/dev/null 2>&1; then
        echo -e "${YELLOW}安装 Docker...${NC}"
        curl -fsSL https://get.docker.com | bash -s -- >/dev/null 2>&1
    fi

    echo -e "${YELLOW}正在从 Gist 同步最新文件...${NC}"

    rm -rf "$INSTALL_DIR/main.py" "$INSTALL_DIR/templates/app.html" >/dev/null 2>&1 || true
    rm -rf "$INSTALL_DIR/main_v2.py" "$INSTALL_DIR/templates/app_v2.html" >/dev/null 2>&1 || true
    rm -rf "$INSTALL_DIR/requirements_v2.txt" "$INSTALL_DIR/docker-compose_v2.yml" >/dev/null 2>&1 || true

    download_file "main_v2.py" "$INSTALL_DIR/main_v2.py" || return
    download_file "requirements_v2.txt" "$INSTALL_DIR/requirements.txt" || return
    download_file "docker-compose_v2.yml" "$INSTALL_DIR/docker-compose.yml" || return
    download_file "app_v2.html" "$INSTALL_DIR/templates/app_v2.html" || return

    download_file "install_v3.sh" "/root/install_v3.sh" >/dev/null 2>&1 \
        || download_file "install%20v3.sh" "/root/install_v3.sh" >/dev/null 2>&1 \
        || true

    download_vendor_assets

    if [ ! -f ".env" ]; then
        cat > .env <<EOF
SECRET_KEY=$(openssl rand -hex 32)
COOKIE_SECURE=False
DB_PATH=data/shortlink.db
EOF
    fi

    if [ ! -f "nginx/conf/app.conf" ]; then
        cat > nginx/conf/app.conf <<EOF
server {
    listen 80;
    server_name $DOMAIN;
    server_tokens off;
    location /.well-known/acme-challenge/ { root /var/www/certbot; }
    location / {
        proxy_pass http://app:80;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header CF-Connecting-IP \$http_cf_connecting_ip;
        proxy_set_header CF-IPCountry \$http_cf_ipcountry;
    }
}
EOF
    fi

    echo -e "${GREEN}正在启动容器...${NC}"
    docker compose down >/dev/null 2>&1 || true
    docker compose up -d --build

    docker compose restart nginx >/dev/null 2>&1 || true

    if [ "$IS_UPDATE" = false ]; then
        echo -e "${YELLOW}正在等待服务启动以初始化管理员...${NC}"

        for i in {1..30}; do
            if docker compose ps | grep "app" | grep -q "Up"; then
                break
            fi
            sleep 1
        done

        echo -n "检测数据库: "
        local DB_READY=false
        for i in {1..90}; do
            if docker compose exec app ls /app/data/shortlink.db >/dev/null 2>&1; then
                DB_READY=true
                echo " 就绪!"
                break
            fi
            echo -n "."
            sleep 2
        done

        if [ "$DB_READY" = false ]; then
            echo -e "\n${RED}错误：数据库初始化超时。请查看日志：docker compose logs -n 200 app${NC}"
        else
            sleep 5
            docker compose exec -T -e ADMIN_USER="$ADMIN_USER" -e ADMIN_PASS="$ADMIN_PASS" app python - <<'PY'
import sqlite3, os, sys
from passlib.context import CryptContext

try:
    db_path = '/app/data/shortlink.db'
    admin_user = (os.environ.get('ADMIN_USER') or '').strip()
    admin_pass = os.environ.get('ADMIN_PASS') or ''

    if not admin_user or not admin_pass:
        print('ERROR: missing ADMIN_USER/ADMIN_PASS')
        sys.exit(2)

    pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')
    hashed = pwd_context.hash(admin_pass)

    con = sqlite3.connect(db_path, timeout=10)
    cur = con.cursor()

    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
    if not cur.fetchone():
        cur.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password_hash TEXT, role TEXT, link_limit INTEGER, expire_time TIMESTAMP, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)')

    cur.execute('SELECT id FROM users WHERE username=?', (admin_user,))
    if not cur.fetchone():
        cur.execute('INSERT INTO users (username, password_hash, role, link_limit) VALUES (?, ?, "admin", 99999)', (admin_user, hashed))
    else:
        cur.execute('UPDATE users SET password_hash=? WHERE username=?', (hashed, admin_user))

    con.commit()
    con.close()
    print('OK')
except Exception as e:
    print(f'ERROR:{e}')
    sys.exit(1)
PY
        fi
    fi

    view_info
}

setup_ssl() {
    echo -e "${BLUE}=== SSL 证书申请 ===${NC}"

    local DOMAIN=""
    if [ ! -f "/root/.tds_domain" ]; then
        DOMAIN=$(get_input "请输入您的域名: ")
    else
        DOMAIN=$(cat /root/.tds_domain)
    fi

    local EMAIL="admin@${DOMAIN}"

    cd /root/smart_tds || return
    mkdir -p nginx/conf certbot/conf certbot/www certbot/log certbot/lib >/dev/null 2>&1 || true

    cat > nginx/conf/app.conf <<EOF
server {
    listen 80;
    server_name $DOMAIN;
    server_tokens off;
    location /.well-known/acme-challenge/ { root /var/www/certbot; }
    location / {
        proxy_pass http://app:80;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header CF-Connecting-IP \$http_cf_connecting_ip;
        proxy_set_header CF-IPCountry \$http_cf_ipcountry;
    }
}
EOF

    docker compose restart nginx
    sleep 5

    docker compose run --rm --entrypoint "\
      certbot certonly --webroot -w /var/www/certbot \
      --config-dir /etc/letsencrypt --work-dir /var/lib/letsencrypt --logs-dir /var/log/letsencrypt \
      --server https://acme-v02.api.letsencrypt.org/directory \
      -d $DOMAIN \
      --email $EMAIL \
      --agree-tos --no-eff-email --force-renewal" certbot

    if [ $? -eq 0 ]; then
        if [ ! -f "certbot/conf/options-ssl-nginx.conf" ]; then
             curl -fsSLo certbot/conf/options-ssl-nginx.conf https://raw.githubusercontent.com/certbot/certbot/master/certbot-nginx/certbot_nginx/_internal/tls_configs/options-ssl-nginx.conf
        fi
        if [ ! -f "certbot/conf/ssl-dhparams.pem" ]; then
             curl -fsSLo certbot/conf/ssl-dhparams.pem https://raw.githubusercontent.com/certbot/certbot/master/certbot/certbot/ssl-dhparams.pem
        fi

        cat > nginx/conf/app.conf <<EOF
server {
    listen 80;
    server_name $DOMAIN;
    server_tokens off;
    location /.well-known/acme-challenge/ { root /var/www/certbot; }
    location / { return 301 https://\$host\$request_uri; }
}
server {
    listen 443 ssl;
    server_name $DOMAIN;
    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;
    location / {
        proxy_pass http://app:80;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header CF-Connecting-IP \$http_cf_connecting_ip;
        proxy_set_header CF-IPCountry \$http_cf_ipcountry;
    }
}
EOF

        sed -i 's/COOKIE_SECURE=False/COOKIE_SECURE=True/g' .env
        docker compose restart app
        docker compose restart nginx
        echo -e "${GREEN}HTTPS 配置完成！${NC}"
    else
        echo -e "${RED}证书申请失败。${NC}"
    fi
}

uninstall_tds() {
    echo -e "${RED}⚠️  警告：这将删除所有数据！${NC}"
    local CONFIRM
    CONFIRM=$(get_input "确认卸载吗？(y/n): ")
    if [ "$CONFIRM" = "y" ]; then
        cd /root/smart_tds 2>/dev/null || true
        docker compose down >/dev/null 2>&1 || true
        cd /root 2>/dev/null || true
        rm -rf /root/smart_tds
        rm -f /root/.tds_domain
        rm -f /root/.tds_info
        echo -e "${GREEN}已卸载。${NC}"
    fi
}

view_info() {
    if [ -f "/root/.tds_info" ]; then
        source /root/.tds_info
        echo -e "${YELLOW}==========================================${NC}"
        echo -e "域名:     ${GREEN}$DOMAIN${NC}"
        echo -e "后台入口: ${GREEN}http://$DOMAIN/admin${NC}"
        echo -e "管理员:   ${GREEN}$ADMIN_USER${NC}"
        echo -e "密码:     ${YELLOW}(出于安全考虑，密码不会本地保存；忘记密码请用菜单 5 重置)${NC}"
        echo -e "${YELLOW}==========================================${NC}"
    fi
    get_input "按回车键继续..."
}

reset_password() {
    echo -e "${BLUE}=== 重置管理员密码 ===${NC}"

    local OLD_USER=""
    if [ -f "/root/.tds_info" ]; then
        source /root/.tds_info
        OLD_USER=$ADMIN_USER
    fi

    echo -e "当前记录的管理员用户: ${GREEN}${OLD_USER:-未知}${NC}"

    local INPUT_USER
    INPUT_USER=$(get_input "请输入要重置的用户名 (留空默认 $OLD_USER): ")
    local TARGET_USER="${INPUT_USER:-$OLD_USER}"

    if [ -z "$TARGET_USER" ]; then
        echo -e "${RED}错误：必须指定用户名！${NC}"
        return
    fi

    local NEW_PASS
    NEW_PASS=$(get_secret_input "请输入新密码: ")
    if [ -z "$NEW_PASS" ]; then
        echo -e "${RED}错误：密码不能为空！${NC}"
        return
    fi

    cd /root/smart_tds || return

    docker compose exec -T -e ADMIN_USER="$TARGET_USER" -e ADMIN_PASS="$NEW_PASS" app python - <<'PY'
import sqlite3, os, sys
from passlib.context import CryptContext

try:
    admin_user = (os.environ.get('ADMIN_USER') or '').strip()
    admin_pass = os.environ.get('ADMIN_PASS') or ''
    if not admin_user or not admin_pass:
        print('ERROR: missing ADMIN_USER/ADMIN_PASS')
        sys.exit(2)

    pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')
    hashed = pwd_context.hash(admin_pass)

    con = sqlite3.connect('/app/data/shortlink.db')
    cur = con.cursor()

    cur.execute('UPDATE users SET password_hash=? WHERE username=?', (hashed, admin_user))
    if cur.rowcount == 0:
        cur.execute('INSERT INTO users (username, password_hash, role, link_limit) VALUES (?, ?, "admin", 99999)', (admin_user, hashed))

    con.commit()
    con.close()
    print('OK')
except Exception as e:
    print(f'ERROR:{e}')
    sys.exit(1)
PY

    if [ -f "/root/.tds_info" ]; then
        local DOMAIN_LINE
        DOMAIN_LINE=$(grep DOMAIN /root/.tds_info | head -n 1)
        echo "$DOMAIN_LINE" > /root/.tds_info
        echo "ADMIN_USER=$TARGET_USER" >> /root/.tds_info
    fi

    echo -e "${GREEN}✅ 密码重置/创建成功！${NC}"
    get_input "按回车键继续..."
}

update_files_only() {
    local INSTALL_DIR="/root/smart_tds"
    if [ ! -d "$INSTALL_DIR" ]; then
        echo -e "${RED}未找到安装目录，请先安装。${NC}"
        return
    fi

    cd "$INSTALL_DIR" || return

    echo -e "${YELLOW}正在更新文件...${NC}"

    rm -rf "$INSTALL_DIR/main.py" "$INSTALL_DIR/templates/app.html" >/dev/null 2>&1 || true
    rm -rf "$INSTALL_DIR/requirements_v2.txt" "$INSTALL_DIR/docker-compose_v2.yml" >/dev/null 2>&1 || true

    download_file "main_v2.py" "$INSTALL_DIR/main_v2.py" || return
    download_file "requirements_v2.txt" "$INSTALL_DIR/requirements.txt" || return
    download_file "docker-compose_v2.yml" "$INSTALL_DIR/docker-compose.yml" || return
    download_file "app_v2.html" "$INSTALL_DIR/templates/app_v2.html" || return

    download_file "install_v3.sh" "/root/install_v3.sh" >/dev/null 2>&1 \
        || download_file "install%20v3.sh" "/root/install_v3.sh" >/dev/null 2>&1 \
        || true

    download_vendor_assets

    docker compose up -d --build app
    docker compose restart nginx >/dev/null 2>&1 || true
    echo -e "${GREEN}完成！${NC}"
}

while true; do
    clear
    echo -e "${YELLOW}Smart TDS Pro 管理脚本 v3 (Gist 一键部署)${NC}"
    echo "1. 部署 / 修复系统 (保留数据)"
    echo "2. 申请 SSL 证书"
    echo "3. 卸载"
    echo "4. 查看信息"
    echo "5. 重置密码 (强制创建管理员)"
    echo "6. 强制更新系统文件"
    echo "0. 退出"

    choice=$(get_input "请选择: ")

    case $choice in
        1) install_base; break ;;
        2) setup_ssl; break ;;
        3) uninstall_tds; break ;;
        4) view_info ;;
        5) reset_password ;;
        6) update_files_only; break ;;
        0) exit 0 ;;
        *) echo "无效选择"; sleep 1 ;;
    esac
done