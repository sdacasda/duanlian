# Smart TDS Pro

轻量级多域名流量分发 / 短链平台，基于 FastAPI + SQLite，内置营销跳转、TikTok 像素/CAPI 上报、邀请制用户体系与可视化管理前端。

## 亮点速览
- ✨ 多目标智能分流：轮询、国家/设备过滤、安全落地页备用。
- 🎯 营销支持：跳转页/直跳、TikTok Pixel/CAPI 事件、二维码生成。
- 🔐 安全守护：登录/验证码限流、签名会话、可选 HTTPS Cookie。
- 🗃️ 数据自管：SQLite WAL、本地定时备份、异步日志写入。
- 🚀 一键上云：Docker Compose + Nginx/Certbot，附一键部署脚本。

## 目录
1. 快速开始（本地 & Docker）
2. 环境变量
3. 数据与备份
4. 安全/性能优化
5. 常用脚本

## 1) 快速开始
### 本地运行
1. Python 3.11+  
2. 安装依赖：`pip install -r requirements_v2.txt`  
3. 复制 `.env.example` 为 `.env` 并填写 `SECRET_KEY` 等  
4. 启动：`uvicorn main_v2:app --host 0.0.0.0 --port 8000 --proxy-headers`  
5. 访问 `/admin` 登录（需预置管理员或邀请码注册）

### Docker 部署
**一键脚本**：`bash deploy_docker.sh [目标目录]`  
作用：从 `https://github.com/sdacasda/duanlian.git` 克隆到指定目录（默认 `duanlian`），自动生成 `.env`（若不存在）、创建数据目录、启动 `docker-compose_v2.yml`。  

**一行命令（直接终端粘贴运行）**：  
```bash
DIR=duanlian REPO=https://github.com/sdacasda/duanlian.git bash -c '
set -euo pipefail
command -v git >/dev/null || { echo "缺少 git"; exit 1; }
command -v docker >/dev/null || { echo "缺少 docker 与 docker compose"; exit 1; }
[ -d "$DIR/.git" ] && git -C "$DIR" pull --ff-only || git clone --depth=1 "$REPO" "$DIR"
cd "$DIR"
[ -f .env ] || { [ -f .env.example ] && cp .env.example .env; }
mkdir -p data backups static templates
docker compose -f docker-compose_v2.yml up -d
echo "完成，访问 /admin 登录"
'
```
（如需自定义目录或仓库地址，修改 `DIR`、`REPO` 变量即可。）

**手动**：  
1. `git clone https://github.com/sdacasda/duanlian.git && cd duanlian`  
2. 准备 `.env`（可用 `.env.example` 拷贝）  
3. `docker compose -f docker-compose_v2.yml up -d`  
4. 默认挂载：`./data:/app/data`，`./backups:/app/backups`，模板/静态 `./templates:/app/templates`、`./static:/app/static`，依赖 `requirements_v2.txt` → 容器内 `requirements.txt`

## 2) 环境变量（重点）
- `SECRET_KEY`：会话签名密钥，必填。  
- `COOKIE_SECURE`：`True` 时 Cookie 仅在 HTTPS 传输。  
- `DB_PATH`：SQLite 文件路径，默认 `data/shortlink.db`。  
- DeepL：`DEEPL_API_KEY` / `DEEPL_API_URL` / `DEEPL_CACHE_MAX` / `DEEPL_CACHE_TTL` / `DEEPL_TIMEOUT` / `DEEPL_RETRIES`。  
- TikTok：`TIKTOK_TIMEOUT` / `TIKTOK_RETRIES`。  
- 限流：`LOGIN_MAX_ATTEMPTS` / `LOGIN_WINDOW`（默认 5 次/300 秒）、`CAPTCHA_MAX_PER_WINDOW` / `CAPTCHA_WINDOW`（默认 30 次/300 秒）。  
- `TZ`：容器时区（如 `Asia/Shanghai`）。  

## 3) 数据与备份
- DB：`data/shortlink.db`（WAL），表含用户/域名/链接/访客日志。  
- 访问日志：`access_logs`，凌晨 3 点清理 6 个月前数据。  
- 备份：`backups/bk_YYYYMMDD.db` 每日生成（需写权限）。  

## 4) 安全 & 性能建议
- HTTPS：用 Nginx + Certbot，`COOKIE_SECURE=True`。  
- 限流：登录/验证码接口已 IP 限流，可按流量调整。  
- 缓存：多进程/多容器时全局缓存不共享，需 Redis 等集中存储或改为 DB/通知刷新。  
- 数据库：已加索引（links slug+domain、visitors ip_hash/link、access_logs link_id/created_at）。高并发可迁移外部 DB。  
- 外部 API：已加超时与重试，建议在日志/监控中关注失败率。  

## 5) 常用脚本
- `deploy_docker.sh`：一键部署（生成 `.env`、准备目录、`docker compose up -d`）。  
- `install_v3.sh`：旧版安装脚本（保留参考，优先用新部署方式）。  

## 路径速记
- 后端：`main_v2.py`，模板：`templates/app_v2.html`，静态：`static/`  
- Compose：`docker-compose_v2.yml`  
- 环境示例：`.env.example`  
