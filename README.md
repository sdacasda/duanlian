# Smart TDS Pro
轻量级多域名流量分发 / 短链平台（FastAPI + SQLite），支持营销跳转、TikTok Pixel/CAPI、邀请制用户体系与可视化管理前端。

## 快速部署（单行命令）
- 直接粘贴运行，默认目录为 `./duanlian`：
```bash
bash <(curl -fsSL https://raw.githubusercontent.com/sdacasda/duanlian/main/deploy_docker.sh)
```
- 安装后全局快捷命令（可选）：在仓库根目录执行
```bash
sudo ln -sf "$(pwd)/d" /usr/local/bin/d
```
之后任意终端输入 `d` 即可再次一键部署（本地有 `deploy_docker.sh` 则用本地，否则远程获取）。

## 核心功能
- 多目标分流：轮询、国家/设备过滤、安全落地页。
- 营销：跳转页/直跳、二维码、TikTok Pixel/CAPI 上报。
- 用户/邀请/套餐管理，PV/UV 统计，异步日志与每日备份。

## 环境变量（常用）
- `SECRET_KEY`（必填）、`COOKIE_SECURE`、`DB_PATH`（默认 `data/shortlink.db`）
- DeepL：`DEEPL_API_KEY` / `DEEPL_API_URL` / `DEEPL_CACHE_MAX` / `DEEPL_CACHE_TTL` / `DEEPL_TIMEOUT` / `DEEPL_RETRIES`
- TikTok：`TIKTOK_TIMEOUT` / `TIKTOK_RETRIES`
- 限流：`LOGIN_MAX_ATTEMPTS` / `LOGIN_WINDOW`、`CAPTCHA_MAX_PER_WINDOW` / `CAPTCHA_WINDOW`
- `TZ`：容器时区（如 `Asia/Shanghai`）

## 数据与备份
- SQLite WAL：`data/shortlink.db`
- 访问日志 `access_logs`：凌晨 3 点清理 6 个月前数据
- 每日备份：`backups/bk_YYYYMMDD.db`

## 安全与性能提示
- 部署 HTTPS 并设置 `COOKIE_SECURE=True`
- 登录/验证码接口已 IP 限流，可按流量调整
- 多实例时缓存不共享，建议改用 Redis 等集中存储
- 已加主要索引（links slug+domain、visitors ip_hash/link、access_logs link_id/created_at）；高并发可迁移外部 DB
