# Smart TDS Pro

## 项目简介
基于 FastAPI + SQLite 的轻量级流量分发/短链系统，支持多域名、多目标轮询、跳转页、TikTok Pixel/CAPI 事件上报、邀请制用户管理等。前端模板位于 `templates/app_v2.html`。

## 主要功能
- 账户体系：用户/管理员、验证码登录、邀请注册，支持套餐扩容（链接数、有效期）。
- 链接管理：多目标轮询、跳转页/直接跳转、营销落地页、TikTok 像素事件、国家/设备过滤、安全落地页。
- 域名管理：多域名绑定、授权用户、公共域名支持。
- 统计与日志：PV/UV 统计、访客持久化分流、访问日志异步写入、每日凌晨备份，旧日志自动清理。
- 工具：二维码生成 `/api/qr`，DeepL 翻译缓存，TikTok 事件模拟调试接口。
- 部署：提供 Docker Compose（Nginx + Certbot）与本地运行方式。

## 快速开始
### 本地运行
1) Python 3.11+  
2) 安装依赖：`pip install -r requirements_v2.txt`  
3) 复制 `.env.example` 为 `.env` 并填写配置  
4) 启动：`uvicorn main_v2:app --host 0.0.0.0 --port 8000 --proxy-headers`  
访问 `/admin` 登录（需预置管理员或使用邀请码注册）。

### Docker Compose
- `docker-compose_v2.yml` 已映射 `requirements_v2.txt` 为容器内 `requirements.txt`，模板目录为 `templates/`。  
- 启动：`docker compose -f docker-compose_v2.yml up -d`（确保 `.env`、`data/`、`backups/` 存在且有写权限）。  

## 环境变量
- `SECRET_KEY`：会话签名密钥，必填。  
- `COOKIE_SECURE`：`True` 时 Cookie 仅在 HTTPS 传输。  
- `DB_PATH`：SQLite 文件路径，默认 `data/shortlink.db`。  
- `DEEPL_API_KEY` / `DEEPL_API_URL` / `DEEPL_CACHE_MAX` / `DEEPL_CACHE_TTL`：翻译相关，可选。  
- `LOGIN_MAX_ATTEMPTS` / `LOGIN_WINDOW`：登录防爆破，默认 5 次/300 秒，超限返回 429。  
- `DEEPL_TIMEOUT` / `DEEPL_RETRIES`：DeepL 请求超时与重试次数，默认 8 秒/1 次重试。  
- `TIKTOK_TIMEOUT` / `TIKTOK_RETRIES`：TikTok 上报超时与重试次数，默认 10 秒/2 次重试。  
- `CAPTCHA_MAX_PER_WINDOW` / `CAPTCHA_WINDOW`：验证码接口限流，默认 30 次/300 秒，超限返回 429。  
- `TZ`：容器时区，如 `Asia/Shanghai`。  

## 数据与备份
- 数据库：`data/shortlink.db`（WAL）。  
- 访问日志：`access_logs` 表，凌晨 3 点清理 6 个月前数据。  
- 备份：`backups/bk_YYYYMMDD.db` 每日生成（需写权限）。  

## 已知待优化
- 多进程/多容器下缓存不共享，需 Redis 等集中存储或主动刷新。  
- 外部 API（TikTok/DeepL）可增加统一超时/重试与日志。  
- 高并发场景可考虑迁移到外部数据库或增加更多复合索引。  
