import os
import secrets
import hashlib
import asyncio
import json
import logging
import time
import random
import shutil
import re
import html
import io
import urllib.request
from urllib.parse import urlparse, urlencode
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Tuple
from uuid import uuid4
from collections import OrderedDict
import threading

from dotenv import load_dotenv
from fastapi import FastAPI, Request, BackgroundTasks, Depends, Response, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.gzip import GZipMiddleware
from passlib.context import CryptContext
from itsdangerous import TimestampSigner
from pydantic import BaseModel, constr
import aiosqlite

try:
    import docker

    docker_client = docker.from_env()
except Exception:
    docker_client = None

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY", "fallback")
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "False").lower() == "true"
DB_PATH_RAW = os.getenv("DB_PATH", "data/shortlink.db")
NGINX_CONF_DIR = "/shared_conf"
BACKUP_DIR = "backups"

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

DEEPL_API_KEY = str(os.getenv("DEEPL_API_KEY", "") or "").strip()
DEEPL_API_URL = str(os.getenv("DEEPL_API_URL", "") or "").strip() or "https://api-free.deepl.com/v2/translate"
try:
    DEEPL_CACHE_MAX = int(os.getenv("DEEPL_CACHE_MAX", "2000") or 2000)
except Exception:
    DEEPL_CACHE_MAX = 2000
try:
    DEEPL_CACHE_TTL = int(os.getenv("DEEPL_CACHE_TTL", "86400") or 86400)
except Exception:
    DEEPL_CACHE_TTL = 86400
try:
    DEEPL_TIMEOUT = int(os.getenv("DEEPL_TIMEOUT", "8") or 8)
except Exception:
    DEEPL_TIMEOUT = 8
try:
    DEEPL_RETRIES = int(os.getenv("DEEPL_RETRIES", "1") or 1)
except Exception:
    DEEPL_RETRIES = 1
DEEPL_CACHE: "OrderedDict[Tuple[str, str], Tuple[float, str]]" = OrderedDict()
DEEPL_LOCK = threading.Lock()

QR_CACHE_TTL = 86400
QR_CACHE_MAX = 2000
QR_CACHE: "OrderedDict[str, Tuple[float, bytes, str, str]]" = OrderedDict()
QR_LOCK = threading.Lock()

try:
    LOGIN_MAX_ATTEMPTS = int(os.getenv("LOGIN_MAX_ATTEMPTS", "5") or 5)
except Exception:
    LOGIN_MAX_ATTEMPTS = 5
try:
    LOGIN_WINDOW = int(os.getenv("LOGIN_WINDOW", "300") or 300)
except Exception:
    LOGIN_WINDOW = 300
LOGIN_ATTEMPTS: Dict[str, List[float]] = {}
LOGIN_LOCK = asyncio.Lock()

try:
    CAPTCHA_MAX_PER_WINDOW = int(os.getenv("CAPTCHA_MAX_PER_WINDOW", "30") or 30)
except Exception:
    CAPTCHA_MAX_PER_WINDOW = 30
try:
    CAPTCHA_WINDOW = int(os.getenv("CAPTCHA_WINDOW", "300") or 300)
except Exception:
    CAPTCHA_WINDOW = 300
CAPTCHA_REQUESTS: Dict[str, List[float]] = {}
CAPTCHA_LOCK = asyncio.Lock()

try:
    TIKTOK_TIMEOUT = int(os.getenv("TIKTOK_TIMEOUT", "10") or 10)
except Exception:
    TIKTOK_TIMEOUT = 10
try:
    TIKTOK_RETRIES = int(os.getenv("TIKTOK_RETRIES", "2") or 2)
except Exception:
    TIKTOK_RETRIES = 2


def _deepl_lang_by_country(country: str) -> str:
    c = str(country or "").strip().upper()
    if c in ("CN", "HK", "TW"):
        return "ZH"
    if c == "JP":
        return "JA"
    if c == "KR":
        return "KO"
    if c in ("DE", "AT", "CH"):
        return "DE"
    if c in ("FR", "BE"):
        return "FR"
    if c in ("ES", "MX", "AR", "CL", "CO", "PE"):
        return "ES"
    if c == "BR":
        return "PT-BR"
    if c == "RU":
        return "RU"
    if c == "IT":
        return "IT"
    if c == "NL":
        return "NL"
    if c == "PL":
        return "PL"
    return "EN"


def _contains_cjk(s: str) -> bool:
    try:
        for ch in str(s or ""):
            o = ord(ch)
            if 0x4E00 <= o <= 0x9FFF:
                return True
            if 0x3040 <= o <= 0x30FF:
                return True
            if 0xAC00 <= o <= 0xD7AF:
                return True
    except Exception:
        return False
    return False


def _deepl_translate_text(text: str, target_lang: str) -> str:
    t = str(text or "")
    if not t.strip():
        return t
    lang = str(target_lang or "").strip().upper()
    if not lang or lang == "ZH":
        return t
    if not DEEPL_API_KEY:
        return t
    if lang in ("EN", "EN-US", "EN-GB") and not _contains_cjk(t):
        return t

    now = time.time()
    cache_key = (lang, t)
    try:
        with DEEPL_LOCK:
            hit = DEEPL_CACHE.get(cache_key)
            if hit and isinstance(hit, tuple) and len(hit) == 2:
                ts, val = hit
                if (now - float(ts or 0)) <= float(DEEPL_CACHE_TTL or 0):
                    try:
                        DEEPL_CACHE.move_to_end(cache_key)
                    except Exception:
                        pass
                    return str(val)
                try:
                    DEEPL_CACHE.pop(cache_key, None)
                except Exception:
                    pass
    except Exception:
        pass

    def _http_post_with_retry(url: str, data: bytes, headers: Dict[str, str], timeout: int, retries: int) -> str:
        last_err = None
        for attempt in range(retries + 1):
            try:
                req = urllib.request.Request(url, data=data, headers=headers, method="POST")
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    return resp.read().decode("utf-8", errors="ignore")
            except Exception as e:
                last_err = e
                if attempt < retries:
                    time.sleep(min(2 ** attempt, 3))
                else:
                    logger.warning(f"HTTP POST failed after {attempt + 1} attempts: {e}")
        return ""

    try:
        data = urlencode({"auth_key": DEEPL_API_KEY, "text": t, "target_lang": lang}).encode("utf-8")
        raw = _http_post_with_retry(
            DEEPL_API_URL,
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=DEEPL_TIMEOUT,
            retries=max(0, DEEPL_RETRIES),
        )
        obj = json.loads(raw) if raw else {}
        trans = ""
        if isinstance(obj, dict) and isinstance(obj.get("translations"), list) and obj["translations"]:
            first = obj["translations"][0]
            if isinstance(first, dict):
                trans = str(first.get("text") or "").strip()
        out = trans or t
    except Exception as e:
        logger.warning(f"DeepL request failed: {e}")
        out = t

    try:
        with DEEPL_LOCK:
            DEEPL_CACHE[cache_key] = (now, out)
            try:
                DEEPL_CACHE.move_to_end(cache_key)
            except Exception:
                pass
            while len(DEEPL_CACHE) > int(DEEPL_CACHE_MAX or 2000):
                try:
                    DEEPL_CACHE.popitem(last=False)
                except Exception:
                    break
    except Exception:
        pass

    return out


def translate_for_country(text: str, country: str) -> str:
    c = str(country or "").strip().upper()
    if c == "CN":
        return str(text or "")
    lang = _deepl_lang_by_country(c)
    return _deepl_translate_text(text, lang)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def _resolve_db_path(p: str) -> str:
    p = os.path.expanduser(str(p or "").strip())
    if not p:
        p = "data/shortlink.db"
    if os.path.isabs(p):
        return os.path.normpath(p)
    return os.path.normpath(os.path.join(BASE_DIR, p))

DB_PATH = _resolve_db_path(DB_PATH_RAW)
try:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
except Exception:
    pass
try:
    logger.info(f"DB_PATH={DB_PATH}")
except Exception:
    pass

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
signer = TimestampSigner(SECRET_KEY)

LINKS_CACHE: Dict[Tuple[str, int], Dict[str, Any]] = {}
DOMAINS_CACHE: Dict[int, str] = {}
DOMAINS_REVERSE: Dict[str, int] = {}
CAPTCHA_CACHE: Dict[str, str] = {}

LOG_BUFFER: List[Tuple[str, int, str, str, str, str, str, bool]] = []
BUFFER_LOCK = asyncio.Lock()

app = FastAPI(docs_url=None, redoc_url=None)
app.add_middleware(GZipMiddleware, minimum_size=1000)

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
try:
    os.makedirs(STATIC_DIR, exist_ok=True)
except Exception:
    pass
app.mount("/static", StaticFiles(directory=STATIC_DIR, check_dir=False), name="static")


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Global Error: {exc}", exc_info=True)
    if isinstance(exc, HTTPException):
        if request.url.path.startswith("/api/"):
            return JSONResponse({"error": getattr(exc, "detail", "Error")}, status_code=exc.status_code)
        return HTMLResponse(content=f"<h1>{getattr(exc, 'detail', 'Error')}</h1>", status_code=exc.status_code)
    if request.url.path.startswith("/api/"):
        return JSONResponse({"error": "Internal Server Error"}, status_code=500)
    return HTMLResponse(content="<h1>System Error</h1>", status_code=500)


class LinkPayload(BaseModel):
    slug: constr(min_length=1, max_length=50, pattern=r"^[a-zA-Z0-9_-]+$")
    targets: str
    domain_id: Optional[int] = None
    remark: Optional[str] = ""
    use_jump_page: bool = False
    landing_mode: Optional[str] = "both"
    pixel_id: Optional[str] = ""
    pixel_event_click: Optional[str] = "Lead"
    pixel_event_auto: Optional[str] = "ViewContent"
    media_url: Optional[str] = ""
    btn_text: Optional[str] = ""
    page_title: Optional[str] = ""
    page_desc: Optional[str] = ""
    safe_url: Optional[str] = ""
    auto_jump: int = 0
    tiktok_access_token: Optional[str] = ""
    tiktok_test_event_code: Optional[str] = ""
    marketing_options: Optional[str] = ""
    country_filter_list: Optional[str] = ""
    country_filter_allow: bool = False
    device_filter_list: Optional[str] = ""
    device_filter_allow: bool = False


class TikTokEventPayload(BaseModel):
    link_id: int
    event: str = "ClickButton"
    event_id: Optional[str] = None
    url: Optional[str] = ""
    referrer: Optional[str] = ""
    ttclid: Optional[str] = ""
    ttp: Optional[str] = ""
    email: Optional[str] = ""
    phone_number: Optional[str] = ""
    external_id: Optional[str] = ""
    pii_raw: int = 0
    test_event_code: Optional[str] = ""
    properties: Optional[Dict[str, Any]] = None


class DeletePayload(BaseModel):
    id: int


class DomainPayload(BaseModel):
    domain: str
    is_public: bool = True


class DomainUpdatePayload(BaseModel):
    id: int
    is_public: bool


class UserUpdatePayload(BaseModel):
    id: int
    link_limit: int
    expire_time: Optional[str] = None
    password: Optional[str] = None


class UserDomainPayload(BaseModel):
    user_id: int
    domain_ids: List[int]


class ClearStatsPayload(BaseModel):
    link_id: int
    range: str


class ClearStatsByReferrerPayload(BaseModel):
    link_id: int
    range: str = "all"
    referrer: str = ""


class SmartGenPayload(BaseModel):
    url: str


class UpdatePayload(BaseModel):
    confirm: bool
    update_backend: bool = False


class RedeemPayload(BaseModel):
    code: str


class ProductPayload(BaseModel):
    id: int = 0
    name: str
    add_links: int = 0
    add_days: int = 0
    price: str = ""
    enabled: bool = True


class PaymentSettingsPayload(BaseModel):
    payment_text: str = ""


@app.get("/")
async def root_redirect():
    return RedirectResponse("/admin", status_code=302)


@app.api_route("/admin", methods=["GET", "HEAD"])
@app.api_route("/login", methods=["GET", "HEAD"])
async def app_entry(request: Request):
    base_dir = os.path.dirname(__file__)
    path = os.path.join(base_dir, "templates", "app_v2.html")
    if not os.path.exists(path):
        raise HTTPException(status_code=500, detail="Missing template: templates/app_v2.html")
    return FileResponse(
        path,
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
            "Expires": "0",
        },
    )


@app.get("/api/qr")
async def api_qr(request: Request, data: str = "", fmt: str = "svg"):
    txt = str(data or "").strip()
    if not txt:
        raise HTTPException(status_code=400, detail="Empty")

    if len(txt) > 2048:
        raise HTTPException(status_code=400, detail="Too long")

    f = str(fmt or "svg").strip().lower()
    if f not in ("svg", "png"):
        f = "svg"

    key = hashlib.sha256((f + "|" + txt).encode("utf-8", errors="ignore")).hexdigest()
    etag = f'W/"qr-{key}"'
    try:
        inm = str(request.headers.get("if-none-match") or "")
        if inm == etag:
            return Response(status_code=304, headers={"ETag": etag, "Cache-Control": "private, max-age=86400"})
    except Exception:
        pass

    now = time.time()
    try:
        with QR_LOCK:
            hit = QR_CACHE.get(key)
            if hit and (now - float(hit[0] or 0)) <= QR_CACHE_TTL:
                QR_CACHE.move_to_end(key)
                content, media_type, _etag = hit[1], hit[2], hit[3]
                return Response(
                    content=content,
                    media_type=media_type,
                    headers={"ETag": _etag, "Cache-Control": "private, max-age=86400"},
                )
            if hit:
                try:
                    del QR_CACHE[key]
                except Exception:
                    pass
    except Exception:
        pass

    def _build_qr_bytes(payload: str, out_fmt: str) -> Tuple[bytes, str]:
        try:
            import qrcode
        except Exception as e:
            raise HTTPException(status_code=500, detail="qrcode module missing") from e

        if out_fmt == "png":
            try:
                qr = qrcode.QRCode(
                    version=None,
                    error_correction=qrcode.constants.ERROR_CORRECT_M,
                    box_size=10,
                    border=2,
                )
                qr.add_data(payload)
                qr.make(fit=True)
                img = qr.make_image(fill_color="black", back_color="white")
                buf = io.BytesIO()
                img.save(buf, format="PNG")
                return buf.getvalue(), "image/png"
            except HTTPException:
                raise
            except Exception as e:
                raise HTTPException(status_code=500, detail="png generation failed") from e

        try:
            import qrcode.image.svg
        except Exception as e:
            raise HTTPException(status_code=500, detail="svg generation failed") from e

        qr = qrcode.QRCode(
            version=None,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=10,
            border=2,
        )
        qr.add_data(payload)
        qr.make(fit=True)
        img = qr.make_image(image_factory=qrcode.image.svg.SvgImage)
        buf = io.BytesIO()
        img.save(buf)
        return buf.getvalue(), "image/svg+xml"

    content, media_type = await asyncio.to_thread(_build_qr_bytes, txt, f)
    try:
        with QR_LOCK:
            QR_CACHE[key] = (now, content, media_type, etag)
            QR_CACHE.move_to_end(key)
            while len(QR_CACHE) > QR_CACHE_MAX:
                try:
                    QR_CACHE.popitem(last=False)
                except Exception:
                    break
    except Exception:
        pass

    return Response(content=content, media_type=media_type, headers={"ETag": etag, "Cache-Control": "private, max-age=86400"})


async def init_db():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("PRAGMA journal_mode=WAL;")
        await db.execute(
            "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password_hash TEXT, role TEXT, link_limit INTEGER, expire_time TIMESTAMP, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"
        )
        await db.execute(
            "CREATE TABLE IF NOT EXISTS invites (code TEXT PRIMARY KEY, max_links INTEGER, expires_at TIMESTAMP, is_used BOOLEAN DEFAULT 0, used_by INTEGER, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"
        )
        await db.execute(
            "CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, add_links INTEGER DEFAULT 0, add_days INTEGER DEFAULT 0, price TEXT DEFAULT '', enabled BOOLEAN DEFAULT 1, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"
        )
        await db.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)")
        await db.execute(
            "CREATE TABLE IF NOT EXISTS domains (id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT UNIQUE, is_active BOOLEAN DEFAULT 1, is_public BOOLEAN DEFAULT 1, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"
        )
        await db.execute("CREATE TABLE IF NOT EXISTS domain_perms (user_id INTEGER, domain_id INTEGER, PRIMARY KEY(user_id, domain_id))")
        await db.execute(
            "CREATE TABLE IF NOT EXISTS links (id INTEGER PRIMARY KEY AUTOINCREMENT, slug TEXT NOT NULL, domain_id INTEGER, owner_id INTEGER, targets TEXT, remark TEXT, current_index INTEGER DEFAULT 0, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, UNIQUE(slug, domain_id))"
        )

        try:
            cursor = await db.execute("PRAGMA table_info(invites)")
            columns = [row[1] for row in await cursor.fetchall()]
            inv_new_cols = {
                "pack_links": "INTEGER DEFAULT 0",
                "pack_days": "INTEGER DEFAULT 0",
                "product_name": "TEXT DEFAULT ''",
                "price": "TEXT DEFAULT ''",
            }
            for col, dtype in inv_new_cols.items():
                if col not in columns:
                    await db.execute(f"ALTER TABLE invites ADD COLUMN {col} {dtype}")
            await db.commit()
        except Exception:
            pass

        try:
            cursor = await db.execute("PRAGMA table_info(users)")
            columns = [row[1] for row in await cursor.fetchall()]
            user_new_cols = {
                "link_limit": "INTEGER DEFAULT 10",
                "expire_time": "TIMESTAMP",
                "created_at": "TIMESTAMP DEFAULT CURRENT_TIMESTAMP",
            }
            for col, dtype in user_new_cols.items():
                if col not in columns:
                    await db.execute(f"ALTER TABLE users ADD COLUMN {col} {dtype}")
            await db.commit()
        except Exception:
            pass

        try:
            cursor = await db.execute("PRAGMA table_info(links)")
            columns = [row[1] for row in await cursor.fetchall()]
            new_cols = {
                "use_jump_page": "BOOLEAN DEFAULT 0",
                "landing_mode": "TEXT DEFAULT 'both'",
                "pixel_id": "TEXT DEFAULT ''",
                "pixel_event_click": "TEXT DEFAULT 'Lead'",
                "pixel_event_auto": "TEXT DEFAULT 'ViewContent'",
                "media_url": "TEXT DEFAULT ''",
                "btn_text": "TEXT DEFAULT ''",
                "page_title": "TEXT DEFAULT ''",
                "page_desc": "TEXT DEFAULT ''",
                "safe_url": "TEXT DEFAULT ''",
                "auto_jump": "INTEGER DEFAULT 0",
                "tiktok_access_token": "TEXT DEFAULT ''",
                "tiktok_test_event_code": "TEXT DEFAULT ''",
                "marketing_options": "TEXT DEFAULT ''",
                "country_filter_list": "TEXT DEFAULT ''",
                "country_filter_allow": "BOOLEAN DEFAULT 0",
                "device_filter_list": "TEXT DEFAULT ''",
                "device_filter_allow": "BOOLEAN DEFAULT 0",
            }
            for col, dtype in new_cols.items():
                if col not in columns:
                    await db.execute(f"ALTER TABLE links ADD COLUMN {col} {dtype}")
            await db.commit()
        except Exception:
            pass

        await db.execute(
            "CREATE TABLE IF NOT EXISTS visitors (ip_hash TEXT, link_id INTEGER, assigned_target TEXT, country TEXT, os TEXT, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (ip_hash, link_id))"
        )
        await db.execute(
            "CREATE TABLE IF NOT EXISTS access_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, slug TEXT, link_id INTEGER, ip_hash TEXT, target_url TEXT, country TEXT, os TEXT, referer TEXT, is_new_visitor BOOLEAN, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"
        )
        await db.execute("CREATE INDEX IF NOT EXISTS idx_access_logs_link_id ON access_logs(link_id)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_access_logs_created_at ON access_logs(created_at)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_visitors_ip_hash ON visitors(ip_hash)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_visitors_link_id ON visitors(link_id)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_links_slug_domain ON links(slug, domain_id)")
        await db.commit()


async def load_cache():
    global LINKS_CACHE, DOMAINS_CACHE, DOMAINS_REVERSE
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            db.row_factory = aiosqlite.Row
            doms = await db.execute_fetchall("SELECT * FROM domains WHERE is_active=1")
            DOMAINS_CACHE = {int(d["id"]): str(d["domain"]) for d in doms}
            DOMAINS_REVERSE = {str(d["domain"]).lower(): int(d["id"]) for d in doms}

            rows = await db.execute_fetchall("SELECT * FROM links")
            LINKS_CACHE = {}
            for r in rows:
                key = (str(r["slug"]), int(r["domain_id"] or 0))
                d = dict(r)
                try:
                    d["targets"] = json.loads(r["targets"])
                except Exception:
                    d["targets"] = []
                d.setdefault("use_jump_page", False)
                d.setdefault("landing_mode", "both")
                d.setdefault("pixel_id", "")
                d.setdefault("pixel_event_click", "Lead")
                d.setdefault("pixel_event_auto", "ViewContent")
                d.setdefault("media_url", "")
                d.setdefault("btn_text", "")
                d.setdefault("page_title", "")
                d.setdefault("page_desc", "")
                d.setdefault("safe_url", "")
                d.setdefault("auto_jump", 0)
                d.setdefault("tiktok_access_token", "")
                d.setdefault("tiktok_test_event_code", "")
                d.setdefault("marketing_options", "")
                d.setdefault("country_filter_list", "")
                d.setdefault("country_filter_allow", 0)
                d.setdefault("device_filter_list", "")
                d.setdefault("device_filter_allow", 0)
                LINKS_CACHE[key] = d
    except Exception as e:
        logger.error(f"Cache load error: {e}")


async def flush_logs():
    while True:
        await asyncio.sleep(1)
        async with BUFFER_LOCK:
            if not LOG_BUFFER:
                continue
            data = list(LOG_BUFFER)
            LOG_BUFFER.clear()
        try:
            async with aiosqlite.connect(DB_PATH) as db:
                await db.executemany(
                    "INSERT INTO access_logs (slug, link_id, ip_hash, target_url, country, os, referer, is_new_visitor) VALUES (?,?,?,?,?,?,?,?)",
                    data,
                )
                await db.commit()
        except Exception:
            pass


async def maintenance_task():
    while True:
        await asyncio.sleep(3600)
        if datetime.now().hour == 3:
            try:
                if not os.path.exists(BACKUP_DIR):
                    os.makedirs(BACKUP_DIR)
                if os.path.exists(DB_PATH):
                    shutil.copy(DB_PATH, f"{BACKUP_DIR}/bk_{datetime.now().strftime('%Y%m%d')}.db")
                async with aiosqlite.connect(DB_PATH) as db:
                    await db.execute("DELETE FROM access_logs WHERE created_at < date('now', '-6 months')")
                    await db.commit()
            except Exception:
                pass


@app.on_event("startup")
async def startup():
    await init_db()
    await load_cache()
    asyncio.create_task(flush_logs())
    asyncio.create_task(maintenance_task())


async def get_current_user(request: Request):
    token = request.headers.get("x-token") or request.cookies.get("session")
    if not token:
        return None
    try:
        data = json.loads(signer.unsign(token, max_age=86400 * 7).decode())
        async with aiosqlite.connect(DB_PATH) as db:
            db.row_factory = aiosqlite.Row
            u = await (
                await db.execute("SELECT id, username, role, link_limit, expire_time FROM users WHERE id=?", (data["uid"],))
            ).fetchone()
            if u and u["expire_time"] and u["expire_time"] < datetime.now().strftime("%Y-%m-%d"):
                return None
            return u
    except Exception:
        return None


@app.get("/api/auth/check")
async def check_auth(user=Depends(get_current_user)):
    return {"status": "authenticated", "user": dict(user)} if user else {"status": "guest"}


@app.get("/api/captcha")
async def api_cap(response: Response, request: Request):
    ip_addr = _get_client_ip(request)
    now_ts = time.time()
    async with CAPTCHA_LOCK:
        arr = [ts for ts in CAPTCHA_REQUESTS.get(ip_addr, []) if now_ts - ts < CAPTCHA_WINDOW]
        if len(arr) >= CAPTCHA_MAX_PER_WINDOW:
            return JSONResponse({"error": "请求过于频繁"}, 429)
        arr.append(now_ts)
        CAPTCHA_REQUESTS[ip_addr] = arr

    n1, n2 = random.randint(1, 10), random.randint(1, 10)
    cap_id = secrets.token_hex(8)
    CAPTCHA_CACHE[cap_id] = str(n1 + n2)
    response.set_cookie(
        "cap_id",
        cap_id,
        httponly=True,
        secure=COOKIE_SECURE,
        max_age=300,
        samesite="lax",
        path="/",
    )
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return {"q": f"{n1} + {n2} = ?", "cap_id": cap_id}


@app.post("/api/auth/login")
async def api_login(data: dict, response: Response, request: Request):
    ip_addr = _get_client_ip(request)
    now_ts = time.time()
    async with LOGIN_LOCK:
        arr = [ts for ts in LOGIN_ATTEMPTS.get(ip_addr, []) if now_ts - ts < LOGIN_WINDOW]
        if len(arr) >= LOGIN_MAX_ATTEMPTS:
            return JSONResponse({"error": "尝试过多，请稍后再试"}, 429)
        LOGIN_ATTEMPTS[ip_addr] = arr

    cid = request.cookies.get("cap_id") or data.get("cap_id") or data.get("capId")
    if not cid or CAPTCHA_CACHE.get(cid) != data.get("captcha"):
        async with LOGIN_LOCK:
            arr = [ts for ts in LOGIN_ATTEMPTS.get(ip_addr, []) if now_ts - ts < LOGIN_WINDOW]
            arr.append(now_ts)
            LOGIN_ATTEMPTS[ip_addr] = arr
        return JSONResponse({"error": "验证码错误"}, 400)
    try:
        del CAPTCHA_CACHE[cid]
    except Exception:
        pass

    username = str(data.get("username") or "").strip()
    password = str(data.get("password") or "")
    if not username or not password:
        return JSONResponse({"error": "用户名或密码错误"}, 401)

    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        u = await (await db.execute("SELECT * FROM users WHERE username=?", (username,))).fetchone()

    if u and pwd_context.verify(password, u["password_hash"]):
        if u["expire_time"] and u["expire_time"] < datetime.now().strftime("%Y-%m-%d"):
            return JSONResponse({"error": "账号已过期"}, 403)
        s = signer.sign(json.dumps({"uid": u["id"], "exp": time.time() + 604800})).decode()
        response.set_cookie(
            "session",
            s,
            httponly=True,
            secure=COOKIE_SECURE,
            max_age=604800,
            samesite="lax",
            path="/",
        )
        async with LOGIN_LOCK:
            LOGIN_ATTEMPTS.pop(ip_addr, None)
        return {"status": "ok", "token": s}

    async with LOGIN_LOCK:
        arr = [ts for ts in LOGIN_ATTEMPTS.get(ip_addr, []) if now_ts - ts < LOGIN_WINDOW]
        arr.append(now_ts)
        LOGIN_ATTEMPTS[ip_addr] = arr
    return JSONResponse({"error": "用户名或密码错误"}, 401)


@app.post("/api/auth/register")
async def api_reg(data: dict, request: Request):
    cid = request.cookies.get("cap_id") or data.get("cap_id") or data.get("capId")
    if not cid or CAPTCHA_CACHE.get(cid) != data.get("captcha"):
        return JSONResponse({"error": "验证码错误"}, 400)
    try:
        del CAPTCHA_CACHE[cid]
    except Exception:
        pass

    username = str(data.get("username") or "").strip()
    password = str(data.get("password") or "")
    invite = str(data.get("invite") or "").strip().upper()
    if not username or not password:
        return JSONResponse({"error": "参数错误"}, 400)

    async with aiosqlite.connect(DB_PATH) as db:
        if await (await db.execute("SELECT 1 FROM users WHERE username=?", (username,))).fetchone():
            return JSONResponse({"error": "Exists"}, 400)

        cnt = (await (await db.execute("SELECT COUNT(*) FROM users")).fetchone())[0]
        role, limit, inv_id, expire_time = ("admin", 9999, None, None) if cnt == 0 else ("user", 10, None, None)

        if cnt > 0:
            db.row_factory = aiosqlite.Row
            inv = await (
                await db.execute("SELECT * FROM invites WHERE code=? AND is_used=0", (invite,))
            ).fetchone()
            if not inv:
                return JSONResponse({"error": "Invalid Invite"}, 400)
            limit, inv_id = inv["max_links"], inv["code"]
            expire_time = inv["expires_at"]

        hashed = pwd_context.hash(password)
        c = await db.execute(
            "INSERT INTO users (username, password_hash, role, link_limit, expire_time) VALUES (?,?,?,?,?)",
            (username, hashed, role, limit, expire_time),
        )
        if inv_id:
            await db.execute("UPDATE invites SET is_used=1, used_by=? WHERE code=?", (c.lastrowid, inv_id))
        await db.commit()

    return {"status": "ok"}


@app.post("/api/auth/logout")
async def logout(response: Response):
    response.delete_cookie("session")
    return {}


@app.post("/api/auth/profile")
async def update_profile(data: dict, user=Depends(get_current_user)):
    if not user:
        return JSONResponse({"error": "Unauthorized"}, 401)

    current_pw = data.get("current_password")
    if not current_pw:
        return JSONResponse({"error": "请输入当前密码"}, 400)

    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        u = await (await db.execute("SELECT * FROM users WHERE id=?", (user["id"],))).fetchone()
        if not u or not pwd_context.verify(str(current_pw), u["password_hash"]):
            return JSONResponse({"error": "当前密码错误"}, 400)

        new_username = data.get("username")
        new_password = data.get("new_password")
        sql_parts: List[str] = []
        params: List[Any] = []

        if new_username and new_username != u["username"]:
            if await (await db.execute("SELECT 1 FROM users WHERE username=?", (new_username,))).fetchone():
                return JSONResponse({"error": "用户名已存在"}, 400)
            sql_parts.append("username=?")
            params.append(new_username)

        if new_password:
            if len(str(new_password)) < 6:
                return JSONResponse({"error": "密码过短"}, 400)
            sql_parts.append("password_hash=?")
            params.append(pwd_context.hash(str(new_password)))

        if sql_parts:
            params.append(user["id"])
            await db.execute(f"UPDATE users SET {','.join(sql_parts)} WHERE id=?", params)
            await db.commit()

    return {"status": "ok", "relogin": bool(data.get("new_password"))}


@app.get("/api/admin/users")
async def list_users(user=Depends(get_current_user)):
    if not user or user["role"] != "admin":
        return JSONResponse({}, 403)

    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        sql = (
            "SELECT u.id, u.username, u.role, u.link_limit, u.expire_time, u.created_at, COUNT(l.id) as used "
            "FROM users u LEFT JOIN links l ON u.id = l.owner_id GROUP BY u.id ORDER BY u.created_at DESC"
        )
        rows = await (await db.execute(sql)).fetchall()
        return [dict(r) for r in rows]


@app.post("/api/admin/user/update")
async def admin_update_user(payload: UserUpdatePayload, user=Depends(get_current_user)):
    if not user or user["role"] != "admin":
        return JSONResponse({}, 403)

    async with aiosqlite.connect(DB_PATH) as db:
        sql_parts = ["link_limit=?", "expire_time=?"]
        params: List[Any] = [payload.link_limit, payload.expire_time]
        if payload.password:
            sql_parts.append("password_hash=?")
            params.append(pwd_context.hash(payload.password))
        params.append(payload.id)
        await db.execute(f"UPDATE users SET {','.join(sql_parts)} WHERE id=?", params)
        await db.commit()
    return {"status": "ok"}


@app.get("/api/link/referrers_v2")
async def list_referrers_v2(link_id: int, range: str = "all", user=Depends(get_current_user)):
    if not user:
        return JSONResponse({}, 401)

    link_id = int(link_id or 0)
    if link_id <= 0:
        return JSONResponse({"error": "Missing link_id"}, 400)

    now_utc = datetime.utcnow()
    start_time = None
    if range and range != "all":
        hours = 1 if range == "1h" else 24
        start_time = now_utc - timedelta(hours=hours)

    async with aiosqlite.connect(DB_PATH) as db:
        link = await (await db.execute("SELECT owner_id FROM links WHERE id=?", (link_id,))).fetchone()
        if not link or (user["role"] != "admin" and int(link[0]) != int(user["id"])):
            return JSONResponse({"error": "Forbidden"}, 403)

        if start_time is None:
            rows = await (await db.execute(
                "SELECT referer, COUNT(*) as c FROM access_logs WHERE link_id=? GROUP BY referer ORDER BY c DESC",
                (link_id,),
            )).fetchall()
        else:
            rows = await (await db.execute(
                "SELECT referer, COUNT(*) as c FROM access_logs WHERE link_id=? AND created_at > ? GROUP BY referer ORDER BY c DESC",
                (link_id, start_time),
            )).fetchall()

    counts: Dict[str, int] = {}
    for r in rows:
        ref_url = (r[0] or "")
        domain = "Direct"
        if ref_url and ref_url != "Direct":
            try:
                domain = urlparse(ref_url).netloc.lower() or "Unknown"
            except Exception:
                domain = "Unknown"
        counts[domain] = counts.get(domain, 0) + int(r[1] or 0)

    items = [{"key": "__all__", "label": "全部来源", "count": int(sum(counts.values()))}]
    items.append({"key": "Direct", "label": "Direct（直接访问）", "count": int(counts.get("Direct", 0))})
    for k, v in sorted(counts.items(), key=lambda x: x[1], reverse=True):
        if k in ("Direct",):
            continue
        items.append({"key": k, "label": k, "count": int(v)})
    return {"items": items}


@app.post("/api/link/clear_stats_by_referrer_v2")
async def clear_stats_by_referrer_v2(payload: ClearStatsByReferrerPayload, user=Depends(get_current_user)):
    if not user:
        return JSONResponse({}, 401)

    link_id = int(payload.link_id or 0)
    if link_id <= 0:
        return JSONResponse({"error": "Missing link_id"}, 400)

    ref = str(payload.referrer or "").strip()
    if not ref:
        return JSONResponse({"error": "Missing referrer"}, 400)

    now_utc = datetime.utcnow()
    start_time = None
    if payload.range and payload.range != "all":
        hours = 1 if payload.range == "1h" else 24
        start_time = now_utc - timedelta(hours=hours)

    async with aiosqlite.connect(DB_PATH) as db:
        link = await (await db.execute("SELECT owner_id FROM links WHERE id=?", (link_id,))).fetchone()
        if not link or (user["role"] != "admin" and int(link[0]) != int(user["id"])):
            return JSONResponse({"error": "Forbidden"}, 403)

        if ref == "__all__":
            if start_time is None:
                await db.execute("DELETE FROM access_logs WHERE link_id=?", (link_id,))
                await db.execute("DELETE FROM visitors WHERE link_id=?", (link_id,))
            else:
                await db.execute("DELETE FROM access_logs WHERE link_id=? AND created_at > ?", (link_id, start_time))
        elif ref == "Direct":
            if start_time is None:
                await db.execute("DELETE FROM access_logs WHERE link_id=? AND (referer IS NULL OR referer='' OR referer='Direct')", (link_id,))
            else:
                await db.execute(
                    "DELETE FROM access_logs WHERE link_id=? AND created_at > ? AND (referer IS NULL OR referer='' OR referer='Direct')",
                    (link_id, start_time),
                )
        else:
            ref_domain = ref.lower()
            if start_time is None:
                await db.execute(
                    "DELETE FROM access_logs WHERE link_id=? AND referer LIKE ?",
                    (link_id, f"%://{ref_domain}/%"),
                )
            else:
                await db.execute(
                    "DELETE FROM access_logs WHERE link_id=? AND created_at > ? AND referer LIKE ?",
                    (link_id, start_time, f"%://{ref_domain}/%"),
                )

        await db.commit()
    return {"status": "ok"}


@app.post("/api/admin/user")
async def admin_update_user_alias(payload: UserUpdatePayload, user=Depends(get_current_user)):
    return await admin_update_user(payload, user=user)


@app.post("/api/admin/user/delete")
async def admin_delete_user(data: dict, user=Depends(get_current_user)):
    if not user or user["role"] != "admin":
        return JSONResponse({}, 403)

    uid = int(data.get("id") or 0)
    if uid <= 0:
        return JSONResponse({"error": "Missing id"}, 400)
    if uid == int(user["id"]):
        return JSONResponse({"error": "Cannot delete self"}, 400)

    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM users WHERE id=?", (uid,))
        await db.execute("DELETE FROM links WHERE owner_id=?", (uid,))
        await db.execute("DELETE FROM domain_perms WHERE user_id=?", (uid,))
        await db.commit()

    await load_cache()
    return {"status": "ok"}


@app.get("/api/admin/user/domains")
async def admin_get_user_domains(user_id: int, user=Depends(get_current_user)):
    if not user or user["role"] != "admin":
        return JSONResponse({}, 403)

    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = lambda c, r: r[0]
        return await (await db.execute("SELECT domain_id FROM domain_perms WHERE user_id=?", (user_id,))).fetchall()


@app.post("/api/admin/user/domains/update")
async def admin_update_user_domains(payload: UserDomainPayload, user=Depends(get_current_user)):
    if not user or user["role"] != "admin":
        return JSONResponse({}, 403)

    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM domain_perms WHERE user_id=?", (payload.user_id,))
        if payload.domain_ids:
            await db.executemany(
                "INSERT INTO domain_perms (user_id, domain_id) VALUES (?,?)",
                [(payload.user_id, int(did)) for did in payload.domain_ids],
            )
        await db.commit()
    return {"status": "ok"}


@app.get("/api/links")
async def get_links(
    page: int = 1,
    limit: int = 10,
    search: str = "",
    link_type: str = "all",
    sort: str = "created_desc",
    user=Depends(get_current_user),
):
    if not user:
        return JSONResponse({}, 401)

    page = int(page or 1)
    limit = int(limit or 10)
    if limit <= 0:
        limit = 10
    if limit > 100:
        limit = 100
    if page <= 0:
        page = 1
    offset = (page - 1) * limit

    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        where_clause = "WHERE l.owner_id=?"
        params: List[Any] = [user["id"]]

        if link_type == "jump":
            where_clause += " AND l.use_jump_page=1"
        elif link_type == "direct":
            where_clause += " AND (l.use_jump_page=0 OR l.use_jump_page IS NULL)"

        if search:
            where_clause += " AND (l.slug LIKE ? OR l.targets LIKE ? OR l.remark LIKE ?)"
            params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])

        sort_map = {
            "created_desc": "l.created_at DESC",
            "created_asc": "l.created_at ASC",
            "pv_desc": "pv DESC",
            "uv_desc": "uv DESC",
            "slug_asc": "l.slug ASC",
        }
        order_by = sort_map.get(sort, "l.created_at DESC")

        total = (await (await db.execute(f"SELECT COUNT(*) FROM links l {where_clause}", params)).fetchone())[0]
        data_sql = (
            "SELECT l.*, d.domain, "
            "(SELECT COUNT(*) FROM access_logs WHERE link_id=l.id) as pv, "
            "(SELECT COUNT(DISTINCT ip_hash) FROM access_logs WHERE link_id=l.id) as uv "
            f"FROM links l LEFT JOIN domains d ON l.domain_id = d.id {where_clause} "
            f"ORDER BY {order_by} LIMIT ? OFFSET ?"
        )
        rows = await (await db.execute(data_sql, params + [limit, offset])).fetchall()

        data: List[Dict[str, Any]] = []
        for r in rows:
            d = dict(r)
            try:
                d["targets"] = json.loads(r["targets"])
            except Exception:
                d["targets"] = []
            d.setdefault("use_jump_page", False)
            d.setdefault("landing_mode", "both")
            d.setdefault("pixel_id", "")
            d.setdefault("pixel_event_click", "Lead")
            d.setdefault("pixel_event_auto", "ViewContent")
            d.setdefault("media_url", "")
            d.setdefault("btn_text", "")
            d.setdefault("page_title", "")
            d.setdefault("page_desc", "")
            d.setdefault("safe_url", "")
            d.setdefault("auto_jump", 0)
            d.setdefault("tiktok_access_token", "")
            d.setdefault("tiktok_test_event_code", "")
            d.setdefault("marketing_options", "")
            d.setdefault("country_filter_list", "")
            d.setdefault("country_filter_allow", 0)
            d.setdefault("device_filter_list", "")
            d.setdefault("device_filter_allow", 0)
            data.append(d)

    return {"data": data, "total": total, "page": page, "pages": (total + limit - 1) // limit}


@app.get("/api/admin/all_links")
async def get_all_links(
    page: int = 1,
    limit: int = 10,
    search: str = "",
    link_type: str = "all",
    sort: str = "created_desc",
    user=Depends(get_current_user),
):
    if not user or user["role"] != "admin":
        return JSONResponse({}, 403)

    page = int(page or 1)
    limit = int(limit or 10)
    if limit <= 0:
        limit = 10
    if limit > 100:
        limit = 100
    if page <= 0:
        page = 1
    offset = (page - 1) * limit

    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        where_clause = "WHERE 1=1"
        params: List[Any] = []

        if link_type == "jump":
            where_clause += " AND l.use_jump_page=1"
        elif link_type == "direct":
            where_clause += " AND (l.use_jump_page=0 OR l.use_jump_page IS NULL)"

        if search:
            where_clause += " AND (l.slug LIKE ? OR l.targets LIKE ? OR l.remark LIKE ? OR u.username LIKE ?)"
            params.extend([f"%{search}%"] * 4)

        sort_map = {
            "created_desc": "l.created_at DESC",
            "created_asc": "l.created_at ASC",
            "pv_desc": "pv DESC",
            "uv_desc": "uv DESC",
            "slug_asc": "l.slug ASC",
        }
        order_by = sort_map.get(sort, "l.created_at DESC")

        count_sql = f"SELECT COUNT(*) FROM links l LEFT JOIN users u ON l.owner_id = u.id {where_clause}"
        total = (await (await db.execute(count_sql, params)).fetchone())[0]

        data_sql = (
            "SELECT l.*, u.username, d.domain, "
            "(SELECT COUNT(*) FROM access_logs WHERE link_id=l.id) as pv, "
            "(SELECT COUNT(DISTINCT ip_hash) FROM access_logs WHERE link_id=l.id) as uv "
            f"FROM links l LEFT JOIN users u ON l.owner_id = u.id LEFT JOIN domains d ON l.domain_id = d.id {where_clause} "
            f"ORDER BY {order_by} LIMIT ? OFFSET ?"
        )
        rows = await (await db.execute(data_sql, params + [limit, offset])).fetchall()

        data: List[Dict[str, Any]] = []
        for r in rows:
            d = dict(r)
            try:
                d["targets"] = json.loads(r["targets"])
            except Exception:
                d["targets"] = []
            d.setdefault("use_jump_page", False)
            d.setdefault("landing_mode", "both")
            d.setdefault("pixel_id", "")
            d.setdefault("pixel_event_click", "Lead")
            d.setdefault("pixel_event_auto", "ViewContent")
            d.setdefault("media_url", "")
            d.setdefault("btn_text", "")
            d.setdefault("page_title", "")
            d.setdefault("page_desc", "")
            d.setdefault("safe_url", "")
            d.setdefault("auto_jump", 0)
            d.setdefault("tiktok_access_token", "")
            d.setdefault("tiktok_test_event_code", "")
            d.setdefault("marketing_options", "")
            data.append(d)

    return {"data": data, "total": total, "page": page, "pages": (total + limit - 1) // limit}


@app.post("/api/link")
async def save_link(payload: LinkPayload, user=Depends(get_current_user)):
    if not user:
        return JSONResponse({}, 401)

    ts = [t.strip() for t in (payload.targets or "").split("\n") if t.strip()]
    if not ts:
        return JSONResponse({"error": "Empty"}, 400)

    try:
        async with aiosqlite.connect(DB_PATH) as db:
            sql_check = "SELECT id FROM links WHERE slug=? AND (domain_id=? OR (domain_id IS NULL AND ? IS NULL))"
            ex = await (await db.execute(sql_check, (payload.slug, payload.domain_id, payload.domain_id))).fetchone()

            landing_mode = str(payload.landing_mode or "both").strip().lower()
            if landing_mode not in ("media", "questions", "both"):
                landing_mode = "both"

            update_vals = [
                json.dumps(ts),
                payload.remark,
                user["id"],
                payload.use_jump_page,
                landing_mode,
                payload.pixel_id,
                payload.pixel_event_click,
                payload.pixel_event_auto,
                payload.media_url,
                payload.btn_text,
                payload.page_title,
                payload.page_desc,
                payload.safe_url,
                payload.auto_jump,
                payload.tiktok_access_token,
                payload.tiktok_test_event_code,
                payload.marketing_options,
                payload.country_filter_list,
                1 if payload.country_filter_allow else 0,
                payload.device_filter_list,
                1 if payload.device_filter_allow else 0,
            ]

            if ex:
                owner_check = await (await db.execute("SELECT owner_id FROM links WHERE id=?", (ex[0],))).fetchone()
                if user["role"] != "admin" and owner_check[0] != user["id"]:
                    return JSONResponse({"error": "后缀已被占用"}, 403)

                await db.execute(
                    "UPDATE links SET targets=?, remark=?, owner_id=?, use_jump_page=?, landing_mode=?, pixel_id=?, pixel_event_click=?, pixel_event_auto=?, media_url=?, btn_text=?, page_title=?, page_desc=?, safe_url=?, auto_jump=?, tiktok_access_token=?, tiktok_test_event_code=?, marketing_options=?, country_filter_list=?, country_filter_allow=?, device_filter_list=?, device_filter_allow=? WHERE id=?",
                    update_vals + [ex[0]],
                )
                link_id = ex[0]
            else:
                used = (await (await db.execute("SELECT COUNT(*) FROM links WHERE owner_id=?", (user["id"],))).fetchone())[0]
                if used >= int(user["link_limit"] or 0):
                    return JSONResponse({"error": "额度已满"}, 400)

                cur = await db.execute(
                    "INSERT INTO links (targets, remark, owner_id, use_jump_page, landing_mode, pixel_id, pixel_event_click, pixel_event_auto, media_url, btn_text, page_title, page_desc, safe_url, auto_jump, tiktok_access_token, tiktok_test_event_code, marketing_options, country_filter_list, country_filter_allow, device_filter_list, device_filter_allow, slug, domain_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    update_vals + [payload.slug, payload.domain_id],
                )
                link_id = cur.lastrowid

            await db.commit()

        key = (payload.slug, payload.domain_id if payload.domain_id else 0)
        LINKS_CACHE[key] = {
            "id": int(link_id),
            "targets": ts,
            "index": 0,
            "owner_id": int(user["id"]),
            "domain_id": payload.domain_id,
            "remark": payload.remark,
            "use_jump_page": payload.use_jump_page,
            "landing_mode": landing_mode,
            "pixel_id": payload.pixel_id,
            "pixel_event_click": payload.pixel_event_click,
            "pixel_event_auto": payload.pixel_event_auto,
            "media_url": payload.media_url,
            "btn_text": payload.btn_text,
            "page_title": payload.page_title,
            "page_desc": payload.page_desc,
            "safe_url": payload.safe_url,
            "auto_jump": payload.auto_jump,
            "tiktok_access_token": payload.tiktok_access_token,
            "tiktok_test_event_code": payload.tiktok_test_event_code,
            "marketing_options": payload.marketing_options,
            "country_filter_list": payload.country_filter_list,
            "country_filter_allow": 1 if payload.country_filter_allow else 0,
            "device_filter_list": payload.device_filter_list,
            "device_filter_allow": 1 if payload.device_filter_allow else 0,
        }
        return {}
    except Exception as e:
        logger.error(f"Save Link Error: {e}")
        return JSONResponse({"error": f"Save failed: {str(e)}"}, 500)


@app.post("/api/delete")
async def del_link(payload: DeletePayload, user=Depends(get_current_user)):
    if not user:
        return JSONResponse({}, 401)

    link_id = int(payload.id)
    async with aiosqlite.connect(DB_PATH) as db:
        ex = await (await db.execute("SELECT slug, domain_id, owner_id FROM links WHERE id=?", (link_id,))).fetchone()
        if not ex or (user["role"] != "admin" and int(ex[2]) != int(user["id"])):
            return JSONResponse({"error": "Forbidden"}, 403)

        await db.execute("DELETE FROM links WHERE id=?", (link_id,))
        await db.execute("DELETE FROM visitors WHERE link_id=?", (link_id,))
        await db.execute("DELETE FROM access_logs WHERE link_id=?", (link_id,))
        await db.commit()

        key = (str(ex[0]), int(ex[1] or 0))
        if key in LINKS_CACHE:
            del LINKS_CACHE[key]
    return {}


@app.post("/api/link/smart_gen")
async def smart_gen(payload: SmartGenPayload):
    url = (payload.url or "").strip()
    if not url:
        return JSONResponse({"error": "Empty URL"}, 400)
    try:
        parsed = urlparse(url)
        parts = [p for p in parsed.netloc.split(".") if p]
        domain_key = parts[-2] if len(parts) > 1 else (parts[0] if parts else "")
        path_key = [p for p in (parsed.path or "").split("/") if p][-1] if parsed.path else ""
        suggestion = f"{domain_key}-{path_key}" if domain_key and path_key else (domain_key or path_key or secrets.token_hex(3))
        suggestion = re.sub(r"[^a-zA-Z0-9-]", "", suggestion)[:20]
        return {"slug": suggestion}
    except Exception:
        return {"slug": secrets.token_hex(3)}


@app.post("/api/link/clear_stats_v2")
async def clear_stats_v2(payload: ClearStatsPayload, user=Depends(get_current_user)):
    if not user:
        return JSONResponse({}, 401)

    now_utc = datetime.utcnow()
    async with aiosqlite.connect(DB_PATH) as db:
        link = await (await db.execute("SELECT owner_id FROM links WHERE id=?", (payload.link_id,))).fetchone()
        if not link or (user["role"] != "admin" and int(link[0]) != int(user["id"])):
            return JSONResponse({"error": "Forbidden"}, 403)

        if payload.range == "all":
            await db.execute("DELETE FROM access_logs WHERE link_id=?", (payload.link_id,))
            await db.execute("DELETE FROM visitors WHERE link_id=?", (payload.link_id,))
        else:
            hours = 1 if payload.range == "1h" else 24
            time_threshold = now_utc - timedelta(hours=hours)
            await db.execute("DELETE FROM access_logs WHERE link_id=? AND created_at > ?", (payload.link_id, time_threshold))

        await db.commit()
    return {"status": "ok"}


@app.get("/api/stats/{slug}")
async def stats(slug: str, range: str = "7d", user=Depends(get_current_user)):
    if not user:
        return JSONResponse({}, 401)

    now_utc = datetime.utcnow()
    if range == "8h":
        start_time = now_utc - timedelta(hours=8)
        time_expr = "strftime('%Y-%m-%d %H:%M', datetime(created_at, 'localtime'))"
    elif range == "24h":
        start_time = now_utc - timedelta(hours=24)
        time_expr = "strftime('%Y-%m-%d %H', datetime(created_at, 'localtime')) || ':' || CASE WHEN CAST(strftime('%M', datetime(created_at, 'localtime')) AS INTEGER) < 30 THEN '00' ELSE '30' END"
    elif range == "30d":
        start_time = now_utc - timedelta(days=30)
        time_expr = "strftime('%Y-%m-%d', datetime(created_at, 'localtime'))"
    else:
        start_time = now_utc - timedelta(days=7)
        time_expr = "strftime('%Y-%m-%d', datetime(created_at, 'localtime'))"

    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        pvuv = await (await db.execute("SELECT COUNT(*) as pv, COUNT(DISTINCT ip_hash) as uv FROM access_logs WHERE slug=?", (slug,))).fetchone()
        sql_trend = f"SELECT {time_expr} as t, COUNT(*) as c FROM access_logs WHERE slug=? AND created_at > ? GROUP BY t ORDER BY t"
        tr = await (await db.execute(sql_trend, (slug, start_time))).fetchall()
        geo = await (await db.execute("SELECT country, COUNT(*) as c FROM access_logs WHERE slug=? AND created_at > ? GROUP BY country ORDER BY c DESC LIMIT 200", (slug, start_time))).fetchall()
        refs = await (await db.execute("SELECT referer, COUNT(*) as c FROM access_logs WHERE slug=? AND created_at > ? GROUP BY referer", (slug, start_time))).fetchall()
        os_data = await (await db.execute("SELECT os, COUNT(*) as c FROM access_logs WHERE slug=? AND created_at > ? GROUP BY os", (slug, start_time))).fetchall()

    sources: Dict[str, int] = {}
    for r in refs:
        ref_url = r["referer"]
        domain = "Direct"
        if ref_url and ref_url != "Direct":
            try:
                domain = urlparse(ref_url).netloc.lower() or "Unknown"
            except Exception:
                domain = "Unknown"
        sources[domain] = sources.get(domain, 0) + int(r["c"])

    return {
        "pv": pvuv["pv"],
        "uv": pvuv["uv"],
        "trend": {r["t"]: r["c"] for r in tr},
        "geo": {r["country"]: r["c"] for r in geo},
        "source": dict(sorted(sources.items(), key=lambda x: x[1], reverse=True)[:8]),
        "os": {r["os"]: r["c"] for r in os_data},
    }


@app.get("/api/stats_id/{link_id}")
async def stats_id(link_id: int, range: str = "7d", user=Depends(get_current_user)):
    if not user:
        return JSONResponse({}, 401)

    link_id = int(link_id or 0)
    if link_id <= 0:
        return JSONResponse({"error": "Invalid id"}, 400)

    now_utc = datetime.utcnow()
    if range == "8h":
        start_time = now_utc - timedelta(hours=8)
        time_expr = "strftime('%Y-%m-%d %H:%M', datetime(created_at, 'localtime'))"
    elif range == "24h":
        start_time = now_utc - timedelta(hours=24)
        time_expr = "strftime('%Y-%m-%d %H', datetime(created_at, 'localtime')) || ':' || CASE WHEN CAST(strftime('%M', datetime(created_at, 'localtime')) AS INTEGER) < 30 THEN '00' ELSE '30' END"
    elif range == "30d":
        start_time = now_utc - timedelta(days=30)
        time_expr = "strftime('%Y-%m-%d', datetime(created_at, 'localtime'))"
    else:
        start_time = now_utc - timedelta(days=7)
        time_expr = "strftime('%Y-%m-%d', datetime(created_at, 'localtime'))"

    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        link = await (await db.execute("SELECT owner_id FROM links WHERE id=?", (link_id,))).fetchone()
        if not link:
            return JSONResponse({"error": "Not Found"}, 404)
        if user["role"] != "admin" and int(link[0] or 0) != int(user["id"]):
            return JSONResponse({"error": "Forbidden"}, 403)

        pvuv = await (
            await db.execute(
                "SELECT COUNT(*) as pv, COUNT(DISTINCT ip_hash) as uv FROM access_logs WHERE link_id=?",
                (link_id,),
            )
        ).fetchone()
        sql_trend = f"SELECT {time_expr} as t, COUNT(*) as c FROM access_logs WHERE link_id=? AND created_at > ? GROUP BY t ORDER BY t"
        tr = await (await db.execute(sql_trend, (link_id, start_time))).fetchall()
        geo = await (
            await db.execute(
                "SELECT country, COUNT(*) as c FROM access_logs WHERE link_id=? AND created_at > ? GROUP BY country ORDER BY c DESC LIMIT 200",
                (link_id, start_time),
            )
        ).fetchall()
        refs = await (
            await db.execute(
                "SELECT referer, COUNT(*) as c FROM access_logs WHERE link_id=? AND created_at > ? GROUP BY referer",
                (link_id, start_time),
            )
        ).fetchall()
        os_data = await (
            await db.execute(
                "SELECT os, COUNT(*) as c FROM access_logs WHERE link_id=? AND created_at > ? GROUP BY os",
                (link_id, start_time),
            )
        ).fetchall()

    sources: Dict[str, int] = {}
    for r in refs:
        ref_url = r["referer"]
        domain = "Direct"
        if ref_url and ref_url != "Direct":
            try:
                domain = urlparse(ref_url).netloc.lower() or "Unknown"
            except Exception:
                domain = "Unknown"
        sources[domain] = sources.get(domain, 0) + int(r["c"])

    return {
        "pv": pvuv["pv"],
        "uv": pvuv["uv"],
        "trend": {r["t"]: r["c"] for r in tr},
        "geo": {r["country"]: r["c"] for r in geo},
        "source": dict(sorted(sources.items(), key=lambda x: x[1], reverse=True)[:8]),
        "os": {r["os"]: r["c"] for r in os_data},
    }


async def setup_domain_ssl(domain: str):
    if not docker_client:
        return False
    try:
        conf_content = (
            f"server {{ listen 80; server_name {domain}; location /.well-known/acme-challenge/ {{ root /var/www/certbot; }} "
            f"location / {{ return 301 https://$host$request_uri; }} }}"
        )
        with open(f"{NGINX_CONF_DIR}/{domain}.conf", "w", encoding="utf-8") as f:
            f.write(conf_content)
        try:
            docker_client.containers.get("nginx").exec_run("nginx -s reload")
        except Exception:
            pass

        certbot = docker_client.containers.get("certbot")
        cmd = (
            f"certbot certonly --webroot -w /var/www/certbot -d {domain} "
            f"--register-unsafely-without-email --agree-tos --force-renewal"
        )
        if certbot.exec_run(cmd)[0] != 0:
            try:
                conf_path = f"{NGINX_CONF_DIR}/{domain}.conf"
                if os.path.exists(conf_path):
                    os.remove(conf_path)
            except Exception:
                pass
            try:
                docker_client.containers.get("nginx").exec_run("nginx -s reload")
            except Exception:
                pass
            return False

        https_conf = (
            f"server {{ listen 80; server_name {domain}; location /.well-known/acme-challenge/ {{ root /var/www/certbot; }} "
            f"location / {{ return 301 https://$host$request_uri; }} }} "
            f"server {{ listen 443 ssl; server_name {domain}; "
            f"ssl_certificate /etc/letsencrypt/live/{domain}/fullchain.pem; "
            f"ssl_certificate_key /etc/letsencrypt/live/{domain}/privkey.pem; "
            f"include /etc/letsencrypt/options-ssl-nginx.conf; "
            f"ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem; "
            f"location / {{ proxy_pass http://app:80; proxy_set_header Host $host; proxy_set_header X-Real-IP $remote_addr; "
            f"proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for; proxy_set_header X-Forwarded-Proto $scheme; "
            f"proxy_set_header CF-Connecting-IP $http_cf_connecting_ip; proxy_set_header CF-IPCountry $http_cf_ipcountry; }} }}"
        )
        with open(f"{NGINX_CONF_DIR}/{domain}.conf", "w", encoding="utf-8") as f:
            f.write(https_conf)
        try:
            docker_client.containers.get("nginx").exec_run("nginx -s reload")
        except Exception:
            pass
        return True
    except Exception:
        return False


@app.get("/api/admin/backup")
async def admin_backup(user=Depends(get_current_user)):
    if not user or user["role"] != "admin":
        return JSONResponse({}, 403)
    try:
        return Response(
            content=open(DB_PATH, "rb").read(),
            media_type="application/octet-stream",
            headers={"Content-Disposition": f"attachment; filename=bk_{int(time.time())}.db"},
        )
    except Exception:
        return JSONResponse({"error": "Backup failed"}, 500)


@app.get("/api/domains")
async def list_domains(user=Depends(get_current_user)):
    if not user:
        return JSONResponse({}, 401)
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        if user["role"] == "admin":
            rows = await (await db.execute("SELECT * FROM domains ORDER BY created_at DESC")).fetchall()
            return [dict(r) for r in rows]
        rows = await (
            await db.execute(
                "SELECT * FROM domains WHERE is_public=1 "
                "UNION SELECT d.* FROM domains d JOIN domain_perms dp ON d.id=dp.domain_id WHERE dp.user_id=?",
                (user["id"],),
            )
        ).fetchall()
        return [dict(r) for r in rows]


@app.post("/api/domain/add")
async def add_domain(payload: DomainPayload, user=Depends(get_current_user)):
    if not user or user["role"] != "admin":
        return JSONResponse({"error": "Denied"}, 403)
    d = (payload.domain or "").strip().lower()
    if not d:
        return JSONResponse({"error": "Required"}, 400)
    success = await setup_domain_ssl(d)
    if not success:
        return JSONResponse({"error": "SSL Failed"}, 400)
    async with aiosqlite.connect(DB_PATH) as db:
        try:
            await db.execute(
                "INSERT INTO domains (domain, is_public) VALUES (?, ?)",
                (d, 1 if payload.is_public else 0),
            )
            await db.commit()
            await load_cache()
        except Exception:
            return JSONResponse({"error": "Exists"}, 400)
    return {"status": "ok"}


@app.post("/api/domain/update")
async def update_domain(payload: DomainUpdatePayload, user=Depends(get_current_user)):
    if not user or user["role"] != "admin":
        return JSONResponse({}, 403)
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "UPDATE domains SET is_public=? WHERE id=?",
            (1 if payload.is_public else 0, payload.id),
        )
        await db.commit()
    await load_cache()
    return {"status": "ok"}


@app.post("/api/domain/delete")
async def delete_domain(data: dict, user=Depends(get_current_user)):
    if not user or user["role"] != "admin":
        return JSONResponse({}, 403)
    did = int(data.get("id") or 0)
    if did <= 0:
        return JSONResponse({"error": "Missing id"}, 400)
    async with aiosqlite.connect(DB_PATH) as db:
        drow = await (await db.execute("SELECT domain FROM domains WHERE id=?", (did,))).fetchone()
        if drow:
            dom = drow[0]
            try:
                conf = f"{NGINX_CONF_DIR}/{dom}.conf"
                if os.path.exists(conf):
                    os.remove(conf)
            except Exception:
                pass
            if docker_client:
                try:
                    docker_client.containers.get("nginx").exec_run("nginx -s reload")
                except Exception:
                    pass
        await db.execute("DELETE FROM domain_perms WHERE domain_id=?", (did,))
        await db.execute("DELETE FROM domains WHERE id=?", (did,))
        await db.commit()
    await load_cache()
    return {"status": "ok"}


@app.post("/api/admin/gen_invite")
async def admin_gen_invite(
    limit: int = 10,
    count: int = 1,
    days: int = 30,
    product_id: int = 0,
    valid_days: Optional[int] = None,
    pack_days: Optional[int] = None,
    user=Depends(get_current_user),
):
    if not user or user["role"] != "admin":
        return JSONResponse({}, 403)
    codes = [secrets.token_hex(4).upper() for _ in range(int(count or 1))]

    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        pack_links = int(limit or 0)
        pack_days_val = int(pack_days or 0)
        product_name = ""
        price = ""

        if product_id:
            p = await (
                await db.execute(
                    "SELECT id, name, add_links, add_days, price, enabled FROM products WHERE id=?",
                    (product_id,),
                )
            ).fetchone()
            if not p:
                return JSONResponse({"error": "套餐不存在"}, 400)
            if not int(p["enabled"] or 0):
                return JSONResponse({"error": "套餐已停用"}, 400)
            if int(p["add_links"] or 0) > 0 and int(p["add_days"] or 0) > 0:
                return JSONResponse({"error": "套餐配置错误：额度与天数不能同时生效"}, 400)
            product_name = str(p["name"] or "")
            price = str(p["price"] or "")
            pack_links = int(p["add_links"] or 0)
            pack_days_val = int(p["add_days"] or 0)
        else:
            if pack_links > 0 and pack_days_val > 0:
                return JSONResponse({"error": "自定义卡密只能选择增加额度或增加天数（二选一）"}, 400)
            if pack_links <= 0 and pack_days_val <= 0:
                return JSONResponse({"error": "请设置增加额度或增加天数"}, 400)

        exp_days = int(valid_days if valid_days is not None else (days or 0))
        if exp_days <= 0:
            exp_days = 30
        expires_at = datetime.now() + timedelta(days=exp_days)

        rows = []
        for c in codes:
            rows.append((c, pack_links, expires_at, pack_links, pack_days_val, product_name, price))
        await db.executemany(
            "INSERT INTO invites (code, max_links, expires_at, pack_links, pack_days, product_name, price) VALUES (?,?,?,?,?,?,?)",
            rows,
        )
        await db.commit()
    return {"codes": codes}


@app.get("/api/admin/products")
async def admin_list_products(user=Depends(get_current_user)):
    if not user or user["role"] != "admin":
        return JSONResponse({}, 403)
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        rows = await (
            await db.execute(
                "SELECT id, name, add_links, add_days, price, enabled, created_at FROM products ORDER BY created_at DESC"
            )
        ).fetchall()
        return [dict(r) for r in rows]


@app.post("/api/admin/product/save")
async def admin_save_product(payload: ProductPayload, user=Depends(get_current_user)):
    if not user or user["role"] != "admin":
        return JSONResponse({}, 403)
    name = (payload.name or "").strip()
    if not name:
        return JSONResponse({"error": "名称不能为空"}, 400)
    add_links = int(payload.add_links or 0)
    add_days = int(payload.add_days or 0)
    price = str(payload.price or "").strip()
    enabled = 1 if payload.enabled else 0
    if add_links > 0 and add_days > 0:
        return JSONResponse({"error": "套餐只能选择增加额度或增加天数（二选一）"}, 400)
    if add_links <= 0 and add_days <= 0:
        return JSONResponse({"error": "套餐至少需要设置增加额度或增加天数"}, 400)
    async with aiosqlite.connect(DB_PATH) as db:
        if int(payload.id or 0) > 0:
            await db.execute(
                "UPDATE products SET name=?, add_links=?, add_days=?, price=?, enabled=? WHERE id=?",
                (name, add_links, add_days, price, enabled, int(payload.id)),
            )
        else:
            await db.execute(
                "INSERT INTO products (name, add_links, add_days, price, enabled) VALUES (?,?,?,?,?)",
                (name, add_links, add_days, price, enabled),
            )
        await db.commit()
    return {"status": "ok"}


@app.post("/api/admin/product/delete")
async def admin_delete_product(data: dict, user=Depends(get_current_user)):
    if not user or user["role"] != "admin":
        return JSONResponse({}, 403)
    pid = int(data.get("id") or 0)
    if pid <= 0:
        return JSONResponse({"error": "Missing id"}, 400)
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM products WHERE id=?", (pid,))
        await db.commit()
    return {"status": "ok"}


@app.get("/api/admin/payment_settings")
async def admin_get_payment_settings(user=Depends(get_current_user)):
    if not user or user["role"] != "admin":
        return JSONResponse({}, 403)
    async with aiosqlite.connect(DB_PATH) as db:
        r = await (await db.execute("SELECT value FROM settings WHERE key='payment_text'", ())).fetchone()
        return {"payment_text": (r[0] if r else "")}


@app.post("/api/admin/payment_settings")
async def admin_set_payment_settings(payload: PaymentSettingsPayload, user=Depends(get_current_user)):
    if not user or user["role"] != "admin":
        return JSONResponse({}, 403)
    payment_text = str(payload.payment_text or "")
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO settings(key, value) VALUES('payment_text', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (payment_text,),
        )
        await db.commit()
    return {"status": "ok"}


@app.get("/api/user/purchase_info")
async def user_purchase_info(user=Depends(get_current_user)):
    if not user:
        return JSONResponse({"error": "Unauthorized"}, 401)
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        payment_row = await (await db.execute("SELECT value FROM settings WHERE key='payment_text'", ())).fetchone()
        products = await (
            await db.execute(
                "SELECT id, name, add_links, add_days, price FROM products WHERE enabled=1 ORDER BY created_at DESC"
            )
        ).fetchall()
        return {
            "payment_text": (payment_row[0] if payment_row else ""),
            "products": [dict(p) for p in products],
        }


@app.get("/api/admin/invites_list")
async def admin_invites_list(user=Depends(get_current_user)):
    if not user or user["role"] != "admin":
        return JSONResponse({}, 403)
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        sql = (
            "SELECT i.code, i.max_links, i.pack_links, i.pack_days, i.product_name, i.price, "
            "strftime('%Y-%m-%d %H:%M:%S', i.expires_at) as expires_at, i.is_used, i.used_by, i.created_at, "
            "u.username as used_by_name "
            "FROM invites i LEFT JOIN users u ON i.used_by = u.id "
            "ORDER BY i.created_at DESC LIMIT 100"
        )
        rows = [dict(r) for r in await (await db.execute(sql)).fetchall()]

        # Backward compatibility for older admin UI templates that expect:
        #   invite.used_by.username
        # while current backend historically returned used_by as numeric user_id.
        for it in rows:
            try:
                used_by_id = it.get('used_by')
                used_by_name = it.get('used_by_name')
                it['used_by_id'] = used_by_id
                it['used_by'] = {
                    'id': used_by_id,
                    'username': used_by_name or '',
                }
            except Exception:
                it['used_by_id'] = it.get('used_by')
                it['used_by'] = {'id': it.get('used_by'), 'username': ''}

        return rows


@app.get("/api/admin/invites")
async def admin_invites_list_alias(user=Depends(get_current_user)):
    return await admin_invites_list(user=user)


@app.post("/api/admin/invite/delete")
async def admin_delete_invite(data: dict, user=Depends(get_current_user)):
    if not user or user["role"] != "admin":
        return JSONResponse({}, 403)
    code = str(data.get("code") or "").strip().upper()
    if not code:
        return JSONResponse({"error": "Missing code"}, 400)
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute("DELETE FROM invites WHERE code=?", (code,))
        await db.commit()
        if cur.rowcount == 0:
            return JSONResponse({"error": "Not Found"}, 404)
    return {"status": "ok"}


@app.post("/api/user/redeem")
async def user_redeem(payload: RedeemPayload, user=Depends(get_current_user)):
    if not user:
        return JSONResponse({"error": "Unauthorized"}, 401)

    code = (payload.code or "").strip().upper()
    if not code:
        return JSONResponse({"error": "请输入兑换码"}, 400)

    def _parse_dt(v):
        if not v:
            return None
        s = str(v).strip()
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                return datetime.strptime(s, fmt)
            except Exception:
                pass
        try:
            return datetime.fromisoformat(s.replace(" ", "T"))
        except Exception:
            return None

    try:
        async with aiosqlite.connect(DB_PATH) as db:
            db.row_factory = aiosqlite.Row
            inv_row = await (await db.execute("SELECT * FROM invites WHERE code=?", (code,))).fetchone()
            inv = dict(inv_row) if inv_row else None
            if not inv:
                return JSONResponse({"error": "兑换码不存在"}, 400)

            if int(inv.get("is_used") or 0):
                return JSONResponse({"error": "兑换码已使用"}, 400)

            if inv.get("expires_at"):
                expired = await (
                    await db.execute("SELECT 1 FROM invites WHERE code=? AND expires_at <= CURRENT_TIMESTAMP", (code,))
                ).fetchone()
                if expired:
                    return JSONResponse({"error": "兑换码已过期"}, 400)

            u_row = await (
                await db.execute("SELECT id, link_limit, expire_time FROM users WHERE id=?", (user["id"],))
            ).fetchone()
            u = dict(u_row) if u_row else None
            if not u:
                return JSONResponse({"error": "用户不存在"}, 400)

            pack_links = int((inv.get("pack_links") or inv.get("max_links") or 0) or 0)
            pack_days = int((inv.get("pack_days") or 0) or 0)

            if pack_days <= 0 and inv.get("expires_at"):
                inv_created = _parse_dt(inv.get("created_at")) or datetime.now()
                inv_expires = _parse_dt(inv.get("expires_at")) or (datetime.now() + timedelta(days=1))
                pack_days = max(0, int(round((inv_expires - inv_created).total_seconds() / 86400.0)))

            if pack_links <= 0 and pack_days <= 0:
                return JSONResponse({"error": "该兑换码无可用权益"}, 400)

            sql_parts: List[str] = []
            params: List[Any] = []

            if pack_links > 0:
                new_limit = int((u.get("link_limit") or 0) or 0) + pack_links
                sql_parts.append("link_limit=?")
                params.append(new_limit)

            if pack_days > 0:
                now_dt = datetime.now()
                user_expire_dt = _parse_dt(u.get("expire_time"))
                base = user_expire_dt if (user_expire_dt and user_expire_dt.date() >= now_dt.date()) else now_dt
                new_expire_dt = base + timedelta(days=pack_days)
                new_expire = new_expire_dt.strftime("%Y-%m-%d")
                sql_parts.append("expire_time=?")
                params.append(new_expire)

            if sql_parts:
                params.append(user["id"])
                await db.execute(f"UPDATE users SET {','.join(sql_parts)} WHERE id=?", params)

            try:
                await db.execute("UPDATE invites SET is_used=1, used_by=? WHERE code=?", (user["id"], code))
            except Exception:
                await db.execute("UPDATE invites SET is_used=1 WHERE code=?", (code,))

            await db.commit()

            updated_row = await (
                await db.execute(
                    "SELECT id, username, role, link_limit, expire_time FROM users WHERE id=?",
                    (user["id"],),
                )
            ).fetchone()
            updated = dict(updated_row) if updated_row else None
            return {"status": "ok", "user": updated or {}}
    except Exception as e:
        logger.error(f"Redeem Error: {e}", exc_info=True)
        return JSONResponse({"error": "兑换失败，请联系管理员或查看服务端日志"}, 400)


@app.post("/api/admin/system/update_files")
async def update_system_files(payload: UpdatePayload, background_tasks: BackgroundTasks, user=Depends(get_current_user)):
    if not user or user["role"] != "admin":
        return JSONResponse({"error": "无权操作"}, 403)

    base_url = os.getenv(
        "UPDATE_BASE_URL",
        "https://gist.githubusercontent.com/sdacasda/7dde7d536650aba99fddf5e28a3e3b71/raw/",
    )
    files = [("app_v2.html", "templates/app_v2.html")]
    if bool(getattr(payload, "update_backend", False)):
        files = [("main_v2.py", "main_v2.py"), ("app_v2.html", "templates/app_v2.html")]
    try:
        import ssl

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        ts = int(time.time())
        for remote_name, local_path in files:
            url = f"{base_url}{remote_name}?v={ts}_{random.randint(1, 9999)}"
            logger.info(f"Updating {local_path} from {url}")
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, context=ctx, timeout=15) as response, open(local_path, "wb") as out_file:
                data = response.read()
                if len(data) < 100:
                    raise Exception(f"File {remote_name} too small, download failed.")
                out_file.write(data)
                out_file.flush()
                os.fsync(out_file.fileno())

        def restart_server():
            time.sleep(1)
            os._exit(0)

        background_tasks.add_task(restart_server)
        return JSONResponse({"status": "ok", "message": "系统更新成功，重启中..."})
    except Exception as e:
        logger.error(f"Update Failed: {e}")
        return JSONResponse({"error": f"更新失败: {str(e)}"}, 500)


def _sha256_hex(s: str) -> str:
    v = (s or "").strip()
    if not v:
        return ""
    if re.fullmatch(r"[a-fA-F0-9]{64}", v):
        return v.lower()
    return hashlib.sha256(v.encode("utf-8")).hexdigest()


def _get_client_ip(request: Request) -> str:
    return (
        request.headers.get("CF-Connecting-IP")
        or request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        or (request.client.host if request.client else "127.0.0.1")
        or "127.0.0.1"
    )


def _get_cookie(request: Request, name: str) -> str:
    try:
        return str(request.cookies.get(name) or "").strip()
    except Exception:
        return ""


def _tiktok_api_post(access_token: str, payload: dict) -> dict:
    url = "https://business-api.tiktok.com/open_api/v1.3/event/track/"
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Access-Token": str(access_token or "").strip(),
        "User-Agent": "Mozilla/5.0",
    }

    def _http_post_with_retry(url: str, data: bytes, headers: Dict[str, str], timeout: int, retries: int) -> str:
        last_err = None
        for attempt in range(retries + 1):
            try:
                req = urllib.request.Request(url, data=data, headers=headers, method="POST")
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    return resp.read().decode("utf-8", errors="ignore")
            except Exception as e:
                last_err = e
                if attempt < retries:
                    time.sleep(min(2 ** attempt, 3))
                else:
                    logger.warning(f"TikTok API failed after {attempt + 1} attempts: {e}")
        return ""

    try:
        raw = _http_post_with_retry(url, data, headers, timeout=TIKTOK_TIMEOUT, retries=max(0, TIKTOK_RETRIES))
        if not raw:
            return {"ok": False, "error": "empty response"}
        try:
            return json.loads(raw)
        except Exception:
            return {"ok": True, "raw": raw}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _tiktok_maybe_user_hash(value: str, allow_raw_hash: bool) -> str:
    v = str(value or "").strip()
    if not v:
        return ""
    if v.lower().startswith("sha256:"):
        v = v.split(":", 1)[1]
    if re.fullmatch(r"[a-fA-F0-9]{64}", v):
        return v.lower()
    return _sha256_hex(v.lower()) if allow_raw_hash else ""


def _build_tiktok_event_payload(
    pixel_id: str,
    event: str,
    event_id: str,
    url: str,
    referrer: str,
    ip: str,
    user_agent: str,
    ttclid: str,
    ttp: str,
    email: str,
    phone_number: str,
    external_id: str,
    allow_raw_hash: bool,
    properties: Optional[Dict[str, Any]] = None,
    test_event_code: str = "",
) -> Dict[str, Any]:
    user_obj: Dict[str, Any] = {
        "ip": ip,
        "user_agent": (user_agent[:512] if user_agent else ""),
    }
    if ttclid:
        user_obj["ttclid"] = ttclid
    if ttp:
        user_obj["ttp"] = ttp

    eh = _tiktok_maybe_user_hash(email, allow_raw_hash)
    ph = _tiktok_maybe_user_hash(phone_number, allow_raw_hash)
    xid = _tiktok_maybe_user_hash(external_id, allow_raw_hash)
    if eh:
        user_obj["email"] = eh
    if ph:
        user_obj["phone"] = ph
    if xid:
        user_obj["external_id"] = xid

    data_item: Dict[str, Any] = {
        "event": event,
        "event_time": int(time.time()),
        "event_id": event_id,
        "page": {"url": url, "referrer": referrer or ""},
        "user": user_obj,
        "properties": properties or {},
    }
    payload: Dict[str, Any] = {
        "event_source": "web",
        "event_source_id": pixel_id,
        "data": [data_item],
    }
    if test_event_code:
        payload["test_event_code"] = test_event_code
    return payload


def is_suspicious_user(request: Request) -> bool:
    ua = request.headers.get("user-agent", "").lower()
    return any(
        b in ua
        for b in [
            "bot",
            "spider",
            "crawl",
            "facebookexternalhit",
            "facebot",
            "twitterbot",
            "slackbot",
            "telegrambot",
            "discordbot",
            "whatsapp",
            "googlebot",
            "bingbot",
            "yandex",
            "preview",
        ]
    )


I18N: Dict[str, Dict[str, str]] = {
    "CN": {
        "jump": "秒后跳转",
        "click": "点击查看详情",
        "line": "点击添加 LINE",
        "tg": "点击加入 Telegram",
        "wa": "WhatsApp 私聊",
        "ig": "打开 Instagram",
        "loading": "加载中...",
        "opening": "正在打开...",
        "opening_app": "正在打开 {app}...",
    },
    "TW": {"jump": "秒後跳轉", "click": "點擊查看詳情", "loading": "載入中...", "opening": "正在開啟...", "opening_app": "正在開啟 {app}...", "line": "點擊加入 LINE", "tg": "點擊加入 Telegram", "wa": "WhatsApp 私聊", "ig": "打開 Instagram"},
    "HK": {"jump": "秒後跳轉", "click": "點擊查看詳情", "loading": "載入中...", "opening": "正在開啟...", "opening_app": "正在開啟 {app}...", "line": "點擊加入 LINE", "tg": "點擊加入 Telegram", "wa": "WhatsApp 私聊", "ig": "打開 Instagram"},
    "JP": {"jump": "秒後にジャンプ", "click": "詳細を見る", "loading": "読み込み中...", "opening": "開いています...", "opening_app": "{app}を開いています...", "line": "LINEで友達追加", "tg": "Telegramに参加", "wa": "WhatsAppでチャット", "ig": "Instagramを開く"},
    "KR": {"jump": "초 후 이동", "click": "자세히 보기", "loading": "불러오는 중...", "opening": "열고 있습니다...", "opening_app": "{app} 여는 중...", "line": "LINE 친구 추가", "tg": "텔레그램 참여", "wa": "WhatsApp 채팅", "ig": "Instagram 열기"},
    "DEFAULT": {
        "jump": "seconds to jump",
        "click": "Click to continue",
        "line": "Add LINE",
        "tg": "Join Telegram",
        "wa": "Chat on WhatsApp",
        "ig": "Open Instagram",
        "loading": "Loading...",
        "opening": "Opening...",
        "opening_app": "Opening {app}...",
    },
}


def detect_country(request: Request) -> str:
    cf_country = request.headers.get("CF-IPCountry")
    if cf_country:
        return cf_country.upper()
    al = request.headers.get("accept-language") or ""
    if al:
        primary = al.split(",")[0].strip()
        parts = primary.split("-")
        lang = parts[0].lower() if parts else ""
        region = parts[1].upper() if len(parts) > 1 else ""
        if region:
            return region
        lang_to_country = {"ko": "KR", "zh": "CN", "ja": "JP", "th": "TH", "vi": "VN", "id": "ID", "ms": "MY", "fil": "PH", "tl": "PH", "hi": "IN", "ar": "AE", "es": "ES", "pt": "PT", "fr": "FR", "de": "DE", "it": "IT", "ru": "RU", "tr": "TR", "pl": "PL", "nl": "NL", "en": "US"}
        if lang and lang in lang_to_country:
            return lang_to_country[lang]
    return "US"


def get_text(country: str, key: str) -> str:
    return I18N.get(country, I18N["DEFAULT"]).get(key, I18N["DEFAULT"].get(key, ""))


def build_deeplink_info(target_url: str):
    target_lower = (target_url or "").lower()
    platform = "other"
    if target_lower.startswith("whatsapp://") or "wa.me" in target_lower or "whatsapp" in target_lower:
        platform = "wa"
    elif target_lower.startswith("tg://") or "t.me" in target_lower or "telegram.me" in target_lower or "telegram" in target_lower:
        platform = "tg"
    elif target_lower.startswith("line://") or "line.me" in target_lower:
        platform = "line"
    elif target_lower.startswith("instagram://") or "instagram.com" in target_lower or "instagr.am" in target_lower:
        platform = "ig"

    platform_name = {"wa": "WhatsApp", "tg": "Telegram", "line": "LINE", "ig": "Instagram"}.get(platform, "App")
    deep_link = ""
    store_url = ""
    try:
        parsed = urlparse(target_url)
        host = (parsed.netloc or "").lower()
        path = (parsed.path or "").strip("/")
        query = (parsed.query or "")

        if platform == "wa":
            phone = ""
            if "wa.me" in host and path:
                phone = re.sub(r"\D", "", path.split("/")[0])
            if (not phone) and ("whatsapp.com" in host) and query:
                m = re.search(r"(?:^|&)phone=([^&]+)", query)
                if m:
                    phone = re.sub(r"\D", "", m.group(1))
            deep_link = f"whatsapp://send?phone={phone}" if phone else ("whatsapp://" if not deep_link else deep_link)
            store_url = "https://www.whatsapp.com/download"

        elif platform == "tg":
            if ("t.me" in host or "telegram.me" in host) and path:
                parts = [p for p in path.split("/") if p]
                if parts:
                    first = parts[0]
                    if first == "joinchat" and len(parts) > 1:
                        deep_link = f"tg://join?invite={parts[1]}"
                    elif first.startswith("+"):
                        deep_link = f"tg://join?invite={first.lstrip('+')}"
                    elif first not in ("share", "joinchat"):
                        deep_link = f"tg://resolve?domain={first}"
            if not deep_link:
                deep_link = "tg://"
            store_url = "https://telegram.org/apps"

        elif platform == "line":
            code = ""
            mode = "p"
            if "line.me" in host:
                parts = [p for p in path.split("/") if p]
                if "ti" in parts:
                    if "g" in parts:
                        mode = "g"
                    code = parts[-1] if parts else ""
                elif parts:
                    code = parts[-1]
            deep_link = f"line://ti/{mode}/{code}" if code else "line://"
            store_url = "https://line.me/en/"
        elif platform == "ig":
            deep_link = ""
            store_url = "https://www.instagram.com/"
        else:
            deep_link = ""
    except Exception:
        deep_link = ""

    return {
        "platform": platform,
        "platform_name": platform_name,
        "deep_link": deep_link,
        "store_url": store_url,
    }


def build_tiktok_pixel_script(pixel_id: str) -> str:
    pid = re.sub(r"[^A-Za-z0-9_-]", "", str(pixel_id or "").strip())
    if not pid or len(pid) <= 2:
        return ""
    script = """<script>
!function (w, d, t) {
  w.TiktokAnalyticsObject=t;var ttq=w[t]=w[t]||[];ttq.methods=["page","track","identify","instances","debug","on","off","once","ready","alias","group","enableCookie","disableCookie","holdConsent","revokeConsent","grantConsent"],ttq.setAndDefer=function(t,e){t[e]=function(){t.push([e].concat(Array.prototype.slice.call(arguments,0)))}};for(var i=0;i<ttq.methods.length;i++)ttq.setAndDefer(ttq,ttq.methods[i]);ttq.instance=function(t){for(
var e=ttq._i[t]||[],n=0;n<ttq.methods.length;n++)ttq.setAndDefer(e,ttq.methods[n]);return e},ttq.load=function(e,n){var r="https://analytics.tiktok.com/i18n/pixel/events.js",o=n&&n.partner;ttq._i=ttq._i||{},ttq._i[e]=[],ttq._i[e]._u=r,ttq._t=ttq._t||{},ttq._t[e]=+new Date,ttq._o=ttq._o||{},ttq._o[e]=n||{};n=document.createElement("script")
;n.type="text/javascript",n.async=!0,n.src=r+"?sdkid="+e+"&lib="+t;e=document.getElementsByTagName("script")[0];e.parentNode.insertBefore(n,e)};

  ttq.load('__PID__');
  ttq.page();
}(window, document, 'ttq');
</script>"""
    return script.replace("__PID__", pid)


def get_loading_html(
    target_url: str,
    country_code: str = "US",
    pixel_id: str = "",
    pixel_event_auto: str = "ViewContent",
    pixel_event_click: str = "Lead",
):
    deep = build_deeplink_info(target_url)
    platform = str(deep.get("platform") or "other")
    platform_name = str(deep.get("platform_name") or "App")
    deep_link = str(deep.get("deep_link") or "").strip()
    store_url = str(deep.get("store_url") or "").strip()

    opening_tpl = get_text(country_code, "opening_app") or get_text(country_code, "opening")
    try:
        tip_text = str(opening_tpl).replace("{app}", platform_name)
    except Exception:
        tip_text = f"{get_text(country_code, 'opening')} {platform_name}".strip()
    title_text = get_text(country_code, "loading")

    pixel_script = build_tiktok_pixel_script(pixel_id)
    delay_ms = 500
    countdown_s = max(1, int(round(delay_ms / 1000.0)))

    target_js = json.dumps(target_url)
    deep_js = json.dumps(deep_link) if deep_link else "''"
    store_js = json.dumps(store_url) if store_url else "''"
    pixel_event_auto_js = json.dumps(str(pixel_event_auto or "ViewContent").strip() or "ViewContent")
    pixel_event_click_js = json.dumps(str(pixel_event_click or "Lead").strip() or "Lead")

    brand = {
        "wa": {"name": "WhatsApp", "color": "#25D366", "bg": "#0b1f17"},
        "tg": {"name": "Telegram", "color": "#2481CC", "bg": "#071a2a"},
        "line": {"name": "LINE", "color": "#06C755", "bg": "#071c10"},
        "ig": {"name": "Instagram", "color": "#E1306C", "bg": "#220815"},
    }.get(platform, {"name": platform_name, "color": "#3B82F6", "bg": "#0B1220"})

    brand_name_safe = html.escape(brand.get("name") or platform_name)
    tip_safe = html.escape(tip_text)
    title_safe = html.escape(title_text)
    accent = html.escape(brand.get("color") or "#3B82F6")
    bg = html.escape(brand.get("bg") or "#0B1220")

    btn_text = get_text(country_code, platform) if platform in ("tg", "line", "wa", "ig") else ""
    if not btn_text:
        btn_text = get_text(country_code, "click")
    btn_text_safe = html.escape(btn_text)

    def _icon_svg(p: str) -> str:
        if p == "tg":
            return """<svg viewBox=\"0 0 24 24\" width=\"22\" height=\"22\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\"><path d=\"M21.6 3.4c.4.2.5.7.4 1.3l-3.2 15.1c-.1.6-.4 1-1 1.2-.3.1-.7 0-1.1-.2l-5.3-3.9-2.6 2.5c-.3.3-.6.4-1 .3-.4-.1-.6-.4-.6-.9l.1-3.9L17.3 6.4c.2-.2.2-.4 0-.5-.2-.1-.4-.1-.6 0L6 12.7l-4.4-1.4c-.5-.2-.8-.5-.8-.9 0-.4.3-.8.9-1L20.2 3.2c.6-.2 1.1-.2 1.4.2Z\" fill=\"#fff\"/></svg>"""
        if p == "wa":
            return """<svg viewBox=\"0 0 24 24\" width=\"22\" height=\"22\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\"><path d=\"M12 2a9.7 9.7 0 0 0-8.4 14.6L2 22l5.6-1.5A9.7 9.7 0 1 0 12 2Z\" fill=\"#fff\" opacity=\".14\"/><path d=\"M12 3.9A8.1 8.1 0 0 0 5.3 16.6l.2.4-1 3.5 3.6-1 .4.2A8.1 8.1 0 1 0 12 3.9Zm4.7 11.2c-.2.5-1.1 1-1.6 1.1-.4.1-.9.2-1.4.1-1.3-.3-2.9-1.2-4.5-2.7-1.6-1.6-2.6-3.3-2.9-4.7-.1-.5 0-1 .2-1.4.2-.4.6-1.1 1.1-1.3.3-.1.6-.1.8 0 .2.1.4.4.5.6l.7 1.6c.1.3.1.6 0 .8l-.3.6c-.1.2-.2.4-.1.6.2.5.7 1.3 1.6 2.2.9.9 1.7 1.4 2.2 1.6.2.1.4 0 .6-.1l.6-.3c.2-.1.5-.1.8 0l1.7.8c.2.1.5.3.6.5.1.2.1.5 0 .8Z\" fill=\"#fff\"/></svg>"""
        if p == "line":
            return """<svg viewBox=\"0 0 24 24\" width=\"22\" height=\"22\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\"><path d=\"M19.5 4.5c-1.6-1.5-4.2-2.5-7.5-2.5C6.2 2 2 5.2 2 9.2c0 3.5 3.1 6.4 7.3 7v3.8c0 .6.7 1 1.2.6l4.1-3.5c4.3-.3 7.4-3.4 7.4-7 0-2.2-1-4.2-2.5-5.6Z\" fill=\"#fff\" opacity=\".18\"/><path d=\"M12 3.6c-4.7 0-8.3 2.6-8.3 5.7 0 2.7 2.7 5 6.4 5.5l.6.1v2.9l3.2-2.7.3-.2h.4c3.7-.4 6.5-2.8 6.5-5.5 0-1.7-.8-3.2-2-4.2C17.7 4.2 15.1 3.6 12 3.6Zm-3.2 6.7c-.4 0-.7-.3-.7-.7s.3-.7.7-.7.7.3.7.7-.3.7-.7.7Zm3.2 0c-.4 0-.7-.3-.7-.7s.3-.7.7-.7.7.3.7.7-.3.7-.7.7Zm3.2 0c-.4 0-.7-.3-.7-.7s.3-.7.7-.7.7.3.7.7-.3.7-.7.7Z\" fill=\"#fff\"/></svg>"""
        if p == "ig":
            return """<svg viewBox=\"0 0 24 24\" width=\"22\" height=\"22\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\"><path d=\"M7.5 2h9A5.5 5.5 0 0 1 22 7.5v9A5.5 5.5 0 0 1 16.5 22h-9A5.5 5.5 0 0 1 2 16.5v-9A5.5 5.5 0 0 1 7.5 2Z\" fill=\"#fff\" opacity=\".16\"/><path d=\"M12 7.3A4.7 4.7 0 1 0 12 16.7 4.7 4.7 0 0 0 12 7.3Zm0 7.7A3 3 0 1 1 12 9a3 3 0 0 1 0 6Zm5.2-7.9a1.1 1.1 0 1 1-2.2 0 1.1 1.1 0 0 1 2.2 0Z\" fill=\"#fff\"/></svg>"""
        return """<svg viewBox=\"0 0 24 24\" width=\"22\" height=\"22\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\"><path d=\"M12 2a10 10 0 1 0 10 10A10 10 0 0 0 12 2Zm1 15h-2v-2h2Zm0-4h-2V7h2Z\" fill=\"#fff\"/></svg>"""
    return f"""<!DOCTYPE html>
<html lang="zh-CN"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1.0,maximum-scale=1.0,user-scalable=no,viewport-fit=cover">
<title>{title_safe}</title>
{pixel_script}
<style>
  *{{box-sizing:border-box;}}
  body{{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#fff;color:#111827;font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;}}
  .wrap{{display:flex;flex-direction:column;align-items:center;gap:12px;padding:24px 20px;text-align:center;max-width:520px;width:100%;}}
  .loader{{width:44px;height:44px;border-radius:999px;border:4px solid rgba(17,24,39,.10);border-top:4px solid {accent};animation:spin .9s linear infinite;}}
  @keyframes spin{{0%{{transform:rotate(0)}}100%{{transform:rotate(360deg)}}}}
  .tip{{font-weight:900;font-size:16px;}}
  .btn{{margin-top:4px;width:100%;max-width:360px;height:52px;border:none;border-radius:16px;background:{accent};color:#fff;font-weight:900;font-size:16px;cursor:pointer;display:none;align-items:center;justify-content:center;box-shadow:0 14px 28px rgba(0,0,0,.18);}}
  .btn:active{{transform:translateY(1px);}}
</style>
</head><body>
  <div class="wrap">
    <div class="loader" aria-hidden="true"></div>
    <div class="tip">{tip_safe}</div>
    <button id="btn" class="btn" type="button" onclick="manual()"><span>{btn_text_safe}</span></button>
  </div>
<script>
  var TARGET = {target_js};
  var DEEP = {deep_js};
  var delayMs = {int(delay_ms)};
  var PIX_AUTO = {pixel_event_auto_js};
  var PIX_CLICK = {pixel_event_click_js};
  var btn = document.getElementById('btn');
  var opened = false;
  var fallbackTriggered = false;
  var __pixAutoDone = false;
  var __pixClickDone = false;

  try {{ document.addEventListener('visibilitychange', function(){{ if(document.hidden) opened = true; }}); }} catch(e) {{}}
  try {{ window.addEventListener('pagehide', function(){{ opened = true; }}); }} catch(e) {{}}
  try {{ window.addEventListener('blur', function(){{ setTimeout(function(){{ opened = true; }}, 0); }}); }} catch(e) {{}}

  function openDeepLink(url){{
    try{{ location.href=url; }}catch(e){{}}
    try{{ var iframe=document.createElement('iframe'); iframe.style.display='none'; iframe.src=url; document.body.appendChild(iframe); setTimeout(function(){{ try{{document.body.removeChild(iframe);}}catch(e){{}} }},1200); }}catch(e){{}}
  }}
  function firePixel(ev){{
    try{{
      if (window.ttq && typeof window.ttq.track === 'function' && ev && String(ev).length > 0) {{
        window.ttq.track(String(ev));
      }}
    }}catch(e){{}}
  }}
  function go(){{ try{{ location.href = TARGET; }}catch(e){{}} }}
  function goWithDeepLink(){{
    if (!__pixAutoDone) {{ __pixAutoDone = true; firePixel(PIX_AUTO); }}
    if (DEEP && typeof DEEP === 'string' && DEEP.length > 3) {{
      openDeepLink(DEEP);
      setTimeout(go, 900);
      return;
    }}
    go();
  }}
  function manual(){{
    if (!__pixClickDone) {{ __pixClickDone = true; firePixel(PIX_CLICK); }}
    goWithDeepLink();
  }}

  try {{ setTimeout(goWithDeepLink, 500); }} catch(e) {{}}
  try {{
    setTimeout(function(){{
      if (opened) return;
      if (btn) btn.style.display = 'flex';
      if (!fallbackTriggered) {{
        fallbackTriggered = true;
        try {{ manual(); }} catch(e) {{}}
      }}
    }}, 2000);
  }} catch(e) {{}}
</script>
</body></html>"""


def get_marketing_html(target_url: str, link_data: dict, country: str):
    landing_mode = str(link_data.get("landing_mode") or "both").strip().lower()
    if landing_mode not in ("media", "questions", "both"):
        landing_mode = "both"
    pixel_id = str(link_data.get("pixel_id") or "").strip()
    pixel_event_click = str(link_data.get("pixel_event_click") or "Lead").strip()
    pixel_event_auto = str(link_data.get("pixel_event_auto") or "ViewContent").strip()
    media_url = str(link_data.get("media_url") or "").strip()
    btn_text = str(link_data.get("btn_text") or "").strip()
    page_title = str(link_data.get("page_title") or "").strip()
    page_desc = str(link_data.get("page_desc") or "").strip()
    auto_jump = int(link_data.get("auto_jump") or 0)
    marketing_options_raw = str(link_data.get("marketing_options") or "").strip()

    deep_info = build_deeplink_info(target_url)
    platform = deep_info["platform"]
    deep_link = deep_info["deep_link"]
    store_url = deep_info["store_url"]

    if not btn_text:
        if platform == "line":
            btn_text = get_text(country, "line")
        elif platform == "tg":
            btn_text = get_text(country, "tg")
        elif platform == "wa":
            btn_text = get_text(country, "wa")
        elif platform == "ig":
            btn_text = get_text(country, "ig")
        else:
            btn_text = get_text(country, "click")

    if btn_text:
        try:
            btn_text = translate_for_country(btn_text, country)
        except Exception:
            pass
    if page_title:
        try:
            page_title = translate_for_country(page_title, country)
        except Exception:
            pass
    if page_desc:
        try:
            page_desc = translate_for_country(page_desc, country)
        except Exception:
            pass

    doc_title = html.escape(page_title or get_text(country, "loading"))
    title_text = html.escape(page_title or "")
    hero_title_html = f"<h1>{title_text}</h1>" if title_text else ""
    loading_badge_text = html.escape(get_text(country, "loading"))
    desc_text = html.escape(page_desc or get_text(country, "opening"))
    pixel_script = build_tiktok_pixel_script(pixel_id)

    media_html = ""
    if landing_mode in ("media", "both") and media_url:
        safe_media_url = html.escape(media_url, quote=True)
        if any(x in media_url.lower() for x in [".mp4", ".mov", ".webm"]):
            media_html = f"<video class=\"hero-media\" src=\"{safe_media_url}\" autoplay loop muted playsinline></video>"
        else:
            media_html = f"<img class=\"hero-media\" src=\"{safe_media_url}\" alt=\"\" />"

    options_html = ""
    if landing_mode in ("questions", "both") and marketing_options_raw:
        try:
            cfg = json.loads(marketing_options_raw)
            items = cfg if isinstance(cfg, list) else (cfg.get("items") if isinstance(cfg, dict) else [])
            if not isinstance(items, list):
                items = []
            blocks = []
            for it in items[:4]:
                if not isinstance(it, dict):
                    continue
                key = re.sub(r"[^A-Za-z0-9_]", "", str(it.get("key") or it.get("id") or "").strip())[:32]
                if not key:
                    continue
                label_raw = str(it.get("label") or key)
                try:
                    label_show = translate_for_country(label_raw, country)
                except Exception:
                    label_show = label_raw
                label = html.escape(label_show)
                typ = str(it.get("type") or "select").strip().lower()
                opts = it.get("options") if isinstance(it.get("options"), list) else []
                default_val = it.get("default")

                if typ == "select":
                    effective_default = default_val
                    try:
                        if effective_default is None and isinstance(opts, list) and len(opts) > 0:
                            for first in opts:
                                if isinstance(first, dict):
                                    cand = first.get("value") if first.get("value") is not None else (first.get("label") or "")
                                else:
                                    cand = first
                                cand = str(cand).strip() if cand is not None else ""
                                if cand:
                                    effective_default = cand
                                    break
                    except Exception:
                        effective_default = default_val

                    parts = [f"<div class=\"opt\"><div class=\"opt-label\">{label}</div><select class=\"opt-select\" data-key=\"{key}\">"]
                    for o in opts[:40]:
                        if isinstance(o, dict):
                            ov = str(o.get("value") if o.get("value") is not None else o.get("label") or "").strip()
                            ol = str(o.get("label") if o.get("label") is not None else ov).strip()
                        else:
                            ov = str(o).strip()
                            ol = ov
                        if not ov:
                            continue
                        try:
                            ol_show = translate_for_country(ol, country)
                        except Exception:
                            ol_show = ol
                        sel = " selected" if (effective_default is not None and str(effective_default) == ov) else ""
                        parts.append(f"<option value=\"{html.escape(ov, quote=True)}\"{sel}>{html.escape(ol_show)}</option>")
                    parts.append("</select></div>")
                    blocks.append("".join(parts))

                elif typ in ("radio", "checkbox"):
                    parts = [f"<div class=\"opt\"><div class=\"opt-label\">{label}</div><div class=\"opt-items\" data-type=\"{typ}\" data-key=\"{key}\">"]
                    default_list = []
                    if isinstance(default_val, list):
                        default_list = [str(x) for x in default_val]
                    elif isinstance(default_val, str) and default_val:
                        default_list = [default_val]
                    for o in opts[:30]:
                        if isinstance(o, dict):
                            ov = str(o.get("value") if o.get("value") is not None else o.get("label") or "").strip()
                            ol = str(o.get("label") if o.get("label") is not None else ov).strip()
                        else:
                            ov = str(o).strip()
                            ol = ov
                        if not ov:
                            continue
                        try:
                            ol_show = translate_for_country(ol, country)
                        except Exception:
                            ol_show = ol
                        checked = " checked" if ((typ == "radio" and default_val is not None and str(default_val) == ov) or (typ == "checkbox" and ov in default_list)) else ""
                        parts.append(
                            f"<label class=\"opt-item\"><input type=\"{typ}\" name=\"opt_{key}\" value=\"{html.escape(ov, quote=True)}\"{checked}> <span>{html.escape(ol_show)}</span></label>"
                        )
                    parts.append("</div></div>")
                    blocks.append("".join(parts))
            if blocks:
                options_html = "<div class=\"opts\" id=\"opts\">" + "".join(blocks) + "</div>"
        except Exception:
            options_html = ""

    btn_text_safe = html.escape(btn_text)
    target_js = json.dumps(target_url)
    deep_js = json.dumps(deep_link)
    store_js = json.dumps(store_url)
    pixel_event_click_js = json.dumps(pixel_event_click)
    pixel_event_auto_js = json.dumps(pixel_event_auto)
    link_id = int(link_data.get("id") or 0)
    opening_text_js = json.dumps(get_text(country, "opening"))

    brand_color = "#3b82f6"
    brand_bg = "#0b1220"
    if platform == "line":
        brand_color = "#06C755"
        brand_bg = "#061a0f"
    elif platform == "tg":
        brand_color = "#2481CC"
        brand_bg = "#071a2a"
    elif platform == "wa":
        brand_color = "#25D366"
        brand_bg = "#071c13"
    elif platform == "ig":
        brand_color = "#E1306C"
        brand_bg = "#220815"

    accent_rgb = "59,130,246"
    try:
        bc = str(brand_color or "").lstrip("#")
        if len(bc) == 3:
            bc = "".join([c + c for c in bc])
        if len(bc) == 6:
            r = int(bc[0:2], 16)
            g = int(bc[2:4], 16)
            b = int(bc[4:6], 16)
            accent_rgb = f"{r},{g},{b}"
    except Exception:
        accent_rgb = "59,130,246"

    questions_only = bool(options_html) and (landing_mode == "questions" or not bool(media_html))
    page_cls = "has-opts" if options_html else "no-opts"
    if questions_only:
        page_cls += " questions-only"

    return f"""<!DOCTYPE html>
<html lang=\"zh-CN\"><head>
<meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1.0,maximum-scale=1.0,user-scalable=no,viewport-fit=cover\">
<title>{doc_title}</title>
<meta name=\"description\" content=\"{desc_text}\">
{pixel_script}
<style>
  :root{{--accent:{html.escape(brand_color)};--bg:{html.escape(brand_bg)};}}
  *{{box-sizing:border-box}}
  body{{margin:0;min-height:100vh;background:
    radial-gradient(900px 680px at 18% 6%, rgba({accent_rgb},.18), transparent 55%),
    radial-gradient(900px 680px at 88% 14%, rgba(255,255,255,.08), transparent 60%),
    radial-gradient(900px 680px at 50% 95%, rgba({accent_rgb},.10), transparent 60%),
    var(--bg);
    color:#e5e7eb;font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;}}
  .page{{min-height:100vh;display:flex;flex-direction:column;}}
  .page{{min-height:100vh;min-height:100svh;min-height:100dvh;display:flex;flex-direction:column;}}
  .hero{{position:relative;flex:1 0 auto;min-height:clamp(320px, 52svh, 560px);overflow:hidden;
    padding:calc(18px + env(safe-area-inset-top)) 18px clamp(74px, 12svh, 112px);
    background:radial-gradient(900px 600px at 20% 10%, rgba(255,255,255,.10), transparent 55%),
    radial-gradient(900px 600px at 90% 30%, rgba({accent_rgb},.22), transparent 55%);
  }}
  .hero-media{{position:absolute;inset:0;width:100%;height:100%;object-fit:cover;object-position:center;display:block;background:#000;}}
  .hero::before{{content:'';position:absolute;inset:0;background:linear-gradient(180deg, rgba(0,0,0,.10), rgba(0,0,0,.58) 55%, rgba(0,0,0,.90));z-index:1;}}
  .hero-inner{{position:relative;z-index:2;max-width:560px;margin:0 auto;display:flex;flex-direction:column;justify-content:flex-end;min-height:44vh;}}
  h1{{margin:0;font-size:26px;line-height:1.12;letter-spacing:.2px;font-weight:950;text-shadow:0 12px 32px rgba(0,0,0,.36);}}
  .panel{{max-width:560px;margin:calc(-1 * clamp(44px, 6svh, 64px)) auto 0;width:100%;padding:0 18px 16px;position:relative;z-index:3;}}
  .page.questions-only .hero{{min-height:100svh;padding-bottom:0;}}
  .page.questions-only .hero-inner{{min-height:auto;justify-content:center;}}
  .page.questions-only .panel{{
    position:fixed;left:0;right:0;
    top:max(12px, env(safe-area-inset-top));
    bottom:max(12px, env(safe-area-inset-bottom));
    margin:0 auto;
    padding:0 16px;
    display:flex;
    flex-direction:column;
    justify-content:center;
  }}
  .page.questions-only .card{{max-height:100%;width:100%;}}
  .page.questions-only .card-body{{max-height:100%;overflow:auto;display:flex;flex-direction:column;}}
  .page.questions-only .opts{{flex:1 1 auto;display:flex;flex-direction:column;justify-content:center;margin:0 0 14px;min-height:0;}}
  .page.questions-only .cta{{flex:0 0 auto;}}
  .page.questions-only h1{{text-align:center;font-size:22px;line-height:1.15;}}
  .page.no-opts .panel{{position:fixed;left:0;right:0;bottom:0;margin:0 auto;padding:0 16px max(16px, env(safe-area-inset-bottom));}}
  .page.no-opts .card-body{{padding:12px 12px 10px;}}
  .page.no-opts .hero{{min-height:100svh;padding-top:22px;padding-bottom:clamp(112px, 16svh, 160px);}}
  .page.no-opts .hero-inner{{min-height:auto;justify-content:flex-start;}}
  .page.no-opts h1{{text-align:center;font-size:22px;line-height:1.15;text-shadow:0 10px 28px rgba(0,0,0,.40);}}
  .card{{background:rgba(15,23,42,.70);backdrop-filter:blur(14px);border:1px solid rgba(255,255,255,.10);border-radius:20px;box-shadow:0 22px 70px rgba(0,0,0,.40);overflow:hidden;}}
  .card-body{{padding:16px 16px 14px;}}
  .opts{{display:flex;flex-direction:column;gap:12px;margin:0 0 14px;}}
  .opt{{background:linear-gradient(180deg, rgba(255,255,255,.07), rgba(255,255,255,.05));border:1px solid rgba(255,255,255,.10);border-radius:16px;padding:12px;}}
  .opt-label{{font-size:13px;font-weight:900;margin-bottom:10px;letter-spacing:.2px;}}
  .opt-select{{width:100%;height:46px;border-radius:14px;border:1px solid rgba(255,255,255,.16);background:rgba(2,6,23,.32);color:#e5e7eb;outline:none;padding:0 12px;}}
  .opt-items{{display:flex;flex-wrap:wrap;gap:10px;}}
  .opt-item{{display:flex;align-items:center;gap:10px;padding:10px 12px;border-radius:999px;background:rgba(2,6,23,.18);border:1px solid rgba(255,255,255,.10);font-size:13px;user-select:none;}}
  .opt-item input{{appearance:none;-webkit-appearance:none;width:18px;height:18px;border-radius:999px;border:2px solid rgba(255,255,255,.28);background:transparent;display:inline-block;position:relative;flex:0 0 auto;}}
  .opt-item input[type=checkbox]{{border-radius:6px;}}
  .opt-item input:checked{{border-color:var(--accent);background:var(--accent);box-shadow:0 10px 26px rgba(0,0,0,.25);}}
  .opt-item input[type=radio]:checked::after{{content:'';position:absolute;inset:4px;border-radius:999px;background:#fff;}}
  .opt-item input[type=checkbox]:checked::after{{content:'';position:absolute;left:5px;top:2px;width:5px;height:9px;border-right:2px solid #fff;border-bottom:2px solid #fff;transform:rotate(45deg);}}
  .opt-item:active{{transform:translateY(1px);}}
  .opt-item:hover{{border-color:rgba(255,255,255,.18);background:rgba(2,6,23,.22);}}
  .cta{{position:sticky;bottom:0;left:0;right:0;padding-top:6px;padding-bottom:max(12px, env(safe-area-inset-bottom));}}
  .loading-row{{display:flex;align-items:center;justify-content:flex-start;padding:0 6px 8px;}}
  .loading-note{{flex:0 0 auto;font-size:12px;line-height:1.1;font-weight:900;
    padding:6px 10px;border-radius:999px;background:rgba(0,0,0,.22);border:1px solid rgba(255,255,255,.16);
    color:rgba(255,255,255,.92);backdrop-filter:blur(10px);opacity:.95;pointer-events:none;
    max-width:100%;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;
  }}
  .loading-note.is-loading{{
    animation:pulse 1.25s ease-in-out infinite;
  }}
  @keyframes pulse{{
    0%{{ transform:scale(1); opacity:.95; }}
    50%{{ transform:scale(1.02); opacity:.78; }}
    100%{{ transform:scale(1); opacity:.95; }}
  }}
  .btn{{width:100%;height:clamp(52px, 7.6svh, 62px);border:none;border-radius:18px;position:relative;overflow:hidden;
    background:linear-gradient(180deg, rgba(255,255,255,.14), rgba(0,0,0,.12)), var(--accent);
    color:#fff;font-weight:950;font-size:15px;cursor:pointer;display:flex;align-items:center;justify-content:center;
    padding:0 16px;
    box-shadow:0 14px 34px rgba(0,0,0,.38);
  }}
  .btn-spinner{{
    width:18px;height:18px;border-radius:999px;
    border:2px solid rgba(255,255,255,.55);
    border-top-color:#fff;
    margin-right:10px;
    display:none;
    animation:spin .8s linear infinite;
    flex:0 0 auto;
  }}
  @keyframes spin{{ to{{ transform:rotate(360deg); }} }}
  .btn.is-loading .btn-spinner{{display:inline-block;}}
  .btn-text{{display:block;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}}
  .btn:active{{transform:translateY(1px);}}
  .btn[disabled]{{opacity:.88;cursor:not-allowed;}}
  .btn-icon{{width:20px;height:20px;display:inline-flex;align-items:center;justify-content:center;}}
  @media (min-width: 768px){{
    .panel{{margin:-64px auto 0;padding-bottom:24px;}}
    .hero{{min-height:clamp(360px, 56svh, 600px);padding:34px 18px 116px;}}
    .hero-inner{{min-height:clamp(360px, 56svh, 600px);}}
    h1{{font-size:28px;}}
    .btn{{height:70px;font-size:17px;}}
  }}
  @media (max-width: 420px){{
    .panel{{padding:0 14px 14px;}}
    .card-body{{padding:14px 14px 12px;}}
    .opt{{padding:11px;}}
    .opt-item{{padding:9px 11px;gap:9px;}}
    .btn{{height:56px;border-radius:16px;font-size:15px;}}
  }}
  @media (max-height: 720px){{
    .hero{{padding-bottom:84px;}}
    .panel{{margin:-44px auto 0;}}
  }}
  @media (max-height: 620px){{
    h1{{font-size:20px;}}
    .hero{{padding-top:calc(12px + env(safe-area-inset-top));padding-bottom:72px;}}
    .panel{{margin:-34px auto 0;padding:0 14px 12px;}}
    .card-body{{padding:14px 14px 12px;}}
    .btn{{height:54px;border-radius:16px;}}
    .page.no-opts .hero{{padding-top:18px;padding-bottom:112px;}}
  }}
</style>
</head><body>
<div class=\"page {page_cls}\">
  <div class=\"hero\">{media_html}<div class=\"hero-inner\">{hero_title_html}</div></div>
  <div class=\"panel\"><div class=\"card\"><div class=\"card-body\">
    {options_html}
    <div class=\"cta\"><div class=\"loading-row\"><span id=\"loadingNote\" class=\"loading-note\">{loading_badge_text}</span></div><button id=\"btn\" class=\"btn\" onclick=\"handleClick()\"><span class=\"btn-spinner\" aria-hidden=\"true\"></span><span class=\"btn-text\">{btn_text_safe}</span></button></div>
  </div></div></div>
</div>
<script>
var target = {target_js};
var deepLink = {deep_js};
var storeUrl = {store_js};
var autoJump = {int(auto_jump)};
var pixelEventClick = {pixel_event_click_js};
var pixelEventAuto = {pixel_event_auto_js};
var linkId = {int(link_id)};
var openingText = {opening_text_js};
var btn = document.getElementById('btn');
var loadingNote = document.getElementById('loadingNote');
var started = false;
var btnTextEl = null;
try{{ btnTextEl = btn ? btn.querySelector('.btn-text') : null; }}catch(e){{ btnTextEl = null; }}

function qs(k){{ try{{ return (new URLSearchParams(location.search)).get(k) || ''; }}catch(e){{ return ''; }} }}
function getCookie(name){{ try{{ var m=document.cookie.match(new RegExp('(?:^|; )'+name.replace(/[.$?*|{{}}()\[\]\\\\\/\+^]/g,'\\\\$&')+'=([^;]*)')); return m?decodeURIComponent(m[1]):''; }}catch(e){{return ''}} }}

function readCustomOptions(){{
  try{{
    var out={{}};
    var box=document.getElementById('opts');
    if(!box) return out;
    var selects=box.querySelectorAll('select[data-key]');
    for(var i=0;i<selects.length;i++){{ var s=selects[i]; if(s.value) out[s.getAttribute('data-key')]=String(s.value); }}
    var groups=box.querySelectorAll('.opt-items[data-key]');
    for(var j=0;j<groups.length;j++){{
      var g=groups[j]; var key=g.getAttribute('data-key'); var typ=g.getAttribute('data-type');
      if(!key||!typ) continue;
      if(typ==='radio'){{ var r=g.querySelector('input[type=radio]:checked'); if(r&&r.value) out[key]=String(r.value); }}
      if(typ==='checkbox'){{ var cs=g.querySelectorAll('input[type=checkbox]:checked'); if(cs&&cs.length){{ var arr=[]; for(var k=0;k<cs.length;k++){{ if(cs[k].value) arr.push(String(cs[k].value)); }} if(arr.length) out[key]=arr.join(','); }} }}
    }}
    return out;
  }}catch(e){{ return {{}}; }}
}}

function sendTiktokS2S(eventName, properties){{
  if(!linkId) return;
  try{{
    var payload={{
      link_id: linkId,
      event: eventName || 'ClickButton',
      event_id: qs('event_id') || (String(Date.now()) + '_' + Math.random().toString(16).slice(2)),
      url: location.href,
      referrer: document.referrer || '',
      ttclid: qs('ttclid') || getCookie('ttclid') || '',
      ttp: getCookie('_ttp') || '',
      email: qs('email_sha256') || qs('email') || '',
      phone_number: qs('phone_number_sha256') || qs('phone_sha256') || qs('phone_number') || qs('phone') || '',
      external_id: qs('external_id_sha256') || qs('external_id') || '',
      pii_raw: (qs('pii_raw')==='1') ? 1 : 0,
      test_event_code: qs('test_event_code') || '',
      properties: properties || null,
    }};
    var body=JSON.stringify(payload);
    if(navigator.sendBeacon){{ navigator.sendBeacon('/api/tiktok/event', new Blob([body],{{type:'application/json'}})); }}
    else if(window.fetch){{ fetch('/api/tiktok/event',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:body,keepalive:true}}).catch(function(){{}}); }}
  }}catch(e){{}}
}}

function openDeepLink(url){{
  try{{ location.href=url; }}catch(e){{}}
  try{{ var iframe=document.createElement('iframe'); iframe.style.display='none'; iframe.src=url; document.body.appendChild(iframe); setTimeout(function(){{ try{{document.body.removeChild(iframe);}}catch(e){{}} }},1200); }}catch(e){{}}
}}
function doJump(){{ location.href = target; }}
function openAppOrFallback(){{
  if(deepLink){{
    var appOpened=false;
    function mark(){{ appOpened=true; }}
    document.addEventListener('visibilitychange',function(){{ if(document.hidden) mark(); }});
    window.addEventListener('pagehide',mark);
    window.addEventListener('blur',function(){{ setTimeout(mark,0); }});
    var start=Date.now();
    openDeepLink(deepLink);
    setTimeout(function(){{ if(!appOpened && Date.now()-start < 5000) doJump(); }}, 1200);
  }} else {{ doJump(); }}
}}

function startJump(isAuto){{
  if(started) return;
  started=true;
  if (loadingNote){{ loadingNote.textContent = openingText; try{{ loadingNote.classList.add('is-loading'); }}catch(e){{}} }}
  try{{ if(btn) btn.classList.add('is-loading'); }}catch(e){{}}
  try{{ if(btnTextEl) btnTextEl.textContent = openingText; }}catch(e){{}}
  btn.setAttribute('disabled','disabled');
  var props = readCustomOptions();
  if(!isAuto) sendTiktokS2S('ClickButton', props);
  setTimeout(openAppOrFallback, 250);
}}
function handleClick(){{ startJump(false); }}

if(autoJump>0){{
  setTimeout(function(){{ startJump(true); }}, autoJump * 1000);
}}
</script>
</body></html>"""


async def update_idx_bg(link_id: int, idx: int):
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute("UPDATE links SET current_index=? WHERE id=?", (idx, link_id))
            await db.commit()
    except Exception:
        pass


async def log_bg(slug: str, link_id: int, ip_hash: str, target: str, country: str, ua: str, referer: str, is_new: bool):
    os_name = "Other"
    lua = (ua or "").lower()
    if any(x in lua for x in ["iphone", "ipad"]):
        os_name = "iOS"
    elif "android" in lua:
        os_name = "Android"
    elif "windows" in lua:
        os_name = "Windows"
    elif "mac os" in lua:
        os_name = "MacOS"
    elif "linux" in lua:
        os_name = "Linux"
    ref_clean = (referer[:200] if referer else "Direct")
    async with BUFFER_LOCK:
        LOG_BUFFER.append((slug, link_id, ip_hash, target, country, os_name, ref_clean, is_new))
    if is_new:
        try:
            async with aiosqlite.connect(DB_PATH) as db:
                await db.execute(
                    "INSERT INTO visitors (ip_hash, link_id, assigned_target, country, os) VALUES (?,?,?,?,?) "
                    "ON CONFLICT(ip_hash, link_id) DO UPDATE SET assigned_target=excluded.assigned_target, updated_at=CURRENT_TIMESTAMP",
                    (ip_hash, link_id, target, country, os_name),
                )
                await db.commit()
        except Exception:
            pass


@app.get("/admin/debug")
async def admin_debug_page(user=Depends(get_current_user)):
    if not user or user["role"] != "admin":
        return RedirectResponse("/admin", status_code=302)
    html_body = """<!doctype html><html lang='zh-CN'><head><meta charset='utf-8'/><meta name='viewport' content='width=device-width,initial-scale=1'/><title>Admin Debug</title>
<style>body{font-family:system-ui,sans-serif;background:#0b1220;color:#e5e7eb;margin:0} .wrap{max-width:980px;margin:0 auto;padding:18px} .card{background:rgba(15,23,42,.85);border:1px solid rgba(255,255,255,.08);border-radius:16px;padding:14px;margin-bottom:12px}
input{width:100%;padding:10px 12px;border-radius:12px;border:1px solid rgba(255,255,255,.12);background:rgba(2,6,23,.55);color:#e5e7eb;outline:none} button{padding:10px 12px;border-radius:12px;border:1px solid rgba(255,255,255,.12);background:rgba(255,255,255,.06);color:#e5e7eb;cursor:pointer}
pre{white-space:pre-wrap;word-break:break-word;background:rgba(2,6,23,.55);padding:10px;border-radius:12px;border:1px solid rgba(255,255,255,.08)}</style></head><body><div class='wrap'>
<div class='card'><h3>DeepLink</h3><input id='target' placeholder='https://t.me/... / https://line.me/... / https://wa.me...'/><div style='height:10px'></div><button onclick='dbgDeep()'>Query</button></div>
<div class='card'><h3>Link Cache</h3><input id='slug' placeholder='slug'/><div style='height:10px'></div><input id='domainId' placeholder='domain_id (number)'/><div style='height:10px'></div><button onclick='dbgLink()'>Query</button></div>
<div class='card'><h3>Result</h3><pre id='out'>-</pre></div>
</div><script>
async function dbgDeep(){var t=document.getElementById('target').value||'';var r=await fetch('/api/admin/debug/deeplink?target='+encodeURIComponent(t));document.getElementById('out').textContent=await r.text();}
async function dbgLink(){var s=document.getElementById('slug').value||'';var d=document.getElementById('domainId').value||'0';var r=await fetch('/api/admin/debug/link?slug='+encodeURIComponent(s)+'&domain_id='+encodeURIComponent(d));document.getElementById('out').textContent=await r.text();}
</script></body></html>"""
    return HTMLResponse(html_body)


@app.get("/api/admin/debug/deeplink")
async def admin_debug_deeplink(target: str = "", user=Depends(get_current_user)):
    if not user or user["role"] != "admin":
        return JSONResponse({}, 403)
    target = (target or "").strip()
    if not target:
        return JSONResponse({"error": "missing target"}, 400)
    return build_deeplink_info(target)


@app.get("/api/admin/debug/link")
async def admin_debug_link(slug: str = "", domain_id: int = 0, user=Depends(get_current_user)):
    if not user or user["role"] != "admin":
        return JSONResponse({}, 403)
    slug = (slug or "").strip()
    if not slug:
        return JSONResponse({"error": "missing slug"}, 400)
    link_data = LINKS_CACHE.get((slug, int(domain_id))) or LINKS_CACHE.get((slug, 0))
    if not link_data:
        return JSONResponse({"error": "not found"}, 404)
    targets = link_data.get("targets") or []
    target_url = targets[0] if targets else ""
    deep = build_deeplink_info(target_url) if target_url else {}
    return {
        "slug": slug,
        "domain_id": int(domain_id),
        "link_id": link_data.get("id"),
        "target_url": target_url,
        "pixel_id": str(link_data.get("pixel_id") or ""),
        "pixel_event_click": str(link_data.get("pixel_event_click") or "Lead"),
        "pixel_event_auto": str(link_data.get("pixel_event_auto") or "ViewContent"),
        "auto_jump": int(link_data.get("auto_jump") or 0),
        "tiktok_access_token": str(link_data.get("tiktok_access_token") or ""),
        "tiktok_test_event_code": str(link_data.get("tiktok_test_event_code") or ""),
        "country_filter_list": str(link_data.get("country_filter_list") or ""),
        "country_filter_allow": int(link_data.get("country_filter_allow") or 0),
        "device_filter_list": str(link_data.get("device_filter_list") or ""),
        "device_filter_allow": int(link_data.get("device_filter_allow") or 0),
        "deeplink": deep,
    }


@app.post("/api/tiktok/event")
async def tiktok_event(payload: TikTokEventPayload, request: Request):
    host = request.headers.get("host", "").split(":")[0].lower()
    origin = (request.headers.get("origin") or "").lower()
    referer = (request.headers.get("referer") or "").lower()
    if host:
        if origin and host not in origin:
            return JSONResponse({"error": "Bad Origin"}, 403)
        if referer and host not in referer:
            return JSONResponse({"error": "Bad Referer"}, 403)

    link_id = int(payload.link_id)
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        row = await (
            await db.execute(
                "SELECT id, pixel_id, tiktok_access_token, tiktok_test_event_code FROM links WHERE id=?",
                (link_id,),
            )
        ).fetchone()
    if not row:
        return JSONResponse({"error": "短链不存在"}, 404)

    access_token = str(row["tiktok_access_token"] or "").strip()
    pixel_id = str(row["pixel_id"] or "").strip()
    if not access_token or not pixel_id:
        return JSONResponse({"error": "未配置 TikTok Access Token 或 Pixel ID"}, 400)

    event = str(payload.event or "ClickButton").strip() or "ClickButton"
    event_id = str(payload.event_id or str(uuid4()))
    url = str(payload.url or "").strip() or str(request.headers.get("referer") or "") or ""
    referrer = str(payload.referrer or "").strip() or str(request.headers.get("referer") or "") or ""
    ip_addr = _get_client_ip(request)
    user_agent = request.headers.get("user-agent", "")
    ttclid = str(payload.ttclid or "").strip() or _get_cookie(request, "ttclid")
    ttp = str(payload.ttp or "").strip() or _get_cookie(request, "_ttp")
    test_code = str(payload.test_event_code or "").strip() or str(row["tiktok_test_event_code"] or "").strip()
    allow_raw_hash = bool(int(payload.pii_raw or 0))

    properties = payload.properties if isinstance(payload.properties, dict) else {}
    api_payload = _build_tiktok_event_payload(
        pixel_id=pixel_id,
        event=event,
        event_id=event_id,
        url=url,
        referrer=referrer,
        ip=ip_addr,
        user_agent=user_agent,
        ttclid=ttclid,
        ttp=ttp,
        email=str(payload.email or ""),
        phone_number=str(payload.phone_number or ""),
        external_id=str(payload.external_id or ""),
        allow_raw_hash=allow_raw_hash,
        properties=properties,
        test_event_code=test_code,
    )
    res = await asyncio.to_thread(_tiktok_api_post, access_token, api_payload)
    return {"ok": True, "tiktok": res, "event_id": event_id}


@app.get("/{slug}")
async def redirect_logic(slug: str, request: Request, background_tasks: BackgroundTasks):
    if slug in ["admin", "login", "register", "logout", "favicon.ico", "api"]:
        return None

    req_host = request.headers.get("host", "").split(":")[0]
    req_domain_id = DOMAINS_REVERSE.get(req_host, 0)
    link_data = LINKS_CACHE.get((slug, req_domain_id))
    if not link_data:
        link_data = LINKS_CACHE.get((slug, 0))
        if link_data and link_data.get("domain_id") and int(link_data.get("domain_id") or 0) != int(req_domain_id) and int(link_data.get("domain_id") or 0) != 0:
            return HTMLResponse("<h1>404 Not Found</h1>", status_code=404)
    if not link_data:
        return HTMLResponse("<h1>404 Not Found</h1>", status_code=404)

    safe_url = str(link_data.get("safe_url") or "").strip()
    if safe_url and is_suspicious_user(request):
        return RedirectResponse(safe_url, status_code=302)

    def _parse_list(raw: str) -> List[str]:
        txt = str(raw or "")
        if not txt.strip():
            return []
        parts = re.split(r"[\s,;\n\r\t]+", txt)
        out: List[str] = []
        for p in parts:
            p = str(p or "").strip()
            if not p:
                continue
            out.append(p)
        return out

    def _ua_device(ua_raw: str) -> str:
        lua = (ua_raw or "").lower()
        if any(x in lua for x in ["iphone", "ipad", "ios"]):
            return "iOS"
        if "android" in lua:
            return "Android"
        if "windows" in lua:
            return "Windows"
        if "mac os" in lua or "macintosh" in lua:
            return "MacOS"
        if "linux" in lua:
            return "Linux"
        return "Other"

    ua = request.headers.get("user-agent", "")
    country = detect_country(request)
    device = _ua_device(ua)

    def _match_filter(list_raw: str, allow_flag: Any, actual_value: str) -> bool:
        items = _parse_list(list_raw)
        if not items:
            return False
        allow = str(int(bool(int(allow_flag or 0)))) if isinstance(allow_flag, (int, bool)) else str(allow_flag or "")
        allow_on = str(allow).strip().lower() in ("1", "true", "yes")
        aset = {str(x).strip().upper() for x in items if str(x).strip()}
        val = str(actual_value or "").strip().upper()
        if not val:
            return allow_on
        hit = val in aset
        return (not hit) if allow_on else hit

    blocked_by_country = _match_filter(link_data.get("country_filter_list"), link_data.get("country_filter_allow"), country)
    blocked_by_device = _match_filter(link_data.get("device_filter_list"), link_data.get("device_filter_allow"), device)
    if blocked_by_country or blocked_by_device:
        if safe_url:
            return RedirectResponse(safe_url, status_code=302)
        return HTMLResponse("<h1>403 Forbidden</h1>", status_code=403)

    targets = link_data.get("targets", [])
    if not targets:
        return HTMLResponse("<h1>Error: No Targets Configured</h1>", status_code=500)

    link_id = int(link_data.get("id") or 0)
    ip = request.headers.get("CF-Connecting-IP") or (request.client.host if request.client else "127.0.0.1")
    ip_hash = hashlib.md5(str(ip).encode()).hexdigest()
    final_target = None
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            row = await (
                await db.execute("SELECT assigned_target FROM visitors WHERE ip_hash=? AND link_id=?", (ip_hash, link_id))
            ).fetchone()
            if row and row[0] in targets:
                final_target = row[0]
    except Exception:
        final_target = None

    if not final_target:
        idx = int(link_data.get("index") or 0)
        final_target = targets[idx % len(targets)]
        key = (slug, int(link_data.get("domain_id") or 0))
        if key in LINKS_CACHE:
            LINKS_CACHE[key]["index"] = (idx + 1) % len(targets)
        background_tasks.add_task(update_idx_bg, link_id, idx + 1)
        is_new = True
    else:
        is_new = False

    ref = request.headers.get("referer", "")
    background_tasks.add_task(log_bg, slug, link_id, ip_hash, final_target, country, ua, ref, is_new)

    access_token = str(link_data.get("tiktok_access_token") or "").strip()
    pixel_id = str(link_data.get("pixel_id") or "").strip()
    if access_token and pixel_id and len(pixel_id) > 2:
        ip_addr = _get_client_ip(request)
        page_url = str(request.url)
        ttclid_q = str(request.query_params.get("ttclid") or "").strip()
        ttclid_cookie = _get_cookie(request, "ttclid")
        ttclid = ttclid_q or ttclid_cookie
        ttp = _get_cookie(request, "_ttp")
        allow_raw = str(request.query_params.get("pii_raw") or "0") == "1"
        email_q = str(request.query_params.get("email") or request.query_params.get("email_sha256") or "")
        phone_q = str(
            request.query_params.get("phone")
            or request.query_params.get("phone_number")
            or request.query_params.get("phone_number_sha256")
            or ""
        )
        external_id_q = str(request.query_params.get("external_id") or request.query_params.get("external_id_sha256") or "")
        test_code = str(request.query_params.get("test_event_code") or "").strip() or str(link_data.get("tiktok_test_event_code") or "").strip()
        content_id_q = str(request.query_params.get("content_id") or request.query_params.get("contentId") or "").strip()
        content_type_q = str(request.query_params.get("content_type") or request.query_params.get("contentType") or "").strip() or "product"

        vc_content_id = content_id_q or str(link_id or slug or "")
        vc_properties = {
            "content_id": vc_content_id,
            "content_type": content_type_q,
            "contents": [{"content_id": vc_content_id, "content_type": content_type_q}],
        }

        def send_viewcontent():
            try:
                evt_id = str(uuid4())
                payload = _build_tiktok_event_payload(
                    pixel_id=pixel_id,
                    event="ViewContent",
                    event_id=evt_id,
                    url=page_url,
                    referrer=ref or "",
                    ip=ip_addr,
                    user_agent=ua,
                    ttclid=ttclid,
                    ttp=ttp,
                    email=email_q,
                    phone_number=phone_q,
                    external_id=external_id_q,
                    allow_raw_hash=allow_raw,
                    properties=vc_properties,
                    test_event_code=test_code,
                )
                _tiktok_api_post(access_token, payload)
            except Exception:
                pass

        background_tasks.add_task(send_viewcontent)

    force_direct_raw = str(
        request.query_params.get("force_direct")
        or request.query_params.get("direct")
        or request.query_params.get("forceDirect")
        or ""
    ).strip().lower()
    force_direct = force_direct_raw in ("1", "true", "yes")

    ttclid_q = str(request.query_params.get("ttclid") or "").strip()
    need_set_ttclid = bool(ttclid_q) and not bool(_get_cookie(request, "ttclid"))
    if (link_data.get("use_jump_page") or False) and not force_direct:
        resp = HTMLResponse(content=get_marketing_html(final_target, link_data, country), headers={"Cache-Control": "no-store"})
    else:
        resp = HTMLResponse(
            content=get_loading_html(
                final_target,
                country,
                str(link_data.get("pixel_id") or ""),
                str(link_data.get("pixel_event_auto") or "ViewContent"),
                str(link_data.get("pixel_event_click") or "Lead"),
            ),
            headers={"Cache-Control": "no-store"},
        )
    if need_set_ttclid:
        resp.set_cookie("ttclid", ttclid_q, max_age=7 * 24 * 3600, samesite="lax", path="/")
    return resp
