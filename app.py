import io
import os
import re
import time
import json
import random
import hashlib
import logging
import threading
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from contextlib import nullcontext
from datetime import datetime, timedelta
from functools import wraps
from urllib.parse import urlparse, urljoin

import dns.resolver
import pandas as pd
import requests
from bs4 import BeautifulSoup
from flask import Flask, has_app_context, render_template, jsonify, send_file, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from serpapi import GoogleSearch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from openai import OpenAI


from config import SERPAPI_KEY, OPENAI_KEY, SERPAPI_KEYS, OPENAI_KEYS, YOUR_EMAIL, YOUR_WEBSITE, SMTP_HOST, SMTP_PORT, SMTP_PASSWORD


app = Flask(__name__)

# Use a stable secret key — random fallback regenerates on restart (fine for dev)
_secret = os.environ.get("SECRET_KEY")
if not _secret:
    _key_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "instance", ".secret_key")
    os.makedirs(os.path.dirname(_key_file), exist_ok=True)
    if os.path.exists(_key_file):
        with open(_key_file, "r") as f:
            _secret = f.read().strip()
    else:
        _secret = os.urandom(32).hex()
        with open(_key_file, "w") as f:
            f.write(_secret)
app.secret_key = _secret

# ---------------------------------------------------------------------------
# Security Configuration
# ---------------------------------------------------------------------------
IS_PRODUCTION = os.environ.get("FLASK_ENV") == "production"

# File upload limit (10 MB)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024

# Session hardening
app.config["SESSION_COOKIE_HTTPONLY"] = True       # JS cannot read cookie
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"      # CSRF protection
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=8)  # auto-logout
if IS_PRODUCTION:
    app.config["SESSION_COOKIE_SECURE"] = True      # HTTPS only in prod

ALLOWED_UPLOAD_EXTENSIONS = {".csv", ".xlsx", ".xls"}

# ---------------------------------------------------------------------------
# Logging (never log secrets)
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger("GarageLeadsPro")
# Suppress noisy libraries (keep werkzeug at INFO so startup URL is visible)
logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)

# ---------------------------------------------------------------------------
# Database & Auth Setup
# ---------------------------------------------------------------------------
DATABASE_URL = os.environ.get("DATABASE_URL")
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "instance", "users.db")

if DATABASE_URL:
    # Render provides postgres:// but SQLAlchemy 2.x requires postgresql://
    if DATABASE_URL.startswith("postgres://"):
        DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
    app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "connect_args": {"sslmode": "require"}
    }
else:
    # Local development fallback — SQLite
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DB_PATH}"

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

def _db_ctx():
    """Return app context only if not already inside one (avoids teardown bugs)."""
    return nullcontext() if has_app_context() else app.app_context()

login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message_category = "info"

# ---------------------------------------------------------------------------
# Rate Limiter (global — protects all routes)
# ---------------------------------------------------------------------------
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per hour"],
    storage_uri="memory://",
)

csrf = CSRFProtect(app)


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="user")  # "admin" or "user"
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property
    def is_admin(self):
        return self.role == "admin"


class AppSetting(db.Model):
    """Persistent key-value settings stored in SQLite (survives redeploys)."""
    __tablename__ = "app_settings"
    key = db.Column(db.String(100), primary_key=True)
    value = db.Column(db.Text, nullable=False, default="")


class ToolResult(db.Model):
    """Stores tool CSV output in the database so data survives container restarts."""
    __tablename__ = "tool_results"
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(50), unique=True, nullable=False)
    csv_data = db.Column(db.Text, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class AuditFile(db.Model):
    """Stores generated PDF audit files in the database."""
    __tablename__ = "audit_files"
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), unique=True, nullable=False)
    pdf_data = db.Column(db.LargeBinary, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


def admin_required(f):
    """Decorator: require admin role."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            return jsonify({"status": "error", "msg": "Admin access required."}), 403
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# Login Rate Limiting (in-memory)
# ---------------------------------------------------------------------------
_login_attempts = {}  # {ip: [timestamp, ...]}
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_SECONDS = 300  # 5 minutes

def _is_rate_limited(ip):
    """Return True if this IP has exceeded login attempts."""
    now = time.time()
    attempts = _login_attempts.get(ip, [])
    # Purge old attempts
    attempts = [t for t in attempts if now - t < LOCKOUT_SECONDS]
    _login_attempts[ip] = attempts
    return len(attempts) >= MAX_LOGIN_ATTEMPTS

def _record_failed_login(ip):
    _login_attempts.setdefault(ip, []).append(time.time())

def _clear_failed_logins(ip):
    _login_attempts.pop(ip, None)


def _validate_username(username):
    """Return error message or None if valid."""
    if not username:
        return "Username is required."
    if len(username) > 50:
        return "Username must be 50 characters or fewer."
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return "Username may only contain letters, numbers, and underscores."
    return None


def _init_db():
    """Create tables and seed default admin if needed."""
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username="admin").first():
            admin = User(username="admin", role="admin")
            admin.set_password("admin123")
            db.session.add(admin)
            db.session.commit()

_init_db()


# ---------------------------------------------------------------------------
# Persistent Settings (DB-backed, survives redeploys)
# ---------------------------------------------------------------------------
def _get_setting(key, default=""):
    """Read a setting from DB. Returns default if not found."""
    with _db_ctx():
        row = db.session.get(AppSetting, key)
        return row.value if row else default


def _set_setting(key, value):
    """Write a setting to DB (upsert)."""
    with _db_ctx():
        row = db.session.get(AppSetting, key)
        if row:
            row.value = value
        else:
            db.session.add(AppSetting(key=key, value=value))
        db.session.commit()


def _load_keys_from_db():
    """On startup, override config values with any DB-stored keys."""
    global SERPAPI_KEYS, SERPAPI_KEY, OPENAI_KEYS, OPENAI_KEY, YOUR_EMAIL, YOUR_WEBSITE

    global SMTP_HOST, SMTP_PORT, SMTP_PASSWORD

    db_serpapi = _get_setting("SERPAPI_KEY", "")
    db_openai = _get_setting("OPENAI_KEY", "")
    db_email = _get_setting("YOUR_EMAIL", "")
    db_website = _get_setting("YOUR_WEBSITE", "")

    db_smtp_host = _get_setting("SMTP_HOST", "")
    db_smtp_port = _get_setting("SMTP_PORT", "")
    db_smtp_password = _get_setting("SMTP_PASSWORD", "")


    if db_serpapi:
        if "," in db_serpapi:
            SERPAPI_KEYS = [k.strip() for k in db_serpapi.split(",") if k.strip()]
        else:
            SERPAPI_KEYS = [db_serpapi.strip()]
        SERPAPI_KEY = SERPAPI_KEYS[0]
    if db_openai:
        if "," in db_openai:
            OPENAI_KEYS = [k.strip() for k in db_openai.split(",") if k.strip()]
        else:
            OPENAI_KEYS = [db_openai.strip()]
        OPENAI_KEY = OPENAI_KEYS[0]
    if db_email:
        YOUR_EMAIL = db_email
    if db_website:
        YOUR_WEBSITE = db_website

    if db_smtp_host:
        SMTP_HOST = db_smtp_host
    if db_smtp_port:
        try:
            SMTP_PORT = int(db_smtp_port)
        except ValueError:
            pass
    if db_smtp_password:
        SMTP_PASSWORD = db_smtp_password


_load_keys_from_db()


# ---------------------------------------------------------------------------
# Security Headers (applied to every response)
# ---------------------------------------------------------------------------
@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    if IS_PRODUCTION:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    # Prevent caching of authenticated pages
    if current_user.is_authenticated:
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
    return response


@app.errorhandler(413)
def file_too_large(e):
    return jsonify({"status": "error", "msg": "File too large. Maximum size is 10 MB."}), 413


@app.errorhandler(429)
def rate_limit_exceeded(e):
    return jsonify({"status": "error", "msg": "Too many requests. Please slow down."}), 429


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(BASE_DIR, "output")
CITIES_FILE = os.path.join(BASE_DIR, "cities.txt")
RAW_CSV = os.path.join(OUTPUT_DIR, "step1_raw.csv")
SCORED_CSV = os.path.join(OUTPUT_DIR, "step2_scored.csv")
ADS_CSV = os.path.join(OUTPUT_DIR, "step3_ads_checked.csv")
WEBSITE_CSV = os.path.join(OUTPUT_DIR, "step4_website_checked.csv")
HOT_CSV = os.path.join(OUTPUT_DIR, "HOT_prospects.csv")
WARM_CSV = os.path.join(OUTPUT_DIR, "WARM_prospects.csv")
CONTACTS_CSV = os.path.join(OUTPUT_DIR, "step5_contacts.csv")
GBP_CSV = os.path.join(OUTPUT_DIR, "step6_gbp.csv")
COMPETITOR_CSV = os.path.join(OUTPUT_DIR, "step7_competitor.csv")
CALCULATED_CSV = os.path.join(OUTPUT_DIR, "step8_calculated.csv")
EMAILS_CSV = os.path.join(OUTPUT_DIR, "step9_emails.csv")
BEST_LEADS_CSV = os.path.join(OUTPUT_DIR, "best_leads.csv")
IMPORTED_CSV = os.path.join(OUTPUT_DIR, "imported_leads.csv")
AUDITS_DIR = os.path.join(BASE_DIR, "audits")

os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(AUDITS_DIR, exist_ok=True)

# ---------------------------------------------------------------------------
# CSV ↔ Database helpers (persist tool data across container restarts)
# ---------------------------------------------------------------------------
_CSV_KEY_MAP = {
    RAW_CSV: "step1_raw",
    SCORED_CSV: "step2_scored",
    ADS_CSV: "step3_ads_checked",
    WEBSITE_CSV: "step4_website_checked",
    HOT_CSV: "HOT_prospects",
    WARM_CSV: "WARM_prospects",
    CONTACTS_CSV: "step5_contacts",
    GBP_CSV: "step6_gbp",
    COMPETITOR_CSV: "step7_competitor",
    CALCULATED_CSV: "step8_calculated",
    EMAILS_CSV: "step9_emails",
    BEST_LEADS_CSV: "best_leads",
    IMPORTED_CSV: "imported_leads",
}


def _save_csv(path, df):
    """Save DataFrame to database (primary) and file (best-effort)."""
    # 1. Write to DB first — this is the durable store
    key = _CSV_KEY_MAP.get(path)
    if key:
        try:
            csv_text = df.to_csv(index=False)
            with _db_ctx():
                row = ToolResult.query.filter_by(key=key).first()
                if row:
                    row.csv_data = csv_text
                    row.updated_at = datetime.utcnow()
                else:
                    db.session.add(ToolResult(key=key, csv_data=csv_text))
                db.session.commit()
            logger.info("DB save OK  ✓  key=%s  rows=%d", key, len(df))
        except Exception as e:
            db.session.rollback()
            logger.error("DB save FAILED for %s: %s", key, e)
    # 2. Also write to filesystem (convenience for local dev)
    try:
        df.to_csv(path, index=False)
    except Exception:
        pass  # ephemeral disk — not critical


def _load_df(path):
    """Load a DataFrame: try DATABASE first, fall back to file."""
    key = _CSV_KEY_MAP.get(path)
    if key:
        try:
            with _db_ctx():
                row = ToolResult.query.filter_by(key=key).first()
                if row:
                    logger.info("DB load OK  ✓  key=%s", key)
                    return pd.read_csv(io.StringIO(row.csv_data))
        except Exception as e:
            logger.warning("DB load failed for %s: %s", key, e)
    # Fallback: filesystem (local dev or DB not populated yet)
    if os.path.exists(path):
        return pd.read_csv(path)
    return None


def _csv_exists(path):
    """Check if CSV data exists — DATABASE first, then file."""
    key = _CSV_KEY_MAP.get(path)
    if key:
        try:
            with _db_ctx():
                if ToolResult.query.filter_by(key=key).first() is not None:
                    return True
        except Exception:
            pass
    return os.path.exists(path)


def _save_audit_pdf(filename, pdf_bytes):
    """Save a generated PDF to database."""
    try:
        with _db_ctx():
            row = AuditFile.query.filter_by(filename=filename).first()
            if row:
                row.pdf_data = pdf_bytes
            else:
                db.session.add(AuditFile(filename=filename, pdf_data=pdf_bytes))
            db.session.commit()
        logger.info("DB audit save OK  ✓  %s", filename)
    except Exception as e:
        db.session.rollback()
        logger.error("DB save FAILED for audit %s: %s", filename, e)


# Track background job status
job_status = {
    "tool1": "idle", "tool2": "idle", "tool3": "idle", "tool4": "idle", "tool5": "idle", "tool6": "idle", "tool7": "idle", "tool8": "idle", "tool9": "idle", "tool10": "idle",
    "tool1_msg": "", "tool2_msg": "", "tool3_msg": "", "tool4_msg": "", "tool5_msg": "", "tool6_msg": "", "tool7_msg": "", "tool8_msg": "", "tool9_msg": "", "tool10_msg": "",
    "pipeline": "idle", "pipeline_msg": "",
    "outreach": "idle", "outreach_msg": "",
    "outreach_sent": 0, "outreach_total": 0, "outreach_failed": 0, "outreach_skipped": 0,
}

# Active service type for scraping (default: garage door repair)
active_service_type = "garage door repair"

# Smart Mode: when enabled, API-heavy tools only process HOT + promising WARM leads
def _is_smart_mode():
    """Read smart_mode from DB (survives restarts + shared across workers)."""
    return _get_setting("smart_mode", "0") == "1"

def _set_smart_mode(enabled):
    """Write smart_mode to DB."""
    _set_setting("smart_mode", "1" if enabled else "0")

# ---------------------------------------------------------------------------
# API Usage Tracking, Caching & Key Rotation
# ---------------------------------------------------------------------------
USAGE_FILE = os.path.join(BASE_DIR, "instance", "api_usage.json")
CACHE_DIR = os.path.join(BASE_DIR, "instance", "serpapi_cache")
CACHE_TTL_DAYS = 7
SERPAPI_MONTHLY_LIMIT = 100  # free tier

os.makedirs(CACHE_DIR, exist_ok=True)

_usage_lock = threading.Lock()


def _load_usage():
    """Load usage counters from disk, resetting if month changed."""
    default = {"serpapi_calls": 0, "openai_calls": 0, "month": datetime.now().strftime("%Y-%m")}
    if os.path.exists(USAGE_FILE):
        try:
            with open(USAGE_FILE, "r") as f:
                data = json.load(f)
            if data.get("month") != datetime.now().strftime("%Y-%m"):
                return default
            return data
        except Exception:
            pass
    return default


def _save_usage(data):
    os.makedirs(os.path.dirname(USAGE_FILE), exist_ok=True)
    with open(USAGE_FILE, "w") as f:
        json.dump(data, f)


api_usage = _load_usage()


def get_serpapi_warning():
    """Return a warning string if credits are low, or empty string."""
    remaining = SERPAPI_MONTHLY_LIMIT - api_usage["serpapi_calls"]
    if remaining <= 10:
        return f" | WARNING: ~{remaining} SerpApi credits remaining!"
    elif remaining <= 20:
        return f" | NOTE: ~{remaining} SerpApi credits remaining."
    return ""


# --- Caching ---

def _cache_key(params):
    """Generate a deterministic filename from SerpApi params (excluding api_key)."""
    filtered = {k: v for k, v in sorted(params.items()) if k != "api_key"}
    raw = json.dumps(filtered, sort_keys=True)
    return hashlib.sha256(raw.encode()).hexdigest()


def _cache_get(params):
    """Return cached response dict or None if miss/expired."""
    key = _cache_key(params)
    path = os.path.join(CACHE_DIR, f"{key}.json")
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r") as f:
            cached = json.load(f)
        cached_at = datetime.fromisoformat(cached["_cached_at"])
        if datetime.now() - cached_at > timedelta(days=CACHE_TTL_DAYS):
            os.remove(path)
            return None
        return cached["data"]
    except Exception:
        return None


def _cache_set(params, data):
    """Store a SerpApi response in the cache."""
    key = _cache_key(params)
    path = os.path.join(CACHE_DIR, f"{key}.json")
    with open(path, "w") as f:
        json.dump({"_cached_at": datetime.now().isoformat(), "data": data}, f)


# --- Key Rotation ---

_serpapi_key_index = 0
_serpapi_exhausted = set()
_openai_key_index = 0
_openai_exhausted = set()


def _get_serpapi_key():
    global _serpapi_key_index
    if not SERPAPI_KEYS:
        raise RuntimeError("No SerpApi keys configured. Set SERPAPI_KEY in .env")
    if len(_serpapi_exhausted) >= len(SERPAPI_KEYS):
        raise RuntimeError("All SerpApi keys exhausted! Add more keys or wait for monthly reset.")
    while _serpapi_key_index in _serpapi_exhausted:
        _serpapi_key_index = (_serpapi_key_index + 1) % len(SERPAPI_KEYS)
    return SERPAPI_KEYS[_serpapi_key_index]


def _rotate_serpapi_key():
    global _serpapi_key_index
    logger.warning("SerpApi key #%d exhausted, rotating...", _serpapi_key_index + 1)
    _serpapi_exhausted.add(_serpapi_key_index)
    if len(_serpapi_exhausted) >= len(SERPAPI_KEYS):
        raise RuntimeError("All SerpApi keys exhausted!")
    _serpapi_key_index = (_serpapi_key_index + 1) % len(SERPAPI_KEYS)
    while _serpapi_key_index in _serpapi_exhausted:
        _serpapi_key_index = (_serpapi_key_index + 1) % len(SERPAPI_KEYS)
    logger.info("Rotated to SerpApi key #%d", _serpapi_key_index + 1)


def _get_openai_key():
    global _openai_key_index
    if not OPENAI_KEYS or (len(OPENAI_KEYS) == 1 and OPENAI_KEYS[0] in ("", "your_openai_api_key_here")):
        raise RuntimeError("No valid OpenAI key configured. Set OPENAI_KEY in .env")
    if len(_openai_exhausted) >= len(OPENAI_KEYS):
        raise RuntimeError("All OpenAI keys exhausted!")
    while _openai_key_index in _openai_exhausted:
        _openai_key_index = (_openai_key_index + 1) % len(OPENAI_KEYS)
    return OPENAI_KEYS[_openai_key_index]


def _rotate_openai_key():
    global _openai_key_index
    logger.warning("OpenAI key #%d exhausted, rotating...", _openai_key_index + 1)
    _openai_exhausted.add(_openai_key_index)
    if len(_openai_exhausted) >= len(OPENAI_KEYS):
        raise RuntimeError("All OpenAI keys exhausted!")
    _openai_key_index = (_openai_key_index + 1) % len(OPENAI_KEYS)
    while _openai_key_index in _openai_exhausted:
        _openai_key_index = (_openai_key_index + 1) % len(OPENAI_KEYS)
    logger.info("Rotated to OpenAI key #%d", _openai_key_index + 1)


# --- Centralized API Wrappers ---

def serpapi_search(params):
    """Centralized SerpApi call with caching, usage tracking, and key rotation."""
    cached = _cache_get(params)
    if cached is not None:
        logger.info("SerpApi cache HIT for %s", params.get("q", params.get("place_id", "?")))
        return cached

    with _usage_lock:
        remaining = SERPAPI_MONTHLY_LIMIT - api_usage["serpapi_calls"]
    if remaining <= 0:
        raise RuntimeError(f"SerpApi monthly limit reached ({SERPAPI_MONTHLY_LIMIT} calls).")

    max_retries = max(len(SERPAPI_KEYS), 1)
    for attempt in range(max_retries):
        current_key = _get_serpapi_key()
        params["api_key"] = current_key
        try:
            search = GoogleSearch(params)
            result = search.get_dict()
            if "error" in result:
                error_msg = result["error"]
                if any(w in error_msg.lower() for w in ("limit", "exceeded", "quota", "plan")):
                    _rotate_serpapi_key()
                    continue
                raise RuntimeError(f"SerpApi error: {error_msg}")
            with _usage_lock:
                api_usage["serpapi_calls"] += 1
                _save_usage(api_usage)
            _cache_set(params, result)
            return result
        except RuntimeError:
            raise
        except Exception as exc:
            raise RuntimeError(f"SerpApi call failed: {exc}")

    raise RuntimeError("All SerpApi keys exhausted after rotation attempts.")


def openai_chat(messages, model="gpt-4o-mini", max_tokens=None, temperature=None):
    """Centralized OpenAI call with usage tracking and key rotation."""
    max_retries = max(len(OPENAI_KEYS), 1)
    for attempt in range(max_retries):
        current_key = _get_openai_key()
        try:
            client = OpenAI(api_key=current_key)
            kwargs = {"model": model, "messages": messages}
            if max_tokens:
                kwargs["max_tokens"] = max_tokens
            if temperature is not None:
                kwargs["temperature"] = temperature
            response = client.chat.completions.create(**kwargs)
            with _usage_lock:
                api_usage["openai_calls"] += 1
                _save_usage(api_usage)
            return response
        except Exception as exc:
            error_str = str(exc).lower()
            if any(w in error_str for w in ("rate_limit", "quota", "insufficient_quota")):
                try:
                    _rotate_openai_key()
                    continue
                except RuntimeError:
                    raise
            raise

    raise RuntimeError("All OpenAI keys exhausted after rotation attempts.")

# ---------------------------------------------------------------------------
# Tool 1 logic – Scraper
# ---------------------------------------------------------------------------

def load_cities():
    with open(CITIES_FILE) as f:
        return [line.strip() for line in f if line.strip()]


def scrape_city(city, service_type="garage door repair"):
    params = {
        "engine": "google_maps",
        "q": f"{service_type} {city}",
    }
    results = serpapi_search(params)
    businesses = results.get("local_results", [])
    rows = []
    for b in businesses:
        rows.append({
            "business_name": b.get("title"),
            "phone": b.get("phone"),
            "website": b.get("website"),
            "address": b.get("address"),
            "rating": b.get("rating"),
            "review_count": b.get("reviews"),
            "place_id": b.get("place_id"),
            "city": city,
        })
    return rows


def run_tool1():
    try:
        job_status["tool1"] = "running"
        job_status["tool1_msg"] = "Scraping in progress..."
        cities = load_cities()
        service = active_service_type
        all_results = []
        for city in cities:
            all_results.extend(scrape_city(city, service))
            time.sleep(3)
        df = pd.DataFrame(all_results)
        _save_csv(RAW_CSV, df)
        job_status["tool1"] = "done"
        job_status["tool1_msg"] = f"Done. Found {len(df)} companies." + get_serpapi_warning()
    except Exception as e:
        job_status["tool1"] = "error"
        job_status["tool1_msg"] = str(e)

# ---------------------------------------------------------------------------
# Tool 2 logic – Review Scorer
# ---------------------------------------------------------------------------

def score_reviews(review_count):
    if pd.isna(review_count):
        return 3, "HOT"
    review_count = int(review_count)
    if review_count <= 79:
        return 3, "HOT"
    elif review_count <= 150:
        return 2, "WARM"
    else:
        return 1, "COLD"


def run_tool2():
    try:
        job_status["tool2"] = "running"
        job_status["tool2_msg"] = "Scoring in progress..."
        df = _load_df(RAW_CSV)
        scores = df["review_count"].apply(score_reviews)
        df["review_score"] = scores.apply(lambda x: x[0])
        df["prospect_label"] = scores.apply(lambda x: x[1])
        _save_csv(SCORED_CSV, df)
        hot = int((df["prospect_label"] == "HOT").sum())
        warm = int((df["prospect_label"] == "WARM").sum())
        cold = int((df["prospect_label"] == "COLD").sum())
        job_status["tool2"] = "done"
        job_status["tool2_msg"] = f"Done. HOT: {hot} | WARM: {warm} | COLD: {cold} | Total: {len(df)}"
    except Exception as e:
        job_status["tool2"] = "error"
        job_status["tool2_msg"] = str(e)

# ---------------------------------------------------------------------------
# Tool 3 logic – Ads Checker
# ---------------------------------------------------------------------------

def get_domain(url):
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower().replace("www.", "")
        return domain
    except Exception:
        return None


def run_tool3():
    try:
        job_status["tool3"] = "running"
        mode_label = " (Smart Mode)" if _is_smart_mode() else ""
        job_status["tool3_msg"] = f"Checking ads{mode_label}... this may take a few minutes."
        df = _load_df(SCORED_CSV)

        ads_running_list = []
        ads_count_list = []
        updated_labels = []
        total = len(df)
        fail_count = 0
        skipped = 0

        for idx, row in df.iterrows():
            website = row.get("website")
            label = row.get("prospect_label")
            ads_running = "UNKNOWN"
            ads_count = 0

            # Smart Mode: skip COLD leads to save API credits
            if _is_smart_mode() and label == "COLD":
                ads_running = "SKIPPED"
                skipped += 1
            elif pd.notna(website):
                domain = get_domain(website)
                if domain:
                    try:
                        params = {
                            "engine": "google",
                            "q": domain,
                        }
                        results = serpapi_search(params)
                        ads = results.get("ads", [])
                        if ads:
                            ads_running = "YES"
                            ads_count = len(ads)
                        else:
                            ads_running = "NO"
                        time.sleep(2)
                    except Exception as exc:
                        logger.warning("Tool3: ads check failed for %s: %s", domain, exc)
                        fail_count += 1

            new_label = label
            if label == "HOT" and ads_count > 3:
                new_label = "WARM"

            ads_running_list.append(ads_running)
            ads_count_list.append(ads_count)
            updated_labels.append(new_label)
            job_status["tool3_msg"] = f"Checked {idx + 1}/{total} companies..."

        df["ads_running"] = ads_running_list
        df["ads_count"] = ads_count_list
        df["prospect_label"] = updated_labels
        _save_csv(ADS_CSV, df)

        hot_no_ads = int(((df["prospect_label"] == "HOT") & (df["ads_running"] == "NO")).sum())
        job_status["tool3"] = "done"
        msg = f"Done. HOT with no ads: {hot_no_ads} | Total: {total}"
        if skipped:
            msg += f" | {skipped} skipped (Smart Mode)"
        if fail_count:
            msg += f" | {fail_count} failed (API limit?)"
        msg += get_serpapi_warning()
        job_status["tool3_msg"] = msg
    except Exception as e:
        job_status["tool3"] = "error"
        job_status["tool3_msg"] = str(e)

# ---------------------------------------------------------------------------
# Tool 4 logic – Website Checker
# ---------------------------------------------------------------------------

def check_website(url):
    """Analyse a single website and return a dict of quality signals."""
    result = {
        "load_speed": None, "has_mobile": False, "has_phone": False,
        "has_form": False, "has_https": False, "copyright_year": None,
        "has_booking": False, "platform": "UNKNOWN", "website_score": 0,
        "website_quality": "BAD",
    }
    if pd.isna(url):
        result["platform"] = "NO WEBSITE"
        return result

    score = 0
    try:
        start = time.time()
        resp = requests.get(url, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
        result["load_speed"] = round(time.time() - start, 2)
        html = resp.text.lower()

        if url.startswith("https"):
            result["has_https"] = True
            score += 1
        if result["load_speed"] and result["load_speed"] < 3:
            score += 2
        if 'meta name="viewport"' in html or "meta name='viewport'" in html:
            result["has_mobile"] = True
            score += 2
        if "tel:" in html:
            result["has_phone"] = True
            score += 2
        if "<form" in html:
            result["has_form"] = True
            score += 1
        if any(w in html for w in ["book", "schedule", "appointment"]):
            result["has_booking"] = True
            score += 1
        years = re.findall(r"20[0-9]{2}", html)
        if years:
            result["copyright_year"] = max(years)
            if int(result["copyright_year"]) >= 2023:
                score += 1

        if "wix" in html:
            result["platform"] = "WIX"
        elif "wordpress" in html or "wp-content" in html:
            result["platform"] = "WORDPRESS"
        elif "squarespace" in html:
            result["platform"] = "SQUARESPACE"
        elif "godaddy" in html:
            result["platform"] = "GODADDY"
        else:
            result["platform"] = "CUSTOM"
    except Exception:
        pass

    result["website_score"] = score
    if score <= 3:
        result["website_quality"] = "BAD"
    elif score <= 6:
        result["website_quality"] = "BASIC"
    else:
        result["website_quality"] = "GOOD"
    return result


def run_tool4():
    try:
        job_status["tool4"] = "running"
        job_status["tool4_msg"] = "Checking websites... this may take a few minutes."
        df = _load_df(ADS_CSV)
        total = len(df)
        rows = []

        for idx, (_, row) in enumerate(df.iterrows()):
            rows.append(check_website(row.get("website")))
            job_status["tool4_msg"] = f"Checked {idx + 1}/{total} websites..."
            time.sleep(2)

        results_df = pd.DataFrame(rows)
        df = pd.concat([df, results_df], axis=1)
        _save_csv(WEBSITE_CSV, df)

        hot_df = df[df["prospect_label"] == "HOT"]
        warm_df = df[df["prospect_label"] == "WARM"]

        # Smart Mode: include promising WARM leads (bad/basic website, < 120 reviews)
        # in the HOT pipeline so Tools 5-10 also process them
        if _is_smart_mode():
            promising_warm = warm_df[
                (warm_df["website_quality"].isin(["BAD", "BASIC"])) |
                (warm_df["review_count"].fillna(0).astype(int) < 120)
            ]
            priority_df = pd.concat([hot_df, promising_warm], ignore_index=True)
            _save_csv(HOT_CSV, priority_df)
            remaining_warm = warm_df[~warm_df.index.isin(promising_warm.index)]
            _save_csv(WARM_CSV, remaining_warm)
        else:
            _save_csv(HOT_CSV, hot_df)
            _save_csv(WARM_CSV, warm_df)

        processed_count = len(hot_df) if not _is_smart_mode() else len(priority_df)

        bad = int((df["website_quality"] == "BAD").sum())
        basic = int((df["website_quality"] == "BASIC").sum())
        good = int((df["website_quality"] == "GOOD").sum())
        job_status["tool4"] = "done"
        msg = f"Done. BAD: {bad} | BASIC: {basic} | GOOD: {good} | "
        if _is_smart_mode():
            msg += f"Priority leads (HOT+WARM): {processed_count}"
        else:
            msg += f"HOT: {len(hot_df)} | WARM: {len(warm_df)}"
        job_status["tool4_msg"] = msg
    except Exception as e:
        job_status["tool4"] = "error"
        job_status["tool4_msg"] = str(e)

# ---------------------------------------------------------------------------
# Tool 5 logic – Contact Finder + SMTP Verification
# ---------------------------------------------------------------------------

def find_owner_name(text):
    _NAME = r"([A-Z][a-z]+ [A-Z][a-z]+)"
    patterns = [
        r"owner[:\s]+" + _NAME,
        r"owned\s+by\s+" + _NAME,
        r"operated\s+by\s+" + _NAME,
        r"founder[:\s]+" + _NAME,
        r"co-founder[:\s]+" + _NAME,
        r"CEO[:\s]+" + _NAME,
        r"president[:\s]+" + _NAME,
        r"meet\s+" + _NAME,
        r"my name is " + _NAME,
    ]
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return match.group(1)
    return None


def verify_email_smtp(email):
    """Verify an email via SMTP. Returns VALID, INVALID, CATCH-ALL, NO_MX, or UNKNOWN."""
    if not email:
        return "UNKNOWN"
    domain = email.split("@")[1]
    try:
        mx_records = dns.resolver.resolve(domain, "MX")
        mx_host = str(sorted(mx_records, key=lambda r: r.preference)[0].exchange).rstrip(".")
    except Exception:
        return "NO_MX"
    try:
        smtp = smtplib.SMTP(timeout=10)
        smtp.connect(mx_host, 25)
        smtp.helo("verify.local")
        smtp.mail("test@verify.local")
        code, _ = smtp.rcpt(email)
        fake_code, _ = smtp.rcpt(f"zzzfake9999@{domain}")
        smtp.quit()
        if code == 250:
            return "CATCH-ALL" if fake_code == 250 else "VALID"
        return "INVALID"
    except (smtplib.SMTPServerDisconnected, smtplib.SMTPConnectError):
        return "UNKNOWN"
    except Exception:
        return "UNKNOWN"


def find_contact(website):
    """Scrape a website for owner name, email, and phone."""
    owner_name = "Team"
    email = None
    phone = None

    email_source = None

    if pd.isna(website):
        return owner_name, email, phone, email_source

    # Junk email domains/prefixes to ignore
    _JUNK_PREFIXES = {"noreply", "no-reply", "donotreply", "mailer-daemon", "example"}
    _JUNK_DOMAINS = {
        "example.com", "wix.com", "wixpress.com", "squarespace.com",
        "wordpress.com", "sentry.io", "googleapis.com", "google.com",
        "facebook.com", "twitter.com", "instagram.com",
    }
    _JUNK_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".css", ".js"}

    def _is_junk_email(addr):
        addr = addr.lower().strip()
        local, _, dom = addr.partition("@")
        if not dom:
            return True
        if local in _JUNK_PREFIXES:
            return True
        if dom in _JUNK_DOMAINS:
            return True
        if any(addr.endswith(ext) for ext in _JUNK_EXTENSIONS):
            return True
        return False

    try:
        urls_to_check = [
            website,
            urljoin(website, "/contact"),
            urljoin(website, "/contact-us"),
            urljoin(website, "/about"),
            urljoin(website, "/about-us"),
            urljoin(website, "/team"),
            urljoin(website, "/our-team"),
        ]
        full_text = ""
        scraped_emails = []
        for url in urls_to_check:
            try:
                r = requests.get(url, timeout=8, headers={"User-Agent": "Mozilla/5.0"})
                if r.status_code != 200:
                    continue
                soup = BeautifulSoup(r.text, "html.parser")
                full_text += " " + soup.get_text(separator=" ").strip()

                # Extract mailto: links
                for a_tag in soup.find_all("a", href=True):
                    href = a_tag["href"]
                    if href.lower().startswith("mailto:"):
                        addr = href[7:].split("?")[0].strip()
                        if addr and "@" in addr and not _is_junk_email(addr):
                            scraped_emails.append(addr.lower())
            except Exception:
                continue

        # Extract emails from page text via regex
        text_emails = re.findall(r"[\w.+-]+@[\w-]+\.[\w.]+", full_text)
        for addr in text_emails:
            addr = addr.lower().strip().rstrip(".")
            if "@" in addr and not _is_junk_email(addr):
                scraped_emails.append(addr)

        # Deduplicate while preserving order
        seen = set()
        unique_emails = []
        for e in scraped_emails:
            if e not in seen:
                seen.add(e)
                unique_emails.append(e)

        name = find_owner_name(full_text)
        if name:
            owner_name = name

        phone_match = re.search(r"\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}", full_text)
        if phone_match:
            phone = phone_match.group()

        # Email priority: scraped (domain match) > scraped (other) > guessed
        domain = get_domain(website)
        if unique_emails and domain:
            domain_matches = [e for e in unique_emails if e.endswith("@" + domain)]
            if domain_matches:
                email = domain_matches[0]
                email_source = "SCRAPED"
            else:
                email = unique_emails[0]
                email_source = "SCRAPED"
        elif unique_emails:
            email = unique_emails[0]
            email_source = "SCRAPED"
        elif domain:
            if owner_name != "Team":
                first = owner_name.split()[0].lower()
                email = f"{first}@{domain}"
                email_source = "GUESSED"
            else:
                email = f"info@{domain}"
                email_source = "GUESSED"
    except Exception:
        pass

    return owner_name, email, phone, email_source


def run_tool5():
    try:
        job_status["tool5"] = "running"
        job_status["tool5_msg"] = "Finding contacts..."
        df = _load_df(HOT_CSV)
        total = len(df)

        owners, emails, phones, statuses, sources = [], [], [], [], []
        for idx, (_, row) in enumerate(df.iterrows()):
            o, e, p, src = find_contact(row.get("website"))
            owners.append(o)
            emails.append(e)
            phones.append(p)
            sources.append(src)

            # SMTP verification
            job_status["tool5_msg"] = f"[{idx + 1}/{total}] Verifying {e or 'N/A'}..."
            status = verify_email_smtp(e)
            statuses.append(status)
            time.sleep(2)

        df["owner_name"] = owners
        df["personal_email"] = emails
        df["email_source"] = sources
        df["email_status"] = statuses
        df["direct_phone"] = phones
        _save_csv(CONTACTS_CSV, df)

        owner_found = int((df["owner_name"] != "Team").sum())
        email_found = int(df["personal_email"].notna().sum())
        scraped = int((df["email_source"] == "SCRAPED").sum())
        valid = int((df["email_status"] == "VALID").sum())
        catchall = int((df["email_status"] == "CATCH-ALL").sum())
        phone_found = int(df["direct_phone"].notna().sum())
        job_status["tool5"] = "done"
        job_status["tool5_msg"] = (
            f"Done. Names: {owner_found} | Emails: {email_found} "
            f"({scraped} scraped, {email_found - scraped} guessed) "
            f"| SMTP: {valid} valid, {catchall} catch-all | Phones: {phone_found}"
        )
    except Exception as e:
        job_status["tool5"] = "error"
        job_status["tool5_msg"] = str(e)

# ---------------------------------------------------------------------------
# Tool 6 logic – GBP Analyser
# ---------------------------------------------------------------------------

def analyse_gbp(place_id):
    """Fetch Google Business Profile data and return a quality dict."""
    result = {
        "gbp_photos": 0, "gbp_services": 0, "gbp_has_description": False,
        "gbp_has_hours": False, "gbp_has_posts": False, "gbp_reply_rate": 0.0,
        "gbp_score": 0, "gbp_label": "POOR",
    }
    if pd.isna(place_id):
        return result

    score = 0
    try:
        params = {"engine": "google_maps", "place_id": place_id}
        data = serpapi_search(params)

        photos = len(data.get("photos", []))
        result["gbp_photos"] = photos
        if photos > 20:
            score += 20
        elif photos >= 10:
            score += 10
        elif photos > 0:
            score += 5

        desc = data.get("description", "")
        if desc:
            result["gbp_has_description"] = True
            score += 15 if len(desc) > 150 else 8

        services_list = data.get("services", [])
        result["gbp_services"] = len(services_list)
        if len(services_list) > 5:
            score += 15
        elif len(services_list) >= 2:
            score += 8

        reviews = data.get("reviews", [])
        responses = sum(1 for r in reviews if "response" in r)
        if len(reviews) > 0:
            result["gbp_reply_rate"] = round(responses / len(reviews), 2)
            if result["gbp_reply_rate"] > 0.5:
                score += 15
            elif result["gbp_reply_rate"] > 0:
                score += 8

        if data.get("hours"):
            result["gbp_has_hours"] = True
            score += 15

        if data.get("posts"):
            result["gbp_has_posts"] = True
            score += 20
    except Exception as exc:
        logger.warning("Tool6: GBP analysis failed for place_id %s: %s", place_id, exc)
        result["_failed"] = True

    result["gbp_score"] = score
    if score < 40:
        result["gbp_label"] = "POOR"
    elif score <= 70:
        result["gbp_label"] = "AVERAGE"
    else:
        result["gbp_label"] = "STRONG"
    return result


def run_tool6():
    try:
        job_status["tool6"] = "running"
        job_status["tool6_msg"] = "Analysing Google profiles..."
        df = _load_df(CONTACTS_CSV)
        total = len(df)
        rows = []
        fail_count = 0

        for idx, (_, row) in enumerate(df.iterrows()):
            gbp_result = analyse_gbp(row.get("place_id"))
            if gbp_result.pop("_failed", False):
                fail_count += 1
            rows.append(gbp_result)
            job_status["tool6_msg"] = f"Checked {idx + 1}/{total} profiles..."
            time.sleep(2)

        results_df = pd.DataFrame(rows)
        df = pd.concat([df, results_df], axis=1)
        _save_csv(GBP_CSV, df)

        avg = round(df["gbp_score"].mean(), 1)
        poor = int((df["gbp_label"] == "POOR").sum())
        average = int((df["gbp_label"] == "AVERAGE").sum())
        strong = int((df["gbp_label"] == "STRONG").sum())
        job_status["tool6"] = "done"
        msg = f"Done. Avg: {avg}/100 | POOR: {poor} | AVERAGE: {average} | STRONG: {strong}"
        if fail_count:
            msg += f" | {fail_count} failed (API limit?)"
        msg += get_serpapi_warning()
        job_status["tool6_msg"] = msg
    except Exception as e:
        job_status["tool6"] = "error"
        job_status["tool6_msg"] = str(e)

# ---------------------------------------------------------------------------
# Tool 7 logic – Competitor Intelligence
# ---------------------------------------------------------------------------

def run_tool7():
    try:
        job_status["tool7"] = "running"
        job_status["tool7_msg"] = "Analysing competitors..."
        df = _load_df(GBP_CSV)
        total = len(df)
        rows = []
        fail_count = 0

        for idx, (_, row) in enumerate(df.iterrows()):
            city = row.get("city", "")
            review_count = row.get("review_count", 0)
            if pd.isna(review_count):
                review_count = 0
            review_count = int(review_count)

            top1_name, top1_reviews = "", 0
            top2_name, top2_reviews = "", 0
            top3_name, top3_reviews = "", 0
            gap_score = 5

            if pd.notna(city) and city:
                try:
                    params = {
                        "engine": "google_maps",
                        "q": f"{active_service_type} {city}",
                        "num": 10,
                    }
                    data = serpapi_search(params)
                    competitors = data.get("local_results", [])
                    competitors = sorted(
                        competitors,
                        key=lambda x: int(x.get("reviews", 0) or 0),
                        reverse=True,
                    )

                    if len(competitors) >= 1:
                        top1_name = competitors[0].get("title", "")
                        top1_reviews = int(competitors[0].get("reviews", 0) or 0)
                    if len(competitors) >= 2:
                        top2_name = competitors[1].get("title", "")
                        top2_reviews = int(competitors[1].get("reviews", 0) or 0)
                    if len(competitors) >= 3:
                        top3_name = competitors[2].get("title", "")
                        top3_reviews = int(competitors[2].get("reviews", 0) or 0)

                    avg_top3 = (top1_reviews + top2_reviews + top3_reviews) / 3 if (top1_reviews + top2_reviews + top3_reviews) > 0 else 0

                    if avg_top3 == 0:
                        gap_score = 1
                    else:
                        ratio = review_count / avg_top3
                        if ratio >= 1.0:
                            gap_score = 1
                        elif ratio >= 0.75:
                            gap_score = 3
                        elif ratio >= 0.5:
                            gap_score = 5
                        elif ratio >= 0.25:
                            gap_score = 7
                        else:
                            gap_score = 9

                    time.sleep(2)
                except Exception as exc:
                    logger.warning("Tool7: competitor check failed for city %s: %s", city, exc)
                    fail_count += 1

            if gap_score <= 3:
                urgency = "LOW"
            elif gap_score <= 6:
                urgency = "MEDIUM"
            else:
                urgency = "HIGH"

            rows.append({
                "top1_name": top1_name,
                "top1_reviews": top1_reviews,
                "top2_name": top2_name,
                "top2_reviews": top2_reviews,
                "top3_name": top3_name,
                "top3_reviews": top3_reviews,
                "competitive_gap_score": gap_score,
                "urgency": urgency,
            })
            job_status["tool7_msg"] = f"Checked {idx + 1}/{total} businesses..."

        results_df = pd.DataFrame(rows)
        df = pd.concat([df, results_df], axis=1)
        _save_csv(COMPETITOR_CSV, df)

        avg_gap = round(df["competitive_gap_score"].mean(), 1)
        low = int((df["urgency"] == "LOW").sum())
        medium = int((df["urgency"] == "MEDIUM").sum())
        high = int((df["urgency"] == "HIGH").sum())
        job_status["tool7"] = "done"
        msg = f"Done. Avg Gap: {avg_gap}/10 | LOW: {low} | MEDIUM: {medium} | HIGH: {high}"
        if fail_count:
            msg += f" | {fail_count} failed (API limit?)"
        msg += get_serpapi_warning()
        job_status["tool7_msg"] = msg
    except Exception as e:
        job_status["tool7"] = "error"
        job_status["tool7_msg"] = str(e)

# ---------------------------------------------------------------------------
# Tool 8 logic – Value Calculator
# ---------------------------------------------------------------------------

def run_tool8():
    """Calculate value metrics and ROI opportunity scores."""
    try:
        job_status["tool8"] = "running"
        job_status["tool8_msg"] = "Calculating value metrics..."
        df = _load_df(COMPETITOR_CSV)
        roi_multiples = []
        monthly_values = []
        value_sentences = []

        for _, row in df.iterrows():
            gap = row.get("competitive_gap_score", 5)
            gbp_score = row.get("gbp_score", 50)
            website_score = row.get("website_score", 5)

            if pd.isna(gap): gap = 5
            if pd.isna(gbp_score): gbp_score = 50
            if pd.isna(website_score): website_score = 5

            gap = int(gap)
            gbp_score = int(gbp_score)
            website_score = int(website_score)

            # ROI opportunity score (0-50 scale)
            ws_opportunity = 10 - website_score
            gbp_opportunity = round((100 - gbp_score) / 10)
            roi_multiple = round(gap * 2.5 + ws_opportunity * 1.5 + gbp_opportunity * 1.0, 1)

            # Estimated monthly value
            base_calls = 20
            capture_rate = min(gap / 10, 1.0)
            estimated_new_calls = max(round(base_calls * capture_rate * 0.5), 1)
            avg_job_value = 350
            monthly_value = estimated_new_calls * avg_job_value

            roi_multiples.append(roi_multiple)
            monthly_values.append(monthly_value)
            value_sentences.append(
                f"~{estimated_new_calls} extra calls/mo = ${monthly_value}/mo (${monthly_value * 12}/yr). ROI score: {roi_multiple}/50."
            )

        df["roi_multiple"] = roi_multiples
        df["monthly_value"] = monthly_values
        df["value_summary_sentence"] = value_sentences

        # Column aliases for tool 9 compatibility
        if "top1_name" in df.columns:
            df["competitor_1_name"] = df["top1_name"]
            df["competitor_1_reviews"] = df["top1_reviews"]

        _save_csv(CALCULATED_CSV, df)

        avg_roi = round(sum(roi_multiples) / len(roi_multiples), 1) if roi_multiples else 0
        high_roi = sum(1 for r in roi_multiples if r >= 30)
        job_status["tool8"] = "done"
        job_status["tool8_msg"] = (
            f"Done. Avg ROI: {avg_roi}/50 | High ROI (30+): {high_roi} | Total: {len(df)}"
        )
    except Exception as e:
        job_status["tool8"] = "error"
        job_status["tool8_msg"] = str(e)

# ---------------------------------------------------------------------------
# Tool 9 logic – Email Personaliser (OpenAI)
# ---------------------------------------------------------------------------

def run_tool9():
    try:
        job_status["tool9"] = "running"
        job_status["tool9_msg"] = "Generating personalised emails..."
        df = _load_df(CALCULATED_CSV)
        total = len(df)
        rows = []
        ai_fail_count = 0

        for idx, (_, row) in enumerate(df.iterrows()):
            business = row.get("business_name", "")
            city = row.get("city", "")
            reviews = row.get("review_count", "")
            ads = row.get("ads_running", "")
            website_quality = row.get("website_quality", "")
            platform = row.get("platform", "")

            comp_name = row.get("competitor_1_name", "")
            comp_reviews = row.get("competitor_1_reviews", "")

            owner = row.get("owner_name", "there")
            if pd.isna(owner) or owner == "Team":
                owner = "there"
            value_sentence = row.get("value_summary_sentence", "")

            context = f"""
Business: {business} in {city}
Reviews: {reviews}
Ads Running: {ads}
Website: {website_quality} ({platform})
Top Competitor: {comp_name} with {comp_reviews} reviews
Value: {value_sentence}
"""

            opener = ""
            try:
                response = openai_chat(
                    messages=[
                        {
                            "role": "system",
                            "content": """You are an expert cold email copywriter.

Write ONE opening line for a cold email.

Rules:
- Max 30 words
- Mention something specific about their business
- Highlight a gap (competitor or missing feature)
- Sound natural and human
- Do NOT sound like AI or marketing""",
                        },
                        {"role": "user", "content": context},
                    ],
                    model="gpt-4o-mini",
                )
                opener = response.choices[0].message.content.strip()
            except Exception as exc:
                logger.warning("Tool9: OpenAI failed for %s: %s", business, exc)
                opener = f"I noticed a few gaps in {business}'s Google presence that could be costing you calls."
                ai_fail_count += 1

            subject = f"Quick question about {business}"

            full_email = f"""Subject: {subject}

Hi {owner},

{opener}

I put together a quick audit showing a few gaps in your Google presence and how you can start getting more calls.

Happy to share it — takes 10 minutes.

Best,
Pravin
{YOUR_WEBSITE}
{YOUR_EMAIL}
"""

            rows.append({
                "business_name": business,
                "owner_name": owner,
                "email_subject": subject,
                "custom_opener": opener,
                "full_email": full_email,
            })
            job_status["tool9_msg"] = f"Generated {idx + 1}/{total} emails..."
            time.sleep(1)

        result_df = pd.DataFrame(rows)
        _save_csv(EMAILS_CSV, result_df)

        job_status["tool9"] = "done"
        msg = f"Done. Generated {len(result_df)} personalised emails."
        if ai_fail_count:
            msg += f" | {ai_fail_count} used fallback (AI unavailable)."
        job_status["tool9_msg"] = msg
    except Exception as e:
        job_status["tool9"] = "error"
        job_status["tool9_msg"] = str(e)

# ---------------------------------------------------------------------------
# Tool 10 logic – PDF Generator
# ---------------------------------------------------------------------------

def run_tool10():
    try:
        job_status["tool10"] = "running"
        job_status["tool10_msg"] = "Generating PDF audits..."
        df = _load_df(EMAILS_CSV)
        total = len(df)
        styles = getSampleStyleSheet()
        generated = []

        for idx, (_, row) in enumerate(df.iterrows()):
            business = row.get("business_name", "Unknown")
            city = row.get("city", "")
            reviews = row.get("review_count", "")
            website_score = row.get("website_score", "")
            gbp_score = row.get("gbp_score", "")
            gap = row.get("competitive_gap_score", "")
            value = row.get("value_summary_sentence", "")

            safe_name = str(business).replace(" ", "_").replace("/", "_")
            filename = os.path.join(AUDITS_DIR, f"{safe_name}_Audit.pdf")

            doc = SimpleDocTemplate(filename)
            content = []

            content.append(Paragraph(f"<b>{business} — Audit Report</b>", styles["Title"]))
            content.append(Spacer(1, 20))

            content.append(Paragraph(f"<b>City:</b> {city}", styles["Normal"]))
            content.append(Paragraph(f"<b>Google Reviews:</b> {reviews}", styles["Normal"]))
            content.append(Paragraph(f"<b>Website Score:</b> {website_score}/10", styles["Normal"]))
            content.append(Paragraph(f"<b>GBP Score:</b> {gbp_score}/100", styles["Normal"]))
            content.append(Paragraph(f"<b>Competitive Gap:</b> {gap}/10", styles["Normal"]))

            content.append(Spacer(1, 20))

            content.append(Paragraph("<b>Revenue Opportunity</b>", styles["Heading2"]))
            val_text = str(value) if pd.notna(value) and str(value) != "nan" else "Contact us for a detailed analysis."
            content.append(Paragraph(val_text, styles["Normal"]))

            content.append(Spacer(1, 20))

            content.append(Paragraph("<b>Key Issues Found:</b>", styles["Heading2"]))
            content.append(Paragraph("- Low visibility compared to competitors", styles["Normal"]))
            content.append(Paragraph("- Missing or weak Google Ads presence", styles["Normal"]))
            content.append(Paragraph("- Website improvements needed", styles["Normal"]))

            content.append(Spacer(1, 20))

            content.append(Paragraph("<b>Our Solution</b>", styles["Heading2"]))
            content.append(Paragraph(
                "We help garage door companies generate consistent leads using Google Ads and optimisation.",
                styles["Normal"],
            ))

            content.append(Spacer(1, 20))

            content.append(Paragraph("<b>Next Step</b>", styles["Heading2"]))
            content.append(Paragraph(
                "Book a 15-minute call to review this audit and discuss growth opportunities.",
                styles["Normal"],
            ))

            doc.build(content)
            # Also save PDF to database for persistence
            pdf_filename = f"{safe_name}_Audit.pdf"
            try:
                with open(os.path.join(AUDITS_DIR, pdf_filename), "rb") as pf:
                    _save_audit_pdf(pdf_filename, pf.read())
            except Exception:
                pass
            generated.append({"business_name": business, "pdf_file": pdf_filename})
            job_status["tool10_msg"] = f"Generated {idx + 1}/{total} PDFs..."

        job_status["tool10"] = "done"
        job_status["tool10_msg"] = f"Done. Generated {len(generated)} PDF audits in /audits folder."
    except Exception as e:
        job_status["tool10"] = "error"
        job_status["tool10_msg"] = str(e)

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

def _load_csv(path):
    """Load a CSV file as list of dicts, or None if it doesn't exist."""
    df = _load_df(path)
    if df is not None:
        for col in df.columns:
            if pd.api.types.is_numeric_dtype(df[col]):
                df[col] = df[col].fillna(0)
            else:
                df[col] = df[col].fillna("")
        return df.to_dict(orient="records")
    return None


def _load_cities_str():
    if os.path.exists(CITIES_FILE):
        with open(CITIES_FILE) as f:
            return ", ".join(line.strip() for line in f if line.strip())
    return ""


def _load_audit_files():
    files = []
    if os.path.exists(AUDITS_DIR):
        files = [f for f in os.listdir(AUDITS_DIR) if f.endswith(".pdf")]
    # Also check database for audit files not on disk
    try:
        db_audits = AuditFile.query.all()
        db_names = {a.filename for a in db_audits}
        disk_names = set(files)
        for name in db_names - disk_names:
            files.append(name)
    except Exception:
        pass
    files.sort()
    return files


# ---------------------------------------------------------------------------
# Auth Routes
# ---------------------------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    if request.method == "POST":
        client_ip = request.remote_addr
        if _is_rate_limited(client_ip):
            return render_template("login.html", error="Too many failed attempts. Please try again in 5 minutes.")
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            _clear_failed_logins(client_ip)
            login_user(user, remember=True)
            logger.info("User '%s' logged in from %s", username, client_ip)
            next_page = request.args.get("next")
            # Validate redirect target to prevent open-redirect attacks
            if next_page:
                parsed = urlparse(next_page)
                if parsed.netloc and parsed.netloc != request.host:
                    next_page = None
            return redirect(next_page or url_for("index"))
        _record_failed_login(client_ip)
        logger.warning("Failed login attempt for '%s' from %s", username, client_ip)
        return render_template("login.html", error="Invalid username or password.")
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logger.info("User '%s' logged out", current_user.username)
    logout_user()
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# User Management Routes (Admin Only)
# ---------------------------------------------------------------------------

@app.route("/users")
@login_required
@admin_required
def list_users():
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template(
        "settings.html", active_page="settings",
        current_cities=_load_cities_str(),
        active_service=active_service_type,
        smart_mode=_is_smart_mode(),
        users=users, show_users=True,
    )


@app.route("/users/create", methods=["POST"])
@login_required
@admin_required
def create_user():
    data = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "")
    role = data.get("role", "user")
    # Validate username
    uname_err = _validate_username(username)
    if uname_err:
        return jsonify({"status": "error", "msg": uname_err})
    if not password:
        return jsonify({"status": "error", "msg": "Password is required."})
    if len(password) < 4:
        return jsonify({"status": "error", "msg": "Password must be at least 4 characters."})
    if len(password) > 128:
        return jsonify({"status": "error", "msg": "Password must be 128 characters or fewer."})
    if role not in ("admin", "user"):
        role = "user"
    if User.query.filter_by(username=username).first():
        return jsonify({"status": "error", "msg": f"Username '{username}' already exists."})
    user = User(username=username, role=role)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    logger.info("Admin '%s' created user '%s' (role=%s)", current_user.username, username, role)
    return jsonify({"status": "ok", "msg": f"User '{username}' created as {role}."})


@app.route("/users/delete", methods=["POST"])
@login_required
@admin_required
def delete_user():
    data = request.get_json()
    user_id = data.get("user_id")
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({"status": "error", "msg": "User not found."})
    if user.id == current_user.id:
        return jsonify({"status": "error", "msg": "You cannot delete yourself."})
    db.session.delete(user)
    db.session.commit()
    logger.info("Admin '%s' deleted user '%s'", current_user.username, user.username)
    return jsonify({"status": "ok", "msg": f"User '{user.username}' deleted."})


@app.route("/users/reset-password", methods=["POST"])
@login_required
@admin_required
def reset_password():
    data = request.get_json()
    user_id = data.get("user_id")
    new_password = data.get("password", "")
    if len(new_password) < 4:
        return jsonify({"status": "error", "msg": "Password must be at least 4 characters."})
    if len(new_password) > 128:
        return jsonify({"status": "error", "msg": "Password must be 128 characters or fewer."})
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({"status": "error", "msg": "User not found."})
    user.set_password(new_password)
    db.session.commit()
    return jsonify({"status": "ok", "msg": f"Password reset for '{user.username}'."})


# ---------------------------------------------------------------------------
# App Routes (All Protected)
# ---------------------------------------------------------------------------

@app.route("/")
@login_required
def index():
    raw_data = _load_csv(RAW_CSV)
    scored_data = _load_csv(SCORED_CSV)
    ads_data = _load_csv(ADS_CSV)
    website_data = _load_csv(WEBSITE_CSV)
    contacts_data = _load_csv(CONTACTS_CSV)
    gbp_data = _load_csv(GBP_CSV)
    competitor_data = _load_csv(COMPETITOR_CSV)
    calculated_data = _load_csv(CALCULATED_CSV)
    emails_data = _load_csv(EMAILS_CSV)
    best_leads_data = _load_csv(BEST_LEADS_CSV)
    audit_files = _load_audit_files()

    # Pre-compute chart data to avoid Jinja2 inside <script>
    chart_data = {
        "prospects": {"hot": 0, "warm": 0, "cold": 0},
        "websites": {"bad": 0, "basic": 0, "good": 0},
        "cities": {},
        "urgency": {"low": 0, "medium": 0, "high": 0},
    }
    if scored_data:
        for r in scored_data:
            lbl = r.get("prospect_label", "")
            if lbl == "HOT": chart_data["prospects"]["hot"] += 1
            elif lbl == "WARM": chart_data["prospects"]["warm"] += 1
            elif lbl == "COLD": chart_data["prospects"]["cold"] += 1
    if website_data:
        for r in website_data:
            q = r.get("website_quality", "")
            if q == "BAD": chart_data["websites"]["bad"] += 1
            elif q == "BASIC": chart_data["websites"]["basic"] += 1
            elif q == "GOOD": chart_data["websites"]["good"] += 1
    if raw_data:
        for r in raw_data:
            city = r.get("city", "Unknown")
            chart_data["cities"][city] = chart_data["cities"].get(city, 0) + 1
    if competitor_data:
        for r in competitor_data:
            u = r.get("urgency", "")
            if u == "LOW": chart_data["urgency"]["low"] += 1
            elif u == "MEDIUM": chart_data["urgency"]["medium"] += 1
            elif u == "HIGH": chart_data["urgency"]["high"] += 1

    return render_template(
        "dashboard.html",
        active_page="dashboard",
        raw_data=raw_data, scored_data=scored_data,
        ads_data=ads_data, website_data=website_data,
        contacts_data=contacts_data, gbp_data=gbp_data,
        competitor_data=competitor_data, calculated_data=calculated_data,
        emails_data=emails_data, best_leads_data=best_leads_data,
        audit_files=audit_files, chart_data=chart_data,
        smart_mode=_is_smart_mode(),
    )


@app.route("/tool/scraper")
@login_required
def page_tool1():
    return render_template("tool1.html", active_page="tool1", raw_data=_load_csv(RAW_CSV))


@app.route("/pipeline-results")
@login_required
def page_pipeline_results():
    """Single page showing all tool results in one view."""
    return render_template(
        "pipeline_results.html",
        active_page="pipeline_results",
        scored_data=_load_csv(SCORED_CSV),
        ads_data=_load_csv(ADS_CSV),
        website_data=_load_csv(WEBSITE_CSV),
        contacts_data=_load_csv(CONTACTS_CSV),
        gbp_data=_load_csv(GBP_CSV),
        competitor_data=_load_csv(COMPETITOR_CSV),
        calculated_data=_load_csv(CALCULATED_CSV),
        emails_data=_load_csv(EMAILS_CSV),
        audit_files=_load_audit_files(),
    )


@app.route("/tool/scorer")
@login_required
def page_tool2():
    return render_template("tool2.html", active_page="tool2", scored_data=_load_csv(SCORED_CSV))


@app.route("/tool/ads")
@login_required
def page_tool3():
    return render_template("tool3.html", active_page="tool3", ads_data=_load_csv(ADS_CSV))


@app.route("/tool/website")
@login_required
def page_tool4():
    return render_template("tool4.html", active_page="tool4", website_data=_load_csv(WEBSITE_CSV))


@app.route("/tool/contacts")
@login_required
def page_tool5():
    return render_template("tool5.html", active_page="tool5", contacts_data=_load_csv(CONTACTS_CSV))


@app.route("/tool/gbp")
@login_required
def page_tool6():
    return render_template("tool6.html", active_page="tool6", gbp_data=_load_csv(GBP_CSV))


@app.route("/tool/competitor")
@login_required
def page_tool7():
    return render_template("tool7.html", active_page="tool7", competitor_data=_load_csv(COMPETITOR_CSV))


@app.route("/tool/value")
@login_required
def page_tool8():
    return render_template("tool8.html", active_page="tool8", calculated_data=_load_csv(CALCULATED_CSV))


@app.route("/tool/emails")
@login_required
def page_tool9():
    return render_template("tool9.html", active_page="tool9", emails_data=_load_csv(EMAILS_CSV))


@app.route("/tool/pdfs")
@login_required
def page_tool10():
    return render_template("tool10.html", active_page="tool10", audit_files=_load_audit_files())


@app.route("/settings")
@login_required
def page_settings():
    return render_template(
        "settings.html", active_page="settings",
        current_cities=_load_cities_str(),
        active_service=active_service_type,
        smart_mode=_is_smart_mode(),
    )


@app.route("/save_cities", methods=["POST"])
@login_required
def save_cities():
    data = request.get_json()
    cities_text = data.get("cities", "")
    cities = [c.strip() for c in cities_text.split(",") if c.strip()]
    with open(CITIES_FILE, "w") as f:
        for city in cities:
            f.write(city + "\n")
    return jsonify({"status": "ok", "msg": f"Saved {len(cities)} cities.", "cities": cities})


@app.route("/save_service", methods=["POST"])
@login_required
def save_service():
    global active_service_type
    data = request.get_json()
    active_service_type = data.get("service", "garage door repair")
    return jsonify({"status": "ok", "msg": f"Service set to: {active_service_type}"})


@app.route("/save_smart_mode", methods=["POST"])
@login_required
def save_smart_mode():
    data = request.get_json()
    enabled = data.get("enabled", False)
    _set_smart_mode(enabled)
    label = "ON" if enabled else "OFF"
    return jsonify({"status": "ok", "msg": f"Smart Mode: {label}"})


@app.route("/save_api_keys", methods=["POST"])
@login_required
@admin_required
def save_api_keys():
    """Admin-only: update API keys in DB (persistent) and .env (backup)."""
    data = request.get_json()

    allowed_keys = {
        "SERPAPI_KEY": data.get("serpapi_key", "").strip(),
        "OPENAI_KEY": data.get("openai_key", "").strip(),
        "YOUR_EMAIL": data.get("your_email", "").strip(),
        "YOUR_WEBSITE": data.get("your_website", "").strip(),
        "SMTP_HOST": data.get("smtp_host", "").strip(),
        "SMTP_PORT": data.get("smtp_port", "").strip(),
        "SMTP_PASSWORD": data.get("smtp_password", "").strip(),
    }

    updated = []
    for key, val in allowed_keys.items():
        if val:  # only save non-empty values
            _set_setting(key, val)
            updated.append(key)

    # Also update .env as backup (best-effort, may fail on read-only filesystems)
    env_path = os.path.join(BASE_DIR, ".env")
    try:
        env_lines = []
        if os.path.exists(env_path):
            with open(env_path, "r") as f:
                env_lines = f.readlines()

        written_keys = set()
        new_lines = []
        for line in env_lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                new_lines.append(line)
                continue
            matched = False
            for key, new_val in allowed_keys.items():
                if stripped.startswith(key + "="):
                    if new_val:
                        new_lines.append(f"{key}={new_val}\n")
                        written_keys.add(key)
                    else:
                        new_lines.append(line)
                    matched = True
                    break
            if not matched:
                new_lines.append(line)
        for key, new_val in allowed_keys.items():
            if key not in written_keys and new_val:
                new_lines.append(f"{key}={new_val}\n")
        with open(env_path, "w") as f:
            f.writelines(new_lines)
    except Exception:
        logger.info("Could not update .env file (read-only filesystem?). DB save succeeded.")

    # Reload globals from DB
    global SERPAPI_KEYS, SERPAPI_KEY, OPENAI_KEYS, OPENAI_KEY, YOUR_EMAIL, YOUR_WEBSITE
    global SMTP_HOST, SMTP_PORT, SMTP_PASSWORD
    global _serpapi_key_index, _serpapi_exhausted, _openai_key_index, _openai_exhausted

    _load_keys_from_db()

    # Reset exhausted keys since we have new keys
    _serpapi_key_index = 0
    _serpapi_exhausted = set()
    _openai_key_index = 0
    _openai_exhausted = set()

    if not updated:
        return jsonify({"status": "ok", "msg": "No changes made (empty values ignored)."})
    return jsonify({"status": "ok", "msg": f"Updated: {', '.join(updated)}. Keys saved to database and reloaded."})


@app.route("/get_api_keys")
@login_required
@admin_required
def get_api_keys():
    """Admin-only: return current API key info (masked for security)."""
    def mask_key(key):
        if not key or key in ("", "your_openai_api_key_here", "your_serpapi_key_here"):
            return ""
        return "Configured"

    return jsonify({
        "serpapi_key": mask_key(SERPAPI_KEY),
        "serpapi_keys_count": len(SERPAPI_KEYS),
        "openai_key": mask_key(OPENAI_KEY),
        "openai_keys_count": len(OPENAI_KEYS),
        "your_email": YOUR_EMAIL,
        "your_website": YOUR_WEBSITE,
        "smtp_host": SMTP_HOST,
        "smtp_port": SMTP_PORT,
        "smtp_configured": bool(SMTP_HOST and SMTP_PASSWORD),
    })


@app.route("/run/pipeline", methods=["POST"])
@login_required
@limiter.limit("5 per hour")
def start_pipeline():
    if job_status["pipeline"] == "running":
        return jsonify({"status": "running", "msg": "Pipeline is already running."})
    thread = threading.Thread(target=run_pipeline)
    thread.start()
    return jsonify({"status": "started", "msg": "Full pipeline started."})


def run_pipeline():
    job_status["pipeline"] = "running"
    tools = [
        ("tool1", "Tool 1 — Scraper", run_tool1),
        ("tool2", "Tool 2 — Review Scorer", run_tool2),
        ("tool3", "Tool 3 — Ads Checker", run_tool3),
        ("tool4", "Tool 4 — Website Checker", run_tool4),
        ("tool5", "Tool 5 — Contact Finder", run_tool5),
        ("tool6", "Tool 6 — GBP Analyser", run_tool6),
        ("tool7", "Tool 7 — Competitor Intel", run_tool7),
        ("tool8", "Tool 8 — Value Calculator", run_tool8),
        ("tool9", "Tool 9 — Email Personaliser", run_tool9),
        ("tool10", "Tool 10 — PDF Generator", run_tool10),
    ]
    errors = []
    try:
        with app.app_context():
            for key, label, func in tools:
                job_status["pipeline_msg"] = f"Running {label}..."
                try:
                    func()
                    if job_status[key] == "error":
                        errors.append(f"{label}: {job_status[key + '_msg']}")
                except Exception as e:
                    logger.error("Pipeline tool %s failed: %s", label, e, exc_info=True)
                    job_status[key] = "error"
                    job_status[key + "_msg"] = str(e)
                    errors.append(f"{label}: {e}")

            # Build summary
            summary_parts = []
            if _csv_exists(RAW_CSV):
                _df = _load_df(RAW_CSV)
                summary_parts.append(f"Companies: {len(_df)}")
            if _csv_exists(HOT_CSV):
                _df = _load_df(HOT_CSV)
                summary_parts.append(f"HOT: {len(_df)}")
            if _csv_exists(EMAILS_CSV):
                _df = _load_df(EMAILS_CSV)
                summary_parts.append(f"Emails: {len(_df)}")
            if os.path.exists(AUDITS_DIR):
                pdfs = [f for f in os.listdir(AUDITS_DIR) if f.endswith(".pdf")]
                summary_parts.append(f"PDFs: {len(pdfs)}")

            msg = "Pipeline complete. " + " | ".join(summary_parts)
            if errors:
                msg += f" | {len(errors)} error(s): " + "; ".join(errors)
    except Exception as e:
        logger.error("Pipeline crashed: %s", e, exc_info=True)
        msg = f"Pipeline crashed: {e}"
        if errors:
            msg += f" | Previous errors: " + "; ".join(errors)

    job_status["pipeline"] = "done"
    job_status["pipeline_msg"] = msg


@app.route("/clear_output", methods=["POST"])
@login_required
def clear_output():
    removed = 0
    for f in os.listdir(OUTPUT_DIR):
        fp = os.path.join(OUTPUT_DIR, f)
        if f.endswith((".csv", ".xlsx")) and os.path.isfile(fp):
            os.remove(fp)
            removed += 1
    pdf_removed = 0
    if os.path.exists(AUDITS_DIR):
        for f in os.listdir(AUDITS_DIR):
            fp = os.path.join(AUDITS_DIR, f)
            if f.endswith(".pdf") and os.path.isfile(fp):
                os.remove(fp)
                pdf_removed += 1
    # Also clear from database
    try:
        ToolResult.query.delete()
        AuditFile.query.delete()
        db.session.commit()
    except Exception as e:
        logger.warning("DB clear failed: %s", e)
    return jsonify({"status": "ok", "msg": f"Removed {removed} data files + {pdf_removed} PDFs."})


@app.route("/run/tool1", methods=["POST"])
@login_required
@limiter.limit("10 per hour")
def start_tool1():
    if job_status["tool1"] == "running":
        return jsonify({"status": "running", "msg": "Tool 1 is already running."})
    thread = threading.Thread(target=run_tool1)
    thread.start()
    return jsonify({"status": "started", "msg": "Tool 1 started."})


@app.route("/run/tool2", methods=["POST"])
@login_required
def start_tool2():
    if job_status["tool2"] == "running":
        return jsonify({"status": "running", "msg": "Tool 2 is already running."})
    if not _csv_exists(RAW_CSV):
        return jsonify({"status": "error", "msg": "Run Tool 1 first — no raw data found."})
    thread = threading.Thread(target=run_tool2)
    thread.start()
    return jsonify({"status": "started", "msg": "Tool 2 started."})


@app.route("/run/tool3", methods=["POST"])
@login_required
def start_tool3():
    if job_status["tool3"] == "running":
        return jsonify({"status": "running", "msg": "Tool 3 is already running."})
    if not _csv_exists(SCORED_CSV):
        return jsonify({"status": "error", "msg": "Run Tool 2 first — no scored data found."})
    thread = threading.Thread(target=run_tool3)
    thread.start()
    return jsonify({"status": "started", "msg": "Tool 3 started."})


@app.route("/run/tool4", methods=["POST"])
@login_required
def start_tool4():
    if job_status["tool4"] == "running":
        return jsonify({"status": "running", "msg": "Tool 4 is already running."})
    if not _csv_exists(ADS_CSV):
        return jsonify({"status": "error", "msg": "Run Tool 3 first — no ads data found."})
    thread = threading.Thread(target=run_tool4)
    thread.start()
    return jsonify({"status": "started", "msg": "Tool 4 started."})


@app.route("/run/tool5", methods=["POST"])
@login_required
def start_tool5():
    if job_status["tool5"] == "running":
        return jsonify({"status": "running", "msg": "Tool 5 is already running."})
    if not _csv_exists(HOT_CSV):
        return jsonify({"status": "error", "msg": "Run Tool 4 first — no HOT prospects found."})
    thread = threading.Thread(target=run_tool5)
    thread.start()
    return jsonify({"status": "started", "msg": "Tool 5 started."})


@app.route("/run/tool6", methods=["POST"])
@login_required
def start_tool6():
    if job_status["tool6"] == "running":
        return jsonify({"status": "running", "msg": "Tool 6 is already running."})
    if not _csv_exists(CONTACTS_CSV):
        return jsonify({"status": "error", "msg": "Run Tool 5 first — no contacts data found."})
    thread = threading.Thread(target=run_tool6)
    thread.start()
    return jsonify({"status": "started", "msg": "Tool 6 started."})


@app.route("/run/tool7", methods=["POST"])
@login_required
def start_tool7():
    if job_status["tool7"] == "running":
        return jsonify({"status": "running", "msg": "Tool 7 is already running."})
    if not _csv_exists(GBP_CSV):
        return jsonify({"status": "error", "msg": "Run Tool 6 first — no GBP data found."})
    thread = threading.Thread(target=run_tool7)
    thread.start()
    return jsonify({"status": "started", "msg": "Tool 7 started."})


@app.route("/run/tool8", methods=["POST"])
@login_required
def start_tool8():
    if job_status["tool8"] == "running":
        return jsonify({"status": "running", "msg": "Tool 8 is already running."})
    if not _csv_exists(COMPETITOR_CSV):
        return jsonify({"status": "error", "msg": "Run Tool 7 first — no competitor data found."})
    thread = threading.Thread(target=run_tool8)
    thread.start()
    return jsonify({"status": "started", "msg": "Tool 8 started."})


@app.route("/run/tool9", methods=["POST"])
@login_required
def start_tool9():
    if job_status["tool9"] == "running":
        return jsonify({"status": "running", "msg": "Tool 9 is already running."})
    if not _csv_exists(CALCULATED_CSV):
        return jsonify({"status": "error", "msg": "Run Tool 8 first — no calculated data found."})
    thread = threading.Thread(target=run_tool9)
    thread.start()
    return jsonify({"status": "started", "msg": "Tool 9 started."})


@app.route("/run/tool10", methods=["POST"])
@login_required
def start_tool10():
    if job_status["tool10"] == "running":
        return jsonify({"status": "running", "msg": "Tool 10 is already running."})
    if not _csv_exists(EMAILS_CSV):
        return jsonify({"status": "error", "msg": "Run Tool 9 first — no emails data found."})
    thread = threading.Thread(target=run_tool10)
    thread.start()
    return jsonify({"status": "started", "msg": "Tool 10 started."})


@app.route("/download/audit/<filename>")
@login_required
def download_audit(filename):
    # Sanitize filename
    safe_name = secure_filename(filename)
    filepath = os.path.join(AUDITS_DIR, safe_name)
    if os.path.exists(filepath):
        return send_file(filepath, as_attachment=True, download_name=safe_name)
    # Fall back to database
    try:
        row = AuditFile.query.filter_by(filename=safe_name).first()
        if row:
            return send_file(
                io.BytesIO(row.pdf_data),
                as_attachment=True,
                download_name=safe_name,
                mimetype="application/pdf",
            )
    except Exception:
        pass
    return "File not found.", 404


@app.route("/status")
@login_required
@limiter.exempt
def status():
    data = dict(job_status)
    remaining = SERPAPI_MONTHLY_LIMIT - api_usage["serpapi_calls"]
    data["smart_mode"] = _is_smart_mode()
    data["api_usage"] = {
        "serpapi_calls": api_usage["serpapi_calls"],
        "serpapi_remaining": remaining,
        "serpapi_limit": SERPAPI_MONTHLY_LIMIT,
        "serpapi_keys_total": len(SERPAPI_KEYS),
        "serpapi_keys_exhausted": len(_serpapi_exhausted),
        "openai_calls": api_usage["openai_calls"],
        "openai_keys_total": len(OPENAI_KEYS),
        "openai_keys_exhausted": len(_openai_exhausted),
        "month": api_usage["month"],
    }
    return jsonify(data)


@app.route("/api_usage")
@login_required
@limiter.exempt
def api_usage_endpoint():
    remaining = SERPAPI_MONTHLY_LIMIT - api_usage["serpapi_calls"]
    return jsonify({
        "serpapi_calls": api_usage["serpapi_calls"],
        "serpapi_remaining": remaining,
        "serpapi_limit": SERPAPI_MONTHLY_LIMIT,
        "serpapi_keys_total": len(SERPAPI_KEYS),
        "serpapi_keys_exhausted": len(_serpapi_exhausted),
        "openai_calls": api_usage["openai_calls"],
        "openai_keys_total": len(OPENAI_KEYS),
        "openai_keys_exhausted": len(_openai_exhausted),
        "month": api_usage["month"],
    })


@app.route("/cache_stats")
@login_required
def cache_stats():
    count = 0
    total_size = 0
    if os.path.exists(CACHE_DIR):
        for f in os.listdir(CACHE_DIR):
            if f.endswith(".json"):
                count += 1
                total_size += os.path.getsize(os.path.join(CACHE_DIR, f))
    return jsonify({
        "cached_queries": count,
        "total_size_kb": round(total_size / 1024, 1),
        "ttl_days": CACHE_TTL_DAYS,
    })


@app.route("/clear_cache", methods=["POST"])
@login_required
def clear_cache():
    removed = 0
    if os.path.exists(CACHE_DIR):
        for f in os.listdir(CACHE_DIR):
            if f.endswith(".json"):
                os.remove(os.path.join(CACHE_DIR, f))
                removed += 1
    return jsonify({"status": "ok", "msg": f"Cleared {removed} cached queries."})


@app.route("/kpi")
@login_required
def kpi():
    """Return KPI data for the dashboard cards and charts."""
    data = {
        "total_leads": 0, "hot_count": 0, "warm_count": 0, "cold_count": 0,
        "emails_ready": 0, "pdfs_ready": 0, "avg_gap": 0,
        "avg_website_score": 0, "avg_gbp_score": 0,
        "ads_yes": 0, "ads_no": 0,
        "bad_sites": 0, "basic_sites": 0, "good_sites": 0,
        "gbp_poor": 0, "gbp_average": 0, "gbp_strong": 0,
        "urgency_low": 0, "urgency_medium": 0, "urgency_high": 0,
        "cities": {},
    }
    try:
        df = _load_df(RAW_CSV)
        if df is not None:
            data["total_leads"] = len(df)
            for _, row in df.iterrows():
                c = str(row.get("city", "Unknown"))
                data["cities"][c] = data["cities"].get(c, 0) + 1
    except Exception:
        pass
    try:
        df = _load_df(SCORED_CSV)
        if df is not None:
            data["hot_count"] = int((df["prospect_label"] == "HOT").sum())
            data["warm_count"] = int((df["prospect_label"] == "WARM").sum())
            data["cold_count"] = int((df["prospect_label"] == "COLD").sum())
    except Exception:
        pass
    try:
        df = _load_df(ADS_CSV)
        if df is not None:
            data["ads_yes"] = int((df["ads_running"] == "YES").sum())
            data["ads_no"] = int((df["ads_running"] == "NO").sum())
    except Exception:
        pass
    try:
        df = _load_df(WEBSITE_CSV)
        if df is not None:
            data["bad_sites"] = int((df["website_quality"] == "BAD").sum())
            data["basic_sites"] = int((df["website_quality"] == "BASIC").sum())
            data["good_sites"] = int((df["website_quality"] == "GOOD").sum())
            data["avg_website_score"] = round(df["website_score"].mean(), 1) if len(df) else 0
    except Exception:
        pass
    try:
        df = _load_df(GBP_CSV)
        if df is not None:
            data["gbp_poor"] = int((df["gbp_label"] == "POOR").sum())
            data["gbp_average"] = int((df["gbp_label"] == "AVERAGE").sum())
            data["gbp_strong"] = int((df["gbp_label"] == "STRONG").sum())
            data["avg_gbp_score"] = round(df["gbp_score"].mean(), 1) if len(df) else 0
    except Exception:
        pass
    try:
        df = _load_df(COMPETITOR_CSV)
        if df is not None:
            data["urgency_low"] = int((df["urgency"] == "LOW").sum())
            data["urgency_medium"] = int((df["urgency"] == "MEDIUM").sum())
            data["urgency_high"] = int((df["urgency"] == "HIGH").sum())
            data["avg_gap"] = round(df["competitive_gap_score"].mean(), 1) if len(df) else 0
    except Exception:
        pass
    try:
        df = _load_df(CALCULATED_CSV)
        if df is not None:
            data["avg_roi"] = round(df["roi_multiple"].mean(), 1) if len(df) else 0
            data["high_roi_count"] = int((df["roi_multiple"] >= 30).sum())
    except Exception:
        pass
    try:
        df = _load_df(EMAILS_CSV)
        if df is not None:
            data["emails_ready"] = len(df)
    except Exception:
        pass
    try:
        data["pdfs_ready"] = len(_load_audit_files())
    except Exception:
        pass
    return jsonify(data)


@app.route("/download_filtered")
@login_required
def download_filtered():
    """Download a filtered subset of a tool's CSV data."""
    tool = request.args.get("tool", "")
    filter_type = request.args.get("filter", "")

    # Map tool to source CSV
    tool_csv_map = {
        "tool2": SCORED_CSV,
        "tool3": ADS_CSV,
        "tool4": WEBSITE_CSV,
        "tool5": CONTACTS_CSV,
        "tool6": GBP_CSV,
        "tool7": COMPETITOR_CSV,
        "tool8": CALCULATED_CSV,
    }

    csv_path = tool_csv_map.get(tool)
    if not csv_path or not _csv_exists(csv_path):
        return "Source data not found. Run the tool first.", 404

    df = _load_df(csv_path)

    # Apply filter based on tool + filter_type
    if tool == "tool2":
        if filter_type == "hot":
            df = df[df["prospect_label"] == "HOT"]
        elif filter_type == "warm":
            df = df[df["prospect_label"] == "WARM"]
        elif filter_type == "cold":
            df = df[df["prospect_label"] == "COLD"]
        else:
            return "Invalid filter for tool2.", 400

    elif tool == "tool3":
        if filter_type == "hot_no_ads":
            df = df[(df["prospect_label"] == "HOT") & (df["ads_running"] == "NO")]
        elif filter_type == "no_ads":
            df = df[df["ads_running"] == "NO"]
        elif filter_type == "running_ads":
            df = df[df["ads_running"] == "YES"]
        else:
            return "Invalid filter for tool3.", 400

    elif tool == "tool4":
        if filter_type == "bad":
            df = df[df["website_quality"] == "BAD"]
        elif filter_type == "basic":
            df = df[df["website_quality"] == "BASIC"]
        elif filter_type == "good":
            df = df[df["website_quality"] == "GOOD"]
        else:
            return "Invalid filter for tool4.", 400

    elif tool == "tool5":
        if filter_type == "has_email":
            df = df[df["personal_email"].notna()]
        elif filter_type == "has_owner":
            df = df[df["owner_name"] != "Team"]
        elif filter_type == "valid_email":
            df = df[df["email_status"] == "VALID"]
        elif filter_type == "scraped_email":
            df = df[df["email_source"] == "SCRAPED"]
        elif filter_type == "guessed_email":
            df = df[df["email_source"] == "GUESSED"]
        else:
            return "Invalid filter for tool5.", 400

    elif tool == "tool6":
        if filter_type == "poor":
            df = df[df["gbp_score"] < 40]
        elif filter_type == "strong":
            df = df[df["gbp_score"] > 70]
        elif filter_type == "average":
            df = df[(df["gbp_score"] >= 40) & (df["gbp_score"] <= 70)]
        else:
            return "Invalid filter for tool6.", 400

    elif tool == "tool7":
        if filter_type == "high_gap":
            df = df[df["competitive_gap_score"] >= 7]
        elif filter_type == "medium_gap":
            df = df[(df["competitive_gap_score"] >= 4) & (df["competitive_gap_score"] <= 6)]
        elif filter_type == "low_gap":
            df = df[df["competitive_gap_score"] <= 3]
        else:
            return "Invalid filter for tool7.", 400

    elif tool == "tool8":
        if filter_type == "high_roi":
            df = df[df["roi_multiple"] >= 30]
        elif filter_type == "medium_roi":
            df = df[(df["roi_multiple"] >= 15) & (df["roi_multiple"] < 30)]
        elif filter_type == "low_roi":
            df = df[df["roi_multiple"] < 15]
        else:
            return "Invalid filter for tool8.", 400
    else:
        return "Invalid tool.", 400

    if len(df) == 0:
        return "No results match that filter.", 404

    filename = f"{tool}_{filter_type}.csv"
    buf = io.BytesIO(df.to_csv(index=False).encode("utf-8"))
    return send_file(buf, as_attachment=True, download_name=filename, mimetype="text/csv")


@app.route("/download_smart")
@login_required
def download_smart():
    """Smart Export: combine filters across tools into one download."""
    label = request.args.get("label", "")        # HOT, WARM, COLD
    ads = request.args.get("ads", "")             # NO, YES
    quality = request.args.get("quality", "")     # BAD, BASIC, GOOD
    gap_min = request.args.get("gap_min", "")     # e.g. 7
    roi_min = request.args.get("roi_min", "")     # e.g. 30

    # Find the most complete CSV (furthest tool that has been run)
    source = None
    for path in [CALCULATED_CSV, COMPETITOR_CSV, GBP_CSV, CONTACTS_CSV, WEBSITE_CSV, ADS_CSV, SCORED_CSV]:
        if _csv_exists(path):
            source = path
            break
    if not source:
        return "No data found. Run the pipeline first.", 404

    df = _load_df(source)

    if label and "prospect_label" in df.columns:
        df = df[df["prospect_label"] == label]
    if ads and "ads_running" in df.columns:
        df = df[df["ads_running"] == ads]
    if quality and "website_quality" in df.columns:
        df = df[df["website_quality"] == quality]
    if gap_min and "competitive_gap_score" in df.columns:
        df = df[df["competitive_gap_score"] >= int(gap_min)]
    if roi_min and "roi_multiple" in df.columns:
        df = df[df["roi_multiple"] >= float(roi_min)]

    if len(df) == 0:
        return "No results match those filters.", 404

    filename = "smart_export.csv"
    buf = io.BytesIO(df.to_csv(index=False).encode("utf-8"))
    return send_file(buf, as_attachment=True, download_name=filename, mimetype="text/csv")


@app.route("/best_leads")
@login_required
@limiter.exempt
def best_leads():
    """Generate Best Leads using dynamic toggle filters."""
    try:
        if not _csv_exists(CALCULATED_CSV):
            return jsonify({"status": "error", "msg": "No data found. Run through Tool 8 first.", "count": 0})

        df = _load_df(CALCULATED_CSV)
        if df is None or df.empty:
            return jsonify({"status": "error", "msg": "Could not load Tool 8 data. Please re-run Tool 8.", "count": 0})

        # Read toggle params ("1" = enabled, default all on)
        use_hot = request.args.get("hot", "1") == "1"
        use_no_ads = request.args.get("no_ads", "1") == "1"
        use_bad_site = request.args.get("bad_site", "1") == "1"
        use_high_roi = request.args.get("high_roi", "1") == "1"
        use_high_gap = request.args.get("high_gap", "1") == "1"
        download = request.args.get("download", "0") == "1"

        mask = pd.Series([True] * len(df), index=df.index)

        if use_hot and "prospect_label" in df.columns:
            mask &= df["prospect_label"] == "HOT"
        if use_no_ads and "ads_running" in df.columns:
            mask &= df["ads_running"] == "NO"
        if use_bad_site and "website_quality" in df.columns:
            mask &= df["website_quality"].isin(["BAD", "BASIC"])
        if use_high_roi and "roi_multiple" in df.columns:
            mask &= df["roi_multiple"] >= 30
        if use_high_gap and "competitive_gap_score" in df.columns:
            mask &= df["competitive_gap_score"] >= 7

        filtered = df[mask]
        _save_csv(BEST_LEADS_CSV, filtered)

        if download:
            if len(filtered) == 0:
                return "No best leads found with current filters.", 404
            buf = io.BytesIO(filtered.to_csv(index=False).encode("utf-8"))
            return send_file(buf, as_attachment=True, download_name="best_leads.csv", mimetype="text/csv")

        # Clean NaN → None so jsonify produces valid JSON (NaN is not valid JSON)
        preview = json.loads(filtered.head(20).to_json(orient="records"))
        return jsonify({"status": "ok", "count": len(filtered), "total": len(df), "preview": preview})
    except Exception as e:
        logger.error("Best leads error: %s", e)
        return jsonify({"status": "error", "msg": f"Error generating best leads: {str(e)}", "count": 0})


@app.route("/download/<tool>/<fmt>")
@login_required
def download(tool, fmt):
    if tool == "tool1":
        csv_path = RAW_CSV
        basename = "step1_raw"
    elif tool == "tool2":
        csv_path = SCORED_CSV
        basename = "step2_scored"
    elif tool == "tool3":
        csv_path = ADS_CSV
        basename = "step3_ads_checked"
    elif tool == "tool4":
        csv_path = WEBSITE_CSV
        basename = "step4_website_checked"
    elif tool == "hot":
        csv_path = HOT_CSV
        basename = "HOT_prospects"
    elif tool == "warm":
        csv_path = WARM_CSV
        basename = "WARM_prospects"
    elif tool == "tool5":
        csv_path = CONTACTS_CSV
        basename = "step5_contacts"
    elif tool == "tool6":
        csv_path = GBP_CSV
        basename = "step6_gbp"
    elif tool == "tool7":
        csv_path = COMPETITOR_CSV
        basename = "step7_competitor"
    elif tool == "tool8":
        csv_path = CALCULATED_CSV
        basename = "step8_calculated"
    elif tool == "tool9":
        csv_path = EMAILS_CSV
        basename = "step9_emails"
    else:
        return "Invalid tool", 404

    if not _csv_exists(csv_path):
        return "File not found. Run the tool first.", 404

    if fmt == "csv":
        df = _load_df(csv_path)
        buf = io.BytesIO(df.to_csv(index=False).encode("utf-8"))
        return send_file(buf, as_attachment=True, download_name=f"{basename}.csv", mimetype="text/csv")
    elif fmt == "excel":
        df = _load_df(csv_path)
        buf = io.BytesIO()
        df.to_excel(buf, index=False)
        buf.seek(0)
        return send_file(buf, as_attachment=True, download_name=f"{basename}.xlsx",
                         mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
    else:
        return "Invalid format. Use csv or excel.", 400


# ---------------------------------------------------------------------------
# Import Leads Feature
# ---------------------------------------------------------------------------

# Standard column names expected by the system
STANDARD_COLS = ["business_name", "phone", "website", "address", "rating", "review_count", "city"]

# Common aliases users might have in their CSV headers
COLUMN_ALIASES = {
    "business_name": ["business_name", "business name", "company", "company_name", "company name",
                      "name", "biz_name", "business", "firm", "shop", "shop_name", "store",
                      "store_name", "establishment", "org", "organization", "brand", "lead_name",
                      "lead name", "client", "client_name", "account", "account_name", "merchant"],
    "phone": ["phone", "phone_number", "phone number", "telephone", "tel", "contact_number",
              "mobile", "cell", "cell_phone", "contact", "number", "ph", "landline",
              "work_phone", "business_phone", "primary_phone", "fax", "dial"],
    "website": ["website", "url", "site", "web", "web_url", "homepage", "link",
                "website_url", "web_address", "domain", "webpage", "portal", "site_url",
                "company_url", "business_url", "www"],
    "address": ["address", "location", "full_address", "street", "street_address",
                "addr", "postal", "mailing", "office_address", "business_address",
                "place", "locality", "geo", "geo_address", "map_address"],
    "rating": ["rating", "stars", "avg_rating", "google_rating", "score", "star_rating",
               "average_rating", "overall_rating", "review_rating", "ratings"],
    "review_count": ["review_count", "reviews", "reviews_count", "num_reviews",
                     "total_reviews", "review count", "reviewcount", "no_of_reviews",
                     "number_of_reviews", "review_total", "feedback_count", "testimonials"],
    "city": ["city", "town", "location_city", "area", "region", "market", "suburb",
             "district", "metro", "municipality", "state", "county", "zip_city", "locale"],
}

# Fuzzy keyword fragments for partial matching (fallback if exact alias fails)
_FUZZY_KEYWORDS = {
    "business_name": ["business", "company", "name", "firm", "store", "shop", "brand", "client"],
    "phone": ["phone", "mobile", "cell", "tel", "contact", "dial"],
    "website": ["web", "url", "site", "domain", "link", "www"],
    "address": ["address", "street", "location", "addr", "postal"],
    "rating": ["rating", "star", "score"],
    "review_count": ["review", "feedback", "testimonial"],
    "city": ["city", "town", "region", "area", "market", "state"],
}


def _auto_map_columns(df_columns):
    """Auto-detect which uploaded columns map to standard columns.
    
    Strategy (in order):
    1. Exact alias match (normalised: lowercase, underscores → spaces)
    2. Fuzzy partial-word match — check if a keyword fragment appears in the column name
    3. Skip columns that can't be matched
    """
    mapping = {}
    used_std = set()  # prevent double-mapping to the same standard col
    df_cols_lower = {c: c.strip().lower().replace("_", " ") for c in df_columns}

    # Pass 1: exact alias match
    for std_col, aliases in COLUMN_ALIASES.items():
        alias_set = {a.lower().replace("_", " ") for a in aliases}
        for orig_col, lower_col in df_cols_lower.items():
            if orig_col in mapping:
                continue
            if lower_col in alias_set and std_col not in used_std:
                mapping[orig_col] = std_col
                used_std.add(std_col)
                break

    # Pass 2: fuzzy partial-word match (fallback for unmapped standard cols)
    for std_col, keywords in _FUZZY_KEYWORDS.items():
        if std_col in used_std:
            continue
        best_col = None
        best_score = 0
        for orig_col, lower_col in df_cols_lower.items():
            if orig_col in mapping:
                continue
            col_score = sum(1 for kw in keywords if kw in lower_col)
            if col_score > best_score:
                best_score = col_score
                best_col = orig_col
        if best_col and best_score > 0:
            mapping[best_col] = std_col
            used_std.add(std_col)

    return mapping


def _rule_score_row(row):
    """Rule-based scoring for a single row. Returns (score_0_to_7, label, reason)."""
    score = 0
    reasons = []

    # Review count scoring
    reviews = 0
    try:
        reviews = float(row.get("review_count", 0))
    except (ValueError, TypeError):
        pass
    if reviews <= 79:
        score += 3
        reasons.append(f"Low reviews ({int(reviews)})")
    elif reviews <= 150:
        score += 2
        reasons.append(f"Moderate reviews ({int(reviews)})")
    else:
        score += 1
        reasons.append(f"High reviews ({int(reviews)})")

    # Rating scoring
    rating = 0
    try:
        rating = float(row.get("rating", 0))
    except (ValueError, TypeError):
        pass
    if rating == 0:
        score += 2
        reasons.append("No rating found")
    elif rating < 4.5:
        score += 2
        reasons.append(f"Low rating ({rating})")
    elif rating < 4.8:
        score += 1
        reasons.append(f"Average rating ({rating})")
    else:
        reasons.append(f"Good rating ({rating})")

    # Website scoring
    website = str(row.get("website", "")).strip()
    if not website:
        score += 2
        reasons.append("No website")
    else:
        reasons.append("Has website")

    # Normalise to 0-10 scale (max raw = 7)
    ai_score = round(min(score / 7 * 10, 10), 1)

    if score >= 5:
        label = "HOT"
    elif score >= 3:
        label = "WARM"
    else:
        label = "COLD"

    reason = " · ".join(reasons)
    return ai_score, label, reason


def _ai_score_lead(row):
    """Use OpenAI to score a single lead. Returns (score_0_to_10, label, reason)."""
    try:
        prompt = (
            "You are an expert lead generation analyst for a digital marketing agency.\n"
            "Analyse this business and rate it as a lead opportunity.\n\n"
            f"Business Name: {row.get('business_name', 'N/A')}\n"
            f"Rating: {row.get('rating', 'N/A')}\n"
            f"Review Count: {row.get('review_count', 'N/A')}\n"
            f"Website: {row.get('website', 'None')}\n"
            f"City: {row.get('city', 'N/A')}\n"
            f"Address: {row.get('address', 'N/A')}\n\n"
            "Reply in EXACTLY this format (3 lines, nothing else):\n"
            "SCORE: <number 0-10>\n"
            "LABEL: <HOT or WARM or COLD>\n"
            "REASON: <one short sentence explaining why>"
        )
        response = openai_chat(
            messages=[{"role": "user", "content": prompt}],
            model="gpt-4.1-mini",
            max_tokens=100,
            temperature=0.3,
        )
        text = response.choices[0].message.content.strip()
        lines = text.split("\n")
        ai_score = 5.0
        label = "WARM"
        reason = "AI analysis"
        for line in lines:
            if line.upper().startswith("SCORE:"):
                try:
                    ai_score = float(line.split(":", 1)[1].strip())
                    ai_score = max(0, min(10, ai_score))
                except ValueError:
                    pass
            elif line.upper().startswith("LABEL:"):
                lbl = line.split(":", 1)[1].strip().upper()
                if lbl in ("HOT", "WARM", "COLD"):
                    label = lbl
            elif line.upper().startswith("REASON:"):
                reason = line.split(":", 1)[1].strip()
        return ai_score, label, reason
    except Exception as e:
        # Fallback to rules if AI fails
        return _rule_score_row(row)


def _classify_imported(df, use_ai=False):
    """Score and classify imported leads.
    
    use_ai=False → fast rule-based scoring
    use_ai=True  → AI scoring via OpenAI (with rule fallback)
    """
    scores = []
    labels = []
    reasons = []

    scorer = _ai_score_lead if use_ai else _rule_score_row

    for _, row in df.iterrows():
        ai_score, label, reason = scorer(row)
        scores.append(ai_score)
        labels.append(label)
        reasons.append(reason)

    df["import_score"] = scores
    df["prospect_label"] = labels
    df["ai_reason"] = reasons
    return df


@app.route("/import-leads")
@login_required
def page_import():
    imported_data = _load_csv(IMPORTED_CSV)
    chart = {"hot": 0, "warm": 0, "cold": 0}
    if imported_data:
        for r in imported_data:
            lbl = r.get("prospect_label", "")
            if lbl == "HOT": chart["hot"] += 1
            elif lbl == "WARM": chart["warm"] += 1
            elif lbl == "COLD": chart["cold"] += 1
    return render_template(
        "import_leads.html", active_page="import",
        imported_data=imported_data, chart=chart,
    )


@app.route("/import-leads/preview", methods=["POST"])
@login_required
@limiter.limit("30 per hour")
def import_preview():
    """Parse uploaded file and return columns + sample for mapping UI."""
    if "file" not in request.files:
        return jsonify({"status": "error", "msg": "No file uploaded."})

    file = request.files["file"]
    if not file.filename:
        return jsonify({"status": "error", "msg": "No file selected."})

    # Sanitize filename and validate extension
    safe_name = secure_filename(file.filename)
    fname = safe_name.lower()
    ext = os.path.splitext(fname)[1]
    if ext not in ALLOWED_UPLOAD_EXTENSIONS:
        return jsonify({"status": "error", "msg": "Only CSV and Excel files (.csv, .xlsx, .xls) are supported."})

    try:
        if ext == ".csv":
            df = pd.read_csv(file)
        else:
            df = pd.read_excel(file)
    except Exception:
        return jsonify({"status": "error", "msg": "Failed to parse file. Ensure it is a valid CSV or Excel file."})

    if len(df) == 0:
        return jsonify({"status": "error", "msg": "File is empty."})

    # Auto-map columns
    auto_map = _auto_map_columns(df.columns)

    # Save raw uploaded file temporarily
    temp_path = os.path.join(OUTPUT_DIR, "_import_temp.csv")
    df.to_csv(temp_path, index=False)

    return jsonify({
        "status": "ok",
        "columns": list(df.columns),
        "auto_map": auto_map,
        "row_count": len(df),
        "sample": df.head(5).fillna("").to_dict(orient="records"),
    })


@app.route("/import-leads/process", methods=["POST"])
@login_required
def import_process():
    """Apply user column mapping, score, classify, and save."""
    data = request.get_json()
    col_map = data.get("mapping", {})  # { uploaded_col: standard_col }

    temp_path = os.path.join(OUTPUT_DIR, "_import_temp.csv")
    if not os.path.exists(temp_path):
        return jsonify({"status": "error", "msg": "No uploaded file found. Please upload again."})

    df = pd.read_csv(temp_path)

    # Rename columns per user mapping
    rename_map = {}
    for orig, std in col_map.items():
        if std and orig in df.columns:
            rename_map[orig] = std
    df = df.rename(columns=rename_map)

    # Fill missing standard columns with empty
    for std_col in STANDARD_COLS:
        if std_col not in df.columns:
            df[std_col] = ""

    # Clean numeric columns
    for num_col in ["rating", "review_count"]:
        df[num_col] = pd.to_numeric(df[num_col], errors="coerce").fillna(0)

    # Fill NaN in string columns
    for col in df.columns:
        if pd.api.types.is_numeric_dtype(df[col]):
            df[col] = df[col].fillna(0)
        else:
            df[col] = df[col].fillna("")

    # Score and classify (check if user requested AI mode)
    use_ai = data.get("use_ai", False)
    df = _classify_imported(df, use_ai=use_ai)

    # Save
    _save_csv(IMPORTED_CSV, df)

    # Clean up temp
    if os.path.exists(temp_path):
        os.remove(temp_path)

    hot = int((df["prospect_label"] == "HOT").sum())
    warm = int((df["prospect_label"] == "WARM").sum())
    cold = int((df["prospect_label"] == "COLD").sum())

    return jsonify({
        "status": "ok",
        "msg": f"Processed {len(df)} leads — HOT: {hot} | WARM: {warm} | COLD: {cold}",
        "total": len(df), "hot": hot, "warm": warm, "cold": cold,
    })


@app.route("/import-leads/push-to-pipeline", methods=["POST"])
@login_required
def import_push_to_pipeline():
    """Feed imported leads into the main tool pipeline at step2 (scored) stage."""
    if not _csv_exists(IMPORTED_CSV):
        return jsonify({"status": "error", "msg": "No imported leads found. Upload and classify first."})

    df = _load_df(IMPORTED_CSV)
    if df is None or len(df) == 0:
        return jsonify({"status": "error", "msg": "Imported leads file is empty."})

    # Map import_score → review_score so the pipeline recognises it
    if "import_score" in df.columns:
        df["review_score"] = df["import_score"]
    elif "review_score" not in df.columns:
        df["review_score"] = 5

    # Ensure all columns that Tool 1 normally produces exist
    for col in ["business_name", "phone", "website", "address", "rating",
                 "review_count", "place_id", "city", "prospect_label"]:
        if col not in df.columns:
            df[col] = ""

    # Ensure numeric columns are clean
    for num_col in ["rating", "review_count", "review_score"]:
        df[num_col] = pd.to_numeric(df[num_col], errors="coerce").fillna(0)

    # Save as step2_scored.csv — this is where Tool 3 picks up
    _save_csv(SCORED_CSV, df)

    # Clear all downstream pipeline files so stale data from a previous run
    # doesn't bleed through — each tool will regenerate its own output
    for downstream in [ADS_CSV, WEBSITE_CSV, HOT_CSV, WARM_CSV,
                       CONTACTS_CSV, GBP_CSV, COMPETITOR_CSV,
                       CALCULATED_CSV, EMAILS_CSV]:
        key = _CSV_KEY_MAP.get(downstream)
        if key:
            try:
                with _db_ctx():
                    ToolResult.query.filter_by(key=key).delete()
                    db.session.commit()
            except Exception:
                pass
        if os.path.exists(downstream):
            os.remove(downstream)

    hot = int((df["prospect_label"] == "HOT").sum())
    warm = int((df["prospect_label"] == "WARM").sum())
    cold = int((df["prospect_label"] == "COLD").sum())

    return jsonify({
        "status": "ok",
        "msg": f"Pushed {len(df)} leads into pipeline — HOT: {hot} | WARM: {warm} | COLD: {cold}. You can now run Tools 3–10 from the sidebar.",
        "total": len(df), "hot": hot, "warm": warm, "cold": cold,
    })


@app.route("/import-leads/run-pipeline", methods=["POST"])
@login_required
@limiter.limit("5 per hour")
def import_run_pipeline():
    """Push imported leads into the pipeline AND run Tools 3–10 automatically."""
    if job_status["pipeline"] == "running":
        return jsonify({"status": "running", "msg": "Pipeline is already running."})

    if not _csv_exists(IMPORTED_CSV):
        return jsonify({"status": "error", "msg": "No imported leads found. Upload and classify first."})

    df = _load_df(IMPORTED_CSV)
    if df is None or len(df) == 0:
        return jsonify({"status": "error", "msg": "Imported leads file is empty."})

    # --- Push to step2 (same logic as push-to-pipeline) ---
    if "import_score" in df.columns:
        df["review_score"] = df["import_score"]
    elif "review_score" not in df.columns:
        df["review_score"] = 5

    for col in ["business_name", "phone", "website", "address", "rating",
                 "review_count", "place_id", "city", "prospect_label"]:
        if col not in df.columns:
            df[col] = ""

    for num_col in ["rating", "review_count", "review_score"]:
        df[num_col] = pd.to_numeric(df[num_col], errors="coerce").fillna(0)

    _save_csv(SCORED_CSV, df)

    # Clear downstream
    for downstream in [ADS_CSV, WEBSITE_CSV, HOT_CSV, WARM_CSV,
                       CONTACTS_CSV, GBP_CSV, COMPETITOR_CSV,
                       CALCULATED_CSV, EMAILS_CSV]:
        key = _CSV_KEY_MAP.get(downstream)
        if key:
            try:
                with _db_ctx():
                    ToolResult.query.filter_by(key=key).delete()
                    db.session.commit()
            except Exception:
                pass
        if os.path.exists(downstream):
            os.remove(downstream)

    # Start pipeline in background thread (tools 3-10)
    thread = threading.Thread(target=_run_import_pipeline)
    thread.start()
    return jsonify({"status": "started", "msg": "Full pipeline started on imported leads."})


def _run_import_pipeline():
    """Run tools 3–10 sequentially on imported data that was pushed to step2."""
    job_status["pipeline"] = "running"
    job_status["pipeline_msg"] = "Starting import pipeline (Tools 3–10)..."

    tools = [
        ("tool3", "Tool 3 — Ads Checker", run_tool3),
        ("tool4", "Tool 4 — Website Checker", run_tool4),
        ("tool5", "Tool 5 — Contact Finder", run_tool5),
        ("tool6", "Tool 6 — GBP Analyser", run_tool6),
        ("tool7", "Tool 7 — Competitor Intel", run_tool7),
        ("tool8", "Tool 8 — Value Calculator", run_tool8),
        ("tool9", "Tool 9 — Email Personaliser", run_tool9),
        ("tool10", "Tool 10 — PDF Generator", run_tool10),
    ]
    errors = []
    try:
        with app.app_context():
            for i, (key, label, func) in enumerate(tools):
                job_status["pipeline_msg"] = f"[{i + 1}/8] Running {label}..."
                try:
                    func()
                    if job_status[key] == "error":
                        errors.append(f"{label}: {job_status[key + '_msg']}")
                except Exception as e:
                    logger.error("Pipeline tool %s failed: %s", label, e, exc_info=True)
                    job_status[key] = "error"
                    job_status[key + "_msg"] = str(e)
                    errors.append(f"{label}: {e}")

            # Build summary
            summary_parts = []
            if _csv_exists(SCORED_CSV):
                _df = _load_df(SCORED_CSV)
                if _df is not None:
                    summary_parts.append(f"Total leads: {len(_df)}")
            if _csv_exists(HOT_CSV):
                _df = _load_df(HOT_CSV)
                if _df is not None:
                    summary_parts.append(f"HOT: {len(_df)}")
            if _csv_exists(EMAILS_CSV):
                _df = _load_df(EMAILS_CSV)
                if _df is not None:
                    summary_parts.append(f"Emails: {len(_df)}")
            if os.path.exists(AUDITS_DIR):
                pdfs = [f for f in os.listdir(AUDITS_DIR) if f.endswith(".pdf")]
                if pdfs:
                    summary_parts.append(f"PDFs: {len(pdfs)}")

            msg = "Import pipeline complete! " + " | ".join(summary_parts)
            if errors:
                msg += f" | {len(errors)} error(s): " + "; ".join(errors)
    except Exception as e:
        logger.error("Import pipeline crashed: %s", e, exc_info=True)
        msg = f"Pipeline crashed: {e}"
        if errors:
            msg += f" | Previous errors: " + "; ".join(errors)

    job_status["pipeline"] = "done"
    job_status["pipeline_msg"] = msg


@app.route("/import-leads/clear", methods=["POST"])
@login_required
def import_clear():
    """Remove imported leads data."""
    for f in [IMPORTED_CSV, os.path.join(OUTPUT_DIR, "_import_temp.csv")]:
        if os.path.exists(f):
            os.remove(f)
    # Also clear from database
    try:
        ToolResult.query.filter_by(key="imported_leads").delete()
        db.session.commit()
    except Exception:
        pass
    return jsonify({"status": "ok", "msg": "Imported leads cleared."})


@app.route("/download/imported/<fmt>")
@login_required
def download_imported(fmt):
    if not _csv_exists(IMPORTED_CSV):
        return "No imported data found. Upload and process first.", 404
    df = _load_df(IMPORTED_CSV)
    if fmt == "csv":
        buf = io.BytesIO(df.to_csv(index=False).encode("utf-8"))
        return send_file(buf, as_attachment=True, download_name="imported_leads.csv", mimetype="text/csv")
    elif fmt == "excel":
        buf = io.BytesIO()
        df.to_excel(buf, index=False)
        buf.seek(0)
        return send_file(buf, as_attachment=True, download_name="imported_leads.xlsx",
                         mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
    return "Invalid format.", 400


@app.route("/download/imported/filtered/<label>")
@login_required
def download_imported_filtered(label):
    if not _csv_exists(IMPORTED_CSV):
        return "No imported data found.", 404
    df = _load_df(IMPORTED_CSV)
    label_upper = label.upper()
    if label_upper not in ("HOT", "WARM", "COLD"):
        return "Invalid label. Use hot, warm, or cold.", 400
    df = df[df["prospect_label"] == label_upper]
    if len(df) == 0:
        return f"No {label_upper} leads found.", 404
    filename = f"imported_{label_upper}.csv"
    buf = io.BytesIO(df.to_csv(index=False).encode("utf-8"))
    return send_file(buf, as_attachment=True, download_name=filename, mimetype="text/csv")


# ---------------------------------------------------------------------------
# Backup Routes (Admin Only) — Full ZIP backup: DB + CSVs + cities.txt
# ---------------------------------------------------------------------------
import shutil
import zipfile

BACKUP_DIR = os.path.join(BASE_DIR, "backups")
os.makedirs(BACKUP_DIR, exist_ok=True)


def _create_backup_zip(dest_path):
    """Create a ZIP containing users.db, output/*.csv, and cities.txt."""
    with zipfile.ZipFile(dest_path, "w", zipfile.ZIP_DEFLATED) as zf:
        # 1. Database
        if os.path.exists(DB_PATH):
            zf.write(DB_PATH, "instance/users.db")
        # 2. All CSV files in output/
        if os.path.isdir(OUTPUT_DIR):
            for fname in os.listdir(OUTPUT_DIR):
                if fname.lower().endswith((".csv", ".xlsx", ".xls")):
                    zf.write(os.path.join(OUTPUT_DIR, fname), f"output/{fname}")
        # 3. cities.txt
        if os.path.exists(CITIES_FILE):
            zf.write(CITIES_FILE, "cities.txt")


@app.route("/backup/download")
@login_required
@admin_required
def backup_download():
    """Download a full ZIP backup (DB + CSVs + config)."""
    import io as _io
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    zip_name = f"garageleadspro_backup_{timestamp}.zip"
    buf = _io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        if os.path.exists(DB_PATH):
            zf.write(DB_PATH, "instance/users.db")
        if os.path.isdir(OUTPUT_DIR):
            for fname in os.listdir(OUTPUT_DIR):
                if fname.lower().endswith((".csv", ".xlsx", ".xls")):
                    zf.write(os.path.join(OUTPUT_DIR, fname), f"output/{fname}")
        if os.path.exists(CITIES_FILE):
            zf.write(CITIES_FILE, "cities.txt")
    buf.seek(0)
    logger.info("Admin '%s' downloaded full backup", current_user.username)
    return send_file(buf, as_attachment=True, download_name=zip_name, mimetype="application/zip")


@app.route("/backup/create", methods=["POST"])
@login_required
@admin_required
def backup_create():
    """Create a timestamped ZIP backup on the server."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_name = f"garageleadspro_backup_{timestamp}.zip"
    backup_path = os.path.join(BACKUP_DIR, backup_name)
    _create_backup_zip(backup_path)
    size_kb = round(os.path.getsize(backup_path) / 1024, 1)
    logger.info("Admin '%s' created backup: %s", current_user.username, backup_name)
    return jsonify({"status": "ok", "msg": f"Backup created: {backup_name} ({size_kb} KB)"})


@app.route("/backup/list")
@login_required
@admin_required
def backup_list():
    """List all saved backups."""
    if not os.path.isdir(BACKUP_DIR):
        return jsonify({"backups": []})
    files = sorted(os.listdir(BACKUP_DIR), reverse=True)
    backups = []
    for f in files:
        if f.endswith(".zip"):
            path = os.path.join(BACKUP_DIR, f)
            size_kb = round(os.path.getsize(path) / 1024, 1)
            backups.append({"name": f, "size_kb": size_kb})
    return jsonify({"backups": backups})


def _restore_from_zip(zip_path):
    """Extract a backup ZIP, overwriting DB + output files + cities.txt."""
    with zipfile.ZipFile(zip_path, "r") as zf:
        names = zf.namelist()
        # Validate: only allow expected paths (security)
        for name in names:
            normed = os.path.normpath(name)
            if normed.startswith("..") or os.path.isabs(normed):
                raise ValueError(f"Unsafe path in ZIP: {name}")
        # 1. Restore database
        if "instance/users.db" in names:
            db_dest = DB_PATH
            os.makedirs(os.path.dirname(db_dest), exist_ok=True)
            with zf.open("instance/users.db") as src, open(db_dest, "wb") as dst:
                dst.write(src.read())
        # 2. Restore output files
        for name in names:
            if name.startswith("output/") and len(name) > len("output/"):
                fname = os.path.basename(name)
                if fname.lower().endswith((".csv", ".xlsx", ".xls")):
                    dest = os.path.join(OUTPUT_DIR, fname)
                    os.makedirs(OUTPUT_DIR, exist_ok=True)
                    with zf.open(name) as src, open(dest, "wb") as dst:
                        dst.write(src.read())
        # 3. Restore cities.txt
        if "cities.txt" in names:
            with zf.open("cities.txt") as src, open(CITIES_FILE, "wb") as dst:
                dst.write(src.read())


@app.route("/backup/restore", methods=["POST"])
@login_required
@admin_required
def backup_restore_upload():
    """Restore from an uploaded ZIP backup file."""
    if "file" not in request.files:
        return jsonify({"status": "error", "msg": "No file uploaded."}), 400
    file = request.files["file"]
    if not file.filename or not file.filename.lower().endswith(".zip"):
        return jsonify({"status": "error", "msg": "Only .zip backup files are accepted."}), 400
    # Save to temp location
    tmp_path = os.path.join(BACKUP_DIR, ".tmp_restore.zip")
    try:
        file.save(tmp_path)
        if not zipfile.is_zipfile(tmp_path):
            return jsonify({"status": "error", "msg": "Invalid ZIP file."}), 400
        _restore_from_zip(tmp_path)
        # Reconnect SQLAlchemy to pick up restored DB
        db.engine.dispose()
        logger.info("Admin '%s' restored from uploaded backup: %s", current_user.username, file.filename)
        return jsonify({"status": "ok", "msg": "Backup restored! Page will reload."})
    except ValueError as e:
        return jsonify({"status": "error", "msg": str(e)}), 400
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


@app.route("/backup/restore-server", methods=["POST"])
@login_required
@admin_required
def backup_restore_server():
    """Restore from a backup already on the server."""
    data = request.get_json(silent=True) or {}
    backup_name = data.get("name", "")
    if not backup_name or not backup_name.endswith(".zip"):
        return jsonify({"status": "error", "msg": "Invalid backup name."}), 400
    # Prevent path traversal
    safe_name = os.path.basename(backup_name)
    backup_path = os.path.join(BACKUP_DIR, safe_name)
    if not os.path.exists(backup_path):
        return jsonify({"status": "error", "msg": "Backup file not found."}), 404
    try:
        _restore_from_zip(backup_path)
        db.engine.dispose()
        logger.info("Admin '%s' restored from server backup: %s", current_user.username, safe_name)
        return jsonify({"status": "ok", "msg": f"Restored from {safe_name}! Page will reload."})
    except ValueError as e:
        return jsonify({"status": "error", "msg": str(e)}), 400

# ---------------------------------------------------------------------------
# Email Outreach — Send personalised emails via SMTP
# ---------------------------------------------------------------------------

OUTREACH_COOLDOWN_SECONDS = 300   # 5-minute cooldown between bulk sends
OUTREACH_DAILY_LIMIT = 80         # max emails per day (Zoho-safe)

# Warm-up schedule: day_number -> max emails allowed
_WARMUP_SCHEDULE = {1: 5, 2: 10, 3: 20, 4: 30, 5: 50, 6: 60, 7: 80}

_SUBJECT_TEMPLATES = [
    "Quick question about {business}",
    "Helping {business} get more calls",
    "Noticed something about {business}",
    "Idea for {business}'s Google presence",
    "{business} — quick growth tip",
]


def _get_outreach_cooldown_remaining():
    """Return seconds remaining in cooldown, or 0 if cooldown expired."""
    last_ts = _get_setting("outreach_last_bulk_ts", "")
    if not last_ts:
        return 0
    try:
        last_dt = datetime.fromisoformat(last_ts)
        elapsed = (datetime.utcnow() - last_dt).total_seconds()
        remaining = OUTREACH_COOLDOWN_SECONDS - elapsed
        return max(0, int(remaining))
    except Exception:
        return 0


def _get_today_email_count():
    """Count emails sent today (UTC) from DB settings."""
    today_str = datetime.utcnow().strftime("%Y-%m-%d")
    count_str = _get_setting(f"emails_sent_{today_str}", "0")
    try:
        return int(count_str)
    except ValueError:
        return 0


def _increment_today_email_count(n=1):
    """Add n to today's email counter."""
    today_str = datetime.utcnow().strftime("%Y-%m-%d")
    current = _get_today_email_count()
    _set_setting(f"emails_sent_{today_str}", str(current + n))


def _get_warmup_limit():
    """Return max emails allowed based on how many days account has been sending."""
    first_send = _get_setting("outreach_first_send_date", "")
    if not first_send:
        return _WARMUP_SCHEDULE.get(1, 5)
    try:
        first_dt = datetime.fromisoformat(first_send).date()
        day_num = (datetime.utcnow().date() - first_dt).days + 1
        # Find the highest matching day in schedule
        limit = 5
        for d, lim in sorted(_WARMUP_SCHEDULE.items()):
            if day_num >= d:
                limit = lim
        return limit
    except Exception:
        return 5


def _vary_subject(business_name):
    """Return a randomly varied email subject line."""
    template = random.choice(_SUBJECT_TEMPLATES)
    return template.format(business=business_name)


def _send_single_email(recipient_email, subject, body):
    """Send one email via SMTP. Returns (success: bool, error_msg: str)."""
    if not SMTP_HOST or not SMTP_PASSWORD or not YOUR_EMAIL:
        return False, "SMTP not configured. Go to Settings → SMTP Settings."
    try:
        msg = MIMEMultipart("alternative")
        msg["From"] = YOUR_EMAIL
        msg["To"] = recipient_email
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain", "utf-8"))
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as server:
            server.starttls()
            server.login(YOUR_EMAIL, SMTP_PASSWORD)
            server.send_message(msg)
        return True, ""
    except smtplib.SMTPAuthenticationError:
        return False, "SMTP authentication failed. Check your email/password in Settings."
    except Exception as e:
        return False, str(e)


@app.route("/outreach/send_single", methods=["POST"])
@login_required
@limiter.limit("30 per minute")
def outreach_send_single():
    """Send a single customised email to one recipient."""
    data = request.get_json(silent=True) or {}
    recipient = data.get("recipient_email", "").strip()
    subject = data.get("subject", "").strip()
    body = data.get("body", "").strip()

    if not recipient or not subject or not body:
        return jsonify({"status": "error", "msg": "Recipient email, subject, and body are required."})
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", recipient):
        return jsonify({"status": "error", "msg": "Invalid email address."})

    ok, err = _send_single_email(recipient, subject, body)
    if ok:
        logger.info("Outreach email sent to %s by %s", recipient, current_user.username)
        return jsonify({"status": "ok", "msg": f"Email sent to {recipient}!"})
    else:
        return jsonify({"status": "error", "msg": err})


@app.route("/outreach/send_bulk", methods=["POST"])
@login_required
@limiter.limit("5 per hour")
def outreach_send_bulk():
    """Send emails to all HOT and/or WARM leads that have email addresses."""
    data = request.get_json(silent=True) or {}
    include_hot = data.get("include_hot", True)
    include_warm = data.get("include_warm", True)
    batch_size = min(int(data.get("batch_size", 10)), 50)  # cap at 50
    send_mode = data.get("send_mode", "safe")  # "safe" or "fast"
    max_emails = min(int(data.get("max_emails", 30)), 100)  # cap at 100

    if not include_hot and not include_warm:
        return jsonify({"status": "error", "msg": "Select at least HOT or WARM."})

    if not SMTP_HOST or not SMTP_PASSWORD or not YOUR_EMAIL:
        return jsonify({"status": "error", "msg": "SMTP not configured. Go to Settings → SMTP Settings."})

    # --- COOLDOWN PROTECTION ---
    cooldown_left = _get_outreach_cooldown_remaining()
    if cooldown_left > 0:
        mins = cooldown_left // 60
        secs = cooldown_left % 60
        return jsonify({"status": "error", "msg": f"Cooldown active. Wait {mins}m {secs}s before sending again."})

    # --- DAILY LIMIT ---
    today_count = _get_today_email_count()
    if today_count >= OUTREACH_DAILY_LIMIT:
        return jsonify({"status": "error", "msg": f"Daily limit reached ({today_count}/{OUTREACH_DAILY_LIMIT} emails sent today). Try again tomorrow."})

    # --- WARM-UP LIMIT ---
    warmup_limit = _get_warmup_limit()
    remaining_today = min(OUTREACH_DAILY_LIMIT - today_count, warmup_limit - today_count)
    if remaining_today <= 0:
        return jsonify({"status": "error", "msg": f"Warm-up limit reached ({today_count} sent today, warm-up allows {warmup_limit}). Send more tomorrow as your reputation builds."})
    max_emails = min(max_emails, remaining_today)

    # Load emails data and calculated data to merge
    emails_df = _load_df(EMAILS_CSV)
    calc_df = _load_df(CALCULATED_CSV)

    if emails_df is None or emails_df.empty:
        return jsonify({"status": "error", "msg": "No email templates found. Run Tool 9 first."})
    if calc_df is None or calc_df.empty:
        return jsonify({"status": "error", "msg": "No pipeline data found. Run Tool 8 first."})

    # Merge to get personal_email and prospect_label
    needed_cols = ["business_name"]
    if "personal_email" in calc_df.columns:
        needed_cols.append("personal_email")
    if "prospect_label" in calc_df.columns:
        needed_cols.append("prospect_label")
    merged = emails_df.merge(calc_df[needed_cols].drop_duplicates("business_name"),
                             on="business_name", how="left")

    if "personal_email" not in merged.columns:
        return jsonify({"status": "error", "msg": "No email addresses found. Run Tool 5 (Contact Finder) first."})

    # Filter by prospect label
    labels = []
    if include_hot:
        labels.append("HOT")
    if include_warm:
        labels.append("WARM")
    if "prospect_label" in merged.columns:
        merged = merged[merged["prospect_label"].isin(labels)]

    # Only rows with valid email addresses
    merged = merged[merged["personal_email"].notna() & (merged["personal_email"] != "")]

    if merged.empty:
        return jsonify({"status": "error", "msg": f"No {'/ '.join(labels)} leads with email addresses found."})

    # --- SMART PRIORITY: HOT first, then WARM ---
    if "prospect_label" in merged.columns:
        label_order = {"HOT": 0, "WARM": 1}
        merged = merged.copy()
        merged["_sort"] = merged["prospect_label"].map(label_order).fillna(2)
        merged = merged.sort_values("_sort").drop(columns=["_sort"])

    # Limit number of emails
    merged = merged.head(max_emails)

    # Record cooldown timestamp BEFORE starting
    _set_setting("outreach_last_bulk_ts", datetime.utcnow().isoformat())
    # Record first-ever send date for warm-up tracking
    if not _get_setting("outreach_first_send_date", ""):
        _set_setting("outreach_first_send_date", datetime.utcnow().isoformat())

    # Start bulk send in background thread
    send_list = []
    for _, row in merged.iterrows():
        full_email = row.get("full_email", "")
        biz_name = row.get("business_name", "")
        recipient = row.get("personal_email", "")
        # --- AUTO SUBJECT VARIATION ---
        subject = _vary_subject(biz_name)
        # Extract body from full_email (remove the "Subject: ..." line)
        body_lines = full_email.split("\n")
        body = "\n".join(line for line in body_lines if not line.startswith("Subject:")).strip()
        # Check if already sent (duplicate prevention)
        already_sent = bool(_get_setting(f"sent_{recipient}_{biz_name}", ""))
        send_list.append({
            "business_name": biz_name,
            "recipient": recipient,
            "subject": subject,
            "body": body,
            "already_sent": already_sent,
            "prospect_label": row.get("prospect_label", ""),
            "status": "pending",
        })

    job_status["outreach"] = "running"
    job_status["outreach_msg"] = f"Sending 0/{len(send_list)} emails..."
    thread = threading.Thread(target=_bulk_send_emails, args=(send_list, batch_size, send_mode))
    thread.start()

    mode_label = "Safe" if send_mode == "safe" else "Fast"
    return jsonify({"status": "started", "msg": f"Sending {len(send_list)} emails ({mode_label} mode, batches of {batch_size})...", "total": len(send_list)})


def _bulk_send_emails(send_list, batch_size=10, send_mode="safe"):
    """Background thread: send emails in batches with smart delays."""
    sent = 0
    failed = 0
    skipped = 0
    retry_queue = []
    total = len(send_list)

    job_status["outreach_sent"] = 0
    job_status["outreach_total"] = total
    job_status["outreach_failed"] = 0
    job_status["outreach_skipped"] = 0

    for batch_start in range(0, total, batch_size):
        batch = send_list[batch_start:batch_start + batch_size]
        for item in batch:
            # Skip already-sent emails (duplicate prevention)
            if item.get("already_sent"):
                item["status"] = "skipped"
                skipped += 1
                job_status["outreach_skipped"] = skipped
                continue
            ok, err = _send_single_email(item["recipient"], item["subject"], item["body"])
            if ok:
                item["status"] = "sent"
                sent += 1
                job_status["outreach_sent"] = sent
                # Track sent status in DB
                try:
                    with _db_ctx():
                        _set_setting(f"sent_{item['recipient']}_{item['business_name']}", datetime.utcnow().isoformat())
                        _increment_today_email_count(1)
                except Exception:
                    pass
            else:
                item["status"] = "failed"
                failed += 1
                job_status["outreach_failed"] = failed
                retry_queue.append(item)
            pct = int(((sent + failed + skipped) / total) * 100)
            job_status["outreach_msg"] = f"Sending... {sent + failed + skipped}/{total} ({pct}%) — {sent} sent, {failed} failed, {skipped} skipped"
            # Delay between emails: safe mode = 5-12s random, fast mode = 2s fixed
            if send_mode == "safe":
                time.sleep(random.randint(5, 12))
            else:
                time.sleep(2)
        # Pause between batches (safe mode = 60s, fast mode = 5s)
        remaining = total - (batch_start + len(batch))
        if remaining > 0:
            pause = 60 if send_mode == "safe" else 5
            job_status["outreach_msg"] = f"Batch done ({sent} sent). Pausing {pause}s before next batch..."
            time.sleep(pause)

    # --- RETRY FAILED EMAILS (one attempt) ---
    retried = 0
    if retry_queue:
        job_status["outreach_msg"] = f"Retrying {len(retry_queue)} failed emails..."
        time.sleep(10)
        for item in retry_queue:
            ok, err = _send_single_email(item["recipient"], item["subject"], item["body"])
            if ok:
                item["status"] = "sent"
                sent += 1
                failed -= 1
                retried += 1
                job_status["outreach_sent"] = sent
                job_status["outreach_failed"] = failed
                try:
                    with _db_ctx():
                        _set_setting(f"sent_{item['recipient']}_{item['business_name']}", datetime.utcnow().isoformat())
                        _increment_today_email_count(1)
                except Exception:
                    pass
            if send_mode == "safe":
                time.sleep(random.randint(5, 12))
            else:
                time.sleep(2)

    job_status["outreach"] = "done"
    msg = f"Done! Sent {sent}/{total} emails."
    if failed:
        msg += f" {failed} failed."
    if skipped:
        msg += f" {skipped} already sent (skipped)."
    if retried:
        msg += f" {retried} recovered on retry."
    today_total = _get_today_email_count()
    msg += f" Today's total: {today_total}/{OUTREACH_DAILY_LIMIT}."
    job_status["outreach_msg"] = msg


@app.route("/outreach/status")
@login_required
@limiter.exempt
def outreach_status():
    total = job_status.get("outreach_total", 0)
    sent = job_status.get("outreach_sent", 0)
    failed = job_status.get("outreach_failed", 0)
    skipped = job_status.get("outreach_skipped", 0)
    progress = int(((sent + failed + skipped) / total) * 100) if total > 0 else 0
    return jsonify({
        "status": job_status.get("outreach", "idle"),
        "msg": job_status.get("outreach_msg", ""),
        "sent": sent,
        "total": total,
        "failed": failed,
        "skipped": skipped,
        "progress": progress,
        "daily_count": _get_today_email_count(),
        "daily_limit": OUTREACH_DAILY_LIMIT,
        "warmup_limit": _get_warmup_limit(),
        "cooldown_remaining": _get_outreach_cooldown_remaining(),
    })


@app.route("/outreach/preview", methods=["POST"])
@login_required
def outreach_preview():
    """Get list of leads that would receive bulk emails."""
    data = request.get_json(silent=True) or {}
    include_hot = data.get("include_hot", True)
    include_warm = data.get("include_warm", True)

    emails_df = _load_df(EMAILS_CSV)
    calc_df = _load_df(CALCULATED_CSV)

    if emails_df is None or emails_df.empty or calc_df is None or calc_df.empty:
        return jsonify({"status": "ok", "leads": [], "count": 0})

    needed_cols = ["business_name"]
    if "personal_email" in calc_df.columns:
        needed_cols.append("personal_email")
    if "prospect_label" in calc_df.columns:
        needed_cols.append("prospect_label")
    merged = emails_df.merge(calc_df[needed_cols].drop_duplicates("business_name"),
                             on="business_name", how="left")

    if "personal_email" not in merged.columns:
        return jsonify({"status": "ok", "leads": [], "count": 0})

    labels = []
    if include_hot:
        labels.append("HOT")
    if include_warm:
        labels.append("WARM")
    if "prospect_label" in merged.columns:
        merged = merged[merged["prospect_label"].isin(labels)]

    merged = merged[merged["personal_email"].notna() & (merged["personal_email"] != "")]

    leads = []
    for _, row in merged.iterrows():
        leads.append({
            "business_name": row.get("business_name", ""),
            "owner_name": row.get("owner_name", ""),
            "personal_email": row.get("personal_email", ""),
            "prospect_label": row.get("prospect_label", ""),
            "email_subject": row.get("email_subject", ""),
            "full_email": row.get("full_email", ""),
        })
    return jsonify({"status": "ok", "leads": leads, "count": len(leads)})

if __name__ == "__main__":
    # Set debug=False for production; use gunicorn in deployed environments
    app.run(debug=not IS_PRODUCTION, port=5000)
