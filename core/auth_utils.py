"""Authentication utilities: JWT, decorators, rate limiting, audit logging."""
from __future__ import annotations
import jwt, time, functools, threading
from datetime import datetime, timedelta, timezone
from flask import request, jsonify, redirect, url_for, g
from flask_bcrypt import Bcrypt

_bcrypt = Bcrypt()

# ── Constants ──────────────────────────────────────────────────────────────────

TOKEN_COOKIE    = "_zg_auth"
TOKEN_EXPIRE_H  = 24          # hours until JWT expires
RATE_LIMIT_MAX  = 5           # max failed logins
RATE_LIMIT_WIN  = 15 * 60     # window in seconds (15 min)

# All platform modules available for permission assignment
PLATFORM_MODULES = [
    # ZeekGlare core
    {"id": "domain",      "label": "Domain Scanner",      "app": "zeekglare", "icon": "🌐"},
    {"id": "ports",       "label": "Port Scanner",        "app": "zeekglare", "icon": "🔍"},
    {"id": "crawler",     "label": "Web Crawler",         "app": "zeekglare", "icon": "🕷️"},
    {"id": "paramhawk",   "label": "ParamHawk",           "app": "zeekglare", "icon": "⚡"},
    {"id": "threatblitz", "label": "ThreatBlitz",         "app": "zeekglare", "icon": "💣"},
    {"id": "fuzzer",      "label": "PathStorm / Fuzzer",  "app": "zeekglare", "icon": "🪓"},
    {"id": "wpscan",      "label": "WPScan",              "app": "zeekglare", "icon": "📝"},
    {"id": "asn",         "label": "ASN Intelligence",    "app": "zeekglare", "icon": "🏢"},
    {"id": "dns",         "label": "DNS Intelligence",    "app": "zeekglare", "icon": "📡"},
    {"id": "osint",       "label": "OSINT Tools",         "app": "zeekglare", "icon": "🔎"},
    {"id": "recon",       "label": "ReconFTW",            "app": "zeekglare", "icon": "🤖"},
    {"id": "oneforall",   "label": "OneForAll",           "app": "zeekglare", "icon": "🌐"},
    {"id": "jsanalysis",  "label": "JS Analysis",         "app": "zeekglare", "icon": "⚙️"},
    {"id": "ipmapper",    "label": "IP Mapper",           "app": "zeekglare", "icon": "🗺️"},
    {"id": "caido",       "label": "Caido Integration",   "app": "zeekglare", "icon": "🔌"},
    {"id": "burp",        "label": "Burp Suite",          "app": "zeekglare", "icon": "🔌"},
    {"id": "workflow",    "label": "Workflow Builder",    "app": "zeekglare", "icon": "🔄"},
    {"id": "scheduler",   "label": "Scheduler",           "app": "zeekglare", "icon": "📅"},
    {"id": "feed",        "label": "Intelligence Feed",   "app": "zeekglare", "icon": "📰"},
    {"id": "export",      "label": "Export & Reports",    "app": "zeekglare", "icon": "📊"},
    {"id": "ai",          "label": "AI Analysis",         "app": "zeekglare", "icon": "🧠"},
    {"id": "chat",        "label": "AI Chat",             "app": "zeekglare", "icon": "💬"},
    # Sub-dashboards
    {"id": "xploiter",    "label": "Xpl03tEr Dashboard",  "app": "xploiter",  "icon": "⚡"},
    {"id": "misc",        "label": "Misc Tools Dashboard","app": "misc",      "icon": "🛠️"},
    # Xploiter vulnerability categories
    {"id": "xss",         "label": "XSS Tools",           "app": "xploiter",  "icon": "⚡"},
    {"id": "sqli",        "label": "SQLi Tools",          "app": "xploiter",  "icon": "💉"},
    {"id": "ssrf",        "label": "SSRF Tools",          "app": "xploiter",  "icon": "🔄"},
    {"id": "cmdi",        "label": "Cmd Injection",       "app": "xploiter",  "icon": "💀"},
    {"id": "lfi",         "label": "LFI / Traversal",     "app": "xploiter",  "icon": "📂"},
    {"id": "xxe",         "label": "XXE Tools",           "app": "xploiter",  "icon": "📄"},
    {"id": "ssti",        "label": "SSTI Tools",          "app": "xploiter",  "icon": "🧩"},
    {"id": "cors",        "label": "CORS Tools",          "app": "xploiter",  "icon": "🌐"},
]

DEFAULT_USER_MODULES = [
    "domain", "ports", "crawler", "paramhawk", "threatblitz",
    "fuzzer", "wpscan", "asn", "dns", "osint", "jsanalysis",
    "ipmapper", "oneforall", "export", "ai", "chat", "xploiter", "misc",
    "xss", "sqli", "ssrf", "cmdi", "lfi",
]

# ── Password helpers ────────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    return _bcrypt.generate_password_hash(password).decode()


def check_password(password: str, hashed: str) -> bool:
    return _bcrypt.check_password_hash(hashed, password)


# ── JWT helpers ─────────────────────────────────────────────────────────────

def _secret() -> str:
    from core.db import get_secret_key
    return get_secret_key()


def generate_token(user: "User", expire_hours: int = TOKEN_EXPIRE_H) -> str:  # noqa
    payload = {
        "sub":      str(user.id),
        "username": user.username,
        "role":     user.role,
        "iat":      datetime.now(timezone.utc),
        "exp":      datetime.now(timezone.utc) + timedelta(hours=expire_hours),
    }
    return jwt.encode(payload, _secret(), algorithm="HS256")


def decode_token(token: str) -> dict | None:
    try:
        return jwt.decode(token, _secret(), algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def get_token_from_request() -> str | None:
    """Extract JWT from cookie, Authorization header, or query param."""
    # 1. httpOnly cookie (main app)
    t = request.cookies.get(TOKEN_COOKIE)
    if t:
        return t
    # 2. Authorization: Bearer TOKEN (API calls from sub-apps)
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:]
    return None


# ── Rate limiting ────────────────────────────────────────────────────────────

def is_rate_limited(ip: str) -> bool:
    """True if this IP has too many failed logins in the current window."""
    from core.models import LoginAttempt
    from core.db import db
    cutoff = datetime.utcnow() - timedelta(seconds=RATE_LIMIT_WIN)
    fails = LoginAttempt.query.filter(
        LoginAttempt.ip_address == ip,
        LoginAttempt.success == False,  # noqa
        LoginAttempt.timestamp >= cutoff,
    ).count()
    return fails >= RATE_LIMIT_MAX


def record_attempt(ip: str, username: str, success: bool):
    from core.models import LoginAttempt
    from core.db import db
    db.session.add(LoginAttempt(ip_address=ip, username=username, success=success))
    db.session.commit()


# ── Simple in-memory API rate limiter ────────────────────────────────────────

_API_LIMITS = {}
_API_LIMITS_LOCK = threading.Lock()


def rate_limit(max_requests: int = 10, window_seconds: int = 60):
    """Decorator that limits requests per IP per endpoint in memory."""
    def decorator(f):
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            ip = request.remote_addr or "unknown"
            key = f"{ip}:{request.endpoint}"
            now = time.time()
            with _API_LIMITS_LOCK:
                bucket = _API_LIMITS.get(key, [])
                # prune old entries
                bucket = [t for t in bucket if now - t < window_seconds]
                if len(bucket) >= max_requests:
                    return jsonify({"error": "Rate limit exceeded. Please slow down."}), 429
                bucket.append(now)
                _API_LIMITS[key] = bucket
            return f(*args, **kwargs)
        return wrapper
    return decorator


# ── Audit logging ────────────────────────────────────────────────────────────

def audit(action: str, details: str = "", user_id: int | None = None, username: str = ""):
    from core.models import AuditLog
    from core.db import db
    ip = request.remote_addr if request else "—"
    if not user_id and hasattr(g, "current_user") and g.current_user:
        user_id  = g.current_user.id
        username = g.current_user.username
    db.session.add(AuditLog(
        user_id=user_id, username=username,
        action=action, details=details, ip_address=ip,
    ))
    db.session.commit()


# ── Load current user ────────────────────────────────────────────────────────

def load_user_from_token(token: str) -> "User | None":  # noqa
    payload = decode_token(token)
    if not payload:
        return None
    from core.models import User
    user = User.query.get(int(payload["sub"]))
    if user and user.status == "active":
        return user
    return None


# ── Decorators ───────────────────────────────────────────────────────────────

def login_required(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        token = get_token_from_request()
        user  = load_user_from_token(token) if token else None
        if not user:
            if request.is_json or request.path.startswith("/api/"):
                return jsonify({"error": "Authentication required", "login_url": "/auth/login"}), 401
            return redirect(f"/auth/login?next={request.path}")
        g.current_user = user
        # Refresh session last_seen
        _touch_session(user)
        return f(*args, **kwargs)
    return wrapper


def admin_required(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        token = get_token_from_request()
        user  = load_user_from_token(token) if token else None
        if not user:
            if request.is_json or request.path.startswith("/api/"):
                return jsonify({"error": "Authentication required"}), 401
            return redirect(f"/auth/login?next={request.path}")
        if user.role != "admin":
            if request.is_json or request.path.startswith("/api/"):
                return jsonify({"error": "Admin access required"}), 403
            return redirect("/")
        g.current_user = user
        return f(*args, **kwargs)
    return wrapper


def module_required(module_id: str):
    """Decorator that checks the user has permission for a specific module."""
    def decorator(f):
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            token = get_token_from_request()
            user  = load_user_from_token(token) if token else None
            if not user:
                return jsonify({"error": "Authentication required"}), 401
            g.current_user = user
            if user.role == "admin":
                return f(*args, **kwargs)
            from core.models import UserToolPermission
            perm = UserToolPermission.query.filter_by(
                user_id=user.id, module_id=module_id, enabled=True
            ).first()
            if not perm:
                return jsonify({"error": f"Access denied: '{module_id}' is not enabled for your account"}), 403
            return f(*args, **kwargs)
        return wrapper
    return decorator


def _touch_session(user):
    """Update last_seen on the active session for the current request."""
    from core.models import ActiveSession
    from core.db import db
    sess = ActiveSession.query.filter_by(
        user_id=user.id,
        ip_address=request.remote_addr,
    ).first()
    if sess:
        sess.last_seen = datetime.utcnow()
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()


def create_session(user, app_name: str = "zeekglare"):
    """Record a new active session in the DB."""
    from core.models import ActiveSession
    from core.db import db
    # Remove old session for same user+ip+app
    ActiveSession.query.filter_by(
        user_id=user.id, ip_address=request.remote_addr, app_name=app_name
    ).delete()
    db.session.add(ActiveSession(
        user_id=user.id,
        username=user.username,
        ip_address=request.remote_addr,
        user_agent=request.user_agent.string[:256] if request.user_agent else "",
        app_name=app_name,
    ))
    db.session.commit()


def delete_session(user_id: int, ip: str):
    from core.models import ActiveSession
    from core.db import db
    ActiveSession.query.filter_by(user_id=user_id, ip_address=ip).delete()
    db.session.commit()


def grant_default_permissions(user):
    """Grant a new user the default set of module permissions."""
    from core.models import UserToolPermission
    from core.db import db
    for mid in DEFAULT_USER_MODULES:
        db.session.add(UserToolPermission(user_id=user.id, module_id=mid, enabled=True))
    db.session.commit()


def get_user_modules(user) -> set:
    """Return set of enabled module IDs for a user (admin gets all)."""
    if user.role == "admin":
        return {m["id"] for m in PLATFORM_MODULES}
    from core.models import UserToolPermission
    return {p.module_id for p in user.permissions.filter_by(enabled=True)}
