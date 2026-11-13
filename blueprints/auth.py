"""Authentication blueprint — login, logout, register, token exchange."""
import json, time, threading, urllib.request, secrets, os, smtplib, pathlib, re
from email.mime.text import MIMEText
from flask import (Blueprint, request, jsonify, render_template,
                   redirect, make_response, g, url_for)
from datetime import datetime

from core.db import db
from core.models import User, UserToolPermission
from core.auth_utils import (
    hash_password, check_password, generate_token, decode_token,
    get_token_from_request, load_user_from_token,
    is_rate_limited, record_attempt, audit,
    create_session, delete_session, grant_default_permissions,
    get_user_modules, TOKEN_COOKIE, TOKEN_EXPIRE_H,
)

def _validate_password(password: str) -> str:
    """Return error message if password doesn't meet complexity, else empty string."""
    if not password or len(password) < 8:
        return "Password must be at least 8 characters."
    if not re.search(r'[A-Z]', password):
        return "Password must contain at least one uppercase letter."
    if not re.search(r'[a-z]', password):
        return "Password must contain at least one lowercase letter."
    if not re.search(r'\d', password):
        return "Password must contain at least one digit."
    if not re.search(r'[^A-Za-z0-9]', password):
        return "Password must contain at least one special character."
    return ""


auth_bp = Blueprint("auth", __name__)


# ── Login page ───────────────────────────────────────────────────────────────

@auth_bp.route("/auth/login", methods=["GET"])
def login_page():
    # Already logged in → redirect home
    token = get_token_from_request()
    if load_user_from_token(token):
        return redirect(request.args.get("next") or "/")
    return render_template("login.html", next=request.args.get("next", "/"))


@auth_bp.route("/auth/login", methods=["POST"])
def login():
    ip       = request.remote_addr
    data     = request.get_json(silent=True) or {}
    username = (data.get("username") or request.form.get("username") or "").strip()
    password = data.get("password") or request.form.get("password") or ""
    next_url = data.get("next") or request.form.get("next") or "/"

    # Rate limit check
    if is_rate_limited(ip):
        audit("login_blocked", f"Rate limit exceeded for {username}", username=username)
        return jsonify({"error": "Too many failed attempts. Try again in 15 minutes."}), 429

    user = User.query.filter_by(username=username).first()

    if not user or not check_password(password, user.password_hash):
        record_attempt(ip, username, success=False)
        audit("login_failed", f"Bad credentials for '{username}'", username=username)
        return jsonify({"error": "Invalid username or password."}), 401

    if user.status != "active":
        record_attempt(ip, username, success=False)
        audit("login_blocked", f"Account {user.status}: {username}", username=username)
        return jsonify({"error": f"Your account is {user.status}. Contact an administrator."}), 403

    # Success on password — check for 2FA
    record_attempt(ip, username, success=True)
    user.last_login = datetime.utcnow()
    db.session.commit()

    try:
        from blueprints.twofa import user_has_totp, issue_pending_2fa
        if user_has_totp(user.id):
            pending = issue_pending_2fa(user.id)
            audit("login_2fa_required", f"TOTP challenge issued for '{username}'",
                  user_id=user.id, username=username)
            return jsonify({
                "twofa_required": True,
                "pending": pending,
                "method": "totp",
                "next": next_url,
            })
    except Exception:
        pass

    create_session(user, app_name="zeekglare")
    audit("login_success", f"User '{username}' logged in from {ip}", user_id=user.id, username=username)

    token = generate_token(user)
    modules = list(get_user_modules(user))

    resp = make_response(jsonify({
        "ok": True,
        "redirect": next_url,
        "user": user.to_dict(),
        "modules": modules,
    }))
    resp.set_cookie(
        TOKEN_COOKIE, token,
        httponly=True,
        samesite="Lax",
        secure=True,
        max_age=TOKEN_EXPIRE_H * 3600,
        path="/",
    )
    return resp


# ── Logout ───────────────────────────────────────────────────────────────────

@auth_bp.route("/auth/logout", methods=["POST", "GET"])
def logout():
    token = get_token_from_request()
    user  = load_user_from_token(token) if token else None
    if user:
        delete_session(user.id, request.remote_addr)
        audit("logout", f"User '{user.username}' logged out", user_id=user.id, username=user.username)

    resp = make_response(redirect("/auth/login"))
    resp.delete_cookie(TOKEN_COOKIE, path="/")
    return resp


# ── Current user info ─────────────────────────────────────────────────────────

@auth_bp.route("/api/auth/me")
def me():
    token = get_token_from_request()
    user  = load_user_from_token(token) if token else None
    if not user:
        return jsonify({"error": "Not authenticated"}), 401
    return jsonify({
        "user":    user.to_dict(),
        "modules": list(get_user_modules(user)),
    })


# ── User Settings (server-side persistence) ───────────────────────────────────

@auth_bp.route("/api/settings/save", methods=["POST"])
def settings_save():
    """Save user settings (API keys, SSH configs, prefs) to the database."""
    token = get_token_from_request()
    user  = load_user_from_token(token) if token else None
    if not user:
        return jsonify({"error": "Not authenticated"}), 401

    body = request.get_json(silent=True) or {}
    # body is the full settings dict — store as JSON
    try:
        user.settings_json = json.dumps(body)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500
    return jsonify({"ok": True})


@auth_bp.route("/api/settings/load")
def settings_load():
    """Load user settings from the database."""
    token = get_token_from_request()
    user  = load_user_from_token(token) if token else None
    if not user:
        return jsonify({"error": "Not authenticated"}), 401

    try:
        data = json.loads(user.settings_json) if user.settings_json else {}
    except (json.JSONDecodeError, TypeError):
        data = {}
    return jsonify(data)


# ── Sub-app token (cross-port navigation) ─────────────────────────────────────

@auth_bp.route("/api/auth/subtoken")
def subtoken():
    """Issue a short-lived token (2h) for launching sub-apps."""
    token = get_token_from_request()
    user  = load_user_from_token(token) if token else None
    if not user:
        return jsonify({"error": "Not authenticated"}), 401
    short_token = generate_token(user, expire_hours=2)
    return jsonify({"token": short_token, "username": user.username})


# ── Change password (self-service) ───────────────────────────────────────────

@auth_bp.route("/api/auth/change-password", methods=["POST"])
def change_password():
    token = get_token_from_request()
    user  = load_user_from_token(token) if token else None
    if not user:
        return jsonify({"error": "Not authenticated"}), 401

    data         = request.get_json(silent=True) or {}
    current      = data.get("current_password", "")
    new_pw       = data.get("new_password", "")

    if not check_password(current, user.password_hash):
        return jsonify({"error": "Current password is incorrect."}), 400
    err = _validate_password(new_pw)
    if err:
        return jsonify({"error": err}), 400

    user.password_hash = hash_password(new_pw)
    db.session.commit()
    audit("password_changed", "User changed their own password",
          user_id=user.id, username=user.username)
    return jsonify({"ok": True})


# ── Register (admin can enable or admin-only) ─────────────────────────────────

@auth_bp.route("/api/auth/register", methods=["POST"])
def register():
    """Admin-invoked user creation. Self-registration disabled by default."""
    token = get_token_from_request()
    actor = load_user_from_token(token) if token else None
    if not actor or actor.role != "admin":
        return jsonify({"error": "Admin access required to create users."}), 403

    data     = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    email    = (data.get("email") or "").strip()
    password = data.get("password") or ""
    role     = data.get("role", "user")

    if not username or not email or not password:
        return jsonify({"error": "username, email, and password are required."}), 400
    err = _validate_password(password)
    if err:
        return jsonify({"error": err}), 400
    if role not in ("admin", "user"):
        return jsonify({"error": "role must be 'admin' or 'user'."}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({"error": f"Username '{username}' already exists."}), 409
    if User.query.filter_by(email=email).first():
        return jsonify({"error": f"Email '{email}' already registered."}), 409

    user = User(
        username=username, email=email,
        password_hash=hash_password(password),
        role=role, status="active",
    )
    db.session.add(user)
    db.session.flush()  # get user.id
    grant_default_permissions(user)
    db.session.commit()
    audit("user_created", f"Admin '{actor.username}' created user '{username}' ({role})",
          user_id=actor.id, username=actor.username)
    return jsonify({"ok": True, "user": user.to_dict()}), 201


# ── Sub-app session handshake ─────────────────────────────────────────────────

@auth_bp.route("/api/auth/validate")
def validate_token():
    """Sub-apps call this to validate a cross-app token and get user info."""
    token = get_token_from_request()
    user  = load_user_from_token(token) if token else None
    if not user:
        return jsonify({"valid": False, "error": "Invalid or expired token"}), 401
    modules = list(get_user_modules(user))
    return jsonify({
        "valid":   True,
        "user":    user.to_dict(),
        "modules": modules,
        "token":   token,
    })


# ── Public login-screen stats (no auth, safe aggregates only) ────────────────
_LOGIN_STATS_CACHE = {"data": None, "ts": 0}
_LOGIN_STATS_TTL = 300  # 5 min
_LOGIN_STATS_LOCK = threading.Lock()


def _fetch_recent_cves(limit=15):
    """Pull a small window of recent CVEs from Shodan CVEDB (free, no auth)."""
    try:
        req = urllib.request.Request(
            f"https://cvedb.shodan.io/cves?last_modified=3d&limit={limit}&sort=epss",
            headers={"User-Agent": "ZeekGlare/2.1"},
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read())
        items = data.get("cves", []) if isinstance(data, dict) else (data or [])
        out = []
        for c in items[:limit]:
            cid = c.get("cve_id") or c.get("id") or ""
            score = c.get("cvss") or c.get("cvss_v3") or 0
            try:
                score = float(score)
            except Exception:
                score = 0
            summary = (c.get("summary") or "")[:140]
            out.append({"id": cid, "cvss": score, "summary": summary})
        return out
    except Exception:
        return []


def _compute_login_stats():
    """Aggregate non-sensitive metrics for the unauthenticated login screen."""
    stats = {
        "cves": [],
        "cve_count": 0,
        "session_count": 0,
        "session_types": {},
        "active_users": 0,
        "blocked_attempts": 0,
        "uptime_started": None,
        "version": "2.1",
    }
    # Recent CVEs
    cves = _fetch_recent_cves(limit=15)
    stats["cves"] = cves
    stats["cve_count"] = len(cves)

    # Intel session counts (aggregate only, no PII)
    try:
        from core.session_manager import SessionManager
        sessions = SessionManager.list_all(admin=True)
        stats["session_count"] = len(sessions)
        types = {}
        for s in sessions:
            t = (s.get("type") or "unknown")
            types[t] = types.get(t, 0) + 1
        stats["session_types"] = types
    except Exception:
        pass

    # Total registered users (count only)
    try:
        stats["active_users"] = User.query.count()
    except Exception:
        pass

    # Blocked login attempts (from in-memory rate limiter, if exposed)
    try:
        from core.auth_utils import _attempts  # type: ignore
        total_failed = 0
        for ip, recs in (_attempts or {}).items():
            total_failed += sum(1 for r in recs if not r.get("success", True))
        stats["blocked_attempts"] = total_failed
    except Exception:
        pass

    return stats


# ── Password recovery (email) ────────────────────────────────────────────────
_RESET_TOKENS = {}        # token -> {"user_id": int, "expires": float}
_RESET_LOCK = threading.Lock()
_RESET_TTL = 1800         # 30 minutes
_RESET_RATE = {}          # email -> last_request_ts (anti-flood)
_RESET_RATE_WINDOW = 60   # 1 request per 60s per email
_RESET_LOG = pathlib.Path("data/password_resets.log")


def _purge_expired_tokens():
    now = time.time()
    with _RESET_LOCK:
        for tok, rec in list(_RESET_TOKENS.items()):
            if rec["expires"] < now:
                _RESET_TOKENS.pop(tok, None)


_AUTH_CONFIG_PATH = pathlib.Path("data/auth_config.json")


def _load_auth_config():
    try:
        with _AUTH_CONFIG_PATH.open() as f:
            return json.load(f) or {}
    except Exception:
        return {}


def _save_auth_config(cfg):
    try:
        _AUTH_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with _AUTH_CONFIG_PATH.open("w") as f:
            json.dump(cfg, f, indent=2)
        return True
    except Exception:
        return False


def _get_smtp_settings():
    """Read SMTP from data/auth_config.json first, fall back to env vars."""
    cfg = _load_auth_config().get("smtp", {}) or {}
    def _v(key, env, default=""):
        v = cfg.get(key)
        if v is None or v == "":
            return os.environ.get(env, default)
        return v
    return {
        "host":    _v("host",    "SMTP_HOST", ""),
        "port":    int(_v("port", "SMTP_PORT", "587") or 587),
        "user":    _v("user",    "SMTP_USER", ""),
        "password":_v("password","SMTP_PASS", ""),
        "from":    _v("from",    "SMTP_FROM", ""),
        "tls":     bool(cfg.get("tls", os.environ.get("SMTP_TLS", "1") != "0")),
    }


def _send_recovery_email(to_email, reset_url, username):
    """Send email via SMTP. Reads data/auth_config.json first, env vars fallback."""
    s = _get_smtp_settings()
    host = s["host"]
    if not host:
        return False
    try:
        port = s["port"]
        user = s["user"]
        pw   = s["password"]
        sender = s["from"] or user or "no-reply@zeekglare.local"
        use_tls = s["tls"]

        body = (
            f"Hello {username},\n\n"
            f"A password recovery request was submitted for your ZeekGlare account.\n\n"
            f"To reset your cipher, click the link below within the next 30 minutes:\n\n"
            f"{reset_url}\n\n"
            f"If you did not request this, you can safely ignore this email — your "
            f"account will remain unchanged.\n\n"
            f"— ZeekGlare Intelligence Platform\n"
        )
        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = "ZeekGlare — Password Recovery"
        msg["From"]    = sender
        msg["To"]      = to_email

        with smtplib.SMTP(host, port, timeout=15) as srv:
            srv.ehlo()
            if use_tls:
                srv.starttls()
                srv.ehlo()
            if user and pw:
                srv.login(user, pw)
            srv.sendmail(sender, [to_email], msg.as_string())
        return True
    except Exception as e:
        try:
            audit("recovery_email_failed", f"SMTP error: {e}", username=username)
        except Exception:
            pass
        return False


def _log_reset_request(username, email, reset_url):
    """Fallback: write reset link to a local file when SMTP isn't configured.
    Admin can read this from the server to assist a locked-out user."""
    try:
        _RESET_LOG.parent.mkdir(parents=True, exist_ok=True)
        safe_user = str(username).replace('\n', '').replace('\r', '')
        safe_email = str(email).replace('\n', '').replace('\r', '')
        safe_url = str(reset_url).replace('\n', '').replace('\r', '')
        with _RESET_LOG.open("a") as f:
            f.write(f"[{datetime.utcnow().isoformat()}Z] user={safe_user} email={safe_email} url={safe_url}\n")
    except Exception:
        pass


@auth_bp.route("/auth/forgot-password", methods=["POST"])
def forgot_password():
    """Initiate password recovery. Always returns generic success message
    to prevent user/email enumeration."""
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    generic_ok = jsonify({
        "ok": True,
        "message": "If that email is registered, a recovery link has been sent. Check your inbox."
    })

    if not email or "@" not in email:
        return jsonify({"error": "Please enter a valid email address."}), 400

    # Rate limit per email
    now = time.time()
    last = _RESET_RATE.get(email, 0)
    if now - last < _RESET_RATE_WINDOW:
        # Still respond generically — don't reveal rate state
        return generic_ok
    _RESET_RATE[email] = now

    _purge_expired_tokens()

    user = User.query.filter_by(email=email).first()
    if user and user.status == "active":
        token = secrets.token_urlsafe(32)
        with _RESET_LOCK:
            _RESET_TOKENS[token] = {
                "user_id": user.id,
                "expires": now + _RESET_TTL,
            }
        # Build reset URL from request host
        scheme = request.scheme
        host   = request.host
        reset_url = f"{scheme}://{host}/auth/reset/{token}"

        sent = _send_recovery_email(user.email, reset_url, user.username)
        if not sent:
            # Fallback: log to file so admin can deliver manually
            _log_reset_request(user.username, user.email, reset_url)
        try:
            audit("password_recovery_requested",
                  f"Recovery link issued for {user.username} (delivery={'smtp' if sent else 'logged'})",
                  username=user.username)
        except Exception:
            pass

    # Always return identical response — no user enumeration
    return generic_ok


@auth_bp.route("/auth/reset/<token>", methods=["GET"])
def reset_password_page(token):
    """Render the password reset form for a valid token."""
    _purge_expired_tokens()
    with _RESET_LOCK:
        rec = _RESET_TOKENS.get(token)
    if not rec:
        return ("<!doctype html><html><head><title>Invalid link</title>"
                "<style>body{background:#020308;color:#e2e8f8;font-family:system-ui;display:flex;"
                "align-items:center;justify-content:center;height:100vh;margin:0}"
                ".card{max-width:420px;padding:32px;border:1px solid #243060;border-radius:14px;"
                "background:#0a0f22;text-align:center}h2{color:#fca5a5;margin-bottom:10px}"
                "a{color:#818cf8;text-decoration:none}</style></head><body><div class='card'>"
                "<h2>⚠ Invalid or Expired Link</h2><p style='color:#8ea4c8;font-size:13px;line-height:1.6'>"
                "This recovery link is no longer valid. Please request a new one from the login page.</p>"
                "<p style='margin-top:20px'><a href='/auth/login'>← Back to sign in</a></p></div></body></html>"), 400
    return render_template("reset_password.html", token=token)


@auth_bp.route("/auth/reset/<token>", methods=["POST"])
def reset_password_submit(token):
    """Apply the new password if the token is valid."""
    _purge_expired_tokens()
    data = request.get_json(silent=True) or {}
    new_pw = data.get("password") or ""
    confirm = data.get("confirm") or ""

    err = _validate_password(new_pw)
    if err:
        return jsonify({"error": err}), 400
    if new_pw != confirm:
        return jsonify({"error": "Passwords do not match."}), 400

    with _RESET_LOCK:
        rec = _RESET_TOKENS.get(token)
        if not rec:
            return jsonify({"error": "This recovery link is invalid or has expired."}), 400
        user_id = rec["user_id"]
        # Single-use: consume the token
        _RESET_TOKENS.pop(token, None)

    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "Account no longer exists."}), 400

    user.password_hash = hash_password(new_pw)
    db.session.commit()
    try:
        audit("password_reset_completed",
              f"Password reset via recovery link for {user.username}",
              username=user.username)
    except Exception:
        pass
    return jsonify({"ok": True, "message": "Password updated. You can now sign in."})


@auth_bp.route("/api/admin/smtp-config", methods=["GET"])
def admin_smtp_get():
    token = get_token_from_request()
    user  = load_user_from_token(token) if token else None
    if not user or user.role != "admin":
        return jsonify({"error": "Admin access required."}), 403
    s = _get_smtp_settings()
    out = dict(s)
    if out.get("password"):
        out["password"] = "••••••••"
    out["configured"] = bool(s["host"])
    return jsonify(out)


@auth_bp.route("/api/admin/smtp-config", methods=["POST"])
def admin_smtp_set():
    token = get_token_from_request()
    user  = load_user_from_token(token) if token else None
    if not user or user.role != "admin":
        return jsonify({"error": "Admin access required."}), 403
    data = request.get_json(silent=True) or {}
    cfg = _load_auth_config()
    smtp = cfg.get("smtp", {}) or {}
    new_pw = data.get("password", "")
    if new_pw and new_pw != "••••••••":
        smtp["password"] = new_pw
    smtp["host"] = (data.get("host") or "").strip()
    try:
        smtp["port"] = int(data.get("port") or 587)
    except Exception:
        smtp["port"] = 587
    smtp["user"] = (data.get("user") or "").strip()
    smtp["from"] = (data.get("from") or "").strip()
    smtp["tls"]  = bool(data.get("tls", True))
    cfg["smtp"]  = smtp
    if not _save_auth_config(cfg):
        return jsonify({"error": "Failed to save config file."}), 500
    audit("smtp_config_updated", f"Admin '{user.username}' updated SMTP settings",
          user_id=user.id, username=user.username)
    return jsonify({"ok": True})


@auth_bp.route("/api/admin/smtp-test", methods=["POST"])
def admin_smtp_test():
    token = get_token_from_request()
    user  = load_user_from_token(token) if token else None
    if not user or user.role != "admin":
        return jsonify({"error": "Admin access required."}), 403
    data = request.get_json(silent=True) or {}
    to = (data.get("to") or user.email or "").strip()
    if not to or "@" not in to:
        return jsonify({"error": "Valid recipient email required."}), 400
    s = _get_smtp_settings()
    if not s["host"]:
        return jsonify({"error": "SMTP not configured. Save settings first."}), 400
    try:
        body = (
            f"Hello {user.username},\n\n"
            f"This is a test email from the ZeekGlare Intelligence Platform.\n"
            f"If you received this, your SMTP configuration is working correctly.\n\n"
            f"— ZeekGlare\n"
        )
        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = "ZeekGlare — SMTP Test"
        msg["From"]    = s["from"] or s["user"] or "no-reply@zeekglare.local"
        msg["To"]      = to
        with smtplib.SMTP(s["host"], s["port"], timeout=15) as srv:
            srv.ehlo()
            if s["tls"]:
                srv.starttls(); srv.ehlo()
            if s["user"] and s["password"]:
                srv.login(s["user"], s["password"])
            srv.sendmail(msg["From"], [to], msg.as_string())
        return jsonify({"ok": True, "message": f"Test email sent to {to}."})
    except Exception as e:
        return jsonify({"error": f"SMTP error: {e}"}), 500


@auth_bp.route("/api/public/login-stats")
def login_stats():
    """Public, cached, aggregate-only metrics for the login screen.
    No PII, no per-user data, no auth required."""
    now = time.time()
    with _LOGIN_STATS_LOCK:
        if _LOGIN_STATS_CACHE["data"] and (now - _LOGIN_STATS_CACHE["ts"]) < _LOGIN_STATS_TTL:
            return jsonify(_LOGIN_STATS_CACHE["data"])
    data = _compute_login_stats()
    with _LOGIN_STATS_LOCK:
        _LOGIN_STATS_CACHE["data"] = data
        _LOGIN_STATS_CACHE["ts"] = now
    return jsonify(data)
