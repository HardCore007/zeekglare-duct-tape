"""Admin dashboard blueprint — user management, permissions, audit logs."""
import csv, io, json, os, psutil, platform as _platform, socket
from flask import Blueprint, request, jsonify, render_template, g, Response
from datetime import datetime, timedelta
from sqlalchemy import func, cast, Date

from core.db import db
from core.models import User, UserToolPermission, AuditLog, ActiveSession, LoginAttempt
from core.auth_utils import (
    admin_required, hash_password, audit,
    grant_default_permissions, get_user_modules,
    PLATFORM_MODULES, DEFAULT_USER_MODULES,
)

admin_bp = Blueprint("admin", __name__)


# ── Dashboard page ────────────────────────────────────────────────────────────

@admin_bp.route("/admin")
@admin_required
def admin_page():
    return render_template("admin.html", current_user=g.current_user)


# ── Overview stats ────────────────────────────────────────────────────────────

@admin_bp.route("/api/admin/stats")
@admin_required
def stats():
    total_users    = User.query.count()
    active_users   = User.query.filter_by(status="active").count()
    suspended      = User.query.filter_by(status="suspended").count()
    admin_count    = User.query.filter_by(role="admin").count()
    active_sessions= ActiveSession.query.count()
    audit_today    = AuditLog.query.filter(
        AuditLog.timestamp >= datetime.utcnow().replace(hour=0, minute=0, second=0)
    ).count()
    # Recent failed logins (last 1h)
    failed_logins  = LoginAttempt.query.filter(
        LoginAttempt.success == False,  # noqa
        LoginAttempt.timestamp >= datetime.utcnow() - timedelta(hours=1),
    ).count()
    return jsonify({
        "total_users":     total_users,
        "active_users":    active_users,
        "suspended_users": suspended,
        "admin_count":     admin_count,
        "active_sessions": active_sessions,
        "audit_today":     audit_today,
        "failed_logins_1h":failed_logins,
        "platform_modules":len(PLATFORM_MODULES),
    })


# ── User CRUD ─────────────────────────────────────────────────────────────────

@admin_bp.route("/api/admin/users", methods=["GET"])
@admin_required
def list_users():
    users = User.query.order_by(User.created_at.desc()).all()
    return jsonify([u.to_dict() for u in users])


@admin_bp.route("/api/admin/users", methods=["POST"])
@admin_required
def create_user():
    data     = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    email    = (data.get("email") or "").strip()
    password = data.get("password") or ""
    role     = data.get("role", "user")

    if not username or not email or not password:
        return jsonify({"error": "username, email, and password are required."}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters."}), 400
    if role not in ("admin", "user"):
        return jsonify({"error": "role must be 'admin' or 'user'."}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({"error": f"Username '{username}' already exists."}), 409
    if User.query.filter_by(email=email).first():
        return jsonify({"error": f"Email '{email}' already registered."}), 409

    user = User(username=username, email=email,
                password_hash=hash_password(password), role=role, status="active")
    db.session.add(user)
    db.session.flush()
    grant_default_permissions(user)
    db.session.commit()
    audit("admin_user_created",
          f"Created user '{username}' role={role}",
          user_id=g.current_user.id, username=g.current_user.username)
    return jsonify({"ok": True, "user": user.to_dict()}), 201


@admin_bp.route("/api/admin/users/<int:uid>", methods=["GET"])
@admin_required
def get_user(uid):
    user = User.query.get_or_404(uid)
    return jsonify(user.to_dict(include_permissions=True))


@admin_bp.route("/api/admin/users/<int:uid>", methods=["PATCH"])
@admin_required
def update_user(uid):
    user = User.query.get_or_404(uid)
    data = request.get_json(silent=True) or {}

    changed = []
    if "status" in data and data["status"] in ("active", "suspended", "disabled"):
        user.status = data["status"]
        changed.append(f"status={data['status']}")
    if "role" in data and data["role"] in ("admin", "user"):
        if user.id == g.current_user.id and data["role"] != "admin":
            return jsonify({"error": "Cannot demote yourself."}), 400
        user.role = data["role"]
        changed.append(f"role={data['role']}")
    if "email" in data:
        user.email = data["email"].strip()
        changed.append("email updated")

    db.session.commit()
    audit("admin_user_updated",
          f"Updated user '{user.username}': {', '.join(changed)}",
          user_id=g.current_user.id, username=g.current_user.username)
    return jsonify({"ok": True, "user": user.to_dict()})


@admin_bp.route("/api/admin/users/<int:uid>", methods=["DELETE"])
@admin_required
def delete_user(uid):
    user = User.query.get_or_404(uid)
    if user.id == g.current_user.id:
        return jsonify({"error": "Cannot delete your own account."}), 400
    username = user.username
    db.session.delete(user)
    db.session.commit()
    audit("admin_user_deleted",
          f"Deleted user '{username}'",
          user_id=g.current_user.id, username=g.current_user.username)
    return jsonify({"ok": True})


@admin_bp.route("/api/admin/users/<int:uid>/reset-password", methods=["POST"])
@admin_required
def reset_password(uid):
    user = User.query.get_or_404(uid)
    data = request.get_json(silent=True) or {}
    new_pw = data.get("password") or ""
    import re as _re
    if not new_pw or len(new_pw) < 8:
        return jsonify({"error": "Password must be at least 8 characters."}), 400
    if not _re.search(r'[A-Z]', new_pw) or not _re.search(r'[a-z]', new_pw) \
       or not _re.search(r'\d', new_pw) or not _re.search(r'[^A-Za-z0-9]', new_pw):
        return jsonify({"error": "Password must contain uppercase, lowercase, digit, and symbol."}), 400
    user.password_hash = hash_password(new_pw)
    db.session.commit()
    audit("admin_password_reset",
          f"Admin reset password for '{user.username}'",
          user_id=g.current_user.id, username=g.current_user.username)
    return jsonify({"ok": True})


# ── Tool Permissions ─────────────────────────────────────────────────────────

@admin_bp.route("/api/admin/users/<int:uid>/permissions", methods=["GET"])
@admin_required
def get_permissions(uid):
    user = User.query.get_or_404(uid)
    enabled = {p.module_id for p in user.permissions.filter_by(enabled=True)}
    modules = [
        {**m, "enabled": m["id"] in enabled}
        for m in PLATFORM_MODULES
    ]
    return jsonify({"user": user.to_dict(), "modules": modules})


@admin_bp.route("/api/admin/users/<int:uid>/permissions", methods=["PUT"])
@admin_required
def set_permissions(uid):
    """Replace the user's full permission set."""
    user    = User.query.get_or_404(uid)
    data    = request.get_json(silent=True) or {}
    enabled = set(data.get("modules", []))

    # Delete all existing
    UserToolPermission.query.filter_by(user_id=user.id).delete()
    # Insert new set
    valid_ids = {m["id"] for m in PLATFORM_MODULES}
    for mid in enabled:
        if mid in valid_ids:
            db.session.add(UserToolPermission(user_id=user.id, module_id=mid, enabled=True))
    db.session.commit()
    audit("admin_permissions_updated",
          f"Set permissions for '{user.username}': {sorted(enabled)}",
          user_id=g.current_user.id, username=g.current_user.username)
    return jsonify({"ok": True})


@admin_bp.route("/api/admin/users/<int:uid>/permissions/<module_id>", methods=["PATCH"])
@admin_required
def toggle_permission(uid, module_id):
    """Enable or disable a single module for a user."""
    user = User.query.get_or_404(uid)
    data = request.get_json(silent=True) or {}
    state = bool(data.get("enabled", True))

    perm = UserToolPermission.query.filter_by(user_id=user.id, module_id=module_id).first()
    if perm:
        perm.enabled = state
    else:
        db.session.add(UserToolPermission(user_id=user.id, module_id=module_id, enabled=state))
    db.session.commit()
    action = "enabled" if state else "disabled"
    audit("admin_permission_toggled",
          f"Module '{module_id}' {action} for user '{user.username}'",
          user_id=g.current_user.id, username=g.current_user.username)
    return jsonify({"ok": True, "module": module_id, "enabled": state})


@admin_bp.route("/api/admin/modules")
@admin_required
def list_modules():
    return jsonify(PLATFORM_MODULES)


# ── Audit Logs ────────────────────────────────────────────────────────────────

@admin_bp.route("/api/admin/audit-logs/clear", methods=["DELETE"])
@admin_required
def clear_audit_logs():
    try:
        deleted = AuditLog.query.delete(synchronize_session=False)
        db.session.commit()
        return jsonify({"ok": True, "deleted": deleted})
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500


@admin_bp.route("/api/admin/audit-logs")
@admin_required
def audit_logs():
    page     = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", 50))
    action_f = request.args.get("action")
    user_f   = request.args.get("username")

    q = AuditLog.query.order_by(AuditLog.timestamp.desc())
    if action_f:
        q = q.filter(AuditLog.action.ilike(f"%{action_f}%"))
    if user_f:
        q = q.filter(AuditLog.username.ilike(f"%{user_f}%"))

    total = q.count()
    logs  = q.offset((page - 1) * per_page).limit(per_page).all()
    return jsonify({
        "logs":     [l.to_dict() for l in logs],
        "total":    total,
        "page":     page,
        "per_page": per_page,
        "pages":    (total + per_page - 1) // per_page,
    })


# ── Active Sessions ───────────────────────────────────────────────────────────

@admin_bp.route("/api/admin/sessions")
@admin_required
def active_sessions():
    sessions = ActiveSession.query.order_by(ActiveSession.last_seen.desc()).all()
    return jsonify([s.to_dict() for s in sessions])


@admin_bp.route("/api/admin/sessions/<int:sid>", methods=["DELETE"])
@admin_required
def kill_session(sid):
    sess = ActiveSession.query.get_or_404(sid)
    username = sess.username
    db.session.delete(sess)
    db.session.commit()
    audit("admin_session_killed",
          f"Admin terminated session for '{username}'",
          user_id=g.current_user.id, username=g.current_user.username)
    return jsonify({"ok": True})


# ── Intelligence Sessions (admin view all users) ──────────────────────────────

@admin_bp.route("/api/admin/intel-sessions")
@admin_required
def intel_sessions():
    """Return all intelligence scan sessions across all users."""
    from core.session_manager import SessionManager
    return jsonify(SessionManager.list_all(admin=True))


@admin_bp.route("/api/admin/intel-sessions/<sid>", methods=["DELETE"])
@admin_required
def delete_intel_session(sid):
    from core.session_manager import SessionManager
    ok = SessionManager.delete(sid, admin=True)
    if not ok:
        return jsonify({"error": "Session not found"}), 404
    audit("admin_intel_session_deleted",
          f"Admin deleted intel session '{sid}'",
          user_id=g.current_user.id, username=g.current_user.username)
    return jsonify({"ok": True})


# ── Tools Update ─────────────────────────────────────────────────────────────

import shutil, subprocess, os as _os, json as _json


def _has_passwordless_sudo():
    """Check if the current user can run sudo without a password prompt."""
    try:
        subprocess.run(["sudo", "-n", "true"], capture_output=True, check=True)
        return True
    except Exception:
        return False


# Cache the sudo check at import time so we don't re-check on every update.
_SUDO_OK = _has_passwordless_sudo()

# (id, label, category, dashboard, update_cmd)
# dashboard: "Intelligence" | "Xpl03tEr" | "Misc Tools" | "All"
_TOOLS_REGISTRY = [
    # ── Intelligence Platform ─────────────────────────────────────────────────
    # Subdomain Enumeration
    ("subfinder",        "Subfinder",        "Subdomain Enum",   "Intelligence", "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
    ("amass",            "Amass",            "Subdomain Enum",   "Intelligence", "go install github.com/owasp-amass/amass/v4/...@master"),
    ("assetfinder",      "AssetFinder",      "Subdomain Enum",   "Intelligence", "go install github.com/tomnomnom/assetfinder@latest"),
    ("cero",             "Cero",             "Subdomain Enum",   "Intelligence", "go install github.com/glebarez/cero@latest"),
    ("findomain",        "Findomain",        "Subdomain Enum",   "Intelligence", ""),
    ("sublist3r",        "Sublist3r",        "Subdomain Enum",   "Intelligence", "pip3 install -U sublist3r"),
    ("github-subdomains","github-subdomains","Subdomain Enum",   "Intelligence", "go install github.com/gwen001/github-subdomains@latest"),
    ("gitlab-subdomains","gitlab-subdomains","Subdomain Enum",   "Intelligence", "go install github.com/gwen001/gitlab-subdomains@latest"),
    # HTTP / Probing
    ("httpx",            "httpx",            "HTTP Probe",       "Intelligence", "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"),
    ("whatweb",          "WhatWeb",          "Tech Detection",   "Intelligence", "apt-get install -y whatweb"),
    # Port Scanners
    ("nmap",             "Nmap",             "Port Scanner",     "Intelligence", "apt-get install -y nmap"),
    ("masscan",          "Masscan",          "Port Scanner",     "Intelligence", "apt-get install -y masscan"),
    ("rustscan",         "RustScan",         "Port Scanner",     "Intelligence", "cargo install rustscan"),
    ("naabu",            "Naabu",            "Port Scanner",     "Intelligence", "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"),
    # Vuln / Web Scanners
    ("nuclei",           "Nuclei",           "Vuln Scanner",     "All",          "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"),
    ("nikto",            "Nikto",            "Web Scanner",      "All",          "apt-get install -y nikto"),
    ("afrog",            "Afrog",            "Vuln Scanner",     "Intelligence", "go install github.com/zan8in/afrog/v3/cmd/afrog@latest"),
    ("wpscan",           "WPScan",           "WP Scanner",       "All",          "command -v wpscan >/dev/null 2>&1 || (apt-get update && apt-get install -y ruby ruby-dev build-essential libcurl4-openssl-dev libxml2 libxml2-dev libxslt1-dev zlib1g-dev); (command -v wpscan >/dev/null 2>&1 && gem update wpscan) || gem install wpscan; mkdir -p /tmp/wpscan-cache && chmod 1777 /tmp/wpscan-cache; rm -rf /tmp/wpscan 2>/dev/null; mkdir -p /tmp/wpscan && chmod 1777 /tmp/wpscan"),
    ("wpprobe",          "WPProbe",          "WP Scanner",       "All",          "command -v go >/dev/null 2>&1 || (apt-get update && apt-get install -y golang-go); go install github.com/Chocapikk/wpprobe@latest && (cp -f \"$(go env GOPATH)/bin/wpprobe\" /usr/local/bin/wpprobe 2>/dev/null || true) && (wpprobe update 2>&1 || /root/go/bin/wpprobe update 2>&1 || true) && (wpprobe update-db 2>&1 || /root/go/bin/wpprobe update-db 2>&1 || true)"),
    # Web Fuzzing
    ("ffuf",             "ffuf",             "Web Fuzzer",       "Intelligence", "go install github.com/ffuf/ffuf/v2@latest"),
    ("ffufai",           "ffufai",           "AI Web Fuzzer",    "Intelligence", "test -d ~/Claude-Code/xploiter-tools/ffufai && cd ~/Claude-Code/xploiter-tools/ffufai && git pull || git clone --depth 1 https://github.com/ffuf/ffuf-ai ~/Claude-Code/xploiter-tools/ffufai"),
    ("dirsearch",        "Dirsearch",        "Dir Fuzzer",       "Intelligence", "pip3 install -U dirsearch"),
    # Param Finders
    ("arjun",            "Arjun",            "Param Finder",     "Intelligence", "pip3 install -U arjun"),
    ("paramspider",      "ParamSpider",      "Param Finder",     "Intelligence", "test -d ~/Claude-Code/xploiter-tools/ParamSpider && cd ~/Claude-Code/xploiter-tools/ParamSpider && git pull || git clone --depth 1 https://github.com/devanshbatham/ParamSpider ~/Claude-Code/xploiter-tools/ParamSpider"),
    ("x8",               "x8",              "Param Finder",     "Intelligence", "cargo install x8"),
    # URL Harvesters
    ("gau",              "GAU",              "URL Harvester",    "Intelligence", "go install github.com/lc/gau/v2/cmd/gau@latest"),
    ("waybackurls",      "Waybackurls",      "URL Harvester",    "Intelligence", "go install github.com/tomnomnom/waybackurls@latest"),
    ("urlfinder",        "URLFinder",        "URL Harvester",    "Intelligence", "go install github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest"),
    ("waymore",          "Waymore",          "URL Harvester",    "Intelligence", "pip3 install -U waymore"),
    # Active Web Crawlers
    ("hakrawler",        "Hakrawler",        "Web Crawler",      "Intelligence", "go install github.com/hakluke/hakrawler@latest"),
    ("gospider",         "GoSpider",         "Web Crawler",      "Intelligence", "go install github.com/jaeles-project/gospider@latest"),
    # JS Analysis
    ("GoLinkFinder",     "GoLinkFinder",     "JS Analysis",      "Intelligence", "go install github.com/0xsha/GoLinkFinder@latest"),
    ("jsluice",          "jsluice",          "JS Analysis",      "Intelligence", "go install github.com/BishopFox/jsluice/cmd/jsluice@latest"),
    ("jsleak",           "jsleak",           "JS Analysis",      "Intelligence", "go install github.com/channyein1337/jsleak@latest"),
    ("getJS",            "getJS",            "JS Analysis",      "Intelligence", "go install github.com/003random/getJS@latest"),
    ("xnLinkFinder",     "xnLinkFinder",     "JS Analysis",      "Intelligence", "pip3 install -U xnLinkFinder"),
    ("secretfinder",     "SecretFinder",     "JS Analysis",      "Intelligence", "test -d ~/Claude-Code/xploiter-tools/SecretFinder && cd ~/Claude-Code/xploiter-tools/SecretFinder && git pull || (cd ~/Claude-Code/xploiter-tools && git clone --depth 1 https://github.com/m4ll0k/SecretFinder && cd SecretFinder && python3 -m venv .venv && .venv/bin/pip install -r requirements.txt)"),
    ("jsanalyzer",       "JSAnalyzer",       "JS Analysis",      "Intelligence", "test -d ~/Claude-Code/xploiter-tools/JSAnalyzer && cd ~/Claude-Code/xploiter-tools/JSAnalyzer && git pull || (cd ~/Claude-Code/xploiter-tools && git clone --depth 1 https://github.com/jenish-sojitra/JSAnalyzer && cd JSAnalyzer && python3 -m venv .venv && .venv/bin/pip install -r requirements.txt)"),
    # ASN / CDN / TLS / OSINT
    ("asnmap",           "ASNMap",           "Network Intel",    "Intelligence", "go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest"),
    ("cdncheck",         "CDNCheck",         "Network Intel",    "Intelligence", "go install github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest"),
    ("tlsx",             "TLSX",             "Network Intel",    "Intelligence", "go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest"),
    ("cvemap",           "CVEMap",           "Network Intel",    "Intelligence", "go install github.com/projectdiscovery/cvemap/cmd/cvemap@latest"),
    ("uncover",          "Uncover",          "OSINT Search",     "Intelligence", "go install github.com/projectdiscovery/uncover/cmd/uncover@latest"),
    # PD Pipeline
    ("dnsx",             "dnsx",             "DNS Tools",        "Intelligence", "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest"),
    ("shuffledns",       "shuffledns",       "DNS Tools",        "Intelligence", "go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"),
    ("alterx",           "alterx",           "DNS Tools",        "Intelligence", "go install github.com/projectdiscovery/alterx/cmd/alterx@latest"),
    ("massdns",          "MassDNS",          "DNS Tools",        "Intelligence", "cd /tmp && git clone --depth 1 https://github.com/blechschmidt/massdns && cd massdns && make && cp bin/massdns /usr/local/bin/ && rm -rf /tmp/massdns"),
    ("katana",           "Katana",           "Web Crawling",     "Intelligence", "go install github.com/projectdiscovery/katana/cmd/katana@latest"),
    ("notify",           "Notify",           "Utility",          "Intelligence", "go install github.com/projectdiscovery/notify/cmd/notify@latest"),
    ("proxify",          "Proxify",          "Web Proxy",        "Intelligence", "go install github.com/projectdiscovery/proxify/cmd/proxify@latest"),
    # Recon Suites
    ("bbot",             "BBOT",             "Recon Suite",      "Intelligence", "pip3 install -U bbot"),
    ("reconftw",         "ReconFTW",         "Recon Suite",      "Intelligence", ""),
    ("sudomy",           "Sudomy",           "Recon Suite",      "Intelligence", "test -d ~/Claude-Code/xploiter-tools/Sudomy && cd ~/Claude-Code/xploiter-tools/Sudomy && git pull || git clone --depth 1 https://github.com/screetsec/Sudomy ~/Claude-Code/xploiter-tools/Sudomy && chmod +x ~/Claude-Code/xploiter-tools/Sudomy/sudomy"),
    ("oneforall",        "OneForAll",        "Recon Suite",      "Intelligence", "test -d ~/OneForAll && cd ~/OneForAll && git pull || (git clone --depth 1 https://github.com/shmilylty/OneForAll ~/OneForAll && cd ~/OneForAll && pip3 install -r requirements.txt)"),

    # ── Xpl03tEr ─────────────────────────────────────────────────────────────
    # XSS
    ("dalfox",           "dalfox",           "XSS",              "Xpl03tEr",     "go install github.com/hahwul/dalfox/v2@latest"),
    ("kxss",             "kxss",             "XSS",              "Xpl03tEr",     "go install github.com/tomnomnom/hacks/kxss@latest"),
    ("xsser",            "XSSer",            "XSS",              "Xpl03tEr",     "apt-get install -y xsser"),
    # SQLi
    ("sqlmap",           "sqlmap",           "SQLi",             "Xpl03tEr",     "pip3 install -U sqlmap"),
    ("ghauri",           "ghauri",           "SQLi",             "Xpl03tEr",     "pip3 install -U ghauri"),
    # SSRF
    ("surf",             "surf",             "SSRF",             "Xpl03tEr",     "go install github.com/assetnote/surf@latest"),
    ("ssrfuzz",          "ssrfuzz",          "SSRF",             "Xpl03tEr",     "go install github.com/ryandamour/ssrfuzz@latest"),
    ("interactsh-client","interactsh-client","SSRF / OOB",       "Xpl03tEr",     "go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"),
    # CORS
    ("corstest",         "CORStest",         "CORS",             "Xpl03tEr",     "pip3 install -U corstest"),
    ("CorsMe",           "CorsMe",           "CORS",             "Xpl03tEr",     "go install github.com/shivangix01b/CorsMe@latest"),
    # CRLF
    ("crlfsuite",        "CRLFsuite",        "CRLF",             "Xpl03tEr",     "pip3 install -U crlfsuite"),
    ("crlfuzz",          "crlfuzz",          "CRLF",             "Xpl03tEr",     "go install github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest"),
    ("injectus",         "Injectus",         "CRLF",             "Xpl03tEr",     "pip3 install -U injectus"),
    # Cmd Injection
    ("commix",           "commix",           "Cmd Injection",    "Xpl03tEr",     "pip3 install -U commix"),
    # LFI
    ("liffy",            "liffy",            "LFI",              "Xpl03tEr",     "pip3 install -U liffy"),
    ("lfimap",           "lfimap",           "LFI",              "Xpl03tEr",     "pip3 install -U lfimap"),
    ("fdsploit",         "FDsploit",         "LFI",              "Xpl03tEr",     "pip3 install -U fdsploit"),
    # XXE
    ("xxexploiter",      "xxexploiter",      "XXE",              "Xpl03tEr",     "pip3 install -U xxexploiter"),
    # SSTI
    ("tplmap",           "tplmap",           "SSTI",             "Xpl03tEr",     "pip3 install -U tplmap"),
    ("sstimap",          "SSTImap",          "SSTI",             "Xpl03tEr",     "test -d ~/Claude-Code/xploiter-tools/SSTImap && cd ~/Claude-Code/xploiter-tools/SSTImap && git pull || git clone --depth 1 https://github.com/vladko312/SSTImap ~/Claude-Code/xploiter-tools/SSTImap"),
    # GraphQL
    ("inql",             "InQL",             "GraphQL",          "Xpl03tEr",     "pip3 install -U inql"),
    ("clairvoyance",     "clairvoyance",     "GraphQL",          "Xpl03tEr",     "pip3 install -U clairvoyance"),
    ("gqlspection",      "gqlspection",      "GraphQL",          "Xpl03tEr",     "pip3 install -U gqlspection"),
    # Smuggling
    ("http2smugl",       "http2smugl",       "Req Smuggling",    "Xpl03tEr",     "pip3 install -U http2smugl"),
    # Race Condition
    ("race-the-web",     "race-the-web",     "Race Condition",   "Xpl03tEr",     "go install github.com/TheHackerDev/race-the-web@latest"),
    # WAF Bypass
    ("nomore403",        "nomore403",        "WAF Bypass",       "Xpl03tEr",     "go install github.com/devploit/nomore403@latest"),
    ("forbidden-buster", "Forbidden Buster", "WAF Bypass",       "Xpl03tEr",     "pip3 install -U forbidden-buster"),
    ("bypass-403",       "bypass-403",       "WAF Bypass",       "Xpl03tEr",     "pip3 install -U bypass-403"),
    # CSRF / Header
    ("xsrfprobe",        "XSRFProbe",        "CSRF",             "Xpl03tEr",     "pip3 install -U xsrfprobe"),
    ("headi",            "headi",            "Header Injection", "Xpl03tEr",     "go install github.com/mlcsec/headi@latest"),

    # ── Misc Tools ────────────────────────────────────────────────────────────
    # Passwords
    ("hydra",            "Hydra",            "Passwords",        "Misc Tools",   "apt-get install -y hydra"),
    ("changeme",         "changeme",         "Passwords",        "Misc Tools",   "pip3 install -U changeme"),
    ("patator",          "patator",          "Passwords",        "Misc Tools",   "pip3 install -U patator"),
    # Secrets Scanning
    ("gitleaks",         "Gitleaks",         "Secrets",          "Misc Tools",   "go install github.com/zricethezav/gitleaks/v8@latest"),
    ("trufflehog",       "TruffleHog",       "Secrets",          "Misc Tools",   "pip3 install -U truffleHog"),
    ("detect-secrets",   "detect-secrets",   "Secrets",          "Misc Tools",   "pip3 install -U detect-secrets"),
    ("noseyparker",      "NoseyParker",       "Secrets",          "Misc Tools",   "cargo install noseyparker"),
    ("whispers",         "Whispers",         "Secrets",          "Misc Tools",   "pip3 install -U whispers"),
    ("cariddi",          "Cariddi",          "Secrets",          "Misc Tools",   "go install github.com/edoardottt/cariddi/cmd/cariddi@latest"),
    ("earlybird",        "EarlyBird",        "Secrets",          "Misc Tools",   "go install github.com/americanexpress/earlybird/cmd/earlybird@latest"),
    ("git-hound",        "GitHound",         "Secrets",          "Misc Tools",   "go install github.com/tillson/git-hound@latest"),
    ("shhgit",           "shhgit",           "Secrets",          "Misc Tools",   "go install github.com/eth0izzle/shhgit@latest"),
    ("gitrob",           "Gitrob",           "Secrets",          "Misc Tools",   "go install github.com/michenriksen/gitrob@latest"),
    ("badsecrets",       "badsecrets",       "Secrets",          "Misc Tools",   "pip3 install -U badsecrets"),
    ("hardcoded-token-hunter","Hardcoded-Token-Hunter","Secrets","Misc Tools",   "test -d ~/Claude-Code/xploiter-tools/Hardcoded-Token-Hunter && cd ~/Claude-Code/xploiter-tools/Hardcoded-Token-Hunter && git pull || git clone --depth 1 https://github.com/KingOfBugbounty/Hardcoded-Token-Hunter ~/Claude-Code/xploiter-tools/Hardcoded-Token-Hunter"),
    # Git
    ("gitjacker",        "Gitjacker",        "Git",              "Misc Tools",   "go install github.com/liamg/gitjacker@latest"),
    ("git-dumper",       "git-dumper",       "Git",              "Misc Tools",   "pip3 install -U git-dumper"),
    ("gato",             "gato",             "Git",              "Misc Tools",   "pip3 install -U gato"),
    ("zizmor",           "zizmor",           "Git",              "Misc Tools",   "pip3 install -U zizmor"),
    ("gitdorker",        "GitDorker",        "Git",              "Misc Tools",   "pip3 install -U GitDorker"),
    ("github-search",    "github-search",    "Git",              "Misc Tools",   "test -d ~/Claude-Code/xploiter-tools/github-search && cd ~/Claude-Code/xploiter-tools/github-search && git pull || git clone --depth 1 https://github.com/gwen001/github-search ~/Claude-Code/xploiter-tools/github-search"),
    # Cloud Buckets
    ("s3scanner",        "S3Scanner",        "Cloud Buckets",    "Misc Tools",   "pip3 install -U s3scanner"),
    ("cloudbrute",       "CloudBrute",       "Cloud Buckets",    "Misc Tools",   "go install github.com/0xsha/CloudBrute@latest"),
    ("s3reverse",        "s3reverse",        "Cloud Buckets",    "Misc Tools",   "go install github.com/hahwul/s3reverse@latest"),
    ("festin",           "Festin",           "Cloud Buckets",    "Misc Tools",   "pip3 install -U festin"),
    # CMS
    ("wprecon",          "wprecon",          "CMS",              "Misc Tools",   "go install github.com/blackcrw/wprecon@latest"),
    ("aem-hacker",       "aem-hacker",       "CMS",              "Misc Tools",   "pip3 install -U aem-hacker"),
    # JWT
    ("jwt-hack",         "jwt-hack",         "JWT",              "Misc Tools",   "go install github.com/hahwul/jwt-hack@latest"),
    ("jwtear",           "jwtear",           "JWT",              "Misc Tools",   "gem install jwtear"),
    # Subdomain Takeover
    ("subjack",          "Subjack",          "Sub Takeover",     "Misc Tools",   "go install github.com/haccer/subjack@latest"),
    ("subzy",            "Subzy",            "Sub Takeover",     "Misc Tools",   "go install github.com/PentestPad/subzy@latest"),
    ("tko-subs",         "tko-subs",         "Sub Takeover",     "Misc Tools",   "go install github.com/anshumanbh/tko-subs@latest"),
    ("second-order",     "second-order",     "Sub Takeover",     "Misc Tools",   "go install github.com/mhmdiaa/second-order@latest"),
    ("SubOver",          "SubOver",          "Sub Takeover",     "Misc Tools",   "go install github.com/Ice3man543/SubOver@latest"),
    # Vuln Scanners (Misc)
    ("jaeles",           "Jaeles",           "Vuln Scanner",     "Misc Tools",   "go install github.com/jaeles-project/jaeles@latest"),
    ("getsploit",        "getsploit",        "Vuln Scanner",     "Misc Tools",   "pip3 install -U getsploit"),
    # Permutation
    ("gotator",          "Gotator",          "DNS Permutation",  "Misc Tools",   "go install github.com/Josue87/gotator@latest"),
    ("dnsgen",           "dnsgen",           "DNS Permutation",  "Misc Tools",   "pip3 install -U dnsgen"),
    ("ripgen",           "ripgen",           "DNS Permutation",  "Misc Tools",   "cargo install ripgen"),
    # Web Proxy
    ("mitmproxy",        "mitmproxy",        "Web Proxy",        "Misc Tools",   "pip3 install -U mitmproxy"),
    # Origin IP
    ("hakoriginfinder",  "hakoriginfinder",  "Origin IP",        "Misc Tools",   "go install github.com/hakluke/hakoriginfinder@latest"),
    ("cloudrip",         "CloudRip",         "Origin IP",        "Misc Tools",   "test -d ~/Claude-Code/xploiter-tools/CloudRip && cd ~/Claude-Code/xploiter-tools/CloudRip && git pull || git clone --depth 1 https://github.com/moscovium-mc/CloudRip ~/Claude-Code/xploiter-tools/CloudRip"),
    # Useful Utilities
    ("anew",             "anew",             "Utility",          "Misc Tools",   "go install github.com/tomnomnom/anew@latest"),
    ("gf",               "gf",               "Utility",          "Misc Tools",   "go install github.com/tomnomnom/gf@latest"),
    ("uro",              "uro",              "Utility",          "Misc Tools",   "pip3 install -U uro"),
    ("unfurl",           "unfurl",           "Utility",          "Misc Tools",   "go install github.com/tomnomnom/unfurl@latest"),
    ("qsreplace",        "qsreplace",        "Utility",          "Misc Tools",   "go install github.com/tomnomnom/qsreplace@latest"),
    ("dnsr",             "dnsReaper",        "Utility",          "Misc Tools",   "test -d ~/Claude-Code/xploiter-tools/dnsReaper && cd ~/Claude-Code/xploiter-tools/dnsReaper && git pull || (git clone --depth 1 https://github.com/punk-security/dnsReaper ~/Claude-Code/xploiter-tools/dnsReaper && cd ~/Claude-Code/xploiter-tools/dnsReaper && python3 -m venv .venv && .venv/bin/pip install -r requirements.txt)"),
]


def _find_tool_path(tid):
    """Return binary path or None. Checks PATH first, then common install dirs."""
    path = shutil.which(tid)
    if not path:
        for candidate in [
            f"/usr/local/bin/{tid}",
            f"/root/go/bin/{tid}",
            _os.path.expanduser(f"~/go/bin/{tid}"),
            _os.path.expanduser(f"~/.local/bin/{tid}"),
            _os.path.expanduser(f"~/.cargo/bin/{tid}"),
            f"/usr/bin/{tid}",
            f"/usr/sbin/{tid}",
            f"/root/.local/bin/{tid}",
        ]:
            if _os.path.isfile(candidate):
                path = candidate
                break
    return path


@admin_bp.route("/api/admin/tools/status")
@admin_required
def tools_status():
    import time
    result = []
    for (tid, label, category, dashboard, update_cmd) in _TOOLS_REGISTRY:
        path = _find_tool_path(tid)
        last_updated = None
        if path:
            try:
                last_updated = int(_os.path.getmtime(path))
            except OSError:
                pass
        result.append({
            "id":           tid,
            "label":        label,
            "category":     category,
            "dashboard":    dashboard,
            "installed":    bool(path),
            "path":         path or "",
            "updatable":    bool(update_cmd),
            "last_updated": last_updated,
        })
    return jsonify(result)


@admin_bp.route("/api/admin/tools/update/<tool_id>", methods=["POST"])
@admin_required
def tool_update(tool_id):
    from flask import Response, stream_with_context

    entry = next((t for t in _TOOLS_REGISTRY if t[0] == tool_id), None)
    if not entry:
        return jsonify({"error": "Unknown tool"}), 404
    tid, label, _, _dashboard, update_cmd = entry
    if not update_cmd:
        return jsonify({"error": f"No update command defined for {label}"}), 400

    def _stream():
        def _sse(obj):
            return f"data: {_json.dumps(obj)}\n\n"

        # On Kali (PEP 668) rewrite pip3 install commands to use pipx,
        # which manages its own venv per tool automatically.
        # Fall back to pip3 --break-system-packages if pipx is unavailable.
        import shutil as _shutil
        import re as _re
        cmd = update_cmd
        _pip_re = _re.compile(r'^pip3\s+install\s+(-U\s+)?', _re.I)
        if _pip_re.match(cmd):
            pkg = _pip_re.sub('', cmd).strip()
            if _shutil.which("pipx"):
                # pipx install handles both fresh install and upgrades
                cmd = f"pipx install --force {pkg}"
            else:
                cmd = f"pip3 install --break-system-packages -U {pkg}"

        yield _sse({"type": "log", "line": f"▸ Updating {label}…"})
        yield _sse({"type": "log", "line": f"$ {cmd}"})

        # Use /root as HOME/GOPATH so go/cargo tools install to a
        # consistent location regardless of which user runs the Flask app.
        _root_home = "/root"
        env = {**_os.environ,
               "GOPATH": f"{_root_home}/go",
               "GOBIN":  f"{_root_home}/go/bin",
               "HOME":   _root_home,
               "PATH":   f"/usr/local/go/bin:"
                         f"{_root_home}/go/bin:"
                         f"{_root_home}/.cargo/bin:"
                         f"{_root_home}/.local/bin:"
                         f"/usr/local/bin:/usr/bin:/bin:/usr/sbin:"
                         + _os.environ.get("PATH", "")}
        is_go_install  = cmd.strip().startswith("go install")
        is_cargo       = cmd.strip().startswith("cargo install")
        is_apt         = cmd.strip().startswith("apt-get")

        # If passwordless sudo is available, run the command as root so it can
        # write to /root/go, /usr/local/bin, and run apt-get without errors.
        # We use `sudo -n env KEY=VAL … cmd` so special characters in env values
        # don't break shell quoting.
        if _SUDO_OK:
            _env_list = []
            for k, v in env.items():
                if k in ("PWD", "OLDPWD", "PS1", "_"):
                    continue
                # env(1) expects KEY=VALUE; pass each as a separate list element
                # so the shell never interprets the value.
                _env_list.append(f"{k}={v}")
            cmd = ["sudo", "-n", "env"] + _env_list + ["bash", "-c", cmd]

        try:
            proc = subprocess.Popen(
                cmd, shell=(not _SUDO_OK),
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1, env=env if not _SUDO_OK else None,
            )
            for line in proc.stdout:
                line = line.rstrip("\n")
                if line:
                    yield _sse({"type": "log", "line": line})
            proc.wait()
            if proc.returncode == 0:
                # Post-install: copy go/cargo binaries to /usr/local/bin/
                # so they are accessible to all system users (e.g. zeekglare).
                _src = None
                if is_go_install:
                    _src = f"{_root_home}/go/bin/{tid}"
                elif is_cargo:
                    _src = f"{_root_home}/.cargo/bin/{tid}"
                if _src and _os.path.isfile(_src):
                    _dst = f"/usr/local/bin/{tid}"
                    try:
                        import shutil as _sh
                        if _SUDO_OK:
                            subprocess.run(
                                ["sudo", "-n", "cp", _src, _dst],
                                capture_output=True, check=True,
                            )
                            subprocess.run(
                                ["sudo", "-n", "chmod", "755", _dst],
                                capture_output=True, check=True,
                            )
                        else:
                            _sh.copy2(_src, _dst)
                            _os.chmod(_dst, 0o755)
                        yield _sse({"type": "log",
                                    "line": f"▸ Copied {tid} → /usr/local/bin/ (accessible to all users)"})
                    except Exception as cp_err:
                        yield _sse({"type": "log",
                                    "line": f"⚠ Could not copy to /usr/local/bin/: {cp_err}"})

                # Refresh path + mtime after update
                path = _find_tool_path(tid)
                mtime = None
                if path:
                    try: mtime = int(_os.path.getmtime(path))
                    except OSError: pass
                yield _sse({"type": "done", "success": True,
                            "line": f"✓ {label} updated successfully.",
                            "last_updated": mtime})
                audit("admin_tool_updated", f"Updated tool: {label} ({tool_id})",
                      user_id=g.current_user.id, username=g.current_user.username)
            else:
                yield _sse({"type": "done", "success": False,
                            "line": f"✗ {label} exited with code {proc.returncode}"})
        except Exception as e:
            yield _sse({"type": "done", "success": False, "line": f"✗ Error: {e}"})

    return Response(
        stream_with_context(_stream()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── Task monitoring (proxy to WatchDog) ──────────────────────────────────────

@admin_bp.route("/api/admin/tasks")
@admin_required
def all_tasks():
    """Proxy the WatchDog status endpoint for the admin dashboard."""
    import requests as _req
    cookies = {}
    auth_cookie = request.cookies.get("_zg_auth")
    if auth_cookie:
        cookies["_zg_auth"] = auth_cookie
    try:
        r = _req.get("http://127.0.0.1:5000/api/watchdog/status", timeout=3, cookies=cookies)
        return jsonify(r.json())
    except Exception as e:
        return jsonify({"error": str(e), "scans": [], "stats": {}}), 200


# ── System Health ────────────────────────────────────────────────────────────

@admin_bp.route("/api/admin/system-health")
@admin_required
def system_health():
    """Real-time system resource usage."""
    cpu_percent = psutil.cpu_percent(interval=0.3)
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    net = psutil.net_io_counters()
    boot = datetime.fromtimestamp(psutil.boot_time())
    uptime_sec = (datetime.utcnow() - boot).total_seconds()

    # Python process count
    python_procs = 0
    for p in psutil.process_iter(["name"]):
        try:
            if "python" in (p.info.get("name") or "").lower():
                python_procs += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    # Network connections count
    try:
        net_conns = len(psutil.net_connections(kind="inet"))
    except (psutil.AccessDenied, OSError):
        net_conns = -1

    # Top processes by CPU
    top_procs = []
    for p in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent"]):
        try:
            info = p.info
            if info["cpu_percent"] and info["cpu_percent"] > 0.1:
                top_procs.append(info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    top_procs.sort(key=lambda x: x.get("cpu_percent", 0), reverse=True)

    return jsonify({
        "cpu_percent": cpu_percent,
        "cpu_count": psutil.cpu_count(),
        "memory": {
            "total": mem.total,
            "used": mem.used,
            "available": mem.available,
            "percent": mem.percent,
        },
        "disk": {
            "total": disk.total,
            "used": disk.used,
            "free": disk.free,
            "percent": disk.percent,
        },
        "network": {
            "bytes_sent": net.bytes_sent,
            "bytes_recv": net.bytes_recv,
        },
        "uptime_seconds": int(uptime_sec),
        "hostname": socket.gethostname(),
        "platform": _platform.platform(),
        "python_version": _platform.python_version(),
        "top_processes": top_procs[:8],
    })


# ── Security Analytics ───────────────────────────────────────────────────────

@admin_bp.route("/api/admin/security-analytics")
@admin_required
def security_analytics():
    """Login attempt analytics for the past 7 days."""
    since = datetime.utcnow() - timedelta(days=7)

    # Daily login attempt counts
    daily = db.session.query(
        cast(LoginAttempt.timestamp, Date).label("day"),
        LoginAttempt.success,
        func.count().label("cnt"),
    ).filter(LoginAttempt.timestamp >= since).group_by("day", LoginAttempt.success).all()

    daily_stats = {}
    for row in daily:
        d = str(row.day)
        if d not in daily_stats:
            daily_stats[d] = {"success": 0, "failed": 0}
        if row.success:
            daily_stats[d]["success"] += row.cnt
        else:
            daily_stats[d]["failed"] += row.cnt

    # Top IPs with failed logins
    top_failed_ips = db.session.query(
        LoginAttempt.ip_address,
        func.count().label("cnt"),
    ).filter(
        LoginAttempt.success == False,  # noqa
        LoginAttempt.timestamp >= since,
    ).group_by(LoginAttempt.ip_address).order_by(func.count().desc()).limit(10).all()

    # Top targeted usernames
    top_usernames = db.session.query(
        LoginAttempt.username,
        func.count().label("cnt"),
    ).filter(
        LoginAttempt.success == False,  # noqa
        LoginAttempt.timestamp >= since,
    ).group_by(LoginAttempt.username).order_by(func.count().desc()).limit(10).all()

    # Hourly distribution (last 24h)
    since_24h = datetime.utcnow() - timedelta(hours=24)
    hourly = db.session.query(
        func.strftime("%H", LoginAttempt.timestamp).label("hour"),
        LoginAttempt.success,
        func.count().label("cnt"),
    ).filter(LoginAttempt.timestamp >= since_24h).group_by("hour", LoginAttempt.success).all()

    hourly_stats = {}
    for row in hourly:
        h = row.hour
        if h not in hourly_stats:
            hourly_stats[h] = {"success": 0, "failed": 0}
        hourly_stats[h]["success" if row.success else "failed"] += row.cnt

    recent_failed = LoginAttempt.query.filter_by(success=False).order_by(
        LoginAttempt.timestamp.desc()).limit(20).all()

    return jsonify({
        "daily_stats": daily_stats,
        "hourly_stats": hourly_stats,
        "top_failed_ips": [{"ip": r.ip_address, "count": r.cnt} for r in top_failed_ips],
        "top_targeted_users": [{"username": r.username, "count": r.cnt} for r in top_usernames],
        "recent_failed": [
            {"ip": a.ip_address, "username": a.username,
             "timestamp": a.timestamp.isoformat() if a.timestamp else None}
            for a in recent_failed
        ],
    })


# ── User Activity Stats ─────────────────────────────────────────────────────

@admin_bp.route("/api/admin/user-activity")
@admin_required
def user_activity():
    since = datetime.utcnow() - timedelta(days=30)
    activity = db.session.query(
        AuditLog.user_id, AuditLog.username,
        func.count().label("event_count"),
        func.max(AuditLog.timestamp).label("last_active"),
    ).filter(AuditLog.timestamp >= since).group_by(
        AuditLog.user_id, AuditLog.username
    ).order_by(func.count().desc()).all()

    action_breakdown = db.session.query(
        AuditLog.username, AuditLog.action, func.count().label("cnt"),
    ).filter(AuditLog.timestamp >= since).group_by(AuditLog.username, AuditLog.action).all()

    breakdown = {}
    for row in action_breakdown:
        u = row.username or "unknown"
        if u not in breakdown:
            breakdown[u] = {}
        breakdown[u][row.action] = row.cnt

    return jsonify({"users": [
        {"user_id": r.user_id, "username": r.username or "unknown",
         "event_count": r.event_count,
         "last_active": r.last_active.isoformat() if r.last_active else None,
         "actions": breakdown.get(r.username or "unknown", {})}
        for r in activity
    ]})


# ── Maintenance Mode ─────────────────────────────────────────────────────────

_MAINT_FILE = os.path.join(os.path.dirname(__file__), "..", "data", "maintenance.json")


def _maint_load():
    try:
        if os.path.exists(_MAINT_FILE):
            with open(_MAINT_FILE) as f:
                return json.load(f)
    except Exception:
        pass
    return {"enabled": False, "message": "", "set_by": "", "set_at": ""}


def _maint_save(data):
    os.makedirs(os.path.dirname(_MAINT_FILE), exist_ok=True)
    with open(_MAINT_FILE, "w") as f:
        json.dump(data, f)


@admin_bp.route("/api/admin/maintenance", methods=["GET"])
@admin_required
def get_maintenance():
    return jsonify(_maint_load())


@admin_bp.route("/api/admin/maintenance", methods=["POST"])
@admin_required
def set_maintenance():
    data = request.get_json(silent=True) or {}
    msg = (data.get("message") or "").strip()
    if not msg:
        msg = "Platform is undergoing maintenance. Please try again shortly."
    state = {
        "enabled": bool(data.get("enabled")),
        "message": msg,
        "set_by":  g.current_user.username,
        "set_at":  datetime.utcnow().isoformat(),
    }
    _maint_save(state)
    audit("admin_maintenance_toggled",
          f"Maintenance mode {'enabled' if state['enabled'] else 'disabled'}: {msg[:80]}",
          user_id=g.current_user.id, username=g.current_user.username)
    return jsonify({"ok": True, "state": state})


@admin_bp.route("/api/maintenance")
def public_maintenance():
    s = _maint_load()
    user = getattr(g, "current_user", None)
    return jsonify({
        "enabled":   bool(s.get("enabled")),
        "message":   s.get("message", ""),
        "is_admin":  bool(user and getattr(user, "role", "") == "admin"),
        "set_by":    s.get("set_by", ""),
    })


# ── Announcements ────────────────────────────────────────────────────────────

_announcements = []
_announce_counter = 0


@admin_bp.route("/api/admin/announcements", methods=["GET"])
@admin_required
def get_announcements():
    return jsonify(_announcements)


@admin_bp.route("/api/admin/announcements", methods=["POST"])
@admin_required
def create_announcement():
    global _announce_counter
    data = request.get_json(silent=True) or {}
    message = (data.get("message") or "").strip()
    atype = data.get("type", "info")
    if not message:
        return jsonify({"error": "Message is required."}), 400
    _announce_counter += 1
    ann = {"id": _announce_counter, "message": message, "type": atype,
           "created_at": datetime.utcnow().isoformat(), "created_by": g.current_user.username}
    _announcements.insert(0, ann)
    audit("admin_announcement_created", f"Announcement: {message[:80]}",
          user_id=g.current_user.id, username=g.current_user.username)
    return jsonify({"ok": True, "announcement": ann}), 201


@admin_bp.route("/api/admin/announcements/<int:aid>", methods=["DELETE"])
@admin_required
def delete_announcement(aid):
    global _announcements
    _announcements = [a for a in _announcements if a["id"] != aid]
    return jsonify({"ok": True})


@admin_bp.route("/api/announcements")
def public_announcements():
    """Active announcements for authenticated users."""
    user = getattr(g, "current_user", None)
    if not user:
        return jsonify([])
    return jsonify(_announcements[:5])


# ── Audit Log Export ─────────────────────────────────────────────────────────

@admin_bp.route("/api/admin/audit-logs/export")
@admin_required
def export_audit_logs():
    action_f = request.args.get("action")
    user_f = request.args.get("username")
    limit = min(int(request.args.get("limit", 5000)), 10000)
    q = AuditLog.query.order_by(AuditLog.timestamp.desc())
    if action_f:
        q = q.filter(AuditLog.action.ilike(f"%{action_f}%"))
    if user_f:
        q = q.filter(AuditLog.username.ilike(f"%{user_f}%"))
    logs = q.limit(limit).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Timestamp", "Username", "Action", "Details", "IP Address"])
    for l in logs:
        writer.writerow([l.timestamp.isoformat() if l.timestamp else "", l.username or "",
                         l.action, l.details or "", l.ip_address or ""])
    return Response(output.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=zeekglare-audit-logs.csv"})


# ── Bulk User Actions ────────────────────────────────────────────────────────

@admin_bp.route("/api/admin/users/bulk-action", methods=["POST"])
@admin_required
def bulk_user_action():
    data = request.get_json(silent=True) or {}
    action = data.get("action")
    user_ids = data.get("user_ids", [])
    if not user_ids:
        return jsonify({"error": "No users selected."}), 400
    if action not in ("suspend", "activate", "delete"):
        return jsonify({"error": "Invalid action."}), 400
    user_ids = [uid for uid in user_ids if uid != g.current_user.id]
    # Prevent removing the last admin
    if action in ("delete", "suspend"):
        remaining_admins = User.query.filter_by(role="admin").count()
        affected_admins = 0
        for uid in user_ids:
            u = User.query.get(uid)
            if u and u.role == "admin":
                affected_admins += 1
        if remaining_admins - affected_admins < 1:
            return jsonify({"error": "Cannot remove the last admin."}), 400
    affected = 0
    for uid in user_ids:
        user = User.query.get(uid)
        if not user:
            continue
        if action == "delete":
            db.session.delete(user)
        elif action == "suspend":
            user.status = "suspended"
        elif action == "activate":
            user.status = "active"
        affected += 1
    db.session.commit()
    audit(f"admin_bulk_{action}", f"Bulk {action}: {affected} users affected",
          user_id=g.current_user.id, username=g.current_user.username)
    return jsonify({"ok": True, "affected": affected})