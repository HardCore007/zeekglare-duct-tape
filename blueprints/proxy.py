"""Proxy settings blueprint — admin-gated SOCKS5/HTTP proxy configuration."""
from flask import Blueprint, request, jsonify, g
from core.auth_utils import login_required
from core import proxy_config

proxy_bp = Blueprint("proxy_settings", __name__)


def _require_admin():
    u = getattr(g, "current_user", None)
    return u and getattr(u, "role", "") == "admin"


@proxy_bp.route("/api/settings/proxy/status", methods=["GET"])
@login_required
def proxy_status():
    """Non-secret status — any authed user may read (used by the UI badge)."""
    return jsonify(proxy_config.public_status())


@proxy_bp.route("/api/settings/proxy", methods=["GET"])
@login_required
def proxy_get():
    if not _require_admin():
        return jsonify({"error": "admin required"}), 403
    return jsonify(proxy_config.admin_view())


@proxy_bp.route("/api/settings/proxy", methods=["POST"])
@login_required
def proxy_save():
    if not _require_admin():
        return jsonify({"error": "admin required"}), 403
    body = request.get_json(silent=True) or {}
    # Accept incoming fields; ignore mask placeholder "••••••"
    incoming = {}
    for k in ("enabled", "type", "host", "port", "username", "password", "remote_dns"):
        if k in body:
            incoming[k] = body[k]
    # If password is the mask placeholder, preserve existing value
    if incoming.get("password") in ("••••••", "", None):
        incoming.pop("password", None)
    # Basic validation when enabling
    if incoming.get("enabled"):
        host = (incoming.get("host") or proxy_config.get_config().get("host") or "").strip()
        try:
            port = int(incoming.get("port") or proxy_config.get_config().get("port") or 0)
        except Exception:
            port = 0
        if not host or not (1 <= port <= 65535):
            return jsonify({"error": "host and port (1-65535) required to enable"}), 400
    cfg = proxy_config.save_config(incoming)
    return jsonify({"ok": True, "config": proxy_config.admin_view(),
                    "status": proxy_config.public_status()})


@proxy_bp.route("/api/settings/proxy/test", methods=["POST"])
@login_required
def proxy_test():
    """Verify the proxy by fetching a public IP echo. Admin only."""
    if not _require_admin():
        return jsonify({"error": "admin required"}), 403
    body = request.get_json(silent=True) or {}
    # Allow testing an ad-hoc config without saving it. If body has host+port,
    # build the URL from body; otherwise use the saved config.
    test_url_override = None
    if body.get("host") and body.get("port"):
        from urllib.parse import quote
        scheme = (body.get("type") or "socks5").lower()
        if scheme == "socks5" and body.get("remote_dns", True):
            scheme = "socks5h"
        user = (body.get("username") or "").strip()
        pw   = body.get("password") or ""
        # If password is the mask placeholder, pull from saved config
        if pw == "••••••":
            pw = proxy_config.get_config().get("password", "")
        auth = ""
        if user:
            auth = f"{quote(user, safe='')}:{quote(pw, safe='')}@" if pw else f"{quote(user, safe='')}@"
        test_url_override = f"{scheme}://{auth}{body['host']}:{body['port']}"

    import requests  # relies on requests[socks] being installed
    proxies = None
    if test_url_override:
        proxies = {"http": test_url_override, "https": test_url_override}
    else:
        proxies = proxy_config.get_requests_proxies()
    if not proxies:
        return jsonify({"ok": False, "error": "no proxy configured"}), 400

    import time as _t
    probe_urls = ["https://api.ipify.org?format=json", "https://httpbin.org/ip"]
    last_err = None
    for url in probe_urls:
        t0 = _t.time()
        try:
            r = requests.get(url, proxies=proxies, timeout=12,
                             headers={"User-Agent": "ZeekGlare/ProxyTest"})
            ms = int((_t.time() - t0) * 1000)
            if r.status_code == 200:
                try:
                    data = r.json()
                except Exception:
                    data = {"raw": r.text[:200]}
                ip = data.get("ip") or data.get("origin") or ""
                return jsonify({"ok": True, "ip": ip, "latency_ms": ms, "probe": url})
            last_err = f"HTTP {r.status_code} from {url}"
        except Exception as e:
            last_err = f"{type(e).__name__}: {e}"
    return jsonify({"ok": False, "error": last_err or "proxy test failed"}), 502
