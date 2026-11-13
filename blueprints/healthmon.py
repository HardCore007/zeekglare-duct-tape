"""Health Monitor — system health, service status, external API checks."""
import os
import time
import json
import socket
import shutil
import threading
import requests
from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify, g, render_template

from core.auth_utils import login_required, admin_required
from core.db import db
from core.models import User

healthmon_bp = Blueprint("healthmon", __name__)

# In-memory health history (last 24h, sampled every 5 min)
_HEALTH_HISTORY = []
_HISTORY_LOCK = threading.Lock()
_MAX_HISTORY = 288  # 24h * 12 samples/hour


def _now_iso():
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def _service_check(host: str, port: int, timeout: float = 2.0) -> dict:
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return {"reachable": True, "latency_ms": round(timeout * 1000, 1)}
    except Exception as e:
        return {"reachable": False, "error": str(e)}


def _http_check(url: str, timeout: int = 8, expected_status=None) -> dict:
    try:
        r = requests.get(url, timeout=timeout, allow_redirects=True)
        ok = r.status_code in (expected_status or [200, 204, 301, 302])
        return {"reachable": ok, "status": r.status_code, "latency_ms": round(r.elapsed.total_seconds() * 1000, 1)}
    except Exception as e:
        return {"reachable": False, "error": str(e)}


def _external_api_checks(user_settings: dict) -> dict:
    """Test a subset of external APIs using stored keys."""
    results = {}
    keys = user_settings or {}

    # Shodan
    if keys.get("shodan_api_key"):
        try:
            r = requests.get(f"https://api.shodan.io/api-info?key={keys['shodan_api_key']}", timeout=8)
            results["shodan"] = {"ok": r.status_code == 200, "status": r.status_code}
        except Exception as e:
            results["shodan"] = {"ok": False, "error": str(e)}
    else:
        results["shodan"] = {"ok": None, "note": "No API key"}

    # SecurityTrails
    if keys.get("securitytrails_api_key"):
        try:
            h = {"APIKEY": keys["securitytrails_api_key"]}
            r = requests.get("https://api.securitytrails.com/v1/account/usage", headers=h, timeout=8)
            results["securitytrails"] = {"ok": r.status_code == 200, "status": r.status_code}
        except Exception as e:
            results["securitytrails"] = {"ok": False, "error": str(e)}
    else:
        results["securitytrails"] = {"ok": None, "note": "No API key"}

    # OpenAI
    if keys.get("openai_api_key"):
        try:
            h = {"Authorization": f"Bearer {keys['openai_api_key']}"}
            r = requests.get("https://api.openai.com/v1/models", headers=h, timeout=8)
            results["openai"] = {"ok": r.status_code == 200, "status": r.status_code}
        except Exception as e:
            results["openai"] = {"ok": False, "error": str(e)}
    else:
        results["openai"] = {"ok": None, "note": "No API key"}

    # Anthropic
    if keys.get("anthropic_api_key"):
        try:
            h = {"x-api-key": keys["anthropic_api_key"], "anthropic-version": "2023-06-01"}
            r = requests.get("https://api.anthropic.com/v1/models", headers=h, timeout=8)
            results["anthropic"] = {"ok": r.status_code in (200, 401), "status": r.status_code}
        except Exception as e:
            results["anthropic"] = {"ok": False, "error": str(e)}
    else:
        results["anthropic"] = {"ok": None, "note": "No API key"}

    # Censys
    if keys.get("censys_api_id") and keys.get("censys_api_secret"):
        try:
            r = requests.get("https://search.censys.io/api/v2/hosts/search", auth=(keys["censys_api_id"], keys["censys_api_secret"]), params={"q": "8.8.8.8", "per_page": 1}, timeout=8)
            results["censys"] = {"ok": r.status_code in (200, 422), "status": r.status_code}
        except Exception as e:
            results["censys"] = {"ok": False, "error": str(e)}
    else:
        results["censys"] = {"ok": None, "note": "No API key"}

    return results


def _tool_availability() -> dict:
    """Check which common tools are available on PATH."""
    tools = {
        "nmap": "nmap", "masscan": "masscan", "rustscan": "rustscan",
        "naabu": "naabu", "subfinder": "subfinder", "amass": "amass",
        "nuclei": "nuclei", "nikto": "nikto", "ffuf": "ffuf",
        "httpx": "httpx", "gau": "gau", "waybackurls": "waybackurls",
        "sqlmap": "sqlmap", "wpscan": "wpscan", "git": "git",
        "python3": "python3", "go": "go", "docker": "docker",
        "node": "node", "npm": "npm",
    }
    env = os.environ.get("PATH", "")
    return {name: bool(shutil.which(cmd)) for name, cmd in tools.items()}


def _system_snapshot() -> dict:
    try:
        import psutil
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage("/")
        load = psutil.getloadavg() if hasattr(psutil, "getloadavg") else (0, 0, 0)
        boot = psutil.boot_time()
        uptime_sec = int(time.time() - boot)

        snapshot = {
            "timestamp": _now_iso(),
            "cpu_percent": psutil.cpu_percent(interval=0.5),
            "cpu_count": psutil.cpu_count(),
            "loadavg": [round(x, 2) for x in load],
            "memory": {
                "total_mb": round(mem.total / (1024 * 1024)),
                "available_mb": round(mem.available / (1024 * 1024)),
                "percent": mem.percent,
            },
            "disk": {
                "total_gb": round(disk.total / (1024 ** 3), 2),
                "free_gb": round(disk.free / (1024 ** 3), 2),
                "percent": round((disk.used / disk.total) * 100, 1),
            },
            "uptime_seconds": uptime_sec,
        }
    except Exception as e:
        snapshot = {"timestamp": _now_iso(), "error": str(e)}
    return snapshot


def _record_history():
    snap = _system_snapshot()
    with _HISTORY_LOCK:
        _HEALTH_HISTORY.append(snap)
        while len(_HEALTH_HISTORY) > _MAX_HISTORY:
            _HEALTH_HISTORY.pop(0)


# ── Routes ────────────────────────────────────────────────────────────────────

@healthmon_bp.route("/health")
@login_required
def health_page():
    return render_template("healthmon.html")


@healthmon_bp.route("/api/health/overview")
@login_required
def overview():
    snap = _system_snapshot()
    services = {
        "intel": _service_check("127.0.0.1", 5000),
        "xploiter": _service_check("127.0.0.1", 5001),
        "misc": _service_check("127.0.0.1", 5002),
        "nginx": _service_check("127.0.0.1", 80),
    }
    snap["services"] = services
    _record_history()
    return jsonify(snap)


@healthmon_bp.route("/api/health/services")
@login_required
def services_status():
    return jsonify({
        "intel": _service_check("127.0.0.1", 5000),
        "xploiter": _service_check("127.0.0.1", 5001),
        "misc": _service_check("127.0.0.1", 5002),
        "nginx_http": _service_check("127.0.0.1", 80),
        "nginx_alt": _service_check("127.0.0.1", 8080),
    })


@healthmon_bp.route("/api/health/external")
@login_required
def external_status():
    u = g.current_user
    settings = {}
    if u.settings_json:
        try:
            blob = json.loads(u.settings_json)
            if isinstance(blob, dict):
                settings = blob
        except Exception:
            pass

    return jsonify({
        "apis": _external_api_checks(settings),
        "platform": {
            "github": _http_check("https://api.github.com", timeout=5),
            "nvd": _http_check("https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1", timeout=10),
            "crtsh": _http_check("https://crt.sh?q=example.com", timeout=8),
        },
    })


@healthmon_bp.route("/api/health/tools")
@login_required
def tools_status():
    return jsonify({"tools": _tool_availability()})


@healthmon_bp.route("/api/health/history")
@admin_required
def history():
    hours = request.args.get("hours", "24")
    try:
        h = int(hours)
    except ValueError:
        h = 24
    cutoff = datetime.utcnow() - timedelta(hours=h)
    with _HISTORY_LOCK:
        filtered = [x for x in _HEALTH_HISTORY if datetime.fromisoformat(x["timestamp"].replace("Z", "+00:00")) >= cutoff]
        return jsonify({"samples": len(filtered), "history": filtered})


@healthmon_bp.route("/api/health/admin/all")
@admin_required
def admin_all():
    """Admin-only comprehensive health snapshot."""
    snap = _system_snapshot()
    snap["services"] = {
        "intel": _service_check("127.0.0.1", 5000),
        "xploiter": _service_check("127.0.0.1", 5001),
        "misc": _service_check("127.0.0.1", 5002),
        "nginx_http": _service_check("127.0.0.1", 80),
        "nginx_alt": _service_check("127.0.0.1", 8080),
    }
    snap["tools"] = _tool_availability()

    u = g.current_user
    settings = {}
    if u.settings_json:
        try:
            blob = json.loads(u.settings_json)
            if isinstance(blob, dict):
                settings = blob
        except Exception:
            pass
    snap["external_apis"] = _external_api_checks(settings)
    snap["platform_checks"] = {
        "github": _http_check("https://api.github.com", timeout=5),
        "nvd": _http_check("https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1", timeout=10),
        "crtsh": _http_check("https://crt.sh?q=example.com", timeout=8),
    }
    _record_history()
    return jsonify(snap)
