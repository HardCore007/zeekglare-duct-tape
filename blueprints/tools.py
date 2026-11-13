"""Tools blueprint — screenshots, subdomain takeover detection, system health."""
import os, shutil, threading, time
from flask import Blueprint, request, jsonify
from services.screenshot import take_screenshot, batch_screenshots
from services.takeover import check_subdomain_takeover
from core.auth_utils import login_required

tools_bp = Blueprint("tools", __name__)


@tools_bp.route("/api/tools/screenshot", methods=["POST"])
def screenshot_route():
    body = request.get_json(silent=True) or {}
    url = (body.get("url") or "").strip()
    if not url:
        return jsonify({"error": "url required"}), 400
    result = take_screenshot(url)
    return jsonify(result)


@tools_bp.route("/api/tools/screenshot/batch", methods=["POST"])
def screenshot_batch():
    body = request.get_json(silent=True) or {}
    urls = body.get("urls", [])
    if not urls:
        return jsonify({"error": "urls list required"}), 400
    results = batch_screenshots(urls)
    return jsonify({"screenshots": results, "count": len(results)})


@tools_bp.route("/api/tools/takeover", methods=["POST"])
def takeover_route():
    body = request.get_json(silent=True) or {}
    subdomains = body.get("subdomains", [])
    if not subdomains:
        return jsonify({"error": "subdomains list required"}), 400
    findings = check_subdomain_takeover(subdomains)
    return jsonify({"findings": findings, "count": len(findings),
                    "checked": len(subdomains[:60])})


# ── System Health Endpoint ────────────────────────────────────────────────────

_HEALTH_TOOLS = [
    ("nmap",        "Port Scanner"),
    ("ffuf",        "PathStorm / Fuzzer"),
    ("subfinder",   "Subdomain Enum"),
    ("httpx",       "HTTP Probing"),
    ("nuclei",      "Vulnerability Scanner"),
    ("katana",      "Crawler"),
    ("amass",       "Subdomain Enum"),
    ("waybackurls", "Wayback Recon"),
    ("gau",         "URL Archiver"),
    ("dalfox",      "XSS Scanner"),
    ("wpprobe",     "WP Scanner"),
    ("wpscan",      "WP Scanner"),
    ("sqlmap",      "SQL Injection"),
    ("nikto",       "Web Scanner"),
    ("dirsearch",   "Dir Brute"),
    ("gobuster",    "Dir Brute"),
    ("whatweb",     "Tech Detect"),
    ("wafw00f",     "WAF Detect"),
    ("arjun",       "Param Finder"),
]


@tools_bp.route("/api/tools/health")
@login_required
def system_health():
    """Quick health check — tool availability, disk, memory."""
    tools = []
    for binary, category in _HEALTH_TOOLS:
        path = shutil.which(binary) or os.path.expanduser(f"~/go/bin/{binary}")
        tools.append({
            "name": binary,
            "category": category,
            "installed": bool(path and os.path.isfile(path)),
        })
    installed = sum(1 for t in tools if t["installed"])

    # Disk usage
    try:
        st = os.statvfs("/")
        disk_total = st.f_blocks * st.f_frsize
        disk_free  = st.f_bavail * st.f_frsize
    except Exception:
        disk_total = disk_free = 0

    # Session count
    from core.session_manager import SessionManager
    sessions = len(list(SessionManager.list_all(admin=True)))

    return jsonify({
        "tools": tools,
        "tools_installed": installed,
        "tools_total": len(tools),
        "disk_total_gb": round(disk_total / (1024**3), 1),
        "disk_free_gb":  round(disk_free / (1024**3), 1),
        "sessions_saved": sessions,
        "uptime_s": int(time.time() - _BOOT_TIME),
    })


_BOOT_TIME = time.time()


# ── Active Scans aggregator ─────────────────────────────────────────────────
# Collects currently running scans from every blueprint that exposes an in-memory
# `_jobs` dict with `{done, tool, target/targets, started_at}` entries, so the
# sidebar widget can show a live feed of what's running across the platform.

def _collect_active_scans():
    out = []
    now = time.time()

    def _is_running(j):
        if not isinstance(j, dict):
            return False
        # Explicit done flags
        if j.get("done") or j.get("finished") or j.get("completed"):
            return False
        status = (j.get("status") or "").lower()
        if status in ("done", "finished", "completed", "error", "failed",
                      "cancelled", "canceled", "stopped"):
            return False
        # If a process handle is attached and exited, it's done
        proc = j.get("proc")
        if proc is not None:
            try:
                if proc.poll() is not None:
                    return False
            except Exception:
                pass
        return True

    def _add(source, jobs_dict, jobs_lock=None, default_tool=None, extra_target_keys=None):
        if jobs_dict is None:
            return
        try:
            if jobs_lock is not None:
                try:
                    jobs_lock.acquire()
                except Exception:
                    jobs_lock = None
            for jid, j in list(jobs_dict.items()):
                if not _is_running(j):
                    continue
                target = j.get("target") or j.get("host") or j.get("url") or j.get("domain") or j.get("country") or ""
                if not target and extra_target_keys:
                    for k in extra_target_keys:
                        v = j.get(k)
                        if v:
                            target = v
                            break
                if not target:
                    tgts = j.get("targets") or j.get("hosts") or []
                    if isinstance(tgts, (list, tuple)) and tgts:
                        target = str(tgts[0]) + (f" (+{len(tgts)-1})" if len(tgts) > 1 else "")
                started = (j.get("started_at") or j.get("start_time")
                           or j.get("created_at") or j.get("started") or 0)
                try:
                    started = float(started)
                except Exception:
                    started = 0
                elapsed = int(now - started) if started else 0
                status = (j.get("status") or j.get("phase") or "running").lower()
                progress = j.get("progress")
                out.append({
                    "id": str(jid),
                    "source": source,
                    "tool": (j.get("tool") or default_tool or source).lower(),
                    "target": str(target)[:120] or "(no target)",
                    "mode": j.get("mode") or j.get("profile") or "",
                    "username": j.get("username") or "",
                    "status": status,
                    "progress": progress if isinstance(progress, (int, float)) else None,
                    "elapsed_s": elapsed,
                })
        except Exception:
            pass
        finally:
            if jobs_lock is not None:
                try:
                    jobs_lock.release()
                except Exception:
                    pass

    # Blueprints exposing an in-memory jobs/scans dict.
    # (module, jobs_attr, lock_attr, display_tool, extra_target_keys)
    _BP_SOURCES = [
        ("wpscan",      "_jobs",     "_lock", None,         None),
        ("threatblitz", "_jobs",     "_lock", None,         None),
        ("fuzzer",      "_jobs",     "_lock", None,         None),
        ("ports",       "_scans",    "_lock", "ports",      None),
        ("paramhawk",   "_scans",    "_lock", "paramhawk",  None),
        ("crawler",     "_scans",    "_lock", "crawler",    None),
        ("sudomy",      "_scans",    "_lock", "sudomy",     None),
        ("cve",         "_scans",    "_lock", "cve",        None),
        ("ipmapper",    "_scans",    "_lock", "ipmapper",   None),
        ("jsanalysis",  "_scans",    "_lock", "jsintel",    None),
        ("recon_extra", "_scans",    "_lock", "recon",      None),
        # Unprefixed naming — ASN / Domain / Recon / DNS
        ("asn",         "scans",     "lock",  "asn",        ["country"]),
        ("domain",      "dom_scans", "lock",  "domain",     ["domain"]),
        ("recon",       "recon_scans", "lock","reconftw",   ["domain"]),
        ("dns",         "dns_scans", "lock",  "dns",        ["domain", "target"]),
    ]
    import importlib
    for modname, jobs_attr, lock_attr, default_tool, extra_keys in _BP_SOURCES:
        try:
            mod = importlib.import_module(f"blueprints.{modname}")
            jobs = getattr(mod, jobs_attr, None)
            lock = getattr(mod, lock_attr, None)
            _add(modname, jobs, lock, default_tool=default_tool, extra_target_keys=extra_keys)
        except Exception:
            pass

    out.sort(key=lambda x: -x["elapsed_s"])
    return out


@tools_bp.route("/api/scans/active")
@login_required
def active_scans():
    scans = _collect_active_scans()
    return jsonify({"scans": scans, "total": len(scans)})
