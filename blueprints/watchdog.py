"""WatchDog blueprint — Bird's-eye monitoring view of all active scans."""
import time
import requests
from flask import Blueprint, jsonify, render_template, g, request as flask_request
from core.auth_utils import login_required

from blueprints.domain      import dom_scans, lock  as dom_lock
from blueprints.ports       import _scans  as port_scans, _lock as port_lock
from blueprints.crawler     import _scans  as crawler_scans, _lock as crawler_lock
from blueprints.paramhawk   import _scans  as param_scans,   _lock as param_lock
from blueprints.threatblitz import _jobs   as tb_jobs,        _lock as tb_lock
from blueprints.fuzzer      import _jobs   as fuzz_jobs,      _lock as fuzz_lock
from blueprints.wpscan      import _jobs   as wp_jobs,        _lock as wp_lock

# Note: xploiter (5001) and misc (5002) run as separate processes → use HTTP polling

watchdog_bp = Blueprint("watchdog", __name__)

XPL_BASE  = "http://127.0.0.1:5001"
MISC_BASE = "http://127.0.0.1:5002"


def _now():
    return time.time()


def _user(r):
    """Extract user fields from a scan dict."""
    return {"user_id": r.get("user_id"), "username": r.get("username", "")}


def _summarise_domain():
    with dom_lock:
        items = list(dom_scans.items())
    result = []
    now = _now()
    for sid, r in items:
        events = r.get("events", [])
        subs   = sum(1 for e in events if e and e.get("type") == "subdomain")
        live   = sum(1 for e in events if e and e.get("type") == "subdomain" and e.get("http_live"))
        result.append({
            "id": sid, "source": "zeekglare", "type": "domain",
            "label": "Domain Mapper",
            "target": r.get("domain", ""),
            "done": r.get("done", False),
            "findings": subs,
            "meta": f"{subs} subs · {live} live",
            "event_count": len(events),
            "started_at": r.get("started_at", now),
            "elapsed": round(now - r.get("started_at", now)),
            **_user(r),
        })
    return result


def _summarise_ports():
    with port_lock:
        items = list(port_scans.items())
    result = []
    now = _now()
    for sid, r in items:
        events = r.get("events", [])
        open_p = sum(1 for e in events if e and e.get("type") == "open_port")
        targets = r.get("targets") or []
        tgt = targets[0] if targets else ""
        if len(targets) > 1:
            tgt += f" +{len(targets)-1}"
        result.append({
            "id": sid, "source": "zeekglare", "type": "ports",
            "label": "Port Scanner",
            "target": tgt,
            "done": r.get("done", False),
            "findings": open_p,
            "meta": f"{open_p} open ports",
            "event_count": len(events),
            "started_at": r.get("started_at", now),
            "elapsed": round(now - r.get("started_at", now)),
            **_user(r),
        })
    return result


def _summarise_crawler():
    with crawler_lock:
        items = list(crawler_scans.items())
    result = []
    now = _now()
    for sid, r in items:
        events = r.get("events", [])
        urls   = sum(1 for e in events if e and e.get("type") in ("url", "endpoint"))
        result.append({
            "id": sid, "source": "zeekglare", "type": "crawler",
            "label": "Crawler",
            "target": r.get("target", ""),
            "done": r.get("done", False),
            "findings": urls,
            "meta": f"{urls} URLs found",
            "event_count": len(events),
            "started_at": r.get("started_at", now),
            "elapsed": round(now - r.get("started_at", now)),
            **_user(r),
        })
    return result


def _summarise_paramhawk():
    with param_lock:
        items = list(param_scans.items())
    result = []
    now = _now()
    for sid, r in items:
        events  = r.get("events", [])
        params  = sum(1 for e in events if e and e.get("type") == "param")
        targets = r.get("targets") or []
        result.append({
            "id": sid, "source": "zeekglare", "type": "paramhawk",
            "label": "ParamHawk",
            "target": targets[0] if targets else "",
            "done": r.get("done", False),
            "findings": params,
            "meta": f"{params} params found",
            "event_count": len(events),
            "started_at": r.get("started_at", now),
            "elapsed": round(now - r.get("started_at", now)),
            **_user(r),
        })
    return result


def _summarise_threatblitz():
    with tb_lock:
        items = list(tb_jobs.items())
    result = []
    now = _now()
    for jid, r in items:
        events  = r.get("events", [])
        vulns   = sum(1 for e in events if e and e.get("type") in ("vuln", "finding"))
        targets = r.get("targets") or []
        result.append({
            "id": jid, "source": "zeekglare", "type": "threatblitz",
            "label": f"ThreatBlitz · {r.get('tool','multi')}",
            "target": targets[0] if targets else "",
            "done": r.get("done", False),
            "findings": vulns,
            "meta": f"{vulns} vulns",
            "event_count": len(events),
            "started_at": r.get("started_at", now),
            "elapsed": round(now - r.get("started_at", now)),
            **_user(r),
        })
    return result


def _summarise_fuzzer():
    with fuzz_lock:
        items = list(fuzz_jobs.items())
    result = []
    now = _now()
    for jid, r in items:
        events = r.get("events", [])
        hits   = sum(1 for e in events if e and e.get("type") == "result")
        result.append({
            "id": jid, "source": "zeekglare", "type": "fuzzer",
            "label": f"Fuzzer · {r.get('tool','ffuf')}",
            "target": r.get("target", ""),
            "done": r.get("done", False),
            "findings": hits,
            "meta": f"{hits} hits",
            "event_count": len(events),
            "started_at": r.get("started_at", now),
            "elapsed": round(now - r.get("started_at", now)),
            **_user(r),
        })
    return result


def _summarise_wpscan():
    with wp_lock:
        items = list(wp_jobs.items())
    result = []
    now = _now()
    for jid, r in items:
        events   = r.get("events", [])
        findings = r.get("findings") or []
        result.append({
            "id": jid, "source": "zeekglare", "type": "wpscan",
            "label": f"WPScan · {r.get('mode','vuln')}",
            "target": r.get("target", ""),
            "done": r.get("done", False),
            "findings": len(findings),
            "meta": f"{len(findings)} findings",
            "event_count": len(events),
            "started_at": r.get("started_at", now),
            "elapsed": round(now - r.get("started_at", now)),
            **_user(r),
        })
    return result


def _poll_remote(base_url, endpoint):
    """HTTP poll a remote dashboard watchdog endpoint, forwarding auth cookie."""
    try:
        cookies = {}
        auth_cookie = flask_request.cookies.get("_zg_auth")
        if auth_cookie:
            cookies["_zg_auth"] = auth_cookie
        r = requests.get(f"{base_url}{endpoint}", timeout=2, cookies=cookies)
        if r.ok:
            return r.json()
    except Exception:
        pass
    return []


@watchdog_bp.route("/watchdog")
@login_required
def watchdog_page():
    return render_template("watchdog.html")


@watchdog_bp.route("/api/watchdog/clear", methods=["POST"])
@login_required
def watchdog_clear():
    """Remove completed scans — user-isolated (admin clears all)."""
    user = getattr(g, "current_user", None)
    is_admin = user and user.role == "admin"
    uid = user.id if user else None
    removed = 0

    def _owned(r):
        return is_admin or r.get("user_id") == uid

    with dom_lock:
        done_ids = [sid for sid, r in dom_scans.items() if r.get("done") and _owned(r)]
        for sid in done_ids:
            del dom_scans[sid]
        removed += len(done_ids)

    with port_lock:
        done_ids = [sid for sid, r in port_scans.items() if r.get("done") and _owned(r)]
        for sid in done_ids:
            del port_scans[sid]
        removed += len(done_ids)

    with crawler_lock:
        done_ids = [sid for sid, r in crawler_scans.items() if r.get("done") and _owned(r)]
        for sid in done_ids:
            del crawler_scans[sid]
        removed += len(done_ids)

    with param_lock:
        done_ids = [sid for sid, r in param_scans.items() if r.get("done") and _owned(r)]
        for sid in done_ids:
            del param_scans[sid]
        removed += len(done_ids)

    with tb_lock:
        done_ids = [jid for jid, r in tb_jobs.items() if r.get("done") and _owned(r)]
        for jid in done_ids:
            del tb_jobs[jid]
        removed += len(done_ids)

    with fuzz_lock:
        done_ids = [jid for jid, r in fuzz_jobs.items() if r.get("done") and _owned(r)]
        for jid in done_ids:
            del fuzz_jobs[jid]
        removed += len(done_ids)

    with wp_lock:
        done_ids = [jid for jid, r in wp_jobs.items() if r.get("done") and _owned(r)]
        for jid in done_ids:
            del wp_jobs[jid]
        removed += len(done_ids)

    # Also ask remote dashboards to clear (they enforce their own auth via cookie)
    cookies = {}
    auth_cookie = flask_request.cookies.get("_zg_auth")
    if auth_cookie:
        cookies["_zg_auth"] = auth_cookie
    for base, ep in [(XPL_BASE, "/api/xploiter/clear"), (MISC_BASE, "/api/misc/clear")]:
        try:
            requests.post(f"{base}{ep}", timeout=2, cookies=cookies)
        except Exception:
            pass

    return jsonify({"cleared": removed, "ok": True})


@watchdog_bp.route("/api/watchdog/status")
@login_required
def watchdog_status():
    """Aggregate status from all scan sources — user-isolated."""
    user = getattr(g, "current_user", None)
    is_admin = user and user.role == "admin"
    uid = user.id if user else None

    all_scans = (
        _summarise_domain()
        + _summarise_ports()
        + _summarise_crawler()
        + _summarise_paramhawk()
        + _summarise_threatblitz()
        + _summarise_fuzzer()
        + _summarise_wpscan()
        + _poll_remote(XPL_BASE, "/api/xploiter/watchdog")
        + _poll_remote(MISC_BASE, "/api/misc/watchdog")
    )
    # Filter: non-admin users only see their own scans
    if is_admin:
        scans = all_scans
    else:
        scans = [s for s in all_scans if s.get("user_id") == uid]

    active         = [s for s in scans if not s.get("done")]
    completed      = [s for s in scans if s.get("done")]
    total_findings = sum(s.get("findings", 0) for s in scans)
    return jsonify({
        "scans": scans,
        "stats": {
            "total":     len(scans),
            "active":    len(active),
            "completed": len(completed),
            "findings":  total_findings,
        },
        "ts": time.time(),
    })
