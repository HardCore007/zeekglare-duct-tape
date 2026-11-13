"""Sessions CRUD blueprint — user-isolated."""
from flask import Blueprint, request, jsonify, g, Response
from core.session_manager import SessionManager
from core.auth_utils import login_required
from services.session_diff import compare_sessions
from services.report_generator import generate_report

sessions_bp = Blueprint("sessions", __name__)


def _ctx():
    """Return (user_id, is_admin) for the current request."""
    u = getattr(g, "current_user", None)
    if not u:
        return None, False
    return u.id, (u.role == "admin")


@sessions_bp.route("/api/sessions", methods=["GET"])
@login_required
def list_sessions():
    uid, is_admin = _ctx()
    return jsonify(SessionManager.list_all(user_id=uid, admin=is_admin))


@sessions_bp.route("/api/sessions/<sid>", methods=["GET"])
@login_required
def get_session(sid):
    uid, is_admin = _ctx()
    s = SessionManager.get(sid, user_id=uid, admin=is_admin)
    if not s:
        return jsonify({"error": "Session not found"}), 404
    return jsonify(s)


@sessions_bp.route("/api/sessions/<sid>", methods=["DELETE"])
@login_required
def delete_session(sid):
    uid, is_admin = _ctx()
    ok = SessionManager.delete(sid, user_id=uid, admin=is_admin)
    if not ok:
        return jsonify({"error": "Session not found or access denied"}), 404
    return jsonify({"ok": True})


@sessions_bp.route("/api/sessions", methods=["POST"])
@login_required
def save_session():
    """Idempotent save — collapses duplicate writes from frontend+backend.

    Many scans save twice: once authoritatively from the backend blueprint
    when the scan stream finishes, and once from the frontend's SSE-done
    handler. Both paths used to create separate UUIDs → duplicate cards.
    Now we look for an existing session matching (type, target, user_id)
    created in the last 90s and update it instead of creating new.
    """
    uid, is_admin = _ctx()
    body = request.get_json(silent=True) or {}
    scan_type = (body.get("type") or "").strip()
    target    = (body.get("target") or "").strip()
    name      = (body.get("name") or "").strip() or f"{scan_type} — {target}"
    summary   = body.get("summary") or {}
    data      = body.get("data") or {}
    u = getattr(g, "current_user", None)
    explicit_id = (body.get("id") or "").strip()

    import time as _t, uuid
    if explicit_id:
        # Caller knows the id — straight save.
        s = SessionManager.save(
            scan_id=explicit_id, scan_type=scan_type, target=target,
            name=name, summary=summary, data=data,
            user_id=uid, username=getattr(u, "username", ""),
        )
        return jsonify({"ok": True, "session": s, "deduped": False})

    # Look for a recent session of the same (type, target) for this user.
    # Backend authoritative saves create the canonical session; this POST
    # path then collapses into it instead of creating a duplicate.
    DEDUP_WINDOW_SECONDS = 90
    now = _t.time()
    existing = None
    try:
        for s in SessionManager.list_all(user_id=uid, admin=is_admin):
            if s.get("type") != scan_type:
                continue
            if (s.get("target") or "") != target:
                continue
            age = now - (s.get("created_at") or 0)
            if 0 <= age <= DEDUP_WINDOW_SECONDS:
                existing = s; break
    except Exception:
        existing = None

    if existing:
        # Merge the frontend-supplied summary/data into the canonical record.
        # Frontend often has lighter info than the backend authoritative save,
        # so we only apply non-empty patches and never overwrite richer data.
        patch = {}
        if summary and not existing.get("summary"):
            patch["summary"] = summary
        if data and not (existing.get("data") or {}):
            patch["data"] = data
        if patch:
            SessionManager.update(existing["id"], patch)
        return jsonify({"ok": True, "session": existing, "deduped": True})

    scan_id = str(uuid.uuid4())[:8]
    s = SessionManager.save(
        scan_id=scan_id, scan_type=scan_type, target=target,
        name=name, summary=summary, data=data,
        user_id=uid, username=getattr(u, "username", ""),
    )
    return jsonify({"ok": True, "session": s, "deduped": False})


@sessions_bp.route("/api/sessions/<sid>", methods=["PATCH"])
@login_required
def rename_session(sid):
    uid, is_admin = _ctx()
    body = request.get_json(silent=True) or {}
    name = (body.get("name") or "").strip()
    if not name:
        return jsonify({"error": "Name is required"}), 400
    ok = SessionManager.rename(sid, name, user_id=uid, admin=is_admin)
    if not ok:
        return jsonify({"error": "Session not found or access denied"}), 404
    return jsonify({"ok": True, "name": name})


@sessions_bp.route("/api/sessions/<sid>/notes", methods=["GET"])
@login_required
def get_notes(sid):
    uid, is_admin = _ctx()
    s = SessionManager.get(sid, user_id=uid, admin=is_admin)
    if not s:
        return jsonify({"error": "Session not found"}), 404
    return jsonify({"notes": s.get("notes", "")})


@sessions_bp.route("/api/sessions/<sid>/notes", methods=["PUT"])
@login_required
def save_notes(sid):
    uid, is_admin = _ctx()
    # Verify access first
    s = SessionManager.get(sid, user_id=uid, admin=is_admin)
    if not s:
        return jsonify({"error": "Session not found or access denied"}), 404
    body = request.get_json(silent=True) or {}
    notes = body.get("notes", "")
    SessionManager.update(sid, {"notes": notes})
    return jsonify({"ok": True})


@sessions_bp.route("/api/sessions/compare", methods=["POST"])
@login_required
def compare_sessions_route():
    body = request.get_json(silent=True) or {}
    sid_a = body.get("session_a", "").strip()
    sid_b = body.get("session_b", "").strip()
    if not sid_a or not sid_b:
        return jsonify({"error": "Both session_a and session_b required"}), 400
    try:
        diff = compare_sessions(sid_a, sid_b)
        return jsonify(diff)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@sessions_bp.route("/api/sessions/timeline", methods=["GET"])
@login_required
def session_timeline():
    """Get timeline of all sessions for visualization."""
    uid, is_admin = _ctx()
    sessions = SessionManager.list_all(user_id=uid, admin=is_admin)
    timeline = []
    for s in sessions:
        entry = {
            "id": s.get("id", ""),
            "type": s.get("type", ""),
            "target": s.get("target", ""),
            "name": s.get("name", ""),
            "created_at": s.get("created_at", 0),
            "summary": s.get("summary", {}),
        }
        # Extract key metrics per type
        sm = s.get("summary", {})
        if s["type"] == "asn":
            entry["metric"] = sm.get("total_asns", 0)
            entry["metric_label"] = "ASNs"
        elif s["type"] == "domain":
            entry["metric"] = sm.get("total_subdomains", 0)
            entry["metric_label"] = "Subdomains"
        elif s["type"] == "ipscope":
            entry["metric"] = sm.get("unique_ips", 0)
            entry["metric_label"] = "IPs"
        elif s["type"] == "ports":
            entry["metric"] = sm.get("total_ports", 0)
            entry["metric_label"] = "Ports"
        elif s["type"] == "threatblitz":
            entry["metric"] = sm.get("total_findings", 0)
            entry["metric_label"] = "Findings"
        else:
            entry["metric"] = 0
            entry["metric_label"] = ""
        timeline.append(entry)

    timeline.sort(key=lambda x: x.get("created_at", 0))
    return jsonify(timeline)


@sessions_bp.route("/api/sessions/tech-aggregate", methods=["GET"])
@login_required
def tech_aggregate():
    """Aggregate technology fingerprints across all domain sessions."""
    uid, is_admin = _ctx()
    sessions = SessionManager.list_all(user_id=uid, admin=is_admin)

    tech_map = {}   # tech -> list of domains
    waf_map = {}    # waf -> list of domains
    cms_map = {}    # cms -> list of domains
    all_domains = []

    for s in sessions:
        if s.get("type") != "domain":
            continue
        data = s.get("data", {})
        for e in data.get("entries", []):
            dom = e.get("domain", "")
            if not dom:
                continue
            entry = {
                "domain": dom, "ip": e.get("ip", ""),
                "http_live": e.get("http_live", False),
                "score": e.get("score", 0),
                "session_id": s.get("id", ""),
                "session_name": s.get("name", ""),
            }
            all_domains.append(entry)

            for t in e.get("tech", []):
                tech_map.setdefault(t, []).append(entry)
            waf = e.get("waf", "")
            if waf:
                waf_map.setdefault(waf, []).append(entry)
            cms = e.get("cms", "")
            if cms:
                cms_map.setdefault(cms, []).append(entry)

    return jsonify({
        "technologies": {k: {"count": len(v), "domains": v[:50]} for k, v in
                        sorted(tech_map.items(), key=lambda x: -len(x[1]))},
        "wafs": {k: {"count": len(v), "domains": v[:50]} for k, v in
                sorted(waf_map.items(), key=lambda x: -len(x[1]))},
        "cms": {k: {"count": len(v), "domains": v[:50]} for k, v in
               sorted(cms_map.items(), key=lambda x: -len(x[1]))},
        "total_domains": len(all_domains),
    })


@sessions_bp.route("/api/sessions/correlate/<ip_or_domain>", methods=["GET"])
@login_required
def correlate_asset(ip_or_domain):
    """Cross-reference an IP or domain across all sessions."""
    uid, is_admin = _ctx()
    sessions = SessionManager.list_all(user_id=uid, admin=is_admin)
    target = ip_or_domain.strip().lower()
    matches = []

    for s in sessions:
        data = s.get("data", {})
        stype = s.get("type", "")
        base = {"session_id": s.get("id"), "session_name": s.get("name", ""),
                "session_type": stype, "created_at": s.get("created_at", 0)}

        if stype == "asn":
            for a in data.get("asn_data", []):
                domains = sum((v for v in (a.get("critical") or {}).values()), [])
                prefixes = a.get("prefixes_v4", [])
                if target in [d.lower() for d in domains]:
                    matches.append({**base, "context": f"Domain in AS{a.get('asn')} ({a.get('name','')})",
                                   "category": a.get("category", "")})
                for p in prefixes:
                    if target in p:
                        matches.append({**base, "context": f"In prefix {p} of AS{a.get('asn')}"})
        elif stype == "domain":
            for e in data.get("entries", []):
                if target in (e.get("domain","")).lower() or target == (e.get("ip","")).lower():
                    matches.append({**base, "context": f"Subdomain: {e.get('domain','')} → {e.get('ip','')}",
                                   "score": e.get("score", 0), "waf": e.get("waf",""), "tech": e.get("tech",[])})
        elif stype == "ipscope":
            for e in data.get("entries", []):
                if target == (e.get("ip","")).lower():
                    matches.append({**base, "context": f"IP with {len(e.get('ports',[]))} ports, risk: {e.get('risk','')}",
                                   "ports": e.get("ports",[]), "risk": e.get("risk","")})
        elif stype == "ports":
            for h, hdata in data.get("results", {}).items():
                if target == h.lower():
                    matches.append({**base, "context": f"Port scan: {len(hdata.get('ports',[]))} open ports",
                                   "ports": hdata.get("ports", [])})
        elif stype == "threatblitz":
            for r in data.get("results", []):
                if target in (r.get("host","")).lower():
                    matches.append({**base, "context": f"Vulnerability: {r.get('template','')} [{r.get('severity','')}]",
                                   "severity": r.get("severity","")})

    return jsonify({"target": ip_or_domain, "matches": matches, "total": len(matches)})


@sessions_bp.route("/api/sessions/report", methods=["POST"])
@login_required
def generate_report_route():
    """Generate a professional report from selected sessions."""
    uid, is_admin = _ctx()
    body = request.get_json(silent=True) or {}
    session_ids = body.get("session_ids", [])
    op_name = body.get("operation_name", "Security Assessment")
    op_target = body.get("target", "")
    include_exec = body.get("include_executive_summary", True)
    include_methodology = body.get("include_methodology", True)
    include_risk = body.get("include_risk_matrix", True)
    include_findings = body.get("include_findings", True)
    include_recommendations = body.get("include_recommendations", True)
    company = (body.get("company") or "ZeekGlare Intelligence").strip() or "ZeekGlare Intelligence"
    classification = (body.get("classification") or "CONFIDENTIAL").strip() or "CONFIDENTIAL"
    fmt = body.get("format", "html")

    if not session_ids:
        return jsonify({"error": "No sessions selected"}), 400

    # Fetch all selected sessions with ownership check
    sessions = []
    for sid in session_ids:
        s = SessionManager.get(sid, user_id=uid, admin=is_admin)
        if s:
            sessions.append(s)

    if not sessions:
        return jsonify({"error": "No accessible sessions found"}), 404

    u = getattr(g, "current_user", None)
    analyst = getattr(u, "username", "Analyst")

    report_html = generate_report(
        sessions=sessions,
        operation_name=op_name,
        target=op_target,
        analyst=analyst,
        include_exec=include_exec,
        include_methodology=include_methodology,
        include_risk=include_risk,
        include_findings=include_findings,
        include_recommendations=include_recommendations,
        company=company,
        classification=classification,
    )

    if fmt == "download":
        import re, uuid as _uuid
        safe = re.sub(r'[^\w\s\-.]', '', op_name)[:60] or 'report'
        safe = re.sub(r'\s+', '_', safe.strip())
        fname = f"ZeekGlare_{safe}_{str(_uuid.uuid4())[:6]}.html"
        return Response(report_html, mimetype="text/html",
                        headers={"Content-Disposition": f'attachment; filename="{fname}"'})

    return jsonify({"html": report_html})
