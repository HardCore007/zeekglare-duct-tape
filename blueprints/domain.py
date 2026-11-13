"""Domain mapping blueprint — reconnect-safe (buffered events)."""
import threading, uuid, queue, json, time
from flask import Blueprint, request, jsonify, Response, stream_with_context, g
from core.auth_utils import module_required, rate_limit
from services.domain_mapper import DomainMapper
from services.screenshot import take_screenshot

domain_bp  = Blueprint("domain", __name__)
dom_scans  = {}
lock       = threading.Lock()


@domain_bp.route("/api/domain-scan", methods=["POST"])
@module_required("domain")
@rate_limit(max_requests=5, window_seconds=60)
def start_domain_scan():
    body   = request.get_json(silent=True) or {}
    domain = (body.get("domain") or "").strip()
    if not domain:
        return jsonify({"error": "Domain is required"}), 400

    scan_id = str(uuid.uuid4())
    q       = queue.Queue()
    mapper  = DomainMapper(
        domain             = domain,
        shodan_key         = body.get("shodan_key") or None,
        networksdb_key     = body.get("networksdb_key") or None,
        securitytrails_key = body.get("securitytrails_key") or None,
        censys_id          = body.get("censys_id") or None,
        censys_secret      = body.get("censys_secret") or None,
        zoomeye_key        = body.get("zoomeye_key") or None,
        fofa_email         = body.get("fofa_email") or None,
        fofa_key           = body.get("fofa_key") or None,
        github_token       = body.get("github_token") or None,
        c99_key            = body.get("c99_key") or None,
        chaos_key          = body.get("chaos_key") or None,
        gitlab_token       = body.get("gitlab_token") or None,
        argosdns_key       = body.get("argosdns_key") or None,
        enabled_sources    = body.get("enabled_sources") or None,
        event_queue        = q,
        max_subs           = int(body.get("max_subs") or 10000),
        probe_http         = bool(body.get("probe_http", True)),
        use_bbot           = body.get("use_bbot", True),
        user_id            = getattr(g, "current_user", None) and g.current_user.id,
        username           = getattr(getattr(g, "current_user", None), "username", ""),
    )
    with lock:
        dom_scans[scan_id] = {
            "queue": q, "mapper": mapper,
            "done": False, "events": [],
            "domain": domain, "started_at": time.time(),
            "user_id":  getattr(g, "current_user", None) and g.current_user.id,
            "username": getattr(getattr(g, "current_user", None), "username", ""),
        }

    def _buffer():
        """Drain the mapper queue into the persistent events list."""
        while True:
            try:
                item = q.get(timeout=90)
                with lock:
                    if scan_id in dom_scans:
                        dom_scans[scan_id]["events"].append(item)
                if item is None:
                    break
            except queue.Empty:
                pass

    def _run():
        try:
            mapper.run()
        finally:
            _notify_args = None
            with lock:
                if scan_id in dom_scans:
                    dom_scans[scan_id]["done"] = True
                    _uid = dom_scans[scan_id].get("user_id")
                    _events = dom_scans[scan_id].get("events", [])
                    _subs = sum(1 for e in _events if e and e.get("type") == "subdomain")
                    _notify_args = (_uid, "domain", domain, _subs, "Domain Mapper")
            if _notify_args:
                from core.notifications import notify_scan_complete
                notify_scan_complete(*_notify_args)

    threading.Thread(target=_buffer, daemon=True).start()
    threading.Thread(target=_run,    daemon=True).start()
    return jsonify({"scan_id": scan_id, "domain": domain})


@domain_bp.route("/api/domain-stream/<scan_id>")
@module_required("domain")
def stream_domain_scan(scan_id):
    with lock:
        scan = dom_scans.get(scan_id)
    if not scan:
        return jsonify({"error": "Not found"}), 404

    def generate():
        offset  = 0
        last_ka = time.time()
        while True:
            with lock:
                scan   = dom_scans.get(scan_id)
                if not scan:
                    break
                events = scan["events"]
                done   = scan["done"]

            # Replay / forward buffered events
            while offset < len(events):
                item = events[offset]
                offset += 1
                if item is None:
                    yield f"data: {json.dumps({'type': 'done'})}\n\n"
                    return
                yield f"data: {json.dumps(item)}\n\n"

            if done:
                yield f"data: {json.dumps({'type': 'done'})}\n\n"
                return

            now = time.time()
            if now - last_ka > 25:
                yield f"data: {json.dumps({'type': 'keepalive'})}\n\n"
                last_ka = now

            time.sleep(0.05)

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@domain_bp.route("/api/domain-status/<scan_id>")
def domain_scan_status(scan_id):
    with lock:
        scan = dom_scans.get(scan_id)
    if not scan:
        return jsonify({"exists": False}), 404
    return jsonify({"exists": True, "done": scan["done"],
                    "event_count": len(scan["events"])})


@domain_bp.route("/api/screenshot", methods=["POST"])
@module_required("domain")
def screenshot():
    body = request.get_json(silent=True) or {}
    url  = (body.get("url") or "").strip()
    if not url:
        return jsonify({"error": "url required"}), 400
    result = take_screenshot(url)
    return jsonify(result)
