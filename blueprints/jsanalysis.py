from core.auth_utils import module_required
"""JS Intel blueprint — reconnect-safe (buffered events)."""
import threading, uuid, queue, json, time
from flask import Blueprint, request, jsonify, Response, stream_with_context, g
from services.js_scanner import JsScanner
from core.session_manager import SessionManager

jsanalysis_bp = Blueprint("jsanalysis", __name__)
_scans = {}
_lock  = threading.Lock()


def _persist_jsintel(scan_id, snap):
    events = snap.get("events", []) or []
    target = snap.get("target", "") or ""

    endpoints = []
    interesting = []
    js_urls = []
    hosts_seen = set()
    seen_ep = set()

    for ev in events:
        if not isinstance(ev, dict):
            continue
        t = ev.get("type")
        if t == "js_urls_found":
            for u in ev.get("urls", []) or []:
                if u not in js_urls:
                    js_urls.append(u)
        elif t == "js_domain_done":
            host = ev.get("host") or ""
            if host:
                hosts_seen.add(host)
            for ep in ev.get("endpoints", []) or []:
                k = ep.get("endpoint") or ""
                if k and k not in seen_ep:
                    seen_ep.add(k)
                    endpoints.append({**ep, "host": host})
            for ep in ev.get("interesting", []) or []:
                interesting.append({**ep, "host": host})

    summary = {
        "status":             "completed",
        "total_hosts":        len(hosts_seen),
        "total_js_urls":      len(js_urls),
        "total_endpoints":    len(endpoints),
        "total_interesting":  len(interesting),
    }
    data = {
        "endpoints":   endpoints,
        "interesting": interesting,
        "js_urls":     js_urls,
        "hosts":       sorted(hosts_seen),
        "target":      target,
    }
    try:
        SessionManager.save(
            scan_id=scan_id, scan_type="jsintel", target=target,
            name=f"JS Intel — {target}" if target else "JS Intel",
            summary=summary, data=data,
            user_id=snap.get("user_id"), username=snap.get("username", ""),
        )
    except Exception:
        pass


@jsanalysis_bp.route("/api/js-scan", methods=["POST"])
@module_required("jsanalysis")
def start_js_scan():
    body         = request.get_json(silent=True) or {}
    domain       = (body.get("domain") or "").strip()
    live_domains = body.get("live_domains") or []
    if not domain or not live_domains:
        return jsonify({"error": "domain and live_domains required"}), 400

    scan_id = str(uuid.uuid4())
    q       = queue.Queue()
    scanner = JsScanner(
        domain        = domain,
        live_domains  = live_domains,
        event_queue   = q,
        max_domains   = int(body.get("max_domains", 30)),
        max_js_per_domain = int(body.get("max_js_per_domain", 20)),
        threads       = int(body.get("threads", 6)),
        enabled_tools = body.get("enabled_tools") or None,
    )
    _uid = getattr(g, "current_user", None) and g.current_user.id
    _un  = getattr(getattr(g, "current_user", None), "username", "")
    with _lock:
        _scans[scan_id] = {"queue": q, "done": False, "events": [],
                           "target": domain, "user_id": _uid, "username": _un}

    def _buffer():
        while True:
            try:
                item = q.get(timeout=90)
                with _lock:
                    if scan_id in _scans:
                        _scans[scan_id]["events"].append(item)
                if item is None:
                    break
            except queue.Empty:
                pass

    def _run():
        try:
            scanner.run()
        finally:
            _snap = None
            with _lock:
                if scan_id in _scans:
                    _scans[scan_id]["done"] = True
                    _snap = dict(_scans[scan_id])
            if _snap:
                _persist_jsintel(scan_id, _snap)

    threading.Thread(target=_buffer, daemon=True).start()
    threading.Thread(target=_run,    daemon=True).start()
    return jsonify({"scan_id": scan_id, "domain": domain, "targets": len(live_domains)})


@jsanalysis_bp.route("/api/js-stream/<scan_id>")
@module_required("jsanalysis")
def stream_js_scan(scan_id):
    with _lock:
        scan = _scans.get(scan_id)
    if not scan:
        return jsonify({"error": "not found"}), 404

    def generate():
        offset  = 0
        last_ka = time.time()
        while True:
            with _lock:
                scan   = _scans.get(scan_id)
                if not scan:
                    break
                events = scan["events"]
                done   = scan["done"]

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


@jsanalysis_bp.route("/api/js-status/<scan_id>")
def js_scan_status(scan_id):
    with _lock:
        scan = _scans.get(scan_id)
    if not scan:
        return jsonify({"exists": False}), 404
    return jsonify({"exists": True, "done": scan["done"],
                    "event_count": len(scan["events"])})
