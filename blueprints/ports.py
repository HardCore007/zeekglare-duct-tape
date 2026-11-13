"""Port Scanner blueprint — multi-tool, multi-target."""
import json, queue, threading, time, uuid
from flask import Blueprint, request, jsonify, Response, stream_with_context, g
from core.auth_utils import module_required, rate_limit
from core.session_manager import SessionManager

ports_bp   = Blueprint("ports", __name__)
_scans     = {}
_lock      = threading.Lock()


def _persist_port_session(scan_id, scan):
    """Collapse SSE events into a session record."""
    events   = scan.get("events", []) or []
    targets  = scan.get("targets", []) or []
    user_id  = scan.get("user_id")
    username = scan.get("username", "")

    results = {}
    total_ports = 0
    crit = high = med = low = 0
    for ev in events:
        if not isinstance(ev, dict):
            continue
        t = ev.get("type")
        if t == "host_start":
            host = ev.get("host") or ""
            if host:
                results.setdefault(host, {"ip": ev.get("ip", ""), "ports": []})
        elif t == "port_result":
            host = ev.get("host") or ""
            if not host:
                continue
            entry = results.setdefault(host, {"ip": ev.get("ip", ""), "ports": []})
            entry["ports"].append({k: v for k, v in ev.items() if k not in ("type", "host", "ip")})
            total_ports += 1
            risk = (ev.get("risk") or "").lower()
            if risk == "critical": crit += 1
            elif risk == "high":   high += 1
            elif risk == "medium": med  += 1
            elif risk == "low":    low  += 1

    target = targets[0] if targets else ""
    name   = f"Ports — {target}" if target else f"Ports — {len(targets)} host(s)"
    summary = {
        "status":       "completed",
        "total_hosts":  len(targets),
        "hosts_with_ports": sum(1 for v in results.values() if v.get("ports")),
        "total_ports":  total_ports,
        "critical":     crit,
        "high":         high,
        "medium":       med,
        "low":          low,
    }
    data = {"results": results, "targets": targets}

    try:
        SessionManager.save(
            scan_id=scan_id, scan_type="ports", target=target,
            name=name, summary=summary, data=data,
            user_id=user_id, username=username,
        )
    except Exception:
        pass


@ports_bp.route("/api/ports/tools")
def ports_tools():
    from services.port_scanner import tool_status
    return jsonify(tool_status())


@ports_bp.route("/api/ports/scan", methods=["POST"])
@module_required("ports")
@rate_limit(max_requests=5, window_seconds=60)
def start_port_scan():
    from services.port_scanner import PortScanner

    body    = request.get_json(silent=True) or {}
    targets = body.get("targets") or []
    if isinstance(targets, str):
        targets = [t.strip() for t in targets.splitlines() if t.strip()]
    targets = [t for t in targets if t]
    if not targets:
        return jsonify({"error": "targets required"}), 400

    scanner = PortScanner(
        targets      = targets,
        tool         = body.get("tool", "nmap"),
        port_profile = body.get("port_profile", "common"),
        custom_ports = body.get("custom_ports") or None,
        scan_type    = body.get("scan_type", "service"),
        concurrency  = int(body.get("concurrency") or 2),
    )
    q       = scanner._eq
    scan_id = str(uuid.uuid4())[:8]

    with _lock:
        _scans[scan_id] = {"done": False, "events": [], "scanner": scanner,
                           "targets": targets, "started_at": time.time(),
                           "user_id":  getattr(g, "current_user", None) and g.current_user.id,
                           "username": getattr(getattr(g, "current_user", None), "username", "")}

    def _buffer():
        while True:
            try:
                item = q.get(timeout=600)
                with _lock:
                    if scan_id in _scans:
                        _scans[scan_id]["events"].append(item)
                if item is None:
                    _notify_args = None
                    _snap = None
                    with _lock:
                        if scan_id in _scans:
                            _scans[scan_id]["done"] = True
                            _uid    = _scans[scan_id].get("user_id")
                            _events = _scans[scan_id].get("events", [])
                            _open   = sum(1 for e in _events if e and e.get("type") == "port_result")
                            _tgts   = _scans[scan_id].get("targets", [])
                            _notify_args = (_uid, "ports", _tgts[0] if _tgts else "", _open, "Port Scanner")
                            _snap = dict(_scans[scan_id])
                    if _snap:
                        _persist_port_session(scan_id, _snap)
                    if _notify_args:
                        from core.notifications import notify_scan_complete
                        notify_scan_complete(*_notify_args)
                    break
            except queue.Empty:
                break

    threading.Thread(target=_buffer, daemon=True).start()
    threading.Thread(target=scanner.run, daemon=True).start()
    return jsonify({"scan_id": scan_id, "targets": len(targets)})


@ports_bp.route("/api/ports/stream/<scan_id>")
@module_required("ports")
def stream_ports(scan_id):
    with _lock:
        scan = _scans.get(scan_id)
    if not scan:
        return jsonify({"error": "Not found"}), 404

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
                item = events[offset]; offset += 1
                if item is None:
                    yield f"data: {json.dumps({'type': 'done'})}\n\n"; return
                yield f"data: {json.dumps(item)}\n\n"
            if done:
                yield f"data: {json.dumps({'type': 'done'})}\n\n"; return
            now = time.time()
            if now - last_ka > 25:
                yield f"data: {json.dumps({'type': 'keepalive'})}\n\n"; last_ka = now
            time.sleep(0.05)

    return Response(stream_with_context(generate()), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@ports_bp.route("/api/ports/status/<scan_id>")
def port_status(scan_id):
    with _lock:
        scan = _scans.get(scan_id)
    if not scan:
        return jsonify({"exists": False}), 404
    return jsonify({"exists": True, "done": scan["done"],
                    "event_count": len(scan["events"])})


@ports_bp.route("/api/ports/stop/<scan_id>", methods=["POST"])
def port_stop(scan_id):
    with _lock:
        scan = _scans.get(scan_id)
    if scan:
        sc = scan.get("scanner")
        if sc:
            sc._stop.set()
        scan["done"] = True
    return jsonify({"stopped": True})
