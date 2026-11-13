import json, queue, threading, time, uuid
from flask import Blueprint, request, Response, jsonify, stream_with_context, g
from core.auth_utils import module_required

paramhawk_bp = Blueprint("paramhawk", __name__)

_scans = {}
_lock  = threading.Lock()


@paramhawk_bp.route("/api/param/tools")
def param_tools():
    from services.param_finder import tool_status
    return jsonify(tool_status())


@paramhawk_bp.route("/api/param/start", methods=["POST"])
@module_required("paramhawk")
def param_start():
    from services.param_finder import ParamFinder

    body    = request.get_json(silent=True) or {}
    targets = body.get("targets") or []
    if isinstance(targets, str):
        targets = [t.strip() for t in targets.splitlines() if t.strip()]
    targets = [t for t in targets if t]
    if not targets:
        return jsonify({"error": "targets required"}), 400

    enabled_tools = body.get("enabled_tools") or None
    methods       = (body.get("methods") or "GET").strip()
    threads       = max(1, min(20, int(body.get("threads") or 10)))

    finder  = ParamFinder(targets=targets, enabled_tools=enabled_tools,
                          methods=methods, threads=threads)
    q       = finder._eq
    scan_id = str(uuid.uuid4())[:8]

    with _lock:
        _scans[scan_id] = {"done": False, "events": [], "targets": targets,
                           "finder": finder, "started_at": time.time(),
                           "user_id": getattr(g, "current_user", None) and g.current_user.id,
                           "username": getattr(getattr(g, "current_user", None), "username", "")}

    def _buffer():
        while True:
            try:
                item = q.get(timeout=600)
                with _lock:
                    if scan_id in _scans:
                        _scans[scan_id]["events"].append(item)
                if item is None:
                    with _lock:
                        if scan_id in _scans:
                            _scans[scan_id]["done"] = True
                    break
            except queue.Empty:
                break

    threading.Thread(target=_buffer, daemon=True).start()
    threading.Thread(target=finder.run, daemon=True).start()

    return jsonify({"scan_id": scan_id, "targets": len(targets)})


@paramhawk_bp.route("/api/param/stream/<scan_id>")
@module_required("paramhawk")
def param_stream(scan_id):
    with _lock:
        scan = _scans.get(scan_id)
    if not scan:
        return jsonify({"error": "scan not found"}), 404

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


@paramhawk_bp.route("/api/param/status/<scan_id>")
def param_status(scan_id):
    with _lock:
        scan = _scans.get(scan_id)
    if not scan:
        return jsonify({"exists": False}), 404
    return jsonify({"exists": True, "done": scan["done"],
                    "targets": len(scan.get("targets", [])),
                    "event_count": len(scan["events"])})


@paramhawk_bp.route("/api/param/stop/<scan_id>", methods=["POST"])
def param_stop(scan_id):
    with _lock:
        scan = _scans.get(scan_id)
    if scan:
        finder = scan.get("finder")
        if finder:
            finder._stop.set()
        scan["done"] = True
    return jsonify({"stopped": True})
