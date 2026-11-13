"""ProjectDiscovery tools blueprint."""
import threading, queue, json
from flask import Blueprint, request, jsonify, Response, stream_with_context, g
from core.auth_utils import login_required
from services.pd_runner import (
    list_pd_sessions, get_pd_session, create_pd_session,
    update_pd_session, delete_pd_session, rename_pd_session,
    check_pd_tools, run_pd_pipeline, TOOL_ORDER,
    run_uncover, run_asnmap, run_tlsx, run_cdncheck, run_cvemap,
    CATEGORIES,
)

pd_bp = Blueprint("pd", __name__)

# Active pipeline queues: sid -> {queue, user_id}
_active: dict = {}
_lock = threading.Lock()


def _uid():
    return g.current_user.id


def _is_admin():
    return getattr(g.current_user, "role", "") == "admin"


def _owns_session(s):
    """Check if current user owns a session (admin sees all)."""
    if _is_admin():
        return True
    return s and s.get("user_id") == _uid()


@pd_bp.route("/api/pd/tools")
@login_required
def tools_status():
    return jsonify(check_pd_tools())


# ── Session CRUD ───────────────────────────────────────────────────────────────
@pd_bp.route("/api/pd/sessions", methods=["GET"])
@login_required
def list_sessions():
    sessions = list_pd_sessions()
    if _is_admin():
        return jsonify(sessions)
    uid = _uid()
    return jsonify([s for s in sessions if s.get("user_id") == uid])


@pd_bp.route("/api/pd/sessions", methods=["POST"])
@login_required
def create_session():
    body = request.get_json(silent=True) or {}
    target = (body.get("target") or "").strip()
    name   = (body.get("name") or "").strip()
    if not target:
        return jsonify({"error": "target required"}), 400
    s = create_pd_session(target, name, user_id=_uid())
    return jsonify(s), 201


@pd_bp.route("/api/pd/sessions/<sid>", methods=["GET"])
@login_required
def get_session(sid):
    s = get_pd_session(sid)
    if not s:
        return jsonify({"error": "Not found"}), 404
    if not _owns_session(s):
        return jsonify({"error": "Not found"}), 404
    return jsonify(s)


@pd_bp.route("/api/pd/sessions/<sid>", methods=["PATCH"])
@login_required
def patch_session(sid):
    body = request.get_json(silent=True) or {}
    name = (body.get("name") or "").strip()
    if not name:
        return jsonify({"error": "name required"}), 400
    s = get_pd_session(sid)
    if not s or not _owns_session(s):
        return jsonify({"error": "Not found"}), 404
    s = rename_pd_session(sid, name)
    if not s:
        return jsonify({"error": "Not found"}), 404
    return jsonify(s)


@pd_bp.route("/api/pd/sessions/<sid>", methods=["DELETE"])
@login_required
def delete_session(sid):
    s = get_pd_session(sid)
    if not s or not _owns_session(s):
        return jsonify({"error": "Not found"}), 404
    # Also stop any active pipeline
    with _lock:
        q_info = _active.pop(sid, None)
    if q_info:
        q_info["queue"].put(None)
    ok = delete_pd_session(sid)
    if not ok:
        return jsonify({"error": "Not found"}), 404
    return jsonify({"ok": True})


# ── Pipeline run + stream ──────────────────────────────────────────────────────
@pd_bp.route("/api/pd/sessions/<sid>/run", methods=["POST"])
@login_required
def run_pipeline(sid):
    body  = request.get_json(silent=True) or {}
    tools = body.get("tools", TOOL_ORDER)
    pdcp_key = (body.get("pdcp_api_key") or "").strip()
    s = get_pd_session(sid)
    if not s:
        return jsonify({"error": "Not found"}), 404
    if not _owns_session(s):
        return jsonify({"error": "Not found"}), 404

    with _lock:
        if sid in _active:
            return jsonify({"error": "Pipeline already running"}), 409

    q = queue.Queue()
    with _lock:
        _active[sid] = {"queue": q, "user_id": _uid()}

    update_pd_session(sid, {"status": "running"})

    def _bg():
        try:
            run_pd_pipeline(sid, s["target"], tools, q, pdcp_api_key=pdcp_key)
        except Exception as e:
            q.put({"type": "error", "message": str(e)})
            q.put(None)
        finally:
            with _lock:
                _active.pop(sid, None)

    threading.Thread(target=_bg, daemon=True).start()
    return jsonify({"ok": True, "sid": sid})


@pd_bp.route("/api/pd/sessions/<sid>/stream")
@login_required
def stream_pipeline(sid):
    # Ownership check
    s = get_pd_session(sid)
    if not s or not _owns_session(s):
        return jsonify({"error": "Not found"}), 404

    with _lock:
        q_info = _active.get(sid)

    # Also verify active pipeline ownership
    if q_info and not _is_admin() and q_info.get("user_id") != _uid():
        return jsonify({"error": "Not found"}), 404

    q = q_info["queue"] if q_info else None

    if not q:
        # Already finished — send saved results
        def replay():
            yield f"data: {json.dumps({'type': 'replay', 'session': s})}\n\n"
            yield f"data: {json.dumps({'type': 'done'})}\n\n"

        return Response(stream_with_context(replay()),
                        mimetype="text/event-stream",
                        headers={"Cache-Control": "no-cache",
                                 "X-Accel-Buffering": "no"})

    def generate():
        while True:
            try:
                item = q.get(timeout=60)
                if item is None:
                    yield f"data: {json.dumps({'type': 'done'})}\n\n"
                    break
                yield f"data: {json.dumps(item)}\n\n"
            except queue.Empty:
                yield f"data: {json.dumps({'type': 'keepalive'})}\n\n"

    return Response(stream_with_context(generate()),
                    mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache",
                             "X-Accel-Buffering": "no"})


@pd_bp.route("/api/pd/sessions/<sid>/stop", methods=["POST"])
@login_required
def stop_pipeline(sid):
    s = get_pd_session(sid)
    if not s or not _owns_session(s):
        return jsonify({"error": "Not found"}), 404
    with _lock:
        q_info = _active.pop(sid, None)
    if q_info:
        q_info["queue"].put(None)
    update_pd_session(sid, {"status": "stopped"})
    return jsonify({"ok": True})


# ── Standalone tool endpoints ──────────────────────────────────────────────────
@pd_bp.route("/api/pd/uncover", methods=["POST"])
@login_required
def uncover_route():
    body    = request.get_json(silent=True) or {}
    query   = (body.get("query") or body.get("target") or "").strip()
    engines = body.get("engines", [])
    if not query:
        return jsonify({"error": "query required"}), 400
    results = run_uncover(query, engines or None)
    return jsonify({"query": query, "results": results, "count": len(results)})


@pd_bp.route("/api/pd/asnmap", methods=["POST"])
@login_required
def asnmap_route():
    body   = request.get_json(silent=True) or {}
    target = (body.get("target") or "").strip()
    if not target:
        return jsonify({"error": "target required"}), 400
    results = run_asnmap(target)
    return jsonify({"target": target, "results": results, "count": len(results)})


@pd_bp.route("/api/pd/tlsx", methods=["POST"])
@login_required
def tlsx_route():
    body  = request.get_json(silent=True) or {}
    hosts = body.get("hosts", [])
    host  = (body.get("host") or "").strip()
    if host:
        hosts = [host]
    if not hosts:
        return jsonify({"error": "hosts required"}), 400
    results = run_tlsx(hosts)
    return jsonify({"results": results, "count": len(results)})


@pd_bp.route("/api/pd/cdncheck", methods=["POST"])
@login_required
def cdncheck_route():
    body  = request.get_json(silent=True) or {}
    hosts = body.get("hosts", [])
    host  = (body.get("host") or "").strip()
    if host:
        hosts = [host]
    if not hosts:
        return jsonify({"error": "hosts required"}), 400
    results = run_cdncheck(hosts)
    return jsonify({"results": results, "count": len(results)})


@pd_bp.route("/api/pd/cvemap", methods=["POST"])
@login_required
def cvemap_route():
    body     = request.get_json(silent=True) or {}
    query    = (body.get("query") or "").strip()
    severity = body.get("severity", "critical,high")
    results  = run_cvemap(query, severity)
    return jsonify({"results": results, "count": len(results)})


@pd_bp.route("/api/pd/categories")
@login_required
def categories_route():
    return jsonify(CATEGORIES)
