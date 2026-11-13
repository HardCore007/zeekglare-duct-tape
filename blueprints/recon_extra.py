"""Extra Recon endpoints — Cloud Asset Discovery, API Discovery, Bulk WHOIS, WAF Bypass."""
import json, threading, queue, time, uuid
from flask import Blueprint, request, Response, jsonify, stream_with_context
from core.auth_utils import module_required, login_required

recon_extra_bp = Blueprint("recon_extra", __name__)

_scans = {}
_lock = threading.Lock()


# ── Cloud Asset Discovery ────────────────────────────────────────────────────

@recon_extra_bp.route("/api/cloud/scan", methods=["POST"])
def cloud_scan():
    from services.cloud_enum import enumerate_cloud_assets
    body = request.get_json(silent=True) or {}
    org = (body.get("org") or "").strip()
    if not org:
        return jsonify({"error": "org name required"}), 400

    eq = queue.Queue()
    scan_id = str(uuid.uuid4())[:8]

    with _lock:
        _scans[scan_id] = {"done": False, "events": []}

    def _run():
        try:
            enumerate_cloud_assets(org, eq=eq)
        except Exception as e:
            eq.put({"type": "cloud_status", "msg": f"Error: {e}"})
        finally:
            eq.put(None)

    def _buffer():
        while True:
            try:
                item = eq.get(timeout=120)
                with _lock:
                    if scan_id in _scans:
                        _scans[scan_id]["events"].append(item)
                if item is None:
                    with _lock:
                        _scans[scan_id]["done"] = True
                    break
            except queue.Empty:
                pass

    threading.Thread(target=_buffer, daemon=True).start()
    threading.Thread(target=_run, daemon=True).start()
    return jsonify({"scan_id": scan_id})


# ── API Endpoint Discovery ───────────────────────────────────────────────────

@recon_extra_bp.route("/api/api-discover/scan", methods=["POST"])
def api_discover():
    from services.api_discovery import discover_api_endpoints
    body = request.get_json(silent=True) or {}
    target = (body.get("target") or "").strip()
    if not target:
        return jsonify({"error": "target URL required"}), 400

    eq = queue.Queue()
    scan_id = str(uuid.uuid4())[:8]

    with _lock:
        _scans[scan_id] = {"done": False, "events": []}

    def _run():
        try:
            discover_api_endpoints(target, eq=eq)
        except Exception as e:
            eq.put({"type": "api_status", "msg": f"Error: {e}"})
        finally:
            eq.put(None)

    def _buffer():
        while True:
            try:
                item = eq.get(timeout=120)
                with _lock:
                    if scan_id in _scans:
                        _scans[scan_id]["events"].append(item)
                if item is None:
                    with _lock:
                        _scans[scan_id]["done"] = True
                    break
            except queue.Empty:
                pass

    threading.Thread(target=_buffer, daemon=True).start()
    threading.Thread(target=_run, daemon=True).start()
    return jsonify({"scan_id": scan_id})


# ── Shared SSE stream for both ───────────────────────────────────────────────

@recon_extra_bp.route("/api/recon-extra/stream/<scan_id>")
@module_required("recon_extra")
def recon_extra_stream(scan_id):
    with _lock:
        scan = _scans.get(scan_id)
    if not scan:
        return jsonify({"error": "scan not found"}), 404

    def generate():
        offset = 0
        last_ka = time.time()
        while True:
            with _lock:
                scan = _scans.get(scan_id)
                if not scan:
                    break
                events = scan["events"]
                done = scan["done"]
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


# ── Bulk WHOIS ───────────────────────────────────────────────────────────────

@recon_extra_bp.route("/api/whois/bulk", methods=["POST"])
def bulk_whois():
    from services.osint import whois_lookup
    body = request.get_json(silent=True) or {}
    targets = body.get("targets", [])
    if isinstance(targets, str):
        targets = [t.strip() for t in targets.split("\n") if t.strip()]
    if not targets:
        return jsonify({"error": "targets required"}), 400

    results = []
    for t in targets[:30]:  # Limit to 30
        try:
            w = whois_lookup(t)
            results.append({"target": t, "whois": w, "error": None})
        except Exception as e:
            results.append({"target": t, "whois": None, "error": str(e)})

    return jsonify({"results": results, "total": len(results)})


# ── WAF Bypass ───────────────────────────────────────────────────────────────

@recon_extra_bp.route("/api/waf/bypass", methods=["POST"])
def waf_bypass():
    from services.waf_bypass import get_waf_bypass
    body = request.get_json(silent=True) or {}
    waf_name = (body.get("waf") or "").strip()
    if not waf_name:
        return jsonify({"error": "waf name required"}), 400
    info = get_waf_bypass(waf_name)
    return jsonify(info or {"name": waf_name, "bypasses": [], "xss_bypass": [], "sqli_bypass": []})


@recon_extra_bp.route("/api/waf/all", methods=["GET"])
def waf_all():
    from services.waf_bypass import get_all_waf_info
    return jsonify(get_all_waf_info())
