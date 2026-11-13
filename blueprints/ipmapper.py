from core.auth_utils import module_required
"""IPScope — IP & Subnet intelligence mapper blueprint."""
import json, queue, threading, time, uuid
from flask import Blueprint, request, Response, jsonify, stream_with_context, g

ipmapper_bp = Blueprint("ipmapper", __name__)

_scans = {}
_lock  = threading.Lock()


@ipmapper_bp.route("/api/ip-map/start", methods=["POST"])
@module_required("ipmapper")
def ip_map_start():
    from services.ip_mapper import IpMapper

    body    = request.get_json(silent=True) or {}
    # Support both legacy "domain" and new "targets" parameter
    targets = (body.get("targets") or body.get("domain") or "").strip()
    if not targets:
        return jsonify({"error": "targets required"}), 400

    seed_ips         = body.get("seed_ips") or []
    enabled_sources  = body.get("enabled_sources") or None
    use_nmap         = bool(body.get("use_nmap", False))
    nmap_args        = (body.get("nmap_args") or "").strip()

    mapper = IpMapper(
        targets         = targets,
        shodan_key      = body.get("shodan_key")         or None,
        fofa_email      = body.get("fofa_email")         or None,
        fofa_key        = body.get("fofa_key")           or None,
        zoomeye_key     = body.get("zoomeye_key")        or None,
        securitytrails_key = body.get("securitytrails_key") or None,
        censys_id       = body.get("censys_id")          or None,
        censys_secret   = body.get("censys_secret")      or None,
        netlas_key      = body.get("netlas_key")         or None,
        greynoise_key   = body.get("greynoise_key")      or None,
        criminalip_key  = body.get("criminalip_key")     or None,
        seed_ips        = seed_ips,
        enabled_sources = enabled_sources,
        use_nmap        = use_nmap,
        nmap_args       = nmap_args,
    )

    q       = mapper._eq
    scan_id = str(uuid.uuid4())[:8]

    with _lock:
        _scans[scan_id] = {
            "done": False, "events": [], "targets": targets,
            "domain": mapper.domain, "use_nmap": use_nmap,
        }

    # Save session immediately
    from core.session_manager import SessionManager
    from datetime import datetime
    _u = getattr(g, "current_user", None)
    # Truncate targets for session name display
    short_target = targets[:60] + ("…" if len(targets) > 60 else "")
    SessionManager.save(
        scan_id   = scan_id,
        scan_type = "ipscope",
        target    = targets,
        name      = f"IPScope: {short_target} — {datetime.now():%Y-%m-%d %H:%M}",
        summary   = {"status": "running", "unique_ips": 0, "unique_cidrs": 0,
                      "use_nmap": use_nmap},
        data      = {},
        user_id   = _u.id if _u else None,
        username  = _u.username if _u else "",
    )

    def _buffer():
        all_entries = []
        while True:
            try:
                item = q.get(timeout=300)
                with _lock:
                    if scan_id in _scans:
                        _scans[scan_id]["events"].append(item)
                if item is None:
                    with _lock:
                        if scan_id in _scans:
                            _scans[scan_id]["done"] = True
                    # Update session with final data
                    SessionManager.update(scan_id, {
                        "summary": {"status": "done",
                                    "unique_ips": len(all_entries),
                                    "unique_cidrs": len({e.get("cidr","") for e in all_entries if e.get("cidr")}),
                                    "use_nmap": use_nmap},
                        "data":    {"entries": all_entries},
                    })
                    break
                # Collect entries for session save
                if isinstance(item, dict) and item.get("type") == "ip_result":
                    all_entries.append(item.get("entry", {}))
                elif isinstance(item, dict) and item.get("type") == "scan_done":
                    # Also update from scan_done entries if available
                    if item.get("entries"):
                        all_entries = item["entries"]
            except queue.Empty:
                pass

    threading.Thread(target=_buffer, daemon=True).start()
    threading.Thread(target=mapper.run, daemon=True).start()

    return jsonify({"scan_id": scan_id, "targets": targets, "domain": mapper.domain})


@ipmapper_bp.route("/api/ip-map/stream/<scan_id>")
@module_required("ipmapper")
def ip_map_stream(scan_id):
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


@ipmapper_bp.route("/api/ip-map/status/<scan_id>")
def ip_map_status(scan_id):
    with _lock:
        scan = _scans.get(scan_id)
    if not scan:
        return jsonify({"exists": False}), 404
    return jsonify({
        "exists": True, "done": scan["done"],
        "targets": scan.get("targets", ""),
        "domain": scan.get("domain", ""),
        "event_count": len(scan["events"]),
    })


@ipmapper_bp.route("/api/ip-map/stop/<scan_id>", methods=["POST"])
def ip_map_stop(scan_id):
    with _lock:
        scan = _scans.get(scan_id)
    if scan and not scan["done"]:
        scan["done"] = True
    return jsonify({"stopped": True})


@ipmapper_bp.route("/api/ip-map/screenshot", methods=["POST"])
@module_required("ipmapper")
def ip_map_screenshot():
    """Take a screenshot of a web service running on an IP:port."""
    import subprocess, shutil, base64, tempfile, os

    body = request.get_json(silent=True) or {}
    ip   = (body.get("ip") or "").strip()
    port = int(body.get("port", 443))
    if not ip:
        return jsonify({"error": "ip required"}), 400

    # Build URL — try both HTTPS and HTTP if needed
    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{ip}:{port}"

    chromium = shutil.which("chromium") or shutil.which("chromium-browser") or shutil.which("google-chrome")
    cutycapt = shutil.which("cutycapt")

    if not chromium and not cutycapt:
        return jsonify({"error": "No screenshot tool available (install chromium or cutycapt)"}), 500

    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp:
        out_path = tmp.name

    def _try_screenshot(target_url):
        """Try chromium first (better SSL handling), fall back to cutycapt."""
        # Remove stale file
        if os.path.exists(out_path) and os.path.getsize(out_path) > 0:
            os.unlink(out_path)
            with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp2:
                return tmp2.name, True  # need new path
        # Try chromium (handles SSL certs properly)
        if chromium:
            try:
                subprocess.run([
                    chromium, "--headless", "--disable-gpu", "--no-sandbox",
                    "--disable-software-rasterizer",
                    f"--screenshot={out_path}", "--window-size=1024,768",
                    "--ignore-certificate-errors",
                    "--disable-web-security",
                    target_url,
                ], timeout=30, capture_output=True)
                if os.path.exists(out_path) and os.path.getsize(out_path) > 100:
                    return out_path, True
            except Exception:
                pass
        # Fall back to cutycapt
        if cutycapt:
            try:
                # Clear any partial file
                if os.path.exists(out_path):
                    os.unlink(out_path)
                subprocess.run([
                    cutycapt, f"--url={target_url}", f"--out={out_path}",
                    "--min-width=1024", "--min-height=768",
                    "--delay=3000", "--insecure",
                ], timeout=30, capture_output=True)
                if os.path.exists(out_path) and os.path.getsize(out_path) > 100:
                    return out_path, True
            except Exception:
                pass
        return out_path, False

    try:
        path, ok = _try_screenshot(url)
        out_path = path  # update in case it changed

        # If HTTPS failed, try HTTP
        if not ok and scheme == "https":
            http_url = f"http://{ip}:{port}"
            path, ok = _try_screenshot(http_url)
            out_path = path
            if ok:
                url = http_url

        if ok and os.path.exists(out_path) and os.path.getsize(out_path) > 100:
            with open(out_path, "rb") as f:
                b64 = base64.b64encode(f.read()).decode()
            os.unlink(out_path)
            return jsonify({"screenshot": b64, "url": url})
        else:
            if os.path.exists(out_path):
                os.unlink(out_path)
            return jsonify({"error": "Screenshot failed — site may be unreachable or returned empty page"}), 500
    except subprocess.TimeoutExpired:
        if os.path.exists(out_path):
            os.unlink(out_path)
        return jsonify({"error": "Screenshot timed out"}), 504
    except Exception as e:
        if os.path.exists(out_path):
            os.unlink(out_path)
        return jsonify({"error": str(e)}), 500
