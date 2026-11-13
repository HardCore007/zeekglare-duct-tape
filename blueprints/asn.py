"""ASN scanning blueprint."""
import threading, uuid, queue, json, subprocess, time, os
from flask import Blueprint, request, jsonify, Response, stream_with_context, g
from services.asn_scanner import StreamingMapper
from core.session_manager import SessionManager
from core.auth_utils import module_required, rate_limit

asn_bp = Blueprint("asn", __name__)
scans  = {}
lock   = threading.Lock()


class _LoggedQueue(queue.Queue):
    """Queue that simultaneously appends every item to a shared event-log list.

    This lets multiple SSE consumers (reconnecting clients) replay the full
    event history from any offset — even after the scan has finished.
    """
    def __init__(self, event_log):
        super().__init__()
        self._log  = event_log
        self._llock = threading.Lock()

    def put(self, item, block=True, timeout=None):
        if item is not None:          # None is the stop sentinel — don't log it
            with self._llock:
                self._log.append(item)
        super().put(item, block=block, timeout=timeout)


@asn_bp.route("/api/scan", methods=["POST"])
@module_required("asn")
def start_scan():
    body           = request.get_json(silent=True) or {}
    country            = (body.get("country") or "").strip().upper()
    limit              = body.get("limit") or None
    threads            = int(body.get("threads") or 20)
    rdns               = bool(body.get("rdns", True))
    networksdb_key     = body.get("networksdb_key") or None
    shodan_key         = body.get("shodan_key") or None
    securitytrails_key = body.get("securitytrails_key") or None

    if not country or len(country) != 2:
        return jsonify({"error": "Invalid country code"}), 400

    scan_id   = str(uuid.uuid4())
    event_log = []
    q         = _LoggedQueue(event_log)
    mapper    = StreamingMapper(
        country_code=country, threads=threads, shodan_key=shodan_key,
        networksdb_key=networksdb_key, securitytrails_key=securitytrails_key,
        sample_rdns=rdns, limit=int(limit) if limit else None,
        event_queue=q, session_id=scan_id,
    )

    # Save session immediately so it survives a page refresh
    from datetime import datetime
    _u = getattr(g, "current_user", None)
    SessionManager.save(
        scan_id   = scan_id,
        scan_type = "asn",
        target    = country,
        name      = f"{country} ASN Map — {datetime.now():%Y-%m-%d %H:%M}",
        summary   = {"status": "running", "total_asns": 0, "critical_asns": 0, "total_domains": 0},
        data      = {},
        user_id   = _u.id if _u else None,
        username  = _u.username if _u else "",
    )

    with lock:
        scans[scan_id] = {
            "queue": q, "mapper": mapper, "done": False,
            "country": country, "events": event_log,
            "started_at": time.time(),
            "username": getattr(getattr(g, "current_user", None), "username", ""),
            "mode": "country",
        }

    def _run():
        try:
            mapper.run()
        finally:
            with lock:
                if scan_id in scans:
                    scans[scan_id]["done"] = True

    threading.Thread(target=_run, daemon=True).start()
    return jsonify({"scan_id": scan_id, "country": country})


@asn_bp.route("/api/scan/<scan_id>/status")
@module_required("asn")
def scan_status(scan_id):
    """Check whether an in-memory scan is still active."""
    with lock:
        scan = scans.get(scan_id)
    if scan:
        return jsonify({"active": True, "done": scan["done"], "country": scan.get("country", "")})
    # Not in memory — check persisted session
    s = SessionManager.get(scan_id)
    if s:
        return jsonify({"active": False, "done": True, "session": s})
    return jsonify({"error": "Not found"}), 404


@asn_bp.route("/api/stream/<scan_id>")
@module_required("asn")
def stream_scan(scan_id):
    with lock:
        scan = scans.get(scan_id)
    if not scan:
        return jsonify({"error": "Not found"}), 404

    def generate():
        offset  = 0
        last_ka = time.time()
        while True:
            with lock:
                events = scan.get("events", [])
                done   = scan["done"]

            # Replay all buffered events from current offset
            while offset < len(events):
                yield f"data: {json.dumps(events[offset])}\n\n"
                offset += 1

            if done:
                yield f"data: {json.dumps({'type': 'done'})}\n\n"
                return

            now = time.time()
            if now - last_ka > 25:
                yield f"data: {json.dumps({'type': 'keepalive'})}\n\n"
                last_ka = now
            time.sleep(0.1)

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@asn_bp.route("/api/scan/asn", methods=["POST"])
@module_required("asn")
@rate_limit(max_requests=5, window_seconds=60)
def start_asn_scan():
    """Scan one or more specific ASN numbers directly."""
    body       = request.get_json(silent=True) or {}
    asn_input          = body.get("asns") or ""
    threads            = int(body.get("threads") or 20)
    rdns               = bool(body.get("rdns", True))
    networksdb_key     = body.get("networksdb_key") or None
    shodan_key         = body.get("shodan_key") or None
    securitytrails_key = body.get("securitytrails_key") or None

    # Parse ASN numbers — accept "AS1234", "1234", comma-separated
    import re as _re
    raw_asns = [a.strip() for a in str(asn_input).replace(",", " ").split() if a.strip()]
    asn_list = []
    for a in raw_asns:
        m = _re.search(r"\d+", a)
        if m:
            asn_list.append(int(m.group()))

    if not asn_list:
        return jsonify({"error": "Provide at least one ASN number"}), 400

    # Use a placeholder country code (required by AssetMapper init)
    scan_id   = str(uuid.uuid4())
    event_log = []
    q         = _LoggedQueue(event_log)

    mapper  = StreamingMapper(
        country_code="ZZ", threads=threads, shodan_key=shodan_key,
        networksdb_key=networksdb_key, securitytrails_key=securitytrails_key,
        sample_rdns=rdns, limit=None, event_queue=q, session_id=scan_id,
    )

    from datetime import datetime
    label = "AS" + ", AS".join(str(a) for a in asn_list[:5])
    _u2 = getattr(g, "current_user", None)
    SessionManager.save(
        scan_id   = scan_id,
        scan_type = "asn",
        target    = label,
        name      = f"{label} — {datetime.now():%Y-%m-%d %H:%M}",
        summary   = {"status": "running", "total_asns": 0, "critical_asns": 0, "total_domains": 0},
        data      = {},
        user_id   = _u2.id if _u2 else None,
        username  = _u2.username if _u2 else "",
    )

    with lock:
        scans[scan_id] = {
            "queue": q, "mapper": mapper, "done": False,
            "country": label, "events": event_log,
            "started_at": time.time(),
            "username": _u2.username if _u2 else "",
            "mode": "asn",
        }

    def _run():
        try:
            mapper.emit({"type": "scan_start", "country": label, "asn_mode": True})
            mapper._total = len(asn_list)
            mapper.emit({"type": "asns_found", "total": len(asn_list)})
            import io, contextlib
            asn_data = []
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                for asn_num in asn_list:
                    try:
                        result = mapper.process_asn(asn_num)
                        asn_data.append(result)
                    except Exception:
                        pass
            mapper.generate_report(asn_data)
            # Persist results to session (mirroring what StreamingMapper.run() does)
            try:
                trimmed = []
                for a in asn_data:
                    entry = dict(a)
                    entry["domains"] = a.get("domains", [])[:30]
                    trimmed.append(entry)
                total_asns    = len(asn_data)
                critical_asns = sum(1 for a in asn_data if a.get("asn_category") != "commercial")
                total_domains = sum(a.get("domain_count", 0) for a in asn_data)
                patch = {
                    "summary": {
                        "status":        "done",
                        "total_asns":    total_asns,
                        "critical_asns": critical_asns,
                        "total_domains": total_domains,
                    },
                    "data": {"asn_data": trimmed},
                }
                SessionManager.update(scan_id, patch)
                mapper.emit({"type": "session_saved", "scan_id": scan_id})
            except Exception:
                pass
        except Exception as e:
            mapper.emit({"type": "error", "message": str(e)})
        finally:
            q.put(None)
            with lock:
                if scan_id in scans:
                    scans[scan_id]["done"] = True

    threading.Thread(target=_run, daemon=True).start()
    return jsonify({"scan_id": scan_id, "asns": asn_list})


@asn_bp.route("/api/asn/amass", methods=["POST"])
@module_required("asn")
def amass_enum():
    body   = request.get_json(silent=True) or {}
    domain = (body.get("domain") or "").strip()
    if not domain:
        return jsonify({"error": "domain required"}), 400

    def generate():
        yield f"data: {json.dumps({'type': 'start', 'domain': domain})}\n\n"
        try:
            # Ensure go/bin on PATH
            env = os.environ.copy()
            go_bin = os.path.expanduser("~/go/bin")
            if go_bin not in env.get("PATH", ""):
                env["PATH"] = go_bin + ":" + env.get("PATH", "")

            cmd = ["amass", "enum", "-d", domain, "-passive"]
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                env=env,
            )
            domains = []
            deadline = time.time() + 120
            for line in proc.stdout:
                sub = line.strip()
                if sub:
                    domains.append(sub)
                    yield f"data: {json.dumps({'type': 'domain', 'domain': sub})}\n\n"
                if time.time() > deadline:
                    proc.kill()
                    yield f"data: {json.dumps({'type': 'warning', 'message': 'Timeout reached (120s), partial results shown'})}\n\n"
                    break
            proc.wait(timeout=5)
            yield f"data: {json.dumps({'type': 'done', 'count': len(domains)})}\n\n"
        except FileNotFoundError:
            yield f"data: {json.dumps({'type': 'error', 'message': 'amass not found — install with: apt install amass'})}\n\n"
            yield f"data: {json.dumps({'type': 'done', 'count': 0})}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n"
            yield f"data: {json.dumps({'type': 'done', 'count': 0})}\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
