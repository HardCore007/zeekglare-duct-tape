"""Sudomy — Subdomain Enumeration & Analysis blueprint."""
import json, os, re, shutil, subprocess, threading, time, uuid, queue
from flask import Blueprint, request, jsonify, Response, stream_with_context, g
from core.auth_utils import module_required, login_required
from core.session_manager import SessionManager

sudomy_bp = Blueprint("sudomy", __name__)

_ANSI = re.compile(r'\x1b\[[0-9;]*[mGKHF]')
_TOOLS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "xploiter-tools")
_SUDOMY_DIR = os.path.join(_TOOLS_DIR, "Sudomy")
_SUDOMY_BIN = os.path.join(_SUDOMY_DIR, "sudomy")

_scans = {}
_lock = threading.Lock()


def _sudomy_installed():
    return os.path.isfile(_SUDOMY_BIN) and os.access(_SUDOMY_BIN, os.X_OK)


def _sse(obj):
    return f"data: {json.dumps(obj)}\n\n"


def _classify(line):
    low = line.lower()
    if any(w in low for w in ("vuln", "takeover", "critical", "high")):
        return "vuln"
    if any(w in low for w in ("found", "subdomain", "discover")):
        return "finding"
    if any(w in low for w in ("error", "failed", "not found", "exception")):
        return "error"
    if any(w in low for w in ("warn",)):
        return "warning"
    if any(w in low for w in ("starting", "running", "checking", "scanning",
                               "complete", "finish", "done", "[*]", "[ ok ]")):
        return "progress"
    if any(w in low for w in ("[+]", "success")):
        return "success"
    return "info"


# ── Routes ────────────────────────────────────────────────────────────────────

@sudomy_bp.route("/api/sudomy/check")
def sudomy_check():
    """Check if Sudomy is installed and list available modules."""
    if not _sudomy_installed():
        return jsonify({
            "installed": False,
            "hint": "Click 'Install Sudomy' to clone and set up automatically.",
        })
    return jsonify({"installed": True, "path": _SUDOMY_BIN})


@sudomy_bp.route("/api/sudomy/install", methods=["POST"])
@module_required("sudomy")
def sudomy_install():
    """Clone Sudomy and install dependencies."""
    if _sudomy_installed():
        return jsonify({"ok": True, "message": "Sudomy already installed"})
    os.makedirs(_TOOLS_DIR, exist_ok=True)
    if not os.path.isdir(_SUDOMY_DIR):
        r = subprocess.run(
            ["git", "clone", "--depth", "1",
             "https://github.com/screetsec/Sudomy", _SUDOMY_DIR],
            capture_output=True, text=True, timeout=120,
        )
        if r.returncode != 0:
            return jsonify({"error": f"git clone failed: {r.stderr.strip()}"}), 500
    # Make executable
    if os.path.isfile(_SUDOMY_BIN):
        os.chmod(_SUDOMY_BIN, 0o755)
    # Install python deps if requirements exist
    req = os.path.join(_SUDOMY_DIR, "requirements.txt")
    if os.path.isfile(req):
        subprocess.run(["pip3", "install", "--break-system-packages",
                        "-q", "-r", req],
                       capture_output=True, timeout=180)
    return jsonify({"ok": _sudomy_installed()})


@sudomy_bp.route("/api/sudomy/scan", methods=["POST"])
@module_required("sudomy")
def sudomy_scan():
    """Start a Sudomy scan."""
    if not _sudomy_installed():
        return jsonify({"error": "Sudomy not installed"}), 500

    body = request.get_json(silent=True) or {}
    domain = (body.get("domain") or "").strip().lower()
    if not domain:
        return jsonify({"error": "domain required"}), 400

    modules = body.get("modules", [])  # e.g. ["-rS", "-pS", "-tO", "--httpx"]
    all_mode = body.get("all", False)

    out_base = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "data", "sudomy"
    )
    os.makedirs(out_base, exist_ok=True)
    out_dir = os.path.join(out_base, f"{domain}_{int(time.time())}")

    cmd = ["bash", _SUDOMY_BIN, "-d", domain, "-o", out_dir]
    if all_mode:
        cmd.append("-a")
    else:
        for m in modules:
            if isinstance(m, str) and m.startswith("-"):
                cmd.append(m)

    scan_id = str(uuid.uuid4())[:8]
    q = queue.Queue()

    with _lock:
        _scans[scan_id] = {
            "queue": q, "domain": domain, "done": False,
            "pid": None, "out_dir": out_dir,
            "user_id": getattr(g, "current_user", None) and g.current_user.id,
            "username": getattr(getattr(g, "current_user", None), "username", ""),
        }

    def _worker():
        start = time.time()
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1,
                env={**os.environ, "TERM": "dumb"},
                preexec_fn=os.setsid,
            )
            with _lock:
                if scan_id in _scans:
                    _scans[scan_id]["pid"] = proc.pid

            q.put({"type": "scan_start", "scan_id": scan_id,
                   "domain": domain, "cmd": " ".join(cmd)})

            for raw in proc.stdout:
                line = _ANSI.sub("", raw).rstrip()
                if not line:
                    continue
                tag = _classify(line)
                q.put({"type": "line", "line": line, "tag": tag,
                       "elapsed": round(time.time() - start, 1)})

            proc.wait()
            elapsed = round(time.time() - start, 1)

            # Parse output directory for results
            results = _parse_output(out_dir, domain)
            q.put({"type": "complete", "scan_id": scan_id,
                   "elapsed": elapsed, "return_code": proc.returncode,
                   "results": results, "out_dir": out_dir})

            # Persist session
            try:
                _uid = ""
                _un  = ""
                with _lock:
                    s = _scans.get(scan_id)
                    if s:
                        _uid = s.get("user_id")
                        _un  = s.get("username", "")
                summary = {
                    "status":           "completed",
                    "total_subdomains": results.get("total_subdomains", 0),
                    "total_live":       results.get("total_live", 0),
                    "total_ports":      results.get("total_ports", 0),
                    "total_takeover":   results.get("total_takeover", 0),
                    "elapsed":          elapsed,
                }
                SessionManager.save(
                    scan_id=scan_id, scan_type="sudomy", target=domain,
                    name=f"Sudomy — {domain}", summary=summary, data=results,
                    user_id=_uid, username=_un,
                )
            except Exception:
                pass
        except Exception as e:
            q.put({"type": "error", "error": str(e)})
        finally:
            q.put(None)  # sentinel
            with _lock:
                if scan_id in _scans:
                    _scans[scan_id]["done"] = True
            # Notify
            _notify_args = None
            with _lock:
                s = _scans.get(scan_id)
                if s:
                    _notify_args = (s.get("user_id"), "sudomy",
                                    domain, 0, "Sudomy Recon")
            if _notify_args:
                try:
                    from core.notifications import notify_scan_complete
                    notify_scan_complete(*_notify_args)
                except Exception:
                    pass

    threading.Thread(target=_worker, daemon=True).start()
    return jsonify({"scan_id": scan_id, "domain": domain})


@sudomy_bp.route("/api/sudomy/stream/<scan_id>")
@module_required("sudomy")
def sudomy_stream(scan_id):
    with _lock:
        scan = _scans.get(scan_id)
    if not scan:
        return jsonify({"error": "Not found"}), 404

    q = scan["queue"]

    def generate():
        while True:
            try:
                item = q.get(timeout=90)
                if item is None:
                    yield _sse({"type": "done"})
                    break
                yield _sse(item)
            except queue.Empty:
                yield _sse({"type": "keepalive"})

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@sudomy_bp.route("/api/sudomy/stop/<scan_id>", methods=["POST"])
@module_required("sudomy")
def sudomy_stop(scan_id):
    with _lock:
        scan = _scans.get(scan_id)
    if not scan:
        return jsonify({"error": "Not found"}), 404
    pid = scan.get("pid")
    if pid:
        try:
            import signal
            os.killpg(os.getpgid(pid), signal.SIGTERM)
        except Exception:
            try:
                os.kill(pid, 9)
            except Exception:
                pass
    return jsonify({"ok": True})


@sudomy_bp.route("/api/sudomy/results/<scan_id>")
def sudomy_results(scan_id):
    """Return parsed results for a completed scan."""
    with _lock:
        scan = _scans.get(scan_id)
    if not scan:
        return jsonify({"error": "Not found"}), 404
    out_dir = scan.get("out_dir", "")
    if not out_dir or not os.path.isdir(out_dir):
        return jsonify({"results": {}})
    return jsonify({"results": _parse_output(out_dir, scan["domain"])})


# ── Output parser ─────────────────────────────────────────────────────────────

def _read_lines(path, max_lines=5000):
    """Read non-empty lines from a file."""
    if not os.path.isfile(path):
        return []
    try:
        with open(path, "r", errors="replace") as f:
            return [l.strip() for l in f if l.strip()][:max_lines]
    except Exception:
        return []


def _find_files(base, patterns):
    """Find files matching name patterns recursively."""
    found = {}
    if not os.path.isdir(base):
        return found
    for root, _, files in os.walk(base):
        for f in files:
            low = f.lower()
            for pat, key in patterns:
                if pat in low:
                    path = os.path.join(root, f)
                    if key not in found:
                        found[key] = path
    return found


def _parse_output(out_dir, domain):
    """Parse Sudomy output directory into structured results."""
    results = {
        "subdomains": [],
        "resolved": [],
        "live_hosts": [],
        "virtual_hosts": [],
        "ports": [],
        "takeover": [],
        "screenshots": [],
        "technologies": [],
        "interesting": [],
        "total_subdomains": 0,
        "total_live": 0,
        "total_ports": 0,
        "total_takeover": 0,
    }

    if not os.path.isdir(out_dir):
        return results

    # Search through output directory for known files
    file_map = _find_files(out_dir, [
        ("subdomain", "subdomains"),
        ("resolved", "resolved"),
        ("httpx", "live"),
        ("httprobe", "live2"),
        ("ip_", "ips"),
        ("virtual", "vhosts"),
        ("port", "ports"),
        ("takeover", "takeover"),
        ("screenshot", "screenshots_dir"),
        ("technolog", "tech"),
        ("interesting", "interesting"),
        ("juicy", "juicy"),
        ("alive", "alive"),
    ])

    # Subdomains
    for key in ("subdomains",):
        if key in file_map:
            results["subdomains"] = _read_lines(file_map[key])

    # Resolved / IPs
    if "resolved" in file_map:
        results["resolved"] = _read_lines(file_map["resolved"])
    elif "ips" in file_map:
        results["resolved"] = _read_lines(file_map["ips"])

    # Live hosts
    for key in ("live", "live2", "alive"):
        if key in file_map:
            results["live_hosts"] = _read_lines(file_map[key])
            break

    # Virtual hosts
    if "vhosts" in file_map:
        results["virtual_hosts"] = _read_lines(file_map["vhosts"])

    # Ports
    if "ports" in file_map:
        results["ports"] = _read_lines(file_map["ports"])

    # Takeover
    if "takeover" in file_map:
        results["takeover"] = _read_lines(file_map["takeover"])

    # Technologies
    if "tech" in file_map:
        results["technologies"] = _read_lines(file_map["tech"])

    # Interesting / juicy paths
    for key in ("interesting", "juicy"):
        if key in file_map:
            results["interesting"] = _read_lines(file_map[key])
            break

    # Screenshots — list image files
    for root, _, files in os.walk(out_dir):
        for f in files:
            if f.lower().endswith((".png", ".jpg", ".jpeg")):
                results["screenshots"].append(os.path.join(root, f))

    # Also scan all .txt files not yet matched for additional data
    for root, _, files in os.walk(out_dir):
        for f in files:
            if f.endswith(".txt"):
                path = os.path.join(root, f)
                if path not in file_map.values():
                    lines = _read_lines(path, 200)
                    if lines:
                        low = f.lower()
                        # Auto-classify by content heuristic
                        if not results["subdomains"] and any("." in l for l in lines[:5]):
                            results["subdomains"] = lines

    results["total_subdomains"] = len(results["subdomains"])
    results["total_live"] = len(results["live_hosts"])
    results["total_ports"] = len(results["ports"])
    results["total_takeover"] = len(results["takeover"])

    return results
