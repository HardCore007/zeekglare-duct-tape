"""OneForAll subdomain enumeration blueprint."""
from core.auth_utils import module_required
import threading, uuid, queue, json, os, re, time
from flask import Blueprint, request, jsonify, Response, stream_with_context, g
from services.oneforall_runner import find_oneforall, run_oneforall

_ANSI = re.compile(r'\x1b\[[0-9;]*[mGKHF]')
_SAFE_DOMAIN = re.compile(r'^[a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)*$')
_SAFE_PATH   = re.compile(r'^[\w/.~-]+$')

ofa_bp = Blueprint("oneforall", __name__)
ofa_scans = {}
ofa_lock  = threading.Lock()


def _sse(obj):
    return f"data: {json.dumps(obj)}\n\n"


@ofa_bp.route("/api/ofa/check", methods=["GET"])
def ofa_check():
    path = find_oneforall()
    if not path:
        return jsonify({
            "installed": False, "path": None,
            "hint": "git clone https://github.com/shmilylty/OneForAll && cd OneForAll && pip3 install -r requirements.txt",
        })
    return jsonify({"installed": True, "path": path})


@ofa_bp.route("/api/ofa/scan", methods=["POST"])
@module_required("oneforall")
def ofa_start():
    body   = request.get_json(silent=True) or {}
    domain = (body.get("domain") or "").strip().lower()
    if not domain:
        return jsonify({"error": "domain required"}), 400

    brute     = body.get("brute", False)
    dns_srv   = body.get("dns", False)
    port_scan = body.get("port_scan", False)
    out_dir   = body.get("output_dir", "").strip() or f"data/oneforall/{uuid.uuid4()}"

    scan_id = str(uuid.uuid4())
    q       = queue.Queue()

    with ofa_lock:
        ofa_scans[scan_id] = {"queue": q, "domain": domain, "pid": None, "done": False}

    _u = getattr(g, "current_user", None)
    threading.Thread(
        target=run_oneforall,
        args=(scan_id, domain, brute, dns_srv, port_scan, out_dir, q, ofa_scans, ofa_lock),
        kwargs={"user_id": _u.id if _u else None, "username": _u.username if _u else ""},
        daemon=True,
    ).start()
    return jsonify({"scan_id": scan_id, "domain": domain})


@ofa_bp.route("/api/ofa/stream/<scan_id>")
@module_required("oneforall")
def ofa_stream(scan_id):
    with ofa_lock:
        scan = ofa_scans.get(scan_id)
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


@ofa_bp.route("/api/ofa/stop/<scan_id>", methods=["POST"])
def ofa_stop(scan_id):
    with ofa_lock:
        scan = ofa_scans.get(scan_id)
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


# ── Remote SSH execution ───────────────────────────────────────────────────

def _ssh_client(host, port, user, key_path, password):
    """Build and return a connected paramiko SSHClient."""
    import paramiko
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kw = {"hostname": host, "port": int(port or 22), "username": user, "timeout": 20}
    if key_path and os.path.isfile(os.path.expanduser(key_path)):
        kw["key_filename"] = os.path.expanduser(key_path)
    elif password:
        kw["password"] = password
    client.connect(**kw)
    return client


def _classify(line):
    low = line.lower()
    if any(w in low for w in ("subdomain", "found", "alive", "discovered")):
        return "finding"
    if any(w in low for w in ("error", "failed", "exception", "traceback")):
        return "error"
    if any(w in low for w in ("warn",)):
        return "warning"
    if any(w in low for w in ("starting", "running", "collecting", "brute", "request")):
        return "progress"
    if any(w in low for w in ("complete", "finished", "done", "total", "success")):
        return "success"
    return "info"


@ofa_bp.route("/api/ofa/remote-check", methods=["POST"])
def ofa_remote_check():
    body     = request.get_json(silent=True) or {}
    host     = (body.get("host") or "").strip()
    port     = int(body.get("port") or 22)
    user     = (body.get("user") or "").strip()
    key_path = (body.get("key_path") or "").strip()
    password = (body.get("password") or "").strip()

    if not host or not user:
        return jsonify({"ok": False, "error": "host and user required"}), 400

    try:
        client = _ssh_client(host, port, user, key_path, password)
        _, stdout, _ = client.exec_command("find ~ /opt /usr/share -name 'oneforall.py' -type f 2>/dev/null | head -3")
        paths = stdout.read().decode().strip()
        _, stdout2, _ = client.exec_command("uname -a")
        uname = stdout2.read().decode().strip()
        client.close()
        ofa_found = bool(paths)
        ofa_path  = paths.splitlines()[0] if paths else ""
        return jsonify({
            "ok": True,
            "oneforall_found": ofa_found,
            "oneforall_path": ofa_path,
            "uname": uname,
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@ofa_bp.route("/api/ofa/remote-scan", methods=["POST"])
@module_required("oneforall")
def ofa_remote_scan():
    body     = request.get_json(silent=True) or {}
    host     = (body.get("host") or "").strip()
    port     = int(body.get("port") or 22)
    user     = (body.get("user") or "").strip()
    key_path = (body.get("key_path") or "").strip()
    password = (body.get("password") or "").strip()
    domain   = (body.get("domain") or "").strip().lower()
    brute    = body.get("brute", False)
    dns_srv  = body.get("dns", False)
    port_scan = body.get("port_scan", False)
    out_dir  = (body.get("output_dir") or f"~/oneforall_results/{domain}").strip()

    if not host or not user or not domain:
        return jsonify({"error": "host, user, and domain required"}), 400
    if not _SAFE_DOMAIN.match(domain):
        return jsonify({"error": "invalid domain"}), 400
    if not _SAFE_PATH.match(out_dir):
        return jsonify({"error": "invalid output directory"}), 400

    scan_id = str(uuid.uuid4())

    # Build remote command
    remote_cmd = f"cd ~/OneForAll && python3 oneforall.py --target {domain} --path {out_dir}"
    if brute:
        remote_cmd += " --brute True"
    if dns_srv:
        remote_cmd += " --dns True"
    if port_scan:
        remote_cmd += " --port small"
    remote_cmd += " run"

    def generate():
        start = time.time()
        try:
            client = _ssh_client(host, port, user, key_path, password)
        except Exception as e:
            yield _sse({"type": "ofa_error", "error": f"SSH connection failed: {e}"})
            yield _sse({"type": "done"})
            return

        yield _sse({"type": "ofa_start", "scan_id": scan_id, "domain": domain,
                    "cmd": remote_cmd, "host": f"{user}@{host}:{port}"})

        try:
            transport = client.get_transport()
            chan = transport.open_session()
            chan.get_pty(term="xterm", width=220, height=50)
            chan.exec_command(remote_cmd)

            buf = ""
            while True:
                if chan.recv_ready():
                    chunk = chan.recv(4096).decode("utf-8", errors="replace")
                    buf += chunk
                    while "\n" in buf:
                        line, buf = buf.split("\n", 1)
                        line = _ANSI.sub("", line).rstrip()
                        if line:
                            tag = _classify(line)
                            yield _sse({"type": "ofa_line", "line": line, "tag": tag})
                elif chan.exit_status_ready():
                    remaining = _ANSI.sub("", buf).strip()
                    if remaining:
                        yield _sse({"type": "ofa_line", "line": remaining, "tag": "info"})
                    break
                else:
                    time.sleep(0.05)

            rc = chan.recv_exit_status()
            elapsed = round(time.time() - start, 1)
            yield _sse({"type": "ofa_complete", "scan_id": scan_id,
                        "return_code": rc, "output_dir": out_dir,
                        "elapsed": elapsed, "results": {}})
        except Exception as e:
            yield _sse({"type": "ofa_error", "error": str(e)})
        finally:
            try:
                client.close()
            except Exception:
                pass
            yield _sse({"type": "done"})

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@ofa_bp.route("/api/ofa/remote-stop", methods=["POST"])
def ofa_remote_stop():
    body     = request.get_json(silent=True) or {}
    host     = (body.get("host") or "").strip()
    port     = int(body.get("port") or 22)
    user     = (body.get("user") or "").strip()
    key_path = (body.get("key_path") or "").strip()
    password = (body.get("password") or "").strip()
    domain   = (body.get("domain") or "").strip()

    if host and user and domain:
        try:
            client = _ssh_client(host, port, user, key_path, password)
            client.exec_command(f"pkill -f 'oneforall.*{domain}'")
            client.close()
        except Exception:
            pass
    return jsonify({"ok": True})
