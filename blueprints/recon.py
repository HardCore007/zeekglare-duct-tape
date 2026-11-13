"""ReconFTW blueprint."""
from core.auth_utils import module_required
import threading, uuid, queue, json, os, pathlib, re, time, shlex
from flask import Blueprint, request, jsonify, Response, stream_with_context, g
from services.recon_runner import find_reconftw, run_recon

_ANSI = re.compile(r'\x1b\[[0-9;]*[mGKHF]')
_SAFE_DOMAIN = re.compile(r'^[a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)*$')
_SAFE_PATH   = re.compile(r'^[\w/.~-]+$')
_SAFE_FLAG   = re.compile(r'^-[a-zA-Z0-9-]+$')

def _classify(line):
    low = line.lower()
    if any(w in low for w in ("vulnerability","xss","sqli","vuln","critical","high severity")):
        return "vuln"
    if any(w in low for w in ("found","subdomain","discovered")):
        return "finding"
    if any(w in low for w in ("error","failed","exception")):
        return "error"
    if any(w in low for w in ("warn",)):
        return "warning"
    if any(w in low for w in ("starting","running","checking","scanning","complete","finished","done")):
        return "progress"
    if any(w in low for w in ("success","✓","[+]")):
        return "success"
    return "info"

def _sse(obj):
    return f"data: {json.dumps(obj)}\n\n"

recon_bp    = Blueprint("recon", __name__)
recon_scans = {}
lock        = threading.Lock()


@recon_bp.route("/api/recon/check", methods=["GET"])
def recon_check():
    path = find_reconftw()
    if not path:
        return jsonify({
            "installed": False, "path": None,
            "hint": "git clone https://github.com/six2dez/reconftw && cd reconftw && ./install.sh",
        })
    try:
        import subprocess
        result = subprocess.run(["bash", path, "--help"],
                                capture_output=True, text=True, timeout=10)
        return jsonify({"installed": True, "path": path,
                        "version": (result.stdout or result.stderr or "")[:300]})
    except Exception as e:
        return jsonify({"installed": True, "path": path, "version": str(e)})


@recon_bp.route("/api/recon/scan", methods=["POST"])
@module_required("recon")
def start_recon_scan():
    body    = request.get_json(silent=True) or {}
    domain  = (body.get("domain") or "").strip().lower()
    if not domain:
        return jsonify({"error": "domain required"}), 400

    mode    = body.get("mode", "-r")
    flags   = body.get("flags", [])
    out_dir = body.get("output_dir", "").strip() or f"data/recon/{str(uuid.uuid4())}"
    # Prevent path traversal: ensure out_dir stays under data/recon
    resolved = pathlib.Path(out_dir).resolve()
    base = pathlib.Path("data/recon").resolve()
    if not str(resolved).startswith(str(base)):
        return jsonify({"error": "invalid output directory"}), 400

    scan_id = str(uuid.uuid4())
    q       = queue.Queue()

    _u = getattr(g, "current_user", None)
    with lock:
        recon_scans[scan_id] = {
            "queue": q, "domain": domain, "mode": mode, "pid": None, "done": False,
            "started_at": time.time(),
            "username": _u.username if _u else "",
        }

    threading.Thread(
        target=run_recon,
        args=(scan_id, domain, mode, flags, out_dir, q, recon_scans, lock),
        kwargs={"user_id": _u.id if _u else None, "username": _u.username if _u else ""},
        daemon=True,
    ).start()
    return jsonify({"scan_id": scan_id, "domain": domain, "mode": mode})


@recon_bp.route("/api/recon/stream/<scan_id>")
@module_required("recon")
def stream_recon(scan_id):
    with lock:
        scan = recon_scans.get(scan_id)
    if not scan:
        return jsonify({"error": "Not found"}), 404

    q = scan["queue"]

    def generate():
        while True:
            try:
                item = q.get(timeout=90)
                if item is None:
                    yield f"data: {json.dumps({'type': 'done'})}\n\n"
                    break
                yield f"data: {json.dumps(item)}\n\n"
            except queue.Empty:
                yield f"data: {json.dumps({'type': 'keepalive'})}\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@recon_bp.route("/api/recon/stop/<scan_id>", methods=["POST"])
def stop_recon(scan_id):
    with lock:
        scan = recon_scans.get(scan_id)
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


@recon_bp.route("/api/recon/remote-check", methods=["POST"])
def remote_check():
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
        _, stdout, _ = client.exec_command("which reconftw 2>/dev/null && echo EXISTS || echo MISSING")
        result    = stdout.read().decode().strip()
        _, stdout2, _ = client.exec_command("which reconftw 2>/dev/null")
        rf_which  = stdout2.read().decode().strip()
        _, stdout3, _ = client.exec_command("uname -a")
        uname = stdout3.read().decode().strip()
        client.close()
        return jsonify({
            "ok": True,
            "reconftw_found": "EXISTS" in result,
            "reconftw_path": rf_which or "reconftw",
            "uname": uname,
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@recon_bp.route("/api/recon/remote-scan", methods=["POST"])
@module_required("recon")
def remote_scan():
    body     = request.get_json(silent=True) or {}
    host     = (body.get("host") or "").strip()
    port     = int(body.get("port") or 22)
    user     = (body.get("user") or "").strip()
    key_path = (body.get("key_path") or "").strip()
    password = (body.get("password") or "").strip()
    domain   = (body.get("domain") or "").strip().lower()
    mode     = (body.get("mode") or "-r").strip()
    flags    = body.get("flags", [])
    out_dir  = (body.get("output_dir") or f"~/reconftw_results/{domain}").strip()

    if not host or not user or not domain:
        return jsonify({"error": "host, user, and domain required"}), 400
    if not _SAFE_DOMAIN.match(domain):
        return jsonify({"error": "invalid domain"}), 400
    if not _SAFE_FLAG.match(mode):
        return jsonify({"error": "invalid mode"}), 400
    if not _SAFE_PATH.match(out_dir) or ".." in out_dir:
        return jsonify({"error": "invalid output directory"}), 400
    for f in flags:
        if isinstance(f, str) and not _SAFE_FLAG.match(f):
            return jsonify({"error": f"invalid flag: {f}"}), 400

    scan_id = str(uuid.uuid4())

    # reconftw is available in PATH on the remote machine
    flag_str   = " ".join(f for f in flags if isinstance(f, str) and f.startswith("-"))
    remote_cmd = f"reconftw -d {shlex.quote(domain)} {shlex.quote(mode)} --output {shlex.quote(out_dir)} {flag_str}".strip()

    def generate():
        start = time.time()
        try:
            client = _ssh_client(host, port, user, key_path, password)
        except Exception as e:
            yield _sse({"type": "recon_error", "error": f"SSH connection failed: {e}"})
            yield _sse({"type": "done"})
            return

        yield _sse({"type": "recon_start", "scan_id": scan_id, "domain": domain,
                    "mode": mode, "cmd": remote_cmd,
                    "host": f"{user}@{host}:{port}"})

        try:
            # Use PTY so reconftw thinks it has a terminal (colors etc)
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
                            yield _sse({"type": "recon_line", "line": line, "tag": tag})
                elif chan.exit_status_ready():
                    # Drain remaining
                    remaining = _ANSI.sub("", buf).strip()
                    if remaining:
                        yield _sse({"type": "recon_line", "line": remaining, "tag": "info"})
                    break
                else:
                    time.sleep(0.05)

            rc = chan.recv_exit_status()
            elapsed = round(time.time() - start, 1)
            yield _sse({"type": "recon_complete", "scan_id": scan_id,
                        "return_code": rc, "output_dir": out_dir,
                        "elapsed": elapsed, "results": {}})

        except Exception as e:
            yield _sse({"type": "recon_error", "error": str(e)})
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


@recon_bp.route("/api/recon/remote-stop", methods=["POST"])
def remote_stop():
    # Nothing to kill server-side for remote — the client closes the SSE stream
    # which causes the generator to stop; the remote process will continue unless
    # the user manually kills it, or we kill via a second SSH connection.
    body     = request.get_json(silent=True) or {}
    host     = (body.get("host") or "").strip()
    port     = int(body.get("port") or 22)
    user     = (body.get("user") or "").strip()
    key_path = (body.get("key_path") or "").strip()
    password = (body.get("password") or "").strip()
    domain   = (body.get("domain") or "").strip()

    if host and user and domain:
        if not _SAFE_DOMAIN.match(domain):
            return jsonify({"error": "invalid domain"}), 400
        try:
            client = _ssh_client(host, port, user, key_path, password)
            client.exec_command(f"pkill -f {shlex.quote('reconftw.*' + domain)}")
            client.close()
        except Exception:
            pass
    return jsonify({"ok": True})
