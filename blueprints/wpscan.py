import json, os, re, shutil, subprocess, tempfile, threading, time, uuid
from flask import Blueprint, request, Response, jsonify, stream_with_context, g
from core.auth_utils import module_required, rate_limit
from core.session_manager import SessionManager

wpscan_bp = Blueprint("wpscan", __name__)


def _persist_wpscan(job_id, snap):
    """Persist WPScan/WPProbe findings as a session."""
    findings = snap.get("findings", []) or []
    target   = snap.get("target", "") or ""
    tool     = snap.get("tool", "wpscan")
    mode     = snap.get("mode", "enum")

    vulns    = [f for f in findings if f.get("type") == "vuln"]
    plugins  = [f for f in findings if f.get("type") in ("plugin_found", "plugin")]
    themes   = [f for f in findings if f.get("type") == "theme"]
    users    = [f for f in findings if f.get("type") == "user"]
    creds    = [f for f in findings if f.get("type") == "credential"]
    versions = [f for f in findings if f.get("type") == "version"]

    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for v in vulns:
        s = (v.get("severity") or "medium").lower()
        if s in sev_counts:
            sev_counts[s] += 1

    name = f"WPScan — {target}" if target else "WPScan"
    summary = {
        "status":      "completed",
        "tool":        tool,
        "mode":        mode,
        "total_vulns": len(vulns),
        "plugins":     len(plugins),
        "themes":      len(themes),
        "users":       len(users),
        "credentials": len(creds),
        **sev_counts,
    }
    data = {
        "vulns":       vulns,
        "plugins":     plugins,
        "themes":      themes,
        "users":       users,
        "credentials": creds,
        "version":     versions[0] if versions else {},
        "target":      target,
        "tool":        tool,
    }
    try:
        SessionManager.save(
            scan_id=job_id, scan_type="wpscan", target=target,
            name=name, summary=summary, data=data,
            user_id=snap.get("user_id"), username=snap.get("username", ""),
        )
    except Exception:
        pass

_WPSCAN  = shutil.which("wpscan") or "/usr/bin/wpscan"

def _find_wpprobe():
    """Resolve wpprobe binary — check PATH, common go locations, /usr/local/bin."""
    p = shutil.which("wpprobe")
    if p:
        return p
    for candidate in [
        "/usr/local/bin/wpprobe",
        "/root/go/bin/wpprobe",
        os.path.expanduser("~/go/bin/wpprobe"),
    ]:
        if os.path.isfile(candidate):
            return candidate
    return None

_WPPROBE = _find_wpprobe()
_jobs   = {}   # job_id → {proc, done, findings, target, mode, tool}
_lock   = threading.Lock()

_ANSI = re.compile(r'\x1b\[[0-9;]*[mGKHF]')

# ── Output parsers ──────────────────────────────────────────────────────────
_VER_RE   = re.compile(r'WordPress version ([\d.]+)', re.I)
_THEME_RE = re.compile(r'theme in use:\s+(\S+)', re.I)
_VULN_RE  = re.compile(r'\[!\]\s+Title:\s+(.+)', re.I)
_FIX_RE   = re.compile(r'Fixed in:\s+([\d.]+)', re.I)
_URL_RE   = re.compile(r'https?://\S+')
_CRED_RE  = re.compile(r'\[SUCCESS\].*?-\s+(\S+)\s+/\s+(\S+)', re.I)
_PROG_RE  = re.compile(r'\((\d+)\s*/\s*(\d+)\)')
_PLUG_RE  = re.compile(r'^\[.\]\s+([\w\-]+)\s*$')
_USER_RE  = re.compile(r'^\[.\]\s+([\w.\-@]+)\s*$')


def _sse(obj):
    return f"data: {json.dumps(obj)}\n\n"


def _line_level(line):
    if line.startswith("[+]"):  return "found"
    if line.startswith("[!]"):  return "warn"
    if line.startswith("[-]"):  return "error"
    return "info"


# ── Routes ──────────────────────────────────────────────────────────────────

@wpscan_bp.route("/api/wpscan/check")
def wpscan_check():
    ws_ok = bool(_WPSCAN and os.path.isfile(_WPSCAN))
    wp_path = _WPPROBE or _find_wpprobe()
    wp_ok = bool(wp_path and os.path.isfile(wp_path))
    return jsonify({
        "available": ws_ok, "path": _WPSCAN if ws_ok else None,
        "wpprobe_available": wp_ok, "wpprobe_path": wp_path if wp_ok else None,
    })


@wpscan_bp.route("/api/wpscan/start", methods=["POST"])
@module_required("wpscan")
@rate_limit(max_requests=5, window_seconds=60)
def wpscan_start():
    body    = request.get_json(silent=True) or {}
    tool    = (body.get("tool") or "wpscan").strip().lower()   # wpscan | wpprobe
    mode    = (body.get("mode") or "enum").strip()             # enum | brute
    url     = (body.get("url") or "").strip().rstrip("/")
    threads = max(1, min(50, int(body.get("threads") or 5)))
    api_tok = (body.get("api_token") or "").strip()

    if not url:
        return jsonify({"error": "url required"}), 400

    # ── WPProbe branch ───────────────────────────────────────────────────────
    if tool == "wpprobe":
        wp_bin = _WPPROBE or _find_wpprobe()
        if not (wp_bin and os.path.isfile(wp_bin)):
            return jsonify({"error": "wpprobe not found — run: go install github.com/Chocapikk/wpprobe@latest"}), 500
        wp_threads = max(1, min(100, int(body.get("workers") or body.get("threads") or 10)))
        wp_mode = (body.get("wp_mode") or "stealthy").strip()
        cmd = [wp_bin, "scan", "-u", url, "-t", str(wp_threads), "-m", wp_mode, "-v"]
        extra = (body.get("extra") or "").strip()
        if extra:
            cmd += extra.split()
        job_id = str(uuid.uuid4())[:8]
        proc   = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1,
            env={**os.environ, "TERM": "dumb", "NO_COLOR": "1"},
        )
        with _lock:
            _jobs[job_id] = {
                "proc": proc, "done": False, "tool": "wpprobe",
                "findings": [], "events": [], "target": url, "mode": "enum",
                "started_at": time.time(),
                "user_id": getattr(g, "current_user", None) and g.current_user.id,
                "username": getattr(getattr(g, "current_user", None), "username", ""),
            }

        def _wpprobe_worker():
            job   = _jobs[job_id]
            start = time.time()

            # Patterns for WPProbe v0.11.x tree-style output
            # e.g. "│   ├── gutenberg (22.9.0)"
            # e.g. "│   ├── jetpack (15.5) [CVE-2024-1234] Critical"
            _TREE_ITEM   = re.compile(r'[├└]──\s+(.+)')
            _ITEM_PARSE  = re.compile(r'^([\w\-]+)\s*(?:\(([^)]*)\))?(.*)$')
            _CVE_RE      = re.compile(r'CVE-\d{4}-\d+', re.I)
            _SEV_RE      = re.compile(r'\b(Critical|High|Medium|Low)\b', re.I)
            _SUMMARY_RE  = re.compile(r'Critical:\s*(\d+)\s*\|\s*High:\s*(\d+)\s*\|\s*Medium:\s*(\d+)\s*\|\s*Low:\s*(\d+)', re.I)

            section = None  # "plugins" | "themes"

            def _push(ev):
                with _lock:
                    if job_id in _jobs:
                        _jobs[job_id]["events"].append(ev)

            for raw in proc.stdout:
                line = _ANSI.sub("", raw).rstrip()
                if not line:
                    continue
                elapsed = round(time.time() - start, 1)
                level   = _line_level(line)
                _push({"type": "log", "line": line, "level": level, "elapsed": elapsed})
                clean = line.strip()

                # Detect summary line: "Critical: 0 | High: 2 | Medium: 1 | Low: 0"
                sm = _SUMMARY_RE.search(clean)
                if sm:
                    _push({"type": "summary",
                           "critical": int(sm.group(1)), "high": int(sm.group(2)),
                           "medium": int(sm.group(3)), "low": int(sm.group(4))})
                    continue

                # Track which section we're in
                if "Plugins" in clean and ("├" in clean or "│" in clean):
                    section = "plugins"
                    continue
                if "Themes" in clean and ("├" in clean or "│" in clean):
                    section = "themes"
                    continue
                if "Warning" in clean and "└" in clean:
                    section = None
                    continue

                # Parse tree items (plugins/themes)
                tm = _TREE_ITEM.search(clean)
                if tm and section:
                    item_text = tm.group(1).strip()
                    im = _ITEM_PARSE.match(item_text)
                    if im:
                        name    = im.group(1)
                        version = im.group(2) or "unknown"
                        rest    = im.group(3) or ""

                        # Check for vulnerabilities in the line
                        cves     = _CVE_RE.findall(rest)
                        sev_m    = _SEV_RE.search(rest)
                        severity = sev_m.group(1) if sev_m else None

                        if section == "themes":
                            ev = {"type": "theme", "name": name, "version": version}
                            job["findings"].append(ev)
                            _push(ev)
                        else:
                            ev = {"type": "plugin_found", "name": name,
                                  "version": version, "line": item_text}
                            job["findings"].append(ev)
                            _push(ev)

                        if cves or severity:
                            title = f"{name} ({version})"
                            if cves:
                                title += " — " + ", ".join(cves)
                            vev = {"type": "vuln", "title": title,
                                   "plugin": name, "severity": severity or "info",
                                   "refs": cves}
                            job["findings"].append(vev)
                            _push(vev)

                # Fallback: detect CVE lines outside tree
                if _CVE_RE.search(clean) and not tm:
                    vev = {"type": "vuln", "title": clean, "plugin": None,
                           "severity": (_SEV_RE.search(clean) or [None, "info"])[1],
                           "refs": _CVE_RE.findall(clean)}
                    job["findings"].append(vev)
                    _push(vev)

            proc.wait()
            total_vulns = sum(1 for f in job["findings"] if f["type"] == "vuln")
            _push({"type": "done", "elapsed": round(time.time() - start, 1),
                   "vulns": total_vulns, "users": 0, "credentials": 0})
            _notify_args = None
            _snap = None
            with _lock:
                if job_id in _jobs:
                    _jobs[job_id]["done"] = True
                    _uid  = _jobs[job_id].get("user_id")
                    _tgt  = _jobs[job_id].get("target", "")
                    _hits = len(_jobs[job_id].get("findings", []))
                    _notify_args = (_uid, "wpscan", _tgt, _hits, "WPProbe")
                    _snap = {
                        "findings": list(_jobs[job_id].get("findings", [])),
                        "target":   _tgt,
                        "tool":     "wpprobe",
                        "mode":     "enum",
                        "user_id":  _uid,
                        "username": _jobs[job_id].get("username", ""),
                    }
            if _snap:
                _persist_wpscan(job_id, _snap)
            if _notify_args:
                from core.notifications import notify_scan_complete
                notify_scan_complete(*_notify_args)

        threading.Thread(target=_wpprobe_worker, daemon=True).start()
        return jsonify({"job_id": job_id, "mode": "enum", "tool": "wpprobe", "cmd": " ".join(cmd)})

    # ── WPScan branch ────────────────────────────────────────────────────────
    if not (_WPSCAN and os.path.isfile(_WPSCAN)):
        return jsonify({"error": "wpscan not found"}), 500

    # Per-user writable cache dir — avoids "Permission denied @ rb_sysopen - /tmp/wpscan/cache"
    # when /tmp/wpscan is owned by another user (e.g. root leftover from a prior run).
    _wp_cache = os.path.join(tempfile.gettempdir(), f"wpscan-cache-{os.getuid()}")
    try:
        os.makedirs(_wp_cache, exist_ok=True)
        os.chmod(_wp_cache, 0o700)
    except Exception:
        pass

    cmd = [_WPSCAN, "--url", url, "--no-banner", "--disable-tls-checks",
           "--cache-dir", _wp_cache,
           "-t", str(threads), "--random-user-agent"]

    if api_tok:
        cmd += ["--api-token", api_tok]

    if mode == "brute":
        passlist  = (body.get("passlist") or "").strip()
        usernames = (body.get("usernames") or "admin").strip()
        attack    = (body.get("attack") or "xmlrpc").strip()
        if passlist:
            real = os.path.realpath(passlist)
            if ".." in passlist or not real.startswith("/"):
                return jsonify({"error": "invalid password list path"}), 400
        if not passlist or not os.path.isfile(passlist):
            return jsonify({"error": f"Password list not found: {passlist}"}), 400
        cmd += ["-U", usernames, "-P", passlist]
        if attack:
            cmd += ["--password-attack", attack]
        # Also enumerate users if not provided explicitly
        cmd += ["--enumerate", "u"]
    else:
        # Enum mode — build flag list from body
        flags = []
        for f in ["vp", "ap", "p", "vt", "at", "t", "u", "tt", "cb", "dbe"]:
            if body.get(f"e_{f}", False):
                flags.append(f)
        if not flags:
            flags = ["vp", "vt", "u", "cb"]
        cmd += ["--enumerate", ",".join(flags)]

    job_id = str(uuid.uuid4())[:8]
    proc   = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1,
        env={**os.environ, "TERM": "dumb"},
    )
    with _lock:
        _jobs[job_id] = {
            "proc": proc, "done": False, "tool": "wpscan",
            "findings": [], "events": [], "target": url, "mode": mode,
            "started_at": time.time(),
            "user_id": getattr(g, "current_user", None) and g.current_user.id,
            "username": getattr(getattr(g, "current_user", None), "username", ""),
        }

    def _worker():
        job   = _jobs[job_id]
        start = time.time()

        in_users   = False
        in_plugin  = False
        cur_plugin = None
        cur_vuln   = None
        vuln_refs  = []

        def _push(ev):
            with _lock:
                if job_id in _jobs:
                    _jobs[job_id]["events"].append(ev)

        def flush_vuln():
            nonlocal cur_vuln, vuln_refs
            if cur_vuln:
                entry = {"type": "vuln", **cur_vuln, "refs": vuln_refs[:]}
                job["findings"].append(entry)
                _push(entry)
            cur_vuln  = None
            vuln_refs = []

        for raw in proc.stdout:
            line = _ANSI.sub("", raw).rstrip()
            if not line:
                continue
            elapsed = round(time.time() - start, 1)
            level   = _line_level(line)
            _push({"type": "log", "line": line, "level": level, "elapsed": elapsed})
            clean = line.strip()

            m = _VER_RE.search(clean)
            if m:
                ev = {"type": "version", "version": m.group(1),
                      "insecure": "insecure" in clean.lower()}
                job["findings"].append(ev)
                _push(ev)
                continue

            m = _THEME_RE.search(clean)
            if m:
                ev = {"type": "theme", "name": m.group(1)}
                job["findings"].append(ev)
                _push(ev)

            if clean.startswith("[+]") and not any(
                kw in clean.lower() for kw in
                ["url:", "started:", "wordpress version", "robots", "xml-rpc",
                 "user(s)", "interesting", "enumerating", "checking",
                 "upload directory", "readme", "license", "changelog"]
            ):
                name = clean[3:].strip().split(" ")[0]
                if name and "/" not in name and len(name) < 60:
                    in_plugin  = True
                    cur_plugin = name

            m = _VULN_RE.search(clean)
            if m:
                flush_vuln()
                cur_vuln  = {"title": m.group(1).strip(), "plugin": cur_plugin}
                vuln_refs = []
                continue

            if cur_vuln and "Fixed in:" in clean:
                fm = _FIX_RE.search(clean)
                if fm:
                    cur_vuln["fixed_in"] = fm.group(1)

            if cur_vuln:
                for ref in _URL_RE.findall(clean):
                    if ref not in vuln_refs:
                        vuln_refs.append(ref)

            if "user(s) identified" in clean.lower():
                in_users = True
                flush_vuln()
                continue

            if in_users and clean.startswith("[+]"):
                username = clean[3:].strip().split("|")[0].strip()
                if username and " " not in username and len(username) < 50:
                    ev = {"type": "user", "username": username}
                    job["findings"].append(ev)
                    _push(ev)

            if in_users and clean.startswith("[i]") and "found by" not in clean.lower():
                in_users = False

            m = _CRED_RE.search(clean)
            if m:
                ev = {"type": "credential",
                      "username": m.group(1), "password": m.group(2)}
                job["findings"].append(ev)
                _push(ev)

            m = _PROG_RE.search(clean)
            if m and ("brute" in clean.lower() or "trying" in clean.lower()):
                _push({"type": "progress",
                       "done": int(m.group(1)), "total": int(m.group(2))})

        flush_vuln()
        proc.wait()
        total_vulns = sum(1 for f in job["findings"] if f["type"] == "vuln")
        total_users = sum(1 for f in job["findings"] if f["type"] == "user")
        total_creds = sum(1 for f in job["findings"] if f["type"] == "credential")
        _push({"type": "done", "elapsed": round(time.time() - start, 1),
               "vulns": total_vulns, "users": total_users, "credentials": total_creds})
        _notify_args = None
        _snap = None
        with _lock:
            if job_id in _jobs:
                _jobs[job_id]["done"] = True
                _uid  = _jobs[job_id].get("user_id")
                _tgt  = _jobs[job_id].get("target", "")
                _hits = len(_jobs[job_id].get("findings", []))
                _notify_args = (_uid, "wpscan", _tgt, _hits, "WPScan")
                _snap = {
                    "findings": list(_jobs[job_id].get("findings", [])),
                    "target":   _tgt,
                    "tool":     "wpscan",
                    "mode":     _jobs[job_id].get("mode", "enum"),
                    "user_id":  _uid,
                    "username": _jobs[job_id].get("username", ""),
                }
        if _snap:
            _persist_wpscan(job_id, _snap)
        if _notify_args:
            from core.notifications import notify_scan_complete
            notify_scan_complete(*_notify_args)

    threading.Thread(target=_worker, daemon=True).start()
    return jsonify({"job_id": job_id, "mode": mode, "tool": "wpscan", "cmd": " ".join(cmd)})


@wpscan_bp.route("/api/wpscan/stream/<job_id>")
@module_required("wpscan")
def wpscan_stream(job_id):
    with _lock:
        job = _jobs.get(job_id)
    if not job:
        return jsonify({"error": "job not found"}), 404

    def generate():
        offset  = 0
        last_ka = time.time()
        while True:
            with _lock:
                job    = _jobs.get(job_id)
                if not job:
                    break
                events = job["events"]
                done   = job["done"]

            while offset < len(events):
                ev = events[offset]
                offset += 1
                yield _sse(ev)
                if ev.get("type") == "done":
                    return

            if done:
                yield _sse({"type": "done"})
                return

            now = time.time()
            if now - last_ka > 25:
                yield _sse({"type": "keepalive"})
                last_ka = now

            time.sleep(0.05)

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@wpscan_bp.route("/api/wpscan/status/<job_id>")
def wpscan_status(job_id):
    with _lock:
        job = _jobs.get(job_id)
    if not job:
        return jsonify({"exists": False}), 404
    return jsonify({"exists": True, "done": job["done"],
                    "target": job.get("target", ""), "mode": job.get("mode", ""),
                    "event_count": len(job["events"])})


@wpscan_bp.route("/api/wpscan/stop/<job_id>", methods=["POST"])
def wpscan_stop(job_id):
    with _lock:
        job = _jobs.get(job_id)
    if job and not job["done"]:
        try:
            job["proc"].terminate()
        except Exception:
            pass
    return jsonify({"stopped": True})
