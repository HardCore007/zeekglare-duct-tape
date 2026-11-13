import json, os, re, shutil, subprocess, tempfile, threading, time, uuid
from flask import Blueprint, request, Response, jsonify, stream_with_context, g
from core.auth_utils import module_required, rate_limit
from core.session_manager import SessionManager

tb_bp = Blueprint("threatblitz", __name__)

_NUCLEI = shutil.which("nuclei") or os.path.expanduser("~/go/bin/nuclei")
_NIKTO  = shutil.which("nikto")  or "/usr/bin/nikto"
_AFROG  = shutil.which("afrog")  or os.path.expanduser("~/go/bin/afrog")
_jobs   = {}
_lock   = threading.Lock()
_ANSI   = re.compile(r'\x1b\[[0-9;]*[mGKHF]')

_NIKTO_OSVDB = re.compile(r'^(OSVDB-\d+):\s*(.+)$')
_NIKTO_CVE   = re.compile(r'(CVE-\d{4}-\d+)', re.I)
_NIKTO_SKIP  = ("Target IP:", "Target Hostname:", "Target Port:", "Start Time:",
                "End Time:", "Nikto v", "----------", "requests:", "+ 0 error")


def _sev_nikto(msg: str) -> str:
    m = msg.lower()
    if re.search(r'CVE-\d{4}-\d+', msg, re.I):          return "high"
    if "osvdb-"  in m:                                   return "medium"
    if any(w in m for w in ("injection", "rce", "exec", "overflow", "shell")): return "high"
    if any(w in m for w in ("xss", "csrf", "redirect", "open redirect")):      return "medium"
    if any(w in m for w in ("ssl", "tls", "header", "cookie", "cors", "clickjacking")): return "low"
    return "info"


def _push(job_id, ev):
    with _lock:
        if job_id in _jobs:
            _jobs[job_id]["events"].append(ev)


def _persist_tb_session(job_id, snap):
    """Persist ThreatBlitz findings as a session."""
    results  = snap.get("results", []) or []
    targets  = snap.get("targets", []) or []
    tool     = snap.get("tool", "") or ""
    target   = targets[0] if targets else ""
    name     = f"ThreatBlitz — {target}" if target else f"ThreatBlitz — {len(targets)} target(s)"

    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for r in results:
        s = (r.get("severity") or "info").lower()
        if s in sev_counts:
            sev_counts[s] += 1

    summary = {
        "status":         "completed",
        "tool":           tool,
        "total_findings": len(results),
        **sev_counts,
    }
    data = {"results": results, "targets": targets, "tool": tool}
    try:
        SessionManager.save(
            scan_id=job_id, scan_type="threatblitz", target=target,
            name=name, summary=summary, data=data,
            user_id=snap.get("user_id"), username=snap.get("username", ""),
        )
    except Exception:
        pass


@tb_bp.route("/api/tb/tools")
def tb_tools():
    return jsonify({
        "nuclei": bool(_NUCLEI and os.path.isfile(_NUCLEI)),
        "nikto":  bool(_NIKTO  and os.path.isfile(_NIKTO)),
        "afrog":  bool(_AFROG  and os.path.isfile(_AFROG)),
    })


@tb_bp.route("/api/tb/start", methods=["POST"])
@module_required("threatblitz")
@rate_limit(max_requests=5, window_seconds=60)
def tb_start():
    body      = request.get_json(silent=True) or {}
    raw_tgts  = body.get("targets") or []
    raw_tool  = (body.get("tool") or "nuclei").lower().strip()
    # Support multi-select: "nuclei+nikto+afrog" or legacy "both"
    if raw_tool == "both":
        selected_tools = {"nuclei", "nikto"}
    else:
        selected_tools = set(raw_tool.split("+"))
    tool      = raw_tool
    severity  = (body.get("severity") or "low,medium,high,critical").strip()
    rate      = max(10, min(500, int(body.get("rate") or 150)))
    templates = (body.get("templates") or "").strip()
    timeout   = max(5, min(60, int(body.get("timeout") or 10)))
    tags      = (body.get("tags") or "").strip()
    if templates and ".." in templates:
        return jsonify({"error": "invalid template path"}), 400
    if tags and not re.match(r'^[a-z0-9_,\-]+$', tags, re.I):
        return jsonify({"error": "invalid tags format"}), 400

    if isinstance(raw_tgts, str):
        raw_tgts = [t.strip() for t in raw_tgts.splitlines() if t.strip()]
    targets = [t for t in raw_tgts if t]

    if not targets:
        return jsonify({"error": "At least one target required"}), 400

    tasks = []   # list of (tool_name, target, cmd)

    if "nuclei" in selected_tools:
        if not (_NUCLEI and os.path.isfile(_NUCLEI)):
            return jsonify({"error": "nuclei not found — install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"}), 500
        for t in targets:
            cmd = [_NUCLEI, "-u", t, "-jsonl", "-silent",
                   "-severity", severity, "-retries", "1",
                   "-timeout", str(timeout), "-rate-limit", str(rate),
                   "-no-color"]
            if templates:
                cmd += ["-t", templates]
            if tags:
                cmd += ["-tags", tags]
            tasks.append(("nuclei", t, cmd))

    if "nikto" in selected_tools:
        if not (_NIKTO and os.path.isfile(_NIKTO)):
            return jsonify({"error": "nikto not found — apt install nikto"}), 500
        for t in targets:
            cmd = [_NIKTO, "-h", t, "-nointeractive",
                   "-timeout", str(timeout), "-no404", "-ask", "no"]
            tasks.append(("nikto", t, cmd))

    if "afrog" in selected_tools:
        if not (_AFROG and os.path.isfile(_AFROG)):
            return jsonify({"error": "afrog not found — install: go install github.com/zan8in/afrog/v3/cmd/afrog@latest"}), 500
        for t in targets:
            out_file = os.path.join(tempfile.gettempdir(), f"afrog_{uuid.uuid4().hex[:8]}.json")
            cmd = [_AFROG, "-t", t, "-j", out_file, "-silent", "-nc", "-doh"]
            if severity:
                cmd += ["-severity", severity]
            tasks.append(("afrog", t, cmd))

    if not tasks:
        return jsonify({"error": "No tasks built"}), 400

    job_id = str(uuid.uuid4())[:8]
    with _lock:
        _jobs[job_id] = {
            "tasks": tasks, "done": False, "results": [],
            "events": [], "targets": targets, "tool": tool, "stop": False,
            "started_at": time.time(),
            "user_id": getattr(g, "current_user", None) and g.current_user.id,
            "username": getattr(getattr(g, "current_user", None), "username", ""),
        }

    def _worker():
        found = 0
        t0    = time.time()
        job   = _jobs[job_id]

        for (tool_name, target, cmd) in job["tasks"]:
            if job.get("stop"):
                break

            _push(job_id, {"type": "tool_start", "tool": tool_name, "target": target})

            stderr_lines = []
            try:
                proc = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    env={**os.environ, "TERM": "dumb"},
                )
                with _lock:
                    if job_id in _jobs:
                        _jobs[job_id]["current_proc"] = proc

                def _stderr(p, tname, tgt):
                    for raw in p.stderr:
                        l = _ANSI.sub("", raw.decode("utf-8", errors="replace")).strip()
                        if not l:
                            continue
                        stderr_lines.append(l)
                        if tname == "afrog":
                            _push(job_id, {"type": "tool_log", "tool": "afrog",
                                           "target": tgt, "line": l})
                threading.Thread(target=_stderr, args=(proc, tool_name, target), daemon=True).start()

                for raw_line in proc.stdout:
                    if job.get("stop"):
                        proc.terminate()
                        break
                    line    = _ANSI.sub("", raw_line.decode("utf-8", errors="replace")).rstrip("\n")
                    elapsed = round(time.time() - t0, 1)

                    if tool_name == "nuclei":
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            obj = json.loads(line)
                        except json.JSONDecodeError:
                            continue

                        info      = obj.get("info", {})
                        sev       = (info.get("severity") or "info").lower()
                        name      = info.get("name", "")
                        matched   = obj.get("matched-at", obj.get("host", target))
                        tmpl_id   = obj.get("template-id", "")
                        desc      = (info.get("description") or "")[:300]
                        info_tags = info.get("tags", [])
                        if not isinstance(info_tags, list):
                            info_tags = []
                        cve     = next((tg for tg in info_tags if tg.upper().startswith("CVE-")), "")
                        refs    = info.get("reference", [])
                        ref_url = refs[0] if isinstance(refs, list) and refs else ""

                        found  += 1
                        result  = {
                            "tool": "nuclei", "target": target, "severity": sev,
                            "name": name, "matched": matched, "template": tmpl_id,
                            "description": desc, "cve": cve, "ref": ref_url,
                        }
                        with _lock:
                            if job_id in _jobs:
                                _jobs[job_id]["results"].append(result)
                        _push(job_id, {"type": "finding", **result,
                                       "found": found, "elapsed": elapsed})

                    elif tool_name == "afrog":
                        # afrog writes progress to stdout — forward as log
                        line = line.strip()
                        if line:
                            _push(job_id, {"type": "tool_log", "tool": "afrog",
                                           "target": target, "line": line})

                    else:  # nikto
                        line = line.strip()
                        if not line.startswith("+"):
                            continue
                        msg = line[1:].strip()
                        if not msg or any(msg.startswith(s) for s in _NIKTO_SKIP):
                            continue

                        om     = _NIKTO_OSVDB.match(msg)
                        ref_id = om.group(1) if om else ""
                        clean  = om.group(2).strip() if om else msg
                        cve_m  = _NIKTO_CVE.search(msg)
                        cve    = cve_m.group(1) if cve_m else ""
                        sev    = _sev_nikto(msg)

                        found  += 1
                        result  = {
                            "tool": "nikto", "target": target, "severity": sev,
                            "name": clean[:120], "matched": target,
                            "template": ref_id, "description": msg[:300],
                            "cve": cve, "ref": "",
                        }
                        with _lock:
                            if job_id in _jobs:
                                _jobs[job_id]["results"].append(result)
                        _push(job_id, {"type": "finding", **result,
                                       "found": found, "elapsed": elapsed})

                proc.wait()
                with _lock:
                    if job_id in _jobs:
                        _jobs[job_id].pop("current_proc", None)

                # afrog: parse JSON output file after process completes
                if tool_name == "afrog":
                    # Find the -j flag value from cmd
                    afrog_out = None
                    for ci, cv in enumerate(cmd):
                        if cv == "-j" and ci + 1 < len(cmd):
                            afrog_out = cmd[ci + 1]
                            break
                    if afrog_out and os.path.isfile(afrog_out):
                        try:
                            with open(afrog_out, "r", errors="replace") as af:
                                for raw_line in af:
                                    raw_line = raw_line.strip()
                                    if not raw_line:
                                        continue
                                    try:
                                        obj = json.loads(raw_line)
                                    except json.JSONDecodeError:
                                        continue
                                    pi       = obj.get("pocinfo") or {}
                                    sev      = (pi.get("severity") or obj.get("severity") or "info").lower()
                                    name     = pi.get("name") or obj.get("name") or ""
                                    matched  = obj.get("url") or obj.get("target") or target
                                    tmpl_id  = pi.get("id") or obj.get("id") or ""
                                    desc     = (pi.get("description") or "")[:300]
                                    vuln_id  = pi.get("vulnid") or ""
                                    cve      = vuln_id if vuln_id.upper().startswith("CVE-") else ""
                                    ref      = ""
                                    refs     = pi.get("reference") or []
                                    if isinstance(refs, list) and refs:
                                        ref = refs[0]
                                    found += 1
                                    result = {
                                        "tool": "afrog", "target": target, "severity": sev,
                                        "name": name[:120], "matched": matched,
                                        "template": tmpl_id, "description": desc,
                                        "cve": cve, "ref": ref,
                                    }
                                    with _lock:
                                        if job_id in _jobs:
                                            _jobs[job_id]["results"].append(result)
                                    _push(job_id, {"type": "finding", **result,
                                                   "found": found,
                                                   "elapsed": round(time.time() - t0, 1)})
                        except Exception:
                            pass
                        finally:
                            try:
                                os.unlink(afrog_out)
                            except Exception:
                                pass

                for err in stderr_lines[-3:]:
                    if any(kw in err.lower() for kw in ("error", "warn", "fatal", "could not")):
                        _push(job_id, {"type": "tool_log", "tool": tool_name,
                                       "target": target, "line": err})

                _push(job_id, {"type": "tool_done", "tool": tool_name,
                               "target": target, "elapsed": round(time.time() - t0, 1)})

            except Exception as e:
                _push(job_id, {"type": "tool_error", "tool": tool_name,
                               "target": target, "message": str(e)})

        _push(job_id, {"type": "done", "found": found,
                       "elapsed": round(time.time() - t0, 1)})
        _notify_args = None
        _snap = None
        with _lock:
            if job_id in _jobs:
                _jobs[job_id]["done"] = True
                _uid  = _jobs[job_id].get("user_id")
                _tgts = _jobs[job_id].get("targets", [])
                _notify_args = (_uid, "threatblitz", _tgts[0] if _tgts else "", found, "ThreatBlitz")
                _snap = {
                    "results":  list(_jobs[job_id].get("results", [])),
                    "targets":  list(_tgts),
                    "tool":     _jobs[job_id].get("tool", ""),
                    "user_id":  _uid,
                    "username": _jobs[job_id].get("username", ""),
                }
        if _snap:
            _persist_tb_session(job_id, _snap)
        if _notify_args:
            from core.notifications import notify_scan_complete
            notify_scan_complete(*_notify_args)

    threading.Thread(target=_worker, daemon=True).start()
    return jsonify({"job_id": job_id, "tool": tool, "target_count": len(targets)})


@tb_bp.route("/api/tb/stream/<job_id>")
@module_required("threatblitz")
def tb_stream(job_id):
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
                yield f"data: {json.dumps(ev)}\n\n"
                if ev.get("type") == "done":
                    return

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


@tb_bp.route("/api/tb/status/<job_id>")
def tb_status(job_id):
    with _lock:
        job = _jobs.get(job_id)
    if not job:
        return jsonify({"exists": False}), 404
    return jsonify({"exists": True, "done": job["done"],
                    "tool": job.get("tool", ""), "targets": job.get("targets", []),
                    "event_count": len(job["events"])})


@tb_bp.route("/api/tb/poll/<job_id>")
def tb_poll(job_id):
    """Return events from offset — simple polling alternative to SSE."""
    offset = int(request.args.get("offset", 0))
    with _lock:
        job = _jobs.get(job_id)
    if not job:
        return jsonify({"error": "job not found"}), 404
    with _lock:
        events = job["events"][offset:]
        done = job["done"]
    return jsonify({"events": events, "done": done, "offset": offset + len(events)})


@tb_bp.route("/api/tb/stop/<job_id>", methods=["POST"])
def tb_stop(job_id):
    with _lock:
        job = _jobs.get(job_id)
    if job:
        job["stop"] = True
        proc = job.pop("current_proc", None)
        if proc:
            try:
                proc.terminate()
            except Exception:
                pass
    return jsonify({"stopped": True})
