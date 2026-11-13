import json, os, re, shutil, subprocess, threading, time, uuid
from flask import Blueprint, request, Response, jsonify, stream_with_context, g
from core.auth_utils import module_required, rate_limit
from core.session_manager import SessionManager
from urllib.parse import urlparse

fuzzer_bp = Blueprint("fuzzer", __name__)

_FFUF      = shutil.which("ffuf") or os.path.expanduser("~/go/bin/ffuf")

# Prefer the system-packaged dirsearch (/usr/bin) over pipx installs
# which can break on newer Python (pkg_resources removed in 3.13). Fall
# back to the standard pipx location since Flask services may not inherit
# ~/.local/bin in PATH.
def _find_dirsearch():
    candidates = [
        "/usr/bin/dirsearch",
        "/usr/local/bin/dirsearch",
        os.path.expanduser("~/.local/bin/dirsearch"),
        "/root/.local/bin/dirsearch",
        "/root/.local/share/pipx/venvs/dirsearch/bin/dirsearch",
    ]
    for p in candidates:
        if p and os.path.isfile(p):
            return p
    return shutil.which("dirsearch") or ""

_DIRSEARCH = _find_dirsearch()

# ffufai — AI-powered wrapper around ffuf
_FFUFAI_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "xploiter-tools", "ffufai")
_FFUFAI_SCRIPT = os.path.join(_FFUFAI_DIR, "ffufai.py")
_FFUFAI_VENV = os.path.join(_FFUFAI_DIR, ".venv")
_FFUFAI_PYTHON = os.path.join(_FFUFAI_VENV, "bin", "python")

def _ffufai_available():
    return os.path.isfile(_FFUFAI_SCRIPT) and os.path.isfile(_FFUFAI_PYTHON)

_FFUFAI_WRAPPER = os.path.join(_FFUFAI_DIR, "_zg_wrapper.py")

def _ffufai_wrapper_path():
    """Create/return a wrapper script that monkey-patches ffufai for custom model/base_url."""
    if not os.path.isfile(_FFUFAI_WRAPPER):
        code = '''#!/usr/bin/env python3
"""ZeekGlare wrapper: patches ffufai to support OPENAI_BASE_URL and custom model via env vars."""
import os, sys, importlib

# Monkey-patch OpenAI client to use custom base_url
_orig_openai_init = None
def _patched_openai_init(self, *a, **kw):
    base = os.environ.get("OPENAI_BASE_URL")
    if base:
        kw["base_url"] = base
    _orig_openai_init(self, *a, **kw)

try:
    import openai
    _orig_openai_init = openai.OpenAI.__init__
    openai.OpenAI.__init__ = _patched_openai_init
except Exception:
    pass

# Monkey-patch chat.completions.create to override model
_custom_model = os.environ.get("FFUFAI_MODEL", "")
if _custom_model:
    try:
        _orig_create = openai.resources.chat.completions.Completions.create
        def _patched_create(self, *a, **kw):
            kw["model"] = _custom_model
            return _orig_create(self, *a, **kw)
        openai.resources.chat.completions.Completions.create = _patched_create
    except Exception:
        pass

# Now run the real ffufai
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
# Re-parse argv as if we are ffufai.py
spec = importlib.util.spec_from_file_location("ffufai", os.path.join(os.path.dirname(os.path.abspath(__file__)), "ffufai.py"))
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
'''
        with open(_FFUFAI_WRAPPER, "w") as f:
            f.write(code)
    return _FFUFAI_WRAPPER

_jobs      = {}
_lock      = threading.Lock()
_ANSI      = re.compile(r'\x1b\[[0-9;]*[mGKHF]')

# dirsearch plain output: "[HH:MM:SS] 200 -   4.5KB - http://target/path  ->  https://redir"
# or just:                "[HH:MM:SS] 200 -   4.5KB - /path"
_DS_RE = re.compile(
    r'^\[[\d:]+\]\s+(\d{3})\s+-\s+([\d.]+\s*[BKMGB]*)\s+-\s+(\S+?)(?:\s+->\s+(\S+))?$',
    re.IGNORECASE,
)
_DS_SIZE_RE = re.compile(r'^([\d.]+)\s*([BKMG]?B?)$', re.I)

# ── Default wordlist scan roots ───────────────────────────────────────────────
_DEFAULT_ROOTS = [
    "/usr/share/wordlists",
    "/usr/share/wordlist",           # singular — this server's convention
    "/usr/share/dirb/wordlists",
    "/usr/share/dirbuster/wordlists",
    "/usr/share/wfuzz/wordlist",
    "/usr/share/seclists/Discovery/Web-Content",
    "/usr/share/SecLists/Discovery/Web-Content",
]
_WL_EXTS     = {".txt", ".lst", ".dict"}
_MAX_SIZE_MB = 500


def _scan_wordlist_dir(root: str) -> dict:
    found = {}
    root  = os.path.realpath(root)
    if not os.path.isdir(root):
        return found
    for dirpath, _, files in os.walk(root, followlinks=True):
        for fname in sorted(files):
            _, ext = os.path.splitext(fname)
            if ext.lower() not in _WL_EXTS:
                continue
            fpath = os.path.join(dirpath, fname)
            try:
                if os.path.getsize(fpath) / (1024*1024) > _MAX_SIZE_MB:
                    continue
            except OSError:
                continue
            rel   = os.path.relpath(fpath, root)
            label = os.path.splitext(rel)[0].replace(os.sep, "/")
            found[label] = fpath
    return found


def _get_all_wordlists(extra_roots=None) -> dict:
    all_lists = {}
    for root in list(_DEFAULT_ROOTS) + (extra_roots or []):
        if root:
            all_lists.update(_scan_wordlist_dir(root))
    return dict(sorted(all_lists.items()))


def _parse_size(s: str) -> int:
    """Convert size string like '4.5KB', '200B', '1MB' to bytes."""
    s = s.strip().upper().replace(" ", "")
    m = _DS_SIZE_RE.match(s)
    if not m:
        try: return int(float(s))
        except: return 0
    num, unit = float(m.group(1)), m.group(2).rstrip("B")
    mult = {"": 1, "K": 1024, "M": 1024**2, "G": 1024**3}.get(unit, 1)
    return int(num * mult)


def _url_to_path(url_or_path: str, base_url: str) -> str:
    """Extract the path component relative to base_url."""
    base = base_url.rstrip("/")
    if url_or_path.startswith("http://") or url_or_path.startswith("https://"):
        if url_or_path.startswith(base):
            path = url_or_path[len(base):]
            return path if path.startswith("/") else "/" + path
        # Different origin — extract path only
        path = urlparse(url_or_path).path or "/"
        return path
    # Already a path
    return url_or_path if url_or_path.startswith("/") else "/" + url_or_path


def _sse(obj):
    return f"data: {json.dumps(obj)}\n\n"


# ── Routes ────────────────────────────────────────────────────────────────────

@fuzzer_bp.route("/api/fuzz/wordlists")
def wordlists():
    extra = request.args.getlist("root")
    safe_extra = [r for r in extra if _is_allowed_path(r)]
    lists = _get_all_wordlists(safe_extra)
    return jsonify({"wordlists": lists, "count": len(lists)})


@fuzzer_bp.route("/api/fuzz/scan-folder", methods=["POST"])
@module_required("fuzzer")
@rate_limit(max_requests=5, window_seconds=60)
def scan_folder():
    body   = request.get_json(silent=True) or {}
    folder = (body.get("path") or "").strip()
    if not folder:
        return jsonify({"error": "path required"}), 400
    if not _is_allowed_path(folder):
        return jsonify({"error": "path not allowed"}), 400
    if not os.path.isdir(folder):
        return jsonify({"error": f"Not a directory: {folder}"}), 400
    return jsonify({"wordlists": _scan_wordlist_dir(folder), "count": len(_scan_wordlist_dir(folder)), "root": folder})


@fuzzer_bp.route("/api/fuzz/tools")
def fuzz_tools():
    return jsonify({
        "ffuf":      bool(_FFUF and os.path.isfile(_FFUF)),
        "dirsearch": bool(_DIRSEARCH and os.path.isfile(_DIRSEARCH)),
        "ffufai":    _ffufai_available(),
    })


@fuzzer_bp.route("/api/fuzz/ffufai/install", methods=["POST"])
@module_required("fuzzer")
def ffufai_install():
    """Clone ffufai repo and create a venv with its dependencies."""
    if _ffufai_available():
        return jsonify({"ok": True, "message": "ffufai already installed"})
    tools_dir = os.path.dirname(_FFUFAI_DIR)
    os.makedirs(tools_dir, exist_ok=True)
    # Clone
    if not os.path.isdir(_FFUFAI_DIR):
        r = subprocess.run(
            ["git", "clone", "https://github.com/jthack/ffufai", _FFUFAI_DIR],
            capture_output=True, text=True, timeout=120,
        )
        if r.returncode != 0:
            return jsonify({"error": f"git clone failed: {r.stderr.strip()}"}), 500
    # Create venv + install deps
    if not os.path.isfile(_FFUFAI_PYTHON):
        subprocess.run(["python3", "-m", "venv", _FFUFAI_VENV], check=True, timeout=60)
        req_file = os.path.join(_FFUFAI_DIR, "requirements.txt")
        if os.path.isfile(req_file):
            subprocess.run([_FFUFAI_PYTHON, "-m", "pip", "install", "-r", req_file],
                           capture_output=True, timeout=180)
        else:
            subprocess.run([_FFUFAI_PYTHON, "-m", "pip", "install", "requests", "openai", "anthropic"],
                           capture_output=True, timeout=180)
    return jsonify({"ok": _ffufai_available()})


@fuzzer_bp.route("/api/fuzz/ffufai/apikey", methods=["POST"])
@module_required("fuzzer")
def ffufai_apikey():
    """Save an AI API key for ffufai (stored server-side in data/ffufai.json)."""
    body = request.get_json(silent=True) or {}
    provider = (body.get("provider") or "anthropic").lower()
    key = (body.get("key") or "").strip()
    if not key:
        return jsonify({"error": "key required"}), 400
    if provider not in ("openai", "anthropic", "nvidia"):
        return jsonify({"error": "provider must be 'openai', 'anthropic', or 'nvidia'"}), 400
    cfg_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "ffufai.json")
    cfg = {}
    if os.path.isfile(cfg_path):
        try:
            cfg = json.loads(open(cfg_path).read())
        except Exception:
            pass
    cfg["provider"] = provider
    cfg["key"] = key
    if provider == "nvidia":
        cfg["nim_base_url"] = (body.get("nim_base_url") or "https://integrate.api.nvidia.com/v1").strip()
        cfg["nim_model"] = (body.get("nim_model") or "").strip()
    with open(cfg_path, "w") as f:
        json.dump(cfg, f)
    return jsonify({"ok": True, "provider": provider})


@fuzzer_bp.route("/api/fuzz/ffufai/status")
def ffufai_status():
    """Check ffufai install status and whether API key is configured."""
    cfg_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "ffufai.json")
    has_key = False
    provider = ""
    if os.path.isfile(cfg_path):
        try:
            cfg = json.loads(open(cfg_path).read())
            has_key = bool(cfg.get("key"))
            provider = cfg.get("provider", "")
        except Exception:
            pass
    return jsonify({
        "installed": _ffufai_available(),
        "has_key": has_key,
        "provider": provider,
        "ffuf_available": bool(_FFUF and os.path.isfile(_FFUF)),
    })


@fuzzer_bp.route("/api/fuzz/start", methods=["POST"])
@module_required("fuzzer")
def fuzz_start():
    body       = request.get_json(silent=True) or {}
    tool       = (body.get("tool") or "ffuf").lower().strip()
    target_url = (body.get("url") or "").strip().rstrip("/")
    wordlist   = (body.get("wordlist") or "").strip()
    threads    = max(1, min(200, int(body.get("threads") or 40)))
    extensions = (body.get("extensions") or "").strip()
    codes      = (body.get("codes") or "200,201,204,301,302,307,401,403,405").strip()
    recursive  = bool(body.get("recursive", False))
    rec_depth  = max(1, min(5, int(body.get("rec_depth") or 2)))
    max_time   = max(30, min(3600, int(body.get("max_time") or 300)))  # seconds per target

    if not wordlist and tool not in ("dirsearch", "ffufai"):
        for cand in (
            "/usr/share/dirb/wordlists/common.txt",
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/wordlist/SecLists/Discovery/Web-Content/common.txt",
            "/usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt",
        ):
            if os.path.isfile(cand):
                wordlist = cand
                break

    if not target_url:
        return jsonify({"error": "url required"}), 400
    if wordlist and not _is_allowed_path(wordlist):
        return jsonify({"error": "wordlist path not allowed"}), 400
    if wordlist and not os.path.isfile(wordlist):
        return jsonify({"error": f"Wordlist not found: {wordlist}"}), 400

    proc_env = {**os.environ, "TERM": "dumb"}

    if tool == "dirsearch":
        if not (_DIRSEARCH and os.path.isfile(_DIRSEARCH)):
            return jsonify({"error": "dirsearch not found"}), 500
        exts = ",".join(e.strip().lstrip(".") for e in extensions.split(",") if e.strip()) if extensions else "php,html,js,txt,json,xml,bak"
        cmd = [
            _DIRSEARCH, "-u", target_url,
            "-t", str(threads),
            "-e", exts,
            "-i", codes,
            "--no-color",
            "--timeout", "10",
            "-q",
        ]
        if wordlist:
            cmd += ["-w", wordlist]
        if extensions:
            cmd.append("-f")
        if recursive:
            cmd += ["-r", "--max-time", str(rec_depth * 120)]

    elif tool == "ffufai":
        if not _ffufai_available():
            return jsonify({"error": "ffufai not installed — click ⚙ Setup in the tool selector"}), 500
        if not _FFUF:
            return jsonify({"error": "ffuf not found — ffufai requires ffuf"}), 500
        # Load API key config
        cfg_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "ffufai.json")
        if not os.path.isfile(cfg_path):
            return jsonify({"error": "No AI API key configured — click ⚙ Setup to add one"}), 400
        try:
            cfg = json.loads(open(cfg_path).read())
        except Exception:
            return jsonify({"error": "Invalid ffufai config"}), 500
        ai_key = cfg.get("key", "")
        ai_provider = cfg.get("provider", "anthropic")
        if not ai_key:
            return jsonify({"error": "No AI API key configured"}), 400
        # Set env vars for ffufai
        if ai_provider == "nvidia":
            # NIM uses OpenAI-compatible API with custom base URL + model
            proc_env["OPENAI_API_KEY"] = ai_key
            nim_base = cfg.get("nim_base_url", "https://integrate.api.nvidia.com/v1")
            nim_model = cfg.get("nim_model", "")
            proc_env["OPENAI_BASE_URL"] = nim_base
            if nim_model:
                proc_env["FFUFAI_MODEL"] = nim_model
        elif ai_provider == "openai":
            proc_env["OPENAI_API_KEY"] = ai_key
        else:
            proc_env["ANTHROPIC_API_KEY"] = ai_key
        # ffufai passes all ffuf args through
        fuzz_url = f"{target_url}/FUZZ"
        if not wordlist:
            for cand in (
                "/usr/share/dirb/wordlists/common.txt",
                "/usr/share/wordlists/dirb/common.txt",
                "/usr/share/wordlist/SecLists/Discovery/Web-Content/common.txt",
                "/usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt",
            ):
                if os.path.isfile(cand):
                    wordlist = cand
                    break
        # Use the wrapper for NIM (patches model/base_url), otherwise use ffufai directly
        script = _ffufai_wrapper_path() if ai_provider == "nvidia" else _FFUFAI_SCRIPT
        cmd = [
            _FFUFAI_PYTHON, script,
            "-u", fuzz_url, "-w", wordlist,
            "-mc", codes, "-t", str(threads),
            "-timeout", "10", "-noninteractive",
            "-json",
            "--ffuf-path", _FFUF,
        ]
        max_exts = int(body.get("max_extensions") or 4)
        cmd += ["--max-extensions", str(max_exts)]
        if extensions:
            exts_list = [e.strip().lstrip(".") for e in extensions.split(",") if e.strip()]
            cmd += ["-e", ",".join("." + e for e in exts_list)]
        if recursive:
            cmd += ["-recursion", "-recursion-depth", str(rec_depth)]

    else:  # ffuf — use -json for reliable structured output
        if not _FFUF:
            return jsonify({"error": "ffuf not found — install: go install github.com/ffuf/ffuf/v2@latest"}), 500
        fuzz_url = f"{target_url}/FUZZ"
        cmd = [
            _FFUF, "-u", fuzz_url, "-w", wordlist,
            "-mc", codes, "-t", str(threads),
            "-timeout", "10", "-noninteractive",
            "-json",   # newline-delimited JSON per result
        ]
        if extensions:
            exts_list = [e.strip().lstrip(".") for e in extensions.split(",") if e.strip()]
            cmd += ["-e", "," .join("." + e for e in exts_list)]
        if recursive:
            cmd += ["-recursion", "-recursion-depth", str(rec_depth)]

    job_id = str(uuid.uuid4())[:8]
    proc   = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, bufsize=1,
        env=proc_env,
    )
    with _lock:
        _jobs[job_id] = {
            "proc": proc, "done": False, "results": [],
            "events": [], "target": target_url, "tool": tool,
            "started_at": time.time(), "max_time": max_time,
            "user_id": getattr(g, "current_user", None) and g.current_user.id,
            "username": getattr(getattr(g, "current_user", None), "username", ""),
        }

    def _watchdog():
        """Kill the process if it exceeds max_time seconds."""
        time.sleep(max_time)
        with _lock:
            job = _jobs.get(job_id)
        if job and not job.get("done"):
            try:
                proc.kill()
            except Exception:
                pass

    threading.Thread(target=_watchdog, daemon=True).start()

    def _worker():
        """Read proc stdout, parse results, buffer events."""
        job        = _jobs[job_id]
        found      = 0
        start      = time.time()
        last_prog  = 0

        def _push(ev):
            with _lock:
                if job_id in _jobs:
                    _jobs[job_id]["events"].append(ev)

        for raw_line in proc.stdout:
            line    = _ANSI.sub("", raw_line).rstrip("\n")
            elapsed = round(time.time() - start, 1)

            if tool == "dirsearch":
                line = line.strip()
                if not line:
                    continue
                m = _DS_RE.match(line)
                if m:
                    status   = int(m.group(1))
                    size     = _parse_size(m.group(2))
                    raw_path = m.group(3).strip()
                    redirect = (m.group(4) or "").strip()
                    path     = _url_to_path(raw_path, target_url)
                    found   += 1
                    ev = {
                        "type": "result", "path": path, "status": status,
                        "size": size, "words": 0, "lines": 0,
                        "found": found, "elapsed": elapsed,
                        "redirect": redirect, "url": raw_path,
                    }
                    job["results"].append({"path": path, "status": status,
                        "size": size, "words": 0, "lines": 0,
                        "redirect": redirect, "url": raw_path})
                    _push(ev)
                else:
                    pm = re.search(r'(\d+)/(\d+)', line)
                    if pm and elapsed - last_prog >= 0.5:
                        last_prog = elapsed
                        _push({"type": "progress",
                               "done": int(pm.group(1)),
                               "total": int(pm.group(2)), "rps": 0})

            else:  # ffuf / ffufai — JSON output
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    pm  = re.search(r'\[(\d+)/(\d+)\]', line)
                    rpm = re.search(r'(\d+)\s*req/sec', line)
                    if pm and elapsed - last_prog >= 0.5:
                        last_prog = elapsed
                        _push({"type": "progress",
                               "done": int(pm.group(1)),
                               "total": int(pm.group(2)),
                               "rps": int(rpm.group(1)) if rpm else 0})
                    elif tool == "ffufai" and line:
                        _push({"type": "info", "message": line, "elapsed": elapsed})
                    continue

                url    = obj.get("url", "")
                status = int(obj.get("status", 0))
                if not status or not url:
                    continue
                inp      = obj.get("input", {})
                fuzz_val = inp.get("FUZZ", "") if isinstance(inp, dict) else str(inp)
                path     = _url_to_path(url, target_url) if url else f"/{fuzz_val}"
                size     = int(obj.get("length", 0))
                words    = int(obj.get("words", 0))
                lines_c  = int(obj.get("lines", 0))
                redirect = obj.get("redirectlocation", "")
                found   += 1
                ev = {
                    "type": "result", "path": path, "status": status,
                    "size": size, "words": words, "lines": lines_c,
                    "found": found, "elapsed": elapsed,
                    "redirect": redirect, "url": url,
                }
                job["results"].append({"path": path, "status": status,
                    "size": size, "words": words, "lines": lines_c,
                    "redirect": redirect, "url": url})
                _push(ev)

        elapsed = round(time.time() - start, 1)
        timed_out = elapsed >= max_time - 1
        _push({"type": "done", "found": found,
               "elapsed": elapsed, "timed_out": timed_out})
        _notify_args = None
        _snap = None
        with _lock:
            if job_id in _jobs:
                _jobs[job_id]["done"] = True
                _uid = _jobs[job_id].get("user_id")
                _tgt = _jobs[job_id].get("target", "")
                _notify_args = (_uid, "fuzzer", _tgt, found, f"Fuzzer · {tool}")
                _snap = {
                    "results":  list(_jobs[job_id].get("results", [])),
                    "target":   _tgt,
                    "tool":     tool,
                    "wordlist": wordlist,
                    "elapsed":  elapsed,
                    "timed_out": timed_out,
                    "user_id":  _uid,
                    "username": _jobs[job_id].get("username", ""),
                }
        if _snap:
            try:
                results = _snap["results"]
                status_counts = {}
                for r in results:
                    s = str(r.get("status") or "")
                    status_counts[s] = status_counts.get(s, 0) + 1
                summary = {
                    "status":       "completed",
                    "tool":         _snap["tool"],
                    "total_paths":  len(results),
                    "wordlist":     _snap["wordlist"],
                    "elapsed":      _snap["elapsed"],
                    "timed_out":    _snap["timed_out"],
                    "status_counts": status_counts,
                }
                data = {
                    "results":  results,
                    "target":   _snap["target"],
                    "tool":     _snap["tool"],
                    "wordlist": _snap["wordlist"],
                }
                SessionManager.save(
                    scan_id=job_id, scan_type="pathstorm", target=_snap["target"],
                    name=f"PathStorm — {_snap['target']}",
                    summary=summary, data=data,
                    user_id=_snap["user_id"], username=_snap["username"],
                )
            except Exception:
                pass
        if _notify_args:
            from core.notifications import notify_scan_complete
            notify_scan_complete(*_notify_args)

    threading.Thread(target=_worker, daemon=True).start()
    return jsonify({"job_id": job_id, "tool": tool, "cmd": " ".join(cmd)})


@fuzzer_bp.route("/api/fuzz/stream/<job_id>")
@module_required("fuzzer")
def fuzz_stream(job_id):
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


@fuzzer_bp.route("/api/fuzz/status/<job_id>")
def fuzz_status(job_id):
    with _lock:
        job = _jobs.get(job_id)
    if not job:
        return jsonify({"exists": False}), 404
    return jsonify({"exists": True, "done": job["done"],
                    "target": job.get("target", ""), "tool": job.get("tool", ""),
                    "event_count": len(job["events"])})


@fuzzer_bp.route("/api/fuzz/stop/<job_id>", methods=["POST"])
def fuzz_stop(job_id):
    with _lock:
        job = _jobs.get(job_id)
    if job and not job["done"]:
        try:
            job["proc"].terminate()
        except Exception:
            pass
    return jsonify({"stopped": True})


@fuzzer_bp.route("/api/fuzz/skip/<job_id>", methods=["POST"])
def fuzz_skip(job_id):
    """Kill the current fuzz job so the frontend advances to the next target."""
    with _lock:
        job = _jobs.get(job_id)
    if job and not job.get("done"):
        try:
            job["proc"].kill()
        except Exception:
            pass
    return jsonify({"skipped": True})
