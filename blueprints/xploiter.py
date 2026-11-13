from core.auth_utils import module_required, login_required, rate_limit
"""Xpl03tEr blueprint — Exploitation toolkit launcher for authorized penetration testing."""
import threading, uuid, json, time, subprocess, shutil, os, queue
from flask import Blueprint, request, jsonify, Response, stream_with_context, g

xploiter_bp = Blueprint("xploiter", __name__)
_runs  = {}
_lock  = threading.Lock()

# Directory that holds git-cloned exploitation tools
TOOLS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "xploiter-tools")

def _tool_dir(name):
    """Return absolute path to a tool's subdirectory inside TOOLS_DIR."""
    return os.path.join(TOOLS_DIR, name)

# ── Tool Registry ─────────────────────────────────────────────────────────────
# Each tool: id, name, category, description, install_hint, cmd_template
# cwd (optional): subdirectory name inside TOOLS_DIR to run from
# {TARGET} = main target, {URL} = URL, {PARAM} = param, {OUTPUT} = output file
# {EXTRA} = extra flags passed from UI

TOOL_REGISTRY = [
    # XSS
    {"id":"xsstrike",      "cat":"xss",        "name":"XSStrike",       "desc":"Advanced XSS detection & exploitation",  "install":"git clone https://github.com/s0md3v/XSStrike", "cwd":"XSStrike", "cmd":["python","xsstrike.py","--url","{TARGET}","__EXTRA__"]},
    {"id":"dalfox",        "cat":"xss",        "name":"dalfox",         "desc":"Fast parameter analysis & XSS scanner",  "install":"go install github.com/hahwul/dalfox/v2@latest", "cmd":["dalfox","url","{TARGET}","__EXTRA__"]},
    {"id":"kxss",          "cat":"xss",        "name":"kxss",           "desc":"Find reflected params for XSS testing",  "install":"go install github.com/tomnomnom/hacks/kxss@latest","cmd":["kxss"]},
    {"id":"bxss",          "cat":"xss",        "name":"bXSS",           "desc":"Blind XSS app & payload injector",       "install":"git clone https://github.com/LewisArdern/bXSS", "cmd":["bxss","--url","{TARGET}","__EXTRA__"]},
    {"id":"xsser",         "cat":"xss",        "name":"XSSer",          "desc":"Automated XSS framework",               "install":"pip install xsser",            "cmd":["xsser","--url","{TARGET}","__EXTRA__"]},
    {"id":"xssnow",        "cat":"xss",        "name":"XSSNow",         "desc":"XSS payload knowledge base & generator", "install":"git clone https://github.com/dr34mhacks/xssnow", "embed":"https://xssnow.in", "cmd":[]},
    # SQLi
    {"id":"sqlmap",        "cat":"sqli",       "name":"sqlmap",         "desc":"Automatic SQL injection & takeover",    "install":"pip install sqlmap",           "cmd":["sqlmap","-u","{TARGET}","--batch","__EXTRA__"]},
    {"id":"ghauri",        "cat":"sqli",       "name":"ghauri",         "desc":"Advanced SQL injection detection tool", "install":"pip install ghauri",           "cmd":["ghauri","-u","{TARGET}","__EXTRA__"]},
    {"id":"nosqlmap",      "cat":"sqli",       "name":"NoSQLMap",       "desc":"NoSQL injection & MongoDB exploitation", "install":"git clone https://github.com/codingo/NoSQLMap", "cwd":"NoSQLMap", "cmd":["python","nosqlmap.py","__EXTRA__"]},
    # SSRF
    {"id":"ssrfmap",       "cat":"ssrf",       "name":"SSRFmap",        "desc":"SSRF exploitation & payload generator",  "install":"git clone https://github.com/swisskyrepo/SSRFmap", "cwd":"SSRFmap", "cmd":["python","ssrfmap.py","-r","{TARGET}","__EXTRA__"]},
    {"id":"gopherus",      "cat":"ssrf",       "name":"Gopherus",       "desc":"Gopher payload generator for SSRF",     "install":"git clone https://github.com/tarunkant/Gopherus", "cwd":"Gopherus", "cmd":["python","gopherus.py","__EXTRA__"]},
    {"id":"surf",          "cat":"ssrf",       "name":"surf",           "desc":"SSRF parameter & endpoint scanner",      "install":"go install github.com/assetnote/surf@latest",  "cmd":["surf","-target","{TARGET}","__EXTRA__"]},
    {"id":"ssrfuzz",       "cat":"ssrf",       "name":"ssrfuzz",        "desc":"SSRF fuzzer",                           "install":"go install github.com/ryandamour/ssrfuzz@latest","cmd":["ssrfuzz","scan","-u","{TARGET}","__EXTRA__"]},
    {"id":"interactsh",    "cat":"ssrf",       "name":"interactsh-client","desc":"Out-of-band interaction server",      "install":"go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest","cmd":["interactsh-client","__EXTRA__"]},
    # CORS
    {"id":"corsy",         "cat":"cors",       "name":"Corsy",          "desc":"CORS misconfiguration scanner",         "install":"git clone https://github.com/s0md3v/Corsy", "cwd":"Corsy", "cmd":["python","corsy.py","-u","{TARGET}","__EXTRA__"]},
    {"id":"corstest",      "cat":"cors",       "name":"CORStest",       "desc":"Test CORS policies",                   "install":"pip install corstest",         "cmd":["corstest","-u","{TARGET}","__EXTRA__"]},
    {"id":"cors-scanner",  "cat":"cors",       "name":"cors-scanner",   "desc":"CORS scanner via nuclei",              "install":"go install github.com/Tanvir-A-Khan/cors-scanner@latest","cmd":["cors-scanner","-url","{TARGET}","__EXTRA__"]},
    {"id":"corsme",        "cat":"cors",       "name":"CorsMe",         "desc":"CORS misconfiguration detector",       "install":"go install github.com/shivangx01b/CorsMe@latest","cmd":["CorsMe","-u","{TARGET}","__EXTRA__"]},
    # CRLF
    {"id":"crlfsuite",     "cat":"crlf",       "name":"CRLFsuite",      "desc":"CRLF injection scanner",               "install":"pip install crlfsuite",        "cmd":["crlfsuite","-u","{TARGET}","__EXTRA__"]},
    {"id":"crlfuzz",       "cat":"crlf",       "name":"crlfuzz",        "desc":"CRLF fuzzer written in Go",            "install":"go install github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest","cmd":["crlfuzz","-u","{TARGET}","__EXTRA__"]},
    {"id":"injectus",      "cat":"crlf",       "name":"Injectus",       "desc":"CRLF & open redirect fuzzer",          "install":"pip install injectus",         "cmd":["injectus","-u","{TARGET}","__EXTRA__"]},
    # Command Injection
    {"id":"commix",        "cat":"cmdi",       "name":"commix",         "desc":"Command injection exploitation tool",  "install":"pip install commix",           "cmd":["commix","--url","{TARGET}","--batch","__EXTRA__"]},
    # LFI / Directory Traversal
    {"id":"liffy",         "cat":"lfi",        "name":"liffy",          "desc":"LFI exploitation tool",                "install":"pip install liffy",            "cmd":["liffy","--url","{TARGET}","__EXTRA__"]},
    {"id":"lfimap",        "cat":"lfi",        "name":"lfimap",         "desc":"LFI map & exploitation",               "install":"pip install lfimap",           "cmd":["lfimap","-u","{TARGET}","__EXTRA__"]},
    {"id":"dotdotpwn",     "cat":"lfi",        "name":"dotdotpwn",      "desc":"Directory traversal fuzzer",           "install":"git clone https://github.com/wireghoul/dotdotpwn", "cwd":"dotdotpwn", "cmd":["perl","dotdotpwn.pl","-m","http","-h","{TARGET}","__EXTRA__"]},
    {"id":"fdsploit",      "cat":"lfi",        "name":"FDsploit",       "desc":"File disclosure & LFI detection",      "install":"pip install fdsploit",         "cmd":["fdsploit","-u","{TARGET}","__EXTRA__"]},
    # XXE
    {"id":"xxeinjector",   "cat":"xxe",        "name":"XXEinjector",    "desc":"XXE injection via file upload",         "install":"git clone https://github.com/enjoiz/XXEinjector", "cwd":"XXEinjector", "cmd":["ruby","XXEinjector.rb","--host={TARGET}","__EXTRA__"]},
    {"id":"xxexploiter",   "cat":"xxe",        "name":"xxexploiter",    "desc":"XXE payload helper",                   "install":"pip install xxexploiter",      "cmd":["xxexploiter","__EXTRA__"]},
    {"id":"oxml_xxe",      "cat":"xxe",        "name":"oxml_xxe",       "desc":"Exploit XXE in Office Open XML",       "install":"git clone https://github.com/BuffaloWill/oxml_xxe","cmd":["ruby","server.rb","__EXTRA__"]},
    # SSTI
    {"id":"tplmap",        "cat":"ssti",       "name":"tplmap",         "desc":"Server-Side Template Injection",       "install":"pip install tplmap",                          "cmd":["tplmap","-u","{TARGET}","__EXTRA__"]},
    {"id":"sstimap",       "cat":"ssti",       "name":"SSTImap",        "desc":"Advanced SSTI detection & exploitation (vladko312)", "install":"git clone https://github.com/vladko312/SSTImap", "cwd":"SSTImap", "cmd":["python","sstimap.py","-u","{TARGET}","__EXTRA__"]},
    # GraphQL
    {"id":"inql",          "cat":"graphql",    "name":"InQL",           "desc":"GraphQL introspection & analyzer",     "install":"pip install inql",             "cmd":["inql","-t","{TARGET}","__EXTRA__"]},
    {"id":"graphqlmap",    "cat":"graphql",    "name":"GraphQLmap",     "desc":"GraphQL exploitation engine",          "install":"git clone https://github.com/swisskyrepo/GraphQLmap", "cwd":"GraphQLmap", "cmd":["python","graphqlmap.py","--url","{TARGET}","__EXTRA__"]},
    {"id":"clairvoyance",  "cat":"graphql",    "name":"clairvoyance",   "desc":"GraphQL schema via introspection",     "install":"pip install clairvoyance",     "cmd":["clairvoyance","-u","{TARGET}","__EXTRA__"]},
    {"id":"graphql-cop",   "cat":"graphql",    "name":"gqlspection",    "desc":"GraphQL introspection & security audit","install":"pip install gqlspection",      "cmd":["gqlspection","-u","{TARGET}","__EXTRA__"]},
    # Request Smuggling
    {"id":"smuggler",      "cat":"smuggling",  "name":"smuggler",       "desc":"HTTP request smuggling scanner",       "install":"git clone https://github.com/defparam/smuggler", "cwd":"smuggler", "cmd":["python","smuggler.py","-u","{TARGET}","__EXTRA__"]},
    {"id":"h2csmuggler",   "cat":"smuggling",  "name":"h2csmuggler",    "desc":"HTTP/2 cleartext smuggling",           "install":"git clone https://github.com/BishopFox/h2csmuggler", "cwd":"h2csmuggler2", "cmd":["python","h2csmuggler.py","--scan","{TARGET}","__EXTRA__"]},
    {"id":"http2smugl",    "cat":"smuggling",  "name":"http2smugl",     "desc":"HTTP request smuggling via HTTP/2",    "install":"pip install http2smugl",       "cmd":["http2smugl","detect","{TARGET}","__EXTRA__"]},
    # Open Redirect
    {"id":"oralyzer",      "cat":"redirect",   "name":"Oralyzer",       "desc":"Open redirect vulnerability analysis",  "install":"git clone https://github.com/r0075h3ll/Oralyzer", "cwd":"Oralyzer", "cmd":["python","oralyzer.py","-u","{TARGET}","__EXTRA__"]},
    {"id":"openredirectx", "cat":"redirect",   "name":"OpenRedireX",    "desc":"Open redirect async fuzzer",           "install":"git clone https://github.com/devanshbatham/OpenRedireX", "cwd":"OpenRedireX", "cmd":["python","openredirex.py","-u","{TARGET}","__EXTRA__"]},
    # Race Condition
    {"id":"turbo-intruder","cat":"race",       "name":"turbo-intruder", "desc":"High-speed web fuzzer (Burp extension)","install":"via Burp Suite BApp Store",   "cmd":["turbo-intruder","__EXTRA__"]},
    {"id":"race-the-web",  "cat":"race",       "name":"race-the-web",   "desc":"Race condition testing tool",          "install":"go install github.com/TheHackerDev/race-the-web@latest","cmd":["race-the-web","__EXTRA__"]},
    # Deserialization
    {"id":"ysoserial",     "cat":"deser",      "name":"ysoserial",      "desc":"Java deserialization payload gen",     "install":"wget https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar","cmd":["java","-jar","ysoserial.jar","__EXTRA__"]},
    {"id":"phpggc",        "cat":"deser",      "name":"PHPGGC",         "desc":"PHP deserialization gadget chains",    "install":"git clone https://github.com/ambionics/phpggc", "cwd":"phpggc", "cmd":["./phpggc","__EXTRA__"]},
    {"id":"marshal-java",  "cat":"deser",      "name":"marshalsec",     "desc":"Java deserialization marshal toolset", "install":"mvn clean package",            "cmd":["java","-cp","marshalsec.jar","__EXTRA__"]},
    # WAF Evasion
    {"id":"nomore403",     "cat":"waf",        "name":"nomore403",      "desc":"Bypass 403 forbidden responses",       "install":"go install github.com/devploit/nomore403@latest","cmd":["nomore403","-u","{TARGET}","__EXTRA__"]},
    {"id":"forbiddenbuster","cat":"waf",       "name":"Forbidden Buster","desc":"403/401 forbidden bypass toolkit",   "install":"pip install forbidden-buster",  "cmd":["forbidden-buster","-u","{TARGET}","__EXTRA__"]},
    {"id":"bypass-403",    "cat":"waf",        "name":"bypass-403",     "desc":"HTTP 403 bypass scripts",              "install":"pip install bypass-403",       "cmd":["bypass-403","-u","{TARGET}","__EXTRA__"]},
    # CSRF
    {"id":"xsrfprobe",     "cat":"csrf",       "name":"XSRFProbe",      "desc":"CSRF audit and exploitation suite",    "install":"pip install xsrfprobe",        "cmd":["xsrfprobe","-u","{TARGET}","__EXTRA__"]},
    # Header Injection
    {"id":"headi",         "cat":"header",     "name":"headi",          "desc":"HTTP header injection scanner",       "install":"go install github.com/mlcsec/headi@latest","cmd":["headi","-u","{TARGET}","__EXTRA__"]},
    # IDOR
    {"id":"autorize",      "cat":"idor",       "name":"Autorize",       "desc":"IDOR detection Burp extension",        "install":"via Burp Suite BApp Store",    "cmd":["autorize","__EXTRA__"]},
]

CATEGORIES = [
    {"id":"xss",       "label":"XSS",               "color":"#f87171","bg":"rgba(248,113,113,.12)"},
    {"id":"sqli",      "label":"SQLi",              "color":"#fb923c","bg":"rgba(251,146,60,.12)"},
    {"id":"ssrf",      "label":"SSRF",              "color":"#34d399","bg":"rgba(52,211,153,.12)"},
    {"id":"cors",      "label":"CORS",              "color":"#60a5fa","bg":"rgba(96,165,250,.12)"},
    {"id":"crlf",      "label":"CRLF",              "color":"#a78bfa","bg":"rgba(167,139,250,.12)"},
    {"id":"cmdi",      "label":"Cmd Injection",     "color":"#ef4444","bg":"rgba(239,68,68,.12)"},
    {"id":"lfi",       "label":"LFI/Traversal",     "color":"#fbbf24","bg":"rgba(251,191,36,.12)"},
    {"id":"xxe",       "label":"XXE",               "color":"#f472b6","bg":"rgba(244,114,182,.12)"},
    {"id":"ssti",      "label":"SSTI",              "color":"#818cf8","bg":"rgba(129,140,248,.12)"},
    {"id":"graphql",   "label":"GraphQL",           "color":"#e879f9","bg":"rgba(232,121,249,.12)"},
    {"id":"smuggling", "label":"Req Smuggling",     "color":"#2dd4bf","bg":"rgba(45,212,191,.12)"},
    {"id":"redirect",  "label":"Open Redirect",     "color":"#4ade80","bg":"rgba(74,222,128,.12)"},
    {"id":"race",      "label":"Race Condition",    "color":"#facc15","bg":"rgba(250,204,21,.12)"},
    {"id":"deser",     "label":"Deserialization",   "color":"#fb7185","bg":"rgba(251,113,133,.12)"},
    {"id":"waf",       "label":"WAF Bypass",        "color":"#94a3b8","bg":"rgba(148,163,184,.12)"},
    {"id":"csrf",      "label":"CSRF",              "color":"#c084fc","bg":"rgba(192,132,252,.12)"},
    {"id":"header",    "label":"Header Injection",  "color":"#67e8f9","bg":"rgba(103,232,249,.12)"},
    {"id":"idor",      "label":"IDOR",              "color":"#86efac","bg":"rgba(134,239,172,.12)"},
]


@xploiter_bp.route("/api/context")
@login_required
def get_context():
    """Export current recon context — user-isolated session data — for Xpl03tEr / Misc Tools."""
    from flask import make_response
    user = getattr(g, "current_user", None)
    uid = user.id if user else None
    is_admin = user and user.role == "admin"
    try:
        from core.session_manager import SessionManager
        summaries = SessionManager.list_all(user_id=uid, admin=is_admin) or []
        sessions = []
        for s in summaries:
            full = SessionManager.get(s["id"], user_id=uid, admin=is_admin)
            if not full:
                sessions.append(s)
                continue
            data = full.get("data", {})
            # Extract subdomains from entries + top_targets
            subs = list({
                e["domain"] for e in data.get("entries", [])
                if isinstance(e, dict) and e.get("domain")
            })
            live_subs = [
                t["domain"] for t in data.get("top_targets", [])
                if isinstance(t, dict) and t.get("domain")
            ]
            urls = [
                u if isinstance(u, str) else u.get("url", "")
                for u in data.get("urls", [])
                if u
            ]
            sessions.append({
                **s,
                "data": {
                    "subdomains": subs,
                    "live_subdomains": live_subs,
                    "urls": [u for u in urls if u],
                }
            })
    except Exception:
        sessions = []

    resp = make_response({"sessions": sessions, "status": "ok"})
    return resp


@xploiter_bp.route("/api/xploiter/tools")
def get_tools():
    """Return tool registry and category list."""
    # Mark which tools are installed
    env = os.environ.copy()
    go_bin  = os.path.expanduser("~/go/bin")
    pip_bin = os.path.expanduser("~/.local/bin")
    env["PATH"] = go_bin + ":" + pip_bin + ":" + env.get("PATH", "")
    tools = []
    for t in TOOL_REGISTRY:
        cmd = t["cmd"][0] if t["cmd"] else ""
        if t.get("embed"):
            installed = True
        elif t.get("cwd"):
            # git-cloned tool — installed if its directory exists
            installed = os.path.isdir(_tool_dir(t["cwd"]))
        elif cmd and cmd not in ("__EXTRA__", "java", "ruby", "python", "perl", "./phpggc"):
            installed = bool(shutil.which(cmd, path=env["PATH"]))
        else:
            installed = None
        tools.append({**{k:v for k,v in t.items() if k != "cmd"}, "installed": installed})
    return jsonify({"tools": tools, "categories": CATEGORIES})


@xploiter_bp.route("/api/xploiter/run", methods=["POST"])
@module_required("xploiter")
@rate_limit(max_requests=5, window_seconds=60)
def run_tool():
    """Start a tool execution and return a scan_id for SSE streaming."""
    body     = request.get_json(silent=True) or {}
    tool_id  = body.get("tool_id", "")
    target   = (body.get("target") or "").strip()
    extra    = body.get("extra_flags", "")   # additional CLI flags from UI

    tool = next((t for t in TOOL_REGISTRY if t["id"] == tool_id), None)
    if not tool:
        return jsonify({"error": "Unknown tool"}), 400
    if not target:
        return jsonify({"error": "target required"}), 400

    user = getattr(g, "current_user", None)
    run_user_id = user.id if user else None

    scan_id = str(uuid.uuid4())
    q = queue.Queue()
    with _lock:
        _runs[scan_id] = {"queue": q, "done": False, "events": [],
                          "tool_id": tool_id, "tool_name": tool["name"],
                          "target": target, "started_at": time.time(),
                          "user_id": run_user_id}

    def _buffer():
        while True:
            try:
                item = q.get(timeout=120)
                with _lock:
                    if scan_id in _runs:
                        _runs[scan_id]["events"].append(item)
                if item is None:
                    break
            except queue.Empty:
                pass

    def _run():
        env = os.environ.copy()
        go_bin  = os.path.expanduser("~/go/bin")
        pip_bin = os.path.expanduser("~/.local/bin")
        env["PATH"] = go_bin + ":" + pip_bin + ":" + env.get("PATH", "")

        # Determine working directory for git-cloned tools
        tool_cwd = None
        if tool.get("cwd"):
            tool_cwd = _tool_dir(tool["cwd"])
            if not os.path.isdir(tool_cwd):
                q.put({"type": "error", "message": f"Tool directory not found: {tool_cwd}\nInstall: {tool.get('install','')}"})
                q.put(None)
                with _lock:
                    if scan_id in _runs:
                        _runs[scan_id]["done"] = True
                return

        # Build command by substituting placeholders
        raw_cmd = tool["cmd"]
        extra_parts = extra.split() if extra else []
        cmd = []
        for part in raw_cmd:
            if part == "__EXTRA__":
                cmd += extra_parts
            elif isinstance(part, str):
                cmd.append(part.replace("{TARGET}", target).replace("{URL}", target))

        # Resolve python → python3 if python is not available
        if cmd and cmd[0] == "python" and not shutil.which("python", path=env["PATH"]):
            if shutil.which("python3", path=env["PATH"]):
                cmd[0] = "python3"

        # For git-cloned Python tools use a per-tool venv to avoid PEP 668
        if cmd and cmd[0] in ("python", "python3") and tool_cwd:
            venv_dir    = os.path.join(tool_cwd, ".venv")
            venv_python = os.path.join(venv_dir, "bin", "python")
            if not os.path.isfile(venv_python):
                q.put({"type": "output", "line": "⟳ Setting up virtual environment…"})
                subprocess.run(["python3", "-m", "venv", venv_dir],
                               capture_output=True)
                req = os.path.join(tool_cwd, "requirements.txt")
                if os.path.isfile(req):
                    q.put({"type": "output", "line": "⟳ Installing requirements…"})
                    subprocess.run([venv_python, "-m", "pip", "install", "-q",
                                    "-r", req], capture_output=True)
            if os.path.isfile(venv_python):
                cmd[0] = venv_python

        INTERPRETERS = {"python", "python3", "ruby", "perl", "java"}
        binary = cmd[0] if cmd else ""

        if binary in INTERPRETERS or (tool_cwd and binary == os.path.join(tool_cwd, ".venv", "bin", "python")):
            # For interpreter-based tools in a cwd, verify the script file exists
            if len(cmd) > 1 and tool_cwd and not cmd[1].startswith("-"):
                script_path = os.path.join(tool_cwd, cmd[1])
                if not os.path.isfile(script_path):
                    q.put({"type": "error", "message": (
                        f"Script not found: {cmd[1]}\n"
                        f"Tool directory: {tool_cwd}\n"
                        f"Install with: {tool.get('install','')}"
                    )})
                    q.put(None)
                    with _lock:
                        if scan_id in _runs:
                            _runs[scan_id]["done"] = True
                    return
        else:
            binary_in_path = shutil.which(binary, path=env["PATH"])
            binary_in_cwd  = tool_cwd and os.path.isfile(os.path.join(tool_cwd, binary))
            if not binary_in_path and not binary_in_cwd and not binary.startswith("./"):
                q.put({"type": "error", "message": (
                    f"'{binary}' is not installed.\n"
                    f"Install: {tool.get('install','')}"
                )})
                q.put(None)
                with _lock:
                    if scan_id in _runs:
                        _runs[scan_id]["done"] = True
                return

        q.put({"type": "start", "tool": tool["name"], "target": target, "cmd": " ".join(cmd)})
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, env=env, bufsize=1,
                cwd=tool_cwd,
            )
            for line in proc.stdout:
                line = line.rstrip()
                if line:
                    q.put({"type": "output", "line": line})
            proc.wait(timeout=600)
            q.put({"type": "done", "returncode": proc.returncode})
        except subprocess.TimeoutExpired:
            proc.kill()
            q.put({"type": "warning", "message": "Process timed out and was killed."})
            q.put({"type": "done", "returncode": -1})
        except Exception as e:
            q.put({"type": "error", "message": str(e)})
            q.put({"type": "done", "returncode": -1})
        finally:
            q.put(None)
            with _lock:
                if scan_id in _runs:
                    _runs[scan_id]["done"] = True

    threading.Thread(target=_buffer, daemon=True).start()
    threading.Thread(target=_run,    daemon=True).start()
    return jsonify({"scan_id": scan_id, "tool": tool["name"], "target": target})


@xploiter_bp.route("/api/xploiter/stream/<scan_id>")
@login_required
def stream_run(scan_id):
    user = getattr(g, "current_user", None)
    with _lock:
        run = _runs.get(scan_id)
    if not run:
        return jsonify({"error": "not found"}), 404
    # Non-admin users can only stream their own runs
    if user and user.role != "admin" and run.get("user_id") != user.id:
        return jsonify({"error": "access denied"}), 403

    def generate():
        offset  = 0
        last_ka = time.time()
        while True:
            with _lock:
                run    = _runs.get(scan_id)
                if not run:
                    break
                events = run["events"]
                done   = run["done"]
            while offset < len(events):
                item = events[offset]
                offset += 1
                if item is None:
                    yield f"data: {json.dumps({'type':'done'})}\n\n"
                    return
                yield f"data: {json.dumps(item)}\n\n"
            if done:
                yield f"data: {json.dumps({'type':'done'})}\n\n"
                return
            now = time.time()
            if now - last_ka > 25:
                yield f"data: {json.dumps({'type':'keepalive'})}\n\n"
                last_ka = now
            time.sleep(0.05)

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@xploiter_bp.route("/api/xploiter/status/<scan_id>")
@login_required
def run_status(scan_id):
    user = getattr(g, "current_user", None)
    with _lock:
        run = _runs.get(scan_id)
    if not run:
        return jsonify({"exists": False}), 404
    if user and user.role != "admin" and run.get("user_id") != user.id:
        return jsonify({"exists": False}), 404
    return jsonify({"exists": True, "done": run["done"], "event_count": len(run["events"])})


@xploiter_bp.route("/api/xploiter/clear", methods=["POST"])
@login_required
def clear_runs():
    """Remove completed runs owned by the current user (admin clears all)."""
    user = getattr(g, "current_user", None)
    is_admin = user and user.role == "admin"
    uid = user.id if user else None
    with _lock:
        done = [sid for sid, r in _runs.items()
                if r.get("done") and (is_admin or r.get("user_id") == uid)]
        for sid in done:
            del _runs[sid]
    return jsonify({"cleared": len(done), "ok": True})


@xploiter_bp.route("/api/xploiter/watchdog")
@login_required
def watchdog_status():
    """Return summary of active/recent Xpl03tEr runs — user-isolated."""
    user = getattr(g, "current_user", None)
    is_admin = user and user.role == "admin"
    uid = user.id if user else None
    with _lock:
        runs = list(_runs.items())
    result = []
    now = time.time()
    for sid, r in runs:
        # Non-admin users only see their own runs
        if not is_admin and r.get("user_id") != uid:
            continue
        events = r.get("events", [])
        findings = sum(1 for e in events if e and e.get("type") in ("finding", "vuln", "result"))
        result.append({
            "id": sid,
            "source": "xploiter",
            "label": r.get("tool_name", r.get("tool_id", "tool")),
            "target": r.get("target", ""),
            "done": r.get("done", False),
            "findings": findings,
            "event_count": len(events),
            "started_at": r.get("started_at", now),
            "elapsed": round(now - r.get("started_at", now)),
        })
    return jsonify(result)
