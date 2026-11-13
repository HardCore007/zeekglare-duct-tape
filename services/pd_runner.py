"""ProjectDiscovery tools integration — full pipeline runner."""
import subprocess, shutil, json, threading, uuid, os
from datetime import datetime
from pathlib import Path

# Ensure go/bin is on path
_go_bin = os.path.expanduser("~/go/bin")
if _go_bin not in os.environ.get("PATH", ""):
    os.environ["PATH"] = _go_bin + ":" + os.environ.get("PATH", "")

# ── Tool registry ──────────────────────────────────────────────────────────────
PD_TOOLS = {
    # ── Discovery ──
    "uncover": {
        "desc": "Expose hosts via Shodan/Censys/FOFA/ZoomEye",
        "category": "discover",
        "cmd": ["uncover", "-q", "{target}", "-json", "-silent", "-e", "shodan,censys,fofa,zoomeye,hunter,netlas"],
        "uses_stdin": False,
        "install": "go install -v github.com/projectdiscovery/uncover/cmd/uncover@latest",
    },
    "subfinder": {
        "desc": "Passive subdomain enumeration",
        "category": "discover",
        "cmd": ["subfinder", "-d", "{target}", "-json", "-silent"],
        "uses_stdin": False,
        "install": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    },
    "alterx": {
        "desc": "Smart subdomain permutation generator",
        "category": "discover",
        "cmd": ["alterx", "-json", "-silent"],
        "uses_stdin": True,
        "install": "go install -v github.com/projectdiscovery/alterx/cmd/alterx@latest",
    },
    "shuffledns": {
        "desc": "Bruteforce subdomain resolver",
        "category": "discover",
        "cmd": ["shuffledns", "-d", "{target}", "-json", "-silent", "-mode", "resolve"],
        "uses_stdin": True,    # resolve mode takes stdin list
        "install": "go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest",
    },
    # ── Enrich ──
    "asnmap": {
        "desc": "Map org/domain to ASN → CIDR ranges",
        "category": "enrich",
        "cmd": ["asnmap", "-d", "{target}", "-json", "-silent"],
        "uses_stdin": False,
        "install": "go install -v github.com/projectdiscovery/asnmap/cmd/asnmap@latest",
    },
    "dnsx": {
        "desc": "Bulk DNS resolution & record extraction",
        "category": "enrich",
        "cmd": ["dnsx", "-json", "-silent", "-a", "-aaaa", "-cname", "-mx", "-ns"],
        "uses_stdin": True,
        "install": "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
    },
    "tlsx": {
        "desc": "TLS certificate grabber & analyser",
        "category": "enrich",
        "cmd": ["tlsx", "-json", "-silent", "-san", "-cn", "-so"],
        "uses_stdin": True,
        "install": "go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest",
    },
    "cdncheck": {
        "desc": "CDN / WAF / cloud provider detection",
        "category": "enrich",
        "cmd": ["cdncheck", "-json", "-silent"],
        "uses_stdin": True,
        "install": "go install -v github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest",
    },
    # ── Probe ──
    "httpx": {
        "desc": "HTTP probing — status, title, tech, CDN",
        "category": "probe",
        "cmd": [
            "httpx", "-json", "-silent",
            "-status-code", "-title", "-tech-detect",
            "-content-length", "-web-server", "-cdn",
        ],
        "uses_stdin": True,
        "install": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
    },
    "naabu": {
        "desc": "Fast port scanner (top 100 ports)",
        "category": "probe",
        "cmd": ["naabu", "-json", "-silent", "-top-ports", "100"],
        "uses_stdin": True,
        "install": "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
    },
    "urlfinder": {
        "desc": "Passive URL collection from multiple sources",
        "category": "probe",
        "cmd": ["urlfinder", "-d", "{target}", "-json", "-silent", "-all"],
        "uses_stdin": False,
        "install": "go install -v github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest",
    },
    "katana": {
        "desc": "Active web crawler (depth 2)",
        "category": "probe",
        "cmd": ["katana", "-json", "-silent", "-d", "2", "-jc"],
        "uses_stdin": True,
        "install": "go install github.com/projectdiscovery/katana/cmd/katana@latest",
    },
    # ── Detect ──
    "nuclei": {
        "desc": "Vulnerability scanning with templates",
        "category": "detect",
        "cmd": [
            "nuclei", "-jsonl", "-silent",
            "-severity", "low,medium,high,critical",
            "-retries", "1",
        ],
        "uses_stdin": True,
        "install": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    },
    "cvemap": {
        "desc": "CVE intelligence & vulnerability mapping",
        "category": "detect",
        "cmd": ["cvemap", "-j", "-silent", "-l", "50"],
        "uses_stdin": False,
        "install": "go install -v github.com/projectdiscovery/cvemap/cmd/cvemap@latest",
    },
}

# Default pipeline order
TOOL_ORDER = [
    "uncover", "subfinder", "alterx", "shuffledns",   # discover
    "asnmap", "dnsx", "tlsx", "cdncheck",              # enrich
    "httpx", "naabu", "urlfinder", "katana",           # probe
    "nuclei", "cvemap",                                 # detect
]

CATEGORIES = {
    "discover": ["uncover", "subfinder", "alterx", "shuffledns"],
    "enrich":   ["asnmap", "dnsx", "tlsx", "cdncheck"],
    "probe":    ["httpx", "naabu", "urlfinder", "katana"],
    "detect":   ["nuclei", "cvemap"],
}

# ── Persistence ────────────────────────────────────────────────────────────────
PD_FILE = Path("data/pd_sessions.json")
PD_FILE.parent.mkdir(parents=True, exist_ok=True)
_lock = threading.Lock()


def _load() -> list:
    if PD_FILE.exists():
        try:
            return json.loads(PD_FILE.read_text())
        except Exception:
            pass
    return []


def _save(sessions: list) -> None:
    with _lock:
        PD_FILE.write_text(json.dumps(sessions, indent=2))


# ── CRUD ───────────────────────────────────────────────────────────────────────
def list_pd_sessions() -> list:
    return _load()


def get_pd_session(sid: str) -> dict | None:
    return next((s for s in _load() if s["id"] == sid), None)


def create_pd_session(target: str, name: str = "", user_id: int = None) -> dict:
    sessions = _load()
    s = {
        "id": str(uuid.uuid4()),
        "target": target.strip(),
        "name": (name.strip() or target.strip()),
        "created_at": datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat(),
        "status": "pending",
        "user_id": user_id,
        "tools": {
            t: {
                "status": "pending",
                "results": [],
                "count": 0,
                "started_at": None,
                "finished_at": None,
                "error": None,
            }
            for t in PD_TOOLS
        },
    }
    sessions.append(s)
    _save(sessions)
    return s


def update_pd_session(sid: str, updates: dict) -> dict | None:
    sessions = _load()
    for i, s in enumerate(sessions):
        if s["id"] == sid:
            sessions[i].update(updates)
            sessions[i]["updated_at"] = datetime.utcnow().isoformat()
            _save(sessions)
            return sessions[i]
    return None


def delete_pd_session(sid: str) -> bool:
    sessions = _load()
    before = len(sessions)
    sessions = [s for s in sessions if s["id"] != sid]
    _save(sessions)
    return len(sessions) < before


def rename_pd_session(sid: str, name: str) -> dict | None:
    return update_pd_session(sid, {"name": name})


# ── Tool check ─────────────────────────────────────────────────────────────────
def check_pd_tools() -> dict:
    out = {}
    for tool, info in PD_TOOLS.items():
        path = shutil.which(tool)
        out[tool] = {
            "installed": bool(path),
            "path": path or "",
            "desc": info["desc"],
            "category": info["category"],
            "install_cmd": info["install"],
        }
    return out


# ── Pipeline runner ────────────────────────────────────────────────────────────
def run_pd_pipeline(sid: str, target: str, selected_tools: list, event_queue, pdcp_api_key: str = ""):
    """Run selected PD tools in order, chaining output between stages."""
    # Inject PDCP key into environment for cvemap
    if pdcp_api_key:
        os.environ["PDCP_API_KEY"] = pdcp_api_key

    def _update_tool(tool: str, **kw):
        sessions = _load()
        for s in sessions:
            if s["id"] == sid:
                s["tools"][tool].update(kw)
                s["updated_at"] = datetime.utcnow().isoformat()
                break
        _save(sessions)

    # Stage buckets — each stage seeds the next
    discovered_hosts: list[str] = []   # after discover stage
    enriched_hosts:   list[str] = []   # after enrich stage
    live_urls:        list[str] = []   # after probe stage

    for tool_name in TOOL_ORDER:
        if tool_name not in selected_tools:
            continue

        tool_cfg = PD_TOOLS[tool_name]
        cat = tool_cfg["category"]

        if not shutil.which(tool_name):
            event_queue.put({"type": "tool_skip", "tool": tool_name,
                             "message": f"{tool_name} not installed"})
            continue

        # cvemap requires PDCP API key
        if tool_name == "cvemap" and not (pdcp_api_key or os.environ.get("PDCP_API_KEY")):
            event_queue.put({"type": "tool_skip", "tool": tool_name,
                             "message": "cvemap requires PDCP API Key — add it in Settings → API Keys"})
            continue

        # Determine stdin input based on category
        stdin_hosts: list[str] = []
        if tool_cfg["uses_stdin"]:
            if cat == "discover":
                stdin_hosts = [target]
            elif cat == "enrich":
                stdin_hosts = discovered_hosts or [target]
            elif cat == "probe":
                stdin_hosts = enriched_hosts or discovered_hosts or [target]
            elif cat == "detect":
                stdin_hosts = live_urls or enriched_hosts or [target]
            if not stdin_hosts:
                event_queue.put({"type": "tool_skip", "tool": tool_name,
                                 "message": "No input from previous stage"})
                continue

        _update_tool(tool_name, status="running",
                     started_at=datetime.utcnow().isoformat())
        event_queue.put({
            "type": "tool_start", "tool": tool_name,
            "desc": tool_cfg["desc"], "category": cat,
            "input_count": len(stdin_hosts),
        })

        results: list = []

        try:
            cmd = [c.replace("{target}", target) for c in tool_cfg["cmd"]]

            if tool_cfg["uses_stdin"] and stdin_hosts:
                stdin_bytes = "\n".join(stdin_hosts).encode()
                proc = subprocess.Popen(
                    cmd, stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                )
                threading.Thread(
                    target=lambda p, d: (p.stdin.write(d), p.stdin.close()),
                    args=(proc, stdin_bytes), daemon=True,
                ).start()
            else:
                proc = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                )

            # Forward stderr in background so stdout doesn't block
            stderr_lines = []
            def _read_stderr(p):
                for raw in p.stderr:
                    l = raw.decode("utf-8", errors="replace").strip()
                    if l:
                        stderr_lines.append(l)
            threading.Thread(target=_read_stderr, args=(proc,), daemon=True).start()

            for raw in proc.stdout:
                line = raw.decode("utf-8", errors="replace").strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    results.append(obj)
                    event_queue.put({"type": "tool_result", "tool": tool_name, "data": obj})
                except json.JSONDecodeError:
                    event_queue.put({"type": "tool_line", "tool": tool_name, "line": line})

            proc.wait(timeout=600)

            # Surface any stderr errors
            for err in stderr_lines[-5:]:
                if err:
                    event_queue.put({"type": "tool_line", "tool": tool_name,
                                     "line": f"[stderr] {err}"})

            _update_tool(tool_name, status="done", results=results[:2000],
                         count=len(results),
                         finished_at=datetime.utcnow().isoformat())
            event_queue.put({"type": "tool_done", "tool": tool_name, "count": len(results)})

            # Feed results into next stage
            next_targets = _extract_next(tool_name, cat, results, target)
            if cat == "discover":
                discovered_hosts.extend(next_targets)
                discovered_hosts = list(dict.fromkeys(discovered_hosts))[:500]
            elif cat == "enrich":
                enriched_hosts.extend(next_targets)
                enriched_hosts = list(dict.fromkeys(enriched_hosts))[:500]
            elif cat == "probe":
                live_urls.extend(next_targets)
                live_urls = list(dict.fromkeys(live_urls))[:500]

        except subprocess.TimeoutExpired:
            proc.kill()
            _update_tool(tool_name, status="error", error="Timed out (10 min)")
            event_queue.put({"type": "tool_error", "tool": tool_name,
                             "error": "Timed out after 10 minutes"})
        except Exception as exc:
            _update_tool(tool_name, status="error", error=str(exc))
            event_queue.put({"type": "tool_error", "tool": tool_name, "error": str(exc)})

    update_pd_session(sid, {"status": "done"})
    event_queue.put({"type": "pipeline_done", "sid": sid})
    event_queue.put(None)


def _extract_next(tool: str, cat: str, results: list, fallback: str) -> list:
    targets = []
    for r in results:
        h = None
        if tool == "uncover":
            h = r.get("ip") or r.get("host")
        elif tool == "subfinder":
            h = r.get("host") or r.get("subdomain")
        elif tool == "alterx":
            h = r.get("host") or r.get("subdomain") or r.get("name")
        elif tool == "shuffledns":
            h = r.get("host") or r.get("a", [None])[0] if isinstance(r.get("a"), list) else r.get("host")
        elif tool == "asnmap":
            # Returns CIDR ranges — pass them to naabu/dnsx
            h = r.get("cidr") or r.get("prefix")
        elif tool == "dnsx":
            h = r.get("host") or r.get("name")
        elif tool == "tlsx":
            h = r.get("host") or r.get("ip")
        elif tool == "cdncheck":
            h = r.get("input") or r.get("host")
        elif tool == "httpx":
            h = r.get("url") or r.get("input")
        elif tool == "naabu":
            ip = r.get("ip") or r.get("host", "")
            port = r.get("port", "")
            h = f"{ip}:{port}" if port else ip
        elif tool == "urlfinder":
            h = r.get("url") or r.get("endpoint")
        elif tool == "katana":
            h = (r.get("request") or {}).get("endpoint") or r.get("endpoint")
        else:
            h = r.get("host") or r.get("url") or r.get("input")
        if h:
            targets.append(str(h))
    return targets or [fallback]


# ── Standalone runners (for direct API calls) ──────────────────────────────────
def run_uncover(query: str, engines: list = None) -> list:
    """Run uncover for a query, return parsed results."""
    if not shutil.which("uncover"):
        return []
    engines_str = ",".join(engines) if engines else "shodan,censys,fofa,zoomeye"
    cmd = ["uncover", "-q", query, "-json", "-silent", "-e", engines_str]
    try:
        out = subprocess.check_output(cmd, timeout=60, stderr=subprocess.DEVNULL)
        results = []
        for line in out.decode().splitlines():
            try:
                results.append(json.loads(line))
            except Exception:
                pass
        return results
    except Exception:
        return []


def run_asnmap(target: str) -> list:
    """Map target to ASN/CIDR ranges."""
    if not shutil.which("asnmap"):
        return []
    cmd = ["asnmap", "-d", target, "-json", "-silent"]
    try:
        out = subprocess.check_output(cmd, timeout=30, stderr=subprocess.DEVNULL)
        results = []
        for line in out.decode().splitlines():
            try:
                results.append(json.loads(line))
            except Exception:
                pass
        return results
    except Exception:
        return []


def run_tlsx(hosts: list) -> list:
    """TLS grab a list of hosts."""
    if not shutil.which("tlsx"):
        return []
    cmd = ["tlsx", "-json", "-silent", "-san", "-cn", "-so"]
    try:
        proc = subprocess.Popen(
            cmd, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        stdin_data = "\n".join(hosts).encode()
        out, _ = proc.communicate(input=stdin_data, timeout=60)
        results = []
        for line in out.decode().splitlines():
            try:
                results.append(json.loads(line))
            except Exception:
                pass
        return results
    except Exception:
        return []


def run_cdncheck(hosts: list) -> list:
    """CDN/WAF detection for a list of IPs/hosts."""
    if not shutil.which("cdncheck"):
        return []
    cmd = ["cdncheck", "-json", "-silent"]
    try:
        proc = subprocess.Popen(
            cmd, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        out, _ = proc.communicate(input="\n".join(hosts).encode(), timeout=60)
        results = []
        for line in out.decode().splitlines():
            try:
                results.append(json.loads(line))
            except Exception:
                pass
        return results
    except Exception:
        return []


def run_cvemap(query: str = "", severity: str = "critical,high") -> list:
    """Query CVEmap for vulnerabilities."""
    if not shutil.which("cvemap"):
        return []
    cmd = ["cvemap", "-j", "-silent", "-l", "30", "-s", severity]
    if query:
        cmd += ["-q", query]
    try:
        out = subprocess.check_output(cmd, timeout=30, stderr=subprocess.DEVNULL)
        results = []
        for line in out.decode().splitlines():
            try:
                results.append(json.loads(line))
            except Exception:
                pass
        return results
    except Exception:
        return []
