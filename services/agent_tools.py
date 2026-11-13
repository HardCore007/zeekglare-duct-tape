"""Tool registry exposed to LLM agents.

Phase 1: recon-only tools. Each tool:
  - Declares a JSON schema (used by Claude tool use)
  - Has a handler(args, state, agent_id) → dict
  - Writes discovered assets + findings into the SharedState so other
    agents benefit without duplicating work
  - Respects SharedState.scope (refuses to hit out-of-scope hosts)
  - Goes through the cache (layer 1) — if an identical tool call already
    ran, the cached result is returned instead of re-running

Tools return structured dicts; the agent runner serializes them into
`tool_result` content blocks. Output is truncated to keep prompts compact.

All subprocess invocations go through `core.proxy_config.wrap_cmd` so they
inherit the global SOCKS5 proxy when enabled.
"""
from __future__ import annotations
import json, os, subprocess, time, re
from urllib.parse import urlparse, urljoin

from core.proxy_config import wrap_cmd
# Importing the package registers all bundled skills into SKILL_REGISTRY.
import services.skills  # noqa: F401
from services.skills.base import applicable_skills, run_skill, SKILL_REGISTRY

# ── Schemas ────────────────────────────────────────────────────────────────

TOOL_SCHEMAS = [
    {
        "name": "subdomain_enum",
        "description": (
            "Enumerate subdomains of a root domain using subfinder (passive). "
            "Returns a list of discovered subdomains. Cheap (~30-90s). Call early."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Root domain (e.g. example.com) — must be in scope."},
            },
            "required": ["domain"],
        },
    },
    {
        "name": "http_probe",
        "description": (
            "Probe hosts with httpx to find live web servers. Returns status code, "
            "title, technologies, server header per live URL. Use after subdomain_enum."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "hosts": {
                    "type": "array", "items": {"type": "string"},
                    "description": "List of hostnames. Max 100 per call.",
                },
            },
            "required": ["hosts"],
        },
    },
    {
        "name": "port_scan",
        "description": (
            "Fast nmap top-100 port scan on up to 10 hosts. Returns open ports with "
            "service/product fingerprints. Slower than http_probe (~30-60s)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "hosts":   {"type": "array", "items": {"type": "string"}, "description": "Hostnames or IPs (max 10)."},
                "profile": {"type": "string", "enum": ["top100", "top1000", "common"], "default": "top100"},
            },
            "required": ["hosts"],
        },
    },
    {
        "name": "js_endpoints",
        "description": (
            "Fetch a web page, extract all JS files, and run LinkFinder against "
            "each to discover hidden endpoints, API paths, and potential secrets."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Full URL like https://example.com/"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "extract_params",
        "description": (
            "Extract query-string params and form/HTML inputs from URLs in shared "
            "state. Walks each known URL, parses query string, and fetches the page "
            "to extract <input name=> + <form action=> targets. Adds discovered "
            "params + URLs to shared state so skills (skill_idor, skill_xss_reflected, "
            "skill_sqli, skill_lfi, skill_ssrf etc.) can find inputs to attack. Call "
            "this between http_probe and the skill_* tools — it's the bridge from "
            "'I have URLs' to 'I have URL+param pairs to test'."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "max_urls": {"type": "integer", "default": 20,
                              "description": "Max URLs to crawl in one call (1-50)."},
                "deep":     {"type": "boolean", "default": False,
                              "description": "If true, also fetch each URL and parse its HTML for hidden inputs/forms (slower)."},
            },
            "required": [],
        },
    },
    {
        "name": "fetch_http",
        "description": (
            "Make a single HTTP request. Use for manual probing (checking headers, "
            "hitting a specific path, testing auth). Returns status, headers, and "
            "body preview (first 4 KB)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url":     {"type": "string"},
                "method":  {"type": "string", "enum": ["GET", "POST", "HEAD", "OPTIONS"], "default": "GET"},
                "headers": {"type": "object", "description": "Optional request headers."},
                "body":    {"type": "string", "description": "Optional request body for POST."},
            },
            "required": ["url"],
        },
    },
    {
        "name": "add_finding",
        "description": (
            "Record a security finding you've confirmed. Dedups across agents — "
            "if another agent already reported the same vuln, you get credit as "
            "co-discoverer. Use ONLY after you have evidence, not speculation."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "vuln_type":   {"type": "string", "description": "e.g. subdomain_takeover, exposed_api_key, open_redirect, sqli, xss"},
                "severity":    {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                "target":      {"type": "string", "description": "Host/domain the finding is on."},
                "location":    {"type": "string", "description": "Specific URL or path where the issue is."},
                "description": {"type": "string", "description": "Concise explanation of the issue and impact."},
                "evidence":    {"type": "string", "description": "Concrete proof — a response snippet, payload, config, etc."},
            },
            "required": ["vuln_type", "severity", "target", "location", "description", "evidence"],
        },
    },
    {
        "name": "done",
        "description": (
            "Signal that your investigation is complete. Provide a short summary of "
            "what you accomplished. The arena will stop calling you after this."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "summary": {"type": "string", "description": "2-3 sentence recap of findings and decisions."},
            },
            "required": ["summary"],
        },
    },
]


def tool_schemas(state=None, *, allow_exploit: bool = False) -> list[dict]:
    """Tools visible to an agent right now.

    Base recon/finding tools always apply. Skills are filtered via their
    `applicable_when(state)` gate so the LLM only sees skills whose
    prerequisites are met (e.g. SkillIdor appears only after a URL/param
    is known). `allow_exploit=False` hides skills marked danger="exploit".
    """
    out = [dict(t) for t in TOOL_SCHEMAS]
    if state is not None:
        for cls in applicable_skills(state, allow_exploit=allow_exploit):
            out.append(cls.tool_schema())
    return out


# ── Dispatch ───────────────────────────────────────────────────────────────

def run_tool(name: str, args: dict, state, agent_id: str,
             *, allow_exploit: bool = False) -> dict:
    """Dispatch + cache + scope check. Returns a dict {ok, ...}.

    Routes skill names (anything registered in SKILL_REGISTRY) through the
    skill runner, which handles scope, Layer-3 dedup, and finding auto-
    submission. Built-in recon/finding tools go through `_HANDLERS`.
    """
    # Skill dispatch — skills manage their own scope + dedup semantics.
    if name in SKILL_REGISTRY:
        t0 = time.time()
        result = run_skill(name, args, state, agent_id, allow_exploit=allow_exploit)
        result["_elapsed"] = round(time.time() - t0, 2)
        return result

    handler = _HANDLERS.get(name)
    if not handler:
        return {"ok": False, "error": f"unknown tool: {name}"}

    # Scope check for network-touching tools
    if name in _SCOPED_TOOLS:
        tgt = _extract_target_for_scope(name, args)
        if tgt and not state.in_scope(tgt):
            return {"ok": False, "error": f"out of scope: {tgt}. Scope = {state.scope}"}

    # Cache lookup
    cached = state.get_cached(name, args)
    if cached:
        out = dict(cached["result"])
        out["_cached"] = True
        return out

    t0 = time.time()
    try:
        result = handler(args, state, agent_id)
    except Exception as e:
        result = {"ok": False, "error": f"{type(e).__name__}: {e}"}
    result["_elapsed"] = round(time.time() - t0, 2)

    # Only cache successful results
    if result.get("ok"):
        state.set_cached(name, args, result)
    return result


def _extract_target_for_scope(tool: str, args: dict) -> str:
    if tool == "subdomain_enum": return args.get("domain", "")
    if tool == "http_probe":
        hosts = args.get("hosts") or []
        return hosts[0] if hosts else ""
    if tool == "port_scan":
        hosts = args.get("hosts") or []
        return hosts[0] if hosts else ""
    if tool == "js_endpoints": return args.get("url", "")
    if tool == "fetch_http":   return args.get("url", "")
    return ""


_SCOPED_TOOLS = {"subdomain_enum", "http_probe", "port_scan", "js_endpoints", "fetch_http"}


# ── Tool implementations ───────────────────────────────────────────────────

def _tool_subdomain_enum(args, state, agent_id):
    domain = (args.get("domain") or "").strip().lower()
    if not domain:
        return {"ok": False, "error": "domain required"}

    env = os.environ.copy()
    env["PATH"] = os.path.expanduser("~/go/bin") + ":" + env.get("PATH", "")
    cmd = wrap_cmd(["subfinder", "-d", domain, "-silent", "-timeout", "30", "-t", "30"])
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180, env=env)
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "subfinder timed out after 180s"}
    subs = sorted({l.strip().lower() for l in (proc.stdout or "").splitlines() if l.strip()})
    new_count = state.add_assets("subdomain", subs)
    return {
        "ok":         True,
        "domain":     domain,
        "count":      len(subs),
        "new_count":  new_count,
        "subdomains": subs[:150],
        "truncated":  len(subs) > 150,
    }


def _tool_http_probe(args, state, agent_id):
    hosts = [h.strip().lower() for h in (args.get("hosts") or []) if h]
    hosts = hosts[:100]
    if not hosts:
        return {"ok": False, "error": "hosts required"}
    # Filter to in-scope
    hosts = [h for h in hosts if state.in_scope(h)]
    if not hosts:
        return {"ok": False, "error": "all hosts out of scope"}

    env = os.environ.copy()
    env["PATH"] = os.path.expanduser("~/go/bin") + ":" + env.get("PATH", "")
    cmd = wrap_cmd(["httpx", "-silent", "-json", "-status-code", "-title",
                    "-tech-detect", "-web-server", "-timeout", "8", "-threads", "25"])
    try:
        proc = subprocess.run(cmd, input="\n".join(hosts), capture_output=True,
                              text=True, timeout=180, env=env)
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "httpx timed out"}

    live = []
    for line in (proc.stdout or "").splitlines():
        try:
            r = json.loads(line)
        except Exception:
            continue
        url = r.get("url")
        if not url: continue
        entry = {
            "url":    url,
            "status": r.get("status_code"),
            "title":  (r.get("title") or "")[:120],
            "server": r.get("webserver") or "",
            "tech":   r.get("tech") or [],
        }
        live.append(entry)
    state.add_assets("url",  [x["url"]  for x in live])
    state.add_assets("tech", [t for x in live for t in (x["tech"] or [])])
    return {"ok": True, "live_count": len(live), "results": live[:80], "truncated": len(live) > 80}


def _tool_port_scan(args, state, agent_id):
    hosts = [h.strip() for h in (args.get("hosts") or []) if h][:10]
    if not hosts:
        return {"ok": False, "error": "hosts required"}
    hosts = [h for h in hosts if state.in_scope(h)]
    if not hosts:
        return {"ok": False, "error": "all hosts out of scope"}

    profile = args.get("profile") or "top100"
    top_n = {"top100": "100", "top1000": "1000", "common": "100"}.get(profile, "100")
    out = []
    for h in hosts:
        cmd = wrap_cmd(["nmap", "-Pn", "-T4", "--top-ports", top_n,
                        "-sV", "--version-intensity", "0", "-oG", "-", h])
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        except subprocess.TimeoutExpired:
            out.append({"host": h, "error": "timeout"})
            continue
        ports = _parse_nmap_grepable(proc.stdout or "")
        for p in ports:
            state.add_assets("port", [f"{h}:{p['port']}"])
        out.append({"host": h, "open_ports": ports})
    return {"ok": True, "hosts_scanned": len(hosts), "results": out}


def _parse_nmap_grepable(text: str) -> list[dict]:
    ports = []
    for line in text.splitlines():
        if "Ports:" not in line: continue
        segs = line.split("Ports:", 1)[1].split(",")
        for s in segs:
            bits = [b.strip() for b in s.strip().split("/")]
            if len(bits) >= 5 and bits[1] == "open":
                ports.append({
                    "port":    int(bits[0]),
                    "proto":   bits[2],
                    "service": bits[4],
                    "product": bits[6] if len(bits) > 6 else "",
                })
    return ports


def _tool_js_endpoints(args, state, agent_id):
    url = (args.get("url") or "").strip()
    if not url:
        return {"ok": False, "error": "url required"}
    import requests
    try:
        r = requests.get(url, timeout=15, verify=False,
                         headers={"User-Agent": "Mozilla/5.0 ZeekGlare-Arena"})
    except Exception as e:
        return {"ok": False, "error": f"fetch failed: {e}"}
    html = r.text or ""
    js_urls = set()
    for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I):
        src = m.group(1)
        js_urls.add(urljoin(url, src))
    js_urls = sorted(js_urls)[:15]

    endpoints = set()
    for js in js_urls:
        try:
            cmd = wrap_cmd(["linkfinder", "-i", js, "-o", "cli"])
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=25)
            for line in (proc.stdout or "").splitlines():
                t = line.strip()
                if t and not t.startswith(("[", "Running", "usage:", "python")):
                    endpoints.add(t[:200])
        except Exception:
            continue
    endpoints = sorted(endpoints)
    state.add_assets("url",      [js for js in js_urls])
    state.add_assets("endpoint", endpoints)
    return {
        "ok": True,
        "url": url,
        "js_files":      js_urls,
        "endpoint_count":len(endpoints),
        "endpoints":     endpoints[:80],
        "truncated":     len(endpoints) > 80,
    }


def _tool_extract_params(args, state, agent_id):
    import re as _re
    cap = max(1, min(int(args.get("max_urls") or 20), 50))
    deep = bool(args.get("deep"))
    urls = state.get_assets("url")[:cap]
    if not urls:
        return {"ok": False, "error": "no URLs in shared state yet — call http_probe or js_endpoints first"}

    discovered: dict[str, set] = {}      # url -> set of param names
    forms_found: list[dict] = []
    for url in urls:
        if not state.in_scope(url):
            continue
        # Layer 1: query-string params from the URL itself.
        try:
            qs = urlparse(url).query
            if qs:
                for k, _v in [p.split("=", 1) if "=" in p else (p, "") for p in qs.split("&") if p]:
                    if k:
                        discovered.setdefault(url, set()).add(k)
        except Exception:
            pass
        # Layer 2: HTML scrape (optional, deep=True).
        if deep:
            try:
                import requests as _rq
                r = _rq.get(url, timeout=8, verify=False, allow_redirects=False,
                             headers={"User-Agent": "Mozilla/5.0 ZeekGlare-Arena-Param"})
                html = r.text or ""
            except Exception:
                continue
            # <input name="..."> — covers most form params
            for m in _re.finditer(r'<input[^>]+name=["\']([^"\']+)["\']', html, _re.I):
                discovered.setdefault(url, set()).add(m.group(1))
            # <select name="..."> + <textarea name="...">
            for tag in ("select", "textarea"):
                for m in _re.finditer(rf'<{tag}[^>]+name=["\']([^"\']+)["\']', html, _re.I):
                    discovered.setdefault(url, set()).add(m.group(1))
            # <form action="..."> targets
            for m in _re.finditer(r'<form[^>]+action=["\']([^"\']+)["\']', html, _re.I):
                action = m.group(1)
                if action.startswith(("http://", "https://")):
                    forms_found.append({"page": url, "action": action})
                elif action.startswith("/"):
                    p = urlparse(url)
                    forms_found.append({"page": url,
                                         "action": f"{p.scheme}://{p.netloc}{action}"})

    # Stuff into shared state.
    total_params = 0
    for u, names in discovered.items():
        for n in names:
            state.add_assets("param", [n])
            total_params += 1
    if forms_found:
        state.add_assets("url", [f["action"] for f in forms_found])

    # Build URL+param pair list for the agent.
    pairs = []
    for u, names in discovered.items():
        for n in sorted(names):
            pairs.append({"url": u, "param": n})
    return {
        "ok":            True,
        "urls_scanned":  len(urls),
        "deep":          deep,
        "param_count":   total_params,
        "url_param_pairs": pairs[:80],
        "forms_found":   forms_found[:30],
        "truncated":     len(pairs) > 80,
    }


def _tool_fetch_http(args, state, agent_id):
    url = (args.get("url") or "").strip()
    if not url:
        return {"ok": False, "error": "url required"}
    method  = (args.get("method") or "GET").upper()
    headers = args.get("headers") or {}
    body    = args.get("body")
    import requests
    try:
        r = requests.request(method, url, headers=headers, data=body,
                             timeout=15, allow_redirects=False, verify=False)
    except Exception as e:
        return {"ok": False, "error": f"request failed: {e}"}

    preview = (r.text or "")[:4096]
    state.add_assets("url", [url])
    return {
        "ok":            True,
        "url":           r.url,
        "status":        r.status_code,
        "headers":       dict(r.headers),
        "body_preview":  preview,
        "body_len":      len(r.content),
        "redirect_to":   r.headers.get("Location", ""),
    }


def _tool_add_finding(args, state, agent_id):
    entry = state.add_finding(
        vuln_type     = args.get("vuln_type", ""),
        severity      = args.get("severity", "info"),
        target        = args.get("target", ""),
        location      = args.get("location", ""),
        description   = args.get("description", ""),
        evidence      = args.get("evidence", ""),
        discovered_by = agent_id,
    )
    return {
        "ok":        True,
        "finding_id": entry["id"],
        "duplicate": entry.get("_duplicate", False),
        "co_discoverers": entry["discovered_by"],
    }


def _tool_done(args, state, agent_id):
    return {"ok": True, "done": True, "summary": (args.get("summary") or "")[:500]}


_HANDLERS = {
    "subdomain_enum": _tool_subdomain_enum,
    "http_probe":     _tool_http_probe,
    "port_scan":      _tool_port_scan,
    "js_endpoints":   _tool_js_endpoints,
    "extract_params": _tool_extract_params,
    "fetch_http":     _tool_fetch_http,
    "add_finding":    _tool_add_finding,
    "done":           _tool_done,
}


# ── Result serialization for LLM tool_result content ───────────────────────

def serialize_tool_result(result: dict, max_chars: int = 4000) -> str:
    """Compact JSON for feeding back to the LLM. Truncates long fields."""
    try:
        s = json.dumps(result, default=str, indent=2)
    except Exception:
        s = str(result)
    if len(s) > max_chars:
        s = s[:max_chars] + f"\n... [truncated {len(s) - max_chars} chars]"
    return s
