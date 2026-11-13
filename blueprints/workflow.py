from core.auth_utils import module_required
"""Visual Workflow Builder — execution engine for ZeekGlare automation pipelines."""
import os, json, uuid, time, pathlib
from flask import Blueprint, request, Response, jsonify, stream_with_context

workflow_bp = Blueprint("workflow", __name__)

WORKFLOW_DIR = pathlib.Path("data/workflows")
WORKFLOW_DIR.mkdir(parents=True, exist_ok=True)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _sse(obj):
    return f"data: {json.dumps(obj)}\n\n"


def _load(wf_id):
    path = WORKFLOW_DIR / f"{wf_id}.json"
    if not path.exists():
        return None
    return json.loads(path.read_text())


def _save(workflow):
    path = WORKFLOW_DIR / f"{workflow['id']}.json"
    path.write_text(json.dumps(workflow, indent=2))


# ── CRUD ──────────────────────────────────────────────────────────────────────

@workflow_bp.route("/api/workflows", methods=["GET"])
@module_required("workflow")
def list_workflows():
    workflows = []
    for f in sorted(WORKFLOW_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        try:
            data = json.loads(f.read_text())
            workflows.append({
                "id":         data["id"],
                "name":       data.get("name", "Untitled"),
                "node_count": len(data.get("nodes", [])),
                "edge_count": len(data.get("edges", [])),
                "created_at": data.get("created_at", ""),
                "updated_at": data.get("updated_at", ""),
            })
        except Exception:
            pass
    return jsonify({"workflows": workflows})


@workflow_bp.route("/api/workflows", methods=["POST"])
@module_required("workflow")
def create_workflow():
    body = request.get_json(silent=True) or {}
    wf_id = "wf-" + uuid.uuid4().hex[:10]
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    workflow = {
        "id":         wf_id,
        "name":       body.get("name", "New Workflow"),
        "created_at": now,
        "updated_at": now,
        "nodes":      body.get("nodes", []),
        "edges":      body.get("edges", []),
    }
    _save(workflow)
    return jsonify({"workflow": workflow})


@workflow_bp.route("/api/workflows/<wf_id>", methods=["GET"])
@module_required("workflow")
def get_workflow(wf_id):
    wf = _load(wf_id)
    if not wf:
        return jsonify({"error": "Not found"}), 404
    return jsonify({"workflow": wf})


@workflow_bp.route("/api/workflows/<wf_id>", methods=["PUT"])
@module_required("workflow")
def update_workflow(wf_id):
    wf = _load(wf_id)
    if not wf:
        return jsonify({"error": "Not found"}), 404
    body = request.get_json(silent=True) or {}
    wf.update({
        "name":       body.get("name",  wf["name"]),
        "nodes":      body.get("nodes", wf["nodes"]),
        "edges":      body.get("edges", wf["edges"]),
        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    })
    _save(wf)
    return jsonify({"workflow": wf})


@workflow_bp.route("/api/workflows/<wf_id>", methods=["DELETE"])
@module_required("workflow")
def delete_workflow(wf_id):
    path = WORKFLOW_DIR / f"{wf_id}.json"
    if path.exists():
        path.unlink()
    return jsonify({"ok": True})


# ── Execution Engine ──────────────────────────────────────────────────────────

def _topo_sort(nodes, edges):
    """Kahn's topological sort. Returns ordered list of node IDs."""
    ids   = [n["id"] for n in nodes]
    adj   = {nid: [] for nid in ids}
    indeg = {nid: 0  for nid in ids}
    for e in edges:
        f, t = e.get("from"), e.get("to")
        if f in adj and t in adj:
            adj[f].append(t)
            indeg[t] += 1
    queue = [nid for nid in ids if indeg[nid] == 0]
    order = []
    while queue:
        nid = queue.pop(0)
        order.append(nid)
        for nxt in adj[nid]:
            indeg[nxt] -= 1
            if indeg[nxt] == 0:
                queue.append(nxt)
    for nid in ids:
        if nid not in order:
            order.append(nid)
    return order


def _start_and_stream(start_url, payload, stream_url, id_field="scan_id", timeout=300):
    """Two-step pattern: POST to start, then GET SSE stream. Returns list of events."""
    try:
        import requests as req
        r = req.post(start_url, json=payload, timeout=30)
        if not r.ok:
            return [{"type": "error", "text": f"Start failed ({r.status_code}): {r.text[:300]}"}]
        data = r.json()
        sid = data.get(id_field)
        if not sid:
            return [{"type": "error", "text": f"No {id_field} in response: {data}"}]
        return _get_sse(stream_url.format(sid), timeout=timeout)
    except Exception as e:
        return [{"type": "error", "text": str(e)}]


def _get_sse(url, timeout=300):
    """GET an SSE stream and collect events until done/error."""
    import requests as req
    events = []
    try:
        with req.get(url, stream=True, timeout=timeout) as resp:
            for raw in resp.iter_lines():
                if isinstance(raw, bytes):
                    raw = raw.decode()
                if not raw.startswith("data: "):
                    continue
                try:
                    ev = json.loads(raw[6:])
                    if ev.get("type") == "keepalive":
                        continue
                    events.append(ev)
                    if ev.get("type") in ("done", "scan_complete", "scan_done",
                                          "pipeline_done", "error"):
                        break
                except Exception:
                    pass
    except Exception as e:
        events.append({"type": "error", "text": str(e)})
    return events


def _execute_node(node, ctx):
    """Execute a single workflow node. Returns output dict merged into ctx."""
    tool   = node.get("type", "")
    cfg    = node.get("config", {})
    base   = "http://127.0.0.1:5000"

    # Resolve target/domains/live from upstream context or node config
    target  = cfg.get("target") or ctx.get("target", "")
    domains = ctx.get("domains", [])
    live    = ctx.get("live_hosts", [])

    try:
        import requests as req

        # ── Input ────────────────────────────────────────────────────────────
        if tool == "input":
            t = cfg.get("target", "").strip()
            return {"target": t, "domains": [t] if t else [], "live_hosts": []}

        # ── Load Session ─────────────────────────────────────────────────────
        elif tool == "load_session":
            r = req.get(f"{base}/api/sessions", timeout=30)
            sessions = r.json().get("sessions", []) if r.ok else []
            sid = cfg.get("session_id", "").strip()
            sess = next((s for s in sessions if s.get("id") == sid), sessions[0] if sessions else None)
            if not sess:
                return {"error": "No session found"}
            entries = sess.get("entries", [])
            found_domains = [e.get("domain", e) if isinstance(e, dict) else e for e in entries if (e.get("domain") if isinstance(e, dict) else e)]
            live_out = [e.get("domain", e) if isinstance(e, dict) else e for e in sess.get("top_targets", [])]
            return {"domains": found_domains, "live_hosts": live_out,
                    "target": sess.get("domain", ""),
                    "summary": f"Loaded {len(found_domains)} domains from session"}

        # ── Domain Mapper ────────────────────────────────────────────────────
        elif tool == "domain_scan":
            domain = target or (domains[0] if domains else "")
            if not domain:
                return {"error": "No target domain for Domain Scan"}
            # sources can be a list (multiselect) or comma string
            sources = cfg.get("sources", ["crtsh", "subfinder", "dnsx"])
            if isinstance(sources, str):
                sources = [s.strip() for s in sources.split(",") if s.strip()]
            if not sources:
                sources = ["crtsh", "subfinder", "dnsx"]

            events = _start_and_stream(
                f"{base}/api/domain-scan",
                {"domain": domain, "enabled_sources": sources, "probe_http": cfg.get("probe", True)},
                f"{base}/api/domain-stream/{{}}",
                id_field="scan_id",
                timeout=300,
            )
            found, live_out, seen = [], [], set()
            for ev in events:
                if ev.get("type") in ("subdomain_result", "probe_update"):
                    entry = ev.get("entry", {})
                    d = entry.get("domain", "")
                    if d and d not in seen:
                        seen.add(d)
                        found.append(d)
                        if entry.get("http_live"):
                            live_out.append(d)
            return {"domains": found, "live_hosts": live_out, "target": domain,
                    "summary": f"{len(found)} subdomains, {len(live_out)} live"}

        # ── DNS ──────────────────────────────────────────────────────────────
        elif tool == "dns_scan":
            domain = cfg.get("target") or target or (domains[0] if domains else "")
            if not domain:
                return {"error": "No target for DNS scan"}
            events = _start_and_stream(
                f"{base}/api/dns/scan",
                {"domain": domain},
                f"{base}/api/dns/stream/{{}}",
                id_field="scan_id",
                timeout=60,
            )
            records = {}
            for ev in events:
                if ev.get("type") == "dns_records":
                    records = ev.get("records", {})
                elif ev.get("type") == "dns_complete":
                    if ev.get("records"):
                        records = ev["records"]
            total = sum(len(v) if isinstance(v, list) else 1 for v in records.values())
            return {"dns_records": records, "target": domain,
                    "summary": f"{total} DNS records"}

        # ── Port Scanner ─────────────────────────────────────────────────────
        elif tool == "port_scan":
            scan_targets = live or domains or ([target] if target else [])
            if not scan_targets:
                return {"error": "No targets for Port Scan"}
            events = _start_and_stream(
                f"{base}/api/ports/scan",
                {"targets": scan_targets[:30], "tool": cfg.get("tool", "nmap"),
                 "port_profile": cfg.get("profile", "common")},
                f"{base}/api/ports/stream/{{}}",
                id_field="scan_id",
                timeout=600,
            )
            port_results = {}
            for ev in events:
                if ev.get("type") == "port_result":
                    h = ev.get("host", "")
                    if h:
                        port_results.setdefault(h, []).append({
                            "port":     ev.get("port"),
                            "protocol": ev.get("protocol", "tcp"),
                            "state":    ev.get("state", "open"),
                            "service":  ev.get("service", ""),
                        })
            total_ports = sum(len(v) for v in port_results.values())
            return {"port_results": port_results,
                    "summary": f"{total_ports} open ports across {len(port_results)} hosts"}

        # ── IP Scope ─────────────────────────────────────────────────────────
        elif tool == "ip_scope":
            domain = target or (domains[0] if domains else "")
            if not domain:
                return {"error": "No target for IP Scope"}
            events = _start_and_stream(
                f"{base}/api/ip-map/start",
                {"domain": domain},
                f"{base}/api/ip-map/stream/{{}}",
                id_field="scan_id",
                timeout=120,
            )
            ip_entries = []
            for ev in events:
                if ev.get("type") == "ip_result":
                    ip_entries.append(ev.get("entry", {}))
            return {"ip_data": ip_entries, "target": domain,
                    "summary": f"{len(ip_entries)} IPs mapped"}

        # ── Crawler ──────────────────────────────────────────────────────────
        elif tool == "crawler":
            domain = target or (domains[0] if domains else "")
            if not domain:
                return {"error": "No target for Crawler"}
            events = _start_and_stream(
                f"{base}/api/crawler/url-harvest",
                {"domain": domain},
                f"{base}/api/crawler/stream/{{}}",
                id_field="scan_id",
                timeout=300,
            )
            urls_found = []
            for ev in events:
                if ev.get("type") == "url":
                    u = ev.get("url", "")
                    if u:
                        urls_found.append(u)
            return {"crawl_urls": urls_found, "target": domain,
                    "summary": f"{len(urls_found)} URLs crawled"}

        # ── ParamHawk ────────────────────────────────────────────────────────
        elif tool == "paramhawk":
            targets_list = [
                h if h.startswith("http") else f"https://{h}"
                for h in (live or domains or ([target] if target else []))
            ]
            if not targets_list:
                return {"error": "No targets for ParamHawk"}
            tool_name = cfg.get("tool", "all")
            enabled_tools = None if tool_name == "all" else [tool_name]
            events = _start_and_stream(
                f"{base}/api/param/start",
                {"targets": targets_list[:20], "enabled_tools": enabled_tools},
                f"{base}/api/param/stream/{{}}",
                id_field="scan_id",
                timeout=300,
            )
            total_params = 0
            for ev in events:
                if ev.get("type") == "url_done":
                    total_params += ev.get("total", 0)
            return {"summary": f"{total_params} parameters discovered"}

        # ── PathStorm ────────────────────────────────────────────────────────
        elif tool == "pathstorm":
            domain = target or (live[0] if live else (domains[0] if domains else ""))
            if not domain:
                return {"error": "No target for PathStorm"}
            url = domain if domain.startswith("http") else f"https://{domain}"
            wordlist_map = {
                "common": "/usr/share/dirb/wordlists/common.txt",
                "medium": "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
                "big":    "/usr/share/wordlists/dirbuster/directory-list-2.3-big.txt",
            }
            wordlist = wordlist_map.get(cfg.get("wordlist", "common"),
                                        "/usr/share/dirb/wordlists/common.txt")
            events = _start_and_stream(
                f"{base}/api/fuzz/start",
                {"url": url, "tool": cfg.get("tool", "ffuf"), "wordlist": wordlist},
                f"{base}/api/fuzz/stream/{{}}",
                id_field="job_id",
                timeout=300,
            )
            paths = []
            for ev in events:
                if ev.get("type") == "result":
                    p = ev.get("path") or ev.get("url", "")
                    if p:
                        paths.append(p)
            return {"paths_found": paths, "summary": f"{len(paths)} paths found"}

        # ── ReconFTW ─────────────────────────────────────────────────────────
        elif tool == "reconftw":
            domain = target or (domains[0] if domains else "")
            if not domain:
                return {"error": "No target for ReconFTW"}
            events = _start_and_stream(
                f"{base}/api/recon/scan",
                {"domain": domain, "mode": cfg.get("mode", "-r")},
                f"{base}/api/recon/stream/{{}}",
                id_field="scan_id",
                timeout=600,
            )
            return {"recon_target": domain,
                    "summary": f"ReconFTW completed for {domain}"}

        # ── OneForAll ────────────────────────────────────────────────────────
        elif tool == "oneforall":
            domain = target or (domains[0] if domains else "")
            if not domain:
                return {"error": "No target for OneForAll"}
            events = _start_and_stream(
                f"{base}/api/ofa/scan",
                {"domain": domain,
                 "brute": cfg.get("brute", False),
                 "dns": cfg.get("dns", False),
                 "port_scan": cfg.get("port_scan", False)},
                f"{base}/api/ofa/stream/{{}}",
                id_field="scan_id",
                timeout=600,
            )
            ofa_subs = []
            ofa_ips  = []
            for ev in events:
                if ev.get("type") == "ofa_complete":
                    results = ev.get("results", {})
                    ofa_subs = results.get("subdomains", [])
                    ofa_ips  = results.get("ips", [])
            merged_domains = list(dict.fromkeys(domains + ofa_subs))
            return {"domains": merged_domains, "ofa_subdomains": ofa_subs,
                    "ofa_ips": ofa_ips, "target": domain,
                    "summary": f"OneForAll: {len(ofa_subs)} subdomains, {len(ofa_ips)} IPs"}

        # ── ASN Scan ─────────────────────────────────────────────────────────
        elif tool == "asn_scan":
            country = cfg.get("country", "").strip()
            domain  = target or (domains[0] if domains else "")
            payload = {"country": country} if country else {"domain": domain}
            events  = _start_and_stream(
                f"{base}/api/scan",
                payload,
                f"{base}/api/stream/{{}}",
                id_field="scan_id",
                timeout=120,
            )
            asns = [ev for ev in events if ev.get("type") == "asn_result"]
            return {"asn_results": asns,
                    "summary": f"{len(asns)} ASNs found"}

        # ── OSINT ────────────────────────────────────────────────────────────
        elif tool == "osint":
            domain = target or (domains[0] if domains else "")
            return {"osint_target": domain, "summary": f"OSINT target set: {domain}"}

        # ── Dorking ──────────────────────────────────────────────────────────
        elif tool == "dorking":
            domain = target or (domains[0] if domains else "")
            return {"dork_target": domain,
                    "summary": f"Dorking queued for {domain} — check Dorking view"}

        # ── ProjectDiscovery ─────────────────────────────────────────────────
        elif tool == "pd":
            domain = target or (domains[0] if domains else "")
            return {"pd_target": domain,
                    "summary": f"PDCP scan queued for {domain}"}

        # ── ThreatBlitz ──────────────────────────────────────────────────────
        elif tool == "threatblitz":
            scan_targets = live or domains or ([target] if target else [])
            if not scan_targets:
                return {"error": "No targets for ThreatBlitz"}
            severity = cfg.get("severity", "critical,high,medium")
            if isinstance(severity, list):
                severity = ",".join(severity)
            events = _start_and_stream(
                f"{base}/api/tb/start",
                {"targets": scan_targets[:20], "tool": cfg.get("tool", "nuclei"),
                 "severity": severity},
                f"{base}/api/tb/stream/{{}}",
                id_field="job_id",
                timeout=600,
            )
            vulns = [ev for ev in events if ev.get("type") == "finding"]
            return {"vulnerabilities": vulns,
                    "summary": f"{len(vulns)} vulnerabilities found"}

        # ── WPScan ───────────────────────────────────────────────────────────
        elif tool == "wpscan":
            domain = target or (domains[0] if domains else "")
            if not domain:
                return {"error": "No target for WPScan"}
            url = domain if domain.startswith("http") else f"https://{domain}"
            r = req.post(f"{base}/api/wpscan/start",
                         json={"url": url, "mode": "enum"}, timeout=30)
            if not r.ok:
                return {"error": f"WPScan start failed: {r.text[:200]}"}
            job_id = r.json().get("job_id")
            if not job_id:
                return {"error": "No job_id from WPScan"}
            events = _get_sse(f"{base}/api/wpscan/stream/{job_id}", timeout=300)
            findings = [ev for ev in events if ev.get("type") == "finding"]
            return {"wpscan_results": findings, "target": domain,
                    "summary": f"WPScan: {len(findings)} findings"}

        # ── Xpl03tEr tools (proxy to port 5001) ─────────────────────────────
        elif tool in (
            "xss_scan", "sqli_scan", "nosql_scan", "ssrf_scan", "lfi_scan",
            "open_redirect", "cmd_inject", "cors_scan", "crlf_scan",
            "ssti_scan", "xxe_scan", "graphql_scan", "smuggling_scan",
            "csrf_scan", "waf_bypass", "deser_scan", "header_inject",
            "race_condition", "sub_takeover",
        ):
            xpl_base = "http://127.0.0.1:5001"
            scan_targets = live or domains or ([target] if target else [])
            if not scan_targets:
                return {"error": f"No targets for {tool}"}

            # Map workflow node type → xploiter tool_id
            xpl_tool_map = {
                "xss_scan":       cfg.get("tool", "dalfox"),
                "sqli_scan":      cfg.get("tool", "sqlmap"),
                "nosql_scan":     "nosqlmap",
                "ssrf_scan":      cfg.get("tool", "ssrfuzz"),
                "lfi_scan":       cfg.get("tool", "lfimap"),
                "open_redirect":  cfg.get("tool", "openredirectx"),
                "cmd_inject":     "commix",
                "cors_scan":      cfg.get("tool", "corsy"),
                "crlf_scan":      cfg.get("tool", "crlfuzz"),
                "ssti_scan":      cfg.get("tool", "tplmap"),
                "xxe_scan":       "xxeinjector",
                "graphql_scan":   cfg.get("tool", "inql"),
                "smuggling_scan": "smuggler",
                "csrf_scan":      "xsrfprobe",
                "waf_bypass":     "nomore403",
                "deser_scan":     "phpggc",
                "header_inject":  "headi",
                "race_condition": "race-the-web",
                "sub_takeover":   cfg.get("tool", "subjack"),
            }
            tool_id = xpl_tool_map.get(tool, "dalfox")
            extra   = cfg.get("extra_flags", "")
            all_output, errors = [], 0

            # Run against up to 5 targets (exploitation tools are slow)
            for tgt in scan_targets[:5]:
                url = tgt if tgt.startswith("http") else f"https://{tgt}"
                try:
                    events = _start_and_stream(
                        f"{xpl_base}/api/xploiter/run",
                        {"tool_id": tool_id, "target": url, "extra_flags": extra},
                        f"{xpl_base}/api/xploiter/stream/{{}}",
                        id_field="scan_id",
                        timeout=600,
                    )
                    for ev in events:
                        if ev.get("type") == "output":
                            all_output.append(f"[{tgt}] {ev.get('line','')}")
                        elif ev.get("type") == "error":
                            errors += 1
                except Exception as ex:
                    errors += 1
                    all_output.append(f"[{tgt}] ERROR: {ex}")

            return {
                "exploit_results": all_output,
                "summary": f"{tool_id}: {len(all_output)} output lines, {errors} errors across {min(len(scan_targets),5)} target(s)",
            }

        # ── Misc Tools (proxy to port 5002) ──────────────────────────────────
        elif tool in (
            "nikto", "nuclei_custom", "gitleaks", "trufflehog",
            "gau_urls", "secretfinder", "jwt_scan", "permutation",
            "cms_scan", "jaeles_scan", "sub_takeover_m",
        ):
            misc_base = "http://127.0.0.1:5002"
            scan_targets = live or domains or ([target] if target else [])
            if not scan_targets:
                return {"error": f"No targets for {tool}"}

            # Map workflow node type → misc_app tool_id
            misc_tool_map = {
                "nikto":          "nikto",
                "nuclei_custom":  "nuclei",
                "gitleaks":       "gitleaks",
                "trufflehog":     "trufflehog",
                "gau_urls":       "cariddi",
                "secretfinder":   "git-hound",
                "jwt_scan":       "jwt-hack",
                "permutation":    cfg.get("tool", "alterx"),
                "cms_scan":       cfg.get("tool", "wpscan"),
                "jaeles_scan":    "jaeles",
                "sub_takeover_m": cfg.get("tool", "subjack"),
            }
            tool_id = misc_tool_map.get(tool, "nikto")
            extra   = cfg.get("extra_flags", "")
            all_output, errors = [], 0

            for tgt in scan_targets[:10]:
                url = tgt if tgt.startswith("http") else f"https://{tgt}"
                try:
                    events = _start_and_stream(
                        f"{misc_base}/api/misc/run",
                        {"tool_id": tool_id, "target": url, "extra_flags": extra},
                        f"{misc_base}/api/misc/stream/{{}}",
                        id_field="scan_id",
                        timeout=600,
                    )
                    for ev in events:
                        if ev.get("type") == "output":
                            all_output.append(f"[{tgt}] {ev.get('line','')}")
                        elif ev.get("type") == "error":
                            errors += 1
                except Exception as ex:
                    errors += 1
                    all_output.append(f"[{tgt}] ERROR: {ex}")

            return {
                "misc_results": all_output,
                "summary": f"{tool_id}: {len(all_output)} lines across {min(len(scan_targets),10)} target(s)",
            }

        # ── AI Analyze ───────────────────────────────────────────────────────
        elif tool == "ai_analyze":
            lines = []
            if ctx.get("domains"):
                lines.append(f"Domains found: {', '.join(ctx['domains'][:20])}")
            if ctx.get("live_hosts"):
                lines.append(f"Live hosts: {', '.join(ctx['live_hosts'][:20])}")
            if ctx.get("port_results"):
                for h, ports in list(ctx["port_results"].items())[:5]:
                    lines.append(f"{h}: {', '.join(str(p.get('port','')) for p in ports[:10])}")
            context_str = "\n".join(lines) or "No scan data available"
            return {"ai_context": context_str, "summary": "AI analysis context prepared"}

        # ── Notify ───────────────────────────────────────────────────────────
        elif tool == "notify":
            msg = cfg.get("message", "Workflow step completed.")
            try:
                r = req.post(f"{base}/api/telegram/send", json={"message": msg}, timeout=10)
                return {"notified": r.ok,
                        "summary": "Notification sent" if r.ok else "Notify failed"}
            except Exception:
                return {"notified": False, "summary": "Telegram not configured"}

        # ── Output / Results ─────────────────────────────────────────────────
        elif tool == "output":
            summary_parts = []
            if ctx.get("domains"):          summary_parts.append(f"{len(ctx['domains'])} domains")
            if ctx.get("live_hosts"):       summary_parts.append(f"{len(ctx['live_hosts'])} live")
            if ctx.get("port_results"):     summary_parts.append(f"{len(ctx['port_results'])} hosts scanned")
            if ctx.get("vulnerabilities"):  summary_parts.append(f"{len(ctx['vulnerabilities'])} vulns")
            if ctx.get("crawl_urls"):       summary_parts.append(f"{len(ctx['crawl_urls'])} URLs")
            if ctx.get("paths_found"):      summary_parts.append(f"{len(ctx['paths_found'])} paths")
            if ctx.get("ofa_subdomains"):   summary_parts.append(f"{len(ctx['ofa_subdomains'])} OneForAll subs")
            if ctx.get("exploit_results"):  summary_parts.append(f"{len(ctx['exploit_results'])} exploit lines")
            if ctx.get("misc_results"):     summary_parts.append(f"{len(ctx['misc_results'])} misc lines")
            return {"output_summary": ", ".join(summary_parts) or "No data",
                    "summary": "Workflow results collected"}

        else:
            return {"skipped": True, "summary": f"Unknown tool type: {tool}"}

    except Exception as e:
        return {"error": str(e)}


@workflow_bp.route("/api/workflows/<wf_id>/run", methods=["POST"])
@module_required("workflow")
@module_required("workflow")
def run_workflow(wf_id):
    wf = _load(wf_id)
    if not wf:
        def _err():
            yield _sse({"type": "error", "message": "Workflow not found"})
        return Response(stream_with_context(_err()), mimetype="text/event-stream")

    body       = request.get_json(silent=True) or {}
    overrides  = body.get("config_overrides", {})
    start_node = body.get("start_node")   # optional: run from this node onwards

    def generate():
        nodes    = wf.get("nodes", [])
        edges    = wf.get("edges", [])
        node_map = {n["id"]: n for n in nodes}

        if not nodes:
            yield _sse({"type": "error", "message": "Workflow has no nodes"})
            return

        full_order = _topo_sort(nodes, edges)

        # If start_node set, only run that node + downstream nodes
        if start_node and start_node in node_map:
            reachable = {start_node}
            changed = True
            while changed:
                changed = False
                for e in edges:
                    if e.get("from") in reachable and e.get("to") not in reachable:
                        reachable.add(e.get("to"))
                        changed = True
            order = [nid for nid in full_order if nid in reachable]
        else:
            order = full_order
        yield _sse({"type": "start",
                    "message": f"Starting: {wf['name']}",
                    "total": len(order)})

        ctx = {}
        for i, nid in enumerate(order):
            node = node_map.get(nid)
            if not node:
                continue

            if overrides.get(nid):
                node = dict(node)
                node["config"] = {**node.get("config", {}), **overrides[nid]}

            label = node.get("label", node.get("type", nid))
            yield _sse({"type": "node_start", "node_id": nid,
                        "label": label, "step": i + 1, "total": len(order)})

            t0      = time.time()
            output  = _execute_node(node, ctx)
            elapsed = round(time.time() - t0, 1)

            if output.get("error"):
                yield _sse({"type": "node_error", "node_id": nid,
                            "label": label, "error": output["error"],
                            "elapsed": elapsed})
            else:
                ctx.update(output)
                yield _sse({"type": "node_done", "node_id": nid,
                            "label": label,
                            "summary": output.get("summary", ""),
                            "elapsed": elapsed})

        yield _sse({"type": "done",
                    "message": f"Workflow '{wf['name']}' completed",
                    "result": {k: ctx[k] for k in (
                        "target", "domains", "live_hosts", "port_results",
                        "vulnerabilities", "output_summary", "crawl_urls", "paths_found",
                        "ofa_subdomains", "ofa_ips"
                    ) if k in ctx}})

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
