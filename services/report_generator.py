"""Professional report generator — builds corporate-grade HTML reports from session data."""
from datetime import datetime, timezone
import html as _html


def _esc(s):
    return _html.escape(str(s)) if s not in (None, "") else ""


_SEV_COLORS = {
    "critical": "#ef4444",
    "high":     "#f59e0b",
    "medium":   "#fb923c",
    "low":      "#14b8a6",
    "info":     "#64748b",
}

_SEV_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _severity_color(sev):
    return _SEV_COLORS.get((sev or "").lower(), "#64748b")


def _severity_weight(sev):
    return _SEV_WEIGHT.get((sev or "").lower(), 0)


def _risk_score(sessions):
    """0-100 overall risk score."""
    score = 0
    for s in sessions:
        sm = s.get("summary", {}) or {}
        data = s.get("data", {}) or {}
        stype = s.get("type", "")
        if stype == "threatblitz":
            score += (sm.get("critical", 0) or 0) * 25
            score += (sm.get("high", 0) or 0) * 15
            score += (sm.get("medium", 0) or 0) * 5
            score += (sm.get("low", 0) or 0) * 1
        elif stype == "ports":
            score += min((sm.get("total_ports", 0) or 0) * 2, 30)
            score += (sm.get("critical", 0) or 0) * 10
            score += (sm.get("high", 0) or 0) * 4
        elif stype == "domain":
            entries = data.get("entries", []) or []
            score += sum(1 for e in entries if (e.get("score", 0) or 0) >= 70) * 5
            score += min(sum(1 for e in entries if not e.get("waf")), 20)
        elif stype == "wpscan":
            score += (sm.get("critical", 0) or 0) * 20
            score += (sm.get("high", 0) or 0) * 10
            score += (sm.get("medium", 0) or 0) * 4
            score += len(data.get("credentials", []) or []) * 20
        elif stype == "ipscope":
            for e in data.get("entries", []) or []:
                score += len(e.get("vulns", []) or []) * 3
        elif stype == "asn":
            score += (sm.get("critical_asns", 0) or 0) * 5
        elif stype == "sudomy":
            score += min((sm.get("total_takeover", 0) or 0) * 15, 30)
        elif stype == "pathstorm":
            score += min(len(data.get("results", []) or []), 15)
        elif stype == "jsintel":
            score += min(len(data.get("interesting", []) or []) * 3, 20)
        elif stype == "arena":
            for f in data.get("findings", []) or []:
                sev = (f.get("severity") or "info").lower()
                score += {"critical": 22, "high": 12, "medium": 4, "low": 1, "info": 0}.get(sev, 0)
    return min(score, 100)


# ═══════════════════════════════════════════════════════════════════════════════
# Per-type renderers — each returns (title, html_body) or None if empty.
# ═══════════════════════════════════════════════════════════════════════════════

def _render_subdomains(all_subdomains):
    if not all_subdomains:
        return None
    live = sum(1 for e in all_subdomains if str(e.get("http_status", "") or "").startswith(("2", "3")))
    high_risk = sum(1 for e in all_subdomains if (e.get("score", 0) or 0) >= 70)
    no_waf    = sum(1 for e in all_subdomains if not e.get("waf"))
    techs = {}
    for e in all_subdomains:
        for t in (e.get("tech", []) or []):
            techs[t] = techs.get(t, 0) + 1

    html = f"""<div class="subsection">
  <h3 class="ss-title">Subdomain Intelligence</h3>
  <p class="lead">Enumeration surfaced <b>{len(all_subdomains)}</b> subdomains — <b style="color:#22c55e">{live}</b> responding, <b style="color:#ef4444">{high_risk}</b> high-risk, <b style="color:#f59e0b">{no_waf}</b> without WAF protection.</p>
  <div class="kpi-row">
    <div class="kpi"><div class="kpi-v">{len(all_subdomains)}</div><div class="kpi-l">Discovered</div></div>
    <div class="kpi"><div class="kpi-v" style="color:#22c55e">{live}</div><div class="kpi-l">Live</div></div>
    <div class="kpi"><div class="kpi-v" style="color:#ef4444">{high_risk}</div><div class="kpi-l">High Risk</div></div>
    <div class="kpi"><div class="kpi-v" style="color:#f59e0b">{no_waf}</div><div class="kpi-l">No WAF</div></div>
    <div class="kpi"><div class="kpi-v">{len(techs)}</div><div class="kpi-l">Technologies</div></div>
  </div>
  <table class="tbl">
    <thead><tr><th>Subdomain</th><th>IP</th><th>Status</th><th>Score</th><th>Technology</th><th>WAF</th></tr></thead>
    <tbody>
"""
    for e in sorted(all_subdomains, key=lambda x: -(x.get("score", 0) or 0))[:150]:
        score = e.get("score", 0) or 0
        cls = "sev-critical" if score >= 70 else "sev-high" if score >= 50 else "sev-medium" if score >= 30 else "sev-low"
        tech = ", ".join((e.get("tech", []) or [])[:4])
        url  = e.get("http_url") or f"https://{e.get('domain','')}"
        html += (
            f"<tr>"
            f"<td class='mono'><a href='{_esc(url)}' target='_blank'>{_esc(e.get('domain',''))}</a></td>"
            f"<td class='mono'>{_esc(e.get('ip',''))}</td>"
            f"<td>{_esc(e.get('http_status',''))}</td>"
            f"<td><span class='badge {cls}'>{score}</span></td>"
            f"<td class='muted'>{_esc(tech)}</td>"
            f"<td>{_esc(e.get('waf','') or '—')}</td>"
            f"</tr>\n"
        )
    if len(all_subdomains) > 150:
        html += f"<tr><td colspan='6' class='muted tc'>… and {len(all_subdomains) - 150} more subdomains</td></tr>\n"
    html += "</tbody></table>\n"

    if techs:
        top = sorted(techs.items(), key=lambda x: -x[1])[:15]
        html += "<div class='chips' style='margin-top:14px'>"
        for t, c in top:
            html += f"<span class='chip'>{_esc(t)} <b>({c})</b></span>"
        html += "</div>"
    html += "</div>\n"
    return ("Subdomain Intelligence", html)


def _render_vulns(all_vulns, sev_counts):
    if not all_vulns:
        return None
    total = max(sum(sev_counts.values()), 1)
    bar = ""
    for sev in ("critical", "high", "medium", "low", "info"):
        pct = sev_counts.get(sev, 0) * 100 / total
        bar += f"<div style='width:{pct:.1f}%;background:{_SEV_COLORS[sev]}' title='{sev}: {sev_counts[sev]}'></div>"

    html = f"""<div class="subsection">
  <h3 class="ss-title">Vulnerability Findings</h3>
  <p class="lead">A total of <b style="color:#ef4444">{len(all_vulns)}</b> vulnerabilities were identified across the assessed assets. Distribution by severity is shown below.</p>
  <div class="sev-bar">{bar}</div>
  <div class="sev-legend">
    <span><i style="background:#ef4444"></i>Critical <b>{sev_counts['critical']}</b></span>
    <span><i style="background:#f59e0b"></i>High <b>{sev_counts['high']}</b></span>
    <span><i style="background:#fb923c"></i>Medium <b>{sev_counts['medium']}</b></span>
    <span><i style="background:#14b8a6"></i>Low <b>{sev_counts['low']}</b></span>
    <span><i style="background:#64748b"></i>Info <b>{sev_counts['info']}</b></span>
  </div>
  <table class="tbl">
    <thead><tr><th>Severity</th><th>Finding</th><th>Host / Endpoint</th><th>CVE / Ref</th><th>Source</th></tr></thead>
    <tbody>
"""
    for v in all_vulns[:120]:
        sev = (v.get("severity", "info") or "info").lower()
        cve = v.get("cve") or ""
        ref = v.get("ref") or ""
        ref_cell = _esc(cve) if cve else (f"<a href='{_esc(ref)}' target='_blank'>ref</a>" if ref else "—")
        html += (
            f"<tr>"
            f"<td><span class='badge sev-{sev}'>{sev.upper()}</span></td>"
            f"<td><b>{_esc(v.get('title') or v.get('name') or 'Unknown')}</b>"
            f"<div class='muted' style='font-size:10.5px;margin-top:2px'>{_esc(str(v.get('detail') or v.get('description') or '')[:140])}</div></td>"
            f"<td class='mono'>{_esc(v.get('host', '') or v.get('matched', ''))}</td>"
            f"<td class='mono'>{ref_cell}</td>"
            f"<td>{_esc(v.get('source', '') or v.get('tool', ''))}</td>"
            f"</tr>\n"
        )
    if len(all_vulns) > 120:
        html += f"<tr><td colspan='5' class='muted tc'>… and {len(all_vulns) - 120} more findings</td></tr>\n"
    html += "</tbody></table></div>\n"
    return ("Vulnerability Findings", html)


def _render_ports(all_ports):
    if not all_ports:
        return None
    by_host = {}
    for p in all_ports:
        by_host.setdefault(p.get("host", ""), []).append(p)

    risk_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for p in all_ports:
        r = (p.get("risk", "info") or "info").lower()
        if r in risk_counts:
            risk_counts[r] += 1

    html = f"""<div class="subsection">
  <h3 class="ss-title">Network Services & Open Ports</h3>
  <p class="lead">Scanned hosts exposed <b>{len(all_ports)}</b> open ports across <b>{len(by_host)}</b> hosts, including <b style="color:#ef4444">{risk_counts['critical']}</b> critical and <b style="color:#f59e0b">{risk_counts['high']}</b> high-risk services.</p>
  <div class="kpi-row">
    <div class="kpi"><div class="kpi-v">{len(by_host)}</div><div class="kpi-l">Hosts</div></div>
    <div class="kpi"><div class="kpi-v">{len(all_ports)}</div><div class="kpi-l">Open Ports</div></div>
    <div class="kpi"><div class="kpi-v" style="color:#ef4444">{risk_counts['critical']}</div><div class="kpi-l">Critical</div></div>
    <div class="kpi"><div class="kpi-v" style="color:#f59e0b">{risk_counts['high']}</div><div class="kpi-l">High</div></div>
  </div>
  <table class="tbl">
    <thead><tr><th>Host</th><th>Port</th><th>Proto</th><th>Service</th><th>Product / Version</th><th>Risk</th></tr></thead>
    <tbody>
"""
    sorted_ports = sorted(all_ports, key=lambda p: -_severity_weight(p.get("risk", "info")))
    for p in sorted_ports[:200]:
        risk = (p.get("risk", "info") or "info").lower()
        prod = " ".join(x for x in [p.get("product", ""), p.get("version", "")] if x)
        html += (
            f"<tr>"
            f"<td class='mono'>{_esc(p.get('host',''))}</td>"
            f"<td class='mono'><b>{_esc(p.get('port',''))}</b></td>"
            f"<td>{_esc(p.get('proto','tcp'))}</td>"
            f"<td>{_esc(p.get('service',''))}</td>"
            f"<td class='muted'>{_esc(prod or '—')}</td>"
            f"<td><span class='badge sev-{risk}'>{risk.upper()}</span></td>"
            f"</tr>\n"
        )
    if len(all_ports) > 200:
        html += f"<tr><td colspan='6' class='muted tc'>… and {len(all_ports) - 200} more ports</td></tr>\n"
    html += "</tbody></table></div>\n"
    return ("Network Services & Open Ports", html)


def _render_ipscope(all_ips):
    if not all_ips:
        return None
    total_vulns = sum(len(e.get("vulns", []) or []) for e in all_ips)
    with_vulns  = sum(1 for e in all_ips if (e.get("vulns", []) or []))
    countries   = {}
    for e in all_ips:
        c = e.get("country", "") or "Unknown"
        countries[c] = countries.get(c, 0) + 1

    html = f"""<div class="subsection">
  <h3 class="ss-title">IP Intelligence</h3>
  <p class="lead">Mapped <b>{len(all_ips)}</b> unique IP addresses across <b>{len(countries)}</b> countries, with <b style="color:#ef4444">{total_vulns}</b> total CVEs across <b>{with_vulns}</b> affected hosts.</p>
  <div class="kpi-row">
    <div class="kpi"><div class="kpi-v">{len(all_ips)}</div><div class="kpi-l">IPs</div></div>
    <div class="kpi"><div class="kpi-v">{len(countries)}</div><div class="kpi-l">Countries</div></div>
    <div class="kpi"><div class="kpi-v" style="color:#ef4444">{total_vulns}</div><div class="kpi-l">CVEs</div></div>
    <div class="kpi"><div class="kpi-v">{with_vulns}</div><div class="kpi-l">Vulnerable Hosts</div></div>
  </div>
  <table class="tbl">
    <thead><tr><th>IP</th><th>ASN</th><th>Organization</th><th>Country</th><th>Ports</th><th>CVEs</th><th>Risk</th></tr></thead>
    <tbody>
"""
    for e in sorted(all_ips, key=lambda x: -len(x.get("vulns", []) or []))[:100]:
        vc  = len(e.get("vulns", []) or [])
        risk = (e.get("risk", "info") or "info").lower()
        asn = e.get("asn", "") or ""
        html += (
            f"<tr>"
            f"<td class='mono'>{_esc(e.get('ip',''))}</td>"
            f"<td class='mono'>{'AS'+str(asn) if asn else '—'}</td>"
            f"<td class='muted'>{_esc(e.get('org','') or e.get('asn_name',''))}</td>"
            f"<td>{_esc(e.get('country','') or '—')}</td>"
            f"<td>{len(e.get('ports',[]) or [])}</td>"
            f"<td style='color:{'#ef4444' if vc else 'inherit'}'>{vc}</td>"
            f"<td><span class='badge sev-{risk}'>{risk.upper()}</span></td>"
            f"</tr>\n"
        )
    html += "</tbody></table></div>\n"
    return ("IP Intelligence", html)


def _render_asn(sessions):
    all_asns = []
    for s in sessions:
        for a in (s.get("data", {}) or {}).get("asn_data", []) or []:
            all_asns.append(a)
    if not all_asns:
        return None
    critical = [a for a in all_asns if a.get("is_critical") or a.get("category") in ("hosting", "critical")]

    html = f"""<div class="subsection">
  <h3 class="ss-title">ASN Intelligence</h3>
  <p class="lead">Identified <b>{len(all_asns)}</b> autonomous systems, of which <b style="color:#f59e0b">{len(critical)}</b> are classified as critical infrastructure (hosting providers or sensitive networks).</p>
  <table class="tbl">
    <thead><tr><th>ASN</th><th>Name</th><th>Category</th><th>RIR</th><th>Country</th><th>Prefixes</th><th>Domains</th></tr></thead>
    <tbody>
"""
    for a in sorted(all_asns, key=lambda x: -(x.get("domain_count", 0) or 0))[:80]:
        cat = (a.get("category", "") or "").lower()
        cat_cls = "sev-critical" if cat in ("critical",) else "sev-high" if cat == "hosting" else "sev-info"
        html += (
            f"<tr>"
            f"<td class='mono'><b>AS{_esc(a.get('asn',''))}</b></td>"
            f"<td>{_esc(a.get('name', '') or a.get('description', ''))}</td>"
            f"<td><span class='badge {cat_cls}'>{_esc(cat.upper() or '—')}</span></td>"
            f"<td>{_esc(a.get('rir','') or '—')}</td>"
            f"<td>{_esc(a.get('country','') or '—')}</td>"
            f"<td>{a.get('prefix_count',0) or 0}</td>"
            f"<td>{a.get('domain_count',0) or 0}</td>"
            f"</tr>\n"
        )
    html += "</tbody></table></div>\n"
    return ("ASN Intelligence", html)


def _render_recon(sessions):
    if not sessions:
        return None
    subs = set(); urls = set(); vulns = []; ips = set()
    for s in sessions:
        d = s.get("data", {}) or {}
        subs.update(d.get("subdomains", []) or [])
        urls.update(d.get("urls", []) or [])
        vulns.extend(d.get("vulnerabilities", []) or [])
        ips.update(d.get("ips", []) or [])
    if not (subs or urls or vulns or ips):
        return None

    html = f"""<div class="subsection">
  <h3 class="ss-title">Automated Reconnaissance (ReconFTW)</h3>
  <p class="lead">Deep reconnaissance surfaced <b>{len(subs)}</b> subdomains, <b>{len(urls)}</b> URLs, <b>{len(ips)}</b> IPs, and <b style="color:#ef4444">{len(vulns)}</b> vulnerability indicators.</p>
  <div class="kpi-row">
    <div class="kpi"><div class="kpi-v">{len(subs)}</div><div class="kpi-l">Subdomains</div></div>
    <div class="kpi"><div class="kpi-v">{len(urls)}</div><div class="kpi-l">URLs</div></div>
    <div class="kpi"><div class="kpi-v">{len(ips)}</div><div class="kpi-l">IPs</div></div>
    <div class="kpi"><div class="kpi-v" style="color:#ef4444">{len(vulns)}</div><div class="kpi-l">Vuln Indicators</div></div>
  </div>
"""
    if vulns:
        html += "<h4 class='ss-sub'>Vulnerability Indicators</h4><table class='tbl'><thead><tr><th>#</th><th>Finding</th></tr></thead><tbody>"
        for i, v in enumerate(vulns[:60], 1):
            html += f"<tr><td>{i}</td><td class='mono' style='font-size:11px'>{_esc(str(v)[:250])}</td></tr>"
        if len(vulns) > 60:
            html += f"<tr><td colspan='2' class='muted tc'>… and {len(vulns) - 60} more</td></tr>"
        html += "</tbody></table>"
    html += "</div>\n"
    return ("Reconnaissance", html)


def _render_sudomy(sessions):
    if not sessions:
        return None
    subs = []; live = []; takeovers = []; tech = []; interesting = []
    for s in sessions:
        d = s.get("data", {}) or {}
        subs.extend(d.get("subdomains", []) or [])
        live.extend(d.get("live_hosts", []) or [])
        takeovers.extend(d.get("takeover", []) or [])
        tech.extend(d.get("technologies", []) or [])
        interesting.extend(d.get("interesting", []) or [])
    subs = list(dict.fromkeys(subs)); live = list(dict.fromkeys(live))

    if not (subs or live or takeovers):
        return None

    html = f"""<div class="subsection">
  <h3 class="ss-title">Sudomy Reconnaissance</h3>
  <p class="lead">Sudomy enumeration discovered <b>{len(subs)}</b> subdomains with <b style="color:#22c55e">{len(live)}</b> live hosts; <b style="color:#ef4444">{len(takeovers)}</b> potential subdomain takeover candidates were flagged.</p>
  <div class="kpi-row">
    <div class="kpi"><div class="kpi-v">{len(subs)}</div><div class="kpi-l">Subdomains</div></div>
    <div class="kpi"><div class="kpi-v" style="color:#22c55e">{len(live)}</div><div class="kpi-l">Live Hosts</div></div>
    <div class="kpi"><div class="kpi-v" style="color:#ef4444">{len(takeovers)}</div><div class="kpi-l">Takeovers</div></div>
    <div class="kpi"><div class="kpi-v">{len(interesting)}</div><div class="kpi-l">Interesting</div></div>
  </div>
"""
    if takeovers:
        html += "<h4 class='ss-sub'>Potential Subdomain Takeovers</h4><table class='tbl'><thead><tr><th>Entry</th></tr></thead><tbody>"
        for t in takeovers[:40]:
            html += f"<tr><td class='mono'>{_esc(t)}</td></tr>"
        html += "</tbody></table>"
    if live:
        html += "<h4 class='ss-sub'>Live Hosts (sample)</h4><div class='chips'>"
        for h in live[:40]:
            html += f"<span class='chip mono'>{_esc(h)}</span>"
        if len(live) > 40:
            html += f"<span class='chip muted'>+{len(live) - 40} more</span>"
        html += "</div>"
    html += "</div>\n"
    return ("Sudomy Reconnaissance", html)


def _render_pathstorm(sessions):
    if not sessions:
        return None
    all_results = []
    tools = set()
    for s in sessions:
        d = s.get("data", {}) or {}
        tool = d.get("tool", "")
        tools.add(tool) if tool else None
        for r in d.get("results", []) or []:
            all_results.append({**r, "_tool": tool, "_target": d.get("target", "")})
    if not all_results:
        return None

    status_counts = {}
    for r in all_results:
        s = str(r.get("status", "") or "—")
        status_counts[s] = status_counts.get(s, 0) + 1
    interesting = [r for r in all_results if str(r.get("status", "")) in ("200", "201", "401", "403")]

    html = f"""<div class="subsection">
  <h3 class="ss-title">Path & Directory Discovery (PathStorm)</h3>
  <p class="lead">Fuzzed <b>{len(sessions)}</b> target(s) with {", ".join(sorted(tools)) or 'dirsearch/ffuf'}, discovering <b>{len(all_results)}</b> paths (<b style="color:#22c55e">{status_counts.get('200', 0)}</b> returning 200, <b style="color:#f59e0b">{status_counts.get('403', 0)}</b> forbidden).</p>
  <div class="chips" style="margin-bottom:12px">
"""
    for code, count in sorted(status_counts.items(), key=lambda x: -x[1])[:10]:
        html += f"<span class='chip'>HTTP {code} <b>({count})</b></span>"
    html += "</div>"

    html += "<table class='tbl'><thead><tr><th>Target</th><th>Path</th><th>Status</th><th>Size</th><th>Redirect</th></tr></thead><tbody>"
    for r in interesting[:180]:
        status = r.get("status", "")
        cls = "sev-low" if status == 200 else "sev-medium" if status == 403 else "sev-info"
        size = r.get("size", 0) or 0
        size_str = f"{size:,}" if isinstance(size, int) else _esc(str(size))
        html += (
            f"<tr>"
            f"<td class='mono muted'>{_esc(r.get('_target',''))}</td>"
            f"<td class='mono'><a href='{_esc(r.get('url','') or '#')}' target='_blank'>{_esc(r.get('path',''))}</a></td>"
            f"<td><span class='badge {cls}'>{status}</span></td>"
            f"<td class='muted'>{size_str}</td>"
            f"<td class='mono muted' style='font-size:10.5px'>{_esc(r.get('redirect','') or '—')}</td>"
            f"</tr>\n"
        )
    if len(interesting) > 180:
        html += f"<tr><td colspan='5' class='muted tc'>… and {len(interesting) - 180} more paths</td></tr>"
    html += "</tbody></table></div>\n"
    return ("Path & Directory Discovery", html)


def _render_crawler(sessions):
    if not sessions:
        return None
    urls = []
    by_source = {}
    for s in sessions:
        d = s.get("data", {}) or {}
        for u in d.get("urls", []) or []:
            urls.append(u)
        for k, v in (d.get("by_source", {}) or {}).items():
            by_source[k] = by_source.get(k, 0) + v
    # dedupe
    seen = set(); deduped = []
    for u in urls:
        key = u.get("url") if isinstance(u, dict) else u
        if key and key not in seen:
            seen.add(key); deduped.append(u)
    if not deduped:
        return None

    html = f"""<div class="subsection">
  <h3 class="ss-title">URL & Endpoint Harvesting (Crawler)</h3>
  <p class="lead">Passive source aggregation collected <b>{len(deduped)}</b> unique URLs from archival indexes (Wayback Machine, CommonCrawl, OTX, URLScan) and harvester tools.</p>
  <div class="kpi-row">
    <div class="kpi"><div class="kpi-v">{len(deduped)}</div><div class="kpi-l">Unique URLs</div></div>
    <div class="kpi"><div class="kpi-v">{len(by_source)}</div><div class="kpi-l">Sources</div></div>
  </div>
"""
    if by_source:
        html += "<h4 class='ss-sub'>Sources Contribution</h4><div class='chips'>"
        for src, count in sorted(by_source.items(), key=lambda x: -x[1]):
            html += f"<span class='chip'>{_esc(src)} <b>({count:,})</b></span>"
        html += "</div>"

    html += "<h4 class='ss-sub'>Sample URLs</h4><table class='tbl'><thead><tr><th>URL</th><th>Source</th></tr></thead><tbody>"
    for u in deduped[:120]:
        url_str = u.get("url") if isinstance(u, dict) else u
        src = u.get("source", "") if isinstance(u, dict) else ""
        html += (
            f"<tr>"
            f"<td class='mono' style='font-size:11px;word-break:break-all'><a href='{_esc(url_str)}' target='_blank'>{_esc(url_str[:200])}</a></td>"
            f"<td class='muted'>{_esc(src)}</td>"
            f"</tr>"
        )
    if len(deduped) > 120:
        html += f"<tr><td colspan='2' class='muted tc'>… and {len(deduped) - 120} more URLs</td></tr>"
    html += "</tbody></table></div>\n"
    return ("URL & Endpoint Harvesting", html)


def _render_jsintel(sessions):
    if not sessions:
        return None
    endpoints = []; interesting = []; js_urls = []
    for s in sessions:
        d = s.get("data", {}) or {}
        endpoints.extend(d.get("endpoints", []) or [])
        interesting.extend(d.get("interesting", []) or [])
        js_urls.extend(d.get("js_urls", []) or [])
    if not (endpoints or interesting or js_urls):
        return None

    html = f"""<div class="subsection">
  <h3 class="ss-title">JavaScript Intelligence</h3>
  <p class="lead">Analyzed <b>{len(js_urls)}</b> JavaScript resources, extracting <b>{len(endpoints)}</b> endpoints — <b style="color:#ef4444">{len(interesting)}</b> of which match sensitive-pattern heuristics (admin, api, auth, debug, token, etc.).</p>
  <div class="kpi-row">
    <div class="kpi"><div class="kpi-v">{len(js_urls)}</div><div class="kpi-l">JS Files</div></div>
    <div class="kpi"><div class="kpi-v">{len(endpoints)}</div><div class="kpi-l">Endpoints</div></div>
    <div class="kpi"><div class="kpi-v" style="color:#ef4444">{len(interesting)}</div><div class="kpi-l">Hot Matches</div></div>
  </div>
"""
    if interesting:
        html += "<h4 class='ss-sub'>Sensitive-Pattern Endpoints</h4><table class='tbl'><thead><tr><th>Endpoint</th><th>Source</th><th>Tool</th></tr></thead><tbody>"
        for e in interesting[:100]:
            html += (
                f"<tr>"
                f"<td class='mono' style='font-size:11px;word-break:break-all'>{_esc(str(e.get('endpoint',''))[:200])}</td>"
                f"<td class='mono muted' style='font-size:10.5px'>{_esc(e.get('source_js','') or e.get('host',''))}</td>"
                f"<td class='muted'>{_esc(e.get('tool',''))}</td>"
                f"</tr>"
            )
        if len(interesting) > 100:
            html += f"<tr><td colspan='3' class='muted tc'>… and {len(interesting) - 100} more</td></tr>"
        html += "</tbody></table>"
    html += "</div>\n"
    return ("JavaScript Intelligence", html)


def _render_wpscan_detail(sessions):
    if not sessions:
        return None
    vulns = []; creds = []; users = []; plugins = []; themes = []; versions = []
    for s in sessions:
        d = s.get("data", {}) or {}
        vulns.extend(d.get("vulns", []) or [])
        creds.extend(d.get("credentials", []) or [])
        users.extend(d.get("users", []) or [])
        plugins.extend(d.get("plugins", []) or [])
        themes.extend(d.get("themes", []) or [])
        if d.get("version"):
            versions.append({**d.get("version"), "target": s.get("target", "")})

    if not (vulns or creds or users or plugins or themes or versions):
        return None

    html = f"""<div class="subsection">
  <h3 class="ss-title">WordPress Deep Inspection</h3>
  <p class="lead">WPScan/WPProbe analysis surfaced <b style="color:#ef4444">{len(vulns)}</b> vulnerabilities, <b>{len(plugins)}</b> plugins, <b>{len(themes)}</b> themes, <b>{len(users)}</b> users, and <b style="color:#ef4444">{len(creds)}</b> compromised credentials.</p>
  <div class="kpi-row">
    <div class="kpi"><div class="kpi-v" style="color:#ef4444">{len(vulns)}</div><div class="kpi-l">Vulnerabilities</div></div>
    <div class="kpi"><div class="kpi-v">{len(plugins)}</div><div class="kpi-l">Plugins</div></div>
    <div class="kpi"><div class="kpi-v">{len(themes)}</div><div class="kpi-l">Themes</div></div>
    <div class="kpi"><div class="kpi-v">{len(users)}</div><div class="kpi-l">Users</div></div>
    <div class="kpi"><div class="kpi-v" style="color:#ef4444">{len(creds)}</div><div class="kpi-l">Credentials</div></div>
  </div>
"""
    if versions:
        html += "<h4 class='ss-sub'>WordPress Core</h4><table class='tbl'><thead><tr><th>Target</th><th>Version</th><th>Status</th></tr></thead><tbody>"
        for v in versions:
            insec = v.get("insecure", False)
            cls = "sev-high" if insec else "sev-low"
            label = "INSECURE" if insec else "SUPPORTED"
            html += f"<tr><td class='mono'>{_esc(v.get('target',''))}</td><td class='mono'>{_esc(v.get('version','?'))}</td><td><span class='badge {cls}'>{label}</span></td></tr>"
        html += "</tbody></table>"

    if vulns:
        html += "<h4 class='ss-sub'>Plugin / Core Vulnerabilities</h4><table class='tbl'><thead><tr><th>Severity</th><th>Title</th><th>Plugin</th><th>Fixed In</th></tr></thead><tbody>"
        for v in vulns[:80]:
            sev = (v.get("severity") or "medium").lower()
            html += (
                f"<tr>"
                f"<td><span class='badge sev-{sev}'>{sev.upper()}</span></td>"
                f"<td><b>{_esc(v.get('title',''))}</b></td>"
                f"<td class='muted'>{_esc(v.get('plugin','') or '—')}</td>"
                f"<td class='mono'>{_esc(v.get('fixed_in','') or '—')}</td>"
                f"</tr>"
            )
        if len(vulns) > 80:
            html += f"<tr><td colspan='4' class='muted tc'>… and {len(vulns) - 80} more</td></tr>"
        html += "</tbody></table>"

    if creds:
        html += "<h4 class='ss-sub'>Compromised Credentials</h4><table class='tbl'><thead><tr><th>Username</th><th>Password</th></tr></thead><tbody>"
        for c in creds:
            html += f"<tr><td class='mono'>{_esc(c.get('username',''))}</td><td class='mono' style='color:#ef4444'>{_esc(c.get('password',''))}</td></tr>"
        html += "</tbody></table>"

    if users:
        html += "<h4 class='ss-sub'>Enumerated Users</h4><div class='chips'>"
        for u in users[:30]:
            html += f"<span class='chip mono'>{_esc(u.get('username',''))}</span>"
        if len(users) > 30:
            html += f"<span class='chip muted'>+{len(users) - 30} more</span>"
        html += "</div>"

    if plugins:
        html += "<h4 class='ss-sub'>Plugins Detected</h4><div class='chips'>"
        for p in plugins[:50]:
            name = p.get("name", "")
            ver = p.get("version", "")
            html += f"<span class='chip'>{_esc(name)}{' · ' + _esc(ver) if ver else ''}</span>"
        if len(plugins) > 50:
            html += f"<span class='chip muted'>+{len(plugins) - 50} more</span>"
        html += "</div>"
    html += "</div>\n"
    return ("WordPress Deep Inspection", html)


# ═══════════════════════════════════════════════════════════════════════════════
# Main entry
# ═══════════════════════════════════════════════════════════════════════════════

def _render_arena(sessions):
    """AI Arena summary across one-or-more arena sessions: agents, leaderboard,
    asset graph, finding-attribution table. Judge verdict gets its own section."""
    if not sessions:
        return None

    total_findings = 0
    total_agents   = 0
    total_cost     = 0.0
    total_steps    = 0
    total_tools    = 0
    asset_totals: dict[str, int] = {}
    agent_rows: list[dict] = []
    finding_rows: list[dict] = []

    for s in sessions:
        d = s.get("data", {}) or {}
        sm = s.get("summary", {}) or {}
        total_findings += int(sm.get("findings", 0) or 0)
        agents_meta = d.get("agents") or []
        total_agents += len(agents_meta)
        for k, v in (sm.get("assets") or {}).items() if isinstance(sm.get("assets"), dict) else []:
            asset_totals[k] = asset_totals.get(k, 0) + int(v or 0)
        # Asset counts are also in data.assets as full lists.
        for k, lst in (d.get("assets") or {}).items():
            if isinstance(lst, list):
                asset_totals[k] = asset_totals.get(k, 0) + len(lst)
        # Per-agent rows from leaderboard (preferred, has totals) or agents meta.
        lb = d.get("leaderboard") or []
        if lb:
            for r in lb:
                agent_rows.append({**r, "session": s.get("name", "")})
                total_cost  += float(r.get("cost") or 0)
                total_steps += int(r.get("steps") or 0)
                total_tools += int(r.get("tools") or 0)
        else:
            for a in agents_meta:
                agent_rows.append({**a, "session": s.get("name", "")})
        for f in d.get("findings", []) or []:
            finding_rows.append({**f, "session": s.get("name", ""),
                                 "target": f.get("target", "") or s.get("target", "")})

    if not agent_rows and not finding_rows:
        return None

    # Sort: critHigh → findings → time
    agent_rows.sort(key=lambda r: (
        -(int(r.get("critHigh") or 0)),
        -(int(r.get("findings") or 0)),
        int(r.get("elapsed") or 999999),
    ))
    finding_rows.sort(key=lambda f: -_severity_weight(f.get("severity", "")))

    # Asset row
    asset_line_bits = []
    for k in ("subdomain", "url", "endpoint", "param", "tech", "port"):
        if asset_totals.get(k):
            asset_line_bits.append(f"<b>{asset_totals[k]}</b> {k}{'s' if asset_totals[k] != 1 else ''}")
    asset_line = " · ".join(asset_line_bits) if asset_line_bits else "no assets discovered"

    html = f"""<div class="subsection">
  <h3 class="ss-title">AI Arena — Autonomous Investigation</h3>
  <p class="lead">Autonomous LLM agents ran against the target for {len(sessions)} race{'s' if len(sessions) != 1 else ''}, producing <b>{total_findings}</b> deduplicated finding{'s' if total_findings != 1 else ''} across <b>{total_agents}</b> agent run{'s' if total_agents != 1 else ''} ({total_steps} steps · {total_tools} tool calls · ${total_cost:.3f}). Shared asset graph: {asset_line}.</p>
  <div class="kpi-row">
    <div class="kpi"><div class="kpi-v">{len(sessions)}</div><div class="kpi-l">Races</div></div>
    <div class="kpi"><div class="kpi-v">{total_agents}</div><div class="kpi-l">Agents</div></div>
    <div class="kpi"><div class="kpi-v" style="color:#eab308">{total_findings}</div><div class="kpi-l">Findings</div></div>
    <div class="kpi"><div class="kpi-v">${total_cost:.2f}</div><div class="kpi-l">LLM Cost</div></div>
    <div class="kpi"><div class="kpi-v">{total_tools}</div><div class="kpi-l">Tool Calls</div></div>
  </div>
"""
    if agent_rows:
        html += """  <h4 class="ss-sub">Agent Leaderboard</h4>
  <table class="tbl">
    <thead><tr><th>Rank</th><th>Agent</th><th>Model</th><th>Findings</th><th>Crit/High</th><th>Tool Calls</th><th>Cost</th><th>Time</th></tr></thead>
    <tbody>
"""
        for i, r in enumerate(agent_rows[:20]):
            medal = ["🥇", "🥈", "🥉"][i] if i < 3 else f"{i+1}."
            label = _esc(r.get("label") or r.get("agent_id") or "?")
            model = _esc(r.get("model") or "")
            html += (
                f"<tr>"
                f"<td>{medal}</td>"
                f"<td><b>{label}</b></td>"
                f"<td class='muted'>{model}</td>"
                f"<td>{int(r.get('findings') or 0)}</td>"
                f"<td>{int(r.get('critHigh') or 0)}</td>"
                f"<td>{int(r.get('tools') or 0)}</td>"
                f"<td>${float(r.get('cost') or 0):.4f}</td>"
                f"<td>{int(r.get('elapsed') or 0)}s</td>"
                f"</tr>\n"
            )
        html += "    </tbody>\n  </table>\n"

    if finding_rows:
        html += """  <h4 class="ss-sub">Submitted Findings</h4>
  <table class="tbl">
    <thead><tr><th>Severity</th><th>Vuln</th><th>Location</th><th>Discovered By</th><th>Description</th></tr></thead>
    <tbody>
"""
        for f in finding_rows[:80]:
            sev = (f.get("severity") or "info").lower()
            color = _severity_color(sev)
            disc = f.get("discovered_by") or []
            disc_str = ",".join(disc) if isinstance(disc, list) else str(disc)
            html += (
                f"<tr>"
                f"<td><span class='badge' style='background:{color}20;color:{color};border-color:{color}40'>{sev.upper()}</span></td>"
                f"<td><b>{_esc(f.get('vuln_type', '—'))}</b></td>"
                f"<td class='muted' style='word-break:break-all'>{_esc(f.get('location', ''))}</td>"
                f"<td class='muted'>{_esc(disc_str)}</td>"
                f"<td class='muted'>{_esc((f.get('description') or '')[:200])}</td>"
                f"</tr>\n"
            )
        if len(finding_rows) > 80:
            html += f"<tr><td colspan='5' class='muted tc'>… and {len(finding_rows) - 80} more findings</td></tr>\n"
        html += "    </tbody>\n  </table>\n"

    html += "</div>\n"
    return ("AI Arena — Autonomous Investigation", html)


def _render_judge(sessions):
    """End-of-race judge verdict(s) — markdown summary, agent scores, finding grades."""
    judges = []
    for s in sessions:
        v = (s.get("data", {}) or {}).get("judge")
        if v:
            judges.append((s, v))
    if not judges:
        return None

    html = """<div class="subsection">
  <h3 class="ss-title">⚖ AI Arena — Judge Verdict</h3>
  <p class="lead">An end-of-race LLM critic reviewed the agents' findings and scored each on evidence rigor, severity accuracy, novelty, and efficiency.</p>
"""
    for s, v in judges:
        winner_aid = v.get("winner_agent_id") or ""
        # Map agent_id → label using session.data.agents
        agents_meta = (s.get("data", {}) or {}).get("agents") or []
        id_to_label = {a.get("agent_id"): a.get("label") or a.get("agent_id") for a in agents_meta}

        summary = _esc(v.get("summary", "")).replace("\n\n", "<br><br>").replace("\n", "<br>")
        html += f"""  <div style="padding:12px 14px;background:rgba(99,102,241,.06);border-left:3px solid #6366f1;border-radius:4px;margin-bottom:14px">
    <div style="font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:#a5b4fc;font-weight:700;margin-bottom:6px">Race: {_esc(s.get('name', '?'))}</div>
    <div style="font-size:12.5px;color:#cbd5e1;line-height:1.6;margin-bottom:8px">{summary}</div>
"""
        if v.get("winner_reason"):
            html += f"""    <div style="font-size:11.5px;color:#fcd34d;font-style:italic;margin-bottom:10px">🏆 Winner ({_esc(id_to_label.get(winner_aid, winner_aid))}): {_esc(v['winner_reason'])}</div>\n"""

        agent_scores = v.get("agents") or []
        if agent_scores:
            html += """    <table class="tbl" style="margin-top:8px">
      <thead><tr><th>Agent</th><th>Score</th><th>Evidence</th><th>Severity</th><th>Novelty</th><th>Efficiency</th><th>Feedback</th></tr></thead>
      <tbody>
"""
            for a in sorted(agent_scores, key=lambda x: -(x.get("score", 0) or 0)):
                aid = a.get("agent_id", "")
                lbl = id_to_label.get(aid, aid)
                medal = "🥇 " if aid == winner_aid else ""
                br = a.get("breakdown") or {}
                html += (
                    f"<tr>"
                    f"<td><b>{medal}{_esc(lbl)}</b></td>"
                    f"<td><b style='color:#fcd34d'>{a.get('score', '?')}/100</b></td>"
                    f"<td>{br.get('evidence', '?')}/5</td>"
                    f"<td>{br.get('severity', '?')}/5</td>"
                    f"<td>{br.get('novelty', '?')}/5</td>"
                    f"<td>{br.get('efficiency', '?')}/5</td>"
                    f"<td class='muted'>{_esc(a.get('feedback', ''))}</td>"
                    f"</tr>\n"
                )
            html += "      </tbody>\n    </table>\n"

        finding_scores = v.get("findings") or []
        if finding_scores:
            html += """    <h5 style="margin-top:10px;color:#a5b4fc;font-size:11.5px;text-transform:uppercase;letter-spacing:.5px">Per-Finding Grades</h5>
    <table class="tbl">
      <thead><tr><th>True Severity</th><th>Evidence</th><th>Severity Assessment</th><th>Notes</th></tr></thead>
      <tbody>
"""
            for f in finding_scores[:30]:
                tsev  = (f.get("true_severity") or "info").lower()
                color = _severity_color(tsev)
                ass   = f.get("severity_assessment", "agree")
                ass_text = {"agree": "✓ Agree",
                            "overrated": "⬇ Overrated",
                            "underrated": "⬆ Underrated"}.get(ass, ass)
                ass_color = {"agree": "#22c55e", "overrated": "#f59e0b",
                             "underrated": "#ef4444"}.get(ass, "#94a3b8")
                html += (
                    f"<tr>"
                    f"<td><span class='badge' style='background:{color}20;color:{color};border-color:{color}40'>{tsev.upper()}</span></td>"
                    f"<td>{f.get('evidence_quality', '?')}/5</td>"
                    f"<td style='color:{ass_color}'>{ass_text}</td>"
                    f"<td class='muted'>{_esc(f.get('notes', ''))}</td>"
                    f"</tr>\n"
                )
            html += "      </tbody>\n    </table>\n"

        next_steps = v.get("next_steps") or []
        if next_steps:
            html += """    <h5 style="margin-top:10px;color:#a5b4fc;font-size:11.5px;text-transform:uppercase;letter-spacing:.5px">Recommended Next Steps</h5>
    <ul style="margin:6px 0 0 22px;line-height:1.6;color:#cbd5e1;font-size:11.5px">
"""
            for step in next_steps:
                html += f"      <li>{_esc(step)}</li>\n"
            html += "    </ul>\n"

        html += "  </div>\n"
    html += "</div>\n"
    return ("Judge Verdict", html)


def generate_report(
    sessions,
    operation_name="Security Assessment",
    target="",
    analyst="Analyst",
    include_exec=True,
    include_methodology=True,
    include_risk=True,
    include_findings=True,
    include_recommendations=True,
    company="ZeekGlare Intelligence",
    classification="CONFIDENTIAL",
):
    now = datetime.now(timezone.utc).strftime("%B %d, %Y at %H:%M UTC")
    date_short = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    by_type = {}
    for s in sessions:
        by_type.setdefault(s.get("type", "unknown"), []).append(s)

    all_targets = set()
    for s in sessions:
        t = s.get("target", "")
        if t:
            all_targets.add(t)
    primary_target = target or (sorted(all_targets)[0] if all_targets else "N/A")

    # Aggregate all vulns across threatblitz + wpscan
    all_vulns = []
    for s in by_type.get("threatblitz", []):
        for r in (s.get("data", {}) or {}).get("results", []) or []:
            all_vulns.append({
                "title":    r.get("name") or r.get("template") or "Finding",
                "severity": r.get("severity", "info"),
                "host":     r.get("matched", "") or r.get("target", ""),
                "detail":   r.get("description", "") or r.get("matched", ""),
                "cve":      r.get("cve", ""),
                "ref":      r.get("ref", ""),
                "source":   (r.get("tool", "") or "ThreatBlitz").title(),
            })
    for s in by_type.get("wpscan", []):
        for v in (s.get("data", {}) or {}).get("vulns", []) or []:
            refs = v.get("refs", []) or []
            all_vulns.append({
                "title":    v.get("title", "WordPress Vulnerability"),
                "severity": v.get("severity", "medium"),
                "host":     s.get("target", ""),
                "detail":   v.get("plugin", "") or v.get("title", ""),
                "cve":      next((r for r in refs if r.startswith("CVE-")), ""),
                "ref":      refs[0] if refs else "",
                "source":   "WPScan",
            })
    # Arena findings — submitted by autonomous agents through skill_*/add_finding.
    for s in by_type.get("arena", []):
        for f in (s.get("data", {}) or {}).get("findings", []) or []:
            disc = f.get("discovered_by") or []
            disc_label = ",".join(disc) if isinstance(disc, list) else str(disc)
            all_vulns.append({
                "title":    f.get("vuln_type", "Arena finding"),
                "severity": (f.get("severity") or "info").lower(),
                "host":     f.get("target", "") or s.get("target", ""),
                "detail":   (f.get("description") or "")[:240] +
                            (f"  · evidence: {(f.get('evidence') or '')[:160]}"
                             if f.get("evidence") else ""),
                "cve":      "",
                "ref":      f.get("location", ""),
                "source":   f"AI Arena ({disc_label})" if disc_label else "AI Arena",
            })
    all_vulns.sort(key=lambda v: -_severity_weight(v.get("severity", "")))

    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for v in all_vulns:
        k = (v.get("severity", "info") or "info").lower()
        if k in sev_counts:
            sev_counts[k] += 1

    # Subdomains (domain type)
    all_subdomains = []
    for s in by_type.get("domain", []):
        for e in (s.get("data", {}) or {}).get("entries", []) or []:
            all_subdomains.append(e)

    # Ports
    all_ports = []
    for s in by_type.get("ports", []):
        for host, hdata in ((s.get("data", {}) or {}).get("results", {}) or {}).items():
            for p in hdata.get("ports", []) or []:
                all_ports.append({**p, "host": host})

    # IPs
    all_ips = []
    for s in by_type.get("ipscope", []):
        for e in (s.get("data", {}) or {}).get("entries", []) or []:
            all_ips.append(e)

    # Risk score
    risk = _risk_score(sessions)
    risk_label = (
        "Critical" if risk >= 75 else
        "High"     if risk >= 50 else
        "Medium"   if risk >= 25 else
        "Low"
    )
    risk_color = _severity_color(risk_label)

    # ── Build sections ────────────────────────────────────────────────────────
    sections = []
    if include_findings:
        sub   = _render_subdomains(all_subdomains)
        if sub: sections.append(sub)
        asn   = _render_asn(by_type.get("asn", []))
        if asn: sections.append(asn)
        rec   = _render_recon(by_type.get("recon", []))
        if rec: sections.append(rec)
        sud   = _render_sudomy(by_type.get("sudomy", []))
        if sud: sections.append(sud)
        crawl = _render_crawler(by_type.get("crawler", []))
        if crawl: sections.append(crawl)
        jsi   = _render_jsintel(by_type.get("jsintel", []))
        if jsi: sections.append(jsi)
        ports = _render_ports(all_ports)
        if ports: sections.append(ports)
        paths = _render_pathstorm(by_type.get("pathstorm", []))
        if paths: sections.append(paths)
        wp    = _render_wpscan_detail(by_type.get("wpscan", []))
        if wp: sections.append(wp)
        ipsc  = _render_ipscope(all_ips)
        if ipsc: sections.append(ipsc)
        # Arena + judge come before the unified vulns table so the reader
        # has agent-attribution context before seeing the merged finding list.
        arena = _render_arena(by_type.get("arena", []))
        if arena: sections.append(arena)
        judge = _render_judge(by_type.get("arena", []))
        if judge: sections.append(judge)
        vulns = _render_vulns(all_vulns, sev_counts)
        if vulns: sections.append(vulns)

    # ── Executive Summary ─────────────────────────────────────────────────────
    exec_html = ""
    if include_exec:
        sev_total = max(sum(sev_counts.values()), 1)
        exec_html = f"""
<div class="section page-break">
  <div class="sec-head"><span class="sec-num">01</span><h2>Executive Summary</h2></div>
  <p class="lead">
    This report documents the findings of a comprehensive security assessment conducted against
    <b>{_esc(primary_target)}</b>. The engagement applied <b>{len(sessions)}</b> discrete scanning session(s)
    across <b>{len(by_type)}</b> reconnaissance and vulnerability-assessment methodologies, producing an
    aggregated risk rating of <b style="color:{risk_color}">{risk_label} ({risk}/100)</b>.
  </p>
  <div class="kpi-row">
    <div class="kpi"><div class="kpi-v">{len(all_subdomains)}</div><div class="kpi-l">Subdomains</div></div>
    <div class="kpi"><div class="kpi-v" style="color:{risk_color}">{len(all_vulns)}</div><div class="kpi-l">Vulnerabilities</div></div>
    <div class="kpi"><div class="kpi-v">{len(all_ports)}</div><div class="kpi-l">Open Ports</div></div>
    <div class="kpi"><div class="kpi-v">{len(all_ips)}</div><div class="kpi-l">IPs Mapped</div></div>
    <div class="kpi"><div class="kpi-v" style="color:#ef4444">{sev_counts['critical']}</div><div class="kpi-l">Critical</div></div>
    <div class="kpi"><div class="kpi-v" style="color:#f59e0b">{sev_counts['high']}</div><div class="kpi-l">High</div></div>
  </div>
  <div class="box">
    <h4>Key Observations</h4>
    <ul>
"""
        obs = []
        if sev_counts["critical"]:
            obs.append(f"<b style='color:#ef4444'>{sev_counts['critical']} critical vulnerabilities</b> require immediate remediation, as they may enable remote code execution, authentication bypass, or direct data exfiltration.")
        if sev_counts["high"]:
            obs.append(f"<b style='color:#f59e0b'>{sev_counts['high']} high-severity vulnerabilities</b> pose significant risk and should be remediated within the current sprint cycle.")
        no_waf_count = sum(1 for e in all_subdomains if not e.get("waf"))
        if no_waf_count > 0:
            obs.append(f"<b>{no_waf_count} subdomains</b> lack WAF protection, increasing exposure to common web application attacks.")
        sensitive_svc = [p for p in all_ports if (p.get("service","") or "").lower() in ("ssh","ftp","telnet","rdp","smb","mysql","postgres","mssql","mongodb","redis","elasticsearch")]
        if sensitive_svc:
            obs.append(f"<b>{len(sensitive_svc)} sensitive services</b> (database, admin, management) are exposed on public network interfaces.")
        if all_subdomains and len(all_subdomains) > 50:
            obs.append(f"Attack surface is large: <b>{len(all_subdomains)}</b> discovered subdomains indicate potential for forgotten or misconfigured assets.")
        if not obs:
            obs.append("No critical-severity issues were identified during the scope of this assessment. Continued monitoring is recommended.")
        exec_html += "".join(f"      <li>{o}</li>\n" for o in obs)
        exec_html += f"""    </ul>
  </div>
</div>
"""

    # ── Methodology ───────────────────────────────────────────────────────────
    meth_html = ""
    if include_methodology:
        type_labels = {
            "asn":         ("ASN Intelligence",          "Autonomous System enumeration, BGP prefix mapping, and critical-infrastructure classification."),
            "domain":      ("Domain Reconnaissance",     "Multi-source subdomain discovery, HTTP probing, technology fingerprinting, and WAF detection."),
            "ports":       ("Network Port Scanning",     "Service enumeration with Nmap/Masscan/RustScan/Naabu, banner grabbing, and TLS inspection."),
            "threatblitz": ("Vulnerability Scanning",    "Template-based vulnerability detection via Nuclei, Nikto, and Afrog."),
            "wpscan":      ("WordPress Assessment",      "Core, plugin, theme, and user enumeration with vulnerability matching."),
            "recon":       ("Automated Reconnaissance",  "Deep multi-tool reconnaissance via ReconFTW framework."),
            "ipscope":     ("IP Intelligence",           "IP mapping, geolocation, ASN attribution, and CVE enrichment."),
            "crawler":     ("URL Harvesting",            "Passive URL discovery from Wayback Machine, CommonCrawl, OTX, URLScan, and crawl tools."),
            "sudomy":      ("Sudomy Reconnaissance",     "Multi-source subdomain intelligence with takeover detection and fingerprinting."),
            "pathstorm":   ("Path & Directory Discovery","Directory and file fuzzing via dirsearch, ffuf, and AI-assisted ffufai."),
            "jsintel":     ("JavaScript Analysis",       "JS endpoint extraction, secret pattern detection, and source map inspection."),
            "workflow":    ("Automated Workflow",        "Chained multi-tool pipeline execution."),
            "arena":       ("AI Arena",                  "Autonomous LLM agents racing against the target — recon, skill probes, and structured finding submission with end-of-race judge verdict."),
        }
        meth_html = """
<div class="section page-break">
  <div class="sec-head"><span class="sec-num">02</span><h2>Methodology &amp; Scope</h2></div>
  <p class="lead">The following reconnaissance and assessment techniques were executed in sequence to progressively map the target's attack surface and identify exposure points.</p>
  <div class="timeline">
"""
        for stype, sess_list in by_type.items():
            label, desc = type_labels.get(stype, (stype.upper(), "Specialized assessment module."))
            tgt_set = sorted({s.get("target", "") for s in sess_list if s.get("target")})
            tgt_chip = ", ".join(tgt_set[:3]) + (f", +{len(tgt_set) - 3} more" if len(tgt_set) > 3 else "")
            meth_html += f"""    <div class="tl-item">
      <div class="tl-dot"></div>
      <div class="tl-body">
        <div class="tl-title">{_esc(label)}</div>
        <div class="tl-desc">{_esc(desc)}</div>
        <div class="tl-meta">
          <span class="chip">{len(sess_list)} session{'s' if len(sess_list) != 1 else ''}</span>
          <span class="chip muted">{_esc(tgt_chip or '—')}</span>
        </div>
      </div>
    </div>
"""
        meth_html += "  </div>\n</div>\n"

    # ── Risk Assessment ───────────────────────────────────────────────────────
    risk_html = ""
    if include_risk:
        risks = []
        if sev_counts["critical"]:
            risks.append(("Critical", "#ef4444", f"{sev_counts['critical']} critical vulnerabilities detected",
                          "These may enable remote code execution, authentication bypass, or direct data compromise. Immediate remediation is required."))
        if sev_counts["high"]:
            risks.append(("High", "#f59e0b", f"{sev_counts['high']} high-severity vulnerabilities",
                          "Significant exploitation potential — address within the current remediation sprint."))
        sensitive_ports = [p for p in all_ports if (p.get("service","") or "").lower() in ("ssh","ftp","telnet","rdp","smb","mysql","postgres","mssql","mongodb","redis","elasticsearch","vnc")]
        if sensitive_ports:
            risks.append(("High", "#f59e0b", "Sensitive administrative services exposed",
                          f"{len(sensitive_ports)} administrative/database services are reachable from the public internet. These should be restricted via firewall rules, VPN, or IP allow-listing."))
        no_waf_count = sum(1 for e in all_subdomains if not e.get("waf"))
        if no_waf_count >= 5:
            risks.append(("Medium", "#fb923c", f"{no_waf_count} subdomains without WAF coverage",
                          "A significant portion of the web asset inventory is not protected by a Web Application Firewall, increasing exposure to common attack classes."))
        if len(all_subdomains) > 50:
            risks.append(("Medium", "#fb923c", "Large attack surface",
                          f"{len(all_subdomains)} discovered subdomains present a wide attack surface; legacy or forgotten assets are likely."))
        takeover_count = sum(1 for s in by_type.get("sudomy", []) for _ in (s.get("data", {}) or {}).get("takeover", []) or [])
        if takeover_count:
            risks.append(("High", "#f59e0b", f"{takeover_count} potential subdomain takeovers",
                          "Dangling DNS records pointing to decommissioned third-party services could be claimed by an attacker and used for phishing or brand abuse."))
        creds_found = sum(len((s.get("data", {}) or {}).get("credentials", []) or []) for s in by_type.get("wpscan", []))
        if creds_found:
            risks.append(("Critical", "#ef4444", f"{creds_found} valid credentials compromised",
                          "Credential compromise was demonstrated during testing. Affected accounts must be reset immediately and credential-hygiene policies reviewed."))
        if not risks:
            risks.append(("Low", "#14b8a6", "No critical risks identified",
                          "The assessment did not identify immediate critical risks. Continue periodic reassessment to detect regressions."))

        risk_html = """
<div class="section page-break">
  <div class="sec-head"><span class="sec-num">03</span><h2>Risk Assessment</h2></div>
  <p class="lead">Consolidated risk register summarizing the material exposures identified during this engagement.</p>
  <div class="risk-grid">
"""
        for sev, color, title, desc in risks:
            risk_html += f"""    <div class="risk-card" style="border-left-color:{color}">
      <div class="rc-head">
        <span class="badge" style="background:{color}20;color:{color};border-color:{color}40">{sev.upper()}</span>
        <h4>{_esc(title)}</h4>
      </div>
      <p>{_esc(desc)}</p>
    </div>
"""
        risk_html += "  </div>\n</div>\n"

    # ── Recommendations ──────────────────────────────────────────────────────
    rec_list = []
    if sev_counts["critical"]:
        rec_list.append(("Immediate", "#ef4444", "Remediate critical vulnerabilities",
                         "Patch, disable, or compensating-control all critical-severity findings before any non-urgent release. Document each fix in a change ticket linked to the finding."))
    if sev_counts["high"]:
        rec_list.append(("Short-term", "#f59e0b", "Address high-severity findings within one sprint",
                         "Assign each high-severity finding to an owner with a SLA-bound due date. Validate fixes with targeted re-scans."))
    if all_subdomains and sum(1 for e in all_subdomains if not e.get("waf")) > 0:
        rec_list.append(("Medium-term", "#fb923c", "Deploy WAF coverage across the web estate",
                         "Standardize Web Application Firewall deployment (CloudFlare, AWS WAF, or similar) across all externally reachable subdomains."))
    sensitive_ports = [p for p in all_ports if (p.get("service","") or "").lower() in ("ssh","ftp","telnet","rdp","smb","mysql","postgres","mssql","mongodb","redis")]
    if sensitive_ports:
        rec_list.append(("Immediate", "#ef4444", "Restrict exposure of sensitive services",
                         "Move administrative and database services behind VPN / bastion / zero-trust network access; enforce MFA on all administrative endpoints."))
    if len(all_subdomains) > 20:
        rec_list.append(("Medium-term", "#fb923c", "Implement asset inventory & attack-surface management",
                         "Maintain an authoritative inventory of external assets with an onboarding/decommissioning lifecycle to prevent orphaned services."))
    rec_list.append(("Continuous", "#14b8a6", "Schedule periodic reassessments",
                     "Establish a cadence (at least quarterly) for re-running this scan profile to detect vulnerability regressions and configuration drift."))
    rec_list.append(("Continuous", "#14b8a6", "Formalize vulnerability management",
                     "Establish SLAs per severity tier and track remediation via a central dashboard. Integrate findings into the organization's risk register."))

    rec_html = ""
    if include_recommendations:
        rec_html = """
<div class="section page-break">
  <div class="sec-head"><span class="sec-num">05</span><h2>Recommendations</h2></div>
  <p class="lead">Prioritized remediation actions, ordered by urgency. Ownership and SLA assignment are recommended for each item.</p>
  <table class="tbl">
    <thead><tr><th>Priority</th><th>Recommendation</th><th>Detail</th></tr></thead>
    <tbody>
"""
        for prio, color, title, detail in rec_list:
            rec_html += (
                f"<tr>"
                f"<td><span class='badge' style='background:{color}20;color:{color};border-color:{color}40'>{prio.upper()}</span></td>"
                f"<td><b>{_esc(title)}</b></td>"
                f"<td class='muted'>{_esc(detail)}</td>"
                f"</tr>"
            )
        rec_html += "</tbody></table></div>\n"

    # ── Findings sections numbering ──────────────────────────────────────────
    findings_html = ""
    if sections:
        findings_html = """
<div class="section page-break">
  <div class="sec-head"><span class="sec-num">04</span><h2>Detailed Findings</h2></div>
  <p class="lead">Per-methodology breakdown of all data collected during the engagement.</p>
"""
        for title, body in sections:
            findings_html += body
        findings_html += "</div>\n"

    # ── TOC ──────────────────────────────────────────────────────────────────
    toc_items = []
    i = 1
    if include_exec:        toc_items.append((f"{i:02d}", "Executive Summary")); i += 1
    if include_methodology: toc_items.append((f"{i:02d}", "Methodology & Scope")); i += 1
    if include_risk:        toc_items.append((f"{i:02d}", "Risk Assessment")); i += 1
    if sections:            toc_items.append((f"{i:02d}", "Detailed Findings")); i += 1
    if include_recommendations: toc_items.append((f"{i:02d}", "Recommendations")); i += 1

    toc_html = f"""
<div class="section">
  <div class="sec-head"><span class="sec-num">TOC</span><h2>Table of Contents</h2></div>
  <div class="toc">
"""
    for num, label in toc_items:
        toc_html += f"    <div class='toc-row'><span class='toc-num'>{num}</span><span class='toc-label'>{label}</span><span class='toc-dots'></span></div>\n"
    if sections:
        toc_html += "    <div class='toc-sub-head'>Findings Sections</div>\n"
        for idx, (title, _body) in enumerate(sections, 1):
            toc_html += f"    <div class='toc-row sub'><span class='toc-num'>04.{idx}</span><span class='toc-label'>{_esc(title)}</span><span class='toc-dots'></span></div>\n"
    toc_html += "  </div>\n</div>\n"

    # ── Final HTML ───────────────────────────────────────────────────────────
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_esc(operation_name)} — Security Assessment Report</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=Source+Serif+Pro:wght@400;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

:root {{
  --ink:       #0f172a;
  --ink-2:     #1e293b;
  --ink-3:     #334155;
  --muted:     #64748b;
  --muted-2:   #94a3b8;
  --border:    #e2e8f0;
  --border-2:  #cbd5e1;
  --bg:        #ffffff;
  --bg-soft:   #f8fafc;
  --bg-mute:   #f1f5f9;
  --accent:    #0f172a;
  --accent-2:  #1e40af;
  --gold:      #b08a3e;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
html {{ font-size: 13px; }}
body {{
  background: #eef2f6;
  color: var(--ink);
  font-family: 'Inter', -apple-system, sans-serif;
  line-height: 1.65;
}}
.page {{
  max-width: 920px;
  margin: 24px auto;
  background: var(--bg);
  box-shadow: 0 2px 12px rgba(15,23,42,.08);
  border: 1px solid var(--border);
  overflow: hidden;
}}
.section {{
  padding: 44px 56px;
  border-bottom: 1px solid var(--border);
}}
.section:last-child {{ border-bottom: none; }}
.sec-head {{
  display: flex;
  align-items: baseline;
  gap: 14px;
  margin-bottom: 20px;
  padding-bottom: 14px;
  border-bottom: 2px solid var(--ink);
}}
.sec-num {{
  font-family: 'Source Serif Pro', serif;
  font-size: 14px;
  font-weight: 600;
  color: var(--gold);
  letter-spacing: 2px;
}}
.sec-head h2 {{
  font-family: 'Source Serif Pro', serif;
  font-size: 24px;
  font-weight: 700;
  color: var(--ink);
  letter-spacing: -0.3px;
}}
.lead {{
  font-size: 13.5px;
  color: var(--ink-2);
  margin-bottom: 18px;
  line-height: 1.75;
}}
p {{ font-size: 13px; color: var(--ink-2); margin-bottom: 10px; }}
.muted {{ color: var(--muted); }}
.mono {{ font-family: 'JetBrains Mono', monospace; font-size: 11.5px; }}
.tc {{ text-align: center; }}

/* COVER */
.cover {{
  padding: 80px 56px 64px;
  background: linear-gradient(180deg, #ffffff 0%, #f8fafc 100%);
  border-bottom: 6px solid var(--ink);
  position: relative;
}}
.cover-top {{
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding-bottom: 40px;
  border-bottom: 1px solid var(--border);
  margin-bottom: 52px;
}}
.cover-brand {{
  display: flex;
  align-items: center;
  gap: 12px;
}}
.cover-logo {{
  width: 36px; height: 36px;
  background: var(--ink);
  border-radius: 6px;
  display: flex;
  align-items: center;
  justify-content: center;
  color: var(--gold);
  font-family: 'Source Serif Pro', serif;
  font-weight: 700;
  font-size: 20px;
}}
.cover-brand-name {{
  font-family: 'Source Serif Pro', serif;
  font-weight: 700;
  font-size: 15px;
  color: var(--ink);
  letter-spacing: -0.2px;
}}
.cover-brand-tag {{
  font-size: 10px;
  text-transform: uppercase;
  letter-spacing: 2px;
  color: var(--muted);
}}
.cover-classification {{
  padding: 6px 14px;
  background: #fee2e2;
  color: #991b1b;
  border: 1px solid #fca5a5;
  font-size: 10px;
  font-weight: 700;
  letter-spacing: 2px;
  text-transform: uppercase;
}}
.cover-label {{
  font-size: 10px;
  font-weight: 600;
  letter-spacing: 3px;
  color: var(--gold);
  text-transform: uppercase;
  margin-bottom: 14px;
}}
.cover h1 {{
  font-family: 'Source Serif Pro', serif;
  font-size: 40px;
  font-weight: 700;
  color: var(--ink);
  line-height: 1.15;
  letter-spacing: -0.8px;
  margin-bottom: 20px;
}}
.cover-target {{
  font-family: 'JetBrains Mono', monospace;
  font-size: 16px;
  color: var(--accent-2);
  padding: 10px 16px;
  background: var(--bg-mute);
  border-left: 3px solid var(--gold);
  display: inline-block;
  margin-bottom: 48px;
}}
.cover-meta {{
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 20px;
  padding-top: 36px;
  border-top: 1px solid var(--border);
}}
.cm-item .cm-label {{
  font-size: 9.5px;
  text-transform: uppercase;
  letter-spacing: 1.5px;
  color: var(--muted);
  margin-bottom: 4px;
}}
.cm-item .cm-val {{
  font-size: 13px;
  color: var(--ink);
  font-weight: 500;
}}
.cover-risk-bar {{
  margin-top: 44px;
  padding: 20px 24px;
  background: var(--ink);
  color: #fff;
  display: flex;
  align-items: center;
  gap: 24px;
}}
.cover-risk-num {{
  font-family: 'Source Serif Pro', serif;
  font-size: 48px;
  font-weight: 700;
  line-height: 1;
  color: {risk_color};
}}
.cover-risk-info {{
  flex: 1;
}}
.cover-risk-info .rl {{ font-size: 10px; letter-spacing: 2px; color: #94a3b8; text-transform: uppercase; margin-bottom: 4px; }}
.cover-risk-info .rv {{ font-size: 18px; font-weight: 600; color: #fff; }}
.cover-risk-info .rd {{ font-size: 11px; color: #94a3b8; margin-top: 4px; }}

/* TOC */
.toc {{ margin-top: 14px; }}
.toc-row {{
  display: flex;
  align-items: baseline;
  gap: 8px;
  padding: 9px 0;
  border-bottom: 1px dotted var(--border);
}}
.toc-row.sub {{ padding-left: 28px; }}
.toc-row.sub .toc-num {{ color: var(--muted); }}
.toc-num {{
  font-family: 'JetBrains Mono', monospace;
  font-size: 11px;
  color: var(--gold);
  font-weight: 600;
  min-width: 44px;
}}
.toc-label {{
  font-size: 12.5px;
  color: var(--ink-2);
}}
.toc-dots {{
  flex: 1;
  border-bottom: 1px dotted var(--border-2);
  margin-bottom: 4px;
}}
.toc-sub-head {{
  margin: 20px 0 6px;
  font-size: 10px;
  letter-spacing: 2px;
  text-transform: uppercase;
  color: var(--muted);
  font-weight: 600;
}}

/* KPIs */
.kpi-row {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 12px;
  margin-bottom: 22px;
}}
.kpi {{
  padding: 16px 18px;
  background: var(--bg-soft);
  border: 1px solid var(--border);
  border-left: 3px solid var(--gold);
}}
.kpi-v {{
  font-family: 'Source Serif Pro', serif;
  font-size: 24px;
  font-weight: 700;
  color: var(--ink);
  line-height: 1;
  margin-bottom: 4px;
}}
.kpi-l {{
  font-size: 10px;
  text-transform: uppercase;
  letter-spacing: 1.5px;
  color: var(--muted);
  font-weight: 600;
}}

/* Tables */
.tbl {{
  width: 100%;
  border-collapse: collapse;
  margin: 10px 0 18px;
  font-size: 11.5px;
}}
.tbl thead th {{
  padding: 10px 12px;
  text-align: left;
  font-size: 10px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 1.2px;
  color: var(--muted);
  background: var(--bg-soft);
  border-bottom: 2px solid var(--ink);
}}
.tbl tbody td {{
  padding: 9px 12px;
  border-bottom: 1px solid var(--border);
  color: var(--ink-2);
  vertical-align: top;
}}
.tbl tbody tr:hover td {{ background: var(--bg-soft); }}
.tbl a {{ color: var(--accent-2); text-decoration: none; }}
.tbl a:hover {{ text-decoration: underline; }}

/* Badges */
.badge {{
  display: inline-block;
  padding: 2px 8px;
  border-radius: 2px;
  font-size: 10px;
  font-weight: 700;
  letter-spacing: 0.5px;
  border: 1px solid transparent;
}}
.sev-critical {{ background:#fee2e2; color:#991b1b; border-color:#fca5a5; }}
.sev-high     {{ background:#fef3c7; color:#92400e; border-color:#fcd34d; }}
.sev-medium   {{ background:#ffedd5; color:#9a3412; border-color:#fdba74; }}
.sev-low      {{ background:#ccfbf1; color:#115e59; border-color:#5eead4; }}
.sev-info     {{ background:#e2e8f0; color:#334155; border-color:#cbd5e1; }}

/* Severity bar */
.sev-bar {{
  display: flex;
  height: 8px;
  margin: 14px 0 10px;
  background: var(--bg-mute);
  overflow: hidden;
}}
.sev-bar > div {{ height: 100%; }}
.sev-legend {{
  display: flex;
  gap: 18px;
  flex-wrap: wrap;
  font-size: 11px;
  color: var(--muted);
  margin-bottom: 18px;
}}
.sev-legend span {{ display: flex; align-items: center; gap: 6px; }}
.sev-legend i {{
  display: inline-block;
  width: 10px; height: 10px;
  border-radius: 2px;
}}
.sev-legend b {{ color: var(--ink); margin-left: 3px; }}

/* Subsections */
.subsection {{
  padding: 22px 0 8px;
  border-top: 1px solid var(--border);
  margin-top: 22px;
}}
.subsection:first-child {{ border-top: none; padding-top: 6px; margin-top: 0; }}
.ss-title {{
  font-family: 'Source Serif Pro', serif;
  font-size: 18px;
  font-weight: 700;
  color: var(--ink);
  margin-bottom: 10px;
}}
.ss-sub {{
  font-family: 'Source Serif Pro', serif;
  font-size: 14px;
  font-weight: 600;
  color: var(--ink-2);
  margin: 18px 0 8px;
  padding-top: 12px;
  border-top: 1px solid var(--border);
}}

/* Chips */
.chips {{
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  margin-bottom: 10px;
}}
.chip {{
  padding: 3px 10px;
  background: var(--bg-mute);
  color: var(--ink-2);
  border: 1px solid var(--border);
  font-size: 11px;
  border-radius: 3px;
}}
.chip.muted {{ color: var(--muted); }}
.chip b {{ color: var(--accent-2); }}

/* Box */
.box {{
  padding: 16px 20px;
  background: var(--bg-soft);
  border: 1px solid var(--border);
  border-left: 3px solid var(--gold);
  margin: 14px 0;
}}
.box h4 {{
  font-family: 'Source Serif Pro', serif;
  font-size: 13px;
  font-weight: 700;
  color: var(--ink);
  margin-bottom: 8px;
}}
.box ul {{ padding-left: 18px; }}
.box li {{
  font-size: 12px;
  color: var(--ink-2);
  margin-bottom: 6px;
  line-height: 1.65;
}}

/* Timeline */
.timeline {{
  position: relative;
  padding-left: 24px;
  margin-top: 16px;
}}
.timeline::before {{
  content: '';
  position: absolute;
  left: 6px; top: 6px; bottom: 6px;
  width: 2px;
  background: var(--border);
}}
.tl-item {{
  position: relative;
  padding-bottom: 20px;
}}
.tl-dot {{
  position: absolute;
  left: -21px; top: 6px;
  width: 11px; height: 11px;
  border-radius: 50%;
  background: var(--gold);
  border: 2px solid var(--bg);
  box-shadow: 0 0 0 1px var(--border-2);
}}
.tl-title {{
  font-family: 'Source Serif Pro', serif;
  font-weight: 700;
  font-size: 14px;
  color: var(--ink);
  margin-bottom: 3px;
}}
.tl-desc {{
  font-size: 12px;
  color: var(--muted);
  margin-bottom: 6px;
  line-height: 1.55;
}}
.tl-meta {{ display: flex; gap: 6px; flex-wrap: wrap; }}

/* Risk cards */
.risk-grid {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: 14px;
  margin-top: 14px;
}}
.risk-card {{
  padding: 16px 18px;
  background: var(--bg-soft);
  border: 1px solid var(--border);
  border-left: 4px solid var(--muted);
}}
.rc-head {{
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 8px;
}}
.rc-head h4 {{
  font-family: 'Source Serif Pro', serif;
  font-size: 13px;
  font-weight: 700;
  color: var(--ink);
}}
.risk-card p {{
  font-size: 11.5px;
  color: var(--ink-2);
  line-height: 1.6;
}}

/* Footer */
.doc-footer {{
  padding: 28px 56px;
  background: var(--ink);
  color: #94a3b8;
  font-size: 10px;
  text-align: center;
  letter-spacing: 0.4px;
}}
.doc-footer b {{ color: #fff; font-weight: 600; }}

/* Toolbar (non-printing) */
.toolbar {{
  position: fixed;
  top: 0; left: 0; right: 0;
  background: var(--ink);
  color: #fff;
  padding: 10px 24px;
  display: flex;
  align-items: center;
  gap: 14px;
  z-index: 100;
  font-size: 12px;
}}
.toolbar .tb-title {{ flex: 1; font-weight: 600; letter-spacing: 0.3px; }}
.toolbar button {{
  padding: 6px 14px;
  font-size: 11.5px;
  font-weight: 600;
  border: 1px solid rgba(255,255,255,.15);
  background: transparent;
  color: #fff;
  cursor: pointer;
  font-family: inherit;
  letter-spacing: 0.3px;
  border-radius: 2px;
}}
.toolbar button.primary {{
  background: var(--gold);
  color: var(--ink);
  border-color: var(--gold);
}}
.toolbar button:hover {{ background: rgba(255,255,255,.1); }}
.toolbar button.primary:hover {{ background: #c09544; }}
body {{ padding-top: 44px; }}

@media print {{
  body {{ padding-top: 0; background: #fff; }}
  .page {{ box-shadow: none; margin: 0; max-width: 100%; border: none; }}
  .toolbar, .no-print {{ display: none !important; }}
  .page-break {{ page-break-before: always; }}
  .section {{ padding: 32px 42px; }}
  .kpi, .box, .risk-card {{ break-inside: avoid; }}
  .tbl {{ break-inside: auto; }}
  .tbl tr {{ break-inside: avoid; }}
}}
</style>
</head>
<body>

<div class="toolbar no-print">
  <span class="tb-title">{_esc(company)} &nbsp;·&nbsp; {_esc(operation_name)}</span>
  <button onclick="window.print()" class="primary">Print / Save PDF</button>
  <button onclick="window.close()">Close</button>
</div>

<div class="page">

  <!-- COVER -->
  <div class="cover">
    <div class="cover-top">
      <div class="cover-brand">
        <div class="cover-logo">Z</div>
        <div>
          <div class="cover-brand-name">{_esc(company)}</div>
          <div class="cover-brand-tag">Security Intelligence Platform</div>
        </div>
      </div>
      <div class="cover-classification">{_esc(classification)}</div>
    </div>

    <div class="cover-label">Security Assessment Report</div>
    <h1>{_esc(operation_name)}</h1>
    <div class="cover-target">{_esc(primary_target)}</div>

    <div class="cover-meta">
      <div class="cm-item">
        <div class="cm-label">Report Date</div>
        <div class="cm-val">{date_short}</div>
      </div>
      <div class="cm-item">
        <div class="cm-label">Prepared By</div>
        <div class="cm-val">{_esc(analyst)}</div>
      </div>
      <div class="cm-item">
        <div class="cm-label">Sessions Analyzed</div>
        <div class="cm-val">{len(sessions)}</div>
      </div>
      <div class="cm-item">
        <div class="cm-label">Methodologies</div>
        <div class="cm-val">{len(by_type)}</div>
      </div>
    </div>

    <div class="cover-risk-bar">
      <div class="cover-risk-num">{risk}</div>
      <div class="cover-risk-info">
        <div class="rl">Overall Risk Rating</div>
        <div class="rv">{risk_label}</div>
        <div class="rd">Composite score across all methodologies · scale 0–100</div>
      </div>
    </div>
  </div>

  {toc_html}
  {exec_html}
  {meth_html}
  {risk_html}
  {findings_html}
  {rec_html}

  <div class="doc-footer">
    <div style="margin-bottom:8px"><b>{_esc(company)}</b> &nbsp;·&nbsp; {_esc(operation_name)} &nbsp;·&nbsp; {date_short}</div>
    <div>Generated on {now} &nbsp;·&nbsp; Prepared by {_esc(analyst)}</div>
    <div style="margin-top:10px;font-size:9px;color:#64748b;letter-spacing:0.5px">
      {_esc(classification)} · Distribution restricted to authorized personnel only.
    </div>
  </div>

</div>

</body>
</html>"""

    return html
