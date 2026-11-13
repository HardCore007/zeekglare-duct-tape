"""Export service — CSV, JSON, HTML, PDF report generation."""
import csv, json, io, pathlib
from datetime import datetime
from fpdf import FPDF
from html import escape as _html_escape
from core.session_manager import SessionManager


# ── JSON ──────────────────────────────────────────────────────────────────────

def export_json(session_id: str) -> bytes:
    s = SessionManager.get(session_id)
    if not s:
        raise ValueError("Session not found")
    return json.dumps(s, indent=2, default=str).encode()


# ── CSV ───────────────────────────────────────────────────────────────────────

def export_csv(session_id: str) -> bytes:
    s = SessionManager.get(session_id)
    if not s:
        raise ValueError("Session not found")

    buf = io.StringIO()
    stype = s.get("type", "")

    if stype == "asn":
        CAT_LABELS = {
            'other': 'General / Other', 'government': 'Government',
            'military': 'Military', 'education': 'Education',
            'finance': 'Finance', 'telecom': 'Telecom',
            'grid_station': 'Grid Station', 'critical_infra': 'Critical Infra',
            'healthcare': 'Healthcare', 'cloud': 'Cloud',
            'hosting': 'Hosting', 'vpn': 'VPN', 'isp': 'ISP',
            'commercial': 'Commercial',
        }
        writer = csv.DictWriter(buf, fieldnames=[
            "asn", "name", "asn_category", "country", "rir",
            "caida_rank", "caida_org", "website", "description",
            "entry_type", "entry_category", "value",
        ])
        writer.writeheader()
        for a in s.get("data", {}).get("asn_data", []):
            cat_raw = a.get("asn_category") or a.get("category") or ""
            base = {
                "asn":          f"AS{a.get('asn', '')}",
                "name":         a.get("name", ""),
                "asn_category": CAT_LABELS.get(cat_raw, cat_raw.title() if cat_raw else ""),
                "country":      a.get("country", ""),
                "rir":          a.get("rir", ""),
                "caida_rank":   a.get("caida_rank", ""),
                "caida_org":    a.get("caida_org", ""),
                "website":      a.get("website", ""),
                "description":  a.get("description", ""),
            }
            # Prefixes
            for p in a.get("prefixes_v4", []):
                writer.writerow({**base, "entry_type": "Prefix", "entry_category": "", "value": p})
            # Domains by category
            classified = a.get("critical") or a.get("classified") or {}
            classified_set = set()
            for dcat, doms in sorted(classified.items(), key=lambda x: (x[0] == 'other', x[0])):
                for d in (doms or []):
                    classified_set.add(d)
                    writer.writerow({
                        **base,
                        "entry_type": "Domain",
                        "entry_category": CAT_LABELS.get(dcat, dcat.title() if dcat else ""),
                        "value": d,
                    })
            # Uncategorized domains
            for d in a.get("domains", []):
                if d not in classified_set:
                    writer.writerow({**base, "entry_type": "Domain", "entry_category": "Uncategorized", "value": d})
            # If no prefixes/domains, still include one summary row
            if not a.get("prefixes_v4") and not classified and not a.get("domains"):
                writer.writerow({**base, "entry_type": "", "entry_category": "", "value": ""})

    elif stype == "domain":
        writer = csv.DictWriter(buf, fieldnames=[
            "domain", "ip", "http_status", "http_live", "score",
            "tech", "waf", "cms", "cloud", "asn", "holder",
        ])
        writer.writeheader()
        for e in s.get("data", {}).get("entries", []):
            writer.writerow({
                "domain":      e.get("domain", ""),
                "ip":          e.get("ip", ""),
                "http_status": e.get("http_status", ""),
                "http_live":   e.get("http_live", False),
                "score":       e.get("score", 0),
                "tech":        "|".join(e.get("tech", [])),
                "waf":         e.get("waf", ""),
                "cms":         e.get("cms", ""),
                "cloud":       e.get("cloud", ""),
                "asn":         e.get("asn", ""),
                "holder":      e.get("holder", ""),
            })

    elif stype == "recon":
        writer = csv.DictWriter(buf, fieldnames=["type", "value"])
        writer.writeheader()
        data = s.get("data", {})
        for sub in data.get("subdomains", []):
            writer.writerow({"type": "subdomain", "value": sub})
        for url in data.get("urls", []):
            writer.writerow({"type": "url", "value": url})
        for vuln in data.get("vulnerabilities", []):
            writer.writerow({"type": "vulnerability", "value": vuln})

    return buf.getvalue().encode()


# ── HTML ──────────────────────────────────────────────────────────────────────

def export_html(session_id: str) -> bytes:
    s = SessionManager.get(session_id)
    if not s:
        raise ValueError("Session not found")

    stype  = s.get("type", "")
    target = s.get("target", "")
    name   = s.get("name", target)
    date   = datetime.fromtimestamp(s.get("created_at", 0)).strftime("%Y-%m-%d %H:%M")
    data   = s.get("data", {})
    sum_   = s.get("summary", {})

    rows_html = ""
    if stype == "asn":
        CAT_LABELS = {
            'other': 'General / Other', 'government': 'Government',
            'military': 'Military', 'education': 'Education',
            'finance': 'Finance', 'telecom': 'Telecom',
            'grid_station': 'Grid Station', 'critical_infra': 'Critical Infra',
            'healthcare': 'Healthcare', 'cloud': 'Cloud',
            'hosting': 'Hosting', 'vpn': 'VPN', 'isp': 'ISP',
            'commercial': 'Commercial',
        }
        CAT_COLORS = {
            'government': '#ef4444', 'military': '#dc2626', 'education': '#f59e0b',
            'finance': '#10b981', 'telecom': '#6366f1', 'grid_station': '#f97316',
            'critical_infra': '#ec4899', 'healthcare': '#14b8a6', 'cloud': '#3b82f6',
            'hosting': '#8b5cf6', 'vpn': '#a855f7', 'isp': '#06b6d4',
            'other': '#64748b', 'commercial': '#64748b',
        }
        blocks = ""
        for a in data.get("asn_data", []):
            cat_raw = a.get("asn_category") or a.get("category") or ""
            cat_label = CAT_LABELS.get(cat_raw, cat_raw.title() if cat_raw else "")
            cat_color = CAT_COLORS.get(cat_raw, "#64748b")
            crit = ' style="border-left:3px solid #ef4444"' if a.get("is_critical") else ""

            # Meta info
            meta_items = [
                ("ASN", f"AS{a.get('asn','')}"),
                ("Name", a.get("name", "")),
                ("Category", cat_label),
                ("Country", a.get("country", "")),
                ("RIR", a.get("rir", "")),
            ]
            if a.get("caida_rank") is not None:
                meta_items.append(("CAIDA Rank", f"#{a.get('caida_rank')}"))
            if a.get("caida_org"):
                meta_items.append(("CAIDA Org", a.get("caida_org")))
            if a.get("website"):
                meta_items.append(("Website", a.get("website")))
            meta_html = "".join(f'<div class="meta-item"><label>{_html_escape(k)}</label><p>{_html_escape(str(v))}</p></div>' for k, v in meta_items)

            # Prefixes
            pfx_list = a.get("prefixes_v4", [])
            pfx_html = ""
            if pfx_list:
                pfx_tags = "".join(f'<span style="display:inline-block;background:#0f162c;border:1px solid #273a62;border-radius:4px;padding:2px 8px;margin:2px;font-size:12px;font-family:monospace">{_html_escape(str(p))}</span>' for p in pfx_list)
                pfx_html = f'<div style="margin:8px 0"><h4 style="color:#818cf8;font-size:13px">Prefixes / CIDRs ({len(pfx_list)})</h4>{pfx_tags}</div>'

            # Domains by category
            classified = a.get("critical") or a.get("classified") or {}
            dom_sections = ""
            classified_set = set()
            for dcat, doms in sorted(classified.items(), key=lambda x: (x[0] == 'other', x[0])):
                if not doms:
                    continue
                for d in doms:
                    classified_set.add(d)
                dc = CAT_COLORS.get(dcat, "#64748b")
                dl = CAT_LABELS.get(dcat, dcat.title() if dcat else "")
                dom_tags = "".join(f'<div style="font-size:12px;padding:2px 0;color:#e2e8f8;font-family:monospace">{_html_escape(str(d))}</div>' for d in doms)
                dom_sections += f'<div style="margin:6px 0"><h4 style="color:{dc};font-size:12px;display:flex;align-items:center;gap:6px"><span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:{dc}"></span>{_html_escape(dl)} ({len(doms)})</h4>{dom_tags}</div>'

            # Uncategorized domains
            uncl = [d for d in a.get("domains", []) if d not in classified_set]
            if uncl:
                dom_tags = "".join(f'<div style="font-size:12px;padding:2px 0;color:#e2e8f8;font-family:monospace">{_html_escape(str(d))}</div>' for d in uncl)
                dom_sections += f'<div style="margin:6px 0"><h4 style="color:#64748b;font-size:12px">Uncategorized ({len(uncl)})</h4>{dom_tags}</div>'

            if dom_sections:
                dom_sections = f'<div style="margin:8px 0"><h4 style="color:#818cf8;font-size:13px">Domains</h4>{dom_sections}</div>'

            desc_html = ""
            if a.get("description"):
                desc_html = f'<div style="margin:8px 0;font-size:12px;color:#8ea4c8">{_html_escape(str(a["description"]))}</div>'

            blocks += f"""
            <div style="background:#0b1022;border:1px solid #1d2b4c;border-radius:8px;padding:16px;margin:12px 0"{crit}>
              <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
                <span style="font-size:16px;font-weight:700;color:#e2e8f8">AS{_html_escape(str(a.get('asn','')))}</span>
                <span style="font-size:14px;color:#8ea4c8">— {_html_escape(str(a.get('name','')))}</span>
                <span style="background:{cat_color}22;color:{cat_color};border:1px solid {cat_color}44;padding:2px 8px;border-radius:4px;font-size:11px">{_html_escape(cat_label)}</span>
              </div>
              <div class="meta">{meta_html}</div>
              {desc_html}{pfx_html}{dom_sections}
            </div>"""

        rows_html = blocks

    elif stype == "domain":
        return _export_domain_interactive(s, name, date, target, data, sum_)

    elif stype == "recon":
        subs_html = "".join(f"<li>{_html_escape(str(sub))}</li>" for sub in data.get("subdomains", [])[:200])
        vulns_html = "".join(f"<li style='color:red'>{_html_escape(str(v))}</li>" for v in data.get("vulnerabilities", [])[:100])
        rows_html = f"<h3>Subdomains ({len(data.get('subdomains',[]))})</h3><ul>{subs_html}</ul><h3>Vulnerabilities ({len(data.get('vulnerabilities',[]))})</h3><ul>{vulns_html}</ul>"

    name_e = _html_escape(name)
    target_e = _html_escape(target)
    stype_e = _html_escape(stype)
    date_e = _html_escape(date)
    html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<title>ZeekGlare Report — {name_e}</title>
<style>
  body{{font-family:Arial,sans-serif;background:#0a0f1e;color:#e2e8f8;margin:0;padding:20px}}
  h1{{color:#6366f1;border-bottom:2px solid #6366f1;padding-bottom:10px}}
  h2{{color:#14b8a6;margin-top:24px}}
  h3{{color:#818cf8}}
  table{{width:100%;border-collapse:collapse;margin:12px 0;font-size:13px}}
  th{{background:#1d2b4c;color:#8ea4c8;padding:8px 12px;text-align:left;border-bottom:2px solid #273a62}}
  td{{padding:7px 12px;border-bottom:1px solid #1d2b4c;color:#e2e8f8}}
  tr:hover td{{background:#0f162c}}
  .meta{{background:#0b1022;border:1px solid #1d2b4c;border-radius:8px;padding:16px;margin:16px 0;display:grid;grid-template-columns:repeat(3,1fr);gap:12px}}
  .meta-item label{{font-size:11px;color:#4a6088;text-transform:uppercase;letter-spacing:.5px}}
  .meta-item p{{font-size:16px;font-weight:600;margin:4px 0 0;color:#e2e8f8}}
  ul{{padding-left:20px;line-height:1.8;font-size:13px}}
  .footer{{margin-top:40px;color:#4a6088;font-size:12px;border-top:1px solid #1d2b4c;padding-top:12px}}
</style></head><body>
<h1>ZeekGlare Intelligence Report</h1>
<p style="color:#4a6088">Generated: {date_e} | Type: {stype_e.upper()} | Target: <b style="color:#e2e8f8">{target_e}</b></p>
<h2>Executive Summary</h2>
<div class="meta">
  {"".join(f'<div class="meta-item"><label>{_html_escape(k.replace("_"," ").title())}</label><p>{_html_escape(str(v))}</p></div>' for k,v in sum_.items() if not isinstance(v, (dict, list)))}
</div>
<h2>Results</h2>
{rows_html}
<div class="footer">ZeekGlare Intelligence Platform &mdash; Authorized Use Only</div>
</body></html>"""
    return html.encode()


# ── PDF ───────────────────────────────────────────────────────────────────────

def export_pdf(session_id: str) -> bytes:
    s = SessionManager.get(session_id)
    if not s:
        raise ValueError("Session not found")

    stype  = s.get("type", "")
    target = s.get("target", "")
    name   = s.get("name", target)
    date   = datetime.fromtimestamp(s.get("created_at", 0)).strftime("%Y-%m-%d %H:%M")
    data   = s.get("data", {})
    sum_   = s.get("summary", {})

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # Header
    pdf.set_fill_color(30, 43, 76)
    pdf.rect(0, 0, 210, 40, "F")
    pdf.set_font("Helvetica", "B", 20)
    pdf.set_text_color(99, 102, 241)
    pdf.cell(0, 15, "ZeekGlare Intelligence Report", ln=True, align="C")
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(142, 164, 200)
    pdf.cell(0, 8, f"Target: {target}  |  Type: {stype.upper()}  |  {date}", ln=True, align="C")
    pdf.ln(8)

    # Summary
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(20, 184, 166)
    pdf.cell(0, 8, "Executive Summary", ln=True)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(30, 30, 30)
    for k, v in sum_.items():
        if not isinstance(v, (dict, list)):
            pdf.cell(0, 6, f"  {k.replace('_', ' ').title()}: {v}", ln=True)
    pdf.ln(6)

    # Data table
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(20, 184, 166)
    pdf.cell(0, 8, "Findings", ln=True)
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(30, 30, 30)

    if stype == "asn":
        CAT_LABELS = {
            'other': 'General / Other', 'government': 'Government',
            'military': 'Military', 'education': 'Education',
            'finance': 'Finance', 'telecom': 'Telecom',
            'grid_station': 'Grid Station', 'critical_infra': 'Critical Infra',
            'healthcare': 'Healthcare', 'cloud': 'Cloud',
            'hosting': 'Hosting', 'vpn': 'VPN', 'isp': 'ISP',
            'commercial': 'Commercial',
        }
        for a in data.get("asn_data", []):
            cat_raw = a.get("asn_category") or a.get("category") or ""
            cat_label = CAT_LABELS.get(cat_raw, cat_raw.title() if cat_raw else "")

            pdf.set_font("Helvetica", "B", 11)
            pdf.set_text_color(99, 102, 241)
            pdf.cell(0, 7, f"AS{a.get('asn','')} - {a.get('name','')[:50]} [{cat_label}]", ln=True)

            pdf.set_font("Helvetica", "", 8)
            pdf.set_text_color(80, 80, 80)
            meta_parts = [f"Country: {a.get('country','')}", f"RIR: {a.get('rir','')}"]
            if a.get("caida_rank") is not None:
                meta_parts.append(f"CAIDA Rank: #{a['caida_rank']}")
            if a.get("website"):
                meta_parts.append(f"Web: {a['website'][:40]}")
            pdf.cell(0, 4, " | ".join(meta_parts), ln=True)

            # Prefixes
            pfx = a.get("prefixes_v4", [])
            if pfx:
                pdf.set_font("Helvetica", "B", 9)
                pdf.set_text_color(30, 30, 30)
                pdf.cell(0, 5, f"  Prefixes ({len(pfx)}):", ln=True)
                pdf.set_font("Helvetica", "", 8)
                for p in pfx:
                    pdf.cell(0, 4, f"    {p}", ln=True)

            # Domains by category
            classified = a.get("critical") or a.get("classified") or {}
            classified_set = set()
            for dcat, doms in sorted(classified.items(), key=lambda x: (x[0] == 'other', x[0])):
                if not doms:
                    continue
                for d in doms:
                    classified_set.add(d)
                dl = CAT_LABELS.get(dcat, dcat.title() if dcat else "")
                pdf.set_font("Helvetica", "B", 9)
                pdf.set_text_color(30, 30, 30)
                pdf.cell(0, 5, f"  {dl} ({len(doms)}):", ln=True)
                pdf.set_font("Helvetica", "", 8)
                for d in doms[:100]:
                    pdf.cell(0, 4, f"    {d[:80]}", ln=True)

            uncl = [d for d in a.get("domains", []) if d not in classified_set]
            if uncl:
                pdf.set_font("Helvetica", "B", 9)
                pdf.set_text_color(30, 30, 30)
                pdf.cell(0, 5, f"  Uncategorized ({len(uncl)}):", ln=True)
                pdf.set_font("Helvetica", "", 8)
                for d in uncl[:100]:
                    pdf.cell(0, 4, f"    {d[:80]}", ln=True)

            pdf.ln(3)

    elif stype == "domain":
        entries = sorted(data.get("entries", []), key=lambda x: -x.get("score", 0))
        for e in entries[:80]:
            live = "LIVE" if e.get("http_live") else "down"
            line = f"[{e.get('score',0):3d}] {e.get('domain','')[:40]} | {live} | {e.get('ip','')} | WAF:{e.get('waf','—')}"
            pdf.cell(0, 5, line[:110], ln=True)

    elif stype == "recon":
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(0, 6, f"Subdomains ({len(data.get('subdomains',[]))})", ln=True)
        pdf.set_font("Helvetica", "", 9)
        for s_ in data.get("subdomains", [])[:100]:
            pdf.cell(0, 5, f"  {s_[:100]}", ln=True)
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(200, 30, 30)
        pdf.cell(0, 6, f"Vulnerabilities ({len(data.get('vulnerabilities',[]))})", ln=True)
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(150, 20, 20)
        for v in data.get("vulnerabilities", [])[:50]:
            pdf.cell(0, 5, f"  {v[:100]}", ln=True)

    # Footer
    pdf.set_y(-20)
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(150, 150, 150)
    pdf.cell(0, 6, "ZeekGlare Intelligence Platform — Authorized Security Use Only", align="C")

    return pdf.output()


# ── Interactive Domain Report ────────────────────────────────────────────────

def _esc(s):
    """HTML-escape a string."""
    return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace('"',"&quot;")

def _export_domain_interactive(s, name, date, target, data, sum_):
    """Generate a fully interactive domain mapping report with all data."""
    import html as _html
    entries = sorted(data.get("entries", []), key=lambda x: -x.get("score", 0))
    asn_groups = data.get("asn_groups", {})
    top_targets = data.get("top_targets", [])

    total = len(entries)
    live = sum(1 for e in entries if e.get("http_live"))
    dead = total - live
    unique_ips = len({e.get("ip") for e in entries if e.get("ip")})
    unique_asns = len({str(e.get("asn","")) for e in entries if e.get("asn")})

    # Tech/WAF/CMS aggregation
    tech_map, waf_map, cms_map = {}, {}, {}
    status_map = {"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, "none": 0}
    for e in entries:
        for t in e.get("tech", []):
            tech_map[t] = tech_map.get(t, 0) + 1
        for t in e.get("whatweb", []):
            tech_map[t] = tech_map.get(t, 0) + 1
        w = e.get("waf", "")
        if w:
            waf_map[w] = waf_map.get(w, 0) + 1
        c = e.get("cms", "")
        if c:
            cms_map[c] = cms_map.get(c, 0) + 1
        st = str(e.get("http_status", "") or "")
        if st.startswith("2"):
            status_map["2xx"] += 1
        elif st.startswith("3"):
            status_map["3xx"] += 1
        elif st.startswith("4"):
            status_map["4xx"] += 1
        elif st.startswith("5"):
            status_map["5xx"] += 1
        else:
            status_map["none"] += 1

    tech_sorted = sorted(tech_map.items(), key=lambda x: -x[1])[:30]
    waf_sorted = sorted(waf_map.items(), key=lambda x: -x[1])
    cms_sorted = sorted(cms_map.items(), key=lambda x: -x[1])

    # ASN breakdown HTML
    asn_blocks = ""
    asn_sorted = sorted(asn_groups.values(), key=lambda x: -x.get("count", 0))
    for ag in asn_sorted[:30]:
        doms_preview = ", ".join(ag.get("domains", [])[:5])
        more = len(ag.get("domains", [])) - 5
        more_txt = f" +{more} more" if more > 0 else ""
        asn_blocks += f'<div class="asn-row"><span class="asn-label">{_esc(ag.get("asn",""))}</span><span class="asn-holder">{_esc(ag.get("holder",""))}</span><span class="asn-count">{ag.get("count",0)}</span><div class="asn-doms">{_esc(doms_preview)}{_esc(more_txt)}</div></div>'

    # Top targets HTML
    top_html = ""
    for t in (top_targets or [])[:15]:
        score = t.get("score", 0)
        sclass = "score-high" if score >= 70 else "score-med" if score >= 40 else "score-low"
        tech_tags = "".join(f'<span class="tag tech-tag">{_esc(x)}</span>' for x in (t.get("tech", []) or [])[:4])
        waf_tag = f'<span class="tag waf-tag">{_esc(t.get("waf",""))}</span>' if t.get("waf") else ""
        cms_tag = f'<span class="tag cms-tag">{_esc(t.get("cms",""))}</span>' if t.get("cms") else ""
        top_html += f'''<div class="top-row">
          <span class="top-score {sclass}">{score}</span>
          <a href="{_esc(t.get("http_url","") or "https://"+t.get("domain",""))}" target="_blank" class="top-domain">{_esc(t.get("domain",""))}</a>
          <span class="top-ip">{_esc(t.get("ip",""))}</span>
          <div class="top-tags">{tech_tags}{waf_tag}{cms_tag}</div>
        </div>'''

    # Build all entries table rows
    all_rows = ""
    for e in entries:
        live_cls = "live-yes" if e.get("http_live") else "live-no"
        live_txt = "LIVE" if e.get("http_live") else "DOWN"
        score = e.get("score", 0)
        sclass = "score-high" if score >= 70 else "score-med" if score >= 40 else "score-low"
        st = str(e.get("http_status", "") or "—")
        tech_list = (e.get("tech", []) or []) + (e.get("whatweb", []) or [])
        tech_tags = "".join(f'<span class="tag tech-tag">{_esc(t)}</span>' for t in tech_list[:6])
        if len(tech_list) > 6:
            tech_tags += f'<span class="tag more-tag">+{len(tech_list)-6}</span>'
        waf_tag = f'<span class="tag waf-tag">WAF: {_esc(e.get("waf",""))}</span>' if e.get("waf") else ""
        cms_tag = f'<span class="tag cms-tag">{_esc(e.get("cms",""))}</span>' if e.get("cms") else ""
        cloud_tag = f'<span class="tag cloud-tag">{_esc(e.get("cloud",""))}</span>' if e.get("cloud") else ""
        server_tag = f'<span class="tag server-tag">{_esc(e.get("ww_server",""))}</span>' if e.get("ww_server") else ""
        title_txt = _esc(e.get("title", "") or "")
        mh = e.get("missing_headers", []) or []
        mh_html = "".join(f'<span class="tag mh-tag">{_esc(h)}</span>' for h in mh) if mh else ""

        all_rows += f'''<tr class="entry-row" data-domain="{_esc(e.get("domain",""))}" data-asn="{_esc(str(e.get("asn","") or ""))}" data-live="{1 if e.get("http_live") else 0}" data-score="{score}" data-status="{st}" data-tech="{_esc(" ".join(tech_list).lower())}">
          <td><span class="score-badge {sclass}">{score}</span></td>
          <td><span class="{live_cls}">{live_txt}</span></td>
          <td><a href="{_esc(e.get("http_url","") or "https://"+e.get("domain",""))}" target="_blank" class="domain-link">{_esc(e.get("domain",""))}</a>{f'<div class="title-text">{title_txt}</div>' if title_txt else ""}</td>
          <td class="status-cell">{st}</td>
          <td class="ip-cell">{_esc(e.get("ip","") or "—")}</td>
          <td class="org-cell">{_esc(e.get("holder","") or "—")}<div class="asn-small">ASN: {_esc(str(e.get("asn","") or "—"))}</div></td>
          <td class="tech-cell">{tech_tags}{waf_tag}{cms_tag}{cloud_tag}{server_tag}</td>
          <td class="mh-cell">{mh_html}</td>
        </tr>'''

    # Tech chart data for JS
    tech_chart_data = json.dumps([{"name": k, "count": v} for k, v in tech_sorted])
    waf_chart_data = json.dumps([{"name": k, "count": v} for k, v in waf_sorted])

    html = f'''<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ZeekGlare Domain Report — {_esc(target)}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0a0f1e;color:#c8d6e5;line-height:1.5}}
a{{color:#818cf8;text-decoration:none}}a:hover{{text-decoration:underline;color:#a5b4fc}}

/* Print */
@media print{{
  body{{background:#fff;color:#1a1a2e;-webkit-print-color-adjust:exact;print-color-adjust:exact}}
  .no-print,.print-bar{{display:none!important}}
  .card{{background:#f8f9fa!important;border-color:#dee2e6!important}}
  .score-badge,.tag{{print-color-adjust:exact;-webkit-print-color-adjust:exact}}
  a{{color:#4338ca}}
}}

/* Layout */
.print-bar{{position:sticky;top:0;z-index:100;background:#0d1329;border-bottom:1px solid #1e2d4a;padding:10px 24px;display:flex;align-items:center;gap:12px}}
.print-bar button{{padding:8px 18px;border-radius:8px;font-size:12px;font-weight:600;cursor:pointer;border:none}}
.print-bar .btn-print{{background:linear-gradient(135deg,#6366f1,#8b5cf6);color:#fff}}
.print-bar .btn-close{{background:transparent;border:1px solid #374151;color:#9ca3af}}
.container{{max-width:1400px;margin:0 auto;padding:24px}}

/* Header */
.header{{background:linear-gradient(135deg,#0d1b3e 0%,#162044 50%,#1a1040 100%);border:1px solid #1e2d4a;border-radius:16px;padding:32px;margin-bottom:24px}}
.header h1{{font-size:22px;font-weight:800;color:#e2e8f0;margin-bottom:4px}}
.header .subtitle{{font-size:13px;color:#64748b}}
.header .target-badge{{display:inline-block;background:#6366f122;color:#818cf8;border:1px solid #6366f144;padding:4px 14px;border-radius:8px;font-size:14px;font-weight:600;margin-top:8px}}

/* Stats grid */
.stats-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:24px}}
.stat-card{{background:#0d1329;border:1px solid #1e2d4a;border-radius:12px;padding:16px;text-align:center}}
.stat-val{{font-size:28px;font-weight:800}}
.stat-label{{font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:.5px;margin-top:2px}}

/* Sections */
.section{{background:#0d1329;border:1px solid #1e2d4a;border-radius:12px;margin-bottom:20px;overflow:hidden}}
.section-header{{padding:16px 20px;border-bottom:1px solid #1e2d4a;display:flex;align-items:center;gap:10px;cursor:pointer;user-select:none}}
.section-header:hover{{background:#111b36}}
.section-header h2{{font-size:14px;font-weight:700;color:#e2e8f0;flex:1}}
.section-header .count{{font-size:11px;padding:2px 10px;border-radius:10px;background:#1e2d4a;color:#94a3b8}}
.section-header .chevron{{transition:transform .2s;color:#64748b}}
.section-header.collapsed .chevron{{transform:rotate(-90deg)}}
.section-body{{padding:0}}
.section-body.hidden{{display:none}}

/* Filter bar */
.filter-bar{{padding:12px 20px;border-bottom:1px solid #1e2d4a;display:flex;gap:10px;flex-wrap:wrap;align-items:center}}
.filter-bar input,.filter-bar select{{padding:6px 12px;border-radius:6px;border:1px solid #1e2d4a;background:#0a0f1e;color:#c8d6e5;font-size:12px;outline:none}}
.filter-bar input:focus,.filter-bar select:focus{{border-color:#6366f1}}
.filter-bar input{{flex:1;min-width:200px}}
.filter-count{{font-size:11px;color:#64748b;margin-left:auto}}

/* Table */
.data-table{{width:100%;border-collapse:collapse;font-size:12px}}
.data-table th{{background:#111b36;color:#64748b;padding:10px 14px;text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.5px;position:sticky;top:0;cursor:pointer;user-select:none;white-space:nowrap}}
.data-table th:hover{{color:#94a3b8;background:#162044}}
.data-table th.sorted{{color:#818cf8}}
.data-table td{{padding:8px 14px;border-bottom:1px solid #111b36;vertical-align:top}}
.data-table tr:hover td{{background:#0f1a32}}

/* Score */
.score-badge{{display:inline-block;padding:2px 10px;border-radius:6px;font-weight:700;font-size:12px;min-width:32px;text-align:center}}
.score-high{{background:#ef444422;color:#f87171;border:1px solid #ef444444}}
.score-med{{background:#f59e0b22;color:#fbbf24;border:1px solid #f59e0b44}}
.score-low{{background:#22c55e22;color:#4ade80;border:1px solid #22c55e44}}

/* Live */
.live-yes{{color:#22c55e;font-weight:600;font-size:11px}}.live-no{{color:#475569;font-size:11px}}
.domain-link{{color:#818cf8;font-weight:500;font-size:12px}}
.title-text{{font-size:10px;color:#475569;margin-top:2px;max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.ip-cell{{font-family:monospace;font-size:11px;color:#94a3b8}}
.org-cell{{font-size:11px;color:#94a3b8;max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.asn-small{{font-size:9px;color:#475569}}
.status-cell{{font-family:monospace;font-size:11px}}

/* Tags */
.tag{{display:inline-block;padding:1px 7px;border-radius:4px;font-size:10px;margin:1px;font-weight:500;white-space:nowrap}}
.tech-tag{{background:#6366f118;color:#818cf8;border:1px solid #6366f130}}
.waf-tag{{background:#ef444418;color:#f87171;border:1px solid #ef444430}}
.cms-tag{{background:#14b8a618;color:#2dd4bf;border:1px solid #14b8a630}}
.cloud-tag{{background:#3b82f618;color:#60a5fa;border:1px solid #3b82f630}}
.server-tag{{background:#f59e0b18;color:#fbbf24;border:1px solid #f59e0b30}}
.more-tag{{background:#1e2d4a;color:#64748b;border:1px solid #2d3b55}}
.mh-tag{{background:#ef444410;color:#f8717180;border:1px solid #ef444420;font-size:9px}}
.tech-cell{{max-width:300px}}
.mh-cell{{max-width:200px}}

/* ASN breakdown */
.asn-row{{display:flex;align-items:center;gap:10px;padding:8px 20px;border-bottom:1px solid #111b36}}
.asn-row:last-child{{border-bottom:none}}
.asn-row:hover{{background:#0f1a32}}
.asn-label{{font-family:monospace;font-weight:700;color:#818cf8;min-width:80px}}
.asn-holder{{font-size:12px;color:#94a3b8;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.asn-count{{background:#1e2d4a;color:#94a3b8;padding:2px 10px;border-radius:10px;font-size:11px;font-weight:600}}
.asn-doms{{font-size:10px;color:#475569;margin-top:2px;display:none}}

/* Top targets */
.top-row{{display:flex;align-items:center;gap:10px;padding:10px 20px;border-bottom:1px solid #111b36}}
.top-row:last-child{{border-bottom:none}}
.top-row:hover{{background:#0f1a32}}
.top-score{{min-width:36px;text-align:center;font-weight:800;font-size:14px;padding:4px 8px;border-radius:6px}}
.top-domain{{font-weight:600;font-size:13px;flex:1}}
.top-ip{{font-family:monospace;font-size:11px;color:#64748b}}
.top-tags{{display:flex;gap:3px;flex-wrap:wrap}}

/* Tech distribution */
.tech-dist{{padding:20px}}
.tech-bar-row{{display:flex;align-items:center;gap:8px;margin-bottom:6px}}
.tech-bar-label{{min-width:140px;font-size:11px;color:#94a3b8;text-align:right;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.tech-bar-wrap{{flex:1;height:20px;background:#111b36;border-radius:4px;overflow:hidden}}
.tech-bar{{height:100%;background:linear-gradient(90deg,#6366f1,#818cf8);border-radius:4px;transition:width .3s;min-width:2px}}
.tech-bar-count{{min-width:30px;font-size:11px;color:#64748b;font-weight:600}}

/* Status dist */
.status-grid{{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;padding:20px}}
.status-card{{text-align:center;padding:12px;border-radius:8px;background:#111b36}}
.status-card .sv{{font-size:22px;font-weight:800}}.status-card .sl{{font-size:10px;color:#64748b;margin-top:2px}}

/* WAF / CMS cards */
.waf-cms-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:10px;padding:20px}}
.wc-card{{background:#111b36;border-radius:8px;padding:12px;display:flex;align-items:center;gap:10px}}
.wc-card .wc-name{{font-size:12px;color:#e2e8f0;flex:1}}.wc-card .wc-count{{font-size:18px;font-weight:700;color:#818cf8}}

/* Footer */
.footer{{text-align:center;color:#374151;font-size:11px;padding:24px;border-top:1px solid #111b36;margin-top:20px}}

/* Nav tabs */
.nav-tabs{{display:flex;gap:2px;padding:0 20px;background:#0a0f1e;border-bottom:1px solid #1e2d4a;overflow-x:auto}}
.nav-tab{{padding:10px 16px;font-size:12px;font-weight:600;color:#64748b;cursor:pointer;border-bottom:2px solid transparent;white-space:nowrap;transition:all .15s}}
.nav-tab:hover{{color:#94a3b8}}.nav-tab.active{{color:#818cf8;border-bottom-color:#818cf8}}
.tab-panel{{display:none}}.tab-panel.active{{display:block}}
</style></head><body>

<div class="print-bar no-print">
  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#818cf8" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
  <span style="font-size:14px;font-weight:700;color:#e2e8f0">ZeekGlare Domain Intelligence Report</span>
  <span style="font-size:11px;color:#64748b;margin-left:8px">{_esc(target)}</span>
  <div style="flex:1"></div>
  <button class="btn-print" onclick="window.print()">Print / Save PDF</button>
  <button class="btn-close" onclick="window.close()">Close</button>
</div>

<div class="container">
  <!-- Header -->
  <div class="header">
    <h1>Domain Intelligence Report</h1>
    <div class="subtitle">Generated {date} by ZeekGlare Intelligence Platform</div>
    <div class="target-badge">{_esc(target)}</div>
  </div>

  <!-- Stats -->
  <div class="stats-grid">
    <div class="stat-card"><div class="stat-val" style="color:#818cf8">{total}</div><div class="stat-label">Total Subdomains</div></div>
    <div class="stat-card"><div class="stat-val" style="color:#22c55e">{live}</div><div class="stat-label">Live (HTTP)</div></div>
    <div class="stat-card"><div class="stat-val" style="color:#ef4444">{dead}</div><div class="stat-label">Dead / Unreachable</div></div>
    <div class="stat-card"><div class="stat-val" style="color:#f59e0b">{unique_ips}</div><div class="stat-label">Unique IPs</div></div>
    <div class="stat-card"><div class="stat-val" style="color:#14b8a6">{unique_asns}</div><div class="stat-label">ASN Networks</div></div>
    <div class="stat-card"><div class="stat-val" style="color:#ec4899">{len(tech_map)}</div><div class="stat-label">Technologies</div></div>
    <div class="stat-card"><div class="stat-val" style="color:#f87171">{sum(waf_map.values())}</div><div class="stat-label">WAF Protected</div></div>
    <div class="stat-card"><div class="stat-val" style="color:#8b5cf6">{len(cms_map)}</div><div class="stat-label">CMS Detected</div></div>
  </div>

  <!-- Nav tabs -->
  <div class="nav-tabs no-print">
    <div class="nav-tab active" onclick="switchTab('all')">All Subdomains</div>
    <div class="nav-tab" onclick="switchTab('top')">Top Targets</div>
    <div class="nav-tab" onclick="switchTab('asn')">ASN Breakdown</div>
    <div class="nav-tab" onclick="switchTab('tech')">Technology Stack</div>
    <div class="nav-tab" onclick="switchTab('status')">HTTP Status</div>
    <div class="nav-tab" onclick="switchTab('security')">Security Posture</div>
  </div>

  <!-- Tab: All Subdomains -->
  <div class="tab-panel active" id="tab-all">
    <div class="section">
      <div class="filter-bar no-print">
        <input type="text" id="rpt-filter" placeholder="Search domains, IPs, tech..." oninput="filterTable()">
        <select id="rpt-live-filter" onchange="filterTable()">
          <option value="">All Status</option>
          <option value="1">Live Only</option>
          <option value="0">Dead Only</option>
        </select>
        <select id="rpt-asn-filter" onchange="filterTable()">
          <option value="">All ASNs</option>
        </select>
        <span class="filter-count" id="rpt-count">{total} entries</span>
      </div>
      <div style="overflow-x:auto;max-height:70vh;overflow-y:auto">
        <table class="data-table" id="rpt-table">
          <thead><tr>
            <th onclick="sortTable('score')" class="sorted">Score</th>
            <th onclick="sortTable('live')">Status</th>
            <th onclick="sortTable('domain')">Subdomain</th>
            <th onclick="sortTable('http')">HTTP</th>
            <th onclick="sortTable('ip')">IP Address</th>
            <th onclick="sortTable('org')">Organization</th>
            <th>Technologies</th>
            <th>Missing Headers</th>
          </tr></thead>
          <tbody>{all_rows}</tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- Tab: Top Targets -->
  <div class="tab-panel" id="tab-top">
    <div class="section">
      <div class="section-header"><h2>High-Value Targets</h2><span class="count">{len(top_targets or [])}</span></div>
      <div class="section-body">{top_html if top_html else '<div style="padding:20px;color:#475569;text-align:center">No high-value targets detected</div>'}</div>
    </div>
  </div>

  <!-- Tab: ASN Breakdown -->
  <div class="tab-panel" id="tab-asn">
    <div class="section">
      <div class="section-header"><h2>Network Distribution (ASN)</h2><span class="count">{len(asn_sorted)} networks</span></div>
      <div class="section-body">{asn_blocks if asn_blocks else '<div style="padding:20px;color:#475569;text-align:center">No ASN data</div>'}</div>
    </div>
  </div>

  <!-- Tab: Technology Stack -->
  <div class="tab-panel" id="tab-tech">
    <div class="section">
      <div class="section-header"><h2>Technology Distribution</h2><span class="count">{len(tech_map)} technologies</span></div>
      <div class="section-body tech-dist" id="tech-bars"></div>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-top:20px">
      <div class="section">
        <div class="section-header"><h2>WAF Detection</h2><span class="count">{len(waf_map)}</span></div>
        <div class="section-body waf-cms-grid">
          {"".join(f'<div class="wc-card"><span class="wc-count">{v}</span><span class="wc-name">{_esc(k)}</span></div>' for k,v in waf_sorted) if waf_sorted else '<div style="padding:20px;color:#475569">No WAFs detected</div>'}
        </div>
      </div>
      <div class="section">
        <div class="section-header"><h2>CMS Detection</h2><span class="count">{len(cms_map)}</span></div>
        <div class="section-body waf-cms-grid">
          {"".join(f'<div class="wc-card"><span class="wc-count">{v}</span><span class="wc-name">{_esc(k)}</span></div>' for k,v in cms_sorted) if cms_sorted else '<div style="padding:20px;color:#475569">No CMS detected</div>'}
        </div>
      </div>
    </div>
  </div>

  <!-- Tab: HTTP Status -->
  <div class="tab-panel" id="tab-status">
    <div class="section">
      <div class="section-header"><h2>HTTP Response Codes</h2></div>
      <div class="section-body">
        <div class="status-grid">
          <div class="status-card"><div class="sv" style="color:#22c55e">{status_map["2xx"]}</div><div class="sl">2xx Success</div></div>
          <div class="status-card"><div class="sv" style="color:#818cf8">{status_map["3xx"]}</div><div class="sl">3xx Redirect</div></div>
          <div class="status-card"><div class="sv" style="color:#f59e0b">{status_map["4xx"]}</div><div class="sl">4xx Client Error</div></div>
          <div class="status-card"><div class="sv" style="color:#ef4444">{status_map["5xx"]}</div><div class="sl">5xx Server Error</div></div>
          <div class="status-card"><div class="sv" style="color:#475569">{status_map["none"]}</div><div class="sl">No Response</div></div>
        </div>
      </div>
    </div>
  </div>

  <!-- Tab: Security Posture -->
  <div class="tab-panel" id="tab-security">
    <div class="section">
      <div class="section-header"><h2>Security Analysis</h2></div>
      <div class="section-body" style="padding:20px">
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px">
          <div>
            <h3 style="font-size:13px;color:#e2e8f0;margin-bottom:12px">WAF Coverage</h3>
            <div style="display:flex;align-items:center;gap:12px;margin-bottom:16px">
              <div style="flex:1;height:8px;background:#111b36;border-radius:4px;overflow:hidden">
                <div style="height:100%;width:{(sum(waf_map.values())/max(live,1))*100:.0f}%;background:linear-gradient(90deg,#22c55e,#14b8a6);border-radius:4px"></div>
              </div>
              <span style="font-size:12px;color:#94a3b8;font-weight:600">{(sum(waf_map.values())/max(live,1))*100:.0f}%</span>
            </div>
            <div style="font-size:11px;color:#64748b">{sum(waf_map.values())} of {live} live subdomains protected by WAF</div>
          </div>
          <div>
            <h3 style="font-size:13px;color:#e2e8f0;margin-bottom:12px">Missing Security Headers</h3>
            <div style="font-size:11px;color:#64748b">Subdomains missing critical headers are flagged in the main table under "Missing Headers" column.</div>
          </div>
        </div>
        <div style="margin-top:20px">
          <h3 style="font-size:13px;color:#e2e8f0;margin-bottom:12px">Score Distribution</h3>
          <div style="display:flex;gap:12px">
            <div style="text-align:center;flex:1;padding:12px;background:#ef444412;border-radius:8px;border:1px solid #ef444430">
              <div style="font-size:24px;font-weight:800;color:#f87171">{sum(1 for e in entries if e.get("score",0)>=70)}</div>
              <div style="font-size:10px;color:#ef4444">High Risk (70+)</div>
            </div>
            <div style="text-align:center;flex:1;padding:12px;background:#f59e0b12;border-radius:8px;border:1px solid #f59e0b30">
              <div style="font-size:24px;font-weight:800;color:#fbbf24">{sum(1 for e in entries if 40<=e.get("score",0)<70)}</div>
              <div style="font-size:10px;color:#f59e0b">Medium Risk (40-69)</div>
            </div>
            <div style="text-align:center;flex:1;padding:12px;background:#22c55e12;border-radius:8px;border:1px solid #22c55e30">
              <div style="font-size:24px;font-weight:800;color:#4ade80">{sum(1 for e in entries if e.get("score",0)<40)}</div>
              <div style="font-size:10px;color:#22c55e">Low Risk (&lt;40)</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <div class="footer">ZeekGlare Intelligence Platform &mdash; Domain Mapping Report &mdash; Authorized Use Only</div>
</div>

<script>
/* Tab navigation */
function switchTab(id) {{
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
  document.getElementById('tab-'+id).classList.add('active');
  event.target.classList.add('active');
}}

/* Collapsible sections */
document.querySelectorAll('.section-header').forEach(h => {{
  h.addEventListener('click', () => {{
    const body = h.nextElementSibling;
    if (!body) return;
    h.classList.toggle('collapsed');
    body.classList.toggle('hidden');
  }});
}});

/* Table sorting */
let _sortCol = 'score', _sortDir = -1;
function sortTable(col) {{
  if (_sortCol === col) _sortDir *= -1;
  else {{ _sortCol = col; _sortDir = -1; }}
  document.querySelectorAll('.data-table th').forEach(th => th.classList.remove('sorted'));
  const tbody = document.querySelector('#rpt-table tbody');
  const rows = Array.from(tbody.querySelectorAll('tr'));
  rows.sort((a, b) => {{
    let va, vb;
    if (col === 'score') {{ va = +a.dataset.score; vb = +b.dataset.score; }}
    else if (col === 'live') {{ va = +a.dataset.live; vb = +b.dataset.live; }}
    else if (col === 'domain') {{ va = a.dataset.domain; vb = b.dataset.domain; return _sortDir * va.localeCompare(vb); }}
    else if (col === 'ip') {{ va = a.querySelector('.ip-cell')?.textContent||''; vb = b.querySelector('.ip-cell')?.textContent||''; return _sortDir * va.localeCompare(vb); }}
    else if (col === 'org') {{ va = a.querySelector('.org-cell')?.textContent||''; vb = b.querySelector('.org-cell')?.textContent||''; return _sortDir * va.localeCompare(vb); }}
    else if (col === 'http') {{ va = a.dataset.status||''; vb = b.dataset.status||''; return _sortDir * va.localeCompare(vb); }}
    else return 0;
    return _sortDir * (va - vb);
  }});
  rows.forEach(r => tbody.appendChild(r));
}}

/* Table filtering */
function filterTable() {{
  const q = (document.getElementById('rpt-filter')?.value || '').toLowerCase();
  const live = document.getElementById('rpt-live-filter')?.value || '';
  const asn = document.getElementById('rpt-asn-filter')?.value || '';
  let count = 0;
  document.querySelectorAll('#rpt-table tbody tr').forEach(row => {{
    const text = row.textContent.toLowerCase();
    const matchQ = !q || text.includes(q) || (row.dataset.tech||'').includes(q);
    const matchL = !live || row.dataset.live === live;
    const matchA = !asn || row.dataset.asn === asn;
    const show = matchQ && matchL && matchA;
    row.style.display = show ? '' : 'none';
    if (show) count++;
  }});
  const el = document.getElementById('rpt-count');
  if (el) el.textContent = count + ' entries';
}}

/* Populate ASN filter dropdown */
(function() {{
  const asns = {{}};
  document.querySelectorAll('#rpt-table tbody tr').forEach(r => {{
    const a = r.dataset.asn;
    if (a && a !== 'None' && a !== '') asns[a] = (asns[a]||0) + 1;
  }});
  const sel = document.getElementById('rpt-asn-filter');
  Object.entries(asns).sort((a,b) => b[1]-a[1]).forEach(([a,c]) => {{
    const opt = document.createElement('option');
    opt.value = a; opt.textContent = 'AS' + a + ' (' + c + ')';
    sel.appendChild(opt);
  }});
}})();

/* Tech bars */
(function() {{
  const data = {tech_chart_data};
  const max = data.length ? data[0].count : 1;
  const container = document.getElementById('tech-bars');
  data.forEach(d => {{
    const pct = (d.count / max * 100).toFixed(0);
    container.innerHTML += '<div class="tech-bar-row"><span class="tech-bar-label">' + d.name +
      '</span><div class="tech-bar-wrap"><div class="tech-bar" style="width:' + pct + '%"></div></div>' +
      '<span class="tech-bar-count">' + d.count + '</span></div>';
  }});
  if (!data.length) container.innerHTML = '<div style="color:#475569;text-align:center">No technology data</div>';
}})();
</script>
</body></html>'''
    return html.encode()
