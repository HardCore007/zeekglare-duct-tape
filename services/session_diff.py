"""Session Comparison / Diff — compare two sessions and find changes."""
from core.session_manager import SessionManager


def compare_sessions(sid_a, sid_b):
    """Compare two sessions and return diff.
    Returns dict with added, removed, changed items.
    """
    a = SessionManager.get(sid_a)
    b = SessionManager.get(sid_b)
    if not a or not b:
        raise ValueError("One or both sessions not found")
    if a.get("type") != b.get("type"):
        raise ValueError(f"Cannot compare different types: {a.get('type')} vs {b.get('type')}")

    stype = a["type"]

    if stype == "asn":
        return _diff_asn(a, b)
    elif stype == "domain":
        return _diff_domain(a, b)
    elif stype == "ipscope":
        return _diff_ipscope(a, b)
    elif stype == "ports":
        return _diff_ports(a, b)
    elif stype == "threatblitz":
        return _diff_threatblitz(a, b)
    else:
        return _diff_generic(a, b)


def _diff_asn(a, b):
    data_a = {str(x.get("asn")): x for x in a.get("data", {}).get("asn_data", [])}
    data_b = {str(x.get("asn")): x for x in b.get("data", {}).get("asn_data", [])}

    keys_a, keys_b = set(data_a.keys()), set(data_b.keys())
    added = [data_b[k] for k in keys_b - keys_a]
    removed = [data_a[k] for k in keys_a - keys_b]

    changed = []
    for k in keys_a & keys_b:
        ea, eb = data_a[k], data_b[k]
        diffs = []
        if ea.get("prefix_count", 0) != eb.get("prefix_count", 0):
            diffs.append(f"Prefixes: {ea.get('prefix_count',0)} → {eb.get('prefix_count',0)}")
        if ea.get("domain_count", 0) != eb.get("domain_count", 0):
            diffs.append(f"Domains: {ea.get('domain_count',0)} → {eb.get('domain_count',0)}")
        if ea.get("category") != eb.get("category"):
            diffs.append(f"Category: {ea.get('category','')} → {eb.get('category','')}")
        # Compare domain lists
        doms_a = set(sum((v for v in (ea.get("critical") or {}).values()), []))
        doms_b = set(sum((v for v in (eb.get("critical") or {}).values()), []))
        new_doms = doms_b - doms_a
        lost_doms = doms_a - doms_b
        if new_doms:
            diffs.append(f"+{len(new_doms)} new domains")
        if lost_doms:
            diffs.append(f"-{len(lost_doms)} removed domains")
        if diffs:
            changed.append({"key": f"AS{k}", "name": eb.get("name", ""), "changes": diffs})

    return {
        "type": "asn", "added": added, "removed": removed, "changed": changed,
        "session_a": {"id": a["id"], "name": a.get("name", ""), "target": a.get("target", ""),
                      "date": a.get("created_at", 0)},
        "session_b": {"id": b["id"], "name": b.get("name", ""), "target": b.get("target", ""),
                      "date": b.get("created_at", 0)},
        "summary": f"+{len(added)} new, -{len(removed)} removed, ~{len(changed)} changed ASNs",
    }


def _diff_domain(a, b):
    data_a = {x.get("domain", ""): x for x in a.get("data", {}).get("entries", [])}
    data_b = {x.get("domain", ""): x for x in b.get("data", {}).get("entries", [])}

    keys_a, keys_b = set(data_a.keys()), set(data_b.keys())
    added = [data_b[k] for k in keys_b - keys_a]
    removed = [data_a[k] for k in keys_a - keys_b]

    changed = []
    for k in keys_a & keys_b:
        ea, eb = data_a[k], data_b[k]
        diffs = []
        if ea.get("ip") != eb.get("ip"):
            diffs.append(f"IP: {ea.get('ip','')} → {eb.get('ip','')}")
        if ea.get("http_status") != eb.get("http_status"):
            diffs.append(f"Status: {ea.get('http_status','')} → {eb.get('http_status','')}")
        if ea.get("http_live") != eb.get("http_live"):
            diffs.append(f"Live: {ea.get('http_live')} → {eb.get('http_live')}")
        if ea.get("waf") != eb.get("waf"):
            diffs.append(f"WAF: {ea.get('waf','')} → {eb.get('waf','')}")
        if diffs:
            changed.append({"key": k, "name": k, "changes": diffs})

    return {
        "type": "domain", "added": added, "removed": removed, "changed": changed,
        "session_a": {"id": a["id"], "name": a.get("name", ""), "target": a.get("target", ""),
                      "date": a.get("created_at", 0)},
        "session_b": {"id": b["id"], "name": b.get("name", ""), "target": b.get("target", ""),
                      "date": b.get("created_at", 0)},
        "summary": f"+{len(added)} new, -{len(removed)} removed, ~{len(changed)} changed subdomains",
    }


def _diff_ipscope(a, b):
    data_a = {x.get("ip", ""): x for x in a.get("data", {}).get("entries", [])}
    data_b = {x.get("ip", ""): x for x in b.get("data", {}).get("entries", [])}

    keys_a, keys_b = set(data_a.keys()), set(data_b.keys())
    added = [data_b[k] for k in keys_b - keys_a]
    removed = [data_a[k] for k in keys_a - keys_b]

    changed = []
    for k in keys_a & keys_b:
        ea, eb = data_a[k], data_b[k]
        ports_a = set(ea.get("ports", []))
        ports_b = set(eb.get("ports", []))
        diffs = []
        new_ports = ports_b - ports_a
        closed_ports = ports_a - ports_b
        if new_ports:
            diffs.append(f"+ports: {','.join(str(p) for p in sorted(new_ports))}")
        if closed_ports:
            diffs.append(f"-ports: {','.join(str(p) for p in sorted(closed_ports))}")
        if ea.get("risk") != eb.get("risk"):
            diffs.append(f"Risk: {ea.get('risk','')} → {eb.get('risk','')}")
        if diffs:
            changed.append({"key": k, "name": k, "changes": diffs})

    return {
        "type": "ipscope", "added": added, "removed": removed, "changed": changed,
        "session_a": {"id": a["id"], "name": a.get("name", ""), "target": a.get("target", ""),
                      "date": a.get("created_at", 0)},
        "session_b": {"id": b["id"], "name": b.get("name", ""), "target": b.get("target", ""),
                      "date": b.get("created_at", 0)},
        "summary": f"+{len(added)} new, -{len(removed)} removed, ~{len(changed)} changed IPs",
    }


def _diff_ports(a, b):
    res_a = a.get("data", {}).get("results", {})
    res_b = b.get("data", {}).get("results", {})

    hosts_a, hosts_b = set(res_a.keys()), set(res_b.keys())
    added = [{"host": h, **res_b[h]} for h in hosts_b - hosts_a]
    removed = [{"host": h, **res_a[h]} for h in hosts_a - hosts_b]

    changed = []
    for h in hosts_a & hosts_b:
        pa = set(res_a[h].get("ports", []))
        pb = set(res_b[h].get("ports", []))
        diffs = []
        if pb - pa:
            diffs.append(f"+ports: {','.join(str(p) for p in sorted(pb - pa))}")
        if pa - pb:
            diffs.append(f"-ports: {','.join(str(p) for p in sorted(pa - pb))}")
        if diffs:
            changed.append({"key": h, "name": h, "changes": diffs})

    return {
        "type": "ports", "added": added, "removed": removed, "changed": changed,
        "session_a": {"id": a["id"], "name": a.get("name", ""), "target": a.get("target", ""),
                      "date": a.get("created_at", 0)},
        "session_b": {"id": b["id"], "name": b.get("name", ""), "target": b.get("target", ""),
                      "date": b.get("created_at", 0)},
        "summary": f"+{len(added)} new, -{len(removed)} removed, ~{len(changed)} changed hosts",
    }


def _diff_threatblitz(a, b):
    ra = a.get("data", {}).get("results", [])
    rb = b.get("data", {}).get("results", [])
    ids_a = {(x.get("template","") + x.get("host","")): x for x in ra}
    ids_b = {(x.get("template","") + x.get("host","")): x for x in rb}
    ka, kb = set(ids_a.keys()), set(ids_b.keys())
    return {
        "type": "threatblitz",
        "added": [ids_b[k] for k in kb - ka],
        "removed": [ids_a[k] for k in ka - kb],
        "changed": [],
        "session_a": {"id": a["id"], "name": a.get("name", ""), "target": a.get("target", ""),
                      "date": a.get("created_at", 0)},
        "session_b": {"id": b["id"], "name": b.get("name", ""), "target": b.get("target", ""),
                      "date": b.get("created_at", 0)},
        "summary": f"+{len(kb-ka)} new, -{len(ka-kb)} resolved findings",
    }


def _diff_generic(a, b):
    return {
        "type": a.get("type", "unknown"),
        "added": [], "removed": [], "changed": [],
        "session_a": {"id": a["id"], "name": a.get("name", ""), "date": a.get("created_at", 0)},
        "session_b": {"id": b["id"], "name": b.get("name", ""), "date": b.get("created_at", 0)},
        "summary": "Comparison not available for this session type",
    }
