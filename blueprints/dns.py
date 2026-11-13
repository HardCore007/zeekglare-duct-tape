from core.auth_utils import module_required
"""DNS Intelligence blueprint."""
import threading, uuid, queue, json
from flask import Blueprint, request, jsonify, Response, stream_with_context
from services.dns_intel import full_dns_scan, enumerate_dns
from services.osint import whois_lookup

dns_bp   = Blueprint("dns", __name__)
dns_scans = {}
lock     = threading.Lock()


@dns_bp.route("/api/dns/scan", methods=["POST"])
@module_required("dns")
def start_dns_scan():
    body   = request.get_json(silent=True) or {}
    domain = (body.get("domain") or "").strip().lower()
    if not domain:
        return jsonify({"error": "domain required"}), 400

    scan_id = str(uuid.uuid4())
    q       = queue.Queue()

    with lock:
        dns_scans[scan_id] = {"queue": q, "domain": domain, "done": False}

    def _run():
        try:
            full_dns_scan(domain, q)
        except Exception as e:
            q.put({"type": "dns_error", "error": str(e)})
            q.put(None)
        finally:
            with lock:
                if scan_id in dns_scans:
                    dns_scans[scan_id]["done"] = True

    threading.Thread(target=_run, daemon=True).start()
    return jsonify({"scan_id": scan_id, "domain": domain})


@dns_bp.route("/api/dns/stream/<scan_id>")
@module_required("dns")
def stream_dns(scan_id):
    with lock:
        scan = dns_scans.get(scan_id)
    if not scan:
        return jsonify({"error": "Not found"}), 404

    q = scan["queue"]

    def generate():
        while True:
            try:
                item = q.get(timeout=60)
                if item is None:
                    yield f"data: {json.dumps({'type': 'done'})}\n\n"
                    break
                yield f"data: {json.dumps(item)}\n\n"
            except queue.Empty:
                yield f"data: {json.dumps({'type': 'keepalive'})}\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@dns_bp.route("/api/dns/quick", methods=["POST"])
@module_required("dns")
def quick_dns():
    body   = request.get_json(silent=True) or {}
    domain = (body.get("domain") or "").strip()
    if not domain:
        return jsonify({"error": "domain required"}), 400
    records = enumerate_dns(domain)
    return jsonify({"domain": domain, "records": records})


@dns_bp.route("/api/whois", methods=["POST"])
def whois_route():
    body   = request.get_json(silent=True) or {}
    domain = (body.get("domain") or "").strip()
    if not domain:
        return jsonify({"error": "domain required"}), 400
    result = whois_lookup(domain)
    return jsonify({"domain": domain, "whois": result})


@dns_bp.route("/api/dns/crtsh", methods=["POST"])
@module_required("dns")
def crtsh_lookup():
    """Fetch subdomains from Certificate Transparency logs via crt.sh."""
    import urllib.request, urllib.error
    body   = request.get_json(silent=True) or {}
    domain = (body.get("domain") or "").strip().lower()
    if not domain:
        return jsonify({"error": "domain required"}), 400

    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "ZeekGlare/1.0"})
        with urllib.request.urlopen(req, timeout=20) as r:
            raw = json.loads(r.read())
    except Exception as e:
        return jsonify({"error": f"crt.sh lookup failed: {e}"}), 502

    # Deduplicate and extract unique subdomains
    seen = set()
    entries = []
    for row in raw:
        names = (row.get("name_value") or "").strip().lower().split("\n")
        for name in names:
            name = name.strip().lstrip("*.")
            if name and name not in seen and name.endswith(domain):
                seen.add(name)
                entries.append({
                    "subdomain": name,
                    "issuer": row.get("issuer_name", ""),
                    "not_before": row.get("not_before", ""),
                    "not_after": row.get("not_after", ""),
                    "serial": row.get("serial_number", ""),
                })

    # Sort by subdomain
    entries.sort(key=lambda x: x["subdomain"])

    return jsonify({
        "domain": domain,
        "total": len(entries),
        "subdomains": entries,
    })


@dns_bp.route("/api/dns/spf-dmarc", methods=["POST"])
@module_required("dns")
def spf_dmarc_check():
    """Check SPF, DMARC, DKIM records and score email security posture."""
    import dns.resolver
    body   = request.get_json(silent=True) or {}
    domain = (body.get("domain") or "").strip().lower()
    if not domain:
        return jsonify({"error": "domain required"}), 400

    result = {"domain": domain, "score": 0, "max_score": 100, "checks": []}
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 10

    # SPF
    try:
        txt = resolver.resolve(domain, "TXT")
        spf = [r.to_text().strip('"') for r in txt if "v=spf1" in r.to_text()]
        if spf:
            spf_rec = spf[0]
            result["spf"] = spf_rec
            result["score"] += 25
            result["checks"].append({"name": "SPF Record", "status": "pass", "detail": spf_rec[:100]})
            # Check for ~all vs -all
            if "-all" in spf_rec:
                result["score"] += 10
                result["checks"].append({"name": "SPF Hard Fail (-all)", "status": "pass", "detail": "Strict policy"})
            elif "~all" in spf_rec:
                result["score"] += 5
                result["checks"].append({"name": "SPF Soft Fail (~all)", "status": "warn", "detail": "Soft fail — consider -all"})
            else:
                result["checks"].append({"name": "SPF Policy", "status": "fail", "detail": "No -all or ~all found"})
        else:
            result["checks"].append({"name": "SPF Record", "status": "fail", "detail": "Not found"})
    except Exception:
        result["checks"].append({"name": "SPF Record", "status": "fail", "detail": "Not found"})

    # DMARC
    try:
        dmarc_recs = resolver.resolve(f"_dmarc.{domain}", "TXT")
        dmarc = [r.to_text().strip('"') for r in dmarc_recs if "v=DMARC1" in r.to_text()]
        if dmarc:
            dmarc_rec = dmarc[0]
            result["dmarc"] = dmarc_rec
            result["score"] += 25
            result["checks"].append({"name": "DMARC Record", "status": "pass", "detail": dmarc_rec[:100]})
            if "p=reject" in dmarc_rec:
                result["score"] += 15
                result["checks"].append({"name": "DMARC Policy", "status": "pass", "detail": "p=reject (strictest)"})
            elif "p=quarantine" in dmarc_rec:
                result["score"] += 10
                result["checks"].append({"name": "DMARC Policy", "status": "warn", "detail": "p=quarantine — consider reject"})
            elif "p=none" in dmarc_rec:
                result["score"] += 2
                result["checks"].append({"name": "DMARC Policy", "status": "fail", "detail": "p=none — monitoring only, no enforcement"})
            if "rua=" in dmarc_rec:
                result["score"] += 5
                result["checks"].append({"name": "DMARC Reporting", "status": "pass", "detail": "Aggregate reports configured"})
        else:
            result["checks"].append({"name": "DMARC Record", "status": "fail", "detail": "Not found"})
    except Exception:
        result["checks"].append({"name": "DMARC Record", "status": "fail", "detail": "Not found"})

    # DKIM (check common selectors)
    dkim_found = False
    for selector in ("default", "google", "selector1", "selector2", "k1", "mail", "dkim", "s1", "s2"):
        try:
            dkim_recs = resolver.resolve(f"{selector}._domainkey.{domain}", "TXT")
            dkim_txt = " ".join(r.to_text().strip('"') for r in dkim_recs)
            if "v=DKIM1" in dkim_txt or "p=" in dkim_txt:
                result["dkim"] = {"selector": selector, "record": dkim_txt[:200]}
                result["score"] += 20
                result["checks"].append({"name": "DKIM Record", "status": "pass", "detail": f"Selector: {selector}"})
                dkim_found = True
                break
        except Exception:
            continue
    if not dkim_found:
        result["checks"].append({"name": "DKIM Record", "status": "warn", "detail": "Not found (checked common selectors)"})

    # MX records
    try:
        mx = resolver.resolve(domain, "MX")
        mx_list = sorted([(r.preference, r.exchange.to_text().rstrip('.')) for r in mx])
        result["mx"] = [{"priority": p, "host": h} for p, h in mx_list]
        result["checks"].append({"name": "MX Records", "status": "pass", "detail": f"{len(mx_list)} mail servers"})
    except Exception:
        result["mx"] = []
        result["checks"].append({"name": "MX Records", "status": "info", "detail": "No MX records"})

    # Grade
    score = result["score"]
    if score >= 80:
        result["grade"] = "A"
    elif score >= 60:
        result["grade"] = "B"
    elif score >= 40:
        result["grade"] = "C"
    elif score >= 20:
        result["grade"] = "D"
    else:
        result["grade"] = "F"

    return jsonify(result)
