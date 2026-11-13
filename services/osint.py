"""OSINT — WHOIS, geolocation, email harvest, GitHub dorking."""
import requests as _req, socket, re, json
import whois as _whois


# ── WHOIS ─────────────────────────────────────────────────────────────────────

def whois_lookup(domain: str) -> dict:
    try:
        w = _whois.whois(domain)
        def _str(v):
            if isinstance(v, list):
                return [str(x) for x in v]
            return str(v) if v else ""
        return {
            "domain_name":  _str(w.domain_name),
            "registrar":    _str(w.registrar),
            "creation_date":_str(w.creation_date),
            "expiration_date": _str(w.expiration_date),
            "updated_date": _str(w.updated_date),
            "name_servers": _str(w.name_servers),
            "status":       _str(w.status),
            "emails":       _str(w.emails),
            "org":          _str(w.org),
            "country":      _str(w.country),
            "dnssec":       _str(w.dnssec),
        }
    except Exception as e:
        return {"error": str(e)}


# ── IP Geolocation ────────────────────────────────────────────────────────────

def geolocate_ip(ip: str) -> dict:
    try:
        r = _req.get(f"http://ip-api.com/json/{ip}",
                     params={"fields": "status,country,countryCode,region,regionName,city,zip,lat,lon,isp,org,as"},
                     timeout=8)
        data = r.json()
        if data.get("status") == "success":
            return data
    except Exception:
        pass
    return {}


def geolocate_bulk(ips: list) -> dict:
    """Geolocate up to 100 IPs in one batch request."""
    ips = list(set(ips))[:100]
    try:
        r = _req.post(
            "http://ip-api.com/batch",
            json=[{"query": ip, "fields": "status,country,countryCode,city,lat,lon,isp,org,as,query"}
                  for ip in ips],
            timeout=15,
        )
        results = {}
        for item in r.json():
            if item.get("status") == "success":
                results[item["query"]] = item
        return results
    except Exception:
        return {}


# ── Email Harvesting (Hunter.io) ──────────────────────────────────────────────

def harvest_emails_hunter(domain: str, api_key: str) -> list:
    if not api_key:
        return []
    try:
        r = _req.get(
            "https://api.hunter.io/v2/domain-search",
            params={"domain": domain, "api_key": api_key, "limit": 100},
            timeout=15,
        )
        emails = []
        for e in r.json().get("data", {}).get("emails", []):
            emails.append({
                "email":       e.get("value", ""),
                "type":        e.get("type", ""),
                "first_name":  e.get("first_name", ""),
                "last_name":   e.get("last_name", ""),
                "position":    e.get("position", ""),
                "confidence":  e.get("confidence", 0),
                "linkedin":    e.get("linkedin", ""),
            })
        return emails
    except Exception:
        return []


def harvest_emails_free(domain: str) -> list:
    """Free email harvest using crt.sh + pattern extraction."""
    emails = set()
    try:
        r = _req.get("https://crt.sh/", params={"q": domain, "output": "json"}, timeout=15)
        for cert in r.json()[:30]:
            text = cert.get("issuer_name", "") + " " + cert.get("name_value", "")
            found = re.findall(r"[\w.+-]+@[\w-]+\.[\w.]+", text)
            emails.update(found)
    except Exception:
        pass
    return [{"email": e, "source": "crtsh"} for e in list(emails)[:50]]


# ── GitHub Dorking ────────────────────────────────────────────────────────────

GITHUB_DORKS = [
    '"{domain}" password',
    '"{domain}" secret',
    '"{domain}" api_key',
    '"{domain}" token',
    '"{domain}" aws_access_key',
    '"{domain}" DB_PASSWORD',
    'filename:.env "{domain}"',
    'filename:config.json "{domain}"',
    'filename:credentials "{domain}"',
]


def github_dork(domain: str, github_token: str = "") -> list:
    headers = {"Accept": "application/vnd.github.v3+json"}
    if github_token:
        headers["Authorization"] = f"token {github_token}"

    findings = []
    for dork_tpl in GITHUB_DORKS[:5]:  # limit to avoid rate limiting
        query = dork_tpl.format(domain=domain)
        try:
            r = _req.get(
                "https://api.github.com/search/code",
                params={"q": query, "per_page": 5},
                headers=headers,
                timeout=12,
            )
            if r.status_code == 403:
                break  # rate limited
            items = r.json().get("items", [])
            for item in items:
                findings.append({
                    "dork":    query,
                    "repo":    item.get("repository", {}).get("full_name", ""),
                    "file":    item.get("path", ""),
                    "url":     item.get("html_url", ""),
                    "sha":     item.get("sha", "")[:8],
                })
        except Exception:
            pass
    return findings


# ── Technology Fingerprinting (enhanced) ─────────────────────────────────────

def fingerprint_target(domain: str) -> dict:
    """Deep tech fingerprinting via HTTP headers + body analysis."""
    result = {"domain": domain, "headers": {}, "tech": [], "server": "", "cms": ""}
    try:
        r = _req.get(f"https://{domain}", timeout=12, verify=False,
                     headers={"User-Agent": "Mozilla/5.0 ZeekGlare/2.0"},
                     allow_redirects=True)
        result["headers"] = dict(r.headers)
        result["status"]  = r.status_code
        result["final_url"] = r.url

        # Extract tech from headers
        for hdr in ("Server", "X-Powered-By", "X-Generator", "X-Framework"):
            val = r.headers.get(hdr, "")
            if val:
                result["tech"].append(val)
                if hdr == "Server":
                    result["server"] = val

        # Body patterns
        body = r.text[:30000].lower()
        for cms, sig in [("WordPress", "wp-content"), ("Drupal", "/sites/default/"),
                          ("Joomla", "joomla"), ("Shopify", "cdn.shopify.com"),
                          ("Magento", "mage/"), ("Ghost", "ghost.io")]:
            if sig.lower() in body:
                result["cms"] = cms
                result["tech"].append(cms)
                break
    except Exception as e:
        result["error"] = str(e)
    return result
