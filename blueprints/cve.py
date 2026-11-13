"""CVE/PoC Intelligence — live feed of latest CVEs with exploits from multiple sources."""
import json, threading, queue, time, uuid, urllib.request, urllib.error, urllib.parse, re
from flask import Blueprint, request, Response, jsonify, stream_with_context
from core.auth_utils import login_required

cve_bp = Blueprint("cve", __name__)

_scans = {}
_lock = threading.Lock()
_feed_cache = {"data": [], "ts": 0}  # auto-refresh cache
_FEED_TTL = 300  # 5 min
_marcio_index = {"data": None, "ts": 0}  # CVE -> [github urls]
_MARCIO_TTL = 3600  # 1 hour


def _req(url, timeout=15):
    """Helper for HTTP GET with UA."""
    r = urllib.request.Request(url, headers={"User-Agent": "ZeekGlare/1.0"})
    with urllib.request.urlopen(r, timeout=timeout) as resp:
        return json.loads(resp.read())


def _severity_from_cvss(score):
    if score is None:
        return "info"
    score = float(score)
    if score >= 9.0: return "critical"
    if score >= 7.0: return "high"
    if score >= 4.0: return "medium"
    if score >= 0.1: return "low"
    return "info"


# ── Source: Shodan CVEDB ─────────────────────────────────────────────────────

def _fetch_shodan_recent(days=7, limit=100):
    """Fetch recently modified CVEs from Shodan CVEDB (free, no auth)."""
    try:
        data = _req(f"https://cvedb.shodan.io/cves?last_modified={days}d&limit={limit}&sort=epss")
        return data.get("cves", []) if isinstance(data, dict) else data
    except Exception:
        return []


def _fetch_shodan_cve(cve_id):
    """Fetch single CVE detail from Shodan."""
    try:
        return _req(f"https://cvedb.shodan.io/cve/{cve_id}")
    except Exception:
        return {}


# ── Source: PoC-in-GitHub ────────────────────────────────────────────────────

def _fetch_latest_pocs(limit=60):
    """Fetch latest PoCs from poc-in-github.motikan2010.net."""
    try:
        data = _req(f"https://poc-in-github.motikan2010.net/api/v1/?sort=created_at&limit={limit}")
        return data.get("pocs", []) if isinstance(data, dict) else (data if isinstance(data, list) else [])
    except Exception:
        return []


def _fetch_poc_for_cve(cve_id):
    """Fetch GitHub PoCs for a specific CVE."""
    try:
        data = _req(f"https://poc-in-github.motikan2010.net/api/v1/?cve_id={cve_id}", timeout=10)
        return data.get("pocs", []) if isinstance(data, dict) else (data if isinstance(data, list) else [])
    except Exception:
        return []


# ── Source: CISA Known Exploited Vulnerabilities (KEV) ───────────────────────

def _fetch_cisa_kev(days=30):
    """Fetch recently added CISA KEV entries."""
    try:
        data = _req("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
        vulns = data.get("vulnerabilities", [])
        vulns.sort(key=lambda x: x.get("dateAdded", ""), reverse=True)
        # Filter to recent N days
        import datetime
        cutoff = (datetime.datetime.now() - datetime.timedelta(days=days)).strftime("%Y-%m-%d")
        return [v for v in vulns if v.get("dateAdded", "") >= cutoff]
    except Exception:
        return []


# ── Source: GitHub Security Advisories ───────────────────────────────────────

def _fetch_github_advisories(limit=30):
    """Fetch latest reviewed GitHub Security Advisories (no auth needed)."""
    try:
        data = _req(f"https://api.github.com/advisories?per_page={limit}&type=reviewed")
        return data if isinstance(data, list) else []
    except Exception:
        return []


# ── Source: NVD ──────────────────────────────────────────────────────────────

def _fetch_nvd_recent(days=7, limit=50):
    """Fetch recently published CVEs from NVD."""
    import datetime
    end = datetime.datetime.utcnow()
    start = end - datetime.timedelta(days=days)
    params = urllib.parse.urlencode({
        "pubStartDate": start.strftime("%Y-%m-%dT00:00:00.000"),
        "pubEndDate": end.strftime("%Y-%m-%dT23:59:59.999"),
        "resultsPerPage": min(limit, 100),
    })
    try:
        data = _req(f"https://services.nvd.nist.gov/rest/json/cves/2.0?{params}", timeout=20)
        return data.get("vulnerabilities", [])
    except Exception:
        return []


def _fetch_nvd_search(query, limit=50):
    """Search NVD by keyword."""
    params = urllib.parse.urlencode({"keywordSearch": query, "resultsPerPage": min(limit, 50)})
    try:
        data = _req(f"https://services.nvd.nist.gov/rest/json/cves/2.0?{params}", timeout=20)
        return data.get("vulnerabilities", [])
    except Exception:
        return []


# ── Source: WatchStack (scrape — no API) ─────────────────────────────────────

def _scrape_watchstack(days=30):
    """Scrape WatchStack for recent CVE discussions."""
    import datetime
    year = datetime.datetime.now().year
    results = []
    try:
        url = f"https://watchstack.io/search?q=CVE-{year}"
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
        })
        with urllib.request.urlopen(req, timeout=15) as r:
            html = r.read().decode("utf-8", errors="replace")
        # Extract CVE IDs and context from the page
        cve_pattern = re.compile(r'(CVE-\d{4}-\d{4,})')
        found = cve_pattern.findall(html)
        seen = set()
        for cve_id in found:
            if cve_id not in seen:
                seen.add(cve_id)
                results.append({"cve_id": cve_id, "source": "watchstack"})
        return results[:50]
    except Exception:
        return []


# ── Source: 0xMarcio/cve (github.txt index of CVE → PoC repos) ───────────────

def _fetch_0xmarcio_index():
    """Download and parse 0xMarcio/cve github.txt into {cve_id: [urls]}. Cached 1h."""
    now = time.time()
    if _marcio_index["data"] is not None and (now - _marcio_index["ts"]) < _MARCIO_TTL:
        return _marcio_index["data"]
    try:
        req = urllib.request.Request(
            "https://raw.githubusercontent.com/0xMarcio/cve/master/github.txt",
            headers={"User-Agent": "ZeekGlare/1.0"},
        )
        with urllib.request.urlopen(req, timeout=30) as r:
            raw = r.read().decode("utf-8", errors="replace")
        idx = {}
        for line in raw.splitlines():
            if " - " not in line:
                continue
            cid, url = line.split(" - ", 1)
            cid = cid.strip()
            url = url.strip()
            if not cid.startswith("CVE-") or not url.startswith("http"):
                continue
            idx.setdefault(cid, []).append(url)
        _marcio_index["data"] = idx
        _marcio_index["ts"] = now
        return idx
    except Exception:
        return _marcio_index.get("data") or {}


def _marcio_pocs_for(cve_id, idx=None):
    """Return a list of PoC dicts from 0xMarcio index for a given CVE id."""
    if idx is None:
        idx = _fetch_0xmarcio_index()
    urls = idx.get(cve_id, []) if idx else []
    out = []
    for u in urls:
        name = u.rstrip("/").split("github.com/", 1)[-1]
        owner = name.split("/", 1)[0] if "/" in name else ""
        out.append({
            "name": name,
            "url": u,
            "description": "Indexed by 0xMarcio/cve",
            "stars": 0,
            "owner": "0xMarcio · " + owner if owner else "0xMarcio",
            "created_at": "",
            "updated_at": "",
        })
    return out


# ── Source: Exploit-DB ───────────────────────────────────────────────────────

def _fetch_exploitdb(days=30):
    """Fetch recent Exploit-DB entries from the official CSV. Returns list of
    dicts keyed by CVE id (one entry per CVE mentioned in an exploit row)."""
    import datetime, csv, io
    url = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 ZeekGlare/1.0"})
        with urllib.request.urlopen(req, timeout=25) as r:
            raw = r.read().decode("utf-8", errors="replace")
        cutoff = (datetime.datetime.now() - datetime.timedelta(days=days)).strftime("%Y-%m-%d")
        reader = csv.DictReader(io.StringIO(raw))
        results = []
        cve_re = re.compile(r"CVE-\d{4}-\d{4,}")
        for row in reader:
            d = row.get("date_published") or row.get("date_added") or ""
            if d and d < cutoff:
                continue
            codes = row.get("codes") or ""
            found = cve_re.findall(codes)
            if not found:
                continue
            for cid in set(found):
                results.append({
                    "cve_id": cid,
                    "edb_id": row.get("id", ""),
                    "url": f"https://www.exploit-db.com/exploits/{row.get('id','')}",
                    "description": row.get("description", ""),
                    "author": row.get("author", ""),
                    "type": row.get("type", ""),
                    "platform": row.get("platform", ""),
                    "date": d,
                    "verified": row.get("verified", "") == "1",
                })
        return results
    except Exception:
        return []


# ── Source: ProjectDiscovery vulnx (api.projectdiscovery.io) ────────────────
# Backs the upstream `vulnx` CLI. Optional X-PDCP-Auth header for higher rate
# limits — without auth, capped at ~10 req/min. Set PDCP_API_KEY in the env
# (the same key vulnx CLI uses) to enable authenticated calls.

VULNX_BASE = "https://api.projectdiscovery.io/v2/vulnerability"


def _vulnx_headers():
    import os
    h = {"User-Agent": "ZeekGlare/1.0"}
    key = os.environ.get("PDCP_API_KEY", "") or os.environ.get("VULNX_API_KEY", "")
    if key:
        h["X-PDCP-Auth"] = key
    return h


def _vulnx_get(path, params=None, timeout=15):
    """GET against api.projectdiscovery.io with optional auth + structured error swallow."""
    url = path if path.startswith("http") else f"{VULNX_BASE}{path}"
    if params:
        url += "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers=_vulnx_headers())
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def _fetch_vulnx_recent(days=7, limit=80):
    """Search vulnx for recently created vulnerabilities, sorted by severity."""
    import datetime
    cutoff = (datetime.datetime.utcnow() - datetime.timedelta(days=days)).strftime("%Y-%m-%d")
    # vulnx query syntax: field:value joined with && (per upstream README).
    q = f"cve_created_at:>={cutoff} && severity:high,critical"
    try:
        data = _vulnx_get("/search", params={"q": q, "limit": str(limit), "sort": "cve_created_at:desc"})
        if isinstance(data, dict):
            return data.get("results") or data.get("data") or data.get("vulnerabilities") or []
        return data if isinstance(data, list) else []
    except Exception:
        return []


def _fetch_vulnx_for_cve(cve_id):
    """Fetch a single CVE detail from vulnx by ID."""
    try:
        data = _vulnx_get(f"/{cve_id}")
        if isinstance(data, dict):
            # PD APIs sometimes wrap payloads — surface the inner record if present.
            return data.get("data") or data.get("result") or data
        return {}
    except Exception:
        return {}


def _vulnx_normalize(rec):
    """Normalize a single vulnx record into the merge-friendly shape used by
    `_build_entry`. Defensive: any field may be missing or shaped slightly
    differently across vulnx releases."""
    if not isinstance(rec, dict):
        return {}
    cve_id = (rec.get("cve_id") or rec.get("id") or rec.get("name") or "").upper()
    cvss = rec.get("cvss_score") or rec.get("cvss")
    if isinstance(cvss, dict):
        cvss = cvss.get("score") or cvss.get("base_score")
    severity = (rec.get("severity") or "").lower()
    summary = rec.get("description") or rec.get("summary") or rec.get("title") or ""
    refs = rec.get("references") or rec.get("refs") or []
    if isinstance(refs, dict):
        # Sometimes references come as {urls:[...], advisories:[...]}
        refs = (refs.get("urls") or []) + (refs.get("advisories") or [])
    pocs = rec.get("pocs") or rec.get("exploits") or []
    epss = rec.get("epss") or rec.get("epss_score")
    if isinstance(epss, dict):
        epss = epss.get("score")
    return {
        "cve_id":   cve_id,
        "cvss":     cvss,
        "severity": severity,
        "summary":  summary,
        "refs":     [r for r in refs if isinstance(r, str)][:8],
        "pocs":     pocs if isinstance(pocs, list) else [],
        "epss":     epss,
        "tags":     rec.get("tags") or [],
        "is_kev":   bool(rec.get("is_kev")),
        "is_remote":bool(rec.get("is_remote")),
        "vendor":   rec.get("vendor") or "",
        "product":  rec.get("product") or "",
        "raw":      rec,
    }


# ── Build unified entry ─────────────────────────────────────────────────────

def _build_entry(cve_id, shodan=None, pocs=None, kev=None, ghsa=None, nvd=None, edb=None, marcio=None, vulnx=None):
    """Merge data from multiple sources into a single CVE entry."""
    shodan = shodan or {}
    pocs = pocs or []
    kev = kev or {}
    ghsa = ghsa or {}
    nvd = nvd or {}
    edb = edb or []
    marcio = marcio or []
    vulnx = vulnx or {}

    # Extract NVD description
    nvd_desc = ""
    for d in nvd.get("descriptions", []):
        if d.get("lang") == "en":
            nvd_desc = d.get("value", "")
            break

    # Extract NVD CVSS
    nvd_cvss = None
    metrics = nvd.get("metrics", {})
    for mkey in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        mlist = metrics.get(mkey, [])
        if mlist:
            nvd_cvss = mlist[0].get("cvssData", {}).get("baseScore")
            break

    cvss = (shodan.get("cvss") or shodan.get("cvss_v3") or nvd_cvss
            or ghsa.get("cvss", {}).get("score") or vulnx.get("cvss"))
    summary = (shodan.get("summary")
               or nvd_desc
               or ghsa.get("summary", "")
               or kev.get("shortDescription", "")
               or vulnx.get("summary", "")
               or (pocs[0].get("vuln_description", "") if pocs else "")
               or "No description available")

    severity = ghsa.get("severity", "").lower() if ghsa.get("severity") else _severity_from_cvss(cvss)
    if severity not in ("critical", "high", "medium", "low", "info"):
        severity = _severity_from_cvss(cvss)

    # Sources list
    sources = []
    if shodan: sources.append("shodan")
    if pocs: sources.append("poc-in-github")
    if kev: sources.append("cisa-kev")
    if ghsa: sources.append("github-advisory")
    if nvd: sources.append("nvd")
    if edb: sources.append("exploit-db")
    if marcio: sources.append("0xmarcio-cve")
    if vulnx: sources.append("vulnx")

    # Merge Exploit-DB entries as PoCs so they render in the Exploits tab
    edb_pocs = []
    for e in edb:
        edb_pocs.append({
            "name": f"EDB-{e.get('edb_id','')}" + (" ✓" if e.get("verified") else ""),
            "url": e.get("url", ""),
            "description": e.get("description", ""),
            "stars": 0,
            "owner": "Exploit-DB" + (f" · {e.get('author','')}" if e.get("author") else ""),
            "created_at": e.get("date", ""),
            "updated_at": e.get("date", ""),
        })

    # Merge vulnx PoCs (from `pocs`/`exploits` field on the vulnx record).
    vulnx_pocs = []
    for p in (vulnx.get("pocs") or []):
        if isinstance(p, str):
            vulnx_pocs.append({
                "name":        p.rsplit("/", 1)[-1] if "/" in p else "vulnx PoC",
                "url":         p,
                "description": "",
                "stars":       0,
                "owner":       "vulnx",
                "created_at":  "",
                "updated_at":  "",
            })
        elif isinstance(p, dict):
            vulnx_pocs.append({
                "name":        p.get("name") or p.get("title") or "vulnx PoC",
                "url":         p.get("url") or p.get("href") or "",
                "description": p.get("description") or "",
                "stars":       int(p.get("stars", 0) or 0),
                "owner":       p.get("owner") or "vulnx",
                "created_at":  p.get("created_at", ""),
                "updated_at":  p.get("updated_at", ""),
            })

    return {
        "cve_id": cve_id,
        "summary": summary,
        "cvss": cvss,
        "severity": severity,
        "epss": shodan.get("epss") or vulnx.get("epss"),
        "kev": bool(kev) or bool(vulnx.get("is_kev")),
        "kev_action": kev.get("requiredAction", ""),
        "kev_due": kev.get("dueDate", ""),
        "ransomware": shodan.get("ransomware_campaign") or (kev.get("knownRansomwareCampaignUse", "Unknown") if kev.get("knownRansomwareCampaignUse") not in (None, "Unknown") else None),
        "references": (shodan.get("references", []) or vulnx.get("refs") or [])[:8],
        "published": shodan.get("published_time") or nvd.get("published") or ghsa.get("published_at", "") or "",
        "vendor": shodan.get("vendor") or kev.get("vendorProject", "") or vulnx.get("vendor", "") or "",
        "product": shodan.get("product") or kev.get("product", "") or vulnx.get("product", "") or "",
        "cpes": shodan.get("cpes", [])[:10],
        "ghsa_url": ghsa.get("html_url", ""),
        "ghsa_id": ghsa.get("ghsa_id", ""),
        "sources": sources,
        "tags": vulnx.get("tags") or [],
        "is_remote": bool(vulnx.get("is_remote")),
        "pocs": [{
            "name": p.get("name", ""),
            "url": p.get("html_url", ""),
            "description": p.get("description", ""),
            "stars": int(p.get("stargazers_count", 0) or 0),
            "owner": p.get("owner", ""),
            "created_at": p.get("created_at", ""),
            "updated_at": p.get("updated_at", ""),
        } for p in pocs] + edb_pocs + list(marcio) + vulnx_pocs,
        "poc_count": len(pocs) + len(edb_pocs) + len(marcio) + len(vulnx_pocs),
    }


# ── Live feed worker ─────────────────────────────────────────────────────────

def _run_live_feed(eq, days=7, limit=80):
    """Background worker: pull from all sources in parallel, merge, push SSE events."""
    try:
        eq.put({"type": "status", "msg": "Starting live CVE feed from 9 sources..."})

        results = {}  # cve_id -> partial data

        # ── 1. Fetch from all sources in parallel ────────────────────────────
        from concurrent.futures import ThreadPoolExecutor, as_completed

        futures = {}
        with ThreadPoolExecutor(max_workers=8) as pool:
            futures["shodan"] = pool.submit(_fetch_shodan_recent, days, min(limit, 100))
            futures["pocs"] = pool.submit(_fetch_latest_pocs, min(limit, 80))
            futures["kev"] = pool.submit(_fetch_cisa_kev, max(days, 30))
            futures["ghsa"] = pool.submit(_fetch_github_advisories, 30)
            futures["nvd"] = pool.submit(_fetch_nvd_recent, days, min(limit, 80))
            futures["watchstack"] = pool.submit(_scrape_watchstack, days)
            futures["exploit-db"] = pool.submit(_fetch_exploitdb, max(days, 30))
            futures["0xmarcio"] = pool.submit(_fetch_0xmarcio_index)
            futures["vulnx"] = pool.submit(_fetch_vulnx_recent, days, min(limit, 80))

            for name, future in futures.items():
                try:
                    data = future.result(timeout=25)
                    eq.put({"type": "status", "msg": f"[{name}] Got {len(data)} results"})

                    if name == "shodan":
                        for cve in data:
                            cid = cve.get("cve_id", "")
                            if cid:
                                results.setdefault(cid, {})["shodan"] = cve

                    elif name == "pocs":
                        for poc in data:
                            cid = poc.get("cve_id", "")
                            if cid:
                                results.setdefault(cid, {}).setdefault("pocs", []).append(poc)

                    elif name == "kev":
                        for kv in data:
                            cid = kv.get("cveID", "")
                            if cid:
                                results.setdefault(cid, {})["kev"] = kv

                    elif name == "ghsa":
                        for adv in data:
                            cid = adv.get("cve_id", "")
                            if cid:
                                results.setdefault(cid, {})["ghsa"] = adv

                    elif name == "nvd":
                        for vuln in data:
                            cve_obj = vuln.get("cve", {})
                            cid = cve_obj.get("id", "")
                            if cid:
                                results.setdefault(cid, {})["nvd"] = cve_obj

                    elif name == "watchstack":
                        for ws in data:
                            cid = ws.get("cve_id", "")
                            if cid:
                                results.setdefault(cid, {}).setdefault("sources_extra", []).append("watchstack")

                    elif name == "exploit-db":
                        for ex in data:
                            cid = ex.get("cve_id", "")
                            if cid:
                                results.setdefault(cid, {}).setdefault("edb", []).append(ex)

                    elif name == "vulnx":
                        for rec in (data or []):
                            norm = _vulnx_normalize(rec)
                            cid = norm.get("cve_id", "")
                            if cid:
                                results.setdefault(cid, {})["vulnx"] = norm

                    elif name == "0xmarcio":
                        # data is the full CVE->urls index dict; we'll merge per-entry below
                        marcio_idx = data or {}
                        results.setdefault("__marcio_idx__", {}).update({"idx": marcio_idx})

                except Exception as e:
                    eq.put({"type": "status", "msg": f"[{name}] Failed: {e}"})

        eq.put({"type": "status", "msg": f"Merging {len(results)} unique CVEs..."})

        # ── 2. For top CVEs without PoCs, check PoC-in-GitHub ────────────────
        # Prioritize: KEV > critical > high, and fetch PoCs for those missing them
        cve_ids_need_pocs = []
        for cid, parts in results.items():
            if "pocs" not in parts:
                shodan = parts.get("shodan", {})
                cvss = shodan.get("cvss") or shodan.get("cvss_v3") or 0
                is_kev = "kev" in parts
                if is_kev or (cvss and float(cvss) >= 7.0):
                    cve_ids_need_pocs.append(cid)
        cve_ids_need_pocs = cve_ids_need_pocs[:25]  # max 25 lookups

        if cve_ids_need_pocs:
            eq.put({"type": "status", "msg": f"Checking PoCs for {len(cve_ids_need_pocs)} high-priority CVEs..."})
            for cid in cve_ids_need_pocs:
                try:
                    pocs = _fetch_poc_for_cve(cid)
                    if pocs:
                        results[cid]["pocs"] = pocs
                    time.sleep(0.15)
                except Exception:
                    pass

        # ── 3. Build unified entries and push ────────────────────────────────
        marcio_idx = (results.pop("__marcio_idx__", {}) or {}).get("idx") or {}
        entries = []
        for cid, parts in results.items():
            entry = _build_entry(
                cid,
                shodan=parts.get("shodan"),
                pocs=parts.get("pocs"),
                kev=parts.get("kev"),
                ghsa=parts.get("ghsa"),
                nvd=parts.get("nvd"),
                edb=parts.get("edb"),
                marcio=_marcio_pocs_for(cid, marcio_idx),
                vulnx=parts.get("vulnx"),
            )
            if parts.get("sources_extra"):
                entry["sources"].extend(parts["sources_extra"])
            entries.append(entry)

        # Sort: KEV first, then by CVSS desc, then by PoC count desc
        entries.sort(key=lambda e: (
            not e["kev"],
            -(float(e["cvss"]) if e["cvss"] else 0),
            -e["poc_count"],
        ))

        eq.put({"type": "status", "msg": f"Streaming {len(entries)} CVEs..."})

        for entry in entries:
            eq.put({"type": "cve_result", "entry": entry})

        eq.put({"type": "status", "msg": f"Feed complete — {len(entries)} CVEs from {len(futures)} sources"})
    except Exception as e:
        eq.put({"type": "error", "msg": str(e)})
    finally:
        eq.put(None)


# ── Search worker ────────────────────────────────────────────────────────────

def _run_search(eq, query, limit=50):
    """Search for a specific CVE or keyword."""
    try:
        if query.upper().startswith("CVE-"):
            cve_id = query.upper().strip()
            eq.put({"type": "status", "msg": f"Looking up {cve_id}..."})

            shodan = _fetch_shodan_cve(cve_id)
            pocs = _fetch_poc_for_cve(cve_id)

            # NVD
            nvd = {}
            try:
                data = _req(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}")
                vulns = data.get("vulnerabilities", [])
                if vulns:
                    nvd = vulns[0].get("cve", {})
            except Exception:
                pass

            # Exploit-DB lookup for this specific CVE
            edb_matches = [e for e in _fetch_exploitdb(days=3650) if e.get("cve_id") == cve_id]
            marcio_matches = _marcio_pocs_for(cve_id)

            # vulnx single-CVE lookup
            vulnx_rec = _vulnx_normalize(_fetch_vulnx_for_cve(cve_id))

            entry = _build_entry(cve_id, shodan=shodan, pocs=pocs, nvd=nvd,
                                 edb=edb_matches, marcio=marcio_matches, vulnx=vulnx_rec)
            eq.put({"type": "cve_result", "entry": entry})
            eq.put({"type": "status", "msg": f"Found {len(pocs)} GitHub PoC(s), {len(edb_matches)} Exploit-DB, {len(marcio_matches)} 0xMarcio entries for {cve_id}"})
        else:
            eq.put({"type": "status", "msg": f"Searching NVD for '{query}'..."})
            vulns = _fetch_nvd_search(query, limit)
            eq.put({"type": "status", "msg": f"Found {len(vulns)} CVEs, enriching..."})

            for v in vulns:
                cve_obj = v.get("cve", {})
                cve_id = cve_obj.get("id", "")
                if not cve_id:
                    continue
                pocs = _fetch_poc_for_cve(cve_id)
                time.sleep(0.2)
                entry = _build_entry(cve_id, pocs=pocs, nvd=cve_obj)
                eq.put({"type": "cve_result", "entry": entry})

        eq.put({"type": "status", "msg": "Search complete"})
    except Exception as e:
        eq.put({"type": "error", "msg": str(e)})
    finally:
        eq.put(None)


# ── API Routes ───────────────────────────────────────────────────────────────

@cve_bp.route("/api/cve/start", methods=["POST"])
def cve_start():
    body = request.get_json(silent=True) or {}
    mode = body.get("mode", "feed")  # feed | search
    search_query = (body.get("query") or "").strip()
    days = int(body.get("days", 7))
    limit = min(int(body.get("limit", 80)), 200)

    if mode == "search" and not search_query:
        return jsonify({"error": "query required for search mode"}), 400

    eq = queue.Queue()
    scan_id = str(uuid.uuid4())[:8]

    with _lock:
        _scans[scan_id] = {"done": False, "events": [], "mode": mode}

    def _buffer():
        while True:
            try:
                item = eq.get(timeout=300)
                with _lock:
                    if scan_id in _scans:
                        _scans[scan_id]["events"].append(item)
                if item is None:
                    with _lock:
                        if scan_id in _scans:
                            _scans[scan_id]["done"] = True
                    break
            except queue.Empty:
                pass

    threading.Thread(target=_buffer, daemon=True).start()

    if mode == "search":
        threading.Thread(target=_run_search, daemon=True, args=(eq, search_query, limit)).start()
    else:
        threading.Thread(target=_run_live_feed, daemon=True, args=(eq, days, limit)).start()

    return jsonify({"scan_id": scan_id, "mode": mode})


@cve_bp.route("/api/cve/stream/<scan_id>")
@login_required
def cve_stream(scan_id):
    with _lock:
        scan = _scans.get(scan_id)
    if not scan:
        return jsonify({"error": "scan not found"}), 404

    def generate():
        offset = 0
        last_ka = time.time()
        while True:
            with _lock:
                scan = _scans.get(scan_id)
                if not scan:
                    break
                events = scan["events"]
                done = scan["done"]

            while offset < len(events):
                item = events[offset]
                offset += 1
                if item is None:
                    yield f"data: {json.dumps({'type': 'done'})}\n\n"
                    return
                yield f"data: {json.dumps(item)}\n\n"

            if done:
                yield f"data: {json.dumps({'type': 'done'})}\n\n"
                return

            now = time.time()
            if now - last_ka > 25:
                yield f"data: {json.dumps({'type': 'keepalive'})}\n\n"
                last_ka = now

            time.sleep(0.05)

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@cve_bp.route("/api/cve/stop/<scan_id>", methods=["POST"])
def cve_stop(scan_id):
    with _lock:
        scan = _scans.get(scan_id)
    if scan and not scan["done"]:
        scan["done"] = True
    return jsonify({"stopped": True})
