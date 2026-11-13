"""Cloud Asset Discovery — enumerate S3, Azure Blobs, GCP Storage for a target org."""
import urllib.request, urllib.error, json, re, concurrent.futures

# Common bucket/blob naming patterns
_PATTERNS = [
    "{org}", "{org}-dev", "{org}-staging", "{org}-prod", "{org}-backup",
    "{org}-assets", "{org}-data", "{org}-media", "{org}-static",
    "{org}-uploads", "{org}-logs", "{org}-public", "{org}-private",
    "{org}-internal", "{org}-test", "{org}-api", "{org}-cdn",
    "{org}-www", "{org}-web", "{org}-app", "{org}-files",
]


def _check_s3(name):
    """Check if an S3 bucket exists and its access level."""
    url = f"https://{name}.s3.amazonaws.com/"
    try:
        req = urllib.request.Request(url, method="HEAD",
                                    headers={"User-Agent": "ZeekGlare/1.0"})
        with urllib.request.urlopen(req, timeout=5) as r:
            return {"name": name, "provider": "AWS S3", "url": url,
                    "status": r.status, "access": "PUBLIC", "risk": "critical"}
    except urllib.error.HTTPError as e:
        if e.code == 403:
            return {"name": name, "provider": "AWS S3", "url": url,
                    "status": 403, "access": "EXISTS (private)", "risk": "info"}
        return None
    except Exception:
        return None


def _check_azure(name):
    """Check if an Azure Blob container exists."""
    url = f"https://{name}.blob.core.windows.net/?comp=list"
    try:
        req = urllib.request.Request(url, method="GET",
                                    headers={"User-Agent": "ZeekGlare/1.0"})
        with urllib.request.urlopen(req, timeout=5) as r:
            body = r.read(500).decode(errors="ignore")
            if "<EnumerationResults" in body:
                return {"name": name, "provider": "Azure Blob", "url": url,
                        "status": 200, "access": "PUBLIC LISTING", "risk": "critical"}
            return {"name": name, "provider": "Azure Blob", "url": url,
                    "status": 200, "access": "PUBLIC", "risk": "high"}
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        return {"name": name, "provider": "Azure Blob", "url": url,
                "status": e.code, "access": "EXISTS (private)", "risk": "info"}
    except Exception:
        return None


def _check_gcp(name):
    """Check if a GCP Storage bucket exists."""
    url = f"https://storage.googleapis.com/{name}/"
    try:
        req = urllib.request.Request(url, method="GET",
                                    headers={"User-Agent": "ZeekGlare/1.0"})
        with urllib.request.urlopen(req, timeout=5) as r:
            return {"name": name, "provider": "GCP Storage", "url": url,
                    "status": 200, "access": "PUBLIC", "risk": "critical"}
    except urllib.error.HTTPError as e:
        if e.code == 403:
            return {"name": name, "provider": "GCP Storage", "url": url,
                    "status": 403, "access": "EXISTS (private)", "risk": "info"}
        return None
    except Exception:
        return None


def enumerate_cloud_assets(org_name, eq=None):
    """Enumerate cloud storage assets for an organization.
    org_name: base organization name (e.g. 'acmecorp')
    eq: optional queue for progress events
    Returns list of found assets.
    """
    org = re.sub(r"[^a-z0-9-]", "", org_name.lower().strip())
    if not org:
        return []

    names = list(set(p.format(org=org) for p in _PATTERNS))
    results = []

    checks = []
    for name in names:
        checks.append(("s3", name))
        checks.append(("azure", name))
        checks.append(("gcp", name))

    if eq:
        eq.put({"type": "cloud_status", "msg": f"Checking {len(names)} name patterns across 3 providers ({len(checks)} total checks)..."})

    def _do_check(item):
        provider, name = item
        if provider == "s3":
            return _check_s3(name)
        elif provider == "azure":
            return _check_azure(name)
        else:
            return _check_gcp(name)

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        futures = {pool.submit(_do_check, c): c for c in checks}
        done_count = 0
        for fut in concurrent.futures.as_completed(futures):
            done_count += 1
            r = fut.result()
            if r:
                results.append(r)
                if eq:
                    eq.put({"type": "cloud_result", "entry": r})
            if eq and done_count % 15 == 0:
                eq.put({"type": "cloud_status", "msg": f"Checked {done_count}/{len(checks)}..."})

    if eq:
        eq.put({"type": "cloud_status", "msg": f"Done — found {len(results)} assets"})

    return results
