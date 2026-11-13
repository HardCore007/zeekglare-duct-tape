"""CVE Lookup — NVD API v2 (free, no key required for basic queries)."""
import requests as _req, re, time

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Tech → search keyword mappings
TECH_CVE_MAP = {
    "apache":     "Apache HTTP Server",
    "nginx":      "nginx",
    "iis":        "Microsoft IIS",
    "wordpress":  "WordPress",
    "drupal":     "Drupal",
    "joomla":     "Joomla",
    "php":        "PHP",
    "python":     "Python",
    "node":       "Node.js",
    "express":    "Express",
    "django":     "Django",
    "flask":      "Flask",
    "tomcat":     "Apache Tomcat",
    "spring":     "Spring Framework",
    "mysql":      "MySQL",
    "postgresql": "PostgreSQL",
    "mongodb":    "MongoDB",
    "redis":      "Redis",
    "elasticsearch": "Elasticsearch",
    "openssl":    "OpenSSL",
    "jquery":     "jQuery",
    "react":      "React",
    "angular":    "Angular",
    "vue":        "Vue.js",
    "shopify":    "Shopify",
    "magento":    "Magento",
}

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}


def lookup_cves(tech_list: list, max_per_tech: int = 5) -> dict:
    """
    Given a list of tech strings (e.g. ['Apache/2.4.51', 'PHP/8.0']),
    return a dict of tech → [CVE records].
    """
    results = {}
    seen_cves = set()

    for tech_raw in tech_list:
        if not tech_raw:
            continue
        key = tech_raw.lower().split("/")[0].split(" ")[0]
        keyword = TECH_CVE_MAP.get(key, tech_raw.split("/")[0])

        # Extract version if present
        version = ""
        m = re.search(r"[/\s](\d+[\.\d]+)", tech_raw)
        if m:
            version = m.group(1)

        try:
            params = {
                "keywordSearch": keyword,
                "resultsPerPage": max_per_tech * 2,
                "startIndex": 0,
            }
            if version:
                params["keywordSearch"] = f"{keyword} {version}"

            r = _req.get(NVD_BASE, params=params, timeout=15,
                         headers={"Accept": "application/json"})
            if r.status_code != 200:
                continue

            cves = []
            for item in r.json().get("vulnerabilities", []):
                cve = item.get("cve", {})
                cve_id = cve.get("id", "")
                if cve_id in seen_cves:
                    continue
                seen_cves.add(cve_id)

                metrics = cve.get("metrics", {})
                cvss_v3 = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", []))
                score = severity = ""
                if cvss_v3:
                    cvss_data = cvss_v3[0].get("cvssData", {})
                    score     = cvss_data.get("baseScore", "")
                    severity  = cvss_data.get("baseSeverity", "")

                descs = cve.get("descriptions", [])
                desc  = next((d["value"] for d in descs if d.get("lang") == "en"), "")[:300]

                refs = [r.get("url", "") for r in cve.get("references", [])[:3]]

                cves.append({
                    "id":          cve_id,
                    "score":       score,
                    "severity":    severity,
                    "description": desc,
                    "refs":        refs,
                    "published":   cve.get("published", "")[:10],
                })
                if len(cves) >= max_per_tech:
                    break

            # Sort by severity
            cves.sort(key=lambda c: SEVERITY_ORDER.get(c.get("severity", ""), 0), reverse=True)
            if cves:
                results[tech_raw] = cves

            time.sleep(0.6)  # NVD rate limit: ~10 req/s without key
        except Exception:
            pass

    return results
