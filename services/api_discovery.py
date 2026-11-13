"""API Endpoint Discovery — scan for common API paths, frameworks, misconfigs."""
import urllib.request, urllib.error, json, concurrent.futures, ssl

# Common API paths to probe
API_PATHS = [
    # Swagger / OpenAPI
    "/swagger.json", "/swagger-ui.html", "/swagger-ui/", "/api-docs",
    "/openapi.json", "/openapi.yaml", "/v2/api-docs", "/v3/api-docs",
    "/swagger/v1/swagger.json", "/swagger/index.html",
    # GraphQL
    "/graphql", "/graphiql", "/altair", "/playground",
    "/api/graphql", "/v1/graphql",
    # Common API versioned endpoints
    "/api/", "/api/v1/", "/api/v2/", "/api/v3/",
    "/rest/", "/rest/v1/", "/rest/v2/",
    # Well-known
    "/.well-known/openid-configuration",
    "/.well-known/security.txt",
    "/.well-known/change-password",
    "/.well-known/assetlinks.json",
    # Config / debug
    "/actuator", "/actuator/health", "/actuator/env", "/actuator/info",
    "/debug", "/debug/vars", "/debug/pprof/",
    "/_debug/", "/phpinfo.php",
    "/server-status", "/server-info",
    "/elmah.axd", "/trace.axd",
    # Auth endpoints
    "/oauth/token", "/oauth/authorize", "/token",
    "/auth/login", "/auth/register",
    "/wp-json/wp/v2/users",
    # Common frameworks
    "/rails/info", "/admin/", "/administrator/",
    "/__docusaurus/", "/wp-admin/",
    "/sitemap.xml", "/robots.txt",
]

# Signatures to identify API frameworks
FRAMEWORK_SIGS = {
    "swagger": ["swagger", "openapi"],
    "graphql": ["graphql", "GraphiQL", "__schema"],
    "spring-actuator": ["actuator", "spring-boot"],
    "rails": ["X-Runtime", "X-Request-Id"],
    "django": ["csrfmiddlewaretoken", "django"],
    "laravel": ["laravel_session", "XSRF-TOKEN"],
    "express": ["X-Powered-By: Express"],
    "fastapi": ["fastapi", "starlette"],
    "asp.net": ["X-AspNet-Version", "__VIEWSTATE"],
    "wordpress": ["wp-json", "WordPress"],
}

_ctx = ssl.create_default_context()
_ctx.check_hostname = False
_ctx.verify_mode = ssl.CERT_NONE


def _probe_path(base_url, path):
    """Probe a single path and return result if interesting."""
    url = base_url.rstrip("/") + path
    try:
        req = urllib.request.Request(url, method="GET",
                                    headers={"User-Agent": "Mozilla/5.0 ZeekGlare/1.0"})
        with urllib.request.urlopen(req, timeout=8, context=_ctx) as r:
            status = r.status
            headers = dict(r.headers)
            body = r.read(4096).decode(errors="ignore")
            ct = headers.get("Content-Type", "")

            # Determine what we found
            finding = {
                "path": path, "url": url, "status": status,
                "content_type": ct, "risk": "info", "finding": "",
            }

            # Check for exposed APIs
            if "swagger" in body.lower() or "openapi" in body.lower():
                finding["finding"] = "Swagger/OpenAPI documentation exposed"
                finding["risk"] = "high"
            elif "graphql" in path.lower() and status == 200:
                finding["finding"] = "GraphQL endpoint accessible"
                finding["risk"] = "medium"
            elif "graphiql" in body.lower() or "GraphiQL" in body:
                finding["finding"] = "GraphiQL IDE exposed"
                finding["risk"] = "high"
            elif "/actuator" in path and status == 200:
                finding["finding"] = "Spring Actuator endpoint exposed"
                finding["risk"] = "critical" if "env" in path else "high"
            elif "phpinfo" in path and "PHP Version" in body:
                finding["finding"] = "PHPInfo page exposed"
                finding["risk"] = "high"
            elif "server-status" in path and "Apache" in body:
                finding["finding"] = "Apache server-status exposed"
                finding["risk"] = "medium"
            elif "wp-json/wp/v2/users" in path and status == 200:
                finding["finding"] = "WordPress user enumeration"
                finding["risk"] = "medium"
            elif "security.txt" in path and status == 200:
                finding["finding"] = "Security.txt found"
                finding["risk"] = "info"
            elif "robots.txt" in path and status == 200:
                finding["finding"] = "Robots.txt found"
                finding["risk"] = "info"
            elif "sitemap" in path and status == 200:
                finding["finding"] = "Sitemap found"
                finding["risk"] = "info"
            elif status == 200 and "application/json" in ct:
                finding["finding"] = "JSON API endpoint"
                finding["risk"] = "low"
            elif status == 200:
                finding["finding"] = "Accessible endpoint"
                finding["risk"] = "info"
            else:
                return None

            # Detect frameworks from headers/body
            frameworks = []
            for fw, sigs in FRAMEWORK_SIGS.items():
                hdr_str = str(headers)
                if any(s.lower() in body.lower() or s.lower() in hdr_str.lower() for s in sigs):
                    frameworks.append(fw)
            finding["frameworks"] = frameworks

            return finding

    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            return {"path": path, "url": url, "status": e.code,
                    "content_type": "", "risk": "low",
                    "finding": f"Protected endpoint ({e.code})",
                    "frameworks": []}
        return None
    except Exception:
        return None


def discover_api_endpoints(target_url, eq=None):
    """Scan a target URL for API endpoints.
    target_url: base URL (e.g. https://example.com)
    eq: optional queue for SSE events
    Returns list of findings.
    """
    if not target_url.startswith("http"):
        target_url = "https://" + target_url

    results = []
    if eq:
        eq.put({"type": "api_status", "msg": f"Probing {len(API_PATHS)} API paths on {target_url}..."})

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        futures = {pool.submit(_probe_path, target_url, p): p for p in API_PATHS}
        done = 0
        for fut in concurrent.futures.as_completed(futures):
            done += 1
            r = fut.result()
            if r:
                results.append(r)
                if eq:
                    eq.put({"type": "api_result", "entry": r})
            if eq and done % 10 == 0:
                eq.put({"type": "api_status", "msg": f"Probed {done}/{len(API_PATHS)} paths..."})

    # Sort by risk
    risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    results.sort(key=lambda x: risk_order.get(x.get("risk", "info"), 4))

    if eq:
        eq.put({"type": "api_status", "msg": f"Done — {len(results)} endpoints found"})

    return results
