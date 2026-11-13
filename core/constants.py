"""Shared constants for ZeekGlare."""

CAT_COLORS = {
    "government":    "#e05252",
    "military":      "#d97706",
    "finance":       "#f59e0b",
    "telecom":       "#8b5cf6",
    "grid_station":  "#f97316",
    "critical_infra":"#ec4899",
    "health":        "#10b981",
    "cyber_security":"#06b6d4",
    "education":     "#3b82f6",
    "commercial":    "#334e68",
}

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

TECH_PATTERNS = {
    "Server":            lambda v: v.split("/")[0].strip() if v else "",
    "X-Powered-By":      lambda v: v.strip(),
    "X-Generator":       lambda v: v.strip(),
    "X-Drupal-Cache":    lambda v: "Drupal",
    "X-Shopify-Stage":   lambda v: "Shopify",
    "X-Wix-Request-Id":  lambda v: "Wix",
    "X-WordPress-Cache": lambda v: "WordPress",
}

WAF_SIGNATURES = {
    "cf-ray":               "Cloudflare",
    "x-sucuri-id":          "Sucuri",
    "x-cache-status":       "Varnish",
    "x-akamai-transformed": "Akamai",
    "x-amzn-requestid":     "AWS",
    "x-azure-ref":          "Azure",
    "x-cdn":                lambda v: f"CDN:{v}",
}

CMS_SIGNATURES = {
    "wp-content":      "WordPress",
    "wp-includes":     "WordPress",
    "/sites/default/": "Drupal",
    "joomla":          "Joomla",
    "typo3":           "TYPO3",
    "magento":         "Magento",
    "shopify":         "Shopify",
}

CLOUD_SIGNATURES = {
    "amazonaws.com":     "AWS",
    "azurewebsites.net": "Azure",
    "cloudapp.net":      "Azure",
    "appspot.com":       "GCP",
    "cloudfunctions.net":"GCP",
    "cloudflare":        "Cloudflare",
    "fastly":            "Fastly",
    "akamai":            "Akamai",
}

INTERESTING_PATHS = [
    "/admin", "/login", "/.env", "/backup", "/.git",
    "/api", "/swagger", "/phpmyadmin", "/wp-admin",
]

# Common reconftw install locations
RECONFTW_PATHS = [
    "/opt/reconftw/reconftw.sh",
    "/root/reconftw/reconftw.sh",
    "/home/user/reconftw/reconftw.sh",
    "./reconftw/reconftw.sh",
]
