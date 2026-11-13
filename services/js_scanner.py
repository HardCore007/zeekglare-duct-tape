"""JS Intel — multi-tool JS endpoint and URL discovery pipeline."""
import os, re, shutil, subprocess, queue, json, requests, urllib3, tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Proxy-aware subprocess shim — see services/domain_mapper.py for rationale.
# `requests` is already covered by core.proxy_config.install_requests_patch().
try:
    from core.proxy_config import wrap_cmd as _pxy_wrap
    _sp_orig_run   = subprocess.run
    _sp_orig_Popen = subprocess.Popen
    class _ProxyAwareSP:
        run    = staticmethod(lambda cmd, *a, **kw: _sp_orig_run(_pxy_wrap(cmd),   *a, **kw))
        Popen  = staticmethod(lambda cmd, *a, **kw: _sp_orig_Popen(_pxy_wrap(cmd), *a, **kw))
        PIPE               = subprocess.PIPE
        DEVNULL            = subprocess.DEVNULL
        STDOUT             = subprocess.STDOUT
        CalledProcessError = subprocess.CalledProcessError
        TimeoutExpired     = subprocess.TimeoutExpired
    subprocess = _ProxyAwareSP
except Exception:
    pass

# ── Tool paths ────────────────────────────────────────────────────────────────
LINKFINDER    = "/home/daud/Tools/LinkFinder/linkfinder.py"
_GOLINKFINDER = shutil.which("GoLinkFinder") or os.path.expanduser("~/go/bin/GoLinkFinder")
_JSLUICE      = shutil.which("jsluice")      or os.path.expanduser("~/go/bin/jsluice")
_JSLEAK       = shutil.which("jsleak")       or os.path.expanduser("~/go/bin/jsleak")
_GETJS        = shutil.which("getJS")        or os.path.expanduser("~/go/bin/getJS")
_GAU          = shutil.which("gau")          or os.path.expanduser("~/go/bin/gau")
_WAYBACKURLS  = shutil.which("waybackurls")  or os.path.expanduser("~/go/bin/waybackurls")
_URLFINDER    = shutil.which("urlfinder")    or os.path.expanduser("~/go/bin/urlfinder")
_WAYMORE      = shutil.which("waymore")
_XNLINKFINDER = shutil.which("xnLinkFinder")

_TOOLS_DIR     = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "xploiter-tools")
_SECRETFINDER  = os.path.join(_TOOLS_DIR, "SecretFinder", "SecretFinder.py")
_JSANALYZER    = shutil.which("JSAnalyzer") or os.path.join(_TOOLS_DIR, "JSAnalyzer", "JSAnalyzer.py")

_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120 Safari/537.36"

# ── Regex filters ─────────────────────────────────────────────────────────────
_HOT_RE = re.compile(
    r'(api[_\-]?key|apikey|secret|token|password|passwd|auth|bearer|oauth|'
    r'access[_\-]?key|private[_\-]?key|client[_\-]?secret|aws|s3[._]|'
    r'firebase|stripe|twilio|sendgrid|slack|webhook|graphql|/admin|'
    r'/internal|/v[0-9]+/|\.env|config\.|/api/|/auth/|/login|/signup|'
    r'/reset|/panel|/dashboard|/debug|/test|/upload|/export|/import)',
    re.IGNORECASE,
)
_KEEP_RE  = re.compile(r'^(https?://|/[a-zA-Z0-9_\-]|\.{1,2}/[a-zA-Z0-9_\-])')
_NOISE_RE = re.compile(
    r'^(text/|image/|application/x-www|multipart/|video/|audio/|'
    r'http://www\.w3\.org|Running against|Usage:|Error:|font/)',
    re.IGNORECASE,
)


def _ep_ok(ep):
    """Return True if this line looks like a real endpoint."""
    ep = ep.strip()
    if not ep or len(ep) < 3:
        return False
    if _NOISE_RE.match(ep):
        return False
    if ep.startswith("Usage") or "Error:" in ep:
        return False
    if not _KEEP_RE.match(ep):
        return False
    if re.match(r'^[\d\-]*[a-f0-9]{8,}\.(js|css|map)$', ep):
        return False
    return True


# ── HTTP helpers ──────────────────────────────────────────────────────────────

def _fetch_page(url, timeout=15):
    try:
        r = requests.get(url, timeout=timeout, verify=False,
                         headers={"User-Agent": _UA}, allow_redirects=True)
        return r.text if r.status_code == 200 else None
    except Exception:
        return None


def _extract_js_urls(html, base_url):
    """Extract JS src URLs from an HTML page."""
    seen, urls = set(), []
    for m in re.finditer(
        r'<script[^>]+src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']',
        html, re.IGNORECASE
    ):
        raw  = m.group(1).strip()
        full = raw if raw.startswith("http") else urljoin(base_url, raw)
        if full not in seen:
            seen.add(full)
            urls.append(full)
    return urls


# ── JS Analyzers (per JS file) ────────────────────────────────────────────────

def _run_linkfinder(js_url, timeout=25):
    if not os.path.isfile(LINKFINDER):
        return []
    try:
        proc = subprocess.run(
            ["python3", LINKFINDER, "-i", js_url, "-o", "cli"],
            capture_output=True, text=True, timeout=timeout,
        )
        return [ep.strip() for ep in proc.stdout.splitlines() if _ep_ok(ep.strip())]
    except Exception:
        return []


def _run_golinkfinder(js_url, timeout=20):
    if not (_GOLINKFINDER and os.path.isfile(_GOLINKFINDER)):
        return []
    try:
        proc = subprocess.run(
            [_GOLINKFINDER, "-d", js_url],
            capture_output=True, text=True, timeout=timeout,
        )
        return [ep.strip() for ep in proc.stdout.splitlines() if _ep_ok(ep.strip())]
    except Exception:
        return []


def _run_jsluice(js_url, timeout=20):
    if not (_JSLUICE and os.path.isfile(_JSLUICE)):
        return []
    try:
        r = requests.get(js_url, timeout=15, verify=False, headers={"User-Agent": _UA})
        if r.status_code != 200:
            return []
        proc = subprocess.run(
            [_JSLUICE, "urls"],
            input=r.text, capture_output=True, text=True, timeout=timeout,
        )
        results = []
        for line in proc.stdout.splitlines():
            try:
                obj = json.loads(line)
                url = obj.get("url") or obj.get("value") or ""
                if url and _ep_ok(url):
                    results.append(url)
            except Exception:
                if _ep_ok(line.strip()):
                    results.append(line.strip())
        return results
    except Exception:
        return []


def _run_jsleak(js_url, timeout=20):
    if not (_JSLEAK and os.path.isfile(_JSLEAK)):
        return []
    try:
        proc = subprocess.run(
            [_JSLEAK, "-u", js_url, "-s"],
            capture_output=True, text=True, timeout=timeout,
        )
        results = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if line and len(line) > 3 and not line.startswith("["):
                results.append(line)
        return results
    except Exception:
        return []


def _run_xnlinkfinder(js_url, timeout=30):
    if not (_XNLINKFINDER and os.path.isfile(_XNLINKFINDER)):
        return []
    try:
        proc = subprocess.run(
            [_XNLINKFINDER, "-i", js_url, "-o", "cli", "-sp", js_url, "-sf"],
            capture_output=True, text=True, timeout=timeout,
        )
        return [ep.strip() for ep in proc.stdout.splitlines() if _ep_ok(ep.strip())]
    except Exception:
        return []


def _run_secretfinder(js_url, timeout=25):
    if not os.path.isfile(_SECRETFINDER):
        return []
    try:
        venv_py = os.path.join(os.path.dirname(_SECRETFINDER), ".venv", "bin", "python3")
        py = venv_py if os.path.isfile(venv_py) else "python3"
        proc = subprocess.run(
            [py, _SECRETFINDER, "-i", js_url, "-o", "cli"],
            capture_output=True, text=True, timeout=timeout,
        )
        return [ep.strip() for ep in proc.stdout.splitlines() if ep.strip() and _ep_ok(ep.strip())]
    except Exception:
        return []


def _run_jsanalyzer(js_url, timeout=25):
    if not os.path.isfile(_JSANALYZER):
        return []
    try:
        venv_py = os.path.join(os.path.dirname(_JSANALYZER), ".venv", "bin", "python3")
        py = venv_py if os.path.isfile(venv_py) else "python3"
        proc = subprocess.run(
            [py, _JSANALYZER, "-u", js_url],
            capture_output=True, text=True, timeout=timeout,
        )
        results = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if line and not line.startswith(("[", "=", "-", "#")) and _ep_ok(line):
                results.append(line)
        return results
    except Exception:
        return []


# ── JS File Finders ───────────────────────────────────────────────────────────

def _run_getjs(base_url, timeout=30):
    """Use getJS to find all JS files on a URL."""
    if not (_GETJS and os.path.isfile(_GETJS)):
        return []
    try:
        proc = subprocess.run(
            [_GETJS, "--url", base_url, "--complete"],
            capture_output=True, text=True, timeout=timeout,
        )
        urls = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if line.startswith("http") and ".js" in line:
                urls.append(line)
        return urls
    except Exception:
        return []


# ── URL Harvesters (per domain) ───────────────────────────────────────────────

def _run_gau(domain, timeout=60):
    if not (_GAU and os.path.isfile(_GAU)):
        return []
    try:
        proc = subprocess.run(
            [_GAU, "--blacklist", "png,jpg,gif,css,woff,woff2,ttf,svg,ico",
             "--threads", "5", domain],
            capture_output=True, text=True, timeout=timeout,
        )
        return [l.strip() for l in proc.stdout.splitlines() if l.strip().startswith("http")]
    except Exception:
        return []


def _run_waybackurls(domain, timeout=60):
    if not (_WAYBACKURLS and os.path.isfile(_WAYBACKURLS)):
        return []
    try:
        proc = subprocess.run(
            [_WAYBACKURLS, domain],
            capture_output=True, text=True, timeout=timeout,
        )
        return [l.strip() for l in proc.stdout.splitlines() if l.strip().startswith("http")]
    except Exception:
        return []


def _run_waymore(domain, timeout=120):
    if not (_WAYMORE and os.path.isfile(_WAYMORE)):
        return []
    try:
        with tempfile.TemporaryDirectory() as tmp:
            proc = subprocess.run(
                [_WAYMORE, "-i", domain, "-mode", "U", "-oU",
                 os.path.join(tmp, "out.txt")],
                capture_output=True, text=True, timeout=timeout,
            )
            out_file = os.path.join(tmp, "out.txt")
            if not os.path.isfile(out_file):
                return []
            with open(out_file, "r", errors="ignore") as f:
                return [l.strip() for l in f if l.strip().startswith("http")]
    except Exception:
        return []


def _run_urlfinder(domain, timeout=60):
    if not (_URLFINDER and os.path.isfile(_URLFINDER)):
        return []
    try:
        proc = subprocess.run(
            [_URLFINDER, "-d", domain, "-silent", "-all"],
            capture_output=True, text=True, timeout=timeout,
        )
        return [l.strip() for l in proc.stdout.splitlines() if l.strip().startswith("http")]
    except Exception:
        return []


# ── Main Scanner class ────────────────────────────────────────────────────────

_ALL_JS_ANALYZERS  = {"linkfinder", "golinkfinder", "jsluice", "jsleak", "xnlinkfinder", "secretfinder", "jsanalyzer"}
_ALL_JS_FINDERS    = {"getjs"}
_ALL_URL_HARVESTERS = {"gau", "waybackurls", "waymore", "urlfinder"}


class JsScanner:
    def __init__(self, domain, live_domains, event_queue=None,
                 max_domains=30, max_js_per_domain=25, threads=5,
                 enabled_tools=None):
        self.domain       = domain
        self.live_domains = live_domains[:max_domains]
        self._eq          = event_queue or queue.Queue()
        self.max_js       = max_js_per_domain
        self.threads      = threads
        # None = all enabled
        self._tools = set(enabled_tools) if enabled_tools is not None else None

    def emit(self, data):
        self._eq.put(data)

    def _on(self, tool):
        return self._tools is None or tool in self._tools

    # ── URL harvesting for a domain ───────────────────────────────────────────

    def _harvest_urls(self, host):
        """Run enabled URL harvesters, return list of {url, source} dicts."""
        all_urls = []
        seen     = set()

        def _add(urls, source):
            for u in urls:
                if u not in seen:
                    seen.add(u)
                    all_urls.append({"url": u, "source": source})

        harvester_fns = [
            ("gau",         _run_gau),
            ("waybackurls", _run_waybackurls),
            ("waymore",     _run_waymore),
            ("urlfinder",   _run_urlfinder),
        ]
        active = [(name, fn) for name, fn in harvester_fns if self._on(name)]
        if not active:
            return all_urls

        self.emit({"type": "harvest_start", "host": host,
                   "tools": [n for n, _ in active]})
        for name, fn in active:
            try:
                urls = fn(host)
                _add(urls, name)
                self.emit({"type": "harvest_tool_done", "host": host,
                           "tool": name, "count": len(urls)})
            except Exception:
                pass

        return all_urls

    # ── per-domain JS analysis pipeline ──────────────────────────────────────

    def _scan_domain(self, host):
        self.emit({"type": "js_domain_start", "host": host})

        # Build base URL
        base_url = f"https://{host}"
        html     = _fetch_page(base_url)
        if html is None:
            base_url = f"http://{host}"
            html     = _fetch_page(base_url)

        # Find JS files — prefer getJS if enabled, then HTML scrape
        js_urls = []
        if self._on("getjs") and html is not None:
            gjs = _run_getjs(base_url)
            if gjs:
                js_urls = gjs
        if not js_urls and html is not None:
            js_urls = _extract_js_urls(html, base_url)
        js_urls = js_urls[: self.max_js]

        if js_urls:
            self.emit({"type": "js_urls_found", "host": host,
                       "count": len(js_urls), "urls": js_urls})

        # Run URL harvesters in parallel with JS analysis
        harvest_result = []
        if any(self._on(t) for t in _ALL_URL_HARVESTERS):
            harvest_result = self._harvest_urls(host)

        # Analyze each JS file
        all_endpoints, interesting, seen_ep = [], [], set()

        def _analyze(url):
            eps = []
            if self._on("linkfinder"):
                eps += [(ep, "linkfinder") for ep in _run_linkfinder(url)]
            if self._on("golinkfinder"):
                eps += [(ep, "golinkfinder") for ep in _run_golinkfinder(url)]
            if self._on("jsluice"):
                eps += [(ep, "jsluice") for ep in _run_jsluice(url)]
            if self._on("jsleak"):
                eps += [(ep, "jsleak") for ep in _run_jsleak(url)]
            if self._on("xnlinkfinder"):
                eps += [(ep, "xnlinkfinder") for ep in _run_xnlinkfinder(url)]
            if self._on("secretfinder"):
                eps += [(ep, "secretfinder") for ep in _run_secretfinder(url)]
            if self._on("jsanalyzer"):
                eps += [(ep, "jsanalyzer") for ep in _run_jsanalyzer(url)]
            return url, eps

        if js_urls:
            with ThreadPoolExecutor(max_workers=min(5, len(js_urls))) as ex:
                for url, eps in ex.map(_analyze, js_urls):
                    for ep, tool in eps:
                        if ep not in seen_ep:
                            seen_ep.add(ep)
                            entry = {"endpoint": ep, "source_js": url, "tool": tool}
                            all_endpoints.append(entry)
                            if _HOT_RE.search(ep):
                                interesting.append(entry)

        # Add harvested URLs as endpoints
        for item in harvest_result:
            u = item["url"]
            if u not in seen_ep:
                seen_ep.add(u)
                entry = {"endpoint": u, "source_js": host,
                         "tool": item["source"], "harvested": True}
                all_endpoints.append(entry)
                if _HOT_RE.search(u):
                    interesting.append(entry)

        if not js_urls and not all_endpoints:
            self.emit({"type": "js_domain_done", "host": host,
                       "js_urls": [], "endpoints": [], "interesting": []})
            return

        self.emit({
            "type":        "js_domain_done",
            "host":        host,
            "js_urls":     js_urls,
            "endpoints":   all_endpoints,
            "interesting": interesting,
        })

    # ── main ─────────────────────────────────────────────────────────────────

    def run(self):
        self.emit({"type": "js_scan_start", "domain": self.domain,
                   "total": len(self.live_domains)})

        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futs = {ex.submit(self._scan_domain, h): h
                    for h in self.live_domains}
            for fut in as_completed(futs):
                try:
                    fut.result()
                except Exception:
                    pass

        self.emit({"type": "js_scan_done", "domain": self.domain})
        self._eq.put(None)
