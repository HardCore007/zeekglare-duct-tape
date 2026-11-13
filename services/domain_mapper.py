"""DomainMapper — ars0n-style subdomain pipeline with HTTP probing."""
import socket, re, base64, uuid, queue, subprocess, json as _json, shutil, time as _time

# Proxy-aware subprocess shim: when the admin has enabled a SOCKS/HTTP proxy in
# Settings → Proxy, every `subprocess.run` / `subprocess.Popen` call in this
# file is transparently prefixed with `proxychains4 -q -f <conf>` so every Go /
# Ruby / Python subprocess (subfinder, amass, findomain, assetfinder, gau,
# whatweb, github-subdomains, etc.) tunnels through the proxy. No-op when the
# proxy is off — zero performance cost and no API changes elsewhere.
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
    subprocess = _ProxyAwareSP  # shadows the module-level name for this file
except Exception:
    pass
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import requests as _req
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_ANSI_RE = re.compile(r'\x1b\[[0-9;]*m')

import sys, os, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from asset_mapper import RIPE_STAT_BASE
from core.constants import (
    SECURITY_HEADERS, TECH_PATTERNS, WAF_SIGNATURES,
    CMS_SIGNATURES, CLOUD_SIGNATURES,
)
from core.session_manager import SessionManager


class DomainMapper:
    def __init__(self, domain, shodan_key=None, networksdb_key=None,
                 securitytrails_key=None, censys_id=None, censys_secret=None,
                 zoomeye_key=None, fofa_email=None, fofa_key=None,
                 github_token=None, c99_key=None,
                 chaos_key=None, gitlab_token=None,
                 argosdns_key=None,
                 enabled_sources=None,
                 event_queue=None, max_subs=10000, probe_http=True, use_bbot=True,
                 user_id=None, username=None):
        d = domain.strip().lower()
        if d.startswith("www."):
            d = d[4:]
        self.domain             = d
        self.shodan_key         = shodan_key
        self.networksdb_key     = networksdb_key
        self.securitytrails_key = securitytrails_key
        self.censys_id          = censys_id
        self.censys_secret      = censys_secret
        self.zoomeye_key        = zoomeye_key
        self.fofa_email         = fofa_email
        self.fofa_key           = fofa_key
        self.github_token       = github_token
        self.c99_key            = c99_key
        self.chaos_key          = chaos_key
        self.gitlab_token       = gitlab_token
        self.argosdns_key       = argosdns_key
        # None means all enabled; a list/set restricts to named sources
        self._enabled           = set(enabled_sources) if enabled_sources is not None else None
        self._eq                = event_queue or queue.Queue()
        self.max_subs           = int(max_subs) if max_subs else 10000
        self.do_probe           = bool(probe_http)
        self.use_bbot           = bool(use_bbot) and bool(shutil.which("bbot"))
        self._asn_cache         = {}
        self.user_id            = user_id
        self.username           = username or ""

    def emit(self, data):
        self._eq.put(data)

    def _get(self, url, params=None, headers=None, auth=None, timeout=20):
        try:
            r = _req.get(url, params=params, headers=headers, auth=auth,
                         timeout=timeout, verify=False)
            return r
        except Exception:
            return None

    # ── Subdomain Sources ─────────────────────────────────────────────────────

    def subdomains_crtsh(self):
        results = []
        r = self._get("https://crt.sh/", params={"q": f"%.{self.domain}", "output": "json"})
        if not r:
            return results
        try:
            for cert in r.json():
                for name in cert.get("name_value", "").split("\n"):
                    name = name.strip().lower().lstrip("*.")
                    if name.endswith(f".{self.domain}") or name == self.domain:
                        if "." in name and " " not in name:
                            results.append({
                                "domain":    name,
                                "source":    "crtsh",
                                "issuer":    cert.get("issuer_name", ""),
                                "not_after": cert.get("not_after", ""),
                            })
        except Exception:
            pass
        return results

    def subdomains_shodan(self):
        if not self.shodan_key:
            return []
        results = []
        r = self._get(
            f"https://api.shodan.io/dns/domain/{self.domain}",
            params={"key": self.shodan_key},
        )
        if not r:
            return results
        try:
            for sub in r.json().get("subdomains", []):
                full = f"{sub}.{self.domain}" if not sub.endswith(self.domain) else sub
                results.append({"domain": full.lower(), "source": "shodan"})
        except Exception:
            pass
        return results

    def subdomains_securitytrails(self):
        if not self.securitytrails_key:
            return []
        results = []
        r = self._get(
            f"https://api.securitytrails.com/v1/domain/{self.domain}/subdomains",
            headers={"APIKEY": self.securitytrails_key},
        )
        if not r:
            return results
        try:
            for sub in r.json().get("subdomains", []):
                full = f"{sub}.{self.domain}"
                results.append({"domain": full.lower(), "source": "securitytrails"})
        except Exception:
            pass
        return results

    def subdomains_argosdns(self):
        if not self.argosdns_key:
            return []
        results = []
        seen    = set()
        headers = {"Authorization": f"Bearer {self.argosdns_key}",
                   "Accept": "application/json"}
        page = 1
        for _ in range(10):
            r = self._get(
                "https://www.argosdns.io/api/v1/subdomains",
                params={"domain": self.domain, "per_page": 100, "page": page},
                headers=headers,
            )
            if not r or r.status_code != 200:
                break
            try:
                data = r.json()
            except Exception:
                break
            items = data.get("data") or data.get("subdomains") or data.get("results") or []
            if not items:
                break
            for it in items:
                name = it.get("subdomain") or it.get("domain") or it.get("name") or (it if isinstance(it, str) else "")
                if not name:
                    continue
                name = name.strip().lower().lstrip("*.")
                if not name or name in seen:
                    continue
                if not (name.endswith(f".{self.domain}") or name == self.domain):
                    continue
                seen.add(name)
                results.append({"domain": name, "source": "argosdns"})
            meta = data.get("meta") or data.get("pagination") or {}
            total_pages = meta.get("total_pages") or meta.get("last_page")
            if total_pages and page >= int(total_pages):
                break
            if len(items) < 100:
                break
            page += 1
            _time.sleep(0.2)
        return results

    def subdomains_censys(self):
        if not (self.censys_id and self.censys_secret):
            return []
        results = []
        seen    = set()
        auth    = (self.censys_id, self.censys_secret)

        def _add(name):
            name = name.strip().lower().lstrip("*.")
            if name and (name.endswith(f".{self.domain}") or name == self.domain) and name not in seen:
                seen.add(name)
                results.append({"domain": name, "source": "censys"})

        # ── Certificate search (paginated up to 5 pages) ──
        cursor = None
        for _ in range(5):
            params = {"q": f"parsed.names:{self.domain}", "per_page": 100}
            if cursor:
                params["cursor"] = cursor
            r = self._get(
                "https://search.censys.io/api/v2/certificates/search",
                params=params, auth=auth,
            )
            if not r or r.status_code != 200:
                break
            try:
                body    = r.json()
                res_obj = body.get("result", {})
                for hit in res_obj.get("hits", []):
                    for name in hit.get("parsed", {}).get("names", []):
                        _add(name)
                cursor = res_obj.get("links", {}).get("next")
                if not cursor:
                    break
            except Exception:
                break

        # ── Hosts search (DNS names associated with hosts) ──
        try:
            r2 = self._get(
                "https://search.censys.io/api/v2/hosts/search",
                params={"q": f"name.value: *.{self.domain}", "per_page": 100},
                auth=auth,
            )
            if r2 and r2.status_code == 200:
                for hit in r2.json().get("result", {}).get("hits", []):
                    for svc in hit.get("services", []):
                        for name in svc.get("tls", {}).get("certificates", {}).get("leaf_data", {}).get("names", []):
                            _add(name)
                    # reverse DNS
                    rdns = hit.get("dns", {}).get("reverse_dns", {}).get("names", [])
                    for name in rdns:
                        _add(name)
        except Exception:
            pass

        return results

    def subdomains_c99(self):
        """C99 SubdomainFinder — https://subdomainfinder.c99.nl/ — API key required."""
        if not self.c99_key:
            return []
        results = []
        seen    = set()
        r = self._get(
            "https://subdomainfinder.c99.nl/api.php",
            params={"key": self.c99_key, "domain": self.domain},
            timeout=30,
        )
        if not r or r.status_code != 200:
            return results
        try:
            data = r.json()
            if not data.get("success"):
                return results
            for sub in data.get("subdomains", []):
                name = sub.strip().lower().rstrip(".")
                if name and (name.endswith(f".{self.domain}") or name == self.domain) and name not in seen:
                    seen.add(name)
                    results.append({"domain": name, "source": "c99"})
        except Exception:
            pass
        return results

    def subdomains_zoomeye(self):
        if not self.zoomeye_key:
            return []
        results = []
        r = self._get(
            "https://api.zoomeye.org/web/search",
            params={"query": f"hostname:*.{self.domain}", "page": 1},
            headers={"Authorization": f"JWT {self.zoomeye_key}"},
        )
        if not r:
            return results
        try:
            for match in r.json().get("matches", []):
                for field in ("rdns", "site"):
                    val = match.get(field, "")
                    if val and (val.endswith(f".{self.domain}") or val == self.domain):
                        results.append({"domain": val.lower().strip(), "source": "zoomeye"})
        except Exception:
            pass
        return results

    def subdomains_fofa(self):
        if not (self.fofa_email and self.fofa_key):
            return []
        results = []
        try:
            query = f'domain="{self.domain}"'
            b64q  = base64.b64encode(query.encode()).decode()
            r = self._get(
                "https://fofa.info/api/v1/search/all",
                params={
                    "email":   self.fofa_email,
                    "key":     self.fofa_key,
                    "qbase64": b64q,
                    "size":    100,
                    "fields":  "host,ip,port",
                },
            )
            if not r:
                return results
            for item in r.json().get("results", []):
                host = item[0] if isinstance(item, list) else item.get("host", "")
                host = re.sub(r"^https?://", "", str(host)).split(":")[0].split("/")[0].lower()
                if host and (host.endswith(f".{self.domain}") or host == self.domain):
                    results.append({"domain": host, "source": "fofa"})
        except Exception:
            pass
        return results

    def subdomains_thc(self):
        """ip.thc.org passive reverse-DNS database — no API key required."""
        results = []
        seen    = set()
        url     = f"https://ip.thc.org/sb/{self.domain}"
        params  = {"l": 100}
        for _ in range(10):          # max 10 pages → 1 000 results
            r = self._get(url, params=params, timeout=15)
            if not r or r.status_code != 200:
                break
            next_cursor = None
            for line in r.text.splitlines():
                raw = _ANSI_RE.sub("", line).strip()
                if raw.startswith(";;Next Page:"):
                    part = raw.split("Next Page:")[-1].strip()
                    if "?p=" in part:
                        next_cursor = part.split("?p=")[-1].split("&")[0]
                elif raw and not raw.startswith(";"):
                    dom = raw.rstrip(".").lower()
                    if (dom.endswith(f".{self.domain}") or dom == self.domain) and dom not in seen:
                        seen.add(dom)
                        results.append({"domain": dom, "source": "thc"})
            if not next_cursor:
                break
            params = {"l": 100, "p": next_cursor}
            _time.sleep(2)           # 0.5 req/s rate limit
        return results

    def subdomains_rapiddns(self):
        """RapidDNS.io — passive DNS database — no API key required."""
        results = []
        seen    = set()
        r = self._get(
            f"https://rapiddns.io/subdomain/{self.domain}",
            params={"full": "1"},
            headers={"User-Agent": "Mozilla/5.0 ZeekGlare/1.0"},
            timeout=20,
        )
        if not r or r.status_code != 200:
            return results
        try:
            rows = re.findall(r'<tr[^>]*>(.*?)</tr>', r.text, re.DOTALL | re.IGNORECASE)
            for row in rows:
                cols = re.findall(r'<td[^>]*>(.*?)</td>', row, re.DOTALL | re.IGNORECASE)
                if not cols:
                    continue
                name = re.sub(r'<[^>]+>', '', cols[0]).strip().lower().rstrip('.')
                if name and (name.endswith(f'.{self.domain}') or name == self.domain) and name not in seen:
                    seen.add(name)
                    results.append({"domain": name, "source": "rapiddns"})
        except Exception:
            pass
        return results

    def subdomains_viewdns(self):
        """ViewDNS.info — subdomain lookup (HTML scrape) — no API key required."""
        results = []
        seen    = set()
        r = self._get(
            "https://viewdns.info/subdomains/",
            params={"domain": self.domain},
            headers={"User-Agent": "Mozilla/5.0 ZeekGlare/1.0",
                     "Accept": "text/html,application/xhtml+xml"},
            timeout=20,
        )
        if not r or r.status_code != 200:
            return results
        try:
            rows = re.findall(r'<tr[^>]*>(.*?)</tr>', r.text, re.DOTALL | re.IGNORECASE)
            for row in rows:
                cols = re.findall(r'<td[^>]*>(.*?)</td>', row, re.DOTALL | re.IGNORECASE)
                if not cols:
                    continue
                name = re.sub(r'<[^>]+>', '', cols[0]).strip().lower().rstrip('.')
                if name and (name.endswith(f'.{self.domain}') or name == self.domain) and name not in seen:
                    seen.add(name)
                    results.append({"domain": name, "source": "viewdns"})
        except Exception:
            pass
        return results

    def subdomains_otx(self):
        """AlienVault OTX — passive DNS — no API key required."""
        results = []
        seen    = set()
        # OTX paginates via `page` param; fetch up to 10 pages of 500 records
        for page in range(1, 11):
            r = self._get(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns",
                params={"limit": 500, "page": page},
                headers={"User-Agent": "Mozilla/5.0 ZeekGlare/1.0"},
                timeout=20,
            )
            if not r or r.status_code != 200:
                break
            try:
                data    = r.json()
                records = data.get("passive_dns", [])
                if not records:
                    break
                for rec in records:
                    name = rec.get("hostname", "").strip().lower().rstrip(".")
                    if name and (name.endswith(f".{self.domain}") or name == self.domain) and name not in seen:
                        seen.add(name)
                        results.append({"domain": name, "source": "otx"})
                # stop if we got fewer records than the limit (last page)
                if len(records) < 500:
                    break
            except Exception:
                break
        return results

    def subdomains_dnsrepo(self):
        """dnsrepo.noc.org — passive DNS repository — no API key required."""
        results = []
        seen    = set()
        r = self._get(
            "https://dnsrepo.noc.org/",
            params={"domain": self.domain},
            headers={"User-Agent": "Mozilla/5.0 ZeekGlare/1.0",
                     "Accept": "application/json, text/html, */*"},
            timeout=20,
        )
        if not r or r.status_code != 200:
            return results
        try:
            data = r.json()
            records = data if isinstance(data, list) else data.get("results", data.get("records", []))
            for rec in records:
                name = (rec.get("name") or rec.get("domain") or rec.get("hostname") or "").strip().lower().rstrip(".")
                if name and (name.endswith(f".{self.domain}") or name == self.domain) and name not in seen:
                    seen.add(name)
                    results.append({"domain": name, "source": "dnsrepo"})
        except Exception:
            # Fallback: regex scrape HTML response
            for m in re.findall(r'([\w][\w.-]*\.' + re.escape(self.domain) + r')\b', r.text):
                name = m.strip().lower().rstrip(".")
                if name not in seen:
                    seen.add(name)
                    results.append({"domain": name, "source": "dnsrepo"})
        return results

    def subdomains_findomain(self):
        """Findomain — fast multi-source subdomain tool."""
        results = []
        seen    = set()
        bin_path = shutil.which("findomain") or os.path.expanduser("~/.local/bin/findomain")
        if not os.path.isfile(bin_path):
            return results
        try:
            self.emit({"type": "source_progress", "source": "findomain", "count": 0, "status": "running"})
            proc = subprocess.run(
                [bin_path, "-t", self.domain, "--quiet"],
                capture_output=True, text=True, timeout=120
            )
            count = 0
            for line in proc.stdout.splitlines():
                name = line.strip().lower().rstrip(".")
                if name and (name.endswith(f".{self.domain}") or name == self.domain) and name not in seen:
                    seen.add(name)
                    results.append({"domain": name, "source": "findomain"})
                    count += 1
            self.emit({"type": "source_progress", "source": "findomain", "count": count, "status": "done"})
        except Exception:
            pass
        return results

    def subdomains_sublist3r(self):
        """Sublist3r — multi-engine passive subdomain enumeration."""
        results = []
        seen    = set()
        script  = "/home/daud/Tools/Sublist3r/sublist3r.py"
        if not os.path.isfile(script):
            # try PATH
            bin_path = shutil.which("sublist3r")
            if not bin_path:
                return results
            cmd = [bin_path, "-d", self.domain, "-o", "/dev/stdout", "-n"]
        else:
            cmd = ["python3", script, "-d", self.domain, "-o", "/dev/stdout", "-n"]
        try:
            import tempfile
            with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as tf:
                out_file = tf.name
            cmd_file = cmd[:-2] + ["-o", out_file, "-n"]  # write to temp file
            self.emit({"type": "source_progress", "source": "sublist3r", "count": 0, "status": "running"})
            subprocess.run(cmd_file, capture_output=True, timeout=180)
            count = 0
            with open(out_file, "r", errors="ignore") as f:
                for line in f:
                    name = line.strip().lower().rstrip(".")
                    if name and (name.endswith(f".{self.domain}") or name == self.domain) and name not in seen:
                        seen.add(name)
                        results.append({"domain": name, "source": "sublist3r"})
                        count += 1
            os.unlink(out_file)
            self.emit({"type": "source_progress", "source": "sublist3r", "count": count, "status": "done"})
        except Exception:
            pass
        return results

    def subdomains_assetfinder(self):
        """assetfinder — tomnomnom's fast passive subdomain discovery."""
        results  = []
        seen     = set()
        bin_path = shutil.which("assetfinder")
        if not bin_path:
            return results
        try:
            self.emit({"type": "source_progress", "source": "assetfinder", "count": 0, "status": "running"})
            proc = subprocess.run(
                [bin_path, "--subs-only", self.domain],
                capture_output=True, text=True, timeout=60,
            )
            count = 0
            for line in proc.stdout.splitlines():
                name = line.strip().lower().rstrip(".")
                if name and (name.endswith(f".{self.domain}") or name == self.domain) and name not in seen:
                    seen.add(name)
                    results.append({"domain": name, "source": "assetfinder"})
                    count += 1
            self.emit({"type": "source_progress", "source": "assetfinder", "count": count, "status": "done"})
        except Exception:
            pass
        return results

    def subdomains_knockpy(self):
        """knockpy — active subdomain enumeration with wordlist bruteforce."""
        results  = []
        seen     = set()
        bin_path = "/home/daud/.local/bin/knockpy"
        if not os.path.isfile(bin_path):
            return results
        try:
            self.emit({"type": "source_progress", "source": "knockpy", "count": 0, "status": "running"})
            proc = subprocess.run(
                [bin_path, "-d", self.domain, "--silent", "--json"],
                capture_output=True, text=True, timeout=120,
            )
            data = _json.loads(proc.stdout)
            count = 0
            for rec in data.get("results", []):
                host = rec.get("host", "").strip().lower().rstrip(".")
                if host and (host.endswith(f".{self.domain}") or host == self.domain) and host not in seen:
                    seen.add(host)
                    results.append({"domain": host, "source": "knockpy"})
                    count += 1
            self.emit({"type": "source_progress", "source": "knockpy", "count": count, "status": "done"})
        except Exception:
            pass
        return results

    def subdomains_github(self):
        """github-subdomains — mine GitHub code search for subdomains."""
        if not self.github_token:
            return []
        results = []
        seen    = set()
        bin_path = shutil.which("github-subdomains")
        if not bin_path:
            return []
        try:
            self.emit({"type": "source_progress", "source": "github-subdomains", "count": 0, "status": "running"})
            proc = subprocess.run(
                [bin_path, "-d", self.domain, "-t", self.github_token, "-raw"],
                capture_output=True, text=True, timeout=120
            )
            count = 0
            for line in proc.stdout.splitlines():
                dom = line.strip().lower().rstrip(".")
                if dom and (dom.endswith(f".{self.domain}") or dom == self.domain) and dom not in seen:
                    seen.add(dom)
                    results.append({"domain": dom, "source": "github-subdomains"})
                    count += 1
            self.emit({"type": "source_progress", "source": "github-subdomains", "count": count, "status": "done"})
        except Exception:
            pass
        return results

    def subdomains_bbot(self):
        """bbot passive subdomain enumeration — streams progress events."""
        results = []
        seen    = set()
        cmd     = [
            shutil.which("bbot"), "-t", self.domain,
            "-p", "subdomain-enum",
            "-rf", "passive",
            "--json",
            "--no-deps",
            "-y",
        ]
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
            )
            count    = 0
            deadline = _time.time() + 240
            self.emit({"type": "source_progress", "source": "bbot", "count": 0, "status": "running"})
            for line in proc.stdout:
                if _time.time() > deadline:
                    proc.kill()
                    self.emit({"type": "source_progress", "source": "bbot", "count": count, "status": "timeout"})
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    ev  = _json.loads(line)
                    typ = ev.get("type", "")
                    if typ in ("DNS_NAME", "DNS_NAME_UNRESOLVED"):
                        dom = ev.get("data", "").strip().lower().rstrip(".")
                        if (dom.endswith(f".{self.domain}") or dom == self.domain) and dom not in seen:
                            seen.add(dom)
                            results.append({"domain": dom, "source": "bbot"})
                            count += 1
                            if count % 5 == 0:
                                self.emit({"type": "source_progress", "source": "bbot",
                                           "count": count, "status": "running"})
                except (_json.JSONDecodeError, KeyError):
                    pass
            proc.wait(timeout=10)
            self.emit({"type": "source_progress", "source": "bbot", "count": count, "status": "done"})
        except Exception:
            self.emit({"type": "source_progress", "source": "bbot", "count": 0, "status": "error"})
        return results

    def subdomains_hackertarget(self):
        """HackerTarget — free passive DNS host-search API."""
        results = []
        seen    = set()
        r = self._get(
            "https://api.hackertarget.com/hostsearch/",
            params={"q": self.domain},
            headers={"User-Agent": "Mozilla/5.0 ZeekGlare/1.0"},
            timeout=20,
        )
        if not r or r.status_code != 200:
            return results
        for line in r.text.splitlines():
            parts = line.split(",")
            name  = parts[0].strip().lower().rstrip(".")
            if name and (name.endswith(f".{self.domain}") or name == self.domain) and name not in seen:
                seen.add(name)
                results.append({"domain": name, "source": "hackertarget"})
        return results

    def subdomains_urlscan(self):
        """urlscan.io — passive search for subdomains."""
        results = []
        seen    = set()
        r = self._get(
            "https://urlscan.io/api/v1/search/",
            params={"q": f"domain:{self.domain}", "size": 1000},
            headers={"User-Agent": "Mozilla/5.0 ZeekGlare/1.0"},
            timeout=20,
        )
        if not r or r.status_code != 200:
            return results
        try:
            for result in r.json().get("results", []):
                page = result.get("page", {})
                for field in ("domain", "ptr"):
                    name = page.get(field, "").strip().lower().rstrip(".")
                    if name and (name.endswith(f".{self.domain}") or name == self.domain) and name not in seen:
                        seen.add(name)
                        results.append({"domain": name, "source": "urlscan"})
        except Exception:
            pass
        return results

    def subdomains_recox(self):
        """Recox — aggregate 7 passive sources (CertSpotter, JLDC/Anubis, HackerTarget, URLScan, crt.sh, RapidDNS, DNSRepo)."""
        from concurrent.futures import ThreadPoolExecutor, as_completed
        results, seen = [], set()
        domain = self.domain

        def _certspotter():
            out = []
            r = self._get(
                "https://api.certspotter.com/v1/issuances",
                params={"domain": domain, "include_subdomains": "true", "expand": "dns_names"},
                timeout=20,
            )
            if not r or r.status_code != 200:
                return out
            try:
                for entry in r.json():
                    for name in entry.get("dns_names", []):
                        sub = name.strip().replace("*.", "").lower().rstrip(".")
                        if sub and (sub.endswith(f".{domain}") or sub == domain) and sub not in seen:
                            seen.add(sub)
                            out.append({"domain": sub, "source": "recox"})
            except Exception:
                pass
            return out

        def _jldc():
            out = []
            r = self._get(f"https://anubisdb.com/anubis/subdomains/{domain}", timeout=20)
            if not r or r.status_code != 200:
                return out
            try:
                for sub in r.json():
                    s = str(sub).strip().lower().rstrip(".")
                    if s and (s.endswith(f".{domain}") or s == domain) and s not in seen:
                        seen.add(s)
                        out.append({"domain": s, "source": "recox"})
            except Exception:
                pass
            return out

        def _hackertarget():
            out = []
            r = self._get("https://api.hackertarget.com/hostsearch/", params={"q": domain}, timeout=20)
            if not r or r.status_code != 200:
                return out
            for line in r.text.splitlines():
                parts = line.split(",")
                name = parts[0].strip().lower().rstrip(".")
                if name and (name.endswith(f".{domain}") or name == domain) and name not in seen:
                    seen.add(name)
                    out.append({"domain": name, "source": "recox"})
            return out

        def _urlscan():
            out = []
            r = self._get("https://urlscan.io/api/v1/search/", params={"q": f"domain:{domain}", "size": 1000}, timeout=20)
            if not r or r.status_code != 200:
                return out
            try:
                for result in r.json().get("results", []):
                    page = result.get("page", {})
                    for field in ("domain", "ptr"):
                        name = page.get(field, "").strip().lower().rstrip(".")
                        if name and (name.endswith(f".{domain}") or name == domain) and name not in seen:
                            seen.add(name)
                            out.append({"domain": name, "source": "recox"})
            except Exception:
                pass
            return out

        def _crtsh():
            out = []
            r = self._get("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"}, timeout=40)
            if not r or r.status_code != 200:
                return out
            try:
                for cert in r.json():
                    for name in cert.get("name_value", "").split("\n"):
                        sub = name.strip().replace("*.", "").lower().rstrip(".")
                        if sub and (sub.endswith(f".{domain}") or sub == domain) and sub not in seen:
                            seen.add(sub)
                            out.append({"domain": sub, "source": "recox"})
            except Exception:
                pass
            return out

        def _rapiddns():
            out = []
            r = self._get(f"https://rapiddns.io/subdomain/{domain}?full=1", timeout=20)
            if not r or r.status_code != 200:
                return out
            try:
                import re as _re
                pattern = _re.compile(rf'<td>([a-z0-9][a-z0-9\\-\\.]*\\.{_re.escape(domain)})<\\/td>', _re.I)
                for m in pattern.finditer(r.text):
                    sub = m.group(1).strip().lower().rstrip(".")
                    if sub and sub not in seen:
                        seen.add(sub)
                        out.append({"domain": sub, "source": "recox"})
            except Exception:
                pass
            return out

        def _dnsrepo():
            out = []
            r = self._get(f"https://dnsrepo.noc.org/?domain={domain}", timeout=20)
            if not r or r.status_code != 200:
                return out
            try:
                import re as _re
                pattern = _re.compile(rf'([a-z0-9][a-z0-9\\-\\.]*\\.{_re.escape(domain)})', _re.I)
                found = set()
                for m in pattern.finditer(r.text):
                    sub = m.group(1).strip().lower().rstrip(".")
                    if sub and sub not in seen and sub not in found:
                        found.add(sub)
                        seen.add(sub)
                        out.append({"domain": sub, "source": "recox"})
            except Exception:
                pass
            return out

        fns = [
            ("certspotter", _certspotter),
            ("jldc", _jldc),
            ("hackertarget", _hackertarget),
            ("urlscan", _urlscan),
            ("crtsh", _crtsh),
            ("rapiddns", _rapiddns),
            ("dnsrepo", _dnsrepo),
        ]
        with ThreadPoolExecutor(max_workers=7) as ex:
            futs = {ex.submit(fn): name for name, fn in fns}
            for fut in as_completed(futs):
                try:
                    results.extend(fut.result())
                except Exception:
                    pass
        return results

    def subdomains_subfinder(self):
        """subfinder — ProjectDiscovery fast passive subdomain enumeration."""
        results  = []
        seen     = set()
        bin_path = shutil.which("subfinder") or os.path.expanduser("~/go/bin/subfinder")
        if not os.path.isfile(bin_path):
            return results
        try:
            self.emit({"type": "source_progress", "source": "subfinder", "count": 0, "status": "running"})
            proc = subprocess.run(
                [bin_path, "-d", self.domain, "-silent", "-all"],
                capture_output=True, text=True, timeout=180,
            )
            count = 0
            for line in proc.stdout.splitlines():
                name = line.strip().lower().rstrip(".")
                if name and (name.endswith(f".{self.domain}") or name == self.domain) and name not in seen:
                    seen.add(name)
                    results.append({"domain": name, "source": "subfinder"})
                    count += 1
            self.emit({"type": "source_progress", "source": "subfinder", "count": count, "status": "done"})
        except Exception:
            pass
        return results

    def subdomains_amass(self):
        """amass — OWASP passive subdomain enumeration."""
        results  = []
        seen     = set()
        bin_path = shutil.which("amass") or os.path.expanduser("~/go/bin/amass")
        if not os.path.isfile(bin_path):
            return results
        try:
            self.emit({"type": "source_progress", "source": "amass", "count": 0, "status": "running"})
            proc = subprocess.run(
                [bin_path, "enum", "-passive", "-d", self.domain, "-silent"],
                capture_output=True, text=True, timeout=240,
            )
            count = 0
            for line in proc.stdout.splitlines():
                name = line.strip().lower().rstrip(".")
                if name and (name.endswith(f".{self.domain}") or name == self.domain) and name not in seen:
                    seen.add(name)
                    results.append({"domain": name, "source": "amass"})
                    count += 1
            self.emit({"type": "source_progress", "source": "amass", "count": count, "status": "done"})
        except Exception:
            pass
        return results

    def subdomains_cero(self):
        """cero — TLS certificate scraper for subdomain discovery."""
        results  = []
        seen     = set()
        bin_path = shutil.which("cero") or os.path.expanduser("~/go/bin/cero")
        if not os.path.isfile(bin_path):
            return results
        try:
            self.emit({"type": "source_progress", "source": "cero", "count": 0, "status": "running"})
            proc = subprocess.run(
                [bin_path, self.domain],
                capture_output=True, text=True, timeout=60,
            )
            count = 0
            for line in proc.stdout.splitlines():
                name = line.strip().lower().rstrip(".").lstrip("*.")
                if name and (name.endswith(f".{self.domain}") or name == self.domain) and name not in seen:
                    seen.add(name)
                    results.append({"domain": name, "source": "cero"})
                    count += 1
            self.emit({"type": "source_progress", "source": "cero", "count": count, "status": "done"})
        except Exception:
            pass
        return results

    def subdomains_chaos(self):
        """Chaos — ProjectDiscovery DNS dataset via CLI binary or API (API key required)."""
        if not self.chaos_key:
            return []
        results = []
        seen    = set()

        # Prefer chaos-client CLI binary if installed
        bin_path = shutil.which("chaos") or os.path.expanduser("~/go/bin/chaos")
        if os.path.isfile(bin_path):
            try:
                self.emit({"type": "source_progress", "source": "chaos", "count": 0, "status": "running"})
                env = os.environ.copy()
                env["PDCP_API_KEY"] = self.chaos_key
                proc = subprocess.run(
                    [bin_path, "-d", self.domain, "-silent"],
                    capture_output=True, text=True, timeout=120, env=env,
                )
                count = 0
                for line in proc.stdout.splitlines():
                    name = line.strip().lower().rstrip(".")
                    if name and (name.endswith(f".{self.domain}") or name == self.domain) and name not in seen:
                        seen.add(name)
                        results.append({"domain": name, "source": "chaos"})
                        count += 1
                self.emit({"type": "source_progress", "source": "chaos", "count": count, "status": "done"})
                return results
            except Exception:
                pass  # Fall through to API method

        # Fallback: HTTP API
        try:
            self.emit({"type": "source_progress", "source": "chaos", "count": 0, "status": "running"})
            r = self._get(
                f"https://dns.projectdiscovery.io/dns/{self.domain}/subdomains",
                headers={"Authorization": self.chaos_key},
                timeout=20,
            )
            if not r or r.status_code != 200:
                self.emit({"type": "source_progress", "source": "chaos", "count": 0, "status": "error"})
                return results
            data   = r.json()
            domain = data.get("domain", self.domain)
            count  = 0
            for sub in data.get("subdomains", []):
                name = f"{sub}.{domain}".lower().rstrip(".")
                if name and (name.endswith(f".{self.domain}") or name == self.domain) and name not in seen:
                    seen.add(name)
                    results.append({"domain": name, "source": "chaos"})
                    count += 1
            self.emit({"type": "source_progress", "source": "chaos", "count": count, "status": "done"})
        except Exception:
            pass
        return results

    def subdomains_gitlab(self):
        """gitlab-subdomains — mine GitLab for subdomains (token required)."""
        if not self.gitlab_token:
            return []
        results  = []
        seen     = set()
        bin_path = shutil.which("gitlab-subdomains") or os.path.expanduser("~/go/bin/gitlab-subdomains")
        if not os.path.isfile(bin_path):
            return []
        try:
            self.emit({"type": "source_progress", "source": "gitlab-subdomains", "count": 0, "status": "running"})
            proc = subprocess.run(
                [bin_path, "-d", self.domain, "-t", self.gitlab_token, "-raw"],
                capture_output=True, text=True, timeout=120,
            )
            count = 0
            for line in proc.stdout.splitlines():
                name = line.strip().lower().rstrip(".")
                if name and (name.endswith(f".{self.domain}") or name == self.domain) and name not in seen:
                    seen.add(name)
                    results.append({"domain": name, "source": "gitlab-subdomains"})
                    count += 1
            self.emit({"type": "source_progress", "source": "gitlab-subdomains", "count": count, "status": "done"})
        except Exception:
            pass
        return results

    # ── Resolution & Enrichment ───────────────────────────────────────────────

    def resolve(self, entry):
        try:
            entry["ip"] = socket.gethostbyname(entry["domain"])
        except Exception:
            entry["ip"] = None
        return entry

    def ip_to_meta(self, ip):
        if not ip:
            return {}
        if ip in self._asn_cache:
            return self._asn_cache[ip]
        try:
            r = _req.get(
                f"{RIPE_STAT_BASE}/prefix-overview/data.json",
                params={"resource": ip},
                timeout=10, verify=False,
            )
            data = r.json().get("data", {})
            asns = data.get("asns", [])
            if asns:
                a = asns[0]
                result = {"asn": a.get("asn", ""), "holder": a.get("holder", ""),
                          "prefix": data.get("resource", "")}
                self._asn_cache[ip] = result
                return result
        except Exception:
            pass
        self._asn_cache[ip] = {}
        return {}

    # ── Detection ─────────────────────────────────────────────────────────────

    def detect_waf(self, headers):
        h = {k.lower(): v for k, v in headers.items()}
        for sig, label in WAF_SIGNATURES.items():
            if sig in h:
                return label(h[sig]) if callable(label) else label
        return ""

    def detect_cms(self, body):
        b = body.lower() if body else ""
        for sig, label in CMS_SIGNATURES.items():
            if sig in b:
                return label
        return ""

    def detect_cloud(self, headers, body):
        combined = " ".join(str(v) for v in headers.values()).lower()
        combined += " " + (body or "").lower()[:2000]
        for sig, label in CLOUD_SIGNATURES.items():
            if sig in combined:
                return label
        return ""

    def probe_http(self, entry):
        domain  = entry.get("domain", "")
        score   = 0
        for scheme in ("https", "http"):
            url = f"{scheme}://{domain}"
            try:
                r = _req.get(url, timeout=12, verify=False, allow_redirects=True,
                             headers={"User-Agent": "Mozilla/5.0 ZeekGlare/1.0"})
                headers     = dict(r.headers)
                body        = r.text[:50000]
                status_code = r.status_code
                title_m     = re.search(r"<title[^>]*>([^<]{0,200})</title>", body, re.I)
                title       = title_m.group(1).strip() if title_m else ""

                tech = []
                for hdr, fn in TECH_PATTERNS.items():
                    val = headers.get(hdr, "")
                    if val:
                        t = fn(val)
                        if t:
                            tech.append(t)

                waf   = self.detect_waf(headers)
                cms   = self.detect_cms(body)
                cloud = self.detect_cloud(headers, body)
                missing = [h for h in SECURITY_HEADERS if h not in headers]

                score += len(missing) * 10
                if status_code in (401, 403): score += 15
                if status_code >= 500:        score += 20
                if any(kw in body.lower() for kw in
                       ["traceback", "stack trace", "exception in", "fatal error"]):
                    score += 50
                score += len(tech) * 3
                if len(body) > 200000: score += 3
                if scheme == "https":  score += 5
                if waf: score += 10
                if cms: score += 5

                entry.update({
                    "http_live": True, "http_status": status_code,
                    "http_url": r.url, "title": title, "tech": tech,
                    "waf": waf, "cms": cms, "cloud": cloud,
                    "missing_headers": missing, "score": min(score, 200),
                })
                return entry

            except _req.exceptions.SSLError:
                score += 25
                entry.update({
                    "http_live": True, "http_status": "ssl_err",
                    "http_url": url, "title": "", "tech": [], "waf": "", "cms": "",
                    "cloud": "", "missing_headers": SECURITY_HEADERS[:],
                    "score": min(score, 200),
                })
                return entry
            except (_req.exceptions.ConnectionError, _req.exceptions.Timeout):
                continue
            except Exception:
                continue

        entry.update({
            "http_live": False, "http_status": None, "http_url": "",
            "title": "", "tech": [], "waf": "", "cms": "", "cloud": "",
            "missing_headers": [], "score": 0,
        })
        return entry

    # ── WhatWeb fingerprinting ────────────────────────────────────────────────

    _WW_NOISE = {
        "Title", "IP", "Allow", "Country", "UncommonHeaders",
        "RequestHeader", "Script", "Open-Graph-Protocol",
        "Google-Analytics", "HTML5", "Cookies", "Email",
        "HTML-Meta-Author", "MetaGenerator", "HTTPServer",
    }

    def whatweb_scan(self, entry):
        """Run WhatWeb on a live host and merge detected technologies into the entry."""
        _ww = shutil.which("whatweb")
        if not _ww:
            return entry
        url = entry.get("http_url") or f"https://{entry['domain']}"
        try:
            self.emit({"type": "source_progress", "source": "whatweb",
                       "count": 0, "status": "running", "domain": entry["domain"]})
            proc = subprocess.run(
                [_ww, "--log-json=-", "-q", "--no-errors", url],
                capture_output=True, text=True, timeout=30,
            )
            ww_tech = []
            ww_server = ""
            for line in proc.stdout.splitlines():
                line = line.strip()
                if not line.startswith("{"):
                    continue
                try:
                    data = _json.loads(line)
                except Exception:
                    continue
                plugins = data.get("plugins", {})
                srv = plugins.get("HTTPServer", {}).get("string", [])
                if srv:
                    ww_server = srv[0]
                for name, info in plugins.items():
                    if name in self._WW_NOISE:
                        continue
                    strings = info.get("string", [])
                    version = info.get("version", [])
                    if strings:
                        label = f"{name}/{strings[0]}" if strings[0] else name
                    elif version:
                        label = f"{name} {version[0]}"
                    else:
                        label = name
                    ww_tech.append(label)
            entry["whatweb"] = ww_tech
            if ww_server:
                entry["ww_server"] = ww_server
        except Exception:
            entry.setdefault("whatweb", [])
        return entry

    # ── MassDNS brute-force ─────────────────────────────────────────────────

    def subdomains_massdns(self):
        """MassDNS — high-performance DNS brute-force subdomain discovery."""
        results = []
        seen    = set()
        bin_path = shutil.which("massdns") or "/usr/local/bin/massdns"
        if not os.path.isfile(bin_path):
            return results

        resolvers = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "resolvers.txt")
        if not os.path.isfile(resolvers):
            return results

        # Build candidate list from a small built-in wordlist
        _WORDS = [
            "www","mail","ftp","smtp","pop","imap","webmail","ns1","ns2",
            "dns","dns1","dns2","mx","mx1","mx2","api","dev","staging",
            "test","beta","admin","portal","app","apps","blog","cdn",
            "cloud","cms","cpanel","dashboard","db","demo","docs","email",
            "git","gitlab","grafana","help","jenkins","jira","ldap",
            "login","m","manage","media","mobile","monitor","mysql",
            "new","news","office","old","ops","oracle","panel","pay",
            "payment","proxy","rdp","redis","remote","repo","report",
            "s3","sandbox","search","secure","server","shop","sip",
            "sms","sql","ssh","ssl","stage","static","status","store",
            "support","svn","syslog","tools","track","vpn","web","wiki",
            "ww1","ww2","www1","www2","www3","autodiscover","autoconfig",
            "calendar","chat","ci","confluence","crm","data","direct",
            "download","edge","exchange","files","forum","gw","host",
            "hub","id","img","intranet","kibana","lab","link","list",
            "log","logs","mailgw","maps","metrics","mirror","nagios",
            "netscaler","node","ns3","ntp","open","origin","outlook",
            "pages","partner","pma","preview","print","prod","production",
            "registry","relay","rest","s1","s2","s3","service","services",
            "sftp","share","sso","stat","stats","storage","stream",
            "survey","sync","time","traefik","upload","vault","video",
            "voip","webdisk","webmin","work","wp","zabbix",
        ]

        try:
            self.emit({"type": "source_progress", "source": "massdns", "count": 0, "status": "running"})

            # Write candidates to temp file
            tmp_in = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
            for w in _WORDS:
                tmp_in.write(f"{w}.{self.domain}\n")
            tmp_in.close()

            proc = subprocess.run(
                [bin_path, "-r", resolvers, "-t", "A", "-o", "S", "-q",
                 "--filter", "NOERROR", tmp_in.name],
                capture_output=True, text=True, timeout=120,
            )

            count = 0
            for line in proc.stdout.splitlines():
                parts = line.strip().split()
                if len(parts) < 3:
                    continue
                name = parts[0].lower().rstrip(".")
                if name and (name.endswith(f".{self.domain}") or name == self.domain) and name not in seen:
                    seen.add(name)
                    results.append({"domain": name, "source": "massdns"})
                    count += 1

            self.emit({"type": "source_progress", "source": "massdns", "count": count, "status": "done"})
        except Exception:
            pass
        finally:
            try:
                os.unlink(tmp_in.name)
            except Exception:
                pass
        return results

    # ── Main Pipeline ─────────────────────────────────────────────────────────

    def run(self):
        self.emit({"type": "scan_start", "domain": self.domain})
        all_entries, seen_domains, sources_used = [], set(), []

        def add_entries(entries, source):
            added = 0
            for e in entries:
                d = e.get("domain", "").strip().lower()
                if d and d not in seen_domains:
                    seen_domains.add(d)
                    all_entries.append(e)
                    added += 1
            if added > 0 and source not in sources_used:
                sources_used.append(source)

        def _on(name):
            """Return True if this source is enabled (None = all enabled)."""
            return self._enabled is None or name in self._enabled

        if _on("crtsh"):
            try:
                add_entries(self.subdomains_crtsh(), "crtsh")
            except Exception:
                pass

        optional_fns = []
        for name, fn in [
            ("thc",          self.subdomains_thc),
            ("rapiddns",     self.subdomains_rapiddns),
            ("viewdns",      self.subdomains_viewdns),
            ("otx",          self.subdomains_otx),
            ("dnsrepo",      self.subdomains_dnsrepo),
            ("hackertarget", self.subdomains_hackertarget),
            ("urlscan",      self.subdomains_urlscan),
            ("recox",        self.subdomains_recox),
            ("findomain",    self.subdomains_findomain),
            ("sublist3r",    self.subdomains_sublist3r),
            ("assetfinder",  self.subdomains_assetfinder),
            ("subfinder",    self.subdomains_subfinder),
            ("amass",        self.subdomains_amass),
            ("cero",         self.subdomains_cero),
            ("massdns",      self.subdomains_massdns),
        ]:
            if _on(name):
                optional_fns.append((name, fn))

        if _on("knockpy"):
                                      optional_fns.append(("knockpy",           self.subdomains_knockpy))
        if _on("bbot") and self.use_bbot:
                                      optional_fns.append(("bbot",             self.subdomains_bbot))
        if _on("shodan") and self.shodan_key:
                                      optional_fns.append(("shodan",           self.subdomains_shodan))
        if _on("securitytrails") and self.securitytrails_key:
                                      optional_fns.append(("securitytrails",   self.subdomains_securitytrails))
        if _on("censys") and self.censys_id and self.censys_secret:
                                      optional_fns.append(("censys",           self.subdomains_censys))
        if _on("zoomeye") and self.zoomeye_key:
                                      optional_fns.append(("zoomeye",          self.subdomains_zoomeye))
        if _on("fofa") and self.fofa_email and self.fofa_key:
                                      optional_fns.append(("fofa",             self.subdomains_fofa))
        if _on("github-subdomains") and self.github_token:
                                      optional_fns.append(("github-subdomains",self.subdomains_github))
        if _on("c99") and self.c99_key:
                                      optional_fns.append(("c99",              self.subdomains_c99))
        if _on("chaos") and self.chaos_key:
                                      optional_fns.append(("chaos",            self.subdomains_chaos))
        if _on("gitlab-subdomains") and self.gitlab_token:
                                      optional_fns.append(("gitlab-subdomains",self.subdomains_gitlab))
        if _on("argosdns") and self.argosdns_key:
                                      optional_fns.append(("argosdns",         self.subdomains_argosdns))

        if optional_fns:
            with ThreadPoolExecutor(max_workers=len(optional_fns)) as ex:
                futs = {ex.submit(fn): src for src, fn in optional_fns}
                for fut in as_completed(futs):
                    try:
                        add_entries(fut.result(), futs[fut])
                    except Exception:
                        pass

        entries = all_entries[:self.max_subs]
        for e in entries:
            for k in ("ip","http_live","http_status","score","tech","waf","cms","cloud",
                      "missing_headers","title","asn","holder","prefix"):
                e.setdefault(k, [] if k in ("tech","missing_headers") else
                             False if k == "http_live" else
                             0 if k == "score" else None if k in ("ip","http_status") else "")

        self.emit({"type": "subdomains_found", "total": len(entries), "sources_used": sources_used})

        if not entries:
            self.emit({"type": "scan_complete", "summary": {
                "total_subdomains": 0, "live_subdomains": 0,
                "total_ips": 0, "total_asns": 0,
                "top_targets": [], "asn_groups": {},
            }})
            self._eq.put(None)
            return

        def resolve_and_emit(entry):
            e  = self.resolve(entry)
            ip = e.get("ip")
            if ip:
                meta       = self.ip_to_meta(ip)
                e["asn"]   = meta.get("asn", "")
                e["holder"]= meta.get("holder", "")
                e["prefix"]= meta.get("prefix", "")
            self.emit({"type": "subdomain_result", "entry": e})
            return e

        with ThreadPoolExecutor(max_workers=40) as ex:
            futs    = [ex.submit(resolve_and_emit, e) for e in entries]
            entries = [f.result() for f in as_completed(futs)]

        if self.do_probe:
            live_entries = [e for e in entries if e.get("ip")]

            def probe_and_emit(entry):
                e = self.probe_http(entry)
                self.emit({"type": "probe_update", "entry": e})
                return e

            with ThreadPoolExecutor(max_workers=20) as ex:
                futs   = [ex.submit(probe_and_emit, e) for e in live_entries]
                probed = [f.result() for f in as_completed(futs)]

            probed_map = {e["domain"]: e for e in probed}
            entries    = [probed_map.get(e["domain"], e) for e in entries]

        # ── WhatWeb phase (runs after HTTP probe, only on live hosts) ──────────
        if self.do_probe and _on("whatweb") and shutil.which("whatweb"):
            live_ww = [e for e in entries if e.get("http_live")]
            self.emit({"type": "source_progress", "source": "whatweb",
                       "count": 0, "status": "running"})

            def ww_and_emit(entry):
                e = self.whatweb_scan(entry)
                self.emit({"type": "probe_update", "entry": e})
                return e

            with ThreadPoolExecutor(max_workers=8) as ex:
                futs   = [ex.submit(ww_and_emit, e) for e in live_ww]
                ww_res = [f.result() for f in as_completed(futs)]

            ww_map  = {e["domain"]: e for e in ww_res}
            entries = [ww_map.get(e["domain"], e) for e in entries]
            self.emit({"type": "source_progress", "source": "whatweb",
                       "count": len(live_ww), "status": "done"})

        asn_groups = {}
        for e in entries:
            key = str(e.get("asn") or "unknown")
            if key not in asn_groups:
                asn_groups[key] = {"asn": key, "holder": e.get("holder", ""),
                                   "count": 0, "domains": []}
            asn_groups[key]["count"] += 1
            asn_groups[key]["domains"].append(e["domain"])

        top_targets = sorted(
            [e for e in entries if e.get("score", 0) > 0],
            key=lambda x: -x.get("score", 0),
        )[:20]

        total_ips  = len({e["ip"] for e in entries if e.get("ip")})
        total_asns = len({str(e.get("asn")) for e in entries if e.get("asn")})
        live_count = sum(1 for e in entries if e.get("http_live"))

        summary = {
            "total_subdomains": len(entries), "live_subdomains": live_count,
            "total_ips": total_ips, "total_asns": total_asns,
            "top_targets": top_targets[:15], "asn_groups": asn_groups,
        }

        try:
            scan_id = str(uuid.uuid4())
            SessionManager.save(
                scan_id=scan_id, scan_type="domain", target=self.domain,
                name=f"{self.domain} — {datetime.now():%Y-%m-%d %H:%M}",
                summary={
                    "total_subdomains": summary["total_subdomains"],
                    "live_subdomains":  summary["live_subdomains"],
                    "total_ips":        summary["total_ips"],
                    "total_asns":       summary["total_asns"],
                },
                data={"entries": entries, "asn_groups": asn_groups, "top_targets": summary["top_targets"]},
                user_id=self.user_id,
                username=self.username,
            )
            self.emit({"type": "session_saved", "scan_id": scan_id})
        except Exception:
            pass

        self.emit({"type": "scan_complete", "summary": summary})
        self._eq.put(None)
