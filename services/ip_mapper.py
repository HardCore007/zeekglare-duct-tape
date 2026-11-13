"""IPScope — IP & Subnet intelligence mapper.

Sources (free): hackertarget, bgpview, internetdb (Shodan free)
Sources (API key): shodan, fofa, zoomeye, securitytrails, censys,
                   netlas, greynoise, criminalip
Optional: nmap for service version detection
"""
import base64, ipaddress, os, queue, re, shutil, socket, subprocess, time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests as _req
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_UA = "Mozilla/5.0 ZeekGlare/1.0"
_TIMEOUT = 20

# Common port → service name mapping (fallback when nmap not used)
_PORT_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCBind", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "Submission",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle", 2049: "NFS",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    5985: "WinRM", 6379: "Redis", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
    8888: "HTTP-Alt", 9200: "Elasticsearch", 9300: "ES-Transport",
    27017: "MongoDB", 11211: "Memcached",
}

# Ports that indicate a web service (for screenshot feature)
WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888, 8008, 3000, 5000}


def _get(url, params=None, headers=None, auth=None, timeout=_TIMEOUT):
    try:
        r = _req.get(url, params=params, headers=headers, auth=auth,
                     timeout=timeout, verify=False)
        return r
    except Exception:
        return None


def _cidr_from_ip(ip_str, prefix_len=24):
    """Return the containing /prefix network string for an IP."""
    try:
        net = ipaddress.ip_network(f"{ip_str}/{prefix_len}", strict=False)
        return str(net)
    except Exception:
        return ""


def _is_valid_ip(s):
    try:
        ipaddress.ip_address(s)
        return not ipaddress.ip_address(s).is_private
    except Exception:
        return False


def _resolve_domain(domain):
    """Resolve domain to list of IPs."""
    ips = []
    try:
        for info in socket.getaddrinfo(domain, None, socket.AF_INET):
            ip = info[4][0]
            if _is_valid_ip(ip) and ip not in ips:
                ips.append(ip)
    except Exception:
        pass
    return ips


def _parse_targets(raw_targets):
    """Parse multi-target input into (domains, ips) tuple.

    Accepts: IPs, CIDRs (expanded), domains — comma/newline/space separated.
    Returns: (list[str] domains, list[str] ips)
    """
    domains = []
    ips = []
    for token in re.split(r'[,\s]+', raw_targets.strip()):
        token = token.strip().lower()
        if not token:
            continue
        # CIDR notation
        if '/' in token:
            try:
                net = ipaddress.ip_network(token, strict=False)
                # Limit expansion to /24 (256 IPs) to prevent abuse
                if net.prefixlen < 24:
                    # For large CIDRs just add the network representation
                    for host in net.hosts():
                        if not host.is_private:
                            ips.append(str(host))
                        if len(ips) > 256:
                            break
                else:
                    for host in net.hosts():
                        if not host.is_private:
                            ips.append(str(host))
                continue
            except Exception:
                pass
        # Single IP
        if _is_valid_ip(token):
            ips.append(token)
            continue
        # Domain
        if re.match(r'^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+$', token):
            if token.startswith("www."):
                token = token[4:]
            domains.append(token)
            continue
    return domains, list(dict.fromkeys(ips))  # dedupe ips preserving order


def _parse_nmap_args(raw):
    """Parse user nmap args into a token list, stripping bare targets."""
    if not raw or not raw.strip():
        return []
    import shlex
    try:
        tokens = shlex.split(raw.strip())
    except ValueError:
        tokens = raw.strip().split()
    # Flags that take a separate value argument
    _VALUE_FLAGS = {
        "-p", "--top-ports", "-T", "--min-rate", "--max-rate",
        "--host-timeout", "--scan-delay", "--max-retries",
        "--min-rtt-timeout", "--max-rtt-timeout", "--initial-rtt-timeout",
        "--version-intensity", "--min-parallelism", "--max-parallelism",
        "-e", "--source-port", "-g", "--ttl",
        "--min-hostgroup", "--max-hostgroup", "-D", "--spoof-mac",
        "--exclude", "--excludefile", "--script", "--script-args",
        "--script-args-file", "--script-timeout",
        "-oN", "-oX", "-oS", "-oA",
        "--datadir", "--servicedb", "--versiondb",
        "--resume", "--stylesheet", "--webxml",
        "-iL", "-iR",
    }
    result = []
    expect_value = False
    for tok in tokens:
        if expect_value:
            result.append(tok)
            expect_value = False
            continue
        if tok.startswith("-"):
            result.append(tok)
            flag_base = tok.split("=")[0]
            if "=" not in tok and flag_base in _VALUE_FLAGS:
                expect_value = True
            continue
        # Drop bare tokens (IPs/hostnames) — we supply the target
    return result


class IpMapper:
    def __init__(self, domain=None, targets=None,
                 shodan_key=None, fofa_email=None, fofa_key=None,
                 zoomeye_key=None, securitytrails_key=None,
                 censys_id=None, censys_secret=None,
                 netlas_key=None, greynoise_key=None, criminalip_key=None,
                 seed_ips=None, enabled_sources=None, event_queue=None,
                 use_nmap=False, nmap_args=None):
        # Multi-target support: parse targets into domains + direct IPs
        if targets:
            self._domains, self._direct_ips = _parse_targets(targets)
        elif domain:
            d = domain.strip().lower()
            if d.startswith("www."):
                d = d[4:]
            self._domains = [d]
            self._direct_ips = []
        else:
            self._domains = []
            self._direct_ips = []
        # Primary domain for backward compat (first domain or empty)
        self.domain             = self._domains[0] if self._domains else ""
        self.targets_raw        = targets or domain or ""
        self.shodan_key         = shodan_key
        self.fofa_email         = fofa_email
        self.fofa_key           = fofa_key
        self.zoomeye_key        = zoomeye_key
        self.securitytrails_key = securitytrails_key
        self.censys_id          = censys_id
        self.censys_secret      = censys_secret
        self.netlas_key         = netlas_key
        self.greynoise_key      = greynoise_key
        self.criminalip_key     = criminalip_key
        self.seed_ips           = list(seed_ips or [])
        self._enabled           = set(enabled_sources) if enabled_sources is not None else None
        self._eq                = event_queue or queue.Queue()
        self._seen_ips          = set()
        self._use_nmap          = use_nmap and shutil.which("nmap") is not None
        self._nmap_extra        = _parse_nmap_args(nmap_args or "")

    def emit(self, data):
        self._eq.put(data)

    def _on(self, src):
        return self._enabled is None or src in self._enabled

    # ── IP collection from each source ────────────────────────────────────────

    def _ips_hackertarget(self):
        results = []
        r = _get("https://api.hackertarget.com/hostsearch/",
                 params={"q": self.domain},
                 headers={"User-Agent": _UA})
        if not r or r.status_code != 200:
            return results
        for line in r.text.splitlines():
            parts = line.split(",")
            if len(parts) >= 2:
                ip = parts[1].strip()
                host = parts[0].strip()
                if _is_valid_ip(ip):
                    results.append({"ip": ip, "hostname": host, "source": "hackertarget"})
        return results

    def _ips_shodan(self):
        if not self.shodan_key:
            return []
        results = []
        # DNS domain lookup — subdomains with IPs
        r = _get(f"https://api.shodan.io/dns/domain/{self.domain}",
                 params={"key": self.shodan_key})
        if r and r.status_code == 200:
            try:
                data = r.json()
                for sub in data.get("subdomains", []):
                    full = f"{sub}.{self.domain}"
                    r2 = _get(f"https://api.shodan.io/dns/resolve",
                              params={"hostnames": full, "key": self.shodan_key})
                    if r2 and r2.status_code == 200:
                        d2 = r2.json()
                        ip = d2.get(full, "")
                        if _is_valid_ip(ip):
                            results.append({"ip": ip, "hostname": full, "source": "shodan"})
            except Exception:
                pass

        # Host search by hostname
        r3 = _get("https://api.shodan.io/shodan/host/search",
                  params={"query": f"hostname:{self.domain}", "key": self.shodan_key})
        if r3 and r3.status_code == 200:
            try:
                for match in r3.json().get("matches", []):
                    ip = match.get("ip_str", "")
                    if _is_valid_ip(ip):
                        results.append({
                            "ip": ip,
                            "hostname": ", ".join(match.get("hostnames", [])),
                            "ports": [match.get("port", 0)],
                            "org": match.get("org", ""),
                            "country": match.get("location", {}).get("country_code", ""),
                            "source": "shodan",
                        })
            except Exception:
                pass
        return results

    def _ips_securitytrails(self):
        if not self.securitytrails_key:
            return []
        results = []
        hdrs = {"APIKEY": self.securitytrails_key}
        # Historical A records
        r = _get(f"https://api.securitytrails.com/v1/history/{self.domain}/dns/a",
                 headers=hdrs)
        if r and r.status_code == 200:
            try:
                for rec in r.json().get("records", []):
                    for val in rec.get("values", []):
                        ip = val.get("ip", "")
                        if _is_valid_ip(ip):
                            results.append({"ip": ip, "source": "securitytrails",
                                            "hostname": self.domain})
            except Exception:
                pass
        # Associated IPs (uses ip_addresses endpoint)
        r2 = _get(f"https://api.securitytrails.com/v1/domain/{self.domain}/associated-ips",
                  headers=hdrs)
        if r2 and r2.status_code == 200:
            try:
                for ip in r2.json().get("records", []):
                    if isinstance(ip, str) and _is_valid_ip(ip):
                        results.append({"ip": ip, "source": "securitytrails",
                                        "hostname": self.domain})
            except Exception:
                pass
        return results

    def _ips_fofa(self):
        if not (self.fofa_email and self.fofa_key):
            return []
        results = []
        try:
            query = f'domain="{self.domain}"'
            b64q  = base64.b64encode(query.encode()).decode()
            r = _get("https://fofa.info/api/v1/search/all",
                     params={"email": self.fofa_email, "key": self.fofa_key,
                             "qbase64": b64q, "size": 200, "fields": "host,ip,port,asn,org"})
            if not r or r.status_code != 200:
                return results
            for item in r.json().get("results", []):
                if isinstance(item, list) and len(item) >= 2:
                    ip = item[1].strip()
                    if _is_valid_ip(ip):
                        results.append({
                            "ip": ip,
                            "hostname": item[0].replace("https://", "").replace("http://", "").split("/")[0],
                            "ports": [int(item[2])] if len(item) > 2 and item[2] else [],
                            "asn": item[3] if len(item) > 3 else "",
                            "org": item[4] if len(item) > 4 else "",
                            "source": "fofa",
                        })
        except Exception:
            pass
        return results

    def _ips_zoomeye(self):
        if not self.zoomeye_key:
            return []
        results = []
        r = _get("https://api.zoomeye.org/host/search",
                 params={"query": f"hostname:{self.domain}", "page": 1},
                 headers={"Authorization": f"JWT {self.zoomeye_key}"})
        if not r or r.status_code != 200:
            return results
        try:
            for match in r.json().get("matches", []):
                ip = match.get("ip", "")
                if _is_valid_ip(ip):
                    results.append({
                        "ip": ip,
                        "hostname": ", ".join(match.get("rdns", {}).get("hostname", [])) if isinstance(match.get("rdns"), dict) else "",
                        "ports": [match.get("portinfo", {}).get("port", 0)],
                        "country": match.get("geoinfo", {}).get("country", {}).get("code", ""),
                        "source": "zoomeye",
                    })
        except Exception:
            pass
        return results

    def _ips_censys(self):
        if not (self.censys_id and self.censys_secret):
            return []
        results = []
        auth = (self.censys_id, self.censys_secret)
        # Search hosts by domain certificate
        r = _get("https://search.censys.io/api/v2/hosts/search",
                 params={"q": f"dns.names:{self.domain}", "per_page": 100},
                 auth=auth)
        if r and r.status_code == 200:
            try:
                for hit in r.json().get("result", {}).get("hits", []):
                    ip = hit.get("ip", "")
                    if _is_valid_ip(ip):
                        results.append({
                            "ip": ip,
                            "asn": str(hit.get("autonomous_system", {}).get("asn", "")),
                            "org": hit.get("autonomous_system", {}).get("name", ""),
                            "country": hit.get("location", {}).get("country_code", ""),
                            "ports": [s.get("port", 0) for s in hit.get("services", [])],
                            "source": "censys",
                        })
            except Exception:
                pass
        return results

    def _ips_netlas(self):
        if not self.netlas_key:
            return []
        results = []
        r = _get("https://app.netlas.io/api/responses/",
                 params={"q": f"domain:{self.domain}", "source_type": "include",
                         "start": 0, "size": 100,
                         "fields": "data.ip,data.port,data.geo.country,data.whois"},
                 headers={"X-API-Key": self.netlas_key, "User-Agent": _UA})
        if r and r.status_code == 200:
            try:
                for item in r.json().get("items", []):
                    d = item.get("data", {})
                    ip = d.get("ip", "")
                    if _is_valid_ip(ip):
                        results.append({
                            "ip": ip,
                            "country": d.get("geo", {}).get("country", ""),
                            "ports": [d.get("port", 0)],
                            "source": "netlas",
                        })
            except Exception:
                pass
        return results

    def _ips_greynoise(self):
        if not self.greynoise_key:
            return []
        results = []
        r = _get("https://api.greynoise.io/v3/experimental/gnql",
                 params={"q": f"metadata.rdns_parent:{self.domain}", "size": 100},
                 headers={"key": self.greynoise_key, "User-Agent": _UA})
        if r and r.status_code == 200:
            try:
                for rec in r.json().get("data", []):
                    ip = rec.get("ip", "")
                    if _is_valid_ip(ip):
                        results.append({
                            "ip": ip,
                            "country": rec.get("metadata", {}).get("country_code", ""),
                            "org": rec.get("metadata", {}).get("organization", ""),
                            "tags": rec.get("tags", []),
                            "source": "greynoise",
                        })
            except Exception:
                pass
        return results

    def _ips_criminalip(self):
        if not self.criminalip_key:
            return []
        results = []
        r = _get(f"https://api.criminalip.io/v1/domain/report/{self.domain}",
                 headers={"x-api-key": self.criminalip_key, "User-Agent": _UA})
        if r and r.status_code == 200:
            try:
                data = r.json()
                for rec in data.get("ip_address", {}).get("data", []):
                    ip = rec.get("ip_address", "")
                    if _is_valid_ip(ip):
                        results.append({
                            "ip": ip,
                            "country": rec.get("country_code", ""),
                            "org": rec.get("org_name", ""),
                            "source": "criminalip",
                        })
            except Exception:
                pass
        return results

    # ── Per-IP enrichment (free) ──────────────────────────────────────────────

    def _enrich_bgpview(self, ip):
        """BGPView — free ASN/prefix lookup."""
        r = _get(f"https://api.bgpview.io/ip/{ip}", timeout=10)
        if not r or r.status_code != 200:
            return {}
        try:
            d    = r.json().get("data", {})
            pfxs = d.get("prefixes", [])
            pfx  = pfxs[0] if pfxs else {}
            return {
                "cidr":    pfx.get("prefix", _cidr_from_ip(ip)),
                "asn":     str(pfx.get("asn", {}).get("asn", "")),
                "org":     pfx.get("asn", {}).get("description", ""),
                "country": pfx.get("country_code", ""),
                "rir":     pfx.get("rir_allocation", {}).get("rir_name", ""),
            }
        except Exception:
            return {}

    def _enrich_internetdb(self, ip):
        """Shodan InternetDB — free port/tag/vuln data."""
        r = _get(f"https://internetdb.shodan.io/{ip}", timeout=10)
        if not r or r.status_code != 200:
            return {}
        try:
            d = r.json()
            return {
                "ports":   d.get("ports", []),
                "tags":    d.get("tags", []),
                "vulns":   d.get("vulns", []),
                "cpes":    d.get("cpes", []),
                "hostnames": d.get("hostnames", []),
            }
        except Exception:
            return {}

    # ── Nmap service detection ───────────────────────────────────────────────

    def _nmap_services(self, ip, ports=None):
        """Run nmap -sV on specific ports (or top 100) and return service info."""
        if not self._use_nmap:
            return {}
        try:
            # Base command — always include -sV and grepable output
            cmd = ["nmap", "-sV", "--open", "-T4"]
            # Add user extra flags (already sanitized)
            # Check if user supplied their own -p / --top-ports / -sV etc.
            extra = self._nmap_extra
            has_port_spec = any(t.startswith("-p") or t.startswith("--top-ports") for t in extra)
            has_timing = any(t.startswith("-T") for t in extra)
            if has_timing:
                # Remove our default -T4 since user specified their own
                cmd = ["nmap", "-sV", "--open"]
            cmd += extra
            # Add port spec if user didn't supply one
            if not has_port_spec:
                if ports:
                    port_str = ",".join(str(p) for p in ports[:50])
                    cmd += ["-p", port_str]
                else:
                    cmd += ["--top-ports", "100"]
            # Grepable output to stdout (always last before target)
            cmd += ["-oG", "-", ip]
            self.emit({"type": "nmap_cmd", "ip": ip,
                       "cmd": " ".join(cmd)})
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            services = {}
            for line in proc.stdout.splitlines():
                if "/open/" in line:
                    # Parse grepable: Ports: 22/open/tcp//ssh//OpenSSH 8.9/
                    m = re.findall(r'(\d+)/open/(?:tcp|udp)//([^/]*)/(?:/([^/]*))?', line)
                    for port_s, svc, version in m:
                        port = int(port_s)
                        svc_name = svc.strip() or _PORT_SERVICES.get(port, "")
                        version = version.strip() if version else ""
                        services[port] = {"service": svc_name, "version": version}
            return services
        except subprocess.TimeoutExpired:
            self.emit({"type": "nmap_timeout", "ip": ip})
            return {}
        except Exception:
            return {}

    # ── Risk scoring ──────────────────────────────────────────────────────────

    def _risk(self, entry):
        score = 0
        vulns = entry.get("vulns", [])
        ports = entry.get("ports", [])
        tags  = [t.lower() for t in entry.get("tags", [])]
        if vulns:             score += len(vulns) * 20
        if any(p in ports for p in [22, 23, 3389, 5900, 6379, 9200, 27017]): score += 30
        if "malware" in tags or "compromised" in tags:  score += 50
        if "tor"     in tags or "vpn"         in tags:  score += 15
        if len(ports) > 10:   score += 10
        if score >= 60:       return "critical"
        if score >= 30:       return "high"
        if score >= 10:       return "medium"
        if score > 0:         return "low"
        return "info"

    # ── Main pipeline ─────────────────────────────────────────────────────────

    def run(self):
        target_label = self.targets_raw or self.domain
        self.emit({"type": "scan_start", "domain": self.domain, "targets": target_label})

        # ip_str → merged entry
        ip_map = {}

        def _new_entry(ip, source="direct"):
            return {"ip": ip, "sources": [source], "ports": [],
                    "tags": [], "vulns": [], "hostnames": [],
                    "cpes": [], "org": "", "asn": "", "cidr": "",
                    "country": "", "rir": "", "risk": "info",
                    "services": {}, "has_web": False}

        def _merge(entries, source):
            count = 0
            for e in entries:
                ip = e.get("ip", "").strip()
                if not ip:
                    continue
                if ip not in ip_map:
                    ip_map[ip] = _new_entry(ip, source)
                entry = ip_map[ip]
                if source not in entry["sources"]:
                    entry["sources"].append(source)
                for field in ("org", "asn", "cidr", "country", "rir"):
                    if not entry[field] and e.get(field):
                        entry[field] = e[field]
                for port in (e.get("ports") or []):
                    if port and port not in entry["ports"]:
                        entry["ports"].append(port)
                for tag in (e.get("tags") or []):
                    if tag not in entry["tags"]:
                        entry["tags"].append(tag)
                hn = e.get("hostname", "")
                if hn and hn not in entry["hostnames"]:
                    entry["hostnames"].append(hn)
                count += 1
            return count

        # ── Phase 0: Add direct IPs (from CIDR expansion or raw IP input) ───
        if self._direct_ips:
            for ip in self._direct_ips:
                if _is_valid_ip(ip) and ip not in ip_map:
                    ip_map[ip] = _new_entry(ip, "direct-input")
            self.emit({"type": "source_done", "source": "direct-input",
                       "count": len(self._direct_ips)})

        # Resolve domains to IPs and add them
        if self._domains:
            for dom in self._domains:
                resolved = _resolve_domain(dom)
                for ip in resolved:
                    if ip not in ip_map:
                        ip_map[ip] = _new_entry(ip, "dns-resolve")
                    entry = ip_map[ip]
                    if dom not in entry["hostnames"]:
                        entry["hostnames"].append(dom)
                    if "dns-resolve" not in entry["sources"]:
                        entry["sources"].append("dns-resolve")
                if resolved:
                    self.emit({"type": "source_done", "source": f"dns:{dom}",
                               "count": len(resolved)})

        # Add seed IPs from Domain Mapper
        if self.seed_ips:
            for ip in self.seed_ips:
                if _is_valid_ip(ip):
                    if ip not in ip_map:
                        ip_map[ip] = _new_entry(ip, "domain-mapper")
                    elif "domain-mapper" not in ip_map[ip]["sources"]:
                        ip_map[ip]["sources"].append("domain-mapper")
            self.emit({"type": "source_done", "source": "domain-mapper",
                       "count": len(self.seed_ips)})

        # ── Phase 1: collect IPs from OSINT sources (only for domains) ───────
        source_fns = []
        if self._domains:  # OSINT sources only work with domains
            if self._on("hackertarget"):
                source_fns.append(("hackertarget", self._ips_hackertarget))
            if self._on("shodan") and self.shodan_key:
                source_fns.append(("shodan", self._ips_shodan))
            if self._on("securitytrails") and self.securitytrails_key:
                source_fns.append(("securitytrails", self._ips_securitytrails))
            if self._on("fofa") and self.fofa_email and self.fofa_key:
                source_fns.append(("fofa", self._ips_fofa))
            if self._on("zoomeye") and self.zoomeye_key:
                source_fns.append(("zoomeye", self._ips_zoomeye))
            if self._on("censys") and self.censys_id and self.censys_secret:
                source_fns.append(("censys", self._ips_censys))
            if self._on("netlas") and self.netlas_key:
                source_fns.append(("netlas", self._ips_netlas))
            if self._on("greynoise") and self.greynoise_key:
                source_fns.append(("greynoise", self._ips_greynoise))
            if self._on("criminalip") and self.criminalip_key:
                source_fns.append(("criminalip", self._ips_criminalip))

        if source_fns:
            with ThreadPoolExecutor(max_workers=len(source_fns)) as ex:
                futs = {ex.submit(fn): name for name, fn in source_fns}
                for fut in as_completed(futs):
                    name = futs[fut]
                    self.emit({"type": "source_start", "source": name})
                    try:
                        entries = fut.result()
                        count   = _merge(entries, name)
                        self.emit({"type": "source_done", "source": name, "count": count})
                    except Exception:
                        self.emit({"type": "source_done", "source": name, "count": 0})

        if not ip_map:
            self.emit({"type": "scan_done", "total": 0, "unique_ips": 0, "unique_cidrs": 0})
            self._eq.put(None)
            return

        self.emit({"type": "collection_done", "unique_ips": len(ip_map)})

        # ── Phase 2: enrich each IP (BGPView + InternetDB) ───────────────────
        def _enrich(ip):
            entry = ip_map[ip]
            bgp = self._enrich_bgpview(ip)
            idb = self._enrich_internetdb(ip)
            for field in ("cidr", "asn", "org", "country", "rir"):
                if not entry[field] and bgp.get(field):
                    entry[field] = bgp[field]
            if not entry["cidr"]:
                entry["cidr"] = _cidr_from_ip(ip)
            for port in (idb.get("ports") or []):
                if port not in entry["ports"]:
                    entry["ports"].append(port)
            for tag in (idb.get("tags") or []):
                if tag not in entry["tags"]:
                    entry["tags"].append(tag)
            for vuln in (idb.get("vulns") or []):
                if vuln not in entry["vulns"]:
                    entry["vulns"].append(vuln)
            for cpe in (idb.get("cpes") or []):
                if cpe not in entry["cpes"]:
                    entry["cpes"].append(cpe)
            for hn in (idb.get("hostnames") or []):
                if hn not in entry["hostnames"]:
                    entry["hostnames"].append(hn)

            # Map ports to service names (fallback)
            if "services" not in entry:
                entry["services"] = {}
            for port in entry["ports"]:
                if port not in entry["services"]:
                    svc = _PORT_SERVICES.get(port, "")
                    entry["services"][port] = {"service": svc, "version": ""}

            # Detect web ports
            entry["has_web"] = bool(set(entry["ports"]) & WEB_PORTS)

            entry["risk"] = self._risk(entry)
            return entry

        with ThreadPoolExecutor(max_workers=20) as ex:
            futs = {ex.submit(_enrich, ip): ip for ip in ip_map}
            for fut in as_completed(futs):
                try:
                    entry = fut.result()
                    self.emit({"type": "ip_result", "entry": entry})
                except Exception:
                    pass

        # ── Phase 3 (optional): nmap service version detection ───────────────
        if self._use_nmap:
            self.emit({"type": "nmap_start", "count": len(ip_map)})
            nmap_done = 0
            with ThreadPoolExecutor(max_workers=5) as ex:
                def _nmap_ip(ip):
                    entry = ip_map[ip]
                    ports = entry["ports"][:50] if entry["ports"] else None
                    svcs = self._nmap_services(ip, ports)
                    if svcs:
                        entry["services"].update(svcs)
                        # Update service names from nmap results
                        for port, info in svcs.items():
                            if port not in entry["ports"]:
                                entry["ports"].append(port)
                        entry["has_web"] = bool(set(entry["ports"]) & WEB_PORTS)
                    return ip, svcs

                futs = {ex.submit(_nmap_ip, ip): ip for ip in ip_map}
                for fut in as_completed(futs):
                    try:
                        ip, svcs = fut.result()
                        nmap_done += 1
                        if svcs:
                            self.emit({"type": "nmap_result", "ip": ip,
                                       "services": {str(k): v for k, v in svcs.items()},
                                       "has_web": ip_map[ip]["has_web"]})
                        self.emit({"type": "nmap_progress", "done": nmap_done,
                                   "total": len(ip_map)})
                    except Exception:
                        nmap_done += 1
            self.emit({"type": "nmap_done"})

        # ── Summary ──────────────────────────────────────────────────────────
        all_entries  = list(ip_map.values())
        unique_cidrs = len({e["cidr"] for e in all_entries if e["cidr"]})
        # Convert services dict keys to strings for JSON
        for e in all_entries:
            if "services" in e:
                e["services"] = {str(k): v for k, v in e["services"].items()}
        self.emit({
            "type":        "scan_done",
            "total":       len(all_entries),
            "unique_ips":  len(all_entries),
            "unique_cidrs": unique_cidrs,
            "entries":     all_entries,
        })
        self._eq.put(None)
