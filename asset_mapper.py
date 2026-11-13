#!/usr/bin/env python3
"""
AssetMapper — Country-level ASN & Domain Discovery Tool
Maps: Country → ASNs → IP Prefixes → Domains → Critical Targets

Data sources (all free, no auth required by default):
  - RIPE Stat API    : country → ASN list + ASN overview + prefixes (fallback)
  - BGPView API      : ASN details + IP prefixes (primary)
  - crt.sh           : certificate transparency domain discovery
  - Reverse DNS      : hostname sampling across IP ranges
  - NetworksDB API   : ASN info, networks, IP→domain mapping (optional key)
  - Shodan API       : enhanced host/domain discovery (optional key)

DISCLAIMER: Use only on networks you are explicitly authorized to test.
"""

import re
import requests
import json
import time
import socket
import ipaddress
import argparse
import sys
import os
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
from datetime import datetime

# ──────────────────────────────────────────────────────────────────────────────
# Constants & Config
# ──────────────────────────────────────────────────────────────────────────────

RIPE_STAT_BASE      = "https://stat.ripe.net/data"
BGPVIEW_BASE        = "https://api.bgpview.io"
CRTSH_BASE          = "https://crt.sh"
NETWORKSDB_BASE     = "https://networksdb.io/api"
SHODAN_BASE         = "https://api.shodan.io"
CAIDA_BASE          = "https://api.asrank.caida.org/v2/restful"
SECURITYTRAILS_BASE = "https://api.securitytrails.com/v1"

# Politeness delay between API calls (seconds)
REQUEST_DELAY = 0.4

# Max prefixes to do reverse-DNS sampling on (avoid huge /8 ranges)
MAX_RDNS_PREFIXES = 5
# Max IPs to probe per prefix during reverse DNS
MAX_RDNS_HOSTS_PER_PREFIX = 40

# Critical infrastructure keyword taxonomy
CRITICAL_KEYWORDS = {
    "government":    ["gov", "govt", "government", "ministry", "minister",
                      "parliament", "senate", "cabinet", "federal", "municipal",
                      "presidency", "president", "prime-minister", "embassy"],
    "military":      ["mil", "army", "navy", "airforce", "air-force", "defense",
                      "defence", "military", "intelligence", "dod", "mod", "ispr",
                      "strategic", "corps", "brigade", "regiment"],
    "finance":       ["bank", "finance", "financial", "treasury", "central-bank",
                      "exchange", "payment", "imf", "worldbank", "fiscal", "revenue",
                      "tax", "customs", "irs", "sbp", "secp", "fintech", "credit"],
    "telecom":       ["telecom", "telco", "noc", "isp", "nic", "carrier",
                      "backbone", "peering", "transit", "pta", "fcc", "ofcom"],
    "grid_station":  ["grid", "grid-station", "power-grid", "electric-grid",
                      "substation", "transmission", "powerhouse", "wapda",
                      "pepco", "ntdc", "gepco", "fesco", "lesco", "mepco",
                      "iesco", "hesco", "qesco", "tesco", "pesco", "sepco",
                      "cppa", "npcc", "disco"],
    "critical_infra":["power", "energy", "electric", "water", "sewage",
                      "nuclear", "oil", "gas", "pipeline", "railway", "rail",
                      "airport", "port", "transport", "infra", "infrastructure"],
    "health":        ["health", "hospital", "medical", "clinic", "who", "cdc",
                      "pharma", "vaccine", "emergency", "rescue", "ems"],
    "cyber_security":["cert", "csirt", "cirt", "cyber", "soc", "siem", "ncert",
                      "pentest", "infosec", "cybersec"],
    "education":     ["edu", "university", "college", "school", "academy",
                      "institute", "hec", "uet", "nust", "pu", "ku"],
}

# ANSI colour helpers
C = {
    "red":    "\033[91m", "green":  "\033[92m", "yellow": "\033[93m",
    "blue":   "\033[94m", "cyan":   "\033[96m", "bold":   "\033[1m",
    "dim":    "\033[2m",  "reset":  "\033[0m",
}

def clr(text, *codes):
    return "".join(C.get(c, "") for c in codes) + str(text) + C["reset"]


# ──────────────────────────────────────────────────────────────────────────────
# Core Mapper Class
# ──────────────────────────────────────────────────────────────────────────────

class AssetMapper:
    def __init__(self, country_code, output_dir="output", threads=20,
                 shodan_key=None, networksdb_key=None, securitytrails_key=None,
                 sample_rdns=True, verbose=False, limit=None):
        self.cc                  = country_code.upper()
        self.output_dir          = output_dir
        self.threads             = threads
        self.shodan_key          = shodan_key
        self.networksdb_key      = networksdb_key
        self.securitytrails_key  = securitytrails_key
        self.sample_rdns         = sample_rdns
        self.verbose             = verbose
        self.limit               = limit
        self.session     = requests.Session()
        self.session.headers.update({
            "User-Agent": "AssetMapper/1.0 (Authorized Security Research)"
        })
        os.makedirs(output_dir, exist_ok=True)

    # ── Logging ───────────────────────────────────────────────────────────────

    def log(self, msg, level="info"):
        colour = {"info": "cyan", "warn": "yellow", "error": "red",
                  "success": "green", "header": "bold"}.get(level, "reset")
        print(f"  {clr(msg, colour)}")

    # ── HTTP helper ───────────────────────────────────────────────────────────

    def _get(self, url, params=None, retries=3, delay=REQUEST_DELAY):
        for attempt in range(retries):
            try:
                time.sleep(delay)
                r = self.session.get(url, params=params, timeout=20)
                if r.status_code == 200:
                    return r
                if r.status_code == 429:
                    wait = 30 * (attempt + 1)
                    self.log(f"Rate-limited ({url}), waiting {wait}s ...", "warn")
                    time.sleep(wait)
                elif r.status_code == 404:
                    return None
            except requests.exceptions.RequestException as e:
                if attempt == retries - 1 and self.verbose:
                    self.log(f"Request failed {url}: {e}", "error")
                time.sleep(2 ** attempt)
        return None

    # ── Step 1 — Country → ASNs ───────────────────────────────────────────────

    def get_country_asns(self):
        """Return all ASNs registered or routed from the target country."""
        self.log(f"Querying RIPE Stat for ASNs in: {self.cc}", "header")
        url = f"{RIPE_STAT_BASE}/country-asns/data.json"
        r   = self._get(url, params={"resource": self.cc, "lod": 1})
        if not r:
            self.log("RIPE Stat query failed — check country code.", "error")
            return []

        data      = r.json().get("data", {})
        countries = data.get("countries", [])
        if not countries:
            self.log("No country data returned — check country code.", "error")
            return []

        entry = countries[0]

        def _parse_asn_set(raw):
            """Parse '{AsnSingle(1234), AsnRange(x,y), ...}' strings."""
            asns = set()
            if not raw:
                return asns
            # AsnSingle(N)
            for m in re.finditer(r"AsnSingle\((\d+)\)", raw):
                asns.add(int(m.group(1)))
            # AsnRange(start, end)
            for m in re.finditer(r"AsnRange\((\d+),\s*(\d+)\)", raw):
                asns.update(range(int(m.group(1)), int(m.group(2)) + 1))
            return asns

        routed_asns     = _parse_asn_set(entry.get("routed", ""))
        non_routed_asns = _parse_asn_set(entry.get("non_routed", ""))
        stats           = entry.get("stats", {})
        all_asns        = sorted(routed_asns | non_routed_asns)

        self.log(
            f"Found {len(all_asns)} ASNs  "
            f"(routed: {stats.get('routed', len(routed_asns))}, "
            f"registered: {stats.get('registered', len(all_asns))})",
            "success"
        )

        if self.limit:
            self.log(f"Limiting to first {self.limit} ASNs.", "warn")
            all_asns = all_asns[: self.limit]

        return all_asns

    # ── Step 2 — ASN → Info + Prefixes ────────────────────────────────────────

    def get_asn_info(self, asn):
        """Fetch ASN metadata — tries BGPView first, falls back to RIPE Stat."""
        # Primary: BGPView
        r = self._get(f"{BGPVIEW_BASE}/asn/{asn}", delay=0.25)
        if r:
            d = r.json().get("data", {})
            return {
                "asn":         asn,
                "name":        d.get("name", f"AS{asn}"),
                "description": d.get("description_short") or d.get("description_full", ""),
                "country":     d.get("country_code", self.cc),
                "rir":         (d.get("rir_allocation") or {}).get("rir_name", ""),
                "website":     d.get("website", ""),
            }
        # Fallback: RIPE Stat as-overview
        r2 = self._get(f"{RIPE_STAT_BASE}/as-overview/data.json",
                       params={"resource": f"AS{asn}"}, delay=0.4)
        if r2:
            d2 = r2.json().get("data", {})
            holder = d2.get("holder", f"AS{asn}")
            # holder format: "ASN NAME-TAG Description ..."
            parts = holder.split(" ", 1)
            name  = parts[0] if parts else holder
            desc  = parts[1] if len(parts) > 1 else ""
            return {
                "asn":         asn,
                "name":        name,
                "description": desc,
                "country":     self.cc,
                "rir":         "",
                "website":     "",
            }
        return {"asn": asn, "name": f"AS{asn}", "description": "",
                "country": self.cc, "rir": "", "website": ""}

    def get_asn_prefixes(self, asn):
        """Return (ipv4_prefixes[], ipv6_prefixes[]) — BGPView then RIPE Stat fallback."""
        # Primary: BGPView
        r = self._get(f"{BGPVIEW_BASE}/asn/{asn}/prefixes", delay=0.25)
        if r:
            d  = r.json().get("data", {})
            v4 = [p["prefix"] for p in d.get("ipv4_prefixes", []) if p.get("prefix")]
            v6 = [p["prefix"] for p in d.get("ipv6_prefixes", []) if p.get("prefix")]
            return v4, v6
        # Fallback: RIPE Stat announced-prefixes
        r2 = self._get(f"{RIPE_STAT_BASE}/announced-prefixes/data.json",
                       params={"resource": f"AS{asn}"}, delay=0.4)
        if r2:
            prefixes = r2.json().get("data", {}).get("prefixes", [])
            v4, v6 = [], []
            for p in prefixes:
                pfx = p.get("prefix", "")
                if not pfx:
                    continue
                (v6 if ":" in pfx else v4).append(pfx)
            return v4, v6
        return [], []

    # ── Step 3 — Domain Discovery ─────────────────────────────────────────────

    def _crtsh_search(self, term):
        """Single crt.sh query; returns a set of domain names."""
        domains = set()
        r = self._get(CRTSH_BASE, params={"q": f"%{term}%", "output": "json"}, delay=1.2)
        if r:
            try:
                for cert in r.json():
                    for name in cert.get("name_value", "").split("\n"):
                        name = name.strip().lower().lstrip("*.")
                        if name and "." in name and " " not in name and "@" not in name:
                            domains.add(name)
            except (json.JSONDecodeError, ValueError):
                pass
        return domains

    def _build_search_terms(self, name, desc):
        """Extract 2-3 meaningful tokens to query crt.sh with."""
        stopwords = {
            "ltd", "inc", "llc", "corp", "co", "pvt", "limited", "as",
            "asn", "isp", "network", "networks", "communications", "telecom",
            "internet", "services", "group", "the", "and", "for", "of"
        }
        combined = f"{name} {desc}".lower()
        words    = [w.strip(".,()-") for w in combined.split()]
        terms    = [w for w in words if len(w) > 4 and w not in stopwords]
        # Deduplicate while preserving order
        seen, out = set(), []
        for t in terms:
            if t not in seen:
                seen.add(t)
                out.append(t)
        return out[:4]

    def discover_domains_crtsh(self, name, desc):
        """Discover domains via certificate transparency logs."""
        domains = set()
        terms   = self._build_search_terms(name, desc)
        for term in terms:
            if self.verbose:
                self.log(f"    crt.sh search: %{term}%", "dim" if hasattr(self, '_dim') else "info")
            domains.update(self._crtsh_search(term))
        return domains

    def _rdns_sample(self, prefix, max_hosts=MAX_RDNS_HOSTS_PER_PREFIX):
        """Reverse-DNS a sample of IPs from a CIDR prefix."""
        domains = set()
        try:
            net   = ipaddress.ip_network(prefix, strict=False)
            hosts = list(net.hosts())
            if len(hosts) > max_hosts:
                step   = max(1, len(hosts) // max_hosts)
                sample = hosts[::step][:max_hosts]
            else:
                sample = hosts
            for ip in sample:
                try:
                    hostname = socket.gethostbyaddr(str(ip))[0].lower()
                    if "." in hostname:
                        domains.add(hostname)
                except (socket.herror, socket.gaierror, OSError):
                    pass
        except Exception:
            pass
        return domains

    def discover_domains_rdns(self, v4_prefixes):
        """Parallel reverse-DNS across sampled prefixes."""
        domains = set()
        # Prefer smaller prefixes (≥/20) to avoid probing huge address spaces
        candidates = sorted(
            v4_prefixes,
            key=lambda p: int(p.split("/")[1]) if "/" in p else 0,
            reverse=True
        )[:MAX_RDNS_PREFIXES]

        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(self._rdns_sample, p): p for p in candidates}
            for f in as_completed(futures):
                try:
                    domains.update(f.result())
                except Exception:
                    pass
        return domains

    def _ndb(self, endpoint, params=None):
        """NetworksDB authenticated GET helper."""
        if not self.networksdb_key:
            return None
        merged = {"apikey": self.networksdb_key}
        if params:
            merged.update(params)
        return self._get(f"{NETWORKSDB_BASE}/{endpoint}", params=merged, delay=0.5)

    def networksdb_asn_info(self, asn):
        """
        Enrich ASN metadata from NetworksDB.
        Returns a dict with extra fields, or {} if unavailable.
        """
        r = self._ndb("asn-info", {"asn": asn})
        if not r:
            return {}
        try:
            d = r.json()
            if d.get("error"):
                return {}
            return {
                "ndb_name":        d.get("name", ""),
                "ndb_description": d.get("description", ""),
                "ndb_country":     d.get("country", ""),
                "ndb_website":     d.get("website", ""),
                "ndb_abuse_email": d.get("abuse_email", ""),
            }
        except (ValueError, KeyError):
            return {}

    def networksdb_asn_prefixes(self, asn):
        """
        Fetch IP networks announced by ASN from NetworksDB (paginated).
        Returns (v4[], v6[]) to supplement BGPView/RIPE data.
        """
        if not self.networksdb_key:
            return [], []
        v4, v6 = [], []
        page = 1
        while True:
            r = self._ndb("asn-networks", {"asn": asn, "page": page})
            if not r:
                break
            try:
                data = r.json()
                if data.get("error") or not data.get("results"):
                    break
                for net in data["results"]:
                    pfx = net.get("cidr", "")
                    if not pfx:
                        continue
                    (v6 if ":" in pfx else v4).append(pfx)
                # NetworksDB paginates with a 'next' field
                if not data.get("next"):
                    break
                page += 1
            except (ValueError, KeyError):
                break
        return v4, v6

    def networksdb_ip_domains(self, ip):
        """
        Resolve all domains hosted on a single IP using NetworksDB.
        Useful for targeted enrichment of key IPs.
        """
        r = self._ndb("ip-domains", {"ip": ip})
        if not r:
            return []
        try:
            data = r.json()
            if data.get("error"):
                return []
            return [d.lower() for d in data.get("domains", []) if "." in d]
        except (ValueError, KeyError):
            return []

    def networksdb_asn_domains(self, asn, v4_prefixes):
        """
        Discover domains within an ASN by probing a sample of IPs via NetworksDB
        ip-domains endpoint (far more complete than reverse DNS alone).
        """
        if not self.networksdb_key or not v4_prefixes:
            return set()

        # Build a sample of representative IPs (first usable from each prefix)
        sample_ips = []
        for pfx in v4_prefixes[:20]:   # cap at 20 prefixes
            try:
                net   = ipaddress.ip_network(pfx, strict=False)
                hosts = list(net.hosts())
                if hosts:
                    sample_ips.append(str(hosts[0]))
                    # Also include middle IP for wider coverage
                    if len(hosts) > 10:
                        sample_ips.append(str(hosts[len(hosts) // 2]))
            except Exception:
                pass

        domains = set()
        with ThreadPoolExecutor(max_workers=min(self.threads, 10)) as ex:
            futures = {ex.submit(self.networksdb_ip_domains, ip): ip
                       for ip in sample_ips}
            for f in as_completed(futures):
                try:
                    domains.update(f.result())
                except Exception:
                    pass
        return domains

    def discover_domains_shodan(self, asn):
        """Enhanced domain discovery via Shodan (requires API key)."""
        if not self.shodan_key:
            return set()
        domains = set()
        url     = f"{SHODAN_BASE}/shodan/host/search"
        params  = {
            "key":   self.shodan_key,
            "query": f"asn:AS{asn}",
            "facets": "hostnames",
            "page":  1,
        }
        r = self._get(url, params=params, delay=1.0)
        if r:
            try:
                for match in r.json().get("matches", []):
                    for h in match.get("hostnames", []):
                        if h and "." in h:
                            domains.add(h.lower())
            except (json.JSONDecodeError, ValueError):
                pass
        return domains

    def get_caida_rank(self, asn):
        """Fetch CAIDA AS Rank data for an ASN (free, no key required)."""
        r = self._get(f"{CAIDA_BASE}/asns/{asn}", delay=0.3)
        if not r:
            return {}
        try:
            data = r.json().get("data", {}).get("asns", {})
            edges = data.get("edges", [])
            if not edges:
                return {}
            node = edges[0].get("node", {})
            return {
                "caida_rank":     node.get("rank"),
                "caida_org":      (node.get("organization") or {}).get("orgName", ""),
                "caida_cone_asns": (node.get("cone") or {}).get("numberAsns", 0),
                "caida_cone_pfx":  (node.get("cone") or {}).get("numberPrefixes", 0),
            }
        except (ValueError, KeyError, TypeError):
            return {}

    def securitytrails_asn_domains(self, asn):
        """Fetch domains for an ASN via SecurityTrails (requires API key)."""
        if not self.securitytrails_key:
            return set()
        domains = set()
        url     = f"{SECURITYTRAILS_BASE}/domains/list"
        headers = {"APIKEY": self.securitytrails_key, "Content-Type": "application/json"}
        payload = {"filter": {"asn": f"AS{asn}"}}
        try:
            r = self.session.post(url, json=payload, headers=headers, timeout=20)
            if r.status_code == 200:
                for rec in r.json().get("records", []):
                    host = rec.get("hostname", "")
                    if host and "." in host:
                        domains.add(host.lower())
        except Exception:
            pass
        return domains

    # ── Step 4 — Classification ───────────────────────────────────────────────

    def classify_domains(self, domains):
        """
        Bucket domains into critical categories.
        Returns dict: {category: [domain, ...], ...}
        Domains matching no keyword go into 'other'.
        """
        buckets = defaultdict(list)
        for domain in sorted(domains):
            matched = False
            for category, keywords in CRITICAL_KEYWORDS.items():
                if any(kw in domain for kw in keywords):
                    buckets[category].append(domain)
                    matched = True
                    break
            if not matched:
                buckets["other"].append(domain)
        return dict(buckets)

    def classify_asn(self, name, desc):
        """Return the primary category of the ASN itself."""
        text = f"{name} {desc}".lower()
        for category, keywords in CRITICAL_KEYWORDS.items():
            if any(kw in text for kw in keywords):
                return category
        return "commercial"

    # ── Per-ASN Pipeline ──────────────────────────────────────────────────────

    def process_asn(self, asn):
        """Full discovery pipeline for a single ASN number."""
        info = self.get_asn_info(asn)
        name, desc = info.get("name", ""), info.get("description", "")

        if self.verbose:
            self.log(f"AS{asn} | {name} | {desc[:60]}", "info")

        # IP prefixes — BGPView primary, RIPE Stat fallback
        v4, v6 = self.get_asn_prefixes(asn)

        # NetworksDB: enrich ASN metadata + supplement prefixes
        if self.networksdb_key:
            ndb_meta = self.networksdb_asn_info(asn)
            if ndb_meta:
                info.update(ndb_meta)
                # Fill gaps in name/description from NetworksDB
                if not info.get("name") or info["name"] == f"AS{asn}":
                    info["name"]        = ndb_meta.get("ndb_name", info["name"])
                    info["description"] = ndb_meta.get("ndb_description", info["description"])
            ndb_v4, ndb_v6 = self.networksdb_asn_prefixes(asn)
            v4 = sorted(set(v4) | set(ndb_v4))
            v6 = sorted(set(v6) | set(ndb_v6))

        info["prefixes_v4"] = v4
        info["prefixes_v6"] = v6
        info["prefix_count"] = len(v4) + len(v6)

        # CAIDA AS Rank (free, always)
        caida = self.get_caida_rank(asn)
        info.update(caida)

        # Domain discovery
        domains = set()
        domains.update(self.discover_domains_crtsh(name, desc))
        if self.sample_rdns and v4:
            domains.update(self.discover_domains_rdns(v4))
        if self.networksdb_key and v4:
            domains.update(self.networksdb_asn_domains(asn, v4))
        if self.shodan_key:
            domains.update(self.discover_domains_shodan(asn))
        if self.securitytrails_key:
            domains.update(self.securitytrails_asn_domains(asn))

        # Enrich result
        domains = {d for d in domains if "@" not in d}
        info["domains"]      = sorted(domains)
        info["domain_count"] = len(domains)
        info["classified"]   = self.classify_domains(domains)
        info["asn_category"] = self.classify_asn(name, desc)

        return info

    # ── Orchestration ─────────────────────────────────────────────────────────

    def run(self):
        print()
        print(clr("═" * 72, "bold"))
        print(clr(f"  AssetMapper  |  Country: {self.cc}  |  {datetime.now():%Y-%m-%d %H:%M}", "bold"))
        print(clr("═" * 72, "bold"))
        print()

        asns = self.get_country_asns()
        if not asns:
            return []

        print()
        extras = []
        if self.sample_rdns:    extras.append("rDNS")
        if self.networksdb_key: extras.append("NetworksDB")
        if self.shodan_key:     extras.append("Shodan")
        extra_str = " + ".join(extras) if extras else "passive only"
        print(clr(f"  [*] Processing {len(asns)} ASNs  [{extra_str}] ...", "yellow"))
        print()

        asn_data = []
        for i, asn in enumerate(asns, 1):
            sys.stdout.write(f"\r  [{i:>4}/{len(asns)}] AS{asn:<8} ...          ")
            sys.stdout.flush()
            try:
                asn_data.append(self.process_asn(asn))
            except KeyboardInterrupt:
                print("\n  Interrupted — saving partial results ...")
                break
            except Exception as e:
                if self.verbose:
                    self.log(f"Error on AS{asn}: {e}", "error")

        print("\n")
        self.generate_report(asn_data)
        return asn_data

    # ── Reporting ─────────────────────────────────────────────────────────────

    def generate_report(self, asn_data):
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        base = os.path.join(self.output_dir, f"{self.cc}_{ts}")

        total_domains  = sum(a["domain_count"] for a in asn_data)
        critical_asns  = [a for a in asn_data if a["asn_category"] != "commercial"]
        all_domains    = sorted({d for a in asn_data for d in a["domains"]})
        all_critical   = [d for a in asn_data
                          for cat, doms in a.get("classified", {}).items()
                          for d in doms if cat != "other"]

        # ── Console ───────────────────────────────────────────────────────────
        print(clr("═" * 72, "bold"))
        print(clr(f"  MAPPING COMPLETE — {self.cc}", "bold"))
        print(clr("═" * 72, "bold"))
        print()
        print(f"  {clr('Total ASNs processed :', 'cyan')}  {len(asn_data)}")
        print(f"  {clr('Critical ASNs        :', 'red')}  {len(critical_asns)}")
        print(f"  {clr('Total unique domains  :', 'cyan')}  {total_domains}")
        print(f"  {clr('Critical domains      :', 'red')}  {len(all_critical)}")
        print()

        # Sort: critical ASNs first, then by domain count
        def sort_key(a):
            return (0 if a["asn_category"] != "commercial" else 1,
                    -a["domain_count"])

        for asn in sorted(asn_data, key=sort_key):
            cat       = asn.get("asn_category", "commercial")
            cat_color = "red" if cat != "commercial" else "green"
            flag      = clr("★", "red") if cat != "commercial" else " "

            print(f"  {flag} {clr('AS'+str(asn['asn']), 'bold'):<12} "
                  f"{clr(asn['name'][:32], 'yellow'):<34} "
                  f"{clr(f'[{cat.upper()[:14]}]', cat_color):<20} "
                  f"Prefixes: {asn['prefix_count']:<5} "
                  f"Domains: {clr(str(asn['domain_count']), 'cyan')}")

            classified = asn.get("classified", {})
            for bucket, doms in classified.items():
                if bucket != "other" and doms:
                    print(f"       {clr('►', 'red')} [{bucket}] — {len(doms)} domain(s):")
                    for d in sorted(doms)[:8]:
                        print(f"           {clr(d, 'dim') if False else d}")
                    if len(doms) > 8:
                        print(f"           {clr(f'... and {len(doms)-8} more', 'dim')}")
            print()

        # ── JSON ──────────────────────────────────────────────────────────────
        json_path = f"{base}.json"
        with open(json_path, "w") as f:
            json.dump({
                "country":        self.cc,
                "timestamp":      ts,
                "total_asns":     len(asn_data),
                "total_domains":  total_domains,
                "critical_asns":  len(critical_asns),
                "critical_domains": len(all_critical),
                "asns":           asn_data,
            }, f, indent=2)

        # ── CSV ───────────────────────────────────────────────────────────────
        csv_path = f"{base}_asns.csv"
        with open(csv_path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow([
                "ASN", "Name", "Description", "Category", "RIR",
                "IPv4_Prefixes", "IPv6_Prefixes", "Domain_Count",
                "Critical_Domain_Count", "Sample_Domains"
            ])
            for a in asn_data:
                crit_count = sum(
                    len(v) for k, v in a.get("classified", {}).items()
                    if k != "other"
                )
                w.writerow([
                    a["asn"], a["name"], a["description"],
                    a["asn_category"], a.get("rir", ""),
                    len(a["prefixes_v4"]), len(a["prefixes_v6"]),
                    a["domain_count"], crit_count,
                    "|".join(a["domains"][:30]),
                ])

        # ── All Domains ───────────────────────────────────────────────────────
        domains_path = f"{base}_domains.txt"
        with open(domains_path, "w") as f:
            f.write("\n".join(all_domains))

        # ── Critical Targets Report ───────────────────────────────────────────
        crit_path = f"{base}_critical.txt"
        with open(crit_path, "w") as f:
            f.write(f"CRITICAL ASSET REPORT — {self.cc}\n")
            f.write(f"Generated: {datetime.now():%Y-%m-%d %H:%M:%S}\n")
            f.write("=" * 60 + "\n\n")
            for a in sorted(critical_asns, key=lambda x: -x["domain_count"]):
                f.write(f"AS{a['asn']} — {a['name']}  [{a['asn_category'].upper()}]\n")
                f.write(f"  Description : {a['description']}\n")
                f.write(f"  RIR         : {a.get('rir','')}\n")
                f.write(f"  IPv4 Prefixes ({len(a['prefixes_v4'])}):\n")
                for p in a["prefixes_v4"]:
                    f.write(f"    {p}\n")
                for bucket, doms in a.get("classified", {}).items():
                    if bucket != "other" and doms:
                        f.write(f"  [{bucket.upper()}] Domains ({len(doms)}):\n")
                        for d in sorted(doms):
                            f.write(f"    {d}\n")
                f.write("\n")

        # ── IP Ranges (for all ASNs) ──────────────────────────────────────────
        ip_path = f"{base}_ip_ranges.txt"
        with open(ip_path, "w") as f:
            f.write(f"IP RANGES — {self.cc}\n")
            f.write(f"Generated: {datetime.now():%Y-%m-%d %H:%M:%S}\n")
            f.write("=" * 60 + "\n\n")
            for a in asn_data:
                if a["prefixes_v4"] or a["prefixes_v6"]:
                    f.write(f"# AS{a['asn']} — {a['name']}\n")
                    for p in a["prefixes_v4"]:
                        f.write(f"{p}\n")
                    f.write("\n")

        print(clr(f"  Output saved to: {os.path.abspath(self.output_dir)}/", "green"))
        print(f"    {clr('Full JSON    :', 'cyan')}  {json_path}")
        print(f"    {clr('ASN CSV      :', 'cyan')}  {csv_path}")
        print(f"    {clr('All Domains  :', 'cyan')}  {domains_path}")
        print(f"    {clr('Critical     :', 'red')}   {crit_path}")
        print(f"    {clr('IP Ranges    :', 'cyan')}  {ip_path}")
        print()


# ──────────────────────────────────────────────────────────────────────────────
# CLI Entry Point
# ──────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="asset_mapper",
        description="AssetMapper — Country-level ASN & Domain Discovery",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python asset_mapper.py PK                               # Full Pakistan mapping
  python asset_mapper.py US --limit 20                    # First 20 US ASNs
  python asset_mapper.py DE --no-rdns                     # Skip reverse DNS
  python asset_mapper.py GB --networksdb KEY -v           # NetworksDB enrichment
  python asset_mapper.py JP --networksdb KEY --shodan KEY # Full enrichment
  python asset_mapper.py TR --output results/TR           # Custom output dir

Output files (in output/ by default):
  <CC>_<ts>.json            Full structured data
  <CC>_<ts>_asns.csv        One row per ASN
  <CC>_<ts>_domains.txt     All discovered domains
  <CC>_<ts>_critical.txt    Critical infrastructure targets
  <CC>_<ts>_ip_ranges.txt   All IP prefixes by ASN

Supported country codes: ISO 3166-1 alpha-2 (PK, US, GB, DE, JP, ...)

DISCLAIMER: For use on networks you are explicitly authorized to assess only.
"""
    )

    parser.add_argument(
        "country",
        metavar="COUNTRY_CODE",
        help="ISO 3166-1 alpha-2 country code (e.g. PK, US, GB, DE)",
    )
    parser.add_argument(
        "--output", "-o",
        default="output",
        metavar="DIR",
        help="Output directory (default: output/)",
    )
    parser.add_argument(
        "--limit", "-l",
        type=int,
        metavar="N",
        help="Process only the first N ASNs (useful for testing)",
    )
    parser.add_argument(
        "--threads", "-t",
        type=int,
        default=20,
        metavar="N",
        help="Thread count for parallel reverse DNS (default: 20)",
    )
    parser.add_argument(
        "--no-rdns",
        action="store_true",
        help="Skip reverse DNS hostname sampling",
    )
    parser.add_argument(
        "--networksdb",
        metavar="API_KEY",
        help="NetworksDB API key for ASN enrichment, prefix data, and IP→domain mapping",
    )
    parser.add_argument(
        "--shodan",
        metavar="API_KEY",
        help="Shodan API key for enhanced domain/host discovery",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print per-ASN details while processing",
    )

    args = parser.parse_args()

    if len(args.country) != 2 or not args.country.isalpha():
        parser.error("Country code must be exactly 2 letters (e.g. PK, US, GB)")

    mapper = AssetMapper(
        country_code    = args.country,
        output_dir      = args.output,
        threads         = args.threads,
        shodan_key      = args.shodan,
        networksdb_key  = args.networksdb,
        sample_rdns     = not args.no_rdns,
        verbose         = args.verbose,
        limit           = args.limit,
    )

    try:
        mapper.run()
    except KeyboardInterrupt:
        print("\n\n  Aborted by user.")
        sys.exit(0)


if __name__ == "__main__":
    main()
