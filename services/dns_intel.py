"""DNS Intelligence — full record enumeration, zone transfer, passive DNS."""
import socket, ssl, queue, uuid, threading
import dns.resolver, dns.zone, dns.query, dns.exception
import requests as _req

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA", "PTR", "SRV", "DMARC"]


def enumerate_dns(domain: str) -> dict:
    """Return all DNS records for a domain."""
    records = {}
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 8

    for rtype in RECORD_TYPES:
        try:
            qtype = "TXT" if rtype == "DMARC" else rtype
            qname = f"_dmarc.{domain}" if rtype == "DMARC" else domain
            answers = resolver.resolve(qname, qtype)
            records[rtype] = [str(r) for r in answers]
        except Exception:
            records[rtype] = []

    return records


def zone_transfer(domain: str) -> list:
    """Attempt AXFR zone transfer against all NS servers."""
    results = []
    try:
        ns_records = dns.resolver.resolve(domain, "NS")
        for ns in ns_records:
            ns_host = str(ns).rstrip(".")
            try:
                ns_ip = socket.gethostbyname(ns_host)
                z = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=10))
                for name in z.nodes:
                    results.append(f"{name}.{domain}")
            except Exception:
                pass
    except Exception:
        pass
    return results


def passive_dns(domain: str) -> list:
    """VirusTotal passive DNS (no key needed for basic queries)."""
    results = []
    try:
        r = _req.get(
            f"https://www.virustotal.com/vtapi/v2/domain/report",
            params={"domain": domain, "apikey": ""},
            timeout=10,
        )
        data = r.json()
        for rec in data.get("resolutions", [])[:20]:
            results.append({
                "ip": rec.get("ip_address", ""),
                "last_resolved": rec.get("last_resolved", ""),
            })
    except Exception:
        pass
    return results


def crt_history(domain: str) -> list:
    """Certificate transparency history from crt.sh."""
    results = []
    try:
        r = _req.get(
            "https://crt.sh/",
            params={"q": domain, "output": "json"},
            timeout=15,
        )
        seen = set()
        for cert in r.json()[:50]:
            name = cert.get("name_value", "").split("\n")[0].strip()
            issuer = cert.get("issuer_name", "")
            not_before = cert.get("not_before", "")
            not_after = cert.get("not_after", "")
            key = f"{name}:{not_before}"
            if key not in seen:
                seen.add(key)
                results.append({
                    "name": name,
                    "issuer": issuer,
                    "not_before": not_before,
                    "not_after": not_after,
                    "id": cert.get("id", ""),
                })
    except Exception:
        pass
    return results


def full_dns_scan(domain: str, event_queue: queue.Queue):
    """Run full DNS intelligence scan, emitting SSE events."""
    event_queue.put({"type": "dns_start", "domain": domain})

    event_queue.put({"type": "dns_progress", "step": "records"})
    records = enumerate_dns(domain)
    event_queue.put({"type": "dns_records", "domain": domain, "records": records})

    event_queue.put({"type": "dns_progress", "step": "zone_transfer"})
    zt = zone_transfer(domain)
    event_queue.put({"type": "dns_zone_transfer",
                     "domain": domain,
                     "success": len(zt) > 0,
                     "records": zt[:100]})

    event_queue.put({"type": "dns_progress", "step": "cert_history"})
    certs = crt_history(domain)
    event_queue.put({"type": "dns_cert_history", "domain": domain, "certs": certs})

    event_queue.put({"type": "dns_complete", "domain": domain,
                     "summary": {
                         "record_types": {k: len(v) for k, v in records.items() if v},
                         "zone_transfer": len(zt) > 0,
                         "certs_found": len(certs),
                     }})
    event_queue.put(None)
