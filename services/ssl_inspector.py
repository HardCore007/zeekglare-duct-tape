"""SSL/TLS Inspector — certificate analysis, cipher suites, expiry."""
import ssl, socket, datetime, json, hashlib, queue

WEAK_CIPHERS = {"RC4", "DES", "3DES", "NULL", "EXPORT", "MD5", "ADH", "AECDH"}
WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


def _connect(hostname: str, port: int, timeout: int = 10):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    s = socket.create_connection((hostname, port), timeout=timeout)
    return ctx.wrap_socket(s, server_hostname=hostname)


def inspect_ssl(hostname: str, port: int = 443) -> dict:
    result = {
        "hostname": hostname,
        "port": port,
        "reachable": False,
        "cert": {},
        "cipher": {},
        "protocol": "",
        "issues": [],
        "score": 100,
    }

    try:
        with _connect(hostname, port) as conn:
            result["reachable"] = True
            cert    = conn.getpeercert()
            cipher  = conn.cipher()         # (name, proto, bits)
            proto   = conn.version()

            result["protocol"] = proto
            result["cipher"]   = {
                "name":     cipher[0] if cipher else "",
                "protocol": cipher[1] if cipher else "",
                "bits":     cipher[2] if cipher else 0,
            }

            # Parse cert
            subject  = dict(x[0] for x in cert.get("subject", []))
            issuer   = dict(x[0] for x in cert.get("issuer", []))
            san      = [v for _, v in cert.get("subjectAltName", [])]
            not_after  = cert.get("notAfter", "")
            not_before = cert.get("notBefore", "")

            expiry = None
            days_left = None
            if not_after:
                try:
                    expiry    = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    days_left = (expiry - datetime.datetime.utcnow()).days
                except Exception:
                    pass

            result["cert"] = {
                "subject":    subject,
                "issuer":     issuer,
                "san":        san[:20],
                "not_before": not_before,
                "not_after":  not_after,
                "days_left":  days_left,
                "serial":     cert.get("serialNumber", ""),
            }

            # Score deductions
            issues = []
            if proto in WEAK_PROTOCOLS:
                issues.append(f"Weak protocol: {proto}")
                result["score"] -= 30
            if cipher and any(w in cipher[0].upper() for w in WEAK_CIPHERS):
                issues.append(f"Weak cipher: {cipher[0]}")
                result["score"] -= 20
            if cipher and cipher[2] and cipher[2] < 128:
                issues.append(f"Short key length: {cipher[2]} bits")
                result["score"] -= 20
            if days_left is not None and days_left < 0:
                issues.append("Certificate EXPIRED")
                result["score"] -= 40
            elif days_left is not None and days_left < 30:
                issues.append(f"Expires soon: {days_left} days")
                result["score"] -= 10
            if not issuer.get("organizationName") and not issuer.get("O"):
                issues.append("Self-signed certificate")
                result["score"] -= 15

            result["issues"] = issues
            result["score"]   = max(0, result["score"])

    except ssl.SSLError as e:
        result["issues"].append(f"SSL error: {str(e)[:100]}")
        result["score"] = 0
    except ConnectionRefusedError:
        result["issues"].append("Connection refused")
    except socket.timeout:
        result["issues"].append("Connection timed out")
    except Exception as e:
        result["issues"].append(str(e)[:100])

    return result


def bulk_ssl_scan(targets: list, event_queue: queue.Queue):
    """Scan multiple targets and stream results."""
    event_queue.put({"type": "ssl_start", "total": len(targets)})
    for t in targets:
        host = t if isinstance(t, str) else t.get("domain", "")
        if not host:
            continue
        r = inspect_ssl(host)
        event_queue.put({"type": "ssl_result", "result": r})
    event_queue.put({"type": "ssl_complete"})
    event_queue.put(None)
