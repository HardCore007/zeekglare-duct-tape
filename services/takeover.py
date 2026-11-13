"""Subdomain takeover detection service."""
import socket
import requests
import dns.resolver

# CNAME-based takeover fingerprints
TAKEOVER_SIGNATURES = {
    "github.io":            ("There isn't a GitHub Pages site here",         "GitHub Pages"),
    "heroku.com":           ("No such app",                                   "Heroku"),
    "herokussl.com":        ("No such app",                                   "Heroku"),
    "pantheon.io":          ("The gods are wise",                             "Pantheon"),
    "wordpress.com":        ("Do you want to register",                       "WordPress"),
    "shopify.com":          ("Sorry, this shop is currently unavailable",     "Shopify"),
    "amazonaws.com":        ("NoSuchBucket",                                  "AWS S3"),
    "s3.amazonaws.com":     ("NoSuchBucket",                                  "AWS S3"),
    "tumblr.com":           ("Whatever you were looking for doesn't currently exist", "Tumblr"),
    "ghost.io":             ("The thing you were looking for is no longer here", "Ghost"),
    "fastly.net":           ("Fastly error: unknown domain",                  "Fastly"),
    "zendesk.com":          ("Help Center Closed",                            "Zendesk"),
    "readme.io":            ("Project doesnt exist",                          "ReadMe"),
    "surge.sh":             ("project not found",                             "Surge"),
    "bitbucket.io":         ("Repository not found",                          "Bitbucket"),
    "unbounce.com":         ("The requested URL was not found",               "Unbounce"),
    "helpscout.net":        ("No settings were found for this company",       "HelpScout"),
    "uservoice.com":        ("This UserVoice subdomain is currently available", "UserVoice"),
    "azurewebsites.net":    ("404 Web Site not found",                        "Azure App Service"),
    "cloudapp.azure.com":   ("404 Web Site not found",                        "Azure Cloud App"),
    "trafficmanager.net":   ("",                                              "Azure Traffic Manager"),
    "cloudfront.net":       ("ERROR: The request could not be satisfied",     "AWS CloudFront"),
    "desk.com":             ("Sorry, We couldn't find your page",             "Desk"),
    "campaignmonitor.com":  ("Trying to access your account",                 "Campaign Monitor"),
    "wixsite.com":          ("Error ConnectYourDomain",                       "Wix"),
    "tilda.cc":             ("Please renew your subscription",                "Tilda"),
    "strikingly.com":       ("MISSING",                                       "Strikingly"),
    "webflow.io":           ("The page you are looking for doesn't exist",    "Webflow"),
    "ngrok.io":             ("Tunnel .* not found",                           "Ngrok"),
}


def check_subdomain_takeover(subdomains: list) -> list:
    """Check a flat list of subdomains (FQDNs) for takeover potential."""
    findings = []
    for fqdn in subdomains[:60]:
        r = _check_single(fqdn.strip())
        if r:
            findings.append(r)
    return findings


def _check_single(fqdn: str) -> dict | None:
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 3

        # Resolve CNAME
        try:
            answers = resolver.resolve(fqdn, "CNAME")
            cname_target = str(answers[0].target).rstrip(".")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            return None
        except Exception:
            return None

        # Check if cname target resolves
        try:
            socket.setdefaulttimeout(3)
            socket.gethostbyname(cname_target)
            target_resolves = True
        except socket.gaierror:
            target_resolves = False

        # Match against known services
        for domain_suffix, (fingerprint, service_name) in TAKEOVER_SIGNATURES.items():
            if domain_suffix not in cname_target:
                continue

            finding = {
                "subdomain": fqdn,
                "cname": cname_target,
                "service": service_name,
                "resolves": target_resolves,
                "risk": "HIGH" if not target_resolves else "MEDIUM",
                "status": "",
            }

            if not target_resolves:
                finding["status"] = "CNAME points to NXDOMAIN — likely vulnerable"
                finding["risk"] = "CRITICAL"
                return finding

            # Try to fetch and match fingerprint
            if fingerprint:
                try:
                    resp = requests.get(
                        f"https://{fqdn}", timeout=6, allow_redirects=True,
                        headers={"User-Agent": "Mozilla/5.0"},
                    )
                    if fingerprint.lower() in resp.text.lower():
                        finding["status"] = f"Fingerprint matched — {service_name} unclaimed"
                        finding["risk"] = "CRITICAL"
                    else:
                        finding["status"] = "CNAME matches known service; fingerprint not found"
                        finding["risk"] = "LOW"
                except Exception:
                    finding["status"] = "Resolves but could not verify — check manually"
            else:
                finding["status"] = "CNAME points to unchecked service"

            return finding

        # CNAME target doesn't resolve to any known service but is NXDOMAIN
        if not target_resolves:
            return {
                "subdomain": fqdn,
                "cname": cname_target,
                "service": "Unknown",
                "resolves": False,
                "risk": "MEDIUM",
                "status": "CNAME target NXDOMAIN — investigate manually",
            }

    except Exception:
        pass

    return None
