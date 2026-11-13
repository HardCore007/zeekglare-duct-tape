from core.auth_utils import module_required
"""OSINT blueprint — WHOIS, geolocation, emails, GitHub dorking, CVE lookup."""
import threading, json
from flask import Blueprint, request, jsonify
from services.osint import (
    whois_lookup, geolocate_ip, geolocate_bulk,
    harvest_emails_hunter, harvest_emails_free, github_dork,
)
from services.cve_lookup import lookup_cves
from services.ssl_inspector import inspect_ssl

osint_bp = Blueprint("osint", __name__)


@osint_bp.route("/api/osint/whois", methods=["POST"])
@module_required("osint")
def whois_route():
    body = request.get_json(silent=True) or {}
    domain = (body.get("domain") or "").strip()
    if not domain:
        return jsonify({"error": "domain required"}), 400
    return jsonify({"domain": domain, "whois": whois_lookup(domain)})


@osint_bp.route("/api/osint/geoip", methods=["POST"])
@module_required("osint")
def geoip_route():
    body = request.get_json(silent=True) or {}
    ips  = body.get("ips", [])
    ip   = body.get("ip", "")
    if ip:
        return jsonify({"ip": ip, "geo": geolocate_ip(ip)})
    if ips:
        return jsonify({"geo": geolocate_bulk(ips)})
    return jsonify({"error": "ip or ips required"}), 400


@osint_bp.route("/api/osint/emails", methods=["POST"])
@module_required("osint")
def emails_route():
    body      = request.get_json(silent=True) or {}
    domain    = (body.get("domain") or "").strip()
    hunter_key = body.get("hunter_key", "")
    if not domain:
        return jsonify({"error": "domain required"}), 400
    if hunter_key:
        emails = harvest_emails_hunter(domain, hunter_key)
    else:
        emails = harvest_emails_free(domain)
    return jsonify({"domain": domain, "emails": emails, "count": len(emails)})


@osint_bp.route("/api/osint/github", methods=["POST"])
def github_route():
    body  = request.get_json(silent=True) or {}
    domain = (body.get("domain") or "").strip()
    token  = body.get("github_token", "")
    if not domain:
        return jsonify({"error": "domain required"}), 400
    findings = github_dork(domain, token)
    return jsonify({"domain": domain, "findings": findings, "count": len(findings)})


@osint_bp.route("/api/osint/cve", methods=["POST"])
def cve_route():
    body      = request.get_json(silent=True) or {}
    tech_list = body.get("tech", [])
    if not tech_list:
        return jsonify({"error": "tech list required"}), 400
    results = lookup_cves(tech_list)
    return jsonify({"cves": results})


@osint_bp.route("/api/osint/ssl", methods=["POST"])
def ssl_route():
    body     = request.get_json(silent=True) or {}
    hostname = (body.get("hostname") or body.get("domain") or "").strip()
    port     = int(body.get("port", 443))
    if not hostname:
        return jsonify({"error": "hostname required"}), 400
    result = inspect_ssl(hostname, port)
    return jsonify(result)


@osint_bp.route("/api/osint/full", methods=["POST"])
def full_osint():
    """Run all OSINT checks on a domain in parallel."""
    body      = request.get_json(silent=True) or {}
    domain    = (body.get("domain") or "").strip()
    hunter_key = body.get("hunter_key", "")
    github_token = body.get("github_token", "")
    if not domain:
        return jsonify({"error": "domain required"}), 400

    results = {}
    errors  = {}

    def run(key, fn, *args):
        try:
            results[key] = fn(*args)
        except Exception as e:
            errors[key] = str(e)

    threads = [
        threading.Thread(target=run, args=("whois",  whois_lookup, domain)),
        threading.Thread(target=run, args=("ssl",    inspect_ssl, domain)),
        threading.Thread(target=run, args=("emails", harvest_emails_hunter if hunter_key else harvest_emails_free,
                                            domain, hunter_key) if hunter_key else ("emails", harvest_emails_free, domain)),
        threading.Thread(target=run, args=("github", github_dork, domain, github_token)),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    return jsonify({"domain": domain, "results": results, "errors": errors})
