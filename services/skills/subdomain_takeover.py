"""SkillSubdomainTakeover — wraps services.takeover.check_subdomain_takeover.

For every subdomain in the shared asset graph (capped to a sane batch),
runs the existing takeover detection logic + applies extra modern CNAME
fingerprints. Confirmed takeovers are direct critical-impact findings —
the attacker can claim the dangling third-party resource and serve content
under the target's domain.
"""
from __future__ import annotations
from typing import Optional

import requests

from services.skills.base import Skill, SkillResult, register
from services.skills._payloads import TAKEOVER_EXTRA_FINGERPRINTS

# Reuse existing service rather than reimplement.
from services.takeover import check_subdomain_takeover


_HEADERS = {"User-Agent": "Mozilla/5.0 ZeekGlare-Arena-Takeover"}


def _check_extra(fqdn: str, cname_target: str) -> Optional[dict]:
    """Apply modern fingerprints not yet in services/takeover.py."""
    for cname_substr, marker, service in TAKEOVER_EXTRA_FINGERPRINTS:
        if cname_substr not in cname_target.lower():
            continue
        try:
            r = requests.get(f"http://{fqdn}", headers=_HEADERS, timeout=8,
                             allow_redirects=False, verify=False)
            body = r.text or ""
        except Exception:
            return None
        if marker.lower() in body.lower():
            return {
                "subdomain": fqdn,
                "cname":     cname_target,
                "service":   service,
                "marker":    marker[:80],
                "status":    r.status_code,
                "fingerprint_matched": True,
            }
    return None


@register
class SkillSubdomainTakeover(Skill):
    name        = "skill_subdomain_takeover"
    danger      = "active"
    description = (
        "Check every known subdomain for dangling-CNAME takeover. Resolves CNAME, "
        "checks if the target resource exists, fetches the HTTP response and "
        "matches against ~30 known service fingerprints (GitHub Pages, Heroku, "
        "AWS S3, Azure, CloudFront, Shopify, Vercel, Netlify, Ghost, Fastly, …). "
        "Confirmed takeover is direct critical impact — the attacker can claim "
        "the dangling resource. Reads only — does NOT register the resource."
    )
    guidance    = (
        "Takeover is the rare bug class where detection IS the impact (a confirmed "
        "fingerprint match means the resource is claimable). Always include the "
        "exact CNAME and the service marker text in evidence so triage can "
        "verify quickly. Never actually register the dangling resource — that's "
        "out of scope for security testing without explicit authorization."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "max_subdomains": {"type": "integer", "default": 200,
                                "description": "Cap on subdomains to check this run."},
        },
        "required": [],
    }

    @classmethod
    def applicable(cls, state) -> bool:
        return state.asset_counts().get("subdomain", 0) > 0

    @classmethod
    def dedup_key(cls, args) -> Optional[tuple[str, str, str, str]]:
        # One attempt per arena race is enough — subdomain set rarely changes
        # mid-race, and the underlying check is expensive.
        return ("__all_subdomains__", "", "subdomain_takeover", "fingerprint_scan")

    @classmethod
    def run(cls, args, state, agent_id) -> SkillResult:
        cap = max(10, min(int(args.get("max_subdomains") or 200), 500))
        subs = state.get_assets("subdomain")[:cap]
        if not subs:
            return SkillResult(ok=False, error="no subdomains in shared state yet")

        # Filter to in-scope.
        subs = [s for s in subs if state.in_scope(s)]
        if not subs:
            return SkillResult(ok=False, error="no in-scope subdomains")

        primary_findings = check_subdomain_takeover(subs) or []

        # Apply extra fingerprints — re-resolve CNAMEs for hosts that didn't
        # match the built-in set.
        extra_findings = []
        primary_set = {f.get("subdomain") for f in primary_findings if isinstance(f, dict)}
        try:
            import dns.resolver
            for fqdn in subs:
                if fqdn in primary_set:
                    continue
                try:
                    ans = dns.resolver.resolve(fqdn, "CNAME", lifetime=4)
                    cname = str(ans[0].target).rstrip(".")
                except Exception:
                    continue
                hit = _check_extra(fqdn, cname)
                if hit:
                    extra_findings.append(hit)
        except ImportError:
            pass

        all_findings = primary_findings + extra_findings
        confirmed = [f for f in all_findings if f.get("fingerprint_matched")]

        if not all_findings:
            return SkillResult(
                ok=True,
                summary=f"No takeover indicators across {len(subs)} subdomain(s).",
                extras={"checked": len(subs)},
            )

        if confirmed:
            ev_lines = [f"Checked {len(subs)} subdomains; {len(confirmed)} confirmed takeover(s):"]
            for f in confirmed[:10]:
                ev_lines.append(
                    f"  {f.get('subdomain')} → CNAME {f.get('cname')} "
                    f"({f.get('service','?')}) HTTP {f.get('status','?')}"
                )
            evidence = "\n".join(ev_lines)
            return SkillResult(
                ok=True,
                summary=f"⚠ {len(confirmed)} subdomain takeover(s) confirmed.",
                evidence=evidence,
                finding={
                    "vuln_type":   "subdomain_takeover",
                    "severity":    "critical",
                    "target":      ",".join(f["subdomain"] for f in confirmed[:5]),
                    "location":    confirmed[0]["subdomain"],
                    "description": (
                        f"{len(confirmed)} subdomain(s) have dangling CNAMEs pointing to "
                        "unclaimed third-party resources. An attacker can register the "
                        "resource and serve arbitrary content under the target's domain — "
                        "phishing, cookie theft, brand abuse."
                    ),
                    "evidence":    evidence,
                },
                extras={"confirmed": confirmed, "all_findings": all_findings,
                        "checked": len(subs)},
            )

        # Indicators but no confirmed match
        ev_lines = [f"Checked {len(subs)} subdomains; {len(all_findings)} indicator(s):"]
        for f in all_findings[:10]:
            ev_lines.append(
                f"  {f.get('subdomain')} → CNAME {f.get('cname')} "
                f"({f.get('status','?')})"
            )
        return SkillResult(
            ok=True,
            summary=f"{len(all_findings)} takeover indicator(s); none fingerprint-matched yet.",
            evidence="\n".join(ev_lines),
            finding={
                "vuln_type":   "subdomain_takeover_candidate",
                "severity":    "low",
                "target":      all_findings[0]["subdomain"],
                "location":    all_findings[0]["subdomain"],
                "description": (
                    f"{len(all_findings)} subdomain(s) point to unresolved or known-takeover-prone "
                    "providers but didn't match a service fingerprint. Worth manual review — "
                    "the fingerprint may have changed or the marker text may be slightly off."
                ),
                "evidence":    "\n".join(ev_lines),
            },
            extras={"all_findings": all_findings, "checked": len(subs)},
        )
