"""SkillCors — probe a URL for misconfigured CORS reflection.

Sends GET requests with an Origin header set to known-bad values and
inspects the response for permissive CORS headers. Confirmed
misconfigurations:

  - critical : Access-Control-Allow-Origin reflects an arbitrary origin AND
               Access-Control-Allow-Credentials: true (cred-leak ready)
  - high     : ACAO reflects arbitrary origin (read-only attacker JS exposure)
  - medium   : null origin or subdomain-confusion accepted
  - info     : ACAO is `*` (open API by design — note but don't flag)
"""
from __future__ import annotations
from typing import Optional
from urllib.parse import urlparse

import requests

from services.skills.base import Skill, SkillResult, register
from services.skills._payloads import CORS_TEST_ORIGINS


_HEADERS = {"User-Agent": "Mozilla/5.0 ZeekGlare-Arena-CORS"}


@register
class SkillCors(Skill):
    name        = "skill_cors"
    danger      = "active"
    description = (
        "Probe a URL for misconfigured CORS by issuing requests with various "
        "Origin headers (arbitrary attacker origin, null, subdomain confusion, "
        "protocol downgrade) and inspecting Access-Control-Allow-Origin / "
        "Access-Control-Allow-Credentials in the response. Most impactful when "
        "ACAO reflects the attacker's origin AND ACAC=true — that's a credentialed "
        "cross-origin read primitive."
    )
    guidance    = (
        "CORS impact ladder: ACAO=* alone is rarely interesting. ACAO reflection + "
        "ACAC:true is the bug. Subdomain confusion (target.com.evil.example) catches "
        "regex-based whitelists. null origin acceptance lets sandboxed iframes / data "
        "URLs steal data."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "URL to probe. Must be in scope."},
        },
        "required": ["url"],
    }

    @classmethod
    def applicable(cls, state) -> bool:
        return state.asset_counts().get("url", 0) > 0

    @classmethod
    def dedup_key(cls, args) -> Optional[tuple[str, str, str, str]]:
        return (args.get("url", ""), "", "cors", "origin_reflection")

    @classmethod
    def run(cls, args, state, agent_id) -> SkillResult:
        url = (args.get("url") or "").strip()
        if not url:
            return SkillResult(ok=False, error="url required")
        if not state.in_scope(url):
            return SkillResult(ok=False, error=f"out of scope: {url}")

        target_host = (urlparse(url).hostname or "").lower()
        # Build origin variants — substitute target into the subdomain-confusion ones
        origins = []
        for o in CORS_TEST_ORIGINS:
            origins.append(o.replace("target.com", target_host) if "target.com" in o else o)

        results = []
        worst_severity = None
        worst_finding  = None

        for origin in origins:
            try:
                r = requests.get(url,
                                 headers={**_HEADERS, "Origin": origin},
                                 timeout=8, allow_redirects=False, verify=False)
            except Exception as e:
                results.append({"origin": origin, "error": f"{type(e).__name__}: {e}"})
                continue
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "")
            rec = {"origin": origin, "status": r.status_code, "acao": acao, "acac": acac}
            results.append(rec)

            if acao and acao == origin:
                # Reflection confirmed.
                if acac.lower() == "true":
                    sev = "critical"
                else:
                    sev = "high"
                if "subdomain" in origin or "target" in origin:
                    sev = sev if sev != "critical" else "critical"  # keep crit
                if not worst_severity or _sev_rank(sev) > _sev_rank(worst_severity):
                    worst_severity = sev
                    worst_finding  = rec

        if worst_finding:
            ev_lines = [f"URL: {url}"]
            for r in results:
                if "error" in r:
                    continue
                ev_lines.append(f"Origin {r['origin']!r} → ACAO={r['acao']!r}  ACAC={r['acac']!r}")
            evidence = "\n".join(ev_lines)
            cred_note = " WITH credentials allowed" if (worst_finding.get("acac") or "").lower() == "true" else ""
            return SkillResult(
                ok=True,
                summary=f"CORS misconfiguration ({worst_severity}): origin reflection{cred_note}.",
                evidence=evidence,
                finding={
                    "vuln_type":   "cors_misconfiguration",
                    "severity":    worst_severity,
                    "target":      url,
                    "location":    url,
                    "description": (
                        f"CORS reflects arbitrary Origin header value into Access-Control-Allow-Origin"
                        + (" and sets Access-Control-Allow-Credentials: true — credentialed cross-origin "
                           "reads are possible from any attacker page the victim visits."
                           if (worst_finding.get('acac') or '').lower() == 'true'
                           else ".")
                    ),
                    "evidence":    evidence,
                },
                extras={"results": results, "worst": worst_finding},
            )

        return SkillResult(
            ok=True,
            summary=f"No CORS misconfiguration found ({len(results)} origins tried).",
            extras={"results": results},
        )


def _sev_rank(s: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(s, 0)
