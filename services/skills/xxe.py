"""SkillXxe — XML eXternal Entity injection probe (inline file-read variant).

Many endpoints accept XML bodies. We POST each payload from
`_payloads.XXE_BODIES` and look for /etc/passwd-style markers in the
response. OOB callbacks are not used here — those need a callback-server
infrastructure outside the arena's scope.

Severity:
  - critical : file content marker reflected (confirmed file disclosure)
  - info     : no markers — XML parsed without entity resolution OR not parsed at all
"""
from __future__ import annotations
from typing import Optional

import requests

from services.skills.base import Skill, SkillResult, register
from services.skills._payloads import XXE_BODIES, XXE_RESPONSE_MARKERS


_HEADERS_XML = {
    "User-Agent":   "Mozilla/5.0 ZeekGlare-Arena-XXE",
    "Content-Type": "application/xml",
    "Accept":       "*/*",
}


@register
class SkillXxe(Skill):
    name        = "skill_xxe"
    danger      = "active"
    description = (
        "Probe an XML-accepting endpoint for XML eXternal Entity injection. POSTs "
        "payloads with external entity references to local files (/etc/passwd, "
        "/etc/hostname) and parameter-entity variants, checks the response for "
        "leaked file content markers. Inline (in-band) only — no OOB callbacks. "
        "Use on endpoints that handle XML (SOAP, REST APIs accepting XML, file "
        "upload endpoints, anywhere Content-Type: application/xml goes)."
    )
    guidance    = (
        "XXE only fires on endpoints that actually parse XML. JSON-only APIs "
        "are immune. If the endpoint normally takes JSON, try forcing XML "
        "via Content-Type override — some servers accept both. Don't fire "
        "OOB-only payloads here; we have no callback infra."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "url":    {"type": "string", "description": "Endpoint URL that accepts an XML body."},
            "method": {"type": "string", "enum": ["POST", "PUT"], "default": "POST"},
            "extra_headers": {"type": "object", "description": "Optional extra headers."},
        },
        "required": ["url"],
    }

    @classmethod
    def applicable(cls, state) -> bool:
        return state.asset_counts().get("url", 0) > 0

    @classmethod
    def dedup_key(cls, args) -> Optional[tuple[str, str, str, str]]:
        return (args.get("url", ""), "", "xxe", "inline_file_read")

    @classmethod
    def run(cls, args, state, agent_id) -> SkillResult:
        url    = (args.get("url") or "").strip()
        method = (args.get("method") or "POST").upper()
        extra  = args.get("extra_headers") or {}
        if not url:
            return SkillResult(ok=False, error="url required")
        if not state.in_scope(url):
            return SkillResult(ok=False, error=f"out of scope: {url}")

        headers = {**_HEADERS_XML, **extra}
        all_probes = []
        hits = []
        for body in XXE_BODIES:
            try:
                r = requests.request(method, url, data=body.encode("utf-8"),
                                     headers=headers, timeout=12,
                                     allow_redirects=False, verify=False)
                resp_body = r.text or ""
            except Exception as e:
                all_probes.append({"payload_short": body[:60], "error": str(e)})
                continue
            matched = [m for m in XXE_RESPONSE_MARKERS if m in resp_body]
            rec = {"payload_short": body[:80], "status": r.status_code,
                   "length": len(resp_body), "matched_markers": matched,
                   "preview": resp_body[:300]}
            all_probes.append(rec)
            if matched:
                hits.append(rec)

        if hits:
            ev_lines = [f"URL: {url}  Method: {method}"]
            for h in hits[:3]:
                ev_lines.append(
                    f"Payload: {h['payload_short']!r} → HTTP {h['status']} "
                    f"matched markers: {h['matched_markers']}"
                )
                ev_lines.append(f"  preview: {h['preview'][:200]!r}")
            evidence = "\n".join(ev_lines)
            return SkillResult(
                ok=True,
                summary=f"XXE confirmed: {len(hits)} payload(s) leaked file content markers.",
                evidence=evidence,
                finding={
                    "vuln_type":   "xxe",
                    "severity":    "critical",
                    "target":      url,
                    "location":    url,
                    "description": (
                        "XML External Entity injection — the XML parser resolves SYSTEM entities "
                        "and reads local files. Direct file-disclosure impact (config files, SSH "
                        "keys, /etc/passwd) and chains to SSRF (entity URI can point at internal "
                        "addresses)."
                    ),
                    "evidence":    evidence,
                },
                extras={"hits": hits, "probes_attempted": len(all_probes)},
            )

        return SkillResult(
            ok=True,
            summary=f"No XXE detected ({len(all_probes)} payloads tried; no file markers in any response).",
            extras={"probes": all_probes[:3]},
        )
