"""SkillOpenRedirect — probe redirect-style params for cross-origin redirect.

For each bypass payload, substitutes the param value with a payload pointing
at an attacker-controlled origin and follows ONE redirect to inspect the
Location header. A 30x where Location resolves to a non-target origin is a
confirmed open redirect.

Severity:
  - high   : 30x with Location pointing to attacker-controlled origin
  - medium : 30x to a target-relative URL (path injection only — partial)
  - info   : no redirect or in-origin redirect
"""
from __future__ import annotations
from typing import Optional
from urllib.parse import urlparse, urlencode, urlunparse, parse_qsl

import requests

from services.skills.base import Skill, SkillResult, register
from services.skills._payloads import OPEN_REDIRECT_PAYLOADS


_HEADERS = {"User-Agent": "Mozilla/5.0 ZeekGlare-Arena-OpenRedirect"}
_EVIL_HOST = "evil-zeekglare-arena.example"


def _swap(url: str, param: str, value: str) -> str:
    p = urlparse(url)
    qs = parse_qsl(p.query, keep_blank_values=True)
    new_qs = [(k, value if k == param else v) for k, v in qs]
    if not any(k == param for k, _ in qs):
        new_qs.append((param, value))
    return urlunparse((p.scheme, p.netloc, p.path, p.params, urlencode(new_qs), p.fragment))


def _resolve_redirect(target_host: str, location: str) -> str:
    """Return 'attacker' | 'target' | 'unknown' based on Location host."""
    if not location:
        return "unknown"
    loc = location.strip()
    # Protocol-relative
    if loc.startswith("//"):
        loc_host = loc[2:].split("/", 1)[0].split("?")[0].split("#")[0]
    elif "://" in loc:
        loc_host = urlparse(loc).hostname or ""
    else:
        # Relative URL — same origin
        return "target"
    loc_host = loc_host.lower()
    if _EVIL_HOST in loc_host:
        return "attacker"
    if target_host and (loc_host == target_host or loc_host.endswith("." + target_host)):
        return "target"
    return "attacker"   # any other host = cross-origin


@register
class SkillOpenRedirect(Skill):
    name        = "skill_open_redirect"
    danger      = "active"
    description = (
        "Probe a URL+param for open-redirect by substituting the param with a "
        "library of bypass payloads (//, @, fragment, encoding tricks). Follows "
        "exactly one hop and inspects the Location header. Confirmed when the "
        "response is a 30x AND Location resolves to an attacker-controlled host. "
        "Use on any param that smells like a redirect (next, return, redirect, "
        "url, dest, target, continue, returnTo)."
    )
    guidance    = (
        "Open redirects pay because they chain — phishing trust transfer, "
        "OAuth state-param theft, SSRF when fetched server-side. The evil host "
        "we use is " + _EVIL_HOST + " (won't resolve, but the Location header "
        "is what counts). Watch for tricks like https://target.com@evil.example "
        "and protocol-relative //evil.example."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "url":   {"type": "string", "description": "URL with the redirect param. Must be in scope."},
            "param": {"type": "string", "description": "Param name (next/return/url/redirect/etc.)."},
        },
        "required": ["url", "param"],
    }

    @classmethod
    def applicable(cls, state) -> bool:
        c = state.asset_counts()
        return c.get("url", 0) > 0 or c.get("param", 0) > 0

    @classmethod
    def dedup_key(cls, args) -> Optional[tuple[str, str, str, str]]:
        return (args.get("url", ""), args.get("param", ""), "open_redirect", "library")

    @classmethod
    def run(cls, args, state, agent_id) -> SkillResult:
        url   = (args.get("url") or "").strip()
        param = (args.get("param") or "").strip()
        if not url or not param:
            return SkillResult(ok=False, error="url and param required")
        if not state.in_scope(url):
            return SkillResult(ok=False, error=f"out of scope: {url}")

        target_host = (urlparse(url).hostname or "").lower()
        attacker_hits = []
        target_hits   = []
        all_probes    = []

        for tmpl in OPEN_REDIRECT_PAYLOADS:
            payload = tmpl.replace("{evil}", _EVIL_HOST)
            probe = _swap(url, param, payload)
            try:
                r = requests.get(probe, headers=_HEADERS, timeout=8,
                                 allow_redirects=False, verify=False)
            except Exception as e:
                all_probes.append({"payload": payload, "error": f"{type(e).__name__}: {e}"})
                continue
            location = r.headers.get("Location", "")
            rec = {"payload": payload, "status": r.status_code, "location": location}
            all_probes.append(rec)
            if 300 <= r.status_code < 400 and location:
                where = _resolve_redirect(target_host, location)
                rec["resolves_to"] = where
                if where == "attacker":
                    attacker_hits.append(rec)
                elif where == "target":
                    target_hits.append(rec)

        if attacker_hits:
            ev_lines = [f"Param: {param}  Target host: {target_host}"]
            for h in attacker_hits[:5]:
                ev_lines.append(
                    f"PAYLOAD {h['payload']!r} → HTTP {h['status']} → Location: {h['location']!r}"
                )
            evidence = "\n".join(ev_lines)
            return SkillResult(
                ok=True,
                summary=f"Open redirect confirmed: {len(attacker_hits)} bypass payload(s) redirect cross-origin.",
                evidence=evidence,
                finding={
                    "vuln_type":   "open_redirect",
                    "severity":    "high",
                    "target":      url,
                    "location":    f"{url} param={param}",
                    "description": (
                        f"Open redirect — param '{param}' accepts attacker-controlled URLs "
                        f"and the server issues a 30x with Location pointing to the attacker host. "
                        f"{len(attacker_hits)} bypass payload(s) succeeded. Chains to phishing, "
                        "OAuth state theft, SSRF when fetched server-side."
                    ),
                    "evidence":    evidence,
                },
                extras={"attacker_hits": attacker_hits, "target_hits": target_hits},
            )

        return SkillResult(
            ok=True,
            summary=f"No open redirect detected ({len(all_probes)} payloads tried).",
            extras={"probes": all_probes[-10:]},
        )
