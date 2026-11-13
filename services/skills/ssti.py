"""SkillSsti — Server-Side Template Injection probe.

Substitutes the param value with each engine's evaluation marker payload
(`{{49*49}}`, `${49*49}`, `<%= 49*49 %>`, …) and looks for the expected
result string (`2401`) reflected in the response. Confirmed SSTI is
critical — almost every template engine is one step from RCE.

Severity:
  - critical : evaluation marker reflected (engine evaluated the expression)
  - info     : no engine evaluated the payload
"""
from __future__ import annotations
from typing import Optional
from urllib.parse import urlparse, urlencode, urlunparse, parse_qsl

import requests

from services.skills.base import Skill, SkillResult, register
from services.skills._payloads import SSTI_PAYLOADS


_HEADERS = {"User-Agent": "Mozilla/5.0 ZeekGlare-Arena-SSTI"}


def _swap(url: str, param: str, value: str) -> str:
    p = urlparse(url)
    qs = parse_qsl(p.query, keep_blank_values=True)
    new_qs = [(k, value if k == param else v) for k, v in qs]
    if not any(k == param for k, _ in qs):
        new_qs.append((param, value))
    return urlunparse((p.scheme, p.netloc, p.path, p.params, urlencode(new_qs), p.fragment))


@register
class SkillSsti(Skill):
    name        = "skill_ssti"
    danger      = "active"
    description = (
        "Probe a URL+param for Server-Side Template Injection. Substitutes the "
        "param value with engine-specific evaluation payloads (Jinja2/Twig "
        "{{49*49}}, Freemarker ${49*49}, ERB <%= 49*49 %>, Velocity, Smarty, "
        "Mako, Tornado, Dust) and checks if the expected result (2401, 7777777, "
        "etc.) reflects in the response — proof the template engine evaluated "
        "the expression. Critical when confirmed (SSTI almost always escalates "
        "to RCE)."
    )
    guidance    = (
        "SSTI hunting: any param echoed in a server-rendered page is suspect. "
        "Try {{49*49}} first — Jinja2/Twig are the most common engines. If it "
        "echoes back literally, no template; if you see 2401, you have RCE-class "
        "impact. Don't over-test once one engine fires."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "url":   {"type": "string", "description": "URL to probe."},
            "param": {"type": "string", "description": "Param name."},
        },
        "required": ["url", "param"],
    }

    @classmethod
    def applicable(cls, state) -> bool:
        c = state.asset_counts()
        return c.get("url", 0) > 0 or c.get("param", 0) > 0

    @classmethod
    def dedup_key(cls, args) -> Optional[tuple[str, str, str, str]]:
        return (args.get("url", ""), args.get("param", ""), "ssti", "eval_marker")

    @classmethod
    def run(cls, args, state, agent_id) -> SkillResult:
        url   = (args.get("url") or "").strip()
        param = (args.get("param") or "").strip()
        if not url or not param:
            return SkillResult(ok=False, error="url and param required")
        if not state.in_scope(url):
            return SkillResult(ok=False, error=f"out of scope: {url}")

        hits = []
        all_probes = []
        for engine, payload, expected in SSTI_PAYLOADS:
            probe = _swap(url, param, payload)
            try:
                r = requests.get(probe, headers=_HEADERS, timeout=10,
                                 allow_redirects=False, verify=False)
                body = r.text or ""
            except Exception as e:
                all_probes.append({"engine": engine, "payload": payload, "error": str(e)})
                continue

            rec = {"engine": engine, "payload": payload, "status": r.status_code,
                   "expected": expected}
            all_probes.append(rec)

            # Hit if the expected marker appears in the response AND it's not
            # already present in the original page (we approximate by checking
            # that the payload itself isn't echoed verbatim — that would be
            # reflection without evaluation).
            if expected and expected in body and payload not in body:
                rec["evaluated"] = True
                hits.append(rec)

        if hits:
            ev_lines = [f"URL: {url}  Param: {param}"]
            for h in hits[:5]:
                ev_lines.append(
                    f"[{h['engine']}] payload={h['payload']!r} → expected '{h['expected']}' found in response (HTTP {h['status']})"
                )
            evidence = "\n".join(ev_lines)
            engines = sorted({h["engine"] for h in hits})
            return SkillResult(
                ok=True,
                summary=f"SSTI confirmed: {len(hits)} payload(s) evaluated by {', '.join(engines)}.",
                evidence=evidence,
                finding={
                    "vuln_type":   "ssti",
                    "severity":    "critical",
                    "target":      url,
                    "location":    f"{url} param={param}",
                    "description": (
                        f"Server-Side Template Injection — param '{param}' is rendered through "
                        f"a template engine ({', '.join(engines)}) without sandboxing. "
                        "Arithmetic expressions evaluate, indicating arbitrary template-context "
                        "execution; most engines escalate to OS-level RCE."
                    ),
                    "evidence":    evidence,
                },
                extras={"hits": hits, "engines": engines},
            )

        return SkillResult(
            ok=True,
            summary=f"No SSTI detected ({len(all_probes)} engine probes tried).",
            extras={"probes": all_probes[:6]},
        )
