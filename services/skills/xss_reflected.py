"""SkillXssReflected — reflected XSS detection with context-aware payloads.

Issues a baseline GET to capture the response shape, then for each payload
context (HTML, attribute, JS-string, URL) substitutes the param value and
checks whether the marker string echoed BACK and whether the surrounding
bytes form an executable context (i.e. not HTML-encoded by the server).

This is detection, not exploitation — the marker is `XSS_MARKER` (a benign
identifier). A confirmed reflection where the marker appears unescaped in
an executable context is graded `high`.
"""
from __future__ import annotations
import re
from typing import Optional
from urllib.parse import urlparse, urlencode, urlunparse, parse_qsl

import requests

from services.skills.base import Skill, SkillResult, register
from services.skills._payloads import XSS_MARKER, XSS_REFLECTED_VECTORS


_HEADERS = {"User-Agent": "Mozilla/5.0 ZeekGlare-Arena-XSS"}


def _swap(url: str, param: str, value: str) -> str:
    p = urlparse(url)
    qs = parse_qsl(p.query, keep_blank_values=True)
    seen = False
    new_qs = []
    for k, v in qs:
        if k == param:
            new_qs.append((k, value)); seen = True
        else:
            new_qs.append((k, v))
    if not seen:
        new_qs.append((param, value))
    return urlunparse((p.scheme, p.netloc, p.path, p.params, urlencode(new_qs), p.fragment))


def _classify(payload: str, body: str) -> str:
    """Return 'executable' | 'encoded' | 'absent' for this payload's reflection."""
    if payload not in body:
        # Encoded forms still count as reflection (echoed but neutered)
        encoded_variants = [
            payload.replace("<", "&lt;").replace(">", "&gt;"),
            payload.replace("<", "&#60;").replace(">", "&#62;"),
            payload.replace("<", "%3C").replace(">", "%3E"),
        ]
        for ev in encoded_variants:
            if ev != payload and ev in body:
                return "encoded"
        return "absent"
    return "executable"


@register
class SkillXssReflected(Skill):
    name        = "skill_xss_reflected"
    danger      = "active"
    description = (
        "Probe a URL+param for reflected XSS. Tries context-aware payloads "
        "(HTML body, HTML attribute, JS string, URL contexts) using a benign "
        "marker string. Detects (a) the marker reflecting unescaped (executable) "
        "vs (b) the marker being HTML/URL-encoded (encoded — defended) vs (c) "
        "no reflection at all. Flags only executable reflections as findings; "
        "encoded reflections are reported as info."
    )
    guidance    = (
        "Reflected XSS hunting: try the simplest payload first (just the marker, "
        "no metacharacters) — if the bare string isn't reflected, the param is "
        "probably not in the response. If it IS reflected, escalate to context "
        "payloads. A reflection that's HTML-encoded is NOT a finding — encoding "
        "is the defense working. Look for `<script>marker</script>` echoed "
        "verbatim — that's the win."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "url":   {"type": "string", "description": "URL to probe. Must be in scope."},
            "param": {"type": "string", "description": "Query param name to inject into."},
            "contexts": {
                "type": "array",
                "items": {"type": "string", "enum": ["raw", "html_context", "attr_context", "js_string", "url_context"]},
                "default": ["raw", "html_context", "attr_context"],
                "description": "Which payload contexts to try (default: raw + html + attr).",
            },
        },
        "required": ["url", "param"],
    }

    @classmethod
    def applicable(cls, state) -> bool:
        c = state.asset_counts()
        return c.get("url", 0) > 0 or c.get("param", 0) > 0

    @classmethod
    def dedup_key(cls, args) -> Optional[tuple[str, str, str, str]]:
        return (args.get("url", ""), args.get("param", ""), "xss", "reflected")

    @classmethod
    def run(cls, args, state, agent_id) -> SkillResult:
        url   = (args.get("url") or "").strip()
        param = (args.get("param") or "").strip()
        if not url or not param:
            return SkillResult(ok=False, error="url and param required")
        if not state.in_scope(url):
            return SkillResult(ok=False, error=f"out of scope: {url}")

        contexts = args.get("contexts") or ["raw", "html_context", "attr_context"]
        executable_hits = []
        encoded_hits    = []
        all_probes      = []

        for ctx in contexts:
            for payload in XSS_REFLECTED_VECTORS.get(ctx, []):
                probe_url = _swap(url, param, payload)
                try:
                    r = requests.get(probe_url, headers=_HEADERS, timeout=10,
                                     allow_redirects=False, verify=False)
                    body = r.text or ""
                except Exception as e:
                    all_probes.append({"context": ctx, "payload": payload,
                                       "error": f"{type(e).__name__}: {e}"})
                    continue

                # The marker must reflect; the full payload's reflection
                # determines context.
                marker_present = XSS_MARKER in body
                klass = _classify(payload, body) if marker_present else "absent"

                rec = {
                    "context": ctx, "payload": payload,
                    "status": r.status_code, "length": len(body),
                    "reflection": klass,
                }
                all_probes.append(rec)
                if klass == "executable":
                    executable_hits.append(rec)
                elif klass == "encoded":
                    encoded_hits.append(rec)

        if executable_hits:
            ev_lines = [f"Param: {param}", f"URL: {url}"]
            for h in executable_hits[:6]:
                ev_lines.append(
                    f"[{h['context']}] payload={h['payload']!r} → reflected unescaped "
                    f"(HTTP {h['status']} {h['length']}B)"
                )
            evidence = "\n".join(ev_lines)
            return SkillResult(
                ok=True,
                summary=f"Reflected XSS confirmed: {len(executable_hits)} executable reflection(s).",
                evidence=evidence,
                finding={
                    "vuln_type":   "xss_reflected",
                    "severity":    "high",
                    "target":      url,
                    "location":    f"{url} param={param}",
                    "description": (
                        f"Reflected XSS — param '{param}' reflects user input back to the response "
                        f"unescaped in {len(executable_hits)} context(s). Marker payload(s) "
                        "appear verbatim in HTML response, indicating an exploitable injection point."
                    ),
                    "evidence":    evidence,
                },
                extras={"executable_hits": executable_hits, "encoded_hits": encoded_hits},
            )

        if encoded_hits:
            return SkillResult(
                ok=True,
                summary=f"Reflection detected but properly encoded ({len(encoded_hits)} hits) — defense holding.",
                extras={"encoded_hits": encoded_hits, "probes": all_probes[-10:]},
            )

        return SkillResult(
            ok=True,
            summary=f"No reflection detected on {param}= across {len(all_probes)} probe(s).",
            extras={"probes_attempted": len(all_probes)},
        )
