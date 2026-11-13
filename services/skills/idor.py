"""SkillIdor — probe for Insecure Direct Object Reference on ID-like params.

How it works:

  1. Baseline: GET the URL with the agent-provided current value.
  2. For each test_value, issue the same request with the param swapped.
  3. Compare status / content-length / body hash to the baseline.
  4. Flag hits where a test_value returns a 2xx + substantively different
     response (suggesting access to another user's object) without auth
     changing between the two calls.

Only applicable once SharedState has seen any URL and any param — the
agent picks which one to probe. Does not mutate the target (GET-only).
"""
from __future__ import annotations
import hashlib
from typing import Optional

import requests

from services.skills.base import Skill, SkillResult, register


_HEADERS = {"User-Agent": "Mozilla/5.0 ZeekGlare-Arena-IDOR"}


def _hash(s: str) -> str:
    return hashlib.sha1((s or "").encode("utf-8", "replace")).hexdigest()[:12]


@register
class SkillIdor(Skill):
    name        = "skill_idor"
    danger      = "active"
    description = (
        "Probe a URL+param for IDOR (Insecure Direct Object Reference). Issues "
        "GET requests swapping the current param value for each test_value, "
        "compares status + body hash + length vs baseline. Flags cases where a "
        "different ID returns 2xx with substantively different content, "
        "suggesting horizontal access. Use when you've found a numeric / UUID-ish "
        "ID in a URL or query param (e.g. /users/42, ?order_id=1001). GET-only, "
        "non-destructive."
    )
    guidance    = (
        "IDOR is the highest-paying bug class in most programs. Always test "
        "adjacent IDs (n-1, n+1), '0', '1', and admin-ish IDs. Also try GraphQL "
        "node queries (base64(User:N)) and WebSocket actions if the app uses them. "
        "Hunt parameter-addition variants — sometimes adding ?user_id=X to an "
        "endpoint that didn't expose it makes the backend honor the override."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "url":           {"type": "string", "description": "URL with the param to swap. Must be in scope."},
            "param":         {"type": "string", "description": "Query-param name to swap. Use 'path' for path IDs."},
            "current_value": {"type": "string", "description": "Current value of the param (baseline)."},
            "test_values":   {
                "type": "array", "items": {"type": "string"},
                "description": "Values to try (max 6). Try adjacent IDs (e.g. '41','43' for baseline 42), '0', '1', and common admin-ish IDs.",
            },
            "cookies":       {"type": "object", "description": "Optional auth cookies (constant across all probes)."},
            "auth_header":   {"type": "string", "description": "Optional Authorization header (constant across all probes)."},
        },
        "required": ["url", "param", "current_value", "test_values"],
    }

    @classmethod
    def applicable(cls, state) -> bool:
        counts = state.asset_counts()
        return (counts.get("url", 0) > 0) or (counts.get("param", 0) > 0)

    @classmethod
    def dedup_key(cls, args) -> Optional[tuple[str, str, str, str]]:
        url = args.get("url", ""); param = args.get("param", "")
        return (url, param, "idor", "value_swap")

    @classmethod
    def run(cls, args, state, agent_id) -> SkillResult:
        url           = (args.get("url") or "").strip()
        param         = (args.get("param") or "").strip()
        current_value = str(args.get("current_value", ""))
        test_values   = [str(v) for v in (args.get("test_values") or [])][:6]
        cookies       = args.get("cookies") or None
        auth_header   = (args.get("auth_header") or "").strip()

        if not url or not param:
            return SkillResult(ok=False, error="url and param required")
        if not state.in_scope(url):
            return SkillResult(ok=False, error=f"out of scope: {url}")
        if not test_values:
            return SkillResult(ok=False, error="test_values required")

        headers = dict(_HEADERS)
        if auth_header:
            headers["Authorization"] = auth_header

        def _probe(value: str) -> dict:
            if param == "path":
                probe_url = url.replace(current_value, value, 1) if current_value else url
                params = None
            else:
                probe_url = url
                params = {param: value}
            try:
                r = requests.get(probe_url, params=params, headers=headers,
                                 cookies=cookies, timeout=12,
                                 allow_redirects=False, verify=False)
                body = r.text or ""
                return {
                    "value":     value,
                    "status":    r.status_code,
                    "length":    len(r.content or b""),
                    "body_hash": _hash(body),
                    "ok":        True,
                    "title":     _grab_title(body),
                }
            except Exception as e:
                return {"value": value, "ok": False, "error": f"{type(e).__name__}: {e}"}

        baseline = _probe(current_value)
        if not baseline.get("ok"):
            return SkillResult(ok=False, error=f"baseline probe failed: {baseline.get('error')}")

        probes = [baseline]
        hits   = []
        for v in test_values:
            if v == current_value:
                continue
            p = _probe(v)
            probes.append(p)
            if not p.get("ok"):
                continue
            # Hit heuristic — 2xx response, different body hash, and
            # meaningfully different length from baseline.
            if (200 <= p["status"] < 300
                and p["body_hash"] != baseline["body_hash"]
                and abs(p["length"] - baseline["length"]) > 48):
                hits.append(p)

        summary = (
            f"Baseline {baseline['status']} ({baseline['length']} B) @ {param}={current_value}. "
            f"Probed {len(probes)-1} alt values → {len(hits)} potential IDOR hit(s)."
        )

        if not hits:
            return SkillResult(
                ok=True,
                summary=summary + " No access differential detected.",
                extras={"baseline": baseline, "probes": probes[1:]},
            )

        # Build an evidence blurb per hit.
        ev_lines = [f"Baseline: {param}={current_value} → HTTP {baseline['status']} {baseline['length']}B "
                    f"(hash={baseline['body_hash']}, title='{baseline['title']}')"]
        for h in hits:
            ev_lines.append(
                f"Hit: {param}={h['value']} → HTTP {h['status']} {h['length']}B "
                f"(hash={h['body_hash']}, title='{h['title']}')"
            )
        evidence = "\n".join(ev_lines)

        severity = "high" if len(hits) >= 2 else "medium"
        return SkillResult(
            ok       = True,
            summary  = summary + " Flagged.",
            evidence = evidence,
            finding  = {
                "vuln_type":   "idor",
                "severity":    severity,
                "target":      url,
                "location":    f"{url} ?{param}=",
                "description": (
                    f"Endpoint returns substantively different 2xx content for "
                    f"{len(hits)} alternative {param} value(s) without auth changes, "
                    "suggesting horizontal access to another object."
                ),
                "evidence":    evidence,
            },
            extras   = {"baseline": baseline, "hits": hits, "probes": probes[1:]},
        )


def _grab_title(body: str) -> str:
    import re
    m = re.search(r"<title[^>]*>([^<]+)</title>", body, re.I)
    return (m.group(1).strip()[:80] if m else "")
