"""SkillGraphql — probe a GraphQL endpoint for common misconfigurations.

Three checks, ordered cheap → useful:
  1. Endpoint discovery — POST a benign `{__typename}` query; if response is
     valid GraphQL, this is a GraphQL endpoint.
  2. Introspection — POST the standard introspection query. If `__schema`
     comes back populated, schema is exposed (high-impact for attackers
     mapping out the API).
  3. Batching — POST a JSON array of 3 queries; if all 3 are processed,
     the endpoint accepts array batching (rate-limit bypass primitive,
     also chains to brute-force on auth mutations).

Severity:
  - high     : introspection enabled in production
  - medium   : batching enabled (rate-limit bypass vector)
  - info     : neither
"""
from __future__ import annotations
import json
from typing import Optional

import requests

from services.skills.base import Skill, SkillResult, register
from services.skills._payloads import (
    GRAPHQL_INTROSPECTION_QUERY,
    GRAPHQL_BATCH_PROBE,
)


_HEADERS = {
    "User-Agent":   "Mozilla/5.0 ZeekGlare-Arena-GraphQL",
    "Content-Type": "application/json",
    "Accept":       "application/json",
}


@register
class SkillGraphql(Skill):
    name        = "skill_graphql"
    danger      = "active"
    description = (
        "Probe a suspected GraphQL endpoint for common misconfigurations. "
        "Three checks: (1) endpoint validation via {__typename}, "
        "(2) introspection — full schema disclosure when enabled in prod, "
        "(3) array batching — rate-limit bypass vector that chains to "
        "credential brute-force on login mutations. Pass the endpoint URL "
        "(usually /graphql, /api/graphql, /v1/graphql)."
    )
    guidance    = (
        "GraphQL hunting: introspection on prod is medium-to-high impact "
        "alone (schema map = attack surface map). Batching matters because "
        "it lets you brute-force login mutations 100-at-a-time without "
        "triggering per-request rate limits. Both together is the bug."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "GraphQL endpoint URL."},
            "auth_header": {"type": "string", "description": "Optional Authorization header value."},
        },
        "required": ["url"],
    }

    @classmethod
    def applicable(cls, state) -> bool:
        return state.asset_counts().get("url", 0) > 0

    @classmethod
    def dedup_key(cls, args) -> Optional[tuple[str, str, str, str]]:
        return (args.get("url", ""), "", "graphql", "introspection+batching")

    @classmethod
    def run(cls, args, state, agent_id) -> SkillResult:
        url = (args.get("url") or "").strip()
        if not url:
            return SkillResult(ok=False, error="url required")
        if not state.in_scope(url):
            return SkillResult(ok=False, error=f"out of scope: {url}")

        headers = dict(_HEADERS)
        if args.get("auth_header"):
            headers["Authorization"] = args["auth_header"]

        # ── 1: endpoint discovery ────────────────────────────────────────────
        try:
            r1 = requests.post(url, headers=headers,
                               data='{"query":"{__typename}"}',
                               timeout=10, allow_redirects=False, verify=False)
            j1 = r1.json() if r1.status_code < 500 else {}
        except Exception as e:
            return SkillResult(ok=False, error=f"endpoint probe failed: {type(e).__name__}: {e}")
        is_graphql = isinstance(j1, dict) and ("data" in j1 or "errors" in j1)
        if not is_graphql:
            return SkillResult(
                ok=True,
                summary=f"Not a GraphQL endpoint (HTTP {r1.status_code}; response not GraphQL-shaped).",
                extras={"discovery_status": r1.status_code},
            )

        # ── 2: introspection ─────────────────────────────────────────────────
        try:
            r2 = requests.post(url, headers=headers,
                               data=GRAPHQL_INTROSPECTION_QUERY,
                               timeout=15, allow_redirects=False, verify=False)
            j2 = r2.json() if r2.status_code < 500 else {}
        except Exception:
            j2 = {}
        introspection_ok = bool(
            isinstance(j2, dict)
            and j2.get("data")
            and j2["data"].get("__schema")
            and (j2["data"]["__schema"].get("types") or [])
        )
        type_count = len((j2.get("data") or {}).get("__schema", {}).get("types") or []) if introspection_ok else 0

        # ── 3: batching ──────────────────────────────────────────────────────
        try:
            r3 = requests.post(url, headers=headers, data=GRAPHQL_BATCH_PROBE,
                               timeout=10, allow_redirects=False, verify=False)
            j3 = r3.json() if r3.status_code < 500 else None
        except Exception:
            j3 = None
        batching_ok = isinstance(j3, list) and len(j3) >= 2 and all("data" in x or "errors" in x for x in j3)

        # ── Result + severity ────────────────────────────────────────────────
        issues = []
        severity = "info"
        if introspection_ok:
            issues.append(f"introspection enabled ({type_count} types exposed)")
            severity = "high"
        if batching_ok:
            issues.append("array batching accepted (rate-limit bypass)")
            if severity == "info":
                severity = "medium"

        if not issues:
            return SkillResult(
                ok=True,
                summary="GraphQL endpoint confirmed; introspection and batching both disabled.",
                extras={"discovery_status": r1.status_code,
                        "introspection_ok": False, "batching_ok": False},
            )

        ev_lines = [f"URL: {url}",
                    f"Endpoint discovery: HTTP {r1.status_code} — GraphQL response shape confirmed",
                    f"Introspection: {'ENABLED' if introspection_ok else 'disabled'}"
                    + (f" ({type_count} types)" if introspection_ok else ""),
                    f"Array batching: {'ACCEPTED' if batching_ok else 'rejected'}"
                    + (f" ({len(j3)} responses)" if batching_ok else "")]
        evidence = "\n".join(ev_lines)
        return SkillResult(
            ok=True,
            summary=f"GraphQL misconfig ({severity}): {', '.join(issues)}.",
            evidence=evidence,
            finding={
                "vuln_type":   "graphql_misconfiguration",
                "severity":    severity,
                "target":      url,
                "location":    url,
                "description": (
                    f"GraphQL endpoint exposes: {', '.join(issues)}. "
                    + ("Schema disclosure maps the entire API surface for attackers. " if introspection_ok else "")
                    + ("Batching lets attackers send N-many queries per request — rate-limit "
                       "bypass for brute-force on login/mutation endpoints." if batching_ok else "")
                ),
                "evidence":    evidence,
            },
            extras={"introspection_ok": introspection_ok,
                    "batching_ok": batching_ok,
                    "type_count": type_count},
        )
