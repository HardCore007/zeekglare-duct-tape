"""SkillJsSecrets — deep regex sweep of every JS file in shared state.

Walks shared state's `url` asset set, picks every URL ending in `.js`, fetches
each (cap to 30 by default), and runs the curated `SECRET_REGEX_CATALOG`
against the body. Every match becomes a finding with:

  - file URL + character offset
  - matched secret label (AWS Access Key, GitHub PAT, Stripe Live Secret, …)
  - the matched text (redacted to prefix+suffix when the regex marks it sensitive)
  - severity from the catalog entry

Run AFTER `js_endpoints` (which populates the JS URL set). One skill call
sweeps the whole site rather than per-file.

Severity per match comes from the catalog — critical for live cloud creds,
high for tokens, medium for JWTs/passwords. Multiple matches across files
get aggregated into a single finding ranked by the worst severity.
"""
from __future__ import annotations
from typing import Optional

import requests

from services.skills.base import Skill, SkillResult, register
from services.skills._payloads import SECRET_REGEX_CATALOG


_HEADERS = {"User-Agent": "Mozilla/5.0 ZeekGlare-Arena-JSSecret"}
_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _redact(s: str, keep: int = 4) -> str:
    """Don't echo full live secrets into shared state. Keep first/last few chars."""
    if not s or len(s) <= (keep * 2 + 3):
        return "***"
    return f"{s[:keep]}…{s[-keep:]}"


def _scan(content: str, url: str) -> list[dict]:
    hits = []
    for label, rx, sev, redact_match in SECRET_REGEX_CATALOG:
        for m in rx.finditer(content):
            full = m.group(1) if (m.lastindex and m.lastindex >= 1) else m.group(0)
            displayed = _redact(full) if redact_match else full
            # Surrounding context for the triager
            start = max(0, m.start() - 40)
            end   = min(len(content), m.end() + 40)
            ctx   = content[start:end].replace("\n", " ")
            hits.append({
                "label":      label,
                "severity":   sev,
                "match":      displayed,
                "match_full": full[:200],   # only stored in extras for skilled-eyes triage
                "url":        url,
                "offset":     m.start(),
                "context":    ctx[:200],
            })
    return hits


@register
class SkillJsSecrets(Skill):
    name        = "skill_js_secrets"
    danger      = "safe"   # GET-only, doesn't touch the target beyond reading public JS
    description = (
        "Deep-scan every JS file in shared state for hardcoded secrets — "
        "AWS / GCP / Azure keys, GitHub PATs, Stripe live secrets, Slack tokens, "
        "Twilio / SendGrid / Mailgun keys, private keys (PEM blocks), JWTs, "
        "database URLs, generic API keys / passwords. Walks every URL ending "
        ".js in shared state (populated by js_endpoints), fetches each (max 30 "
        "per call), runs ~25 regex patterns, aggregates matches into one "
        "finding ranked by the worst-severity hit. Run AFTER js_endpoints."
    )
    guidance    = (
        "JS secret leaks are the highest-ROI find on most bug-bounty programs — "
        "developers commit live API keys to public bundles all the time. AWS / "
        "Stripe / GitHub PAT hits are critical (direct cloud takeover). Always "
        "verify the secret is live before reporting (curl with the key) — "
        "but DON'T do that inside the arena (out of scope). Just flag it."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "max_files":     {"type": "integer", "default": 30, "description": "Cap on JS files to fetch this run (1-60)."},
            "extra_js_urls": {"type": "array", "items": {"type": "string"},
                               "description": "Optional additional JS URLs the agent has discovered manually."},
        },
        "required": [],
    }

    @classmethod
    def applicable(cls, state) -> bool:
        # Reachable as soon as ANY URL is known — the skill itself filters to .js
        return state.asset_counts().get("url", 0) > 0

    @classmethod
    def dedup_key(cls, args) -> Optional[tuple[str, str, str, str]]:
        # One sweep per arena race — the JS file set rarely changes mid-race
        return ("__all_js__", "", "js_secrets", "regex_sweep")

    @classmethod
    def run(cls, args, state, agent_id) -> SkillResult:
        cap = max(1, min(int(args.get("max_files") or 30), 60))
        extra = [u for u in (args.get("extra_js_urls") or []) if isinstance(u, str)]
        js_urls = [u for u in state.get_assets("url") if u.endswith(".js")]
        for u in extra:
            if u not in js_urls:
                js_urls.append(u)
        # Filter to in-scope
        js_urls = [u for u in js_urls if state.in_scope(u)][:cap]
        if not js_urls:
            return SkillResult(
                ok=False,
                error="no .js URLs in shared state — run js_endpoints first",
            )

        all_hits = []
        files_scanned = 0
        files_failed  = 0
        for url in js_urls:
            try:
                r = requests.get(url, headers=_HEADERS, timeout=12, verify=False,
                                 allow_redirects=True)
            except Exception:
                files_failed += 1
                continue
            if r.status_code >= 400 or not r.text:
                files_failed += 1
                continue
            files_scanned += 1
            hits = _scan(r.text, url)
            all_hits.extend(hits)

        if not all_hits:
            return SkillResult(
                ok=True,
                summary=f"No secrets found across {files_scanned} JS file(s).",
                extras={"files_scanned": files_scanned, "files_failed": files_failed,
                        "patterns_tried": len(SECRET_REGEX_CATALOG)},
            )

        # Group hits by severity — finding gets the worst severity
        worst_sev = max(all_hits, key=lambda h: _SEV_RANK.get(h["severity"], 0))["severity"]

        # Build evidence — top 12 hits, one per line, already redacted
        ev_lines = [f"Scanned {files_scanned} JS file(s); found {len(all_hits)} secret-shaped match(es)."]
        ev_lines.append("")
        for h in all_hits[:12]:
            ev_lines.append(f"[{h['severity'].upper():8}] {h['label']:25} → {h['match']}")
            ev_lines.append(f"           in {h['url']}")
            ev_lines.append(f"           context: …{h['context']}…")
            ev_lines.append("")
        if len(all_hits) > 12:
            ev_lines.append(f"… and {len(all_hits) - 12} more match(es)")
        evidence = "\n".join(ev_lines)

        # By-label tally for the description
        from collections import Counter
        label_counts = Counter(h["label"] for h in all_hits)
        top_labels = ", ".join(f"{n}× {lbl}" for lbl, n in label_counts.most_common(5))

        return SkillResult(
            ok=True,
            summary=f"⚠ {len(all_hits)} secret-shaped match(es) in JS — worst severity: {worst_sev}.",
            evidence=evidence,
            finding={
                "vuln_type":   "secrets_in_js",
                "severity":    worst_sev,
                "target":      js_urls[0],
                "location":    f"{files_scanned} JS file(s)",
                "description": (
                    f"Hardcoded secrets discovered in client-side JavaScript. "
                    f"{len(all_hits)} match(es) across {files_scanned} file(s) — "
                    f"breakdown: {top_labels}. Live cloud credentials in JS bundles "
                    "lead to direct account / infra takeover; tokens like JWTs and "
                    "OAuth secrets enable identity forgery. Verify each hit manually "
                    "before reporting, but treat critical-severity matches as immediate."
                ),
                "evidence":    evidence,
            },
            extras={
                "files_scanned":  files_scanned,
                "files_failed":   files_failed,
                "patterns_tried": len(SECRET_REGEX_CATALOG),
                "hit_count":      len(all_hits),
                "by_label":       dict(label_counts),
                "all_hits":       [{k: v for k, v in h.items() if k != "match_full"} for h in all_hits[:30]],
            },
        )
