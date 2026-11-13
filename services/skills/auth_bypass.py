"""SkillAuthBypass — probe a blocked URL with a library of bypass techniques.

Given a URL that's known to return 401/403 (the agent tells us the baseline),
try common bypass tricks and flag any that flip the response to 2xx:

  - IP-trust headers (X-Forwarded-For, X-Real-IP, X-Originating-IP, X-Remote-Addr)
  - URL-rewrite headers (X-Original-URL, X-Rewrite-URL)
  - Method override (HTTP verb tampering + X-HTTP-Method-Override)
  - Path encoding tricks (trailing /, double slashes, URL-encoded dots,
    semicolon, %00, matrix params, /./, /..;/)
  - Host header injection

Each attempt is one deterministic HTTP call. Non-destructive. Results come
back as a list of (technique, status, length) so the LLM can see exactly
which tricks worked.
"""
from __future__ import annotations
import hashlib, re
from typing import Optional
from urllib.parse import urlparse, urlunparse

import requests

from services.skills.base import Skill, SkillResult, register
from services.skills._payloads import (
    AUTH_BYPASS_IP_HEADERS,
    AUTH_BYPASS_REWRITE_HEADERS,
    AUTH_BYPASS_METHOD_OVERRIDES,
    AUTH_BYPASS_PATH_SUFFIXES,
    API_VERSION_REGEX,
    API_VERSION_ALTERNATES,
)


_HEADERS = {"User-Agent": "Mozilla/5.0 ZeekGlare-Arena-AuthBypass"}


def _hash(s: str) -> str:
    return hashlib.sha1((s or "").encode("utf-8", "replace")).hexdigest()[:12]


# (technique_id, build_request_fn) — each fn returns a dict of overrides:
#   {"method": str, "url": str, "headers": {...}}
def _techniques(url: str) -> list[tuple[str, callable]]:
    t = []

    def hdr(name, val):
        def _f(u, method):
            return {"method": method, "url": u, "headers": {name: val}}
        return _f

    # IP-trust headers (sourced from _payloads.AUTH_BYPASS_IP_HEADERS)
    for h, v in AUTH_BYPASS_IP_HEADERS:
        t.append((f"header:{h}={v}", hdr(h, v)))

    # URL-rewrite headers
    for h in AUTH_BYPASS_REWRITE_HEADERS:
        t.append((f"header:{h}", lambda u, m, h=h: _with_rewrite(u, m, h)))

    # Method overrides (verb tampering)
    for alt in AUTH_BYPASS_METHOD_OVERRIDES:
        t.append((f"method:{alt}", lambda u, m, alt=alt: {"method": alt, "url": u, "headers": {}}))
    t.append(("header:X-HTTP-Method-Override=PUT",
              lambda u, m: {"method": m, "url": u, "headers": {"X-HTTP-Method-Override": "PUT"}}))

    # Path-encoding tricks
    for suffix in AUTH_BYPASS_PATH_SUFFIXES:
        t.append((f"path+{suffix!r}", lambda u, m, suffix=suffix: _with_path_suffix(u, m, suffix)))

    # API version swap — sibling endpoint may lack the auth middleware.
    for new_version in _api_version_swaps(url):
        t.append((f"path:api-version={new_version or 'drop'}",
                  lambda u, m, nv=new_version: _with_version_swap(u, m, nv)))

    return t


def _api_version_swaps(url: str) -> list[str]:
    """Detect /vN/ or /api/vN/ in the URL path; return sibling versions to try."""
    p = urlparse(url)
    m = re.search(API_VERSION_REGEX, p.path or "")
    if not m:
        return []
    current = f"v{m.group(1)}"
    return [v for v in API_VERSION_ALTERNATES if v != current]


def _with_version_swap(url: str, method: str, new_version: str) -> dict:
    """Replace the first /vN/ or /api/vN/ segment with new_version (or drop)."""
    p = urlparse(url)
    if new_version:
        new_path = re.sub(API_VERSION_REGEX,
                          lambda m: m.group(0).replace(f"v{m.group(1)}", new_version, 1),
                          p.path or "", count=1)
    else:
        # Drop the /vN/ segment entirely.
        new_path = re.sub(API_VERSION_REGEX, "/", p.path or "", count=1)
    return {
        "method":  method,
        "url":     urlunparse((p.scheme, p.netloc, new_path, p.params, p.query, "")),
        "headers": {},
    }


def _with_rewrite(url: str, method: str, header_name: str) -> dict:
    """Strip path from URL, then set header_name = /original/path."""
    p = urlparse(url)
    rewritten = p.path or "/"
    if p.query:
        rewritten += "?" + p.query
    base = urlunparse((p.scheme, p.netloc, "/", "", "", ""))
    return {"method": method, "url": base, "headers": {header_name: rewritten}}


def _with_path_suffix(url: str, method: str, suffix: str) -> dict:
    p = urlparse(url)
    new_path = (p.path or "/") + suffix
    return {
        "method": method,
        "url":    urlunparse((p.scheme, p.netloc, new_path, p.params, p.query, "")),
        "headers": {},
    }


@register
class SkillAuthBypass(Skill):
    name        = "skill_auth_bypass"
    danger      = "active"
    description = (
        "Probe a blocked URL (401/403) with a library of auth-bypass techniques: "
        "IP-trust headers (X-Forwarded-For etc.), URL-rewrite headers, HTTP method "
        "tampering, path-encoding tricks (trailing slash, //, %2e, /..;/, etc.), "
        "and API version swaps (e.g. /v2/ → /v1/ when the older route lacks auth). "
        "Each technique is one GET/HEAD request; non-destructive. Flags any technique "
        "that flips the response to 2xx — that's an access control bypass. Call this "
        "after you've confirmed an endpoint returns 401 or 403 via fetch_http."
    )
    guidance    = (
        "Old API versions (/v1/) often lack the auth middleware their newer siblings "
        "(/v2/, /v3/) have. When you find a 401/403 on /api/vN/, always check sibling "
        "versions. Also: sibling endpoints under the same prefix (e.g. /admin/export "
        "next to /admin) frequently have missing middleware."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "url":             {"type": "string", "description": "The blocked URL to probe. Must be in scope."},
            "baseline_method": {"type": "string", "enum": ["GET", "HEAD"], "default": "GET"},
            "baseline_status": {"type": "integer", "description": "Status you saw (usually 401 or 403)."},
            "max_techniques":  {"type": "integer", "default": 20, "description": "Cap on techniques to try (1–30)."},
            "cookies":         {"type": "object", "description": "Optional cookies sent on every probe."},
        },
        "required": ["url"],
    }

    @classmethod
    def applicable(cls, state) -> bool:
        return state.asset_counts().get("url", 0) > 0

    @classmethod
    def dedup_key(cls, args) -> Optional[tuple[str, str, str, str]]:
        return (args.get("url", ""), "", "auth_bypass", "library")

    @classmethod
    def run(cls, args, state, agent_id) -> SkillResult:
        url = (args.get("url") or "").strip()
        if not url:
            return SkillResult(ok=False, error="url required")
        if not state.in_scope(url):
            return SkillResult(ok=False, error=f"out of scope: {url}")

        baseline_method = (args.get("baseline_method") or "GET").upper()
        max_techniques  = max(1, min(int(args.get("max_techniques") or 20), 30))
        cookies         = args.get("cookies") or None

        # Baseline.
        try:
            br = requests.request(baseline_method, url, headers=_HEADERS,
                                  cookies=cookies, timeout=10,
                                  allow_redirects=False, verify=False)
        except Exception as e:
            return SkillResult(ok=False, error=f"baseline failed: {type(e).__name__}: {e}")

        baseline = {
            "method":    baseline_method,
            "status":    br.status_code,
            "length":    len(br.content or b""),
            "body_hash": _hash(br.text or ""),
        }
        if 200 <= br.status_code < 300:
            # Nothing to bypass — the URL isn't blocked in our context.
            return SkillResult(
                ok=True,
                summary=f"Baseline returned {br.status_code} — no auth to bypass.",
                extras={"baseline": baseline},
            )

        # Run techniques.
        techniques = _techniques(url)[:max_techniques]
        probes = []
        hits   = []
        for tid, build in techniques:
            try:
                spec = build(url, baseline_method)
                r = requests.request(
                    spec["method"], spec["url"],
                    headers={**_HEADERS, **spec["headers"]},
                    cookies=cookies, timeout=8,
                    allow_redirects=False, verify=False,
                )
                rec = {
                    "technique": tid,
                    "status":    r.status_code,
                    "length":    len(r.content or b""),
                    "body_hash": _hash(r.text or ""),
                }
                probes.append(rec)
                if 200 <= r.status_code < 300 and rec["body_hash"] != baseline["body_hash"]:
                    hits.append(rec)
            except Exception as e:
                probes.append({"technique": tid, "error": f"{type(e).__name__}: {e}"})

        summary = (
            f"Baseline {baseline['status']} {baseline['length']}B. "
            f"Tried {len(techniques)} techniques → {len(hits)} bypass(es)."
        )

        if not hits:
            return SkillResult(
                ok=True,
                summary=summary + " No bypass found.",
                extras={"baseline": baseline, "probes": probes},
            )

        ev_lines = [f"Baseline: {baseline['method']} → HTTP {baseline['status']} ({baseline['length']}B)"]
        for h in hits:
            ev_lines.append(
                f"BYPASS via {h['technique']} → HTTP {h['status']} ({h['length']}B)"
            )
        evidence = "\n".join(ev_lines)

        return SkillResult(
            ok       = True,
            summary  = summary + " Bypass confirmed.",
            evidence = evidence,
            finding  = {
                "vuln_type":   "auth_bypass",
                "severity":    "high",
                "target":      url,
                "location":    url,
                "description": (
                    f"Access control bypass: endpoint returns {baseline['status']} on a "
                    f"normal request but yields 2xx when {len(hits)} technique(s) are "
                    "applied (IP-trust header, URL-rewrite header, method tampering, "
                    "or path encoding)."
                ),
                "evidence":    evidence,
            },
            extras   = {"baseline": baseline, "hits": hits,
                        "probe_count": len(probes)},
        )
