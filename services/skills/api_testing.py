"""SkillApiTesting — three API-class checks per URL.

  1. HTTP verb tampering — try GET/POST/PUT/DELETE/PATCH/OPTIONS on the same
     URL. If a "DELETE" returns 200 where the agent expected 405, or OPTIONS
     leaks Allow: <verbs>, that's a finding.
  2. HTTP Parameter Pollution — duplicate-param injection (?role=user&role=admin).
     Look for response shape change vs single-param baseline.
  3. Mass assignment — for JSON POST/PATCH endpoints, append privilege-elevation
     fields (is_admin, role:admin, etc.) and check whether the response reflects
     elevated privilege OR a different shape than baseline.

Severity:
  - critical : mass-assignment success (response reflects elevated role) OR
               DELETE/PUT verb tampering succeeds on a state-changing URL
  - high     : HPP succeeded (param-pollution shifted response)
  - medium   : OPTIONS leaks Allow listing additional verbs
  - info     : nothing
"""
from __future__ import annotations
import json
from typing import Optional
from urllib.parse import urlparse, urlencode, urlunparse, parse_qsl

import requests

from services.skills.base import Skill, SkillResult, register
from services.skills._payloads import HPP_INJECTIONS, MASS_ASSIGNMENT_FIELDS, STATE_CHANGE_KEYWORDS
from services.skills._poc import capture_from_response


_HEADERS = {"User-Agent": "Mozilla/5.0 ZeekGlare-Arena-API"}
_VERBS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]


def _swap(url: str, param: str, value: str) -> str:
    p = urlparse(url)
    qs = parse_qsl(p.query, keep_blank_values=True)
    new_qs = [(k, value if k == param else v) for k, v in qs]
    if not any(k == param for k, _ in qs):
        new_qs.append((param, value))
    return urlunparse((p.scheme, p.netloc, p.path, p.params, urlencode(new_qs), p.fragment))


@register
class SkillApiTesting(Skill):
    name        = "skill_api_testing"
    danger      = "active"
    description = (
        "Three checks per URL: (1) HTTP verb tampering — try every method on "
        "the same URL, look for unexpected 2xx and OPTIONS Allow leakage. "
        "(2) HTTP Parameter Pollution — inject duplicate params like "
        "?role=admin and check response shape change vs single-param baseline. "
        "(3) Mass assignment — for JSON POST/PATCH endpoints, append privilege-"
        "elevation fields (is_admin, role) and check whether the response "
        "reflects elevation. Use on REST endpoints discovered via "
        "extract_params or http_probe."
    )
    guidance    = (
        "API testing is bread-and-butter — bugs hide in the details devs forget. "
        "Mass assignment is the single highest-paying API bug class because the "
        "fix requires schema-level allow-listing and most teams don't do it. "
        "Always test PATCH on user/profile endpoints with {is_admin:true}. "
        "OPTIONS often leaks Allow: GET,POST,PUT,DELETE — sometimes auth is "
        "only on POST and DELETE goes through unauth."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "url":         {"type": "string", "description": "API URL to probe."},
            "baseline_method": {"type": "string", "enum": ["GET", "POST", "PUT", "PATCH", "DELETE"], "default": "GET"},
            "json_body":   {"type": "object", "description": "Optional JSON body for POST/PATCH/PUT (mass-assignment test)."},
            "headers":     {"type": "object", "description": "Optional auth headers (Authorization, etc.)."},
            "checks":      {
                "type": "array",
                "items": {"type": "string", "enum": ["verb_tampering", "hpp", "mass_assignment"]},
                "default": ["verb_tampering", "hpp", "mass_assignment"],
            },
        },
        "required": ["url"],
    }

    @classmethod
    def applicable(cls, state) -> bool:
        return state.asset_counts().get("url", 0) > 0

    @classmethod
    def dedup_key(cls, args) -> Optional[tuple[str, str, str, str]]:
        return (args.get("url", ""), args.get("baseline_method", "GET"),
                "api_testing", "verb+hpp+massassign")

    @classmethod
    def run(cls, args, state, agent_id) -> SkillResult:
        url            = (args.get("url") or "").strip()
        baseline_method= (args.get("baseline_method") or "GET").upper()
        json_body      = args.get("json_body") or None
        headers        = {**_HEADERS, **(args.get("headers") or {})}
        checks         = args.get("checks") or ["verb_tampering", "hpp", "mass_assignment"]
        if not url:
            return SkillResult(ok=False, error="url required")
        if not state.in_scope(url):
            return SkillResult(ok=False, error=f"out of scope: {url}")

        # Baseline.
        try:
            r0 = requests.request(baseline_method, url, headers=headers,
                                   json=json_body, timeout=10,
                                   allow_redirects=False, verify=False)
        except Exception as e:
            return SkillResult(ok=False, error=f"baseline failed: {type(e).__name__}: {e}")

        baseline_status = r0.status_code
        baseline_len    = len(r0.content or b"")

        verb_findings = []
        hpp_findings  = []
        mass_findings = []
        all_probes    = []

        # ── 1. Verb tampering ────────────────────────────────────────────────
        if "verb_tampering" in checks:
            for verb in _VERBS:
                if verb == baseline_method:
                    continue
                try:
                    rv = requests.request(verb, url, headers=headers, timeout=8,
                                           allow_redirects=False, verify=False)
                except Exception:
                    continue
                rec = {"check": "verb", "verb": verb, "status": rv.status_code,
                       "length": len(rv.content or b""), "_response": rv}
                all_probes.append(rec)
                # OPTIONS → check Allow header
                if verb == "OPTIONS":
                    allow = rv.headers.get("Allow") or rv.headers.get("Access-Control-Allow-Methods", "")
                    if allow:
                        rec["allow_header"] = allow
                        # If Allow lists state-changing methods we couldn't otherwise hit
                        verbs_in_allow = [v.strip().upper() for v in allow.split(",")]
                        leaked = [v for v in verbs_in_allow if v in ("PUT", "DELETE", "PATCH")]
                        if leaked:
                            verb_findings.append(rec)
                # Unexpected 2xx on a state-change verb when baseline isn't 2xx → bug
                elif (200 <= rv.status_code < 300
                      and not (200 <= baseline_status < 300)
                      and verb in ("PUT", "DELETE", "PATCH", "POST")):
                    verb_findings.append(rec)

        # ── 2. HTTP Parameter Pollution ──────────────────────────────────────
        if "hpp" in checks and "?" in url:
            for extra_name, extra_val, label in HPP_INJECTIONS:
                # Inject as duplicate param
                p = urlparse(url)
                qs = parse_qsl(p.query, keep_blank_values=True)
                qs.append((extra_name, extra_val))
                hpp_url = urlunparse((p.scheme, p.netloc, p.path, p.params, urlencode(qs), p.fragment))
                try:
                    rh = requests.get(hpp_url, headers=headers, timeout=8,
                                       allow_redirects=False, verify=False)
                except Exception:
                    continue
                len_delta    = abs(len(rh.content or b"") - baseline_len)
                status_delta = rh.status_code != baseline_status
                rec = {"check": "hpp", "label": label, "extra": f"{extra_name}={extra_val}",
                       "status": rh.status_code, "length": len(rh.content or b""),
                       "len_delta": len_delta, "_response": rh}
                all_probes.append(rec)
                # Hit if response materially differs and the new response is still 2xx
                if 200 <= rh.status_code < 300 and (status_delta or len_delta > 100):
                    hpp_findings.append(rec)

        # ── 3. Mass assignment ───────────────────────────────────────────────
        if ("mass_assignment" in checks
            and baseline_method in ("POST", "PUT", "PATCH")
            and isinstance(json_body, dict)):
            for elev in MASS_ASSIGNMENT_FIELDS:
                inj_body = {**json_body, **elev}
                try:
                    rm = requests.request(baseline_method, url, headers=headers,
                                           json=inj_body, timeout=10,
                                           allow_redirects=False, verify=False)
                except Exception:
                    continue
                # Heuristic: response reflects elevated key OR baseline 4xx → 2xx
                body = rm.text or ""
                elev_key = list(elev.keys())[0]
                elev_val = json.dumps(elev[elev_key])
                reflected = elev_key in body and (str(elev[elev_key]).lower() in body.lower()
                                                   or elev_val.lower() in body.lower())
                rec = {"check": "mass_assignment", "elev": elev,
                       "status": rm.status_code, "reflected": reflected,
                       "length": len(rm.content or b""), "_response": rm}
                all_probes.append(rec)
                if (200 <= rm.status_code < 300
                    and (reflected or
                         (not (200 <= baseline_status < 300)))):
                    mass_findings.append(rec)

        all_findings = mass_findings + verb_findings + hpp_findings
        if not all_findings:
            return SkillResult(
                ok=True,
                summary=(f"No API issues across {len(all_probes)} probe(s)."
                         f" Baseline {baseline_method} → {baseline_status}."),
                extras={"baseline_status": baseline_status,
                        "verb_probes": sum(1 for p in all_probes if p["check"] == "verb"),
                        "hpp_probes":  sum(1 for p in all_probes if p["check"] == "hpp"),
                        "mass_probes": sum(1 for p in all_probes if p["check"] == "mass_assignment")},
            )

        # Pick worst — mass_assignment > verb > hpp
        is_state_change = any(k in (urlparse(url).path or "").lower() for k in STATE_CHANGE_KEYWORDS)
        if mass_findings:
            best = mass_findings[0]
            sev = "critical"
            vuln_type = "mass_assignment"
            descr = (
                f"Mass assignment — appending {list(best['elev'].keys())[0]}={list(best['elev'].values())[0]!r} "
                f"to the {baseline_method} body produces a 2xx response"
                + (" with the elevated field reflected in the response body" if best["reflected"] else "")
                + ". Direct privilege elevation."
            )
        elif verb_findings:
            best = verb_findings[0]
            sev = "critical" if (is_state_change and best["verb"] in ("PUT", "DELETE", "PATCH")) else "medium"
            vuln_type = "http_verb_tampering"
            if best.get("allow_header"):
                descr = (f"OPTIONS leaks Allow: {best['allow_header']} — endpoint accepts state-changing "
                         "verbs that aren't reachable via the documented method.")
            else:
                descr = (f"Verb tampering — {best['verb']} on {url} returns "
                         f"{best['status']} where {baseline_method} returns {baseline_status}. "
                         + ("State-changing path keyword present — direct unintended write." if is_state_change else ""))
        else:
            best = hpp_findings[0]
            sev = "high"
            vuln_type = "http_parameter_pollution"
            descr = (f"HTTP Parameter Pollution — appending duplicate ?{best['extra']} "
                     f"shifts response (status {baseline_status}→{best['status']}, "
                     f"size delta {best['len_delta']}B). Backend honors the second occurrence — "
                     "common pattern for role/permission overrides.")

        poc = capture_from_response(best["_response"],
                                     caption=descr.split(".")[0])
        return SkillResult(
            ok=True,
            summary=f"API issue confirmed ({vuln_type}, {sev}).",
            evidence=poc.format(),
            finding={
                "vuln_type":   vuln_type,
                "severity":    sev,
                "target":      url,
                "location":    url,
                "description": descr,
                "evidence":    poc.format(),
            },
            extras={
                "verb_findings":  [{k: v for k, v in r.items() if k != "_response"} for r in verb_findings],
                "hpp_findings":   [{k: v for k, v in r.items() if k != "_response"} for r in hpp_findings],
                "mass_findings":  [{k: v for k, v in r.items() if k != "_response"} for r in mass_findings],
                "baseline":       {"method": baseline_method, "status": baseline_status, "length": baseline_len},
            },
        )
