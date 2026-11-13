"""SkillCsrf — detect missing/weak CSRF tokens on state-changing endpoints.

Workflow:
  1. GET the user-supplied page; parse <form> elements.
  2. For each POST/PUT/DELETE/PATCH form:
     - Look for hidden inputs whose name matches CSRF_TOKEN_NAMES
     - Check Set-Cookie headers from the page response for SameSite=Strict|Lax
  3. Issue a cross-origin POST to the form's action URL WITHOUT the token
     and with `Origin: https://attacker-zg.example`.
  4. If the response is success-shaped (200/302 to a success-y location)
     vs the baseline rejection (403/400/401), CSRF is exploitable.

Severity:
  - critical : state-changing endpoint (matches STATE_CHANGE_KEYWORDS) accepts
               cross-origin POST with no CSRF token
  - high     : non-critical-keyword form accepts cross-origin POST
  - info     : token + SameSite cookie both present (defense holding)
"""
from __future__ import annotations
import re
from typing import Optional
from urllib.parse import urljoin, urlparse

import requests

from services.skills.base import Skill, SkillResult, register
from services.skills._payloads import CSRF_TOKEN_NAMES, STATE_CHANGE_KEYWORDS
from services.skills._poc import capture_from_response


_HEADERS = {"User-Agent": "Mozilla/5.0 ZeekGlare-Arena-CSRF"}
_EVIL_ORIGIN = "https://attacker-zg.example"


def _find_forms(html: str, base_url: str):
    """Return list of {action, method, inputs:[name,value]}."""
    forms = []
    for fm in re.finditer(r"<form\b([^>]*)>(.*?)</form>", html, re.I | re.S):
        attrs = fm.group(1) or ""
        body  = fm.group(2) or ""
        am = re.search(r'\baction=["\']([^"\']*)["\']', attrs, re.I)
        mm = re.search(r'\bmethod=["\']([^"\']*)["\']', attrs, re.I)
        action = (am.group(1) if am else "").strip() or base_url
        method = (mm.group(1) if mm else "GET").upper()
        if method == "GET":   # only state-changing methods are interesting for CSRF
            continue
        action_abs = urljoin(base_url, action)
        inputs = []
        for inp in re.finditer(r"<input\b([^>]*)>", body, re.I):
            ia = inp.group(1) or ""
            nm = re.search(r'\bname=["\']([^"\']+)["\']', ia, re.I)
            vm = re.search(r'\bvalue=["\']([^"\']*)["\']', ia, re.I)
            tm = re.search(r'\btype=["\']([^"\']*)["\']', ia, re.I)
            if nm:
                inputs.append({"name": nm.group(1),
                                "value": vm.group(1) if vm else "",
                                "type":  (tm.group(1) if tm else "text").lower()})
        forms.append({"action": action_abs, "method": method, "inputs": inputs})
    return forms


def _has_csrf_token(form: dict) -> bool:
    names = {(i["name"] or "").lower() for i in form["inputs"]}
    return any(t.lower() in names for t in CSRF_TOKEN_NAMES)


def _classify_state_change(action_url: str) -> bool:
    p = (urlparse(action_url).path or "").lower()
    return any(k in p for k in STATE_CHANGE_KEYWORDS)


@register
class SkillCsrf(Skill):
    name        = "skill_csrf"
    danger      = "active"
    description = (
        "Detect missing/weak CSRF on state-changing forms. GETs the page, "
        "parses every <form method=POST|PUT|DELETE|PATCH>, checks for hidden "
        "CSRF-token inputs (csrf_token / authenticity_token / "
        "__RequestVerificationToken / etc.) AND for SameSite cookie flags. "
        "Then issues a cross-origin POST to the form action without the token "
        "and with Origin: " + _EVIL_ORIGIN + ". If the request succeeds where "
        "the baseline would have been blocked, CSRF is exploitable."
    )
    guidance    = (
        "CSRF impact ladder: a CSRF on /change-password or /transfer-funds is "
        "critical (full account takeover via 1-click); CSRF on /update-bio is "
        "low. Always inspect the form action's path keywords before grading. "
        "If the page sets SameSite=Strict cookies AND has a token, modern "
        "browsers reject the attack — flag info, not high."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "url":     {"type": "string", "description": "URL of a page that contains a form. Must be in scope."},
            "cookies": {"type": "object", "description": "Optional auth cookies (so the session has a logged-in form)."},
        },
        "required": ["url"],
    }

    @classmethod
    def applicable(cls, state) -> bool:
        return state.asset_counts().get("url", 0) > 0

    @classmethod
    def dedup_key(cls, args) -> Optional[tuple[str, str, str, str]]:
        return (args.get("url", ""), "", "csrf", "form_scan")

    @classmethod
    def run(cls, args, state, agent_id) -> SkillResult:
        url     = (args.get("url") or "").strip()
        cookies = args.get("cookies") or None
        if not url:
            return SkillResult(ok=False, error="url required")
        if not state.in_scope(url):
            return SkillResult(ok=False, error=f"out of scope: {url}")

        try:
            r0 = requests.get(url, headers=_HEADERS, cookies=cookies,
                              timeout=12, allow_redirects=False, verify=False)
        except Exception as e:
            return SkillResult(ok=False, error=f"page fetch failed: {type(e).__name__}: {e}")

        # Cookie SameSite check
        samesite_strict = False
        for c in r0.headers.get_list("Set-Cookie") if hasattr(r0.headers, "get_list") \
                 else (r0.headers.get("Set-Cookie", "").split(",") if r0.headers.get("Set-Cookie") else []):
            if re.search(r"samesite=(strict|lax)", c, re.I):
                samesite_strict = True; break

        forms = _find_forms(r0.text or "", url)
        if not forms:
            return SkillResult(
                ok=True,
                summary="No POST/PUT/DELETE/PATCH forms found on this page — nothing to CSRF.",
                extras={"samesite": samesite_strict},
            )

        hits = []
        all_probes = []
        for form in forms:
            has_token       = _has_csrf_token(form)
            is_state_change = _classify_state_change(form["action"])
            probe_data = {i["name"]: i["value"] for i in form["inputs"]
                          if i.get("name") and (i.get("type") not in ("submit", "button"))}
            try:
                rp = requests.request(
                    form["method"], form["action"],
                    data=probe_data,
                    headers={**_HEADERS,
                             "Origin": _EVIL_ORIGIN,
                             "Referer": _EVIL_ORIGIN + "/"},
                    cookies=cookies,
                    timeout=10, allow_redirects=False, verify=False,
                )
            except Exception as e:
                all_probes.append({"action": form["action"], "method": form["method"],
                                   "error": str(e)})
                continue

            success_shaped = (200 <= rp.status_code < 300) or (
                rp.status_code in (302, 303) and "/login" not in (rp.headers.get("Location") or "").lower()
            )
            rec = {
                "action":         form["action"],
                "method":         form["method"],
                "has_csrf_token": has_token,
                "samesite_set":   samesite_strict,
                "is_state_change":is_state_change,
                "status":         rp.status_code,
                "location":       rp.headers.get("Location", ""),
                "success_shaped": success_shaped,
                "_response":      rp,
            }
            all_probes.append(rec)
            # Vulnerable when: no token AND no SameSite AND request succeeded.
            if not has_token and not samesite_strict and success_shaped:
                hits.append(rec)

        if not hits:
            return SkillResult(
                ok=True,
                summary=(f"CSRF appears defended across {len(forms)} form(s) "
                         f"(token={'present' if any(_has_csrf_token(f) for f in forms) else 'absent'}, "
                         f"SameSite={'set' if samesite_strict else 'absent'})."),
                extras={"forms_scanned": len(forms),
                        "probes": [{k: v for k, v in p.items() if k != "_response"} for p in all_probes]},
            )

        worst = max(hits, key=lambda h: (h["is_state_change"], 200 <= h["status"] < 300))
        sev = "critical" if worst["is_state_change"] else "high"
        poc = capture_from_response(
            worst["_response"],
            caption=f"CSRF — cross-origin {worst['method']} to {worst['action']} succeeded "
                    f"(no token, no SameSite); state-change-keyword: {worst['is_state_change']}"
        )
        return SkillResult(
            ok=True,
            summary=f"CSRF confirmed on {len(hits)}/{len(forms)} form(s) — severity {sev}.",
            evidence=poc.format(),
            finding={
                "vuln_type":   "csrf",
                "severity":    sev,
                "target":      url,
                "location":    worst["action"],
                "description": (
                    f"Cross-Site Request Forgery — form action {worst['action']} accepts "
                    f"a {worst['method']} request from a foreign origin with no CSRF token "
                    "and no SameSite cookie protection. "
                    + ("Path keywords suggest a state-changing action (account/password/"
                       "settings/etc.) — full one-click account takeover potential."
                       if worst["is_state_change"] else
                       "Endpoint accepts the request but isn't on a sensitive-keyword path; "
                       "manual triage needed to assess impact.")
                ),
                "evidence":    poc.format(),
            },
            extras={"hits": [{k: v for k, v in h.items() if k != "_response"} for h in hits],
                    "samesite_set": samesite_strict},
        )
