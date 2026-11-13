"""SkillAccessControl — admin path enumeration + role-context probing.

Two checks:
  1. Path enumeration — try a curated list of admin/sensitive paths against
     the host and flag those that return 2xx or interesting 3xx redirects
     (not to /login).
  2. Role-context probe (when `auth_cookies` provided) — re-test the same
     paths AS the authenticated low-priv user. If a path returns 2xx with
     low-priv cookies but should require admin, that's vertical privilege
     escalation.

Severity:
  - critical : write-class admin endpoint (POST /api/admin/users) reachable
               OR sensitive file disclosure (/.env with credentials)
  - high     : admin GET endpoint reachable without auth, OR low-priv user
               can reach an admin path
  - medium   : interesting status (401/403 vs 404 — confirms the path exists
               but is gated)
  - info     : nothing reachable
"""
from __future__ import annotations
import re
from typing import Optional
from urllib.parse import urlparse, urlunparse

import requests

from services.skills.base import Skill, SkillResult, register
from services.skills._payloads import ADMIN_PATHS, SENSITIVE_FILE_PATHS, STATE_CHANGE_KEYWORDS
from services.skills._poc import capture_from_response


_HEADERS = {"User-Agent": "Mozilla/5.0 ZeekGlare-Arena-AccessCtrl"}


def _origin_root(url: str) -> str:
    p = urlparse(url)
    if not p.netloc:
        return url
    return urlunparse((p.scheme or "https", p.netloc, "", "", "", ""))


def _is_login_redirect(loc: str) -> bool:
    if not loc:
        return False
    l = loc.lower()
    return any(k in l for k in ("/login", "/signin", "/auth", "/account/login"))


@register
class SkillAccessControl(Skill):
    name        = "skill_access_control"
    danger      = "active"
    description = (
        "Enumerate common admin / sensitive paths on the target host (~50 paths "
        "covering /admin, /wp-admin, /api/admin, /actuator, /server-status, "
        "/.env, /.git/config, /backup.zip, /swagger.json, etc.). For each that "
        "returns 2xx (or non-login 3xx), flag it. If `auth_cookies` is provided, "
        "re-tests every path AS the authenticated low-priv user — paths that "
        "return 2xx with low-priv cookies but should require admin reveal "
        "vertical privilege escalation."
    )
    guidance    = (
        "Access-control bugs scale with what's behind the door. /server-status "
        "leaking is medium; /api/admin/users with PII is critical; /.env with "
        "DB creds is critical (chains to direct DB access). Always include "
        "the response body's first 200 chars in evidence — that's what tells "
        "the triager whether the endpoint actually has data or just the "
        "wrapper/CSS shell."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "url":          {"type": "string", "description": "Any URL on the target host (only the origin is used for path enumeration)."},
            "auth_cookies": {"type": "object", "description": "Optional low-priv authenticated cookies for role-context probing."},
            "auth_header":  {"type": "string", "description": "Optional Authorization header (Bearer token, etc.)."},
            "extra_paths":  {"type": "array", "items": {"type": "string"},
                              "description": "Optional additional paths to probe (e.g. ones the agent discovered earlier)."},
        },
        "required": ["url"],
    }

    @classmethod
    def applicable(cls, state) -> bool:
        return state.asset_counts().get("url", 0) > 0 or state.asset_counts().get("subdomain", 0) > 0

    @classmethod
    def dedup_key(cls, args) -> Optional[tuple[str, str, str, str]]:
        # One enumeration per host per arena race is enough.
        host = (urlparse(args.get("url", "")).netloc or "").lower()
        return (host, "", "access_control", "path_enum")

    @classmethod
    def run(cls, args, state, agent_id) -> SkillResult:
        url = (args.get("url") or "").strip()
        if not url:
            return SkillResult(ok=False, error="url required")
        if not state.in_scope(url):
            return SkillResult(ok=False, error=f"out of scope: {url}")

        origin = _origin_root(url)
        cookies     = args.get("auth_cookies") or None
        auth_header = (args.get("auth_header") or "").strip()
        extra       = [p for p in (args.get("extra_paths") or []) if isinstance(p, str)]

        all_paths = ADMIN_PATHS + SENSITIVE_FILE_PATHS + extra
        unauthed_hits = []
        authed_hits   = []
        all_probes    = []

        # ── Pass 1: unauthenticated probes ──────────────────────────────────
        for path in all_paths:
            full = origin.rstrip("/") + path
            try:
                r = requests.get(full, headers=_HEADERS, timeout=8,
                                 allow_redirects=False, verify=False)
            except Exception as e:
                all_probes.append({"path": path, "error": str(e)})
                continue
            is_state = any(k in path.lower() for k in STATE_CHANGE_KEYWORDS)
            location = r.headers.get("Location", "")
            success = (
                200 <= r.status_code < 300
                or (300 <= r.status_code < 400 and not _is_login_redirect(location))
            )
            rec = {"path": path, "status": r.status_code, "length": len(r.content or b""),
                   "is_state": is_state, "location": location, "_response": r}
            all_probes.append(rec)
            if success:
                unauthed_hits.append(rec)

        # ── Pass 2: authenticated low-priv probes (when cookies/header given) ──
        if cookies or auth_header:
            headers = dict(_HEADERS)
            if auth_header: headers["Authorization"] = auth_header
            for path in all_paths:
                # Skip if already publicly reachable — that's already a finding,
                # no extra info from the authenticated probe.
                if any(h["path"] == path for h in unauthed_hits):
                    continue
                full = origin.rstrip("/") + path
                try:
                    r = requests.get(full, headers=headers, cookies=cookies, timeout=8,
                                     allow_redirects=False, verify=False)
                except Exception:
                    continue
                if 200 <= r.status_code < 300:
                    authed_hits.append({
                        "path": path, "status": r.status_code,
                        "length": len(r.content or b""),
                        "is_state": any(k in path.lower() for k in STATE_CHANGE_KEYWORDS),
                        "_response": r,
                    })

        # ── Severity grading ────────────────────────────────────────────────
        if not unauthed_hits and not authed_hits:
            return SkillResult(
                ok=True,
                summary=f"No admin/sensitive paths reachable across {len(all_paths)} probes.",
                extras={"probes_attempted": len(all_probes)},
            )

        # Best (worst) hit = highest-impact one; sensitive file > state-change > read
        def _impact(h):
            in_sensitive = h["path"] in SENSITIVE_FILE_PATHS
            return (in_sensitive, h.get("is_state", False),
                    1 if 200 <= h["status"] < 300 else 0)
        all_hits = unauthed_hits + authed_hits
        worst = max(all_hits, key=_impact)

        in_sensitive = worst["path"] in SENSITIVE_FILE_PATHS
        if in_sensitive or worst["is_state"]:
            sev = "critical"
        elif unauthed_hits:
            sev = "high"
        else:  # only privesc paths (low-priv reaches admin)
            sev = "high"

        poc = capture_from_response(
            worst["_response"],
            caption=(f"{'Privesc — low-priv user reaches' if worst in authed_hits else 'Public unauth access to'} "
                     f"{worst['path']} ({worst['status']})")
        )

        ev_lines = [f"Origin: {origin}",
                    f"Probed {len(all_paths)} paths; {len(unauthed_hits)} reachable unauth, "
                    f"{len(authed_hits)} reachable as low-priv user."]
        for h in unauthed_hits[:10]:
            ev_lines.append(f"  UNAUTH  {h['path']:30}  HTTP {h['status']}  ({h['length']}B)")
        for h in authed_hits[:10]:
            ev_lines.append(f"  PRIVESC {h['path']:30}  HTTP {h['status']}  ({h['length']}B) (low-priv user)")
        evidence = "\n".join(ev_lines) + "\n\n" + poc.format()

        return SkillResult(
            ok=True,
            summary=f"Access-control finding ({sev}): {len(unauthed_hits)} public + {len(authed_hits)} privesc reachable path(s).",
            evidence=evidence,
            finding={
                "vuln_type":   "access_control",
                "severity":    sev,
                "target":      origin,
                "location":    origin.rstrip("/") + worst["path"],
                "description": (
                    f"Improper access control — {worst['path']!r} is reachable "
                    + ("publicly without authentication" if worst in unauthed_hits
                       else "by an authenticated low-priv user (vertical privesc)")
                    + (". This is a sensitive disclosure path (config/source/backup) — "
                       "credentials or source code exposure likely." if in_sensitive
                       else (". Path keywords suggest a state-changing or admin-class "
                             "action — direct unauthorized control of the application."
                             if worst["is_state"] else
                             ". Manual triage to confirm exact impact."))
                ),
                "evidence":    evidence,
            },
            extras={
                "unauthed_hits": [{k: v for k, v in h.items() if k != "_response"} for h in unauthed_hits],
                "authed_hits":   [{k: v for k, v in h.items() if k != "_response"} for h in authed_hits],
                "paths_probed":  len(all_paths),
            },
        )
