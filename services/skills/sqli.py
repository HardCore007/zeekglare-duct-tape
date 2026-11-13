"""SkillSqli — error-pattern pre-check + optional sqlmap confirmation.

Two-stage:
  1. Lightweight error probe — append a single quote to the param value and
     look for known SQL error markers in the response. Cheap, ~1 request.
  2. If marker hit OR caller forces, optionally run sqlmap with strict
     non-destructive flags (--batch --random-agent --risk=1 --level=1
     --threads=2 --timeout=20 --retries=1 --technique=BEUST --no-cast
     --output-dir=<tmp>) and parse the report for confirmed injections.

Marked `danger="exploit"` because sqlmap actively probes the database with
many requests; it's gated behind the orchestrator's `allow_exploit` flag.
The error-probe stage runs even when sqlmap is disabled.

Severity:
  - critical : sqlmap confirms injection
  - high     : SQL error marker reflected (likely SQLi but unconfirmed)
  - info     : nothing found
"""
from __future__ import annotations
import json, os, re, shutil, subprocess, tempfile
from typing import Optional
from urllib.parse import urlparse, urlencode, urlunparse, parse_qsl

import requests

from services.skills.base import Skill, SkillResult, register
from services.skills._payloads import SQLI_ERROR_MARKERS


_HEADERS = {"User-Agent": "Mozilla/5.0 ZeekGlare-Arena-SQLi"}


def _swap(url: str, param: str, value: str) -> str:
    p = urlparse(url)
    qs = parse_qsl(p.query, keep_blank_values=True)
    new_qs = [(k, value if k == param else v) for k, v in qs]
    return urlunparse((p.scheme, p.netloc, p.path, p.params, urlencode(new_qs), p.fragment))


def _check_error_markers(body: str) -> list[str]:
    body_lc = (body or "").lower()
    return [m for m in SQLI_ERROR_MARKERS if m in body_lc]


def _run_sqlmap(url: str, param: str, cookies: dict | None) -> dict:
    """Run sqlmap with strict non-destructive defaults. Returns parsed result."""
    if not shutil.which("sqlmap"):
        return {"available": False, "error": "sqlmap not on PATH"}
    out_dir = tempfile.mkdtemp(prefix="zg-sqlmap-")
    cmd = [
        "sqlmap", "-u", url, "-p", param,
        "--batch", "--random-agent",
        "--risk=1", "--level=1",
        "--threads=2", "--timeout=20", "--retries=1",
        "--technique=BEUST",     # boolean/error/union/stacked/time
        "--no-cast", "--smart",
        "--output-dir", out_dir,
        "--disable-coloring",
    ]
    if cookies:
        cmd += ["--cookie", "; ".join(f"{k}={v}" for k, v in cookies.items())]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        return {"available": True, "confirmed": False, "error": "sqlmap timed out (120s cap)"}
    out = (proc.stdout or "") + "\n" + (proc.stderr or "")

    confirmed = bool(re.search(r"is vulnerable|sqlmap identified the following injection", out, re.I))
    techniques = re.findall(r"Type:\s+([A-Za-z\- ]+)", out)
    dbms = ""
    m = re.search(r"back-end DBMS:\s+(.+)", out)
    if m:
        dbms = m.group(1).strip().splitlines()[0]
    return {
        "available":  True,
        "confirmed":  confirmed,
        "techniques": list(dict.fromkeys(t.strip() for t in techniques)),
        "dbms":       dbms,
        "stdout_tail": out[-1500:],
    }


@register
class SkillSqli(Skill):
    name        = "skill_sqli"
    danger      = "exploit"   # Off unless allow_exploit is set on the orchestrator
    description = (
        "Probe a URL+param for SQL injection. Two-stage: (1) lightweight error-marker "
        "probe by appending a single quote — checks response for known SQL error patterns "
        "(MySQL/Postgres/SQLite/MSSQL/Oracle/DB2). (2) If errors appear OR force_sqlmap=true, "
        "runs sqlmap with strict non-destructive flags (risk=1 level=1, 2 threads, 120s "
        "cap, no destructive techniques). Returns confirmed injection point + DBMS + "
        "techniques on success. Only available when 'Allow active exploitation' is enabled "
        "in the arena."
    )
    guidance    = (
        "SQLi triage: error-based shows up in 1 request, blind takes longer. If the "
        "error probe doesn't match a marker, sqlmap is unlikely to find anything either — "
        "skip the call to save budget. When confirmed, sqlmap reports DBMS + techniques; "
        "include both in the finding evidence."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "url":   {"type": "string", "description": "URL with the param to probe."},
            "param": {"type": "string", "description": "Param name to inject into."},
            "cookies": {"type": "object", "description": "Optional auth cookies."},
            "force_sqlmap": {"type": "boolean", "default": False,
                             "description": "Run sqlmap even if the error-probe didn't match (slower)."},
        },
        "required": ["url", "param"],
    }

    @classmethod
    def applicable(cls, state) -> bool:
        c = state.asset_counts()
        return c.get("url", 0) > 0 or c.get("param", 0) > 0

    @classmethod
    def dedup_key(cls, args) -> Optional[tuple[str, str, str, str]]:
        return (args.get("url", ""), args.get("param", ""), "sqli", "error+sqlmap")

    @classmethod
    def run(cls, args, state, agent_id) -> SkillResult:
        url   = (args.get("url") or "").strip()
        param = (args.get("param") or "").strip()
        cookies = args.get("cookies") or None
        force_sqlmap = bool(args.get("force_sqlmap"))
        if not url or not param:
            return SkillResult(ok=False, error="url and param required")
        if not state.in_scope(url):
            return SkillResult(ok=False, error=f"out of scope: {url}")

        # ── Stage 1: error-pattern probe ─────────────────────────────────────
        probe_url = _swap(url, param, "'\"")
        try:
            r = requests.get(probe_url, headers=_HEADERS, cookies=cookies,
                             timeout=10, allow_redirects=False, verify=False)
        except Exception as e:
            return SkillResult(ok=False, error=f"error probe failed: {type(e).__name__}: {e}")
        markers = _check_error_markers(r.text or "")

        # ── Stage 2: sqlmap (gated by error hit OR explicit force) ──────────
        run_sqlmap = bool(markers) or force_sqlmap
        sqlmap_result = _run_sqlmap(url, param, cookies) if run_sqlmap else {"available": True, "skipped": True}

        if sqlmap_result.get("confirmed"):
            ev = (
                f"URL: {url}  Param: {param}\n"
                f"Stage 1 (error probe): markers matched: {markers or 'none — sqlmap forced'}\n"
                f"Stage 2 (sqlmap): CONFIRMED\n"
                f"  DBMS: {sqlmap_result.get('dbms', 'unknown')}\n"
                f"  Techniques: {', '.join(sqlmap_result.get('techniques') or [])}\n"
                f"--- sqlmap output (last 1500 chars) ---\n{sqlmap_result.get('stdout_tail', '')}"
            )
            return SkillResult(
                ok=True,
                summary=f"SQL injection CONFIRMED via sqlmap ({sqlmap_result.get('dbms', '?')}).",
                evidence=ev,
                finding={
                    "vuln_type":   "sqli",
                    "severity":    "critical",
                    "target":      url,
                    "location":    f"{url} param={param}",
                    "description": (
                        f"SQL injection confirmed via sqlmap on param '{param}'. "
                        f"DBMS: {sqlmap_result.get('dbms', 'unknown')}. "
                        f"Techniques: {', '.join(sqlmap_result.get('techniques') or ['?'])}. "
                        "Direct database access available — high impact (data exfiltration, auth bypass)."
                    ),
                    "evidence":    ev,
                },
                extras={"sqlmap": sqlmap_result, "error_markers": markers},
            )

        if markers:
            ev = (
                f"URL: {url}  Param: {param}\n"
                f"Single-quote probe matched {len(markers)} known SQL error marker(s):\n"
                + "\n".join(f"  - {m}" for m in markers)
                + (f"\nsqlmap follow-up: {sqlmap_result}" if run_sqlmap else "")
            )
            return SkillResult(
                ok=True,
                summary=f"SQL error markers matched ({len(markers)}); sqlmap unconfirmed.",
                evidence=ev,
                finding={
                    "vuln_type":   "sqli_error",
                    "severity":    "high",
                    "target":      url,
                    "location":    f"{url} param={param}",
                    "description": (
                        f"Database error messages leak from param '{param}' when special "
                        "characters are injected. Confirmed SQLi is likely but sqlmap hasn't "
                        "verified yet. Manual follow-up recommended."
                    ),
                    "evidence":    ev,
                },
                extras={"error_markers": markers, "sqlmap": sqlmap_result},
            )

        return SkillResult(
            ok=True,
            summary="No SQL injection signals (error probe clean; sqlmap skipped).",
            extras={"error_probe_status": r.status_code},
        )
