"""SkillRaceCondition — burst N concurrent identical requests at a state-
changing endpoint and look for "should-have-failed-twice" outcomes.

The classic case is a one-time-use coupon, a referral-bonus, or a balance-
deduction operation. If the application checks-then-acts non-atomically,
firing N requests in parallel can yield M > 1 successes where exactly 1
should have happened.

We can't know application semantics, so this skill reports the timing
distribution and the response shape distribution; the AGENT decides
whether the result indicates a race condition. We flag a finding only
when distinct successful response shapes appear AND counts of "success-
shaped" responses exceed 1.

Severity:
  - high     : > 1 success-shaped response when only 1 should be possible
  - medium   : multiple identical success responses (unclear semantics —
               may be benign if endpoint is idempotent)
  - info     : all responses identical to baseline single-request
"""
from __future__ import annotations
import hashlib, time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

import requests

from services.skills.base import Skill, SkillResult, register
from services.skills._payloads import RACE_DEFAULT_BURST_SIZE, RACE_DEFAULT_TIMEOUT
from services.skills._poc import capture_from_response


_HEADERS = {"User-Agent": "Mozilla/5.0 ZeekGlare-Arena-Race"}


def _hash(s: str) -> str:
    return hashlib.sha1((s or "").encode("utf-8", "replace")).hexdigest()[:12]


@register
class SkillRaceCondition(Skill):
    name        = "skill_race_condition"
    danger      = "active"
    description = (
        "Detect TOCTOU race conditions on a state-changing endpoint. Fires N "
        "concurrent identical requests (default 25) and groups responses by "
        "status + body hash. If the endpoint should logically allow only 1 "
        "success (one-time coupon, referral bonus, account creation) but the "
        "burst yields multiple success-shaped responses, that's the bug. "
        "Use POST/PUT/DELETE on actions you suspect are non-atomic."
    )
    guidance    = (
        "Race conditions are highest-impact on financial / one-time-use "
        "endpoints: redeem coupon, apply referral, transfer funds, create "
        "account with unique email. The pattern: check (does coupon exist?) "
        "then act (mark used). If 25 requests hit between check and act, all "
        "25 see 'unused' and act in parallel. Look for >1 same-shape "
        "response in the burst output."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "url":      {"type": "string", "description": "Endpoint URL."},
            "method":   {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE", "PATCH"], "default": "POST"},
            "headers":  {"type": "object", "description": "Optional auth headers (Authorization, Cookie)."},
            "json_body":{"type": "object", "description": "Optional JSON body for the request."},
            "form_data":{"type": "object", "description": "Optional form-urlencoded body."},
            "burst":    {"type": "integer", "default": RACE_DEFAULT_BURST_SIZE,
                          "description": f"Concurrent requests to fire (default {RACE_DEFAULT_BURST_SIZE}, max 50)."},
        },
        "required": ["url"],
    }

    @classmethod
    def applicable(cls, state) -> bool:
        return state.asset_counts().get("url", 0) > 0

    @classmethod
    def dedup_key(cls, args) -> Optional[tuple[str, str, str, str]]:
        return (args.get("url", ""), args.get("method", "POST"), "race", "burst")

    @classmethod
    def run(cls, args, state, agent_id) -> SkillResult:
        url    = (args.get("url") or "").strip()
        method = (args.get("method") or "POST").upper()
        headers = {**_HEADERS, **(args.get("headers") or {})}
        json_body = args.get("json_body") or None
        form_data = args.get("form_data") or None
        burst  = max(2, min(int(args.get("burst") or RACE_DEFAULT_BURST_SIZE), 50))

        if not url:
            return SkillResult(ok=False, error="url required")
        if not state.in_scope(url):
            return SkillResult(ok=False, error=f"out of scope: {url}")

        # Single baseline first.
        try:
            r0 = requests.request(method, url, headers=headers,
                                   json=json_body, data=form_data,
                                   timeout=RACE_DEFAULT_TIMEOUT, verify=False,
                                   allow_redirects=False)
        except Exception as e:
            return SkillResult(ok=False, error=f"baseline failed: {type(e).__name__}: {e}")
        baseline_hash = _hash(r0.text or "")
        baseline_status = r0.status_code

        # Burst.
        def _one():
            try:
                rr = requests.request(method, url, headers=headers,
                                       json=json_body, data=form_data,
                                       timeout=RACE_DEFAULT_TIMEOUT, verify=False,
                                       allow_redirects=False)
                return {
                    "status":   rr.status_code,
                    "length":   len(rr.content or b""),
                    "body_hash": _hash(rr.text or ""),
                    "_response": rr,
                }
            except Exception as e:
                return {"error": f"{type(e).__name__}: {e}"}

        t0 = time.time()
        results = []
        with ThreadPoolExecutor(max_workers=burst) as ex:
            futs = [ex.submit(_one) for _ in range(burst)]
            for f in as_completed(futs):
                results.append(f.result())
        elapsed = time.time() - t0

        ok_results = [r for r in results if "error" not in r]
        # Group by (status, body_hash)
        shapes: dict[tuple, list] = {}
        for r in ok_results:
            shapes.setdefault((r["status"], r["body_hash"]), []).append(r)

        # Count success-shaped responses (2xx).
        success_shapes = {k: v for k, v in shapes.items() if 200 <= k[0] < 300}
        success_total  = sum(len(v) for v in success_shapes.values())

        summary = (
            f"Burst {burst} reqs in {elapsed:.2f}s — {len(ok_results)} responses, "
            f"{len(shapes)} distinct shapes, {success_total} success-shaped"
        )
        # Heuristic flag: distinct success shapes > 1 OR success_total > 1
        flagged = success_total > 1 and (
            len(success_shapes) > 1 or
            # OR all-identical successes that DIFFER from the baseline (suggests
            # baseline was rejected and burst weren't — the race won).
            (len(success_shapes) == 1 and list(success_shapes.keys())[0] != (baseline_status, baseline_hash))
        )

        if not flagged:
            return SkillResult(
                ok=True,
                summary=summary + " — no race condition signal.",
                extras={"baseline": {"status": baseline_status, "hash": baseline_hash},
                        "shape_counts": {f"{k[0]}/{k[1]}": len(v) for k, v in shapes.items()}},
            )

        # Build evidence with the most-common success-shape representative.
        rep_key, rep_list = max(success_shapes.items(), key=lambda x: len(x[1]))
        rep = rep_list[0]
        poc = capture_from_response(
            rep["_response"],
            caption=(f"Race condition signal — burst of {burst} produced {success_total} "
                     f"success-shaped responses (baseline {baseline_status}/{baseline_hash[:6]})")
        )
        severity = "high" if (len(success_shapes) > 1 or success_total > 2) else "medium"
        return SkillResult(
            ok=True,
            summary=summary + f" — flagged ({severity}).",
            evidence=poc.format(),
            finding={
                "vuln_type":   "race_condition",
                "severity":    severity,
                "target":      url,
                "location":    f"{method} {url}",
                "description": (
                    f"TOCTOU race condition signal — {burst} concurrent {method} requests "
                    f"produced {success_total} success-shaped responses (across {len(success_shapes)} "
                    "shapes). For endpoints that should logically allow only one success per "
                    "logical action (one-time coupon, referral, balance change), this is the bug. "
                    "Verify by checking application state (was the coupon redeemed N times?)."
                ),
                "evidence":    poc.format(),
            },
            extras={
                "baseline":      {"status": baseline_status, "hash": baseline_hash},
                "shapes":        {f"{k[0]}/{k[1]}": len(v) for k, v in shapes.items()},
                "success_shapes": {f"{k[0]}/{k[1]}": len(v) for k, v in success_shapes.items()},
                "elapsed_s":     round(elapsed, 2),
            },
        )
