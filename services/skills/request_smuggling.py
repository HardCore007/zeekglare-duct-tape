"""SkillRequestSmuggling — CL.TE / TE.CL detection via timing differential.

We don't actually smuggle a real attack request (which could affect other
users). Instead we send the classic differential-parsing probes and measure
response timing — when the front-end and back-end disagree about how to
parse Content-Length vs Transfer-Encoding, the back-end ends up waiting
for more body bytes that never arrive, producing a timeout-shaped delay.

This is a heuristic, not a confirmation. A delayed CL.TE probe + normal
baseline timing strongly suggests differential parsing. Manual follow-up
with smuggler/h2csmuggler is recommended for confirmation.

Severity:
  - high     : both probes show timing differential vs baseline
  - medium   : only one probe shows differential (could be coincidence)
  - info     : timings consistent with baseline
"""
from __future__ import annotations
import socket, ssl, time
from typing import Optional
from urllib.parse import urlparse

from services.skills.base import Skill, SkillResult, register
from services.skills._payloads import SMUGGLING_PROBE_CL_TE, SMUGGLING_PROBE_TE_CL


def _send_raw(host: str, port: int, use_tls: bool, payload: str, timeout: float = 5.0) -> tuple[float, bytes]:
    """Send raw HTTP and measure how long until the server responds (or times out).

    Returns (elapsed_seconds, response_bytes). On socket timeout, returns the
    elapsed time and whatever was received before the timeout.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    if use_tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = ctx.wrap_socket(sock, server_hostname=host)
    t0 = time.time()
    try:
        sock.connect((host, port))
        sock.sendall(payload.encode("utf-8"))
        chunks = []
        while True:
            try:
                data = sock.recv(4096)
                if not data:
                    break
                chunks.append(data)
                # Stop early if we've got the whole headers + small body
                if b"\r\n\r\n" in b"".join(chunks) and len(b"".join(chunks)) > 256:
                    break
            except socket.timeout:
                break
        return (time.time() - t0, b"".join(chunks))
    finally:
        try:
            sock.close()
        except Exception:
            pass


@register
class SkillRequestSmuggling(Skill):
    name        = "skill_request_smuggling"
    danger      = "active"
    description = (
        "Probe an HTTP/1.1 service for request-smuggling potential (CL.TE / "
        "TE.CL parser disagreement). Sends two malformed probes that confuse "
        "front-end vs back-end parsers and measures timing — a back-end that "
        "waits for additional body bytes (because it honors Transfer-Encoding "
        "where the front-end honored Content-Length) shows up as a timeout-"
        "shaped delay vs baseline. Heuristic only — confirm with smuggler / "
        "h2csmuggler externally."
    )
    guidance    = (
        "Smuggling pays huge when it works (cache poisoning, request hijack, "
        "auth bypass) but is hard to confirm without dedicated tooling. Use "
        "this skill to surface candidates only — once you see timing "
        "differential, hand off to a human with a real smuggler tool."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "Target HTTP(S) URL — only the host:port matters."},
        },
        "required": ["url"],
    }

    @classmethod
    def applicable(cls, state) -> bool:
        return state.asset_counts().get("url", 0) > 0

    @classmethod
    def dedup_key(cls, args) -> Optional[tuple[str, str, str, str]]:
        return (args.get("url", ""), "", "smuggling", "cl_te+te_cl")

    @classmethod
    def run(cls, args, state, agent_id) -> SkillResult:
        url = (args.get("url") or "").strip()
        if not url:
            return SkillResult(ok=False, error="url required")
        if not state.in_scope(url):
            return SkillResult(ok=False, error=f"out of scope: {url}")

        p = urlparse(url)
        host = (p.hostname or "").lower()
        if not host:
            return SkillResult(ok=False, error=f"could not parse hostname from {url}")
        port = p.port or (443 if p.scheme == "https" else 80)
        use_tls = (p.scheme == "https")

        baseline_payload = (
            f"GET / HTTP/1.1\r\nHost: {host}\r\n"
            "User-Agent: Mozilla/5.0 ZeekGlare-Arena-Smuggle\r\n"
            "Connection: close\r\n\r\n"
        )

        try:
            t_baseline, _ = _send_raw(host, port, use_tls, baseline_payload, timeout=5.0)
            t_clte, _     = _send_raw(host, port, use_tls,
                                       SMUGGLING_PROBE_CL_TE.format(host=host),
                                       timeout=6.0)
            t_tecl, _     = _send_raw(host, port, use_tls,
                                       SMUGGLING_PROBE_TE_CL.format(host=host),
                                       timeout=6.0)
        except Exception as e:
            return SkillResult(ok=False, error=f"socket error: {type(e).__name__}: {e}")

        # Differential threshold: probe should exceed baseline by 2x AND > 1.5s
        threshold = max(t_baseline * 2.0, 1.5)
        clte_diff = t_clte > threshold
        tecl_diff = t_tecl > threshold

        result_summary = (
            f"baseline={t_baseline:.2f}s  CL.TE={t_clte:.2f}s  TE.CL={t_tecl:.2f}s"
        )

        if clte_diff and tecl_diff:
            severity = "high"
            descr = (
                "Both CL.TE and TE.CL probes timed out vs baseline, indicating "
                "front-end/back-end parsers disagree on how to handle "
                "Content-Length + Transfer-Encoding. Strong smuggling candidate."
            )
        elif clte_diff or tecl_diff:
            severity = "medium"
            descr = (
                f"One probe ({'CL.TE' if clte_diff else 'TE.CL'}) showed timing "
                "differential vs baseline. Possible smuggling — could be "
                "coincidental network noise. Re-run or confirm with a dedicated tool."
            )
        else:
            return SkillResult(
                ok=True,
                summary=f"No smuggling timing differential ({result_summary}).",
                extras={"baseline_s": t_baseline, "cl_te_s": t_clte, "te_cl_s": t_tecl},
            )

        evidence = (
            f"Target: {host}:{port}  TLS: {use_tls}\n"
            f"Baseline GET /:           {t_baseline:.2f}s\n"
            f"CL.TE differential probe: {t_clte:.2f}s  {'⚠' if clte_diff else '✓'}\n"
            f"TE.CL differential probe: {t_tecl:.2f}s  {'⚠' if tecl_diff else '✓'}\n"
            f"Threshold (max(baseline*2, 1.5)): {threshold:.2f}s"
        )
        return SkillResult(
            ok=True,
            summary=f"HTTP request-smuggling candidate ({severity}): {result_summary}",
            evidence=evidence,
            finding={
                "vuln_type":   "http_smuggling_candidate",
                "severity":    severity,
                "target":      f"{host}:{port}",
                "location":    f"{p.scheme}://{host}:{port}/",
                "description": descr + " Manual confirmation with smuggler / h2csmuggler recommended.",
                "evidence":    evidence,
            },
            extras={"baseline_s": t_baseline, "cl_te_s": t_clte, "te_cl_s": t_tecl,
                    "clte_diff": clte_diff, "tecl_diff": tecl_diff},
        )
