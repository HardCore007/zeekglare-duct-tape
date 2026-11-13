"""PoC capture helpers — turn a `requests` request/response into a structured
evidence string suitable for the `evidence` field of a finding.

The point: when an agent submits a finding, we want the evidence to be
reproducible by a human triager copy-pasting into Burp/curl. That means:

  - the EXACT HTTP request that demonstrated the bug (method, path, headers, body)
  - a slice of the response (status, headers, first ~600 bytes of body)
  - timing + a short caption of what made this the "winning" probe

Skills construct a `PocCapture` from the `requests.Response` object they
already have, attach a caption, and stuff `capture.format()` into
`SkillResult.evidence`.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from urllib.parse import urlparse


_HEADER_REDACT = {"authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token"}


def _redact(name: str, value: str) -> str:
    if name.lower() in _HEADER_REDACT:
        v = (value or "")
        if len(v) <= 8:
            return "***"
        return v[:4] + "…" + v[-4:]
    return value


def _request_line_from_url(method: str, url: str) -> str:
    p = urlparse(url)
    path = p.path or "/"
    if p.query:
        path += "?" + p.query
    return f"{method.upper()} {path} HTTP/1.1"


@dataclass
class PocCapture:
    method:        str = "GET"
    url:           str = ""
    request_headers: dict = field(default_factory=dict)
    request_body:  str = ""
    response_status: int = 0
    response_headers: dict = field(default_factory=dict)
    response_body: str = ""
    elapsed_ms:    float = 0.0
    caption:       str = ""   # one-line description of why this is the PoC

    def format(self, max_body: int = 600) -> str:
        """Render a copy-pasteable evidence block."""
        lines = []
        if self.caption:
            lines.append(f"[{self.caption}]")
        # Request
        host = (urlparse(self.url).netloc or "")
        lines.append("--- REQUEST ---")
        lines.append(_request_line_from_url(self.method, self.url))
        if host:
            lines.append(f"Host: {host}")
        for k, v in (self.request_headers or {}).items():
            if k.lower() == "host":
                continue
            lines.append(f"{k}: {_redact(k, str(v))}")
        if self.request_body:
            body = self.request_body
            if len(body) > max_body:
                body = body[:max_body] + f"\n... [+{len(body) - max_body} bytes truncated]"
            lines.append("")
            lines.append(body)
        # Response
        lines.append("--- RESPONSE ---")
        lines.append(f"HTTP/1.1 {self.response_status}"
                     + (f"   ({self.elapsed_ms:.0f} ms)" if self.elapsed_ms else ""))
        for k, v in (self.response_headers or {}).items():
            lines.append(f"{k}: {_redact(k, str(v))}")
        if self.response_body:
            body = self.response_body
            if len(body) > max_body:
                body = body[:max_body] + f"\n... [+{len(body) - max_body} bytes truncated]"
            lines.append("")
            lines.append(body)
        return "\n".join(lines)


def capture_from_response(r, *, request_body: str = "", caption: str = "") -> PocCapture:
    """Build a PocCapture from a `requests` Response object."""
    elapsed_ms = (getattr(r, "elapsed", None).total_seconds() * 1000) if getattr(r, "elapsed", None) else 0.0
    return PocCapture(
        method           = (r.request.method if r.request else "GET"),
        url              = (r.request.url    if r.request else ""),
        request_headers  = dict(r.request.headers) if (r.request and r.request.headers) else {},
        request_body     = request_body or (r.request.body if r.request and r.request.body else ""),
        response_status  = r.status_code,
        response_headers = dict(r.headers or {}),
        response_body    = (r.text or "")[:2000],
        elapsed_ms       = elapsed_ms,
        caption          = caption,
    )
