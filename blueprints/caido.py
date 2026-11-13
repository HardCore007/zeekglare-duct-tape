from core.auth_utils import module_required
"""Caido web proxy integration — send domain mapper results to Caido for manual testing."""
import json, time
import urllib3
from flask import Blueprint, request, Response, stream_with_context

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

caido_bp = Blueprint("caido", __name__)


def _gql(api_url: str, api_key: str, query: str, variables: dict = None) -> dict:
    """Execute a GraphQL request against Caido's API."""
    import requests as r
    payload = {"query": query}
    if variables:
        payload["variables"] = variables
    resp = r.post(
        f"{api_url.rstrip('/')}/graphql",
        json=payload,
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        timeout=12,
        verify=False,
    )
    resp.raise_for_status()
    return resp.json()


def _get_current_scope(api_url: str, api_key: str) -> list:
    """Fetch existing scope allowlist from Caido."""
    data = _gql(api_url, api_key, "query { scope { allowlist denylist } }")
    scope = (data.get("data") or {}).get("scope") or {}
    return list(scope.get("allowlist") or [])


def _update_scope(api_url: str, api_key: str, allowlist: list) -> dict:
    mutation = """
    mutation UpdateScope($input: UpdateScopeInput!) {
      updateScope(input: $input) {
        scope { allowlist denylist }
        error { ... on OtherError { code } }
      }
    }
    """
    return _gql(api_url, api_key, mutation, {"input": {"allowlist": allowlist}})


def _host_patterns(host: str) -> list:
    """Return [exact, wildcard-base] patterns for a host."""
    parts = host.split(".")
    patterns = [host]
    if len(parts) > 2:
        wildcard = "*." + ".".join(parts[-2:])
        if wildcard not in patterns:
            patterns.append(wildcard)
    return patterns


def _sse(obj: dict) -> str:
    return f"data: {json.dumps(obj)}\n\n"


@caido_bp.route("/api/caido/push", methods=["POST"])
@module_required("caido")
def caido_push():
    import requests as r

    body      = request.get_json(silent=True) or {}
    hosts     = body.get("hosts") or []
    proxy_url = (body.get("proxy_url") or "http://127.0.0.1:8080").rstrip("/")
    api_key   = (body.get("api_key") or "").strip()
    mode      = body.get("mode", "both")   # proxy | scope | both

    if not hosts:
        return Response(json.dumps({"error": "No hosts provided"}),
                        status=400, mimetype="application/json")
    if mode in ("scope", "both") and not api_key:
        return Response(json.dumps({"error": "Caido API key required for scope mode. Add it in Settings → Integrations."}),
                        status=400, mimetype="application/json")

    def generate():
        total = len(hosts)

        # ── Phase 1: route traffic through Caido proxy ──────────────────────
        if mode in ("proxy", "both"):
            yield _sse({"type": "phase", "text": f"Routing {total} URL(s) through Caido proxy…"})
            proxies = {"http": proxy_url, "https": proxy_url}
            done = 0
            for entry in hosts:
                url = entry.get("url") or f"http://{entry['host']}"
                try:
                    r.head(url, proxies=proxies, timeout=8, verify=False, allow_redirects=True)
                    done += 1
                    yield _sse({"type": "proxy_ok", "host": entry["host"],
                                "done": done, "total": total})
                except r.exceptions.ProxyError:
                    done += 1
                    yield _sse({"type": "proxy_err", "host": entry["host"],
                                "error": "Proxy unreachable — is Caido running?",
                                "done": done, "total": total})
                except Exception as e:
                    done += 1
                    yield _sse({"type": "proxy_err", "host": entry["host"],
                                "error": str(e), "done": done, "total": total})
                time.sleep(0.04)

        # ── Phase 2: update Caido scope via GraphQL ──────────────────────────
        if mode in ("scope", "both"):
            yield _sse({"type": "phase", "text": "Fetching current Caido scope…"})
            try:
                existing = _get_current_scope(proxy_url, api_key)
            except Exception as e:
                yield _sse({"type": "scope_err",
                            "error": f"Could not read scope: {e}. Check your API key."})
                existing = []

            new_patterns = []
            for entry in hosts:
                for pat in _host_patterns(entry["host"]):
                    if pat not in existing and pat not in new_patterns:
                        new_patterns.append(pat)

            merged = existing + new_patterns
            yield _sse({"type": "scope_info",
                        "text": f"Adding {len(new_patterns)} pattern(s) to scope ({len(merged)} total)…"})
            try:
                result = _update_scope(proxy_url, api_key, merged)
                err = ((result.get("data") or {}).get("updateScope") or {}).get("error")
                if err:
                    yield _sse({"type": "scope_err", "error": f"Caido error: {err}"})
                else:
                    yield _sse({"type": "scope_ok",
                                "added": len(new_patterns), "total": len(merged)})
            except Exception as e:
                yield _sse({"type": "scope_err", "error": str(e)})

        yield _sse({"type": "done", "total": total})

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
