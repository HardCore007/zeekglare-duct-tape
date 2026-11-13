from core.auth_utils import module_required
"""Burp Suite proxy integration — send domain mapper results to Burp for manual testing."""
import json, time
import urllib3
from flask import Blueprint, request, Response, stream_with_context

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

burp_bp = Blueprint("burp", __name__)


def _burp_get(api_url: str, api_key: str, path: str) -> dict:
    """GET request to Burp Suite REST API."""
    import requests as r
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = api_key
    resp = r.get(
        f"{api_url.rstrip('/')}{path}",
        headers=headers,
        timeout=10,
        verify=False,
    )
    resp.raise_for_status()
    return resp.json()


def _burp_put(api_url: str, api_key: str, path: str, payload: dict) -> dict:
    """PUT request to Burp Suite REST API."""
    import requests as r
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = api_key
    resp = r.put(
        f"{api_url.rstrip('/')}{path}",
        json=payload,
        headers=headers,
        timeout=10,
        verify=False,
    )
    resp.raise_for_status()
    return resp.json() if resp.text else {}


def _get_current_scope(api_url: str, api_key: str) -> dict:
    """Fetch existing scope from Burp Suite REST API."""
    data = _burp_get(api_url, api_key, "/v0.1/target/scope")
    return data


def _build_scope_entry(host: str, scheme: str = None) -> dict:
    """Build a Burp scope entry for a host."""
    return {
        "enabled": True,
        "scheme": scheme or "https",
        "host": host,
        "port": "",
        "file": "/",
    }


def _host_in_scope(host: str, include_list: list) -> bool:
    """Check if a host is already covered by the scope."""
    for entry in include_list:
        entry_host = entry.get("host", "")
        if entry_host == host:
            return True
        # wildcard — .*\.example\.com covers sub.example.com
        if entry_host.startswith(".*\\."):
            base = entry_host[4:]
            if host == base or host.endswith("." + base):
                return True
    return False


def _sse(obj: dict) -> str:
    return f"data: {json.dumps(obj)}\n\n"


@burp_bp.route("/api/burp/push", methods=["POST"])
@module_required("burp")
def burp_push():
    import requests as r

    body      = request.get_json(silent=True) or {}
    hosts     = body.get("hosts") or []
    proxy_url = (body.get("proxy_url") or "http://127.0.0.1:8080").rstrip("/")
    api_url   = (body.get("api_url") or "http://127.0.0.1:1337").rstrip("/")
    api_key   = (body.get("api_key") or "").strip()
    mode      = body.get("mode", "both")   # proxy | scope | both

    if not hosts:
        return Response(json.dumps({"error": "No hosts provided"}),
                        status=400, mimetype="application/json")
    if mode in ("scope", "both") and not api_url:
        return Response(json.dumps({"error": "Burp REST API URL required for scope mode."}),
                        status=400, mimetype="application/json")

    def generate():
        total = len(hosts)

        # ── Phase 1: route traffic through Burp proxy ────────────────────────
        if mode in ("proxy", "both"):
            yield _sse({"type": "phase", "text": f"Routing {total} URL(s) through Burp proxy…"})
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
                                "error": "Proxy unreachable — is Burp Suite running?",
                                "done": done, "total": total})
                except Exception as e:
                    done += 1
                    yield _sse({"type": "proxy_err", "host": entry["host"],
                                "error": str(e), "done": done, "total": total})
                time.sleep(0.04)

        # ── Phase 2: update Burp Target Scope via REST API ───────────────────
        if mode in ("scope", "both"):
            yield _sse({"type": "phase", "text": "Fetching current Burp target scope…"})
            try:
                current_scope = _get_current_scope(api_url, api_key)
                existing_include = current_scope.get("include") or []
            except Exception as e:
                yield _sse({"type": "scope_err",
                            "error": f"Could not read scope: {e}. Check Burp REST API URL/key."})
                existing_include = []

            new_entries = []
            for entry in hosts:
                host = entry["host"]
                if not _host_in_scope(host, existing_include):
                    # Add both https and http entries
                    new_entries.append(_build_scope_entry(host, "https"))
                    new_entries.append(_build_scope_entry(host, "http"))

            merged_include = existing_include + new_entries
            added_hosts = len(new_entries) // 2  # each host = 2 entries (http+https)

            yield _sse({"type": "scope_info",
                        "text": f"Adding {added_hosts} host(s) to Burp scope ({len(merged_include)} rules total)…"})
            try:
                _burp_put(api_url, api_key, "/v0.1/target/scope", {
                    "include": merged_include,
                    "exclude": current_scope.get("exclude") or [],
                })
                yield _sse({"type": "scope_ok",
                            "added": added_hosts, "total": len(merged_include)})
            except Exception as e:
                yield _sse({"type": "scope_err", "error": str(e)})

        yield _sse({"type": "done", "total": total})

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
