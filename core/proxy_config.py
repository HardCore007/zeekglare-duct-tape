"""Global SOCKS5 (or HTTP) proxy configuration.

When the admin enables a proxy in Settings → Proxy, three things happen:

  1. `install_requests_patch()` wraps `requests.Session.request` so every
     `requests.get/post/...` call anywhere in the codebase inherits the proxy.
  2. `apply_env()` sets HTTP_PROXY/HTTPS_PROXY/ALL_PROXY/NO_PROXY in the
     parent process environment — modern CLI tools (nuclei, httpx, ffuf,
     subfinder, gau, waybackurls, curl, etc.) read these and honor them.
  3. The frontend surfaces a "Proxy Active" badge + toast on every scan.

Config is stored at data/proxy_config.json. Password is stored in plain text
on disk — the file should be treated as sensitive (0600 on save).
"""
from __future__ import annotations
import json, os, threading
from pathlib import Path
from urllib.parse import quote

_CFG_PATH = Path("data/proxy_config.json")
_LOCK = threading.Lock()
_CACHE: dict | None = None

_DEFAULT: dict = {
    "enabled":  False,
    "type":     "socks5",   # "socks5" | "socks5h" | "http" | "https"
    "host":     "",
    "port":     0,
    "username": "",
    "password": "",
    "remote_dns": True,     # socks5h — resolve DNS through the proxy
}


def _load_raw() -> dict:
    try:
        if _CFG_PATH.exists():
            with _CFG_PATH.open("r", encoding="utf-8") as f:
                data = json.load(f)
            cfg = dict(_DEFAULT)
            cfg.update({k: data.get(k, v) for k, v in _DEFAULT.items()})
            return cfg
    except Exception:
        pass
    return dict(_DEFAULT)


def get_config() -> dict:
    global _CACHE
    with _LOCK:
        if _CACHE is None:
            _CACHE = _load_raw()
        return dict(_CACHE)


def save_config(new_cfg: dict) -> dict:
    """Merge + persist + re-apply env. Returns the stored config."""
    global _CACHE
    with _LOCK:
        current = _CACHE if _CACHE is not None else _load_raw()
        merged = dict(current)
        for k in _DEFAULT:
            if k in new_cfg:
                merged[k] = new_cfg[k]
        # Coerce types
        merged["enabled"]    = bool(merged.get("enabled"))
        merged["remote_dns"] = bool(merged.get("remote_dns", True))
        merged["type"]       = (merged.get("type") or "socks5").lower()
        merged["host"]       = (merged.get("host") or "").strip()
        merged["username"]   = (merged.get("username") or "").strip()
        merged["password"]   = merged.get("password") or ""
        try:
            merged["port"] = int(merged.get("port") or 0)
        except Exception:
            merged["port"] = 0

        _CFG_PATH.parent.mkdir(parents=True, exist_ok=True)
        tmp = _CFG_PATH.with_suffix(".json.tmp")
        with tmp.open("w", encoding="utf-8") as f:
            json.dump(merged, f, indent=2)
        tmp.replace(_CFG_PATH)
        try:
            os.chmod(_CFG_PATH, 0o600)
        except Exception:
            pass
        _CACHE = merged

    apply_env()
    return dict(merged)


def is_enabled() -> bool:
    c = get_config()
    return bool(c.get("enabled") and c.get("host") and c.get("port"))


def proxy_url() -> str | None:
    """Return a full proxy URL (with userinfo) or None when disabled/incomplete."""
    c = get_config()
    if not (c.get("enabled") and c.get("host") and c.get("port")):
        return None
    scheme = c.get("type") or "socks5"
    if scheme == "socks5" and c.get("remote_dns", True):
        scheme = "socks5h"
    host = c["host"]
    port = c["port"]
    user = c.get("username") or ""
    pw   = c.get("password") or ""
    auth = ""
    if user:
        auth = f"{quote(user, safe='')}:{quote(pw, safe='')}@" if pw else f"{quote(user, safe='')}@"
    return f"{scheme}://{auth}{host}:{port}"


def get_requests_proxies() -> dict | None:
    url = proxy_url()
    if not url:
        return None
    return {"http": url, "https": url}


def public_status() -> dict:
    """Non-secret status for the frontend badge — safe for all authed users."""
    c = get_config()
    enabled = bool(c.get("enabled") and c.get("host") and c.get("port"))
    return {
        "enabled": enabled,
        "type":    c.get("type", "socks5"),
        "host":    c.get("host", "") if enabled else "",
        "port":    c.get("port", 0) if enabled else 0,
        "label":   f"{c.get('type','socks5')}://{c.get('host','')}:{c.get('port',0)}" if enabled else "",
    }


def admin_view() -> dict:
    """Admin view — includes username; password is masked."""
    c = get_config()
    return {
        "enabled":    c.get("enabled", False),
        "type":       c.get("type", "socks5"),
        "host":       c.get("host", ""),
        "port":       c.get("port", 0),
        "username":   c.get("username", ""),
        "password":   "••••••" if c.get("password") else "",
        "has_password": bool(c.get("password")),
        "remote_dns": c.get("remote_dns", True),
    }


# ── Runtime injection ────────────────────────────────────────────────────────

_PATCHED = False


def install_requests_patch() -> None:
    """Wrap requests.Session.request so every call inherits the proxy when on.
    Idempotent — safe to call once at app startup."""
    global _PATCHED
    if _PATCHED:
        return
    try:
        import requests as _r
    except Exception:
        return

    _orig = _r.Session.request

    def _patched(self, method, url, **kwargs):
        proxies = get_requests_proxies()
        if proxies and not kwargs.get("proxies"):
            kwargs["proxies"] = proxies
        return _orig(self, method, url, **kwargs)

    _r.Session.request = _patched
    _PATCHED = True
    # Apply env on first install so subprocess children inherit if already on.
    apply_env()


_ENV_KEYS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
             "http_proxy", "https_proxy", "all_proxy")


def apply_env() -> None:
    """Reflect proxy state into os.environ so subprocess tools inherit it."""
    url = proxy_url()
    if url:
        for k in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
                  "http_proxy", "https_proxy", "all_proxy"):
            os.environ[k] = url
        os.environ.setdefault("NO_PROXY", "localhost,127.0.0.1,::1")
        os.environ.setdefault("no_proxy", "localhost,127.0.0.1,::1")
    else:
        for k in _ENV_KEYS:
            os.environ.pop(k, None)
    _write_proxychains_conf()


# ── Subprocess wrapping via proxychains4 ──────────────────────────────────────
# Go tools' support for SOCKS5 via HTTP_PROXY env is inconsistent (Go stdlib
# doesn't parse socks5:// URLs; many tools silently bypass the proxy). The
# universal fix is proxychains4-ng — it LD_PRELOADs a shim that intercepts
# TCP connect() calls at the libc layer and redirects them through SOCKS,
# regardless of the tool's own HTTP client implementation.

_PROXYCHAINS_CONF = "/tmp/zeekglare-proxychains.conf"


def _write_proxychains_conf() -> None:
    """Regenerate the proxychains config whenever proxy settings change.
    Idempotent: deletes the file when proxy is disabled so stale confs can't
    accidentally route traffic."""
    c = get_config()
    enabled = bool(c.get("enabled") and c.get("host") and c.get("port"))
    if not enabled:
        try: os.remove(_PROXYCHAINS_CONF)
        except FileNotFoundError: pass
        except Exception: pass
        return
    ptype = (c.get("type") or "socks5").lower()
    # proxychains4 only understands: http, socks4, socks5
    if ptype in ("socks5h", "socks5"):
        pc_type = "socks5"
    elif ptype in ("http", "https"):
        pc_type = "http"
    else:
        pc_type = "socks5"
    # proxychains requires a NUMERIC IP for the proxy host (hostnames are
    # rejected unless strict chaintype is used). Resolve locally; this is
    # only the proxy server's own address — target URL DNS still goes
    # through the proxy because `proxy_dns` is set above.
    host = c["host"]
    try:
        import socket as _sock
        ip = _sock.gethostbyname(host)
    except Exception:
        ip = host  # fall back; proxychains will print a clear error if non-numeric
    line = f"{pc_type} {ip} {c['port']}"
    if c.get("username"):
        # proxychains auth: "proto host port user pass"
        pw = c.get("password") or ""
        line += f" {c['username']}"
        if pw:
            line += f" {pw}"
    conf = (
        "# Auto-generated by ZeekGlare — do not edit by hand.\n"
        "quiet_mode\n"
        "proxy_dns\n"
        "remote_dns_subnet 224\n"
        "tcp_read_time_out 15000\n"
        "tcp_connect_time_out 8000\n"
        "localnet 127.0.0.0/255.0.0.0\n"
        "localnet 10.0.0.0/255.0.0.0\n"
        "localnet 172.16.0.0/255.240.0.0\n"
        "localnet 192.168.0.0/255.255.0.0\n"
        "\n[ProxyList]\n"
        f"{line}\n"
    )
    try:
        with open(_PROXYCHAINS_CONF, "w", encoding="utf-8") as f:
            f.write(conf)
        os.chmod(_PROXYCHAINS_CONF, 0o600)
    except Exception:
        pass


def wrap_cmd(cmd):
    """Return `cmd` prefixed with proxychains4 when proxy is enabled.

    `cmd` may be a list (preferred) or a string. When proxy is off, returns
    `cmd` unchanged. When on, returns a list starting with proxychains4 so the
    wrapped process routes every TCP connection (and DNS via proxy_dns) through
    the configured SOCKS5/HTTP proxy.

    Safe to use everywhere — no-op when proxy is disabled or proxychains4 is
    missing from PATH.
    """
    if not is_enabled():
        return cmd
    import shutil as _sh
    pc_bin = _sh.which("proxychains4") or _sh.which("proxychains")
    if not pc_bin:
        return cmd
    if not os.path.exists(_PROXYCHAINS_CONF):
        _write_proxychains_conf()
        if not os.path.exists(_PROXYCHAINS_CONF):
            return cmd
    prefix = [pc_bin, "-q", "-f", _PROXYCHAINS_CONF]
    if isinstance(cmd, (list, tuple)):
        return prefix + list(cmd)
    # String form — join with space; caller is responsible for quoting.
    return " ".join(prefix) + " " + cmd
