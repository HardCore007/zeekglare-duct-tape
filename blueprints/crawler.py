"""Crawler blueprint — Endpoint Recon via passive sources (Wayback, CommonCrawl, OTX, URLScan)
and active crawlers (hakrawler, gospider)."""
import threading, uuid, json, time, os, shutil, subprocess, requests
from flask import Blueprint, request, jsonify, Response, stream_with_context, g
from core.auth_utils import module_required, rate_limit
from core.session_manager import SessionManager


def _tool_env():
    env = os.environ.copy()
    go_bin  = os.path.expanduser("~/go/bin")
    pip_bin = os.path.expanduser("~/.local/bin")
    env["PATH"] = go_bin + ":" + pip_bin + ":" + env.get("PATH", "")
    return env

crawler_bp = Blueprint("crawler", __name__)
_scans = {}
_lock  = threading.Lock()


def _persist_crawler(scan_id, snap, kind="endpoint-recon"):
    """Persist crawler URL discovery as a session."""
    events = snap.get("events", []) or []
    target = snap.get("target", "") or ""

    urls = []
    by_source = {}
    for ev in events:
        if not isinstance(ev, dict):
            continue
        if ev.get("type") == "url" and ev.get("url"):
            src = ev.get("source", "unknown")
            urls.append({"url": ev["url"], "source": src})
            by_source[src] = by_source.get(src, 0) + 1

    # Dedup URLs
    seen = set()
    deduped = []
    for u in urls:
        key = u["url"]
        if key not in seen:
            seen.add(key)
            deduped.append(u)

    name = f"Crawler — {target}" if target else "Crawler"
    summary = {
        "status":     "completed",
        "kind":       kind,
        "total_urls": len(deduped),
        "sources":    by_source,
    }
    data = {"urls": deduped, "by_source": by_source, "target": target}
    try:
        SessionManager.save(
            scan_id=scan_id, scan_type="crawler", target=target,
            name=name, summary=summary, data=data,
            user_id=snap.get("user_id"), username=snap.get("username", ""),
        )
    except Exception:
        pass

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; ZeekGlare/1.0; +https://zeekglare.io)"}


# ── Passive source queries ────────────────────────────────────────────────────

from urllib.parse import quote as _quote

def _query_wayback(domain):
    try:
        url = (
            f"http://web.archive.org/cdx/search/cdx"
            f"?url=*.{_quote(domain, safe='')}/*&output=json&fl=original&collapse=urlkey&limit=10000"
        )
        r = requests.get(url, timeout=40, headers=HEADERS)
        data = r.json()
        if isinstance(data, list):
            for row in data[1:]:  # skip header
                if row and row[0]:
                    yield row[0]
    except Exception:
        pass


def _query_commoncrawl(domain):
    try:
        # Latest index
        idx_url = "https://index.commoncrawl.org/collinfo.json"
        try:
            idx = requests.get(idx_url, timeout=10, headers=HEADERS).json()
            index_id = idx[0]["id"] if idx else "CC-MAIN-2024-10"
        except Exception:
            index_id = "CC-MAIN-2024-10"

        url = f"https://index.commoncrawl.org/{index_id}-index?url=*.{_quote(domain, safe='')}/*&output=json"
        r = requests.get(url, timeout=40, headers=HEADERS)
        for line in r.text.strip().split("\n"):
            if not line:
                continue
            try:
                d = json.loads(line)
                if d.get("url"):
                    yield d["url"]
            except Exception:
                pass
    except Exception:
        pass


def _query_otx(domain):
    page = 1
    while page <= 10:
        try:
            url = (
                f"https://otx.alienvault.com/api/v1/indicators/domain/{_quote(domain, safe='')}"
                f"/url_list?limit=500&page={page}"
            )
            r = requests.get(url, timeout=30, headers=HEADERS)
            data = r.json()
            items = data.get("url_list", [])
            if not items:
                break
            for item in items:
                if item.get("url"):
                    yield item["url"]
            if not data.get("has_next"):
                break
            page += 1
        except Exception:
            break


def _query_urlscan(domain):
    try:
        url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=10000"
        r = requests.get(url, timeout=30, headers=HEADERS)
        data = r.json()
        for result in data.get("results", []):
            page_url = result.get("page", {}).get("url")
            if page_url:
                yield page_url
    except Exception:
        pass


def _build_seeds(domain, extra_targets=None):
    """Build a sorted seed-URL set from a root domain + optional list of live subdomains.
    Accepts bare hostnames or full URLs; emits both http:// and https:// variants for bare hostnames."""
    seeds = set()
    if domain:
        seeds.add(f"http://{domain}")
        seeds.add(f"https://{domain}")
    for t in (extra_targets or []):
        t = (t or "").strip()
        if not t:
            continue
        if t.startswith("http://") or t.startswith("https://"):
            seeds.add(t)
        else:
            seeds.add(f"http://{t}")
            seeds.add(f"https://{t}")
    return sorted(seeds)


def _query_hakrawler(domain, extra_targets=None):
    """Active crawler — pipes seed URLs into hakrawler stdin and emits discovered URLs."""
    env = _tool_env()
    if not shutil.which("hakrawler", path=env["PATH"]):
        return
    seeds_list = _build_seeds(domain, extra_targets)
    if not seeds_list:
        return
    seeds_blob = "\n".join(seeds_list) + "\n"
    # Scale timeout with seed count (capped). Hakrawler is concurrent so it scales reasonably.
    timeout_s = min(180 + 10 * len(seeds_list), 900)
    try:
        proc = subprocess.Popen(
            ["hakrawler", "-subs", "-u", "-d", "3", "-t", "20"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, env=env,
        )
        try:
            proc.stdin.write(seeds_blob)
            proc.stdin.close()
        except Exception:
            pass
        deadline = time.time() + timeout_s
        for line in proc.stdout:
            u = line.strip()
            if u and (u.startswith("http://") or u.startswith("https://")):
                yield u
            if time.time() > deadline:
                break
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
    except Exception:
        pass


def _query_gospider(domain, extra_targets=None):
    """Active crawler — gospider spiders all seed URLs (root + live subdomains) and emits discovered URLs."""
    import tempfile
    env = _tool_env()
    if not shutil.which("gospider", path=env["PATH"]):
        return
    seeds_list = _build_seeds(domain, extra_targets)
    if not seeds_list:
        return
    timeout_s = min(180 + 10 * len(seeds_list), 900)
    sites_file = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(seeds_list) + "\n")
            sites_file = f.name
        proc = subprocess.Popen(
            ["gospider", "-S", sites_file, "-d", "2", "-c", "10", "-t", "8",
             "-q", "--blacklist", r"\.(jpg|jpeg|gif|css|png|woff|woff2|ttf|eot|svg|ico)$"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, env=env,
        )
        deadline = time.time() + timeout_s
        for line in proc.stdout:
            s = line.strip()
            url = None
            if " - " in s:
                parts = s.split(" - ", 1)
                if len(parts) == 2 and (parts[1].startswith("http://") or parts[1].startswith("https://")):
                    url = parts[1]
            elif s.startswith("http://") or s.startswith("https://"):
                url = s
            if url:
                url = url.split()[0].rstrip('",;)')
                if url.startswith("http"):
                    yield url
            if time.time() > deadline:
                break
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
    except Exception:
        pass
    finally:
        if sites_file:
            try: os.remove(sites_file)
            except Exception: pass


SOURCE_FNS = {
    "wayback":      _query_wayback,
    "commoncrawl":  _query_commoncrawl,
    "otx":          _query_otx,
    "urlscan":      _query_urlscan,
    "hakrawler":    _query_hakrawler,
    "gospider":     _query_gospider,
}


_ACTIVE_CRAWLERS = {"hakrawler", "gospider"}


def _do_endpoint_recon(domain, sources, q, live_targets=None):
    live_targets = live_targets or []
    q.put({"type": "start", "domain": domain, "sources": sources, "live_targets": len(live_targets)})
    seen = set()
    total = 0

    for src in sources:
        fn = SOURCE_FNS.get(src)
        if not fn:
            continue
        q.put({"type": "source_start", "source": src, "seeds": (1 + len(live_targets)) if src in _ACTIVE_CRAWLERS else 1})
        count = 0
        try:
            gen = fn(domain, extra_targets=live_targets) if src in _ACTIVE_CRAWLERS else fn(domain)
            for raw_url in gen:
                u = raw_url.strip()
                if not u or u in seen:
                    continue
                seen.add(u)
                count += 1
                total += 1
                q.put({"type": "url", "url": u, "source": src})
                if count % 200 == 0:
                    q.put({"type": "source_progress", "source": src, "count": count})
        except Exception as e:
            q.put({"type": "source_error", "source": src, "error": str(e)})
        q.put({"type": "source_done", "source": src, "count": count})

    # NOTE: no explicit 'done' push here — the stream generator emits a single
    # 'done' event when it sees the None sentinel that `_run`'s finally block
    # puts on the queue. Pushing one here would cause the client to receive two
    # 'done' events and historically triggered duplicate session saves.


# ── Routes ────────────────────────────────────────────────────────────────────

@crawler_bp.route("/api/crawler/endpoint-recon", methods=["POST"])
@module_required("crawler")
@rate_limit(max_requests=5, window_seconds=60)
def start_endpoint_recon():
    body    = request.get_json(silent=True) or {}
    domain  = (body.get("domain") or "").strip().lower()
    sources = body.get("sources") or ["wayback", "commoncrawl", "otx", "urlscan"]
    # Optional: list of live subdomain hostnames or full URLs to seed active crawlers.
    # Passive sources are wildcard-scoped and ignore this list.
    raw_live = body.get("live_targets") or []
    live_targets = []
    if isinstance(raw_live, list):
        for t in raw_live[:500]:        # cap to avoid runaway scans
            if isinstance(t, str) and t.strip():
                live_targets.append(t.strip())

    if not domain:
        return jsonify({"error": "domain required"}), 400

    scan_id = str(uuid.uuid4())
    q       = __import__("queue").Queue()

    with _lock:
        _scans[scan_id] = {"queue": q, "done": False, "events": [], "target": domain, "started_at": __import__("time").time(),
                           "user_id": getattr(g, "current_user", None) and g.current_user.id,
                           "username": getattr(getattr(g, "current_user", None), "username", "")}

    def _buffer():
        while True:
            try:
                item = q.get(timeout=120)
                with _lock:
                    if scan_id in _scans:
                        _scans[scan_id]["events"].append(item)
                if item is None:
                    break
            except __import__("queue").Empty:
                pass

    def _run():
        try:
            _do_endpoint_recon(domain, sources, q, live_targets=live_targets)
        except Exception as e:
            q.put({"type": "error", "message": str(e)})
        finally:
            q.put(None)
            _snap = None
            with _lock:
                if scan_id in _scans:
                    _scans[scan_id]["done"] = True
                    _snap = dict(_scans[scan_id])
            if _snap:
                _persist_crawler(scan_id, _snap, kind="endpoint-recon")

    threading.Thread(target=_buffer, daemon=True).start()
    threading.Thread(target=_run,    daemon=True).start()
    return jsonify({"scan_id": scan_id, "domain": domain, "live_targets": len(live_targets)})


@crawler_bp.route("/api/crawler/url-harvest", methods=["POST"])
@module_required("crawler")
@rate_limit(max_requests=5, window_seconds=60)
def start_url_harvest():
    """Run CLI URL harvesting tools (gau, waybackurls, waymore, urlfinder)."""
    import subprocess, os, shutil
    body   = request.get_json(silent=True) or {}
    domain = (body.get("domain") or "").strip().lower()
    tools  = body.get("tools") or ["gau", "waybackurls", "waymore", "urlfinder"]

    if not domain:
        return jsonify({"error": "domain required"}), 400

    scan_id = str(uuid.uuid4())
    q       = __import__("queue").Queue()

    with _lock:
        _scans[scan_id] = {"queue": q, "done": False, "events": [], "target": domain, "started_at": __import__("time").time(),
                           "user_id": getattr(g, "current_user", None) and g.current_user.id,
                           "username": getattr(getattr(g, "current_user", None), "username", "")}

    def _buffer():
        while True:
            try:
                item = q.get(timeout=120)
                with _lock:
                    if scan_id in _scans:
                        _scans[scan_id]["events"].append(item)
                if item is None:
                    break
            except __import__("queue").Empty:
                pass

    def _run_tool(tool, domain, q):
        env = os.environ.copy()
        go_bin = os.path.expanduser("~/go/bin")
        pip_bin = os.path.expanduser("~/.local/bin")
        env["PATH"] = go_bin + ":" + pip_bin + ":" + env.get("PATH", "")

        cmd_map = {
            "gau":         ["gau", domain],
            "waybackurls": ["waybackurls", domain],
            "waymore":     ["waymore", "-i", domain, "-mode", "U"],
            "urlfinder":   ["urlfinder", "-d", domain, "-silent"],
        }
        cmd = cmd_map.get(tool)
        if not cmd or not shutil.which(cmd[0], path=env["PATH"]):
            q.put({"type": "tool_skip", "tool": tool, "reason": "not installed"})
            return

        q.put({"type": "tool_start", "tool": tool})
        count = 0
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, env=env,
            )
            for line in proc.stdout:
                u = line.strip()
                if u:
                    count += 1
                    q.put({"type": "url", "url": u, "source": tool})
            proc.wait(timeout=5)
        except Exception as e:
            q.put({"type": "tool_error", "tool": tool, "error": str(e)})
        q.put({"type": "tool_done", "tool": tool, "count": count})

    def _run():
        try:
            q.put({"type": "start", "domain": domain, "tools": tools})
            seen = set()
            for tool in tools:
                _run_tool(tool, domain, q)
        except Exception as e:
            q.put({"type": "error", "message": str(e)})
        finally:
            q.put(None)
            _snap = None
            with _lock:
                if scan_id in _scans:
                    _scans[scan_id]["done"] = True
                    _snap = dict(_scans[scan_id])
            if _snap:
                _persist_crawler(scan_id, _snap, kind="url-harvest")

    threading.Thread(target=_buffer, daemon=True).start()
    threading.Thread(target=_run,    daemon=True).start()
    return jsonify({"scan_id": scan_id, "domain": domain})


@crawler_bp.route("/api/crawler/stream/<scan_id>")
@module_required("crawler")
def stream_crawler(scan_id):
    with _lock:
        scan = _scans.get(scan_id)
    if not scan:
        return jsonify({"error": "not found"}), 404

    def generate():
        offset  = 0
        last_ka = time.time()
        while True:
            with _lock:
                scan   = _scans.get(scan_id)
                if not scan:
                    break
                events = scan["events"]
                done   = scan["done"]

            while offset < len(events):
                item = events[offset]
                offset += 1
                if item is None:
                    yield f"data: {json.dumps({'type': 'done'})}\n\n"
                    return
                yield f"data: {json.dumps(item)}\n\n"

            if done:
                yield f"data: {json.dumps({'type': 'done'})}\n\n"
                return

            now = time.time()
            if now - last_ka > 25:
                yield f"data: {json.dumps({'type': 'keepalive'})}\n\n"
                last_ka = now

            time.sleep(0.05)

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@crawler_bp.route("/api/crawler/status/<scan_id>")
def crawler_status(scan_id):
    with _lock:
        scan = _scans.get(scan_id)
    if not scan:
        return jsonify({"exists": False}), 404
    return jsonify({"exists": True, "done": scan["done"], "event_count": len(scan["events"])})
