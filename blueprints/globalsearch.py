"""Global Search — full-text search across all session data."""
import os
import json
import re
from datetime import datetime
from flask import Blueprint, request, jsonify, g, render_template
from core.auth_utils import login_required, admin_required
from core.session_manager import SessionManager

globalsearch_bp = Blueprint("globalsearch", __name__)

SESSIONS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "sessions")


def _load_all_sessions(user_id: int = None, is_admin: bool = False):
    """Load all session JSON files with optional user filtering."""
    sessions = []
    if not os.path.isdir(SESSIONS_DIR):
        return sessions
    for fname in os.listdir(SESSIONS_DIR):
        if not fname.endswith(".json"):
            continue
        fpath = os.path.join(SESSIONS_DIR, fname)
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            continue

        # User isolation
        owner = data.get("user_id")
        if not is_admin and owner is not None and owner != user_id:
            continue

        data["_file"] = fname
        sessions.append(data)
    return sessions


def _score_match(obj, query_lower: str, query_re) -> int:
    """Return a match score for a session object. Higher = better match."""
    score = 0
    text_chunks = []

    def _extract(obj):
        if isinstance(obj, str):
            text_chunks.append(obj)
        elif isinstance(obj, (list, tuple)):
            for item in obj:
                _extract(item)
        elif isinstance(obj, dict):
            for v in obj.values():
                _extract(v)

    _extract(obj)
    full_text = " ".join(text_chunks).lower()

    if query_lower in full_text:
        score += 1
        # Boost exact target matches
        target = str(obj.get("target", "")).lower()
        if query_lower in target:
            score += 3
        # Boost module name matches
        module = str(obj.get("module", "")).lower()
        if query_lower in module:
            score += 2

    # Regex hits
    try:
        hits = len(query_re.findall(full_text))
        score += min(hits, 5)
    except Exception:
        pass

    return score


def _session_summary(data: dict) -> dict:
    """Build a compact summary of a session for search results."""
    findings = 0
    if isinstance(data.get("findings"), list):
        findings = len(data["findings"])
    elif isinstance(data.get("results"), list):
        findings = len(data["results"])
    elif isinstance(data.get("subdomains"), list):
        findings = len(data["subdomains"])
    elif isinstance(data.get("urls"), list):
        findings = len(data["urls"])
    elif isinstance(data.get("ports"), list):
        findings = len(data["ports"])
    elif isinstance(data.get("vulnerabilities"), list):
        findings = len(data["vulnerabilities"])

    return {
        "id": data.get("id", data.get("session_id", "")),
        "target": data.get("target", data.get("domain", data.get("url", "Unknown"))),
        "module": data.get("module", data.get("type", "unknown")),
        "label": data.get("label", data.get("name", "")),
        "findings": findings,
        "created_at": data.get("created_at", data.get("timestamp", "")),
        "user_id": data.get("user_id"),
        "file": data.get("_file", ""),
    }


@globalsearch_bp.route("/search")
@login_required
def search_page():
    return render_template("globalsearch.html")


@globalsearch_bp.route("/api/search", methods=["POST"])
@login_required
def global_search():
    body = request.get_json(silent=True) or {}
    query = (body.get("query") or "").strip()
    module_filter = body.get("module")
    date_from = body.get("date_from")
    date_to = body.get("date_to")
    limit = body.get("limit", 50)
    try:
        limit = int(limit)
    except ValueError:
        limit = 50
    limit = max(1, min(limit, 200))

    if not query or len(query) < 2:
        return jsonify({"error": "Query must be at least 2 characters."}), 400

    user = g.current_user
    is_admin = user.role == "admin"
    sessions = _load_all_sessions(user.id, is_admin)

    query_lower = query.lower()
    try:
        query_re = re.compile(re.escape(query), re.IGNORECASE)
    except Exception:
        query_re = re.compile(re.escape(query_lower))

    results = []
    for s in sessions:
        # Module filter
        if module_filter:
            mod = str(s.get("module", s.get("type", ""))).lower()
            if module_filter.lower() not in mod:
                continue

        # Date filter
        if date_from or date_to:
            ts = s.get("created_at", s.get("timestamp", ""))
            if ts:
                try:
                    # Handle ISO format
                    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    if date_from:
                        df = datetime.fromisoformat(date_from)
                        if dt < df:
                            continue
                    if date_to:
                        dte = datetime.fromisoformat(date_to)
                        if dt > dte:
                            continue
                except Exception:
                    pass

        score = _score_match(s, query_lower, query_re)
        if score > 0:
            results.append({"score": score, "session": _session_summary(s)})

    results.sort(key=lambda x: x["score"], reverse=True)
    results = results[:limit]

    # Unique modules present in results
    modules = sorted({r["session"]["module"] for r in results})

    return jsonify({
        "query": query,
        "total": len(results),
        "modules": modules,
        "results": [r["session"] for r in results],
    })


@globalsearch_bp.route("/api/search/modules")
@login_required
def search_modules():
    """Return all unique module/types present in sessions."""
    user = g.current_user
    sessions = _load_all_sessions(user.id, user.role == "admin")
    mods = sorted({s.get("module", s.get("type", "unknown")) for s in sessions})
    return jsonify({"modules": mods})


@globalsearch_bp.route("/api/search/stats")
@admin_required
def search_stats():
    """Admin-only stats about session storage."""
    sessions = _load_all_sessions(is_admin=True)
    total = len(sessions)
    by_module = {}
    by_user = {}
    total_size = 0

    for s in sessions:
        mod = s.get("module", s.get("type", "unknown"))
        by_module[mod] = by_module.get(mod, 0) + 1
        uid = s.get("user_id", "none")
        by_user[str(uid)] = by_user.get(str(uid), 0) + 1

    if os.path.isdir(SESSIONS_DIR):
        for f in os.listdir(SESSIONS_DIR):
            if f.endswith(".json"):
                total_size += os.path.getsize(os.path.join(SESSIONS_DIR, f))

    return jsonify({
        "total_sessions": total,
        "by_module": by_module,
        "by_user": by_user,
        "storage_bytes": total_size,
        "storage_mb": round(total_size / (1024 * 1024), 2),
    })
