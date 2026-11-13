"""AI Arena blueprint — autonomous LLM agents investigate a target.

Phase 2: N agents share one SharedState; orchestration lives in
`services.agent_orchestrator.ArenaOrchestrator`. This file is HTTP-only.

Routes:
    POST   /api/arena/start            — kick off a race
    GET    /api/arena/stream/<sid>     — SSE event multiplex
    POST   /api/arena/stop/<sid>       — cancel in-flight run
    GET    /api/arena/sessions         — list (user-scoped)
    GET    /api/arena/session/<sid>    — fetch full transcript + findings
    DELETE /api/arena/session/<sid>    — delete

Session records go through the standard SessionManager so they appear in
the existing Sessions pane + Report Builder.
"""
from __future__ import annotations
import json, os, threading, time, uuid
from flask import Blueprint, request, Response, jsonify, stream_with_context, g

from core.auth_utils     import login_required, module_required
from core.session_manager import SessionManager
from services.agent_orchestrator import ArenaOrchestrator

arena_bp = Blueprint("arena", __name__)

_ARENAS: dict[str, ArenaOrchestrator] = {}
_LOCK = threading.Lock()

_DEFAULT_BUDGET = {
    "max_steps":      20,
    "max_seconds":    1800,
    "max_cost_usd":   2.0,
    "max_tool_calls": 40,
}


# ── Helpers ────────────────────────────────────────────────────────────────

def _uid():
    u = getattr(g, "current_user", None)
    return u.id if u else None


def _uname():
    u = getattr(g, "current_user", None)
    return u.username if u else ""


def _is_admin():
    u = getattr(g, "current_user", None)
    try:
        return bool(u and getattr(u, "is_admin", False))
    except Exception:
        return False


def _owns(orch: ArenaOrchestrator) -> bool:
    return _is_admin() or orch.user_id == _uid()


# ── Routes ─────────────────────────────────────────────────────────────────

@arena_bp.route("/api/arena/start", methods=["POST"])
@login_required
def start():
    body     = request.get_json(silent=True) or {}
    target   = (body.get("target") or "").strip().lower()
    scope    = body.get("scope") or []
    if isinstance(scope, str):
        scope = [s.strip() for s in scope.split(",") if s.strip()]
    if not target:
        return jsonify({"error": "target required"}), 400

    agents_in  = body.get("agents") or []
    if not agents_in:
        # Default: one Claude agent with whatever key the caller provided
        agents_in = [{
            "provider": body.get("provider", "anthropic"),
            "model":    body.get("model", "claude-opus-4-7"),
            "api_key":  body.get("api_key", ""),
            "label":    body.get("label", "Agent-1"),
            "role_hint":body.get("role_hint", ""),
        }]

    # Validate agents + provide keys from env as fallback
    for a in agents_in:
        a["provider"] = (a.get("provider") or "anthropic").lower()
        if a["provider"] not in ("anthropic", "openai", "nvidia"):
            return jsonify({"error": f"Unknown provider: {a['provider']}"}), 400
        if not a.get("api_key"):
            env_key = {
                "anthropic": "ANTHROPIC_API_KEY",
                "openai":    "OPENAI_API_KEY",
                "nvidia":    "NVIDIA_API_KEY",
            }.get(a["provider"], "")
            a["api_key"] = os.environ.get(env_key, "")
        if not a.get("api_key"):
            return jsonify({
                "error": f"No API key for {a['provider']} (agent '{a.get('label','?')}'). "
                         "Pass it in the request or set the env var."
            }), 400
        if not a.get("model"):
            a["model"] = {
                "anthropic": "claude-opus-4-7",
                "openai":    "gpt-4o",
                "nvidia":    "meta/llama-3.3-70b-instruct",
            }.get(a["provider"], "claude-opus-4-7")
        if not a.get("label"):
            a["label"] = f"{a['provider']}:{a['model']}"

    budget = dict(_DEFAULT_BUDGET)
    budget.update({k: v for k, v in (body.get("budget") or {}).items() if v is not None})

    # Judge config — optional. Falls back to the first Anthropic agent's key
    # so the frontend doesn't need a separate judge key field by default.
    judge_cfg = body.get("judge") or {}
    if judge_cfg:
        jprov = (judge_cfg.get("provider") or "anthropic").lower()
        if not judge_cfg.get("api_key"):
            # Inherit key from an agent of the same provider.
            for a in agents_in:
                if a["provider"] == jprov and a.get("api_key"):
                    judge_cfg["api_key"] = a["api_key"]; break
            if not judge_cfg.get("api_key"):
                env_key = {
                    "anthropic": "ANTHROPIC_API_KEY",
                    "openai":    "OPENAI_API_KEY",
                    "nvidia":    "NVIDIA_API_KEY",
                }.get(jprov, "")
                judge_cfg["api_key"] = os.environ.get(env_key, "")
        judge_cfg["provider"] = jprov
        if not judge_cfg.get("model"):
            judge_cfg["model"] = {
                "anthropic": "claude-opus-4-7",
                "openai":    "gpt-4o",
                "nvidia":    "nvidia/llama-3.1-nemotron-ultra-253b-v1",
            }.get(jprov, "claude-opus-4-7")
        # If we couldn't resolve a key, skip the judge rather than erroring
        # the whole race.
        if not judge_cfg.get("api_key"):
            judge_cfg = None

    sid = str(uuid.uuid4())
    orch = ArenaOrchestrator(
        sid           = sid,
        target        = target,
        scope         = scope or [target],
        agents_in     = agents_in,
        budget        = budget,
        user_id       = _uid(),
        username      = _uname(),
        allow_exploit = bool(body.get("allow_exploit", False)),
        judge_config  = judge_cfg or None,
        auto_mode     = bool(body.get("auto_mode", False)),
    )
    with _LOCK:
        _ARENAS[sid] = orch
    orch.start()
    return jsonify({
        "sid":    sid,
        "target": target,
        "scope":  orch.scope,
        "agents": orch.agents_meta,
        "budget": orch.budget,
    })


@arena_bp.route("/api/arena/stream/<sid>")
@login_required
def stream(sid):
    with _LOCK:
        orch = _ARENAS.get(sid)
    if not orch:
        return jsonify({"error": "not found"}), 404
    if not _owns(orch):
        return jsonify({"error": "forbidden"}), 403

    def gen():
        yield f"data: {json.dumps({'type':'hello','agents':orch.agents_meta,'target':orch.target})}\n\n"
        offset = 0
        last_ka = time.time()
        while True:
            new_events, done = orch.get_events(offset)
            for ev in new_events:
                yield f"data: {json.dumps(ev)}\n\n"
                offset += 1
            if done:
                yield f"data: {json.dumps({'type':'arena_done','sid':sid})}\n\n"
                return
            now = time.time()
            if now - last_ka > 25:
                yield f"data: {json.dumps({'type':'keepalive'})}\n\n"
                last_ka = now
            time.sleep(0.15)

    return Response(
        stream_with_context(gen()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@arena_bp.route("/api/arena/stop/<sid>", methods=["POST"])
@login_required
def stop(sid):
    with _LOCK:
        orch = _ARENAS.get(sid)
    if not orch:
        return jsonify({"error": "not found"}), 404
    if not _owns(orch):
        return jsonify({"error": "forbidden"}), 403
    orch.stop()
    return jsonify({"ok": True})


@arena_bp.route("/api/arena/sessions")
@login_required
def list_sessions():
    all_sess = SessionManager.list_all(user_id=_uid(), admin=_is_admin())
    arenas = [s for s in all_sess if s.get("type") == "arena"]
    return jsonify({"sessions": arenas})


@arena_bp.route("/api/arena/session/<sid>")
@login_required
def get_session(sid):
    s = SessionManager.get(sid, user_id=_uid(), admin=_is_admin())
    if not s:
        return jsonify({"error": "not found"}), 404
    with _LOCK:
        orch = _ARENAS.get(sid)
    if orch and _owns(orch):
        new_events, done = orch.get_events(0)
        s = dict(s)
        s["live"] = {
            "done":        done,
            "findings":    orch.state.list_findings(),
            "assets":      orch.state.asset_counts(),
            "leaderboard": orch.leaderboard(),
            "events":      new_events[-500:],
        }
    return jsonify(s)


@arena_bp.route("/api/arena/session/<sid>", methods=["DELETE"])
@login_required
def delete_session(sid):
    with _LOCK:
        orch = _ARENAS.get(sid)
        if orch:
            if not _owns(orch):
                return jsonify({"error": "forbidden"}), 403
            orch.stop()
            _ARENAS.pop(sid, None)
    ok = SessionManager.delete(sid, user_id=_uid(), admin=_is_admin())
    return jsonify({"ok": bool(ok)})


@arena_bp.route("/api/arena/models")
@login_required
def models():
    """Models suitable for agent use — must support tool use / function calling."""
    return jsonify({
        "providers": {
            "anthropic": [
                {"id": "claude-opus-4-7",   "label": "Claude Opus 4.7  (best)"},
                {"id": "claude-opus-4-6",   "label": "Claude Opus 4.6"},
                {"id": "claude-sonnet-4-6", "label": "Claude Sonnet 4.6  (balanced)"},
                {"id": "claude-haiku-4-5",  "label": "Claude Haiku 4.5  (fast/cheap)"},
            ],
            "openai": [
                {"id": "gpt-4o",      "label": "GPT-4o"},
                {"id": "gpt-4o-mini", "label": "GPT-4o mini  (cheap)"},
            ],
            "nvidia": [
                {"id": "meta/llama-3.3-70b-instruct",             "label": "Llama 3.3 70B  (NIM, balanced)"},
                {"id": "nvidia/llama-3.3-nemotron-super-49b-v1",  "label": "Nemotron Super 49B  (NIM)"},
                {"id": "nvidia/llama-3.1-nemotron-ultra-253b-v1", "label": "Nemotron Ultra 253B  (NIM, heavy)"},
                {"id": "mistralai/mixtral-8x22b-instruct-v0.1",   "label": "Mixtral 8x22B  (NIM)"},
                {"id": "deepseek-ai/deepseek-v3.2",               "label": "DeepSeek V3.2  (NIM, reasoning)"},
                {"id": "deepseek-ai/deepseek-r1",                 "label": "DeepSeek R1  (NIM, reasoning)"},
            ],
        },
        "default_budget": _DEFAULT_BUDGET,
    })
