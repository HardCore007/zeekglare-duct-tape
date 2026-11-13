"""ArenaOrchestrator — owns one arena race.

Responsibilities split out of `blueprints/arena.py` so the blueprint stays
HTTP-only:

  - Build SharedState + a roster of AgentRunner instances
  - Provide an emit() callback that buffers events for SSE consumers
  - Spawn one daemon thread per agent and one orchestrator thread
  - Compute live leaderboard snapshots from buffered events
  - On completion, persist final findings + transcript via SessionManager

Designed so Phase 3 can plug in additional roles (judge agent, skill-aware
agents) without touching the route layer.
"""
from __future__ import annotations
import threading, time
from datetime import datetime

from core.session_manager import SessionManager
from services.agent_cache  import SharedState
from services.agent_runner import AgentRunner
from services.agent_judge  import JudgeAgent


class ArenaOrchestrator:
    def __init__(self, *, sid: str, target: str, scope: list,
                 agents_in: list, budget: dict,
                 user_id, username: str,
                 allow_exploit: bool = False,
                 judge_config: dict | None = None,
                 auto_mode: bool = False):
        self.sid       = sid
        self.target    = target
        self.scope     = [s for s in (scope or [target]) if s]
        self.budget    = dict(budget)
        self.user_id   = user_id
        self.username  = username
        self.allow_exploit = bool(allow_exploit)
        self.auto_mode     = bool(auto_mode)
        self.judge_config: dict | None = judge_config or None
        self.judge_verdict: dict | None = None
        self._phase_thread: threading.Thread | None = None
        self._phase_stop = threading.Event()
        self.events:   list = []
        self.done:     bool = False
        self.started_at = time.time()

        self._lock     = threading.RLock()
        self.state     = SharedState(target=target, scope=self.scope)
        self.runners:  list[AgentRunner] = []

        for i, a in enumerate(agents_in):
            agent_id = f"a{i+1}"
            self.runners.append(AgentRunner(
                agent_id       = agent_id,
                label          = a.get("label") or f"{a['provider']}:{a['model']}",
                provider       = a["provider"],
                api_key        = a["api_key"],
                model          = a["model"],
                target         = target,
                state          = self.state,
                emit           = self._emit,
                budget         = self.budget,
                role_hint      = a.get("role_hint", ""),
                allow_exploit  = self.allow_exploit,
            ))

        self.agents_meta = [
            {"agent_id": r.agent_id, "label": r.label,
             "provider": r.provider, "model": r.model}
            for r in self.runners
        ]

    # ── Event buffer ──────────────────────────────────────────────────────
    def _emit(self, event_type: str, payload: dict):
        ev = {"type": event_type, "ts": time.time(), **payload}
        with self._lock:
            self.events.append(ev)

    def event_count(self) -> int:
        with self._lock:
            return len(self.events)

    def get_events(self, offset: int) -> tuple[list, bool]:
        with self._lock:
            return list(self.events[offset:]), self.done

    def stop(self):
        for r in self.runners:
            r.stop()

    # ── Live leaderboard snapshot (also persisted at completion) ─────────
    def leaderboard(self) -> list[dict]:
        """Server-side ranking — same logic the UI applies client-side.
        Used by /api/arena/session/<sid> so a refresh shows the live ranking
        even before the race finishes.
        """
        # Walk the event log to build per-agent rollups.
        per: dict[str, dict] = {}
        for r in self.runners:
            per[r.agent_id] = {
                "agent_id": r.agent_id,
                "label":    r.label,
                "findings": 0, "critHigh": 0,
                "cost":     0.0, "elapsed": 0,
                "tokens":   0, "tools": 0, "steps": 0,
                "done":     False,
            }
        with self._lock:
            evs = list(self.events)
        for ev in evs:
            aid = ev.get("agent_id"); rec = per.get(aid) if aid else None
            if not rec:
                continue
            t = ev.get("type")
            if t == "finding" and not ev.get("duplicate"):
                rec["findings"] += 1
                sev = (ev.get("severity") or "").lower()
                if sev in ("critical", "high"):
                    rec["critHigh"] += 1
            elif t == "cost_update":
                rec["tokens"] = (ev.get("tokens_in") or 0) + (ev.get("tokens_out") or 0)
                rec["cost"]   = ev.get("cost_usd") or rec["cost"]
            elif t == "agent_done":
                rec["done"]    = True
                rec["elapsed"] = ev.get("elapsed") or 0
                rec["tools"]   = ev.get("tool_calls") or 0
                rec["steps"]   = ev.get("steps") or 0
        rows = list(per.values())
        rows.sort(key=lambda r: (-r["critHigh"], -r["findings"], r["elapsed"], r["cost"]))
        return rows

    # ── Run loop ──────────────────────────────────────────────────────────
    def start(self):
        # Persist a "running" session immediately so it survives a refresh.
        SessionManager.save(
            scan_id   = self.sid,
            scan_type = "arena",
            target    = self.target,
            name      = f"AI Arena — {self.target} — {datetime.now():%Y-%m-%d %H:%M}",
            summary   = {"status": "running", "findings": 0,
                         "agents": len(self.runners), "target": self.target},
            data      = {"scope": self.scope, "budget": self.budget,
                         "agents": self.agents_meta},
            user_id   = self.user_id,
            username  = self.username,
        )
        threading.Thread(
            target=self._run_all, daemon=True,
            name=f"arena-{self.sid}-orch",
        ).start()

    def _run_all(self):
        # Auto Mode: spin up a background phase tracker that steers agents
        # through Recon → Discovery → Probing → Impact → Verdict.
        if self.auto_mode:
            self._emit("phase_change", {"phase": 0, "name": "recon",
                                         "reason": "auto-mode start"})
            self._phase_thread = threading.Thread(
                target=self._phase_tracker, daemon=True,
                name=f"arena-{self.sid}-phase",
            )
            self._phase_thread.start()

        threads = []
        for r in self.runners:
            t = threading.Thread(
                target=r.run, daemon=True,
                name=f"arena-{self.sid}-{r.agent_id}",
            )
            t.start()
            threads.append(t)
        for t in threads:
            t.join()
        self._phase_stop.set()
        # Judge pass (optional) — blocks final-done so the SSE client sees
        # the verdict before the stream closes.
        if self.auto_mode and self.state.advance_phase(4, reason="all agents joined"):
            self._emit("phase_change", {"phase": 4, "name": "verdict",
                                         "reason": "agents finished — judge running"})
        self._run_judge()
        with self._lock:
            self.done = True
        self._persist_final()

    def _phase_tracker(self):
        """Watches SharedState every 3s and advances the phase based on
        observed assets / findings / time. Each advancement emits a
        `phase_change` SSE event so the UI's progress bar updates.

        Transition rules (Auto Mode):
          0→1 : recon    → discovery   when subdomain_count >= 1 OR 90s elapsed
          1→2 : discovery → probing    when url_count >= 1 OR 180s elapsed
          2→3 : probing  → impact      when any finding exists OR 60% of budget time elapsed
          3→4 : impact   → verdict     orchestrator handles after agents join
        """
        # Snapshot the per-agent budget (use the longest-running agent's cap).
        max_seconds = max((r.budget["max_seconds"] for r in self.runners), default=1800)
        deadline_60pct = self.started_at + (max_seconds * 0.60)

        while not self._phase_stop.is_set():
            elapsed = time.time() - self.started_at
            counts  = self.state.asset_counts()
            phase   = self.state.phase

            advanced = False
            if phase == 0 and (counts.get("subdomain", 0) >= 1 or elapsed > 90):
                reason = (f"subdomains: {counts.get('subdomain', 0)}"
                          if counts.get("subdomain", 0) else "timeout")
                advanced = self.state.advance_phase(1, reason)
                if advanced:
                    self._emit("phase_change", {"phase": 1, "name": "discovery", "reason": reason})
            elif phase == 1 and (counts.get("url", 0) >= 1 or elapsed > 180):
                reason = (f"live urls: {counts.get('url', 0)}"
                          if counts.get("url", 0) else "timeout")
                advanced = self.state.advance_phase(2, reason)
                if advanced:
                    self._emit("phase_change", {"phase": 2, "name": "probing", "reason": reason})
            elif phase == 2:
                findings_n = len(self.state.list_findings())
                if findings_n >= 1 or time.time() > deadline_60pct:
                    reason = (f"findings: {findings_n}" if findings_n
                              else "60% budget elapsed")
                    advanced = self.state.advance_phase(3, reason)
                    if advanced:
                        self._emit("phase_change", {"phase": 3, "name": "impact", "reason": reason})

            if self._phase_stop.wait(3.0):
                return

    def _run_judge(self):
        cfg = self.judge_config
        if not cfg or not cfg.get("api_key"):
            return
        try:
            with self._lock:
                events_snapshot = list(self.events)
            judge = JudgeAgent(
                provider   = cfg.get("provider", "anthropic"),
                api_key    = cfg["api_key"],
                model      = cfg.get("model", "claude-opus-4-7"),
                state      = self.state,
                agents_meta= self.agents_meta,
                events     = events_snapshot,
                emit       = self._emit,
            )
            judge.run()
            self.judge_verdict = judge.verdict
        except Exception:
            # Any failure is already emitted as judge_error by JudgeAgent;
            # never fail the whole race because the judge glitched.
            pass

    def _persist_final(self):
        try:
            findings = self.state.list_findings()
            counts   = self.state.asset_counts()
            snap     = self.state.snapshot()
            SessionManager.update(self.sid, {
                "summary": {
                    "status":    "done",
                    "findings":  len(findings),
                    "agents":    len(self.runners),
                    "target":    self.target,
                    "subdomains":counts.get("subdomain", 0),
                    "urls":      counts.get("url", 0),
                    "endpoints": counts.get("endpoint", 0),
                },
                "data": {
                    "scope":       self.scope,
                    "budget":      self.budget,
                    "agents":      self.agents_meta,
                    "findings":    findings,
                    "leaderboard": self.leaderboard(),
                    "judge":       self.judge_verdict,
                    "assets":      {k: sorted(v) if isinstance(v, (list, set)) else v
                                    for k, v in snap["assets"].items()},
                    "events":      self.events[-500:],
                },
            })
        except Exception:
            pass
