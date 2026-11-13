"""JudgeAgent — end-of-race LLM critic for the AI Arena.

After all agents have stopped, the orchestrator spawns a JudgeAgent with the
race transcript + every finding. The judge makes one LLM call (no tool use,
no streaming) that:

  1. Scores each finding's evidence quality (0–5) and assesses whether the
     severity rating is right
  2. Scores each agent (0–100) on evidence rigor, severity accuracy,
     novelty, and efficiency
  3. Picks a winner and explains why
  4. Lists actionable next steps for the human operator

The judge returns strict JSON — we parse it tolerantly (stripping ```json
fences) and emit:

    judge_start    — judge spawned (provider, model)
    judge_verdict  — full structured verdict (parsed JSON)
    judge_error    — exception or parse failure (raw response included)

Persists to session.data.judge so Report Builder can include the verdict.
"""
from __future__ import annotations
import json, re, time, traceback
from services.llm_client import LLMClient


SYSTEM_PROMPT = """You are the ZeekGlare AI Arena Judge.

Multiple AI agents just investigated a target. Your job is to evaluate their
work like a senior security engineer reviewing junior pentesters' reports.

You receive:
  - The full list of findings each agent submitted (with evidence)
  - Per-agent statistics (steps, tool calls, cost, time)
  - The shared asset graph the agents built collaboratively
  - A condensed event timeline per agent (their tool calls and key text)

Evaluate strictly. Reward:
  - Concrete reproducible evidence (HTTP responses, payload+response pairs)
  - Accurate severity (a 200 OK on /robots.txt is NOT critical)
  - Novelty (genuinely new attack surface vs duplicating shared knowledge)
  - Efficient tool use (one focused scan beats five shallow ones)

Penalize:
  - Speculative findings without concrete evidence
  - Severity inflation
  - Wasting budget on already-cached results
  - Findings that are just restating the recon output

Return STRICT JSON (no markdown fences, no commentary outside JSON) matching
this schema exactly:

{
  "summary":        "1-3 paragraph markdown analysis of the race overall",
  "winner_agent_id": "a1",
  "winner_reason":  "1-2 sentences explaining the choice",
  "agents": [
    {
      "agent_id":  "a1",
      "score":     0-100,
      "breakdown": {"evidence": 0-5, "severity": 0-5, "novelty": 0-5, "efficiency": 0-5},
      "feedback":  "2-3 sentences of specific praise/critique"
    }
  ],
  "findings": [
    {
      "finding_id":          "uuid-from-input",
      "evidence_quality":    0-5,
      "severity_assessment": "agree" | "overrated" | "underrated",
      "true_severity":       "critical" | "high" | "medium" | "low" | "info",
      "notes":               "1-2 sentences"
    }
  ],
  "next_steps": ["actionable string", ...]
}
"""


class JudgeAgent:
    def __init__(self, *, provider: str, api_key: str, model: str,
                 state, agents_meta: list, events: list, emit):
        self.provider     = provider
        self.api_key      = api_key
        self.model        = model
        self.state        = state
        self.agents_meta  = agents_meta
        self.events       = events
        self.emit         = emit
        self.verdict: dict | None = None

    def run(self):
        self.emit("judge_start", {"provider": self.provider, "model": self.model})

        try:
            findings  = self.state.list_findings()
            transcript = _build_transcript(self.events, self.agents_meta)
            agent_stats = _per_agent_stats(self.events, self.agents_meta)
            asset_counts = self.state.asset_counts()

            user_msg = (
                f"## Target\n{self.state.target}\n"
                f"Scope: {', '.join(self.state.scope)}\n\n"
                f"## Asset graph\n{json.dumps(asset_counts)}\n\n"
                f"## Agents\n{json.dumps(self.agents_meta, indent=2)}\n\n"
                f"## Per-agent statistics\n{json.dumps(agent_stats, indent=2)}\n\n"
                f"## Findings ({len(findings)} total)\n{json.dumps(findings, indent=2, default=str)}\n\n"
                f"## Condensed transcript (per agent)\n{transcript}\n\n"
                "Now evaluate. Return strict JSON per the schema."
            )

            client = LLMClient(provider=self.provider, api_key=self.api_key,
                               model=self.model)
            llm_step = client.step(
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_msg}],
                tools=[],
                max_tokens=6144,
                thinking=True,   # Opus/Sonnet — extended thinking aids fair grading
            )

            raw = "".join(b.get("text", "") for b in llm_step.blocks
                          if b.get("type") == "text").strip()
            verdict = _parse_json_lenient(raw)
            if verdict is None:
                self.emit("judge_error", {
                    "error": "Could not parse judge JSON output",
                    "raw":   raw[:2000],
                    "tokens_in":  llm_step.tokens_in,
                    "tokens_out": llm_step.tokens_out,
                    "cost_usd":   round(llm_step.cost_usd, 4),
                })
                return

            self.verdict = verdict
            self.emit("judge_verdict", {
                "verdict":    verdict,
                "tokens_in":  llm_step.tokens_in,
                "tokens_out": llm_step.tokens_out,
                "cost_usd":   round(llm_step.cost_usd, 4),
                "elapsed":    round(llm_step.elapsed, 2),
            })
        except Exception as e:
            self.emit("judge_error", {
                "error": f"{type(e).__name__}: {e}",
                "trace": traceback.format_exc()[-1500:],
            })


# ── Helpers ──────────────────────────────────────────────────────────────────

def _parse_json_lenient(s: str) -> dict | None:
    """Try several recovery strategies before giving up on the LLM's JSON."""
    if not s:
        return None
    # Strip markdown fences if present.
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", s, re.S)
    if fenced:
        s = fenced.group(1)
    # First: direct parse.
    try:
        return json.loads(s)
    except Exception:
        pass
    # Second: find the largest {...} substring and try that.
    first = s.find("{")
    last  = s.rfind("}")
    if first >= 0 and last > first:
        candidate = s[first : last + 1]
        try:
            return json.loads(candidate)
        except Exception:
            return None
    return None


def _per_agent_stats(events: list, agents_meta: list) -> dict:
    out: dict[str, dict] = {}
    for a in agents_meta:
        aid = a["agent_id"]
        out[aid] = {
            "label":    a.get("label", aid),
            "model":    a.get("model", ""),
            "provider": a.get("provider", ""),
            "steps":    0, "tool_calls": 0, "tokens": 0,
            "cost":     0.0, "elapsed": 0,
            "findings": 0, "tools_used": {},
        }
    for ev in events:
        aid = ev.get("agent_id"); rec = out.get(aid) if aid else None
        if not rec:
            continue
        t = ev.get("type")
        if t == "tool_call":
            rec["tool_calls"] += 1
            rec["tools_used"][ev.get("tool", "?")] = \
                rec["tools_used"].get(ev.get("tool", "?"), 0) + 1
        elif t == "cost_update":
            rec["tokens"] = (ev.get("tokens_in") or 0) + (ev.get("tokens_out") or 0)
            rec["cost"]   = ev.get("cost_usd") or rec["cost"]
            rec["steps"]  = max(rec["steps"], ev.get("step") or 0)
        elif t == "finding" and not ev.get("duplicate"):
            rec["findings"] += 1
        elif t == "agent_done":
            rec["elapsed"] = ev.get("elapsed") or rec["elapsed"]
    return out


def _build_transcript(events: list, agents_meta: list,
                      max_per_agent: int = 30) -> str:
    """Compact per-agent timeline — text + tool_call summaries only.

    Caps each agent at `max_per_agent` events to keep token cost bounded.
    """
    by_agent: dict[str, list[str]] = {}
    for a in agents_meta:
        by_agent[a["agent_id"]] = []

    for ev in events:
        aid = ev.get("agent_id")
        if aid not in by_agent:
            continue
        t = ev.get("type")
        if t == "agent_text":
            by_agent[aid].append(f"  [step {ev.get('step')}] TEXT: {(ev.get('text') or '')[:200]}")
        elif t == "tool_call":
            args_short = json.dumps(ev.get("args") or {}, default=str)[:160]
            by_agent[aid].append(f"  [step {ev.get('step')}] TOOL {ev.get('tool')}({args_short})")
        elif t == "tool_result":
            ok = "✓" if ev.get("ok") else "✗"
            by_agent[aid].append(f"  [step {ev.get('step')}] {ok} {(ev.get('summary') or '')[:160]}")
        elif t == "finding":
            by_agent[aid].append(
                f"  [step {ev.get('step')}] FINDING {ev.get('severity', '?').upper()} "
                f"{ev.get('vuln_type','')} @ {ev.get('location','')}"
                + (" (dup)" if ev.get("duplicate") else "")
            )

    parts = []
    for a in agents_meta:
        aid  = a["agent_id"]
        rows = by_agent[aid][-max_per_agent:]
        if not rows:
            parts.append(f"{aid} ({a.get('label','')}): (no transcript)")
            continue
        parts.append(f"{aid} ({a.get('label','')}):\n" + "\n".join(rows))
    return "\n\n".join(parts)
