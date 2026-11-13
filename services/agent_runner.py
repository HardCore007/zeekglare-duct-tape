"""AgentRunner — drives one LLM agent through a tool-use loop.

Emits rich SSE events so the UI can render the agent's runtime behavior:

    agent_start      — agent spawned (model, target, budget)
    agent_thought    — extended-thinking block (Claude's reasoning)
    agent_text       — narrative text block (what the agent is saying)
    tool_call        — agent invoked a tool (name + args + call_id)
    tool_result      — tool returned (summary + cached flag + elapsed)
    finding          — a confirmed finding landed in the shared pool
    state_update     — shared-state counts changed (assets/findings)
    cost_update      — running token + cost counters
    agent_error      — exception during a step
    agent_done       — agent stopped (reason, totals)

Budget enforcement: max_steps, max_seconds, max_cost_usd, max_tool_calls.
The first cap hit stops the loop with `reason`.
"""
from __future__ import annotations
import time, traceback

from services.llm_client     import LLMClient
from services.agent_tools    import tool_schemas, run_tool, serialize_tool_result
from services.agent_cache    import SharedState
from services.skills.base    import guidance_block


SYSTEM_PROMPT = """You are an autonomous penetration-testing agent inside the ZeekGlare AI Arena.
Your job: investigate a target and surface real, evidence-backed security findings.

Rules of engagement:
- Target: {target}
- In-scope hosts: {scope}
- NEVER touch anything out of scope. Out-of-scope tool calls are blocked automatically.
- Think out loud briefly before each tool call so operators can follow your logic.
- Call `add_finding` only when you have concrete evidence — not speculation.
- Call `done` when you've exhausted useful avenues or hit diminishing returns.
- Another agent may be working the same target. Read the shared-state context
  each turn and avoid redoing work they already did.

Recommended flow (adapt as needed):
1. subdomain_enum — find the attack surface
2. http_probe     — identify live web hosts + tech stack
3. js_endpoints   — on interesting hosts, discover hidden API paths
4. extract_params — pull params from URLs/forms so skills have inputs to test
5. port_scan      — on interesting hosts, check non-web services
6. fetch_http     — manual probes (headers, specific paths, auth endpoints)
7. Skills         — once you have URLs+params, skill_* tools appear in your
                    list (skill_idor, skill_xss_reflected, skill_sqli, skill_lfi,
                    skill_ssrf, skill_open_redirect, skill_nosqli, skill_ssti,
                    skill_xxe, skill_rce, skill_jwt, skill_cors, skill_graphql,
                    skill_subdomain_takeover, skill_file_upload,
                    skill_request_smuggling, skill_race_condition,
                    skill_auth_bypass). They run structured probes + auto-submit
                    findings on success.
8. add_finding    — for issues you confirm manually (not via a skill)
9. done           — when you're out of productive leads

Keep tool calls focused. Prefer one deep scan over five shallow ones.
Always explain WHY before calling a tool.
"""


class AgentRunner:
    def __init__(self, *, agent_id: str, label: str,
                 provider: str, api_key: str, model: str,
                 target: str, state: SharedState,
                 emit, budget: dict, role_hint: str = "",
                 allow_exploit: bool = False):
        """
        emit(event_type: str, payload: dict) — callback to push SSE events.
        budget — {max_steps, max_seconds, max_cost_usd, max_tool_calls}
        role_hint — optional extra instruction ("focus on web app", etc.)
        allow_exploit — when True, `danger=exploit` skills become visible.
            Defaults False so exploit skills are off unless the user opts in.
        """
        self.agent_id = agent_id
        self.label    = label
        self.llm      = LLMClient(provider=provider, api_key=api_key, model=model)
        self.provider = provider
        self.model    = model
        self.target   = target
        self.state    = state
        self.emit     = emit
        self.role_hint= role_hint
        self.allow_exploit = bool(allow_exploit)
        self.budget   = {
            "max_steps":      int(budget.get("max_steps", 20)),
            "max_seconds":    int(budget.get("max_seconds", 1800)),
            "max_cost_usd":   float(budget.get("max_cost_usd", 2.0)),
            "max_tool_calls": int(budget.get("max_tool_calls", 40)),
        }
        self._stopping = False

        # Running totals
        self.step_count       = 0
        self.tool_call_count  = 0
        self.tokens_in_total  = 0
        self.tokens_out_total = 0
        self.cost_total       = 0.0
        self.started_at       = 0.0
        self.history          = []  # Anthropic-style messages

    def stop(self):
        self._stopping = True

    def run(self):
        self.started_at = time.time()
        self.emit("agent_start", {
            "agent_id": self.agent_id, "label": self.label,
            "provider": self.provider, "model": self.model,
            "target":   self.target,   "budget": dict(self.budget),
            "role_hint":self.role_hint,
        })

        # Seed conversation
        obj = f"Investigate {self.target}. Produce findings with evidence."
        if self.role_hint:
            obj += f"\n\nSpecial focus: {self.role_hint}"
        self.history = [{"role": "user", "content": obj}]

        done_reason = ""
        try:
            while True:
                if self._stopping:
                    done_reason = "stopped_by_user"; break
                if self.step_count >= self.budget["max_steps"]:
                    done_reason = "max_steps"; break
                if time.time() - self.started_at > self.budget["max_seconds"]:
                    done_reason = "max_seconds"; break
                if self.cost_total >= self.budget["max_cost_usd"]:
                    done_reason = "max_cost"; break
                if self.tool_call_count >= self.budget["max_tool_calls"]:
                    done_reason = "max_tool_calls"; break

                stopped = self._one_step()
                if stopped:
                    done_reason = stopped
                    break
        except Exception as e:
            self.emit("agent_error", {
                "agent_id": self.agent_id,
                "error":    f"{type(e).__name__}: {e}",
                "trace":    traceback.format_exc()[-1500:],
            })
            done_reason = "error"
        finally:
            self.emit("agent_done", {
                "agent_id":  self.agent_id,
                "reason":    done_reason or "unknown",
                "steps":     self.step_count,
                "tool_calls":self.tool_call_count,
                "tokens_in": self.tokens_in_total,
                "tokens_out":self.tokens_out_total,
                "cost_usd":  round(self.cost_total, 4),
                "elapsed":   round(time.time() - self.started_at, 1),
            })

    def _one_step(self):
        self.step_count += 1
        step_no = self.step_count

        system = SYSTEM_PROMPT.format(
            target=self.target, scope=", ".join(self.state.scope)
        )
        # Inject fresh shared-state context as the last user message if
        # history's tail is an assistant message — otherwise append inline.
        # Simpler: prepend it to the system prompt each call.
        ctx = self.state.reasoning_context()
        if ctx:
            system += "\n\n" + ctx
        # Phase guidance (Auto Mode) — steer the agent to the right activity.
        ph = _phase_directive(self.state)
        if ph:
            system += "\n\n" + ph
        # Per-skill hunting tips for skills that apply this turn.
        gb = guidance_block(self.state, allow_exploit=self.allow_exploit)
        if gb:
            system += "\n\n" + gb

        try:
            llm_step = self.llm.step(
                system=system,
                messages=self.history,
                tools=tool_schemas(self.state, allow_exploit=self.allow_exploit),
                max_tokens=4096,
                thinking=True,
            )
        except Exception as e:
            self.emit("agent_error", {
                "agent_id": self.agent_id,
                "error":    f"LLM call failed: {type(e).__name__}: {e}",
            })
            return "llm_error"

        # Accumulate costs
        self.tokens_in_total  += llm_step.tokens_in
        self.tokens_out_total += llm_step.tokens_out
        self.cost_total       += llm_step.cost_usd
        self.emit("cost_update", {
            "agent_id":   self.agent_id,
            "step":       step_no,
            "tokens_in":  self.tokens_in_total,
            "tokens_out": self.tokens_out_total,
            "cost_usd":   round(self.cost_total, 4),
            "step_elapsed": round(llm_step.elapsed, 2),
        })

        # Add assistant blocks to history (Anthropic requires full blocks incl thinking)
        self.history.append({"role": "assistant", "content": llm_step.blocks})

        # Emit events for each block
        tool_uses = []
        for blk in llm_step.blocks:
            t = blk.get("type")
            if t == "thinking":
                self.emit("agent_thought", {
                    "agent_id": self.agent_id,
                    "step":     step_no,
                    "text":     blk.get("thinking", ""),
                })
            elif t == "text":
                self.emit("agent_text", {
                    "agent_id": self.agent_id,
                    "step":     step_no,
                    "text":     blk.get("text", ""),
                })
            elif t == "tool_use":
                tool_uses.append(blk)

        # No tool calls → agent finished its turn without a tool
        if not tool_uses:
            if llm_step.stop_reason in ("end_turn", "stop"):
                return "end_turn"
            return "no_tool_no_text"

        # Execute tool calls, append tool_result blocks
        tool_results = []
        agent_done_signal = False
        for tu in tool_uses:
            name    = tu.get("name", "")
            args    = tu.get("input") or {}
            call_id = tu.get("id")
            self.tool_call_count += 1
            self.emit("tool_call", {
                "agent_id": self.agent_id,
                "step":     step_no,
                "call_id":  call_id,
                "tool":     name,
                "args":     args,
            })

            result = run_tool(name, args, self.state, self.agent_id,
                              allow_exploit=self.allow_exploit)

            self.emit("tool_result", {
                "agent_id":  self.agent_id,
                "step":      step_no,
                "call_id":   call_id,
                "tool":      name,
                "ok":        bool(result.get("ok")),
                "cached":    bool(result.get("_cached")),
                "elapsed":   result.get("_elapsed"),
                "summary":   _summarize_result(name, result),
                "full":      result,
            })

            # Finding event — fires for BOTH the LLM-driven add_finding tool
            # AND skill_* dispatches that auto-submit (run_skill returns
            # finding_id when its SkillResult.finding fires). We pull the
            # full record from shared state so the UI gets description +
            # evidence (PoC), not just a label.
            finding_id = result.get("finding_id")
            if finding_id and result.get("ok"):
                full = next((f for f in self.state.list_findings()
                             if f.get("id") == finding_id), None)
                if full:
                    self.emit("finding", {
                        "agent_id":      self.agent_id,
                        "finding_id":    finding_id,
                        "vuln_type":     full.get("vuln_type"),
                        "severity":      full.get("severity"),
                        "target":        full.get("target"),
                        "location":      full.get("location"),
                        "description":   full.get("description"),
                        "evidence":      full.get("evidence"),
                        "discovered_by": full.get("discovered_by"),
                        "source":        name,   # 'add_finding' or 'skill_*'
                        "duplicate":     bool(result.get("duplicate")
                                              or result.get("finding_duplicate")),
                    })

            if name == "done":
                agent_done_signal = True

            tool_results.append({
                "type":         "tool_result",
                "tool_use_id":  call_id,
                "content":      serialize_tool_result(result),
            })

        self.history.append({"role": "user", "content": tool_results})

        # Emit state snapshot
        self.emit("state_update", {
            "assets":       self.state.asset_counts(),
            "findings":     len(self.state.list_findings()),
        })

        if agent_done_signal:
            return "agent_signalled_done"
        if llm_step.stop_reason == "end_turn":
            return "end_turn"
        return ""   # continue


_PHASE_DIRECTIVES = {
    0: ("RECON",
        "FOCUS: this phase is about mapping the attack surface. Use subdomain_enum on the "
        "root target FIRST. Other tools come later — do not jump ahead. Call done only "
        "after at least one subdomain_enum has run."),
    1: ("DISCOVERY",
        "FOCUS: probe the discovered subdomains. Use http_probe to find live web hosts, "
        "then js_endpoints on the most interesting ones (login pages, admin panels, APIs) "
        "to surface hidden endpoints. Then call extract_params (deep=true) to populate "
        "the param graph — skills need URL+param pairs to work. Don't run skills yet."),
    2: ("PROBING",
        "FOCUS: now that you have URLs and params, run skill_* tools to detect "
        "vulnerabilities. Pick skills based on what's available — skill_idor on numeric "
        "IDs, skill_ssrf on URL-accepting params, skill_xss_reflected on echo'd params, "
        "skill_open_redirect on redirect-style params, skill_subdomain_takeover once. "
        "Always explain WHY before each skill call."),
    3: ("IMPACT",
        "FOCUS: verify and deepen the findings you already have. For each finding, "
        "re-issue the winning request via fetch_http and capture the full response as "
        "evidence. Hunt for higher-severity escalations (e.g. SSRF → metadata, IDOR → "
        "admin records). Only add new findings if they meaningfully extend an existing chain."),
    4: ("VERDICT",
        "FOCUS: stop adding new findings. The judge is about to grade your work. Call "
        "done with a 2-3 sentence summary of your strongest finding."),
}


def _phase_directive(state) -> str:
    """Build the phase-specific instructions block for the system prompt."""
    name_dir = _PHASE_DIRECTIVES.get(state.phase)
    if not name_dir:
        return ""
    name, directive = name_dir
    return f"Current phase: {name} ({state.phase + 1}/5)\n{directive}"


def _summarize_result(tool: str, result: dict) -> str:
    if not result.get("ok"):
        return f"FAILED: {result.get('error', 'unknown')}"
    if tool == "subdomain_enum":
        return f"Found {result.get('count')} subdomains ({result.get('new_count')} new)"
    if tool == "http_probe":
        return f"Found {result.get('live_count')} live URLs"
    if tool == "port_scan":
        hosts = result.get("results") or []
        total = sum(len(h.get("open_ports") or []) for h in hosts)
        return f"Scanned {result.get('hosts_scanned')} hosts — {total} open ports"
    if tool == "js_endpoints":
        return f"Extracted {result.get('endpoint_count')} endpoints from {len(result.get('js_files', []))} JS files"
    if tool == "fetch_http":
        return f"HTTP {result.get('status')} — {result.get('body_len')} bytes"
    if tool == "add_finding":
        return f"Finding recorded ({'co-discoverer' if result.get('duplicate') else 'first'})"
    if tool == "done":
        return result.get("summary", "")[:200]
    return "ok"
