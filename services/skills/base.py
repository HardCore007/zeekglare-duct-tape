"""Skill base contract for AI Arena Phase 3.

A Skill is a bounded attack module the agent can invoke as a tool. Compared
to plain tools in agent_tools.py, skills:

  - Declare `applicable_when(state)` so they're only shown to the agent when
    prerequisites are met (no SkillSqli before any param is found)
  - Classify themselves by `danger` — "safe" | "active" | "exploit" — so the
    orchestrator can gate exploit skills behind an explicit authorization
  - Return a structured `SkillResult` that can auto-submit a finding on
    success (with evidence) and feeds Layer-3 dedup (attack attempts)

Skills live in `services/skills/<name>.py` and register themselves via the
`@register` decorator. The orchestrator merges skill tool schemas into the
agent's tool list each step.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Callable, Optional


SKILL_REGISTRY: dict[str, "Skill"] = {}


@dataclass
class SkillResult:
    ok: bool
    summary: str = ""
    evidence: str = ""
    # When set, the orchestrator auto-submits a finding via SharedState.
    finding: Optional[dict] = None
    # Free-form extras surfaced to the LLM in the tool_result body.
    extras: dict = field(default_factory=dict)
    # Truthy string if the skill was skipped due to dedup (Layer 3).
    deduped: str = ""
    error: str = ""

    def to_dict(self) -> dict:
        d = {
            "ok":       self.ok,
            "summary":  self.summary,
        }
        if self.evidence: d["evidence"] = self.evidence[:1000]
        if self.finding:  d["finding"]  = self.finding
        if self.extras:   d["extras"]   = self.extras
        if self.deduped:  d["deduped"]  = self.deduped
        if self.error:    d["error"]    = self.error
        return d


class Skill:
    """Override in subclasses. Subclasses set class-level metadata + run()."""
    name: str          = ""
    description: str   = ""
    input_schema: dict = {}
    danger: str        = "active"   # "safe" | "active" | "exploit"
    # Optional compact hunting guide. When the skill is applicable this
    # turn, the orchestrator injects it into the agent's system prompt
    # so the LLM has class-specific heuristics in addition to the schema.
    # Keep terse — this is a per-step token cost. 1–4 short lines.
    guidance: str      = ""

    # Prerequisites — override to gate when the skill is shown.
    @classmethod
    def applicable(cls, state) -> bool:
        return True

    @classmethod
    def tool_schema(cls) -> dict:
        return {
            "name":         cls.name,
            "description":  cls.description,
            "input_schema": cls.input_schema,
        }

    # Layer-3 dedup: skills return (endpoint, param, family, technique). The
    # orchestrator calls state.try_mark_attempt() before run() and short-
    # circuits with `deduped=...` when the same attempt was already tried.
    @classmethod
    def dedup_key(cls, args: dict) -> Optional[tuple[str, str, str, str]]:
        return None

    @classmethod
    def run(cls, args: dict, state, agent_id: str) -> SkillResult:
        raise NotImplementedError


def register(cls):
    """Decorator — registers a Skill subclass in SKILL_REGISTRY."""
    if not getattr(cls, "name", ""):
        raise ValueError(f"Skill {cls.__name__} missing `name` attribute")
    if cls.name in SKILL_REGISTRY:
        raise ValueError(f"Skill name collision: {cls.name}")
    SKILL_REGISTRY[cls.name] = cls
    return cls


def applicable_skills(state, *, allow_exploit: bool = False) -> list[type[Skill]]:
    """Skills an agent should see this turn, given current state + policy."""
    out = []
    for cls in SKILL_REGISTRY.values():
        if cls.danger == "exploit" and not allow_exploit:
            continue
        try:
            if cls.applicable(state):
                out.append(cls)
        except Exception:
            continue
    return out


def guidance_block(state, *, allow_exploit: bool = False) -> str:
    """Compact per-skill hunting tips for injection into the system prompt.

    Only the tips for currently-applicable skills are returned, so context
    cost scales with surface area, not the registry size.
    """
    bits = []
    for cls in applicable_skills(state, allow_exploit=allow_exploit):
        if cls.guidance:
            bits.append(f"  • {cls.name}: {cls.guidance.strip()}")
    if not bits:
        return ""
    return "Skill hunting tips:\n" + "\n".join(bits)


def run_skill(name: str, args: dict, state, agent_id: str,
              *, allow_exploit: bool = False) -> dict:
    """Dispatch — scope check, dedup check, run, auto-submit finding."""
    cls = SKILL_REGISTRY.get(name)
    if not cls:
        return {"ok": False, "error": f"unknown skill: {name}"}
    if cls.danger == "exploit" and not allow_exploit:
        return {"ok": False, "error": f"skill '{name}' requires exploit authorization"}

    # Layer 3 dedup — don't rerun identical attempt fingerprints.
    dk = cls.dedup_key(args) or None
    if dk:
        endpoint, param, family, technique = dk
        if not state.try_mark_attempt(endpoint, param, family, technique):
            return {
                "ok":      True,
                "skipped": True,
                "deduped": f"{family}/{technique} already tried on {endpoint}?{param}",
                "summary": "Duplicate attempt — another agent tried this already.",
            }

    try:
        result = cls.run(args, state, agent_id)
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}

    d = result.to_dict()
    # Auto-submit a finding if the skill flagged one.
    if result.ok and result.finding:
        f = dict(result.finding)
        f.setdefault("discovered_by", agent_id)
        entry = state.add_finding(
            vuln_type     = f.get("vuln_type", cls.name),
            severity      = f.get("severity", "medium"),
            target        = f.get("target", ""),
            location      = f.get("location", ""),
            description   = f.get("description", ""),
            evidence      = f.get("evidence", result.evidence),
            discovered_by = agent_id,
        )
        d["finding_id"]       = entry["id"]
        d["finding_duplicate"] = entry.get("_duplicate", False)
    return d
