"""Skills package — bounded attack modules exposed to arena agents.

Each skill is a subclass of `Skill` (services.skills.base). The orchestrator
shows an agent only the skills whose `applicable(state)` returns True this
turn, so e.g. SkillSqli doesn't appear before any parameters are known.

Import side-effects register skills into SKILL_REGISTRY.
"""
from services.skills.base import Skill, SkillResult, SKILL_REGISTRY, register
from services.skills import (   # noqa: F401 — import-side-effect registers each
    idor, auth_bypass,
    ssrf, xss_reflected, open_redirect, cors, jwt, subdomain_takeover,
    sqli, ssti, xxe, rce, graphql,
    nosqli, lfi, file_upload, request_smuggling, race_condition,
    csrf, access_control, api_testing, js_secrets,
)

__all__ = ["Skill", "SkillResult", "SKILL_REGISTRY", "register"]
