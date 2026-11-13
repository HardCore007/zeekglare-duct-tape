"""SharedState — cross-agent dedup + asset graph for the AI Arena.

Single object shared across all agents in one arena session. Enforces the
five dedup layers from the design doc:

  1. Tool invocations  — cache (tool, args_hash) → result JSON
  2. Asset graph       — canonical (type, value) set: subdomain, endpoint, param, url
  3. Attack attempts   — (endpoint, param, family, technique) — for Phase 3
  4. Findings pool     — (vuln_type, target, location, evidence_hash) fingerprint
  5. Reasoning context — compact summary injected into every agent's prompt

Thread-safe via a single RLock. Methods return copies so callers don't
accidentally mutate shared state.
"""
from __future__ import annotations
import hashlib, json, threading, time, uuid
from collections import OrderedDict


def _h(obj) -> str:
    raw = json.dumps(obj, sort_keys=True, default=str)
    return hashlib.sha1(raw.encode()).hexdigest()[:16]


PHASE_NAMES = ["recon", "discovery", "probing", "impact", "verdict"]


class SharedState:
    def __init__(self, target: str, scope: list[str] | None = None):
        self.target      = target
        self.scope       = [s.strip() for s in (scope or [target]) if s and s.strip()]
        self._lock       = threading.RLock()
        self._tool_cache: "OrderedDict[str, dict]" = OrderedDict()
        self._assets:     dict[str, set]           = {
            "subdomain": set(), "endpoint": set(), "url": set(),
            "param":     set(), "tech":     set(), "port":     set(),
        }
        self._attempts:   set  = set()
        self._findings:   dict = {}   # fp → finding
        self._started_at = time.time()
        # Phase tracking — only meaningful in Auto Mode, but always available.
        # 0=recon, 1=discovery, 2=probing, 3=impact, 4=verdict.
        self.phase: int = 0
        self.phase_history: list[dict] = [{"phase": 0, "name": "recon",
                                           "ts": self._started_at, "reason": "start"}]

    # ── Layer 1 — tool invocation cache ──────────────────────────────────
    def cache_key(self, tool: str, args: dict) -> str:
        return f"{tool}:{_h(args)}"

    def get_cached(self, tool: str, args: dict):
        with self._lock:
            return self._tool_cache.get(self.cache_key(tool, args))

    def set_cached(self, tool: str, args: dict, result: dict):
        with self._lock:
            self._tool_cache[self.cache_key(tool, args)] = {
                "result":    result,
                "cached_at": time.time(),
            }
            # Cap memory — LRU eviction at 500 entries
            while len(self._tool_cache) > 500:
                self._tool_cache.popitem(last=False)

    # ── Layer 2 — asset graph ────────────────────────────────────────────
    def add_assets(self, kind: str, values) -> int:
        """Returns the number of NEW (not previously seen) values."""
        if kind not in self._assets:
            self._assets[kind] = set()
        added = 0
        with self._lock:
            for v in (values or []):
                if not v:
                    continue
                s = str(v).strip().lower()
                if not s:
                    continue
                if s not in self._assets[kind]:
                    self._assets[kind].add(s)
                    added += 1
        return added

    def get_assets(self, kind: str) -> list[str]:
        with self._lock:
            return sorted(self._assets.get(kind, set()))

    def asset_counts(self) -> dict:
        with self._lock:
            return {k: len(v) for k, v in self._assets.items()}

    # ── Layer 3 — attack attempts (used by exploit skills, Phase 3) ──────
    def try_mark_attempt(self, endpoint: str, param: str,
                         family: str, technique: str) -> bool:
        """Returns True if this is NEW (and records it); False if duplicate."""
        key = f"{endpoint}|{param}|{family}|{technique}".lower()
        with self._lock:
            if key in self._attempts:
                return False
            self._attempts.add(key)
            return True

    # ── Layer 4 — findings pool ──────────────────────────────────────────
    def add_finding(self, *, vuln_type: str, severity: str, target: str,
                    location: str, description: str, evidence: str,
                    discovered_by: str) -> dict:
        fp = _h({"t": vuln_type, "tg": target, "loc": location,
                 "ev": (evidence or "")[:200]})
        with self._lock:
            existing = self._findings.get(fp)
            if existing:
                if discovered_by not in existing["discovered_by"]:
                    existing["discovered_by"].append(discovered_by)
                existing["_duplicate"] = True
                return existing
            entry = {
                "id":           str(uuid.uuid4()),
                "fingerprint":  fp,
                "vuln_type":    vuln_type,
                "severity":     (severity or "info").lower(),
                "target":       target,
                "location":     location,
                "description":  description,
                "evidence":     evidence,
                "discovered_by":[discovered_by],
                "created_at":   time.time(),
                "_duplicate":   False,
            }
            self._findings[fp] = entry
            return entry

    def list_findings(self) -> list[dict]:
        with self._lock:
            return [dict(f) for f in self._findings.values()]

    # ── Layer 5 — compact reasoning context for prompts ──────────────────
    def reasoning_context(self, max_items_per_kind: int = 30) -> str:
        """Compact summary of shared state for injection into the LLM prompt."""
        with self._lock:
            bits = []
            counts = {k: len(v) for k, v in self._assets.items()}
            bits.append("Shared knowledge across agents:")
            bits.append(
                f"  Assets — subdomains:{counts['subdomain']}  "
                f"urls:{counts['url']}  endpoints:{counts['endpoint']}  "
                f"params:{counts['param']}  tech:{counts['tech']}  "
                f"ports:{counts['port']}"
            )
            for kind in ("subdomain", "url", "endpoint", "param", "tech", "port"):
                vals = sorted(self._assets[kind])[:max_items_per_kind]
                if vals:
                    bits.append(f"  {kind}s: {', '.join(vals)}")
            if self._findings:
                bits.append(f"  Findings so far: {len(self._findings)}")
                for f in list(self._findings.values())[:10]:
                    bits.append(
                        f"    - [{f['severity'].upper()}] "
                        f"{f['vuln_type']} on {f['location']} "
                        f"(by {','.join(f['discovered_by'])})"
                    )
            if self._attempts:
                bits.append(f"  Prior attack attempts: {len(self._attempts)} — do not repeat them.")
            return "\n".join(bits)

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "target":      self.target,
                "scope":       list(self.scope),
                "assets":      {k: sorted(v) for k, v in self._assets.items()},
                "findings":    [dict(f) for f in self._findings.values()],
                "tool_cache_size": len(self._tool_cache),
                "attempts":    len(self._attempts),
                "elapsed":     time.time() - self._started_at,
            }

    # ── Phase machine ─────────────────────────────────────────────────────
    def advance_phase(self, new_phase: int, reason: str = "") -> bool:
        """Advance the shared phase counter monotonically. Returns True if
        the phase actually changed. Older phases never re-enter."""
        with self._lock:
            if new_phase <= self.phase:
                return False
            self.phase = new_phase
            self.phase_history.append({
                "phase":  new_phase,
                "name":   PHASE_NAMES[new_phase] if 0 <= new_phase < len(PHASE_NAMES) else f"p{new_phase}",
                "ts":     time.time(),
                "reason": reason,
            })
            return True

    def phase_name(self) -> str:
        return PHASE_NAMES[self.phase] if 0 <= self.phase < len(PHASE_NAMES) else f"p{self.phase}"

    # ── Scope enforcement (used by tool handlers before hitting target) ──
    def in_scope(self, host_or_url: str) -> bool:
        if not host_or_url:
            return False
        from urllib.parse import urlparse
        h = host_or_url.strip().lower()
        if "://" in h:
            h = (urlparse(h).hostname or "").lower()
        for s in self.scope:
            s = s.lower().lstrip(".")
            if h == s or h.endswith("." + s):
                return True
        return False
