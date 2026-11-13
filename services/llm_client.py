"""LLM client with tool-use support for the AI Arena.

Provider-agnostic facade: supports Anthropic Claude (extended thinking +
tool use), OpenAI function calling, and NVIDIA NIM via the OpenAI-compatible
endpoint at https://integrate.api.nvidia.com/v1.

The output of every `step()` is a normalized `LLMStep` with:

    blocks  : list[dict] — exact block dicts as returned by the provider
              (type: text | thinking | tool_use). Safe to append directly to
              an Anthropic `messages` history and re-send.
    stop_reason, tokens_in, tokens_out, cost_usd, elapsed

The caller is responsible for:
  - Executing tool calls and appending tool_result blocks to history
  - Enforcing budget caps (we just report cost/tokens)

Visibility: thinking blocks are preserved and returned — the runner streams
them as `agent_thought` SSE events so the UI can show Claude's reasoning.
"""
from __future__ import annotations
import json, time
from dataclasses import dataclass, field

# ── Approx pricing (USD per 1M tokens) — for budget/telemetry only ──────────
_COSTS = {
    "claude-opus-4-7":   (15.0, 75.0),
    "claude-opus-4-6":   (15.0, 75.0),
    "claude-sonnet-4-6": ( 3.0, 15.0),
    "claude-haiku-4-5":  ( 1.0,  5.0),
    "gpt-4o":            ( 2.5, 10.0),
    "gpt-4o-mini":       ( 0.15, 0.60),
    "o3-mini":           ( 1.1,  4.4),
    "o1":                (15.0, 60.0),
    # NVIDIA NIM — published per-token pricing on build.nvidia.com (USD/1M).
    "meta/llama-3.3-70b-instruct":                ( 0.20, 0.20),
    "nvidia/llama-3.3-nemotron-super-49b-v1":     ( 0.20, 0.40),
    "nvidia/llama-3.1-nemotron-ultra-253b-v1":    ( 0.60, 1.80),
    "mistralai/mixtral-8x22b-instruct-v0.1":      ( 1.20, 1.20),
    "deepseek-ai/deepseek-v3.2":                  ( 0.27, 1.10),
    "deepseek-ai/deepseek-r1":                    ( 0.55, 2.20),
}

NVIDIA_BASE_URL = "https://integrate.api.nvidia.com/v1"


def _cost(model: str, tin: int, tout: int) -> float:
    key = model.split(":")[0]
    # Match by prefix — API model IDs often carry date suffixes
    for k, rates in _COSTS.items():
        if key.startswith(k) or k in key:
            return (tin * rates[0] + tout * rates[1]) / 1_000_000
    return (tin * 3.0 + tout * 15.0) / 1_000_000  # conservative fallback


@dataclass
class LLMStep:
    blocks: list = field(default_factory=list)  # list[dict]
    stop_reason: str = ""
    tokens_in: int = 0
    tokens_out: int = 0
    cost_usd: float = 0.0
    elapsed: float = 0.0


class LLMClient:
    def __init__(self, provider: str, api_key: str, model: str):
        self.provider = (provider or "").lower()
        self.api_key  = api_key
        self.model    = model

    def step(self, system: str, messages: list, tools: list,
             max_tokens: int = 4096, thinking: bool = True) -> LLMStep:
        t0 = time.time()
        if self.provider == "anthropic":
            st = self._step_anthropic(system, messages, tools, max_tokens, thinking)
        elif self.provider == "openai":
            st = self._step_openai(system, messages, tools, max_tokens,
                                   base_url=None, capture_reasoning=False)
        elif self.provider == "nvidia":
            st = self._step_openai(system, messages, tools, max_tokens,
                                   base_url=NVIDIA_BASE_URL,
                                   capture_reasoning="deepseek" in self.model.lower())
        else:
            raise ValueError(f"unsupported provider: {self.provider}")
        st.elapsed = time.time() - t0
        st.cost_usd = _cost(self.model, st.tokens_in, st.tokens_out)
        return st

    # ── Anthropic ─────────────────────────────────────────────────────────
    def _step_anthropic(self, system, messages, tools, max_tokens, thinking):
        import anthropic
        client = anthropic.Anthropic(api_key=self.api_key)

        params = dict(
            model=self.model,
            max_tokens=max(max_tokens, 4096),
            system=system,
            messages=messages,
        )
        if tools:
            params["tools"] = [_anthropic_tool(t) for t in tools]

        # Extended thinking — gives us reasoning visibility. Haiku / 4.5
        # family and below don't support it; detect conservatively.
        if thinking and ("opus" in self.model or "sonnet" in self.model):
            params["thinking"] = {"type": "enabled", "budget_tokens": 2048}
            # When thinking is enabled, temp / top_p must be default.
            params["max_tokens"] = max(params["max_tokens"], 6144)

        resp = client.messages.create(**params)
        blocks = []
        for b in resp.content:
            bt = getattr(b, "type", "")
            if bt == "text":
                blocks.append({"type": "text", "text": b.text})
            elif bt == "thinking":
                blocks.append({
                    "type":      "thinking",
                    "thinking":  getattr(b, "thinking", ""),
                    "signature": getattr(b, "signature", ""),
                })
            elif bt == "redacted_thinking":
                blocks.append({
                    "type": "redacted_thinking",
                    "data": getattr(b, "data", ""),
                })
            elif bt == "tool_use":
                blocks.append({
                    "type":  "tool_use",
                    "id":    b.id,
                    "name":  b.name,
                    "input": b.input,
                })
        return LLMStep(
            blocks=blocks,
            stop_reason=resp.stop_reason or "",
            tokens_in=resp.usage.input_tokens,
            tokens_out=resp.usage.output_tokens,
        )

    # ── OpenAI-compatible (OpenAI + NVIDIA NIM) ───────────────────────────
    def _step_openai(self, system, messages, tools, max_tokens,
                     base_url=None, capture_reasoning=False):
        # Translate Anthropic-style `messages` → OpenAI chat format and
        # normalize function calls back into our block dict shape.
        from openai import OpenAI
        client = OpenAI(api_key=self.api_key, base_url=base_url) if base_url \
                 else OpenAI(api_key=self.api_key)
        oa_msgs = _to_openai_messages(system, messages)
        oa_tools = [{
            "type": "function",
            "function": {
                "name":        t["name"],
                "description": t["description"],
                "parameters":  t["input_schema"],
            },
        } for t in tools]

        kwargs = dict(
            model=self.model,
            messages=oa_msgs,
            tools=oa_tools or None,
            max_tokens=max_tokens,
        )
        if capture_reasoning:
            # DeepSeek (via NIM) — turn on chain-of-thought mode.
            kwargs["extra_body"] = {"chat_template_kwargs": {"thinking": True}}

        resp = client.chat.completions.create(**kwargs)
        choice = resp.choices[0]
        msg    = choice.message
        blocks = []
        # Reasoning trace, if the provider exposes one (DeepSeek).
        reasoning = getattr(msg, "reasoning_content", None)
        if reasoning:
            blocks.append({"type": "thinking", "thinking": reasoning, "signature": ""})
        if msg.content:
            blocks.append({"type": "text", "text": msg.content})
        for tc in (msg.tool_calls or []):
            try:
                args = json.loads(tc.function.arguments or "{}")
            except Exception:
                args = {}
            blocks.append({
                "type":  "tool_use",
                "id":    tc.id,
                "name":  tc.function.name,
                "input": args,
            })
        return LLMStep(
            blocks=blocks,
            stop_reason=choice.finish_reason or "",
            tokens_in=resp.usage.prompt_tokens,
            tokens_out=resp.usage.completion_tokens,
        )


def _anthropic_tool(t: dict) -> dict:
    return {
        "name":         t["name"],
        "description":  t["description"],
        "input_schema": t["input_schema"],
    }


def _to_openai_messages(system: str, messages: list) -> list:
    out = [{"role": "system", "content": system}]
    for m in messages:
        role = m.get("role")
        content = m.get("content")
        if role == "user":
            # content may be string or list of tool_result blocks
            if isinstance(content, str):
                out.append({"role": "user", "content": content})
            else:
                for blk in content:
                    if blk.get("type") == "tool_result":
                        out.append({
                            "role":         "tool",
                            "tool_call_id": blk.get("tool_use_id"),
                            "content":      str(blk.get("content", "")),
                        })
        elif role == "assistant":
            text_parts = []
            tool_calls = []
            for blk in (content or []):
                if blk.get("type") == "text":
                    text_parts.append(blk.get("text", ""))
                elif blk.get("type") == "tool_use":
                    tool_calls.append({
                        "id":   blk["id"],
                        "type": "function",
                        "function": {
                            "name":      blk["name"],
                            "arguments": json.dumps(blk.get("input") or {}),
                        },
                    })
            entry = {"role": "assistant", "content": "\n".join(text_parts) or None}
            if tool_calls:
                entry["tool_calls"] = tool_calls
            out.append(entry)
    return out
