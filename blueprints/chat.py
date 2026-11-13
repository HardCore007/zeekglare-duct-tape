from core.auth_utils import module_required
"""Chat blueprint — multi-LLM conversational intelligence with project context."""
import json, os
from flask import Blueprint, request, Response, stream_with_context

chat_bp = Blueprint("chat", __name__)

# ── Provider configs ──────────────────────────────────────────────────────────

NVIDIA_BASE_URL = "https://integrate.api.nvidia.com/v1"
OPENAI_BASE_URL = "https://api.openai.com/v1"

PROVIDER_MODELS = {
    "anthropic": [
        {"id": "claude-opus-4-6",   "label": "Claude Opus 4.6"},
        {"id": "claude-sonnet-4-6", "label": "Claude Sonnet 4.6"},
        {"id": "claude-haiku-4-5",  "label": "Claude Haiku 4.5"},
    ],
    "nvidia": [
        {"id": "deepseek-ai/deepseek-v3.2",                          "label": "DeepSeek V3.2"},
        {"id": "deepseek-ai/deepseek-r1",                            "label": "DeepSeek R1"},
        {"id": "nvidia/llama-3.1-nemotron-ultra-253b-v1",            "label": "Nemotron Ultra 253B"},
        {"id": "nvidia/llama-3.3-nemotron-super-49b-v1",             "label": "Nemotron Super 49B"},
        {"id": "meta/llama-3.3-70b-instruct",                        "label": "Llama 3.3 70B"},
        {"id": "mistralai/mixtral-8x22b-instruct-v0.1",              "label": "Mixtral 8x22B"},
        {"id": "qwen/qwen2.5-coder-32b-instruct",                    "label": "Qwen2.5 Coder 32B"},
        {"id": "google/gemma-3-27b-it",                              "label": "Gemma 3 27B"},
    ],
    "openai": [
        {"id": "gpt-4o",            "label": "GPT-4o"},
        {"id": "gpt-4o-mini",       "label": "GPT-4o mini"},
        {"id": "o3-mini",           "label": "o3-mini"},
        {"id": "o1",                "label": "o1"},
        {"id": "gpt-4-turbo",       "label": "GPT-4 Turbo"},
    ],
}

SYSTEM_BASE = """You are ZeekGlare AI — an expert cybersecurity intelligence assistant embedded in the ZeekGlare OSINT & recon platform. You help operators analyze scan results, identify attack surfaces, prioritize targets, and plan penetration testing engagements. Be concise, technical, and actionable. Use markdown formatting.

## PLATFORM OVERVIEW
ZeekGlare is a full-stack OSINT & attack surface management platform with the following modules:

### Core Intelligence Views
- **Domain Mapper** — Subdomain enumeration using 20+ sources: crt.sh, DNS brute-force, Shodan, SecurityTrails, Censys, ZoomEye, FOFA, NetworksDB, GitHub dorks, C99, Chaos, Netlas, VirusTotal, PDCP, GitLab. HTTP probing for live host detection. JS Intel (endpoint extraction via LinkFinder). AI Analyze for instant attack surface reports. Caido & Burp Suite proxy integration to push live hosts for manual testing.
- **ASN Intelligence** — Country-level or direct ASN mapping. Data sources: RIPE Stat, BGPView, CAIDA AS Rank (global rank + routing cone), Shodan, SecurityTrails, NetworksDB, rDNS. Per-ASN detail modal with CAIDA rank, routing cone size, and one-click external links: RIPEstat, BGPView, bgp.he.net, CAIDA AS Rank, NLNOG Looking Glass, RIPE Atlas, SecurityTrails. AI analysis of ASN results.
- **Port Scanner** — nmap / masscan / rustscan with profiles (common, top100, top1000, full). Multi-target parallel scanning.
- **DNS & SSL** — Full DNS record enumeration (A, AAAA, MX, TXT, NS, CNAME, SOA), SSL certificate inspection, zone transfer attempts.
- **OSINT** — Email harvesting, breach data, LinkedIn, social media, GitHub dorks, Shodan/Censys queries, WHOIS.
- **IP Scope** — Reverse IP lookup, ASN-to-CIDR mapping, geolocation, hosting provider enrichment.
- **Crawler** — Recursive web crawler with JS endpoint extraction, form discovery, login page detection, technology fingerprinting.
- **ParamHawk** — Passive & active parameter discovery (Arjun, waybackurls, GAU, x8).
- **PathStorm** — Directory & path fuzzing (ffuf, feroxbuster, gobuster, dirsearch) with custom wordlists.
- **WPScan** — WordPress-specific enumeration: plugins, themes, users, vulnerabilities.
- **ThreatBlitz** — Vulnerability scanning with nuclei, nikto, sqlmap. Template-based scanning with severity filtering.
- **ReconFTW** — Full recon automation framework integration for comprehensive target reconnaissance.
- **ProjectDiscovery Cloud** — PDCP integration for cloud-based scanning and asset management.
- **Dorking** — Google/Bing/GitHub dork generation and execution for target intelligence.

### Companion Dashboards (separate ports)
- **Xpl03tEr** (port 5001) — Exploitation toolkit dashboard. Organized by category (web, network, cloud, etc.). Runs tools against targets from ZeekGlare sessions. Auto-syncs session data from ZeekGlare.
- **Misc Tools** (port 5002) — Miscellaneous bug bounty tools dashboard (100+ tools from awesome-bugbounty-tools). Active session selector, live target picker, parallel execution across all subdomains, real-time streaming output with per-target color coding and progress tracking.

### Integrations
- **Caido Proxy** — Route live hosts through Caido proxy (populates history/sitemap) and update project scope via GraphQL API.
- **Burp Suite** — Route live hosts through Burp proxy + update Target Scope via REST API (port 1337).
- **Telegram Bot** — Notification bot for scan alerts and completion events.
- **AI Providers** — Anthropic (Claude Opus/Sonnet/Haiku), NVIDIA NIM (DeepSeek, Nemotron, Llama, Mixtral), OpenAI (GPT-4o, o1, o3). Any key works — platform auto-selects first available provider.

### Sessions System
All scans save sessions with full data: subdomains (entries[].domain), live hosts (top_targets[].domain), URLs, technologies, port results. Sessions sync automatically to Xpl03tEr and Misc Tools dashboards.

### Scheduler
Automated recurring scans via cron-based scheduler for Domain Mapper, Port Scanner, and other tools.

## PLATFORM CONTROL
When the user asks you to perform a platform action (navigate, start a scan, open a tool, etc.), append ONE JSON command block at the very END of your response:
<ZG_ACTION>{"action":"ACTION_NAME","params":{...}}</ZG_ACTION>

Available actions:
- switchView — {"view": "global|asn|domain|crawler|recon|dns|ports|osint|pd|scheduler|sessions|feed|dorking|paramhawk|ipscope|pathstorm|wpscan|threatblitz|chat|settings"}
- startDomainScan — {"domain": "example.com"}
- startAsnScan — {"country": "US"} OR {"asns": ["13335", "15169"]}
- startPortScan — {"targets": ["host1","host2"], "tool": "nmap", "profile": "common|top100|top1000|full"}
- startDnsScan — {"domain": "example.com"}
- startReconScan — {"domain": "example.com"}
- startCrawl — {"domain": "example.com"}
- startParamScan — {"targets": ["https://example.com"]}
- startIpScan — {"domain": "example.com"}
- openXploiter — {} (opens Xpl03tEr dashboard in new tab)
- openMiscTools — {} (opens Misc Tools dashboard in new tab)
- notify — {"message": "text", "level": "info|success|error"}

Rules: Only include an action when the user explicitly requests it. Only one action per response. Never explain or mention the action tag in your text."""


@chat_bp.route("/api/chat/models")
@module_required("chat")
def get_models():
    return {"providers": PROVIDER_MODELS}


@chat_bp.route("/api/chat", methods=["POST"])
@module_required("chat")
def chat():
    body     = request.get_json(silent=True) or {}
    provider = body.get("provider", "anthropic")
    model    = body.get("model", "")
    messages = body.get("messages", [])   # [{role, content}]
    context  = body.get("context", "")   # injected project data
    api_key  = body.get("api_key", "") or os.environ.get(_env_key(provider), "")

    if not api_key:
        return Response(
            _err_stream(f"No API key for {provider}. Add it in Settings."),
            mimetype="text/event-stream"
        )
    if not messages:
        return Response(
            _err_stream("No messages provided."),
            mimetype="text/event-stream"
        )
    if not model:
        return Response(
            _err_stream("No model selected."),
            mimetype="text/event-stream"
        )

    system = body.get("system_override") or SYSTEM_BASE
    if context:
        system += f"\n\n--- CURRENT PROJECT DATA ---\n{context}\n--- END PROJECT DATA ---"

    if provider == "anthropic":
        gen = _stream_anthropic(api_key, model, messages, system)
    elif provider in ("nvidia", "openai"):
        base_url = NVIDIA_BASE_URL if provider == "nvidia" else OPENAI_BASE_URL
        gen = _stream_openai_compat(api_key, model, messages, system, base_url, provider)
    else:
        gen = _err_stream(f"Unknown provider: {provider}")

    return Response(
        stream_with_context(gen),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── Provider streaming helpers ────────────────────────────────────────────────

def _stream_anthropic(api_key, model, messages, system):
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=api_key)
        # Filter to only user/assistant messages; strip any system role
        msgs = [m for m in messages if m.get("role") in ("user", "assistant")]
        with client.messages.stream(
            model=model,
            max_tokens=8192,
            system=system,
            messages=msgs,
        ) as stream:
            for event in stream:
                if event.type == "content_block_delta" and event.delta.type == "text_delta":
                    yield _data({"type": "text", "text": event.delta.text})
        yield _data({"type": "done"})
    except Exception as e:
        yield _data({"type": "error", "text": str(e)})


def _stream_openai_compat(api_key, model, messages, system, base_url, provider):
    try:
        from openai import OpenAI
        client = OpenAI(api_key=api_key, base_url=base_url)
        all_msgs = [{"role": "system", "content": system}]
        all_msgs += [m for m in messages if m.get("role") in ("user", "assistant")]

        # DeepSeek V3.2 via NVIDIA supports thinking mode
        extra = {}
        if provider == "nvidia" and "deepseek" in model.lower():
            extra["extra_body"] = {"chat_template_kwargs": {"thinking": True}}

        stream = client.chat.completions.create(
            model=model,
            messages=all_msgs,
            temperature=0.7,
            top_p=0.95,
            max_tokens=8192,
            stream=True,
            **extra,
        )
        for chunk in stream:
            if not getattr(chunk, "choices", None):
                continue
            delta = chunk.choices[0].delta
            # Reasoning content (DeepSeek thinking)
            reasoning = getattr(delta, "reasoning_content", None)
            if reasoning:
                yield _data({"type": "thinking", "text": reasoning})
            if delta.content:
                yield _data({"type": "text", "text": delta.content})
        yield _data({"type": "done"})
    except Exception as e:
        yield _data({"type": "error", "text": str(e)})


def _data(obj):
    return f"data: {json.dumps(obj)}\n\n"


def _err_stream(msg):
    def _gen():
        yield f"data: {json.dumps({'type':'error','text':msg})}\n\n"
    return _gen()


def _env_key(provider):
    return {
        "anthropic": "ANTHROPIC_API_KEY",
        "nvidia":    "NVIDIA_API_KEY",
        "openai":    "OPENAI_API_KEY",
    }.get(provider, "")
