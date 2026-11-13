from core.auth_utils import module_required
"""AI Enhancement blueprint — multi-provider scan analysis."""
import os, json
from flask import Blueprint, request, Response, stream_with_context

ai_bp = Blueprint("ai", __name__)

NVIDIA_BASE_URL = "https://integrate.api.nvidia.com/v1"
OPENAI_BASE_URL = "https://api.openai.com/v1"

# Default models per provider for analysis tasks
ANALYSIS_MODELS = {
    "anthropic": "claude-opus-4-6",
    "nvidia":    "nvidia/llama-3.1-nemotron-ultra-253b-v1",
    "openai":    "gpt-4o",
}


def _stream_ai(provider: str, api_key: str, system: str, user_msg: str, max_tokens: int = 4096):
    """Unified streaming generator for all three AI providers."""
    if provider == "anthropic":
        import anthropic
        client = anthropic.Anthropic(api_key=api_key)
        with client.messages.stream(
            model=ANALYSIS_MODELS["anthropic"],
            max_tokens=max_tokens,
            thinking={"type": "adaptive"},
            system=system,
            messages=[{"role": "user", "content": user_msg}],
        ) as stream:
            for event in stream:
                if event.type == "content_block_delta" and event.delta.type == "text_delta":
                    yield event.delta.text

    elif provider in ("nvidia", "openai"):
        from openai import OpenAI
        base_url = NVIDIA_BASE_URL if provider == "nvidia" else OPENAI_BASE_URL
        client = OpenAI(base_url=base_url, api_key=api_key)
        model = ANALYSIS_MODELS[provider]
        stream = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user",   "content": user_msg},
            ],
            max_tokens=max_tokens,
            stream=True,
        )
        for chunk in stream:
            if chunk.choices and chunk.choices[0].delta.content:
                yield chunk.choices[0].delta.content
    else:
        raise ValueError(f"Unknown provider: {provider}")


@ai_bp.route("/api/ai/test", methods=["POST"])
@module_required("ai")
def test_key():
    """Quick connection test for an AI provider key."""
    body     = request.get_json(silent=True) or {}
    provider = body.get("provider", "anthropic")
    api_key  = (body.get("api_key") or "").strip()

    if not api_key:
        return {"ok": False, "error": "No API key provided."}, 400

    try:
        if provider == "anthropic":
            import anthropic
            client = anthropic.Anthropic(api_key=api_key)
            client.messages.create(
                model="claude-haiku-4-5-20251001",
                max_tokens=1,
                messages=[{"role": "user", "content": "hi"}],
            )

        elif provider in ("nvidia", "openai"):
            from openai import OpenAI
            base_url = NVIDIA_BASE_URL if provider == "nvidia" else OPENAI_BASE_URL
            test_model = "meta/llama-3.3-70b-instruct" if provider == "nvidia" else "gpt-4o-mini"
            client = OpenAI(base_url=base_url, api_key=api_key)
            client.chat.completions.create(
                model=test_model,
                messages=[{"role": "user", "content": "hi"}],
                max_tokens=1,
            )
        else:
            return {"ok": False, "error": f"Unknown provider: {provider}"}, 400

        return {"ok": True}

    except Exception as e:
        msg = str(e)
        # Surface clean auth errors
        if "auth" in msg.lower() or "401" in msg or "invalid" in msg.lower() or "incorrect" in msg.lower():
            return {"ok": False, "error": "Invalid API key — authentication failed."}
        return {"ok": False, "error": msg[:200]}


@ai_bp.route("/api/ai-analyze", methods=["POST"])
@module_required("ai")
def ai_analyze():
    body     = request.get_json(silent=True) or {}
    context  = body.get("context", "")
    mode     = body.get("mode", "domain")
    provider = body.get("provider", "anthropic")
    api_key  = body.get("api_key") or os.environ.get(
        {"anthropic": "ANTHROPIC_API_KEY", "nvidia": "NVIDIA_API_KEY", "openai": "OPENAI_API_KEY"}.get(provider, "ANTHROPIC_API_KEY"), ""
    )

    if not api_key:
        return Response(
            json.dumps({"error": f"No API key for {provider}. Add it in Settings → AI Keys."}),
            status=400, mimetype="application/json",
        )
    if not context:
        return Response(
            json.dumps({"error": "No scan data provided for analysis."}),
            status=400, mimetype="application/json",
        )

    system_prompts = {
        "domain": (
            "You are an expert penetration tester and bug bounty hunter analyzing subdomain enumeration results. "
            "Given scan data from a Domain Mapper, identify: "
            "1) High-value targets (admin panels, dev/staging environments, API endpoints, login pages). "
            "2) Potential vulnerabilities (subdomain takeover candidates, interesting technologies, exposed services). "
            "3) Attack surface insights (cloud providers, CDN configurations, security headers gaps). "
            "4) Prioritized task list for further investigation. "
            "Be concise, actionable, and structured with clear sections. Use markdown formatting."
        ),
        "asn": (
            "You are an expert network security analyst reviewing ASN and IP range data. "
            "Given ASN intelligence data, identify: "
            "1) Critical IP ranges and exposed hosts worth targeting. "
            "2) Interesting open ports and services. "
            "3) Potential network-level vulnerabilities or misconfigurations. "
            "4) Prioritized reconnaissance tasks. "
            "Be concise, actionable, and structured. Use markdown formatting."
        ),
        "recon": (
            "You are an expert penetration tester reviewing full reconnaissance data. "
            "Analyze the recon findings and provide: "
            "1) Executive summary of the attack surface. "
            "2) Critical findings that need immediate attention. "
            "3) Technology stack analysis and version-specific vulnerabilities. "
            "4) Comprehensive prioritized task list for exploitation. "
            "Be concise, actionable, and structured. Use markdown formatting."
        ),
        "js": (
            "You are an expert penetration tester and bug bounty hunter specializing in JavaScript security analysis. "
            "Given JS Intel scan data (JS files found on live subdomains and endpoints extracted by LinkFinder), analyze and provide: "
            "1) **Sensitive Data Exposure** — flag any hardcoded API keys, tokens, secrets, passwords, or credentials found in endpoints or JS paths. "
            "2) **Hidden Endpoints** — identify internal/undocumented API routes, admin panels, debug endpoints, authentication flows (/login, /auth, /token, /oauth). "
            "3) **Attack Surface** — GraphQL endpoints, file upload/export paths, internal microservice URLs, cloud storage references (S3, Firebase, GCS). "
            "4) **Prioritized Findings** — rank each finding by severity (Critical/High/Medium/Low) with a brief exploitation note. "
            "5) **Recommended Next Steps** — specific tools/techniques to probe the most interesting endpoints. "
            "Be concise, structured with clear sections, and use markdown formatting. "
            "For each critical finding include the source JS file and the specific endpoint/secret."
        ),
    }

    system = system_prompts.get(mode, system_prompts["domain"])

    def generate():
        try:
            for text in _stream_ai(provider, api_key, system, context):
                yield f"data: {json.dumps({'type': 'text', 'text': text})}\n\n"
            yield f"data: {json.dumps({'type': 'done'})}\n\n"
        except Exception as e:
            msg = str(e)
            if "auth" in msg.lower() or "401" in msg or "invalid" in msg.lower():
                msg = f"Invalid API key for {provider}."
            yield f"data: {json.dumps({'type': 'error', 'text': msg})}\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
