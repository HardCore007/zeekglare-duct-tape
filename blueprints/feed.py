from core.auth_utils import module_required
"""X/Twitter Feed blueprint — live cyber intelligence feed with AI analysis."""
import os, json, time, re
from flask import Blueprint, request, jsonify, Response, stream_with_context

feed_bp = Blueprint("feed", __name__)

# Simple in-process cache to avoid hammering rate limits
_cache = {"tweets": [], "ts": 0}
_CACHE_TTL = 90  # seconds

# ── Keyword detection ─────────────────────────────────────────────────────────

_CATS = {
    "cve":       re.compile(r'CVE-\d{4}-\d+|zero.?day|0day|RCE|remote code|arbitrary code|sql inject|xss|ssrf|lfi|rfi|path travers|privilege escal|auth bypass|buffer overflow|heap overflow|use.after.free|out.of.bounds', re.I),
    "bugbounty": re.compile(r'bug.?bounty|hackerone|bugcrowd|intigriti|synack|responsible.disclosure|hall.of.fame|bounty.program|subdomain.takeover|open.redirect|recon.tip|recon method', re.I),
    "exploit":   re.compile(r'\bexploit\b|payload|reverse.shell|web.?shell|metasploit|meterpreter|shellcode|bypas|evasion|obfuscat|post.exploit|lateral.move|pivoting', re.I),
    "tools":     re.compile(r'\bnuclei\b|\bbursuite?\b|\bnmap\b|\bffuf\b|\bgobuster\b|\bsqlmap\b|\bhydra\b|\bhashcat\b|\bsubfinder\b|\bamass\b|\bhttpx\b|\bnuclei\b|\bghauri\b|\bferoxbuster\b|\bsecretfinder\b|\bgau\b|\bwaybackurls\b', re.I),
    "malware":   re.compile(r'ransomware|malware|trojan|botnet|APT\d*|threat.actor|campaign|backdoor|stealer|infostealer|spyware|keylogger|c2\b|c&c|command.and.control', re.I),
    "breach":    re.compile(r'data.?breach|leaked?|exposed|compromised|credential.stuffing|password.dump|database.leak|hacked|defaced', re.I),
    "news":      re.compile(r'cybersecurity|infosec|pentest|red.?team|blue.?team|SOC\b|threat.intel|OSINT|CTF\b|writeup|disclosure|advisory|patch.tuesday|security.update', re.I),
}

_CAT_COLORS = {
    "cve":       ("#fef2f2", "#f87171", "CVE"),
    "bugbounty": ("#fefce8", "#facc15", "Bug Bounty"),
    "exploit":   ("#fdf4ff", "#c084fc", "Exploit"),
    "tools":     ("#eff6ff", "#60a5fa", "Tools"),
    "malware":   ("#fff7ed", "#fb923c", "Malware"),
    "breach":    ("#fef2f2", "#f87171", "Breach"),
    "news":      ("#f0fdf4", "#4ade80", "News"),
}

def _categorize(text):
    return [cat for cat, rx in _CATS.items() if rx.search(text)]


def _make_client(creds):
    """Return (tweepy.Client or None, error_str or None). Tries v1 OAuth first."""
    try:
        import tweepy
    except ImportError:
        return None, None, "tweepy not installed. Run: pip install tweepy"

    key    = creds.get("x_api_key", "")
    secret = creds.get("x_api_secret", "")
    token  = creds.get("x_access_token", "")
    tsecret= creds.get("x_access_secret", "")
    bearer = creds.get("x_bearer_token", "")

    v1_api = None
    if all([key, secret, token, tsecret]):
        try:
            auth = tweepy.OAuth1UserHandler(key, secret, token, tsecret)
            v1_api = tweepy.API(auth, wait_on_rate_limit=False)
        except Exception:
            pass

    client = None
    if bearer:
        try:
            client = tweepy.Client(
                bearer_token=bearer,
                consumer_key=key or None,
                consumer_secret=secret or None,
                access_token=token or None,
                access_token_secret=tsecret or None,
                wait_on_rate_limit=False,
            )
        except Exception:
            pass
    elif all([key, secret, token, tsecret]):
        try:
            client = tweepy.Client(
                consumer_key=key, consumer_secret=secret,
                access_token=token, access_token_secret=tsecret,
                wait_on_rate_limit=False,
            )
        except Exception:
            pass

    if not client and not v1_api:
        return None, None, "No valid X credentials. Add them in Settings."

    return client, v1_api, None


def _fmt_v1(t):
    txt = getattr(t, "full_text", None) or t.text
    return {
        "id":            str(t.id),
        "text":          txt,
        "author_name":   t.user.name,
        "author_handle": t.user.screen_name,
        "author_avatar": getattr(t.user, "profile_image_url_https", ""),
        "created_at":    t.created_at.isoformat(),
        "likes":         t.favorite_count,
        "retweets":      t.retweet_count,
        "url":           f"https://x.com/{t.user.screen_name}/status/{t.id}",
        "is_rt":         hasattr(t, "retweeted_status"),
        "categories":    _categorize(txt),
    }


def _fmt_v2(t, users_map):
    u = users_map.get(str(t.author_id), {})
    m = t.public_metrics or {}
    return {
        "id":            str(t.id),
        "text":          t.text,
        "author_name":   u.get("name", ""),
        "author_handle": u.get("username", ""),
        "author_avatar": u.get("profile_image_url", ""),
        "created_at":    t.created_at.isoformat() if t.created_at else "",
        "likes":         m.get("like_count", 0),
        "retweets":      m.get("retweet_count", 0),
        "url":           f"https://x.com/i/web/status/{t.id}",
        "is_rt":         t.text.startswith("RT @"),
        "categories":    _categorize(t.text),
    }


# ── Routes ────────────────────────────────────────────────────────────────────

@feed_bp.route("/api/feed/timeline", methods=["POST"])
@module_required("feed")
def get_timeline():
    global _cache
    body   = request.get_json(silent=True) or {}
    creds  = {k: body.get(k, "") for k in ("x_api_key","x_api_secret","x_access_token","x_access_secret","x_bearer_token")}
    count  = min(int(body.get("count", 50)), 200)
    force  = body.get("force_refresh", False)
    filter_cyber = body.get("cyber_only", False)

    # Return cache if fresh
    if not force and _cache["tweets"] and (time.time() - _cache["ts"]) < _CACHE_TTL:
        tweets = _cache["tweets"]
        if filter_cyber:
            tweets = [t for t in tweets if t["categories"]]
        return jsonify({"tweets": tweets[:count], "count": len(tweets), "cached": True})

    client, v1_api, err = _make_client(creds)
    if err:
        return jsonify({"error": err}), 400

    tweets = []

    # --- Try home timeline via v1 (needs user OAuth) ---
    if v1_api:
        try:
            raw = v1_api.home_timeline(count=count, tweet_mode="extended", include_rts=True)
            tweets = [_fmt_v1(t) for t in raw]
        except Exception as e:
            err_msg = str(e)
            # Fall through to v2 search if rate limited or auth issue
            if "403" in err_msg or "401" in err_msg:
                v1_api = None
            elif tweets:
                pass  # partial results ok

    # --- Fallback: v2 search for cyber content ---
    if not tweets and client:
        try:
            query = (
                "(cybersecurity OR infosec OR CVE OR \"bug bounty\" OR pentest "
                "OR hacking OR exploit OR malware OR ransomware OR \"red team\") "
                "lang:en -is:retweet"
            )
            resp = client.search_recent_tweets(
                query=query,
                max_results=min(count, 100),
                tweet_fields=["created_at", "author_id", "public_metrics", "text"],
                expansions=["author_id"],
                user_fields=["name", "username", "profile_image_url"],
            )
            users_map = {}
            if resp.includes and resp.includes.get("users"):
                for u in resp.includes["users"]:
                    users_map[str(u.id)] = {"name": u.name, "username": u.username,
                                            "profile_image_url": getattr(u, "profile_image_url", "")}
            tweets = [_fmt_v2(t, users_map) for t in (resp.data or [])]
        except Exception as e:
            if not tweets:
                return jsonify({"error": str(e)}), 500

    _cache = {"tweets": tweets, "ts": time.time()}

    if filter_cyber:
        tweets = [t for t in tweets if t["categories"]]

    return jsonify({"tweets": tweets[:count], "count": len(tweets), "cached": False})


@feed_bp.route("/api/feed/analyze", methods=["POST"])
@module_required("feed")
def analyze_feed():
    body     = request.get_json(silent=True) or {}
    tweets   = body.get("tweets", [])
    provider = body.get("provider", "anthropic")
    api_key  = body.get("api_key") or os.environ.get(
        {"anthropic": "ANTHROPIC_API_KEY", "nvidia": "NVIDIA_API_KEY", "openai": "OPENAI_API_KEY"}.get(provider, "ANTHROPIC_API_KEY"), ""
    )
    focus    = body.get("focus", "all")   # all | cve | bugbounty | tools | exploit

    if not api_key:
        return Response(json.dumps({"error": f"No API key for {provider}. Add it in Settings → AI Keys."}),
                        status=400, mimetype="application/json")
    if not tweets:
        return Response(json.dumps({"error": "No tweets loaded. Refresh the feed first."}),
                        status=400, mimetype="application/json")

    lines = []
    for t in tweets[:100]:
        cats = ",".join(t.get("categories", [])) or "general"
        lines.append(f"[@{t.get('author_handle','?')}|{cats}] {t.get('text','')}")
    feed_text = "\n".join(lines)

    focus_extra = {
        "cve":       " Focus specifically on CVEs, affected products, CVSS scores, patch status, and PoC availability.",
        "bugbounty": " Focus specifically on bug bounty programs, payouts, targets, recon techniques, and writeup insights.",
        "tools":     " Focus specifically on new or notable security tools, frameworks, techniques released or trending.",
        "exploit":   " Focus specifically on active exploits, in-the-wild exploitation, PoCs, and attack techniques.",
    }.get(focus, "")

    system = (
        "You are a senior cybersecurity intelligence analyst. "
        "Your team needs a structured, actionable brief from the latest infosec Twitter/X feed." + focus_extra + " "
        "Produce the following sections (skip any with no data):\n"
        "## 🔴 Critical CVEs & Vulnerabilities\n"
        "List CVE IDs, affected software, severity (CVSS if mentioned), exploitation status.\n"
        "## 🟠 Active Exploits & Threat Activity\n"
        "In-the-wild exploitation, ransomware, APT campaigns, PoC releases.\n"
        "## 🟡 Bug Bounty Intelligence\n"
        "New programs, big payouts, recon tips, interesting targets, writeup summaries.\n"
        "## 🔵 New Tools & Techniques\n"
        "Tools released, techniques trending, offensive/defensive research.\n"
        "## 🟢 Key Takeaways\n"
        "5 concise bullet points your team should act on immediately.\n\n"
        "Be concise, structured, and prioritize actionable intelligence. Use markdown."
    )

    from blueprints.ai import _stream_ai
    user_msg = f"Analyze this cybersecurity feed ({len(tweets)} tweets):\n\n{feed_text}"

    def generate():
        try:
            for text in _stream_ai(provider, api_key, system, user_msg, max_tokens=3500):
                yield f"data: {json.dumps({'type':'text','text':text})}\n\n"
            yield f"data: {json.dumps({'type':'done'})}\n\n"
        except Exception as e:
            msg = str(e)
            if "auth" in msg.lower() or "401" in msg or "invalid" in msg.lower():
                msg = f"Invalid API key for {provider}."
            yield f"data: {json.dumps({'type':'error','text':msg})}\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
