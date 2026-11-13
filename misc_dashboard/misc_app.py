#!/usr/bin/env python3
"""Miscellaneous Tools Dashboard — Standalone Flask app on port 5002."""
import sys, os, threading, uuid, json, time, subprocess, shutil, queue

# Ensure go/local bins on PATH
for _p in (os.path.expanduser("~/go/bin"), os.path.expanduser("~/.local/bin")):
    if _p not in os.environ.get("PATH", ""):
        os.environ["PATH"] = _p + ":" + os.environ.get("PATH", "")

# Directory that holds git-cloned tools (shared with xploiter)
TOOLS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "xploiter-tools")

def _tool_dir(name):
    return os.path.join(TOOLS_DIR, name)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
# Add parent dir so core/ and blueprints/ are importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, request, jsonify, Response, stream_with_context, render_template, make_response, g
from werkzeug.middleware.proxy_fix import ProxyFix
from core.db import configure_app, init_db
from core.auth_utils import login_required, module_required
from blueprints.auth import auth_bp
from blueprints.apidocs import apidocs_bp

_MAIN_STATIC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static")
app = Flask(__name__, template_folder="templates", static_folder=_MAIN_STATIC, static_url_path="/static")
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_host=1, x_proto=1, x_prefix=1)
configure_app(app)
app.register_blueprint(auth_bp)
app.register_blueprint(apidocs_bp)
init_db(app)

# ── Tool Registry ─────────────────────────────────────────────────────────────
TOOL_REGISTRY = [
    # ── Passwords ──────────────────────────────────────────────────────────────
    {"id":"hydra",       "cat":"passwords", "name":"hydra",            "desc":"Parallelized login cracker, multiple protocols",       "install":"apt install hydra",          "cmd":["hydra","-t","4","-l","admin","-P","/usr/share/wordlists/rockyou.txt","{TARGET}","__EXTRA__"]},
    {"id":"changeme",    "cat":"passwords", "name":"changeme",         "desc":"Default credential scanner",                          "install":"pip install changeme",       "cmd":["changeme","{TARGET}","__EXTRA__"]},
    {"id":"patator",     "cat":"passwords", "name":"patator",          "desc":"Multi-purpose brute-forcer, modular design",          "install":"pip install patator",        "cmd":["patator","http_fuzz","url={TARGET}","__EXTRA__"]},
    {"id":"brutex",      "cat":"passwords", "name":"BruteX",           "desc":"Auto brute force all services on a target",           "install":"git clone https://github.com/1N3/BruteX", "cmd":["bash","BruteX","--target","{TARGET}","__EXTRA__"]},
    # ── Secrets ────────────────────────────────────────────────────────────────
    {"id":"gitleaks",    "cat":"secrets",   "name":"gitleaks",         "desc":"Scan git repos/files for secrets with regex+entropy",  "install":"go install github.com/zricethezav/gitleaks/v8@latest", "cmd":["gitleaks","detect","--source","{TARGET}","__EXTRA__"]},
    {"id":"trufflehog",  "cat":"secrets",   "name":"trufflehog",       "desc":"Searches git repos for high entropy strings & secrets","install":"pip install truffleHog",     "cmd":["trufflehog","git","{TARGET}","__EXTRA__"]},
    {"id":"detect-secrets","cat":"secrets", "name":"detect-secrets",   "desc":"Enterprise friendly secret detection in code",        "install":"pip install detect-secrets", "cmd":["detect-secrets","scan","{TARGET}","__EXTRA__"]},
    {"id":"noseyparker", "cat":"secrets",   "name":"noseyparker",      "desc":"Finds secrets and sensitive info in text and git",    "install":"cargo install noseyparker", "cmd":["noseyparker","scan","--datastore","/tmp/np-ds","{TARGET}","__EXTRA__"]},
    {"id":"secretfinder","cat":"secrets",   "name":"SecretFinder",     "desc":"Find sensitive data in JavaScript files",             "install":"git clone https://github.com/m4ll0k/SecretFinder", "cmd":["python3","SecretFinder.py","-i","{TARGET}","__EXTRA__"]},
    {"id":"gitrob",      "cat":"secrets",   "name":"gitrob",           "desc":"Reconnaissance tool for GitHub organizations",        "install":"go install github.com/michenriksen/gitrob@latest", "cmd":["gitrob","{TARGET}","__EXTRA__"]},
    {"id":"cariddi",     "cat":"secrets",   "name":"cariddi",          "desc":"Crawl URLs and scan for endpoints, secrets, API keys","install":"go install github.com/edoardottt/cariddi/cmd/cariddi@latest", "cmd":["cariddi","-s","-e","-info","__EXTRA__"]},
    {"id":"whispers",    "cat":"secrets",   "name":"whispers",         "desc":"Identify hardcoded secrets and dangerous behaviours",  "install":"pip install whispers",       "cmd":["whispers","{TARGET}","__EXTRA__"]},
    {"id":"git-secrets", "cat":"secrets",   "name":"git-secrets",      "desc":"Prevents committing secrets into git repositories",   "install":"git clone https://github.com/awslabs/git-secrets", "cmd":["git-secrets","--scan","{TARGET}","__EXTRA__"]},
    {"id":"shhgit",      "cat":"secrets",   "name":"shhgit",           "desc":"Find GitHub secrets in real time",                    "install":"go install github.com/eth0izzle/shhgit@latest", "cmd":["shhgit","__EXTRA__"]},
    {"id":"rusty-hog",   "cat":"secrets",   "name":"rusty-hog",        "desc":"Suite of secret scanners built in Rust",              "install":"cargo install rusty_hog",    "cmd":["ankogitscan","{TARGET}","__EXTRA__"]},
    {"id":"earlybird",   "cat":"secrets",   "name":"earlybird",        "desc":"Sensitive data detection, scans source code repos",   "install":"go install github.com/americanexpress/earlybird/cmd/earlybird@latest", "cmd":["earlybird","-path","{TARGET}","__EXTRA__"]},
    {"id":"git-hound",   "cat":"secrets",   "name":"GitHound",         "desc":"Recon leveraging Code Search API for exposed API keys","install":"go install github.com/tillson/git-hound@latest", "cmd":["git-hound","--subdomain-file","{TARGET}","__EXTRA__"]},
    {"id":"badsecrets",  "cat":"secrets",   "name":"badsecrets",       "desc":"Detect known/default secrets across platforms",        "install":"pip install badsecrets",    "cmd":["python3","-m","badsecrets","{TARGET}","__EXTRA__"]},
    {"id":"hardcoded-token-hunter","cat":"secrets","name":"Hardcoded-Token-Hunter","desc":"Find hardcoded tokens, API keys & secrets in repos","install":"git clone https://github.com/KingOfBugbounty/Hardcoded-Token-Hunter","cmd":["python3","scanner.py","-p","{TARGET}","__EXTRA__"]},
    # ── Git ────────────────────────────────────────────────────────────────────
    {"id":"gittools",    "cat":"git",       "name":"GitTools",         "desc":"3 tools for exploiting websites with .git repos",     "install":"git clone https://github.com/internetwache/GitTools", "cmd":["bash","gitdumper.sh","{TARGET}","__EXTRA__"]},
    {"id":"gitjacker",   "cat":"git",       "name":"gitjacker",        "desc":"Leak git repositories from misconfigured websites",   "install":"go install github.com/liamg/gitjacker@latest", "cmd":["gitjacker","-u","{TARGET}","__EXTRA__"]},
    {"id":"git-dumper",  "cat":"git",       "name":"git-dumper",       "desc":"Dump a git repository from a website",               "install":"pip install git-dumper",     "cmd":["git-dumper","{TARGET}","./output","__EXTRA__"]},
    {"id":"dvcs-ripper", "cat":"git",       "name":"dvcs-ripper",      "desc":"Rip web accessible VCS: SVN/GIT/HG",                 "install":"git clone https://github.com/kost/dvcs-ripper", "cmd":["perl","rip-git.pl","-v","-u","{TARGET}","__EXTRA__"]},
    {"id":"gato",        "cat":"git",       "name":"gato",             "desc":"GitHub Self-Hosted Runner Enumeration and Attack",    "install":"pip install gato",           "cmd":["gato","e","--target","{TARGET}","__EXTRA__"]},
    {"id":"zizmor",      "cat":"git",       "name":"zizmor",           "desc":"Static analysis tool for GitHub Actions",            "install":"pip install zizmor",         "cmd":["zizmor","{TARGET}","__EXTRA__"]},
    {"id":"gitdorker",   "cat":"git",       "name":"GitDorker",        "desc":"GitHub dork scanner scraping org/user/repo data",     "install":"pip install GitDorker",      "cmd":["python3","GitDorker.py","-d","./Dorks/alldorksv3","-q","{TARGET}","__EXTRA__"]},
    {"id":"github-search","cat":"git",      "name":"github-search",    "desc":"Tools to search GitHub for code, repos, users",       "install":"git clone https://github.com/gwen001/github-search","cmd":["python3","github-search.py","-k","{TARGET}","__EXTRA__"]},
    # ── Buckets ────────────────────────────────────────────────────────────────
    {"id":"s3scanner",   "cat":"buckets",   "name":"S3Scanner",        "desc":"Scan for open AWS S3 buckets and dump contents",      "install":"pip install s3scanner",      "cmd":["s3scanner","scan","--bucket","{TARGET}","__EXTRA__"]},
    {"id":"cloudbrute",  "cat":"buckets",   "name":"CloudBrute",       "desc":"Cloud resource enumerator — S3/Azure/GCP",            "install":"go install github.com/0xsha/CloudBrute@latest", "cmd":["CloudBrute","-d","{TARGET}","__EXTRA__"]},
    {"id":"s3reverse",   "cat":"buckets",   "name":"s3reverse",        "desc":"Convert various S3 bucket formats for testing",       "install":"go install github.com/hahwul/s3reverse@latest", "cmd":["s3reverse","-l","{TARGET}","__EXTRA__"]},
    {"id":"festin",      "cat":"buckets",   "name":"festin",           "desc":"S3 bucket weakness discovery",                        "install":"pip install festin",         "cmd":["festin","-d","{TARGET}","__EXTRA__"]},
    {"id":"cloudscraper","cat":"buckets",   "name":"CloudScraper",     "desc":"Enumerate cloud resources including S3/Azure/DO",     "install":"git clone https://github.com/jordanpotti/CloudScraper", "cmd":["python3","CloudScraper.py","-t","{TARGET}","__EXTRA__"]},
    {"id":"s3_objects_check","cat":"buckets","name":"s3_objects_check","desc":"Whitebox evaluation of S3 object permissions",       "install":"git clone https://github.com/nccgroup/s3_objects_check", "cmd":["python3","s3_objects_check.py","-p","{TARGET}","__EXTRA__"]},
    # ── CMS ────────────────────────────────────────────────────────────────────
    {"id":"wpscan",      "cat":"cms",       "name":"wpscan",           "desc":"Black box WordPress security scanner",                "install":"gem install wpscan",         "cmd":["wpscan","--url","{TARGET}","__EXTRA__"]},
    {"id":"cmsmap",      "cat":"cms",       "name":"CMSmap",           "desc":"Python CMS scanner — WP/Joomla/Drupal/Moodle",        "install":"git clone https://github.com/Dionach/CMSmap", "cwd":"CMSmap",   "cmd":["python3","cmsmap.py","{TARGET}","__EXTRA__"]},
    {"id":"joomscan",    "cat":"cms",       "name":"joomscan",         "desc":"OWASP Joomla Vulnerability Scanner",                  "install":"git clone https://github.com/OWASP/joomscan", "cwd":"joomscan", "cmd":["perl","joomscan.pl","--url","{TARGET}","__EXTRA__"]},
    {"id":"wprecon",     "cat":"cms",       "name":"wprecon",          "desc":"WordPress reconnaissance tool",                       "install":"go install github.com/blackcrw/wprecon@latest", "cmd":["wprecon","--url","{TARGET}","__EXTRA__"]},
    {"id":"aemhacker",   "cat":"cms",       "name":"aem-hacker",       "desc":"Identify vulnerable Adobe Experience Manager webapps","install":"pip install aem-hacker",     "cmd":["aem-hacker","-u","{TARGET}","__EXTRA__"]},
    {"id":"wpprobe",     "cat":"cms",       "name":"WPProbe",          "desc":"WordPress vulnerability & plugin scanner",            "install":"go install github.com/Chocapikk/wpprobe@latest", "cmd":["wpprobe","-u","{TARGET}","__EXTRA__"]},
    # ── JWT ────────────────────────────────────────────────────────────────────
    {"id":"jwt_tool",    "cat":"jwt",       "name":"jwt_tool",         "desc":"Toolkit for testing, tweaking and cracking JWTs",     "install":"git clone https://github.com/ticarpi/jwt_tool", "cwd":"jwt_tool", "cmd":["python3","jwt_tool.py","{TARGET}","__EXTRA__"]},
    {"id":"jwt-hack",    "cat":"jwt",       "name":"jwt-hack",         "desc":"Tool for hacking/security testing JWT",               "install":"go install github.com/hahwul/jwt-hack@latest", "cmd":["jwt-hack","crack","{TARGET}","__EXTRA__"]},
    {"id":"jwtear",      "cat":"jwt",       "name":"jwtear",           "desc":"Modular CLI tool to parse, create and manipulate JWT","install":"gem install jwtear",         "cmd":["jwtear","--help","__EXTRA__"]},
    {"id":"c-jwt-cracker","cat":"jwt",      "name":"c-jwt-cracker",    "desc":"JWT brute force cracker written in C",               "install":"git clone https://github.com/brendan-rius/c-jwt-cracker", "cmd":["./jwtcrack","{TARGET}","__EXTRA__"]},
    # ── Subdomain Takeover ─────────────────────────────────────────────────────
    {"id":"subjack",     "cat":"subtakeover","name":"subjack",         "desc":"Subdomain takeover tool written in Go",               "install":"go install github.com/haccer/subjack@latest", "cmd":["subjack","-w","{TARGET}","-t","100","-o","./output.txt","__EXTRA__"]},
    {"id":"subzy",       "cat":"subtakeover","name":"subzy",           "desc":"Subdomain takeover tool using response fingerprints", "install":"go install github.com/PentestPad/subzy@latest", "cmd":["subzy","run","--targets","{TARGET}","__EXTRA__"]},
    {"id":"dnsr",        "cat":"subtakeover","name":"dnsReaper",       "desc":"Sub-domain takeover, emphasis on accuracy & speed",   "install":"git clone https://github.com/punk-security/dnsReaper", "cmd":["python3","main.py","file","--filename","{TARGET}","__EXTRA__"]},
    {"id":"tko-subs",    "cat":"subtakeover","name":"tko-subs",        "desc":"Detect and takeover subdomains with dead DNS records", "install":"go install github.com/anshumanbh/tko-subs@latest", "cmd":["tko-subs","-domains","{TARGET}","__EXTRA__"]},
    {"id":"second-order","cat":"subtakeover","name":"second-order",    "desc":"Second-order subdomain takeover scanner",             "install":"go install github.com/mhmdiaa/second-order@latest", "cmd":["second-order","-base","{TARGET}","__EXTRA__"]},
    {"id":"subover",     "cat":"subtakeover","name":"SubOver",         "desc":"Powerful subdomain takeover tool",                    "install":"go install github.com/Ice3man543/SubOver@latest", "cmd":["SubOver","-l","{TARGET}","__EXTRA__"]},
    # ── Vulnerability Scanners ─────────────────────────────────────────────────
    {"id":"nuclei",      "cat":"vulnscan",  "name":"nuclei",           "desc":"Fast configurable scanning based on community templates","install":"go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", "cmd":["nuclei","-u","{TARGET}","__EXTRA__"]},
    {"id":"nikto",       "cat":"vulnscan",  "name":"nikto",            "desc":"Web server vulnerability scanner",                    "install":"apt install nikto",          "cmd":["nikto","-h","{TARGET}","__EXTRA__"]},
    {"id":"jaeles",      "cat":"vulnscan",  "name":"jaeles",           "desc":"Swiss Army knife for automated web app testing",      "install":"go install github.com/jaeles-project/jaeles@latest", "cmd":["jaeles","scan","-u","{TARGET}","__EXTRA__"]},
    {"id":"getsploit",   "cat":"vulnscan",  "name":"getsploit",        "desc":"CLI utility for searching and downloading exploits",   "install":"pip install getsploit",      "cmd":["getsploit","{TARGET}","__EXTRA__"]},
    {"id":"cariddi-scan","cat":"vulnscan",  "name":"cariddi (scan)",   "desc":"Crawl URLs and scan for secrets, api keys, tokens",   "install":"go install github.com/edoardottt/cariddi/cmd/cariddi@latest", "cmd":["cariddi","-s","-e","-info","__EXTRA__"]},
    # ── Permutation ────────────────────────────────────────────────────────────
    {"id":"alterx",      "cat":"permutation","name":"alterx",          "desc":"Fast customizable subdomain wordlist generator via DSL","install":"go install github.com/projectdiscovery/alterx/cmd/alterx@latest", "cmd":["alterx","-list","{TARGET}","__EXTRA__"]},
    {"id":"gotator",     "cat":"permutation","name":"gotator",         "desc":"Generate DNS wordlists through permutations",          "install":"go install github.com/Josue87/gotator@latest", "cmd":["gotator","-sub","{TARGET}","__EXTRA__"]},
    {"id":"dnsgen",      "cat":"permutation","name":"dnsgen",          "desc":"Flexible DNS name permutation tool",                   "install":"pip install dnsgen",         "cmd":["dnsgen","-","{TARGET}","__EXTRA__"]},
    {"id":"altdns",      "cat":"permutation","name":"altdns",          "desc":"Generate permutations, alterations, mutations of subdomains","install":"git clone https://github.com/infosec-au/altdns", "cwd":"altdns", "cmd":["python3","-m","altdns","-i","{TARGET}","-o","./output.txt","__EXTRA__"]},
    {"id":"ripgen",      "cat":"permutation","name":"ripgen",          "desc":"Rust-based high performance domain permutation gen",   "install":"cargo install ripgen",       "cmd":["ripgen","-d","{TARGET}","__EXTRA__"]},
    # ── Web Proxy ──────────────────────────────────────────────────────────────
    {"id":"mitmproxy",   "cat":"proxy",     "name":"mitmproxy",        "desc":"Interactive TLS-capable intercepting HTTP proxy",       "install":"pip install mitmproxy",      "cmd":["mitmproxy","__EXTRA__"]},
    {"id":"proxify",     "cat":"proxy",     "name":"proxify",          "desc":"Portable proxy for capturing/manipulating HTTP traffic","install":"go install github.com/projectdiscovery/proxify/cmd/proxify@latest", "cmd":["proxify","__EXTRA__"]},
    # ── Origin IP ──────────────────────────────────────────────────────────────
    {"id":"hakoriginfinder","cat":"originip","name":"hakoriginfinder", "desc":"Discover origin host behind reverse proxy / bypass WAF","install":"go install github.com/hakluke/hakoriginfinder@latest", "cmd":["hakoriginfinder","-h","{TARGET}","__EXTRA__"]},
    {"id":"cloudrip",    "cat":"originip",  "name":"CloudRip",         "desc":"Find real IPs hiding behind Cloudflare via subdomains","install":"git clone https://github.com/moscovium-mc/CloudRip", "cmd":["python3","cloudrip.py","-d","{TARGET}","__EXTRA__"]},
    # ── Useful ─────────────────────────────────────────────────────────────────
    {"id":"anew",        "cat":"useful",    "name":"anew",             "desc":"Add new lines to files, skipping duplicates",          "install":"go install github.com/tomnomnom/anew@latest", "cmd":["anew","{TARGET}","__EXTRA__"]},
    {"id":"gf",          "cat":"useful",    "name":"gf",               "desc":"Wrapper around grep for common bug bounty patterns",    "install":"go install github.com/tomnomnom/gf@latest", "cmd":["gf","{TARGET}","__EXTRA__"]},
    {"id":"uro",         "cat":"useful",    "name":"uro",              "desc":"Deduplicate URL lists for crawling/pentesting",        "install":"pip install uro",            "cmd":["uro","-i","{TARGET}","__EXTRA__"]},
    {"id":"unfurl",      "cat":"useful",    "name":"unfurl",           "desc":"Pull out bits of URLs from stdin",                     "install":"go install github.com/tomnomnom/unfurl@latest", "cmd":["unfurl","__EXTRA__"]},
    {"id":"qsreplace",   "cat":"useful",    "name":"qsreplace",        "desc":"Replace query string values with user-supplied value",  "install":"go install github.com/tomnomnom/qsreplace@latest", "cmd":["qsreplace","__EXTRA__"]},
    {"id":"notify",      "cat":"useful",    "name":"notify",           "desc":"Stream tool output and publish to multiple platforms",  "install":"go install github.com/projectdiscovery/notify/cmd/notify@latest", "cmd":["notify","__EXTRA__"]},
]

CATEGORIES = [
    {"id":"passwords",   "label":"Passwords",           "icon":"🔑","color":"#ef4444","rgb":"239,68,68"},
    {"id":"secrets",     "label":"Secrets",             "icon":"🕵️","color":"#f97316","rgb":"249,115,22"},
    {"id":"git",         "label":"Git",                 "icon":"🐙","color":"#a78bfa","rgb":"167,139,250"},
    {"id":"buckets",     "label":"Cloud Buckets",       "icon":"☁️","color":"#60a5fa","rgb":"96,165,250"},
    {"id":"cms",         "label":"CMS",                 "icon":"📝","color":"#34d399","rgb":"52,211,153"},
    {"id":"jwt",         "label":"JWT",                 "icon":"🎫","color":"#fbbf24","rgb":"251,191,36"},
    {"id":"subtakeover", "label":"Subdomain Takeover",  "icon":"🎯","color":"#f472b6","rgb":"244,114,182"},
    {"id":"vulnscan",    "label":"Vuln Scanners",       "icon":"🔬","color":"#e879f9","rgb":"232,121,249"},
    {"id":"permutation", "label":"Permutation",         "icon":"🔄","color":"#2dd4bf","rgb":"45,212,191"},
    {"id":"proxy",       "label":"Web Proxy",           "icon":"🌐","color":"#818cf8","rgb":"129,140,248"},
    {"id":"originip",    "label":"Origin IP",           "icon":"📡","color":"#4ade80","rgb":"74,222,128"},
    {"id":"useful",      "label":"Useful Tools",        "icon":"🛠️","color":"#94a3b8","rgb":"148,163,184"},
]

# ── In-memory run store ───────────────────────────────────────────────────────
_runs = {}
_lock = threading.Lock()


# ── Routes ────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    from flask import make_response as _mkr, redirect as _rd
    from core.auth_utils import (get_token_from_request, load_user_from_token,
                                  TOKEN_COOKIE, TOKEN_EXPIRE_H)
    token = get_token_from_request()
    user  = load_user_from_token(token) if token else None
    if not user:
        return _rd("/auth/login?next=/misc/")
    return render_template("index.html")


@app.route("/api/misc/tools")
def get_tools():
    env = os.environ.copy()
    tools = []
    for t in TOOL_REGISTRY:
        if t.get("cwd"):
            installed = os.path.isdir(_tool_dir(t["cwd"]))
        else:
            binary = t["cmd"][0] if t["cmd"] else ""
            installed = bool(shutil.which(binary, path=env["PATH"])) if binary and binary not in ("python3","bash","perl","ruby","java","cargo") else None
        tools.append({k: v for k, v in t.items() if k != "cmd"} | {"installed": installed})
    return jsonify({"tools": tools, "categories": CATEGORIES})


def _build_cmd(tool, target, extra):
    extra_parts = extra.split() if extra else []
    cmd = []
    for part in tool["cmd"]:
        if part == "__EXTRA__":
            cmd += extra_parts
        elif isinstance(part, str):
            cmd.append(part.replace("{TARGET}", target))
    return cmd


@app.route("/api/misc/run", methods=["POST"])
@module_required("misc")
def run_tool():
    body    = request.get_json(silent=True) or {}
    tool_id = body.get("tool_id", "")
    target  = (body.get("target") or "").strip()
    extra   = body.get("extra_flags", "")

    tool = next((t for t in TOOL_REGISTRY if t["id"] == tool_id), None)
    if not tool:
        return jsonify({"error": "Unknown tool"}), 400
    if not target:
        return jsonify({"error": "target required"}), 400

    user = getattr(g, "current_user", None)
    run_user_id = user.id if user else None

    scan_id = str(uuid.uuid4())
    q = queue.Queue()
    with _lock:
        _runs[scan_id] = {"queue": q, "done": False, "events": [],
                          "tool_id": tool_id, "tool_name": tool["name"],
                          "target": target, "started_at": time.time(),
                          "user_id": run_user_id}

    def _buffer():
        while True:
            try:
                item = q.get(timeout=120)
                with _lock:
                    if scan_id in _runs:
                        _runs[scan_id]["events"].append(item)
                if item is None:
                    break
            except queue.Empty:
                pass

    def _run():
        env = os.environ.copy()
        tool_cwd = _tool_dir(tool["cwd"]) if tool.get("cwd") else None
        if tool_cwd and not os.path.isdir(tool_cwd):
            q.put({"type":"error","message":f"Tool directory not found: {tool_cwd}\nInstall: {tool.get('install','')}"})
            q.put(None)
            with _lock:
                if scan_id in _runs:
                    _runs[scan_id]["done"] = True
            return
        cmd = _build_cmd(tool, target, extra)
        # For git-cloned Python tools use a per-tool venv to avoid PEP 668
        if cmd and cmd[0] in ("python", "python3") and tool_cwd:
            venv_dir    = os.path.join(tool_cwd, ".venv")
            venv_python = os.path.join(venv_dir, "bin", "python")
            if not os.path.isfile(venv_python):
                q.put({"type": "output", "line": "⟳ Setting up virtual environment…", "target": target})
                subprocess.run(["python3", "-m", "venv", venv_dir], capture_output=True)
                req = os.path.join(tool_cwd, "requirements.txt")
                if os.path.isfile(req):
                    q.put({"type": "output", "line": "⟳ Installing requirements…", "target": target})
                    subprocess.run([venv_python, "-m", "pip", "install", "-q",
                                    "-r", req], capture_output=True)
            if os.path.isfile(venv_python):
                cmd[0] = venv_python
        binary = cmd[0] if cmd else ""
        binary_ok = shutil.which(binary, path=env["PATH"]) or (tool_cwd and os.path.isfile(os.path.join(tool_cwd, binary))) or os.path.isfile(binary)
        if not binary_ok and binary not in ("python3","perl","ruby","bash","java"):
            q.put({"type":"error","message":f"{binary} is not installed. {tool.get('install','')}"})
            q.put(None)
            with _lock:
                if scan_id in _runs:
                    _runs[scan_id]["done"] = True
            return
        q.put({"type":"start","tool":tool["name"],"target":target,"cmd":" ".join(cmd)})
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, env=env, bufsize=1, cwd=tool_cwd)
            for line in proc.stdout:
                line = line.rstrip()
                if line:
                    q.put({"type":"output","line":line,"target":target})
            proc.wait(timeout=600)
            q.put({"type":"done","returncode":proc.returncode})
        except subprocess.TimeoutExpired:
            proc.kill()
            q.put({"type":"warning","message":"Process timed out.","target":target})
            q.put({"type":"done","returncode":-1})
        except Exception as e:
            q.put({"type":"error","message":str(e),"target":target})
            q.put({"type":"done","returncode":-1})
        finally:
            q.put(None)
            with _lock:
                if scan_id in _runs:
                    _runs[scan_id]["done"] = True

    threading.Thread(target=_buffer, daemon=True).start()
    threading.Thread(target=_run,    daemon=True).start()
    return jsonify({"scan_id": scan_id, "tool": tool["name"], "target": target})


@app.route("/api/misc/run_multi", methods=["POST"])
@module_required("misc")
def run_tool_multi():
    """Run a tool simultaneously against multiple targets in parallel threads."""
    body    = request.get_json(silent=True) or {}
    tool_id = body.get("tool_id", "")
    targets = [t.strip() for t in (body.get("targets") or []) if str(t).strip()]
    extra   = body.get("extra_flags", "")

    tool = next((t for t in TOOL_REGISTRY if t["id"] == tool_id), None)
    if not tool:
        return jsonify({"error": "Unknown tool"}), 400
    if not targets:
        return jsonify({"error": "targets list required"}), 400

    user = getattr(g, "current_user", None)
    run_user_id = user.id if user else None

    scan_id = str(uuid.uuid4())
    q = queue.Queue()
    with _lock:
        _runs[scan_id] = {"queue": q, "done": False, "events": [],
                          "tool_id": tool_id, "tool_name": tool["name"],
                          "target": ", ".join(targets[:3]) + ("..." if len(targets) > 3 else ""),
                          "started_at": time.time(),
                          "user_id": run_user_id}

    total       = len(targets)
    fin_count   = [0]
    fin_lock    = threading.Lock()

    def _buffer():
        while True:
            try:
                item = q.get(timeout=120)
                with _lock:
                    if scan_id in _runs:
                        _runs[scan_id]["events"].append(item)
                if item is None:
                    break
            except queue.Empty:
                pass

    def _finish_one():
        with fin_lock:
            fin_count[0] += 1
            if fin_count[0] >= total:
                q.put({"type":"all_done","total":total})
                q.put(None)
                with _lock:
                    if scan_id in _runs:
                        _runs[scan_id]["done"] = True

    def _run_one(target):
        env = os.environ.copy()
        tool_cwd = _tool_dir(tool["cwd"]) if tool.get("cwd") else None
        cmd = _build_cmd(tool, target, extra)
        # For git-cloned Python tools use a per-tool venv to avoid PEP 668
        if cmd and cmd[0] in ("python", "python3") and tool_cwd:
            venv_dir    = os.path.join(tool_cwd, ".venv")
            venv_python = os.path.join(venv_dir, "bin", "python")
            if not os.path.isfile(venv_python):
                subprocess.run(["python3", "-m", "venv", venv_dir], capture_output=True)
                req = os.path.join(tool_cwd, "requirements.txt")
                if os.path.isfile(req):
                    subprocess.run([venv_python, "-m", "pip", "install", "-q",
                                    "-r", req], capture_output=True)
            if os.path.isfile(venv_python):
                cmd[0] = venv_python
        binary = cmd[0] if cmd else ""
        binary_ok = shutil.which(binary, path=env["PATH"]) or (tool_cwd and os.path.isfile(os.path.join(tool_cwd, binary))) or os.path.isfile(binary)
        if not binary_ok and binary not in ("python3","perl","ruby","bash","java"):
            q.put({"type":"error","target":target,
                   "message":f"{binary} is not installed. {tool.get('install','')}"})
            _finish_one()
            return
        q.put({"type":"start","tool":tool["name"],"target":target,"cmd":" ".join(cmd)})
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, env=env, bufsize=1, cwd=tool_cwd)
            for line in proc.stdout:
                line = line.rstrip()
                if line:
                    q.put({"type":"output","line":line,"target":target})
            proc.wait(timeout=600)
            q.put({"type":"target_done","target":target,"returncode":proc.returncode})
        except subprocess.TimeoutExpired:
            proc.kill()
            q.put({"type":"warning","target":target,"message":"Timed out."})
            q.put({"type":"target_done","target":target,"returncode":-1})
        except Exception as e:
            q.put({"type":"error","target":target,"message":str(e)})
            q.put({"type":"target_done","target":target,"returncode":-1})
        finally:
            _finish_one()

    threading.Thread(target=_buffer, daemon=True).start()
    for t in targets:
        threading.Thread(target=_run_one, args=(t,), daemon=True).start()

    return jsonify({"scan_id": scan_id, "tool": tool["name"],
                    "targets": targets, "count": total})


@app.route("/api/misc/stream/<scan_id>")
@login_required
def stream_run(scan_id):
    user = getattr(g, "current_user", None)
    with _lock:
        run = _runs.get(scan_id)
    if not run:
        return jsonify({"error": "not found"}), 404
    if user and user.role != "admin" and run.get("user_id") != user.id:
        return jsonify({"error": "access denied"}), 403

    def generate():
        offset = 0
        last_ka = time.time()
        while True:
            with _lock:
                run = _runs.get(scan_id)
                if not run: break
                events = run["events"]
                done   = run["done"]
            while offset < len(events):
                item = events[offset]; offset += 1
                if item is None:
                    yield f"data: {json.dumps({'type':'done'})}\n\n"; return
                yield f"data: {json.dumps(item)}\n\n"
            if done:
                yield f"data: {json.dumps({'type':'done'})}\n\n"; return
            now = time.time()
            if now - last_ka > 25:
                yield f"data: {json.dumps({'type':'keepalive'})}\n\n"; last_ka = now
            time.sleep(0.05)

    return Response(stream_with_context(generate()),
                    mimetype="text/event-stream",
                    headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"})


@app.route("/api/misc/status/<scan_id>")
@login_required
def run_status(scan_id):
    user = getattr(g, "current_user", None)
    with _lock:
        run = _runs.get(scan_id)
    if not run:
        return jsonify({"exists": False}), 404
    if user and user.role != "admin" and run.get("user_id") != user.id:
        return jsonify({"exists": False}), 404
    return jsonify({"exists": True, "done": run["done"], "event_count": len(run["events"])})


@app.route("/api/misc/watchdog")
@login_required
def watchdog_status():
    """Return summary of active/recent Misc Tool runs — user-isolated."""
    user = getattr(g, "current_user", None)
    is_admin = user and user.role == "admin"
    uid = user.id if user else None
    with _lock:
        runs = list(_runs.items())
    result = []
    now = time.time()
    for sid, r in runs:
        if not is_admin and r.get("user_id") != uid:
            continue
        events = r.get("events", [])
        findings = sum(1 for e in events if e and e.get("type") in ("finding", "vuln", "result"))
        result.append({
            "id": sid,
            "source": "misc",
            "label": r.get("tool_name", r.get("tool_id", "tool")),
            "target": r.get("target", ""),
            "done": r.get("done", False),
            "findings": findings,
            "event_count": len(events),
            "started_at": r.get("started_at", now),
            "elapsed": round(now - r.get("started_at", now)),
        })
    return jsonify(result)


@app.route("/api/misc/clear", methods=["POST"])
@login_required
def clear_runs():
    """Remove completed runs owned by the current user (admin clears all)."""
    user = getattr(g, "current_user", None)
    is_admin = user and user.role == "admin"
    uid = user.id if user else None
    with _lock:
        done = [sid for sid, r in _runs.items()
                if r.get("done") and (is_admin or r.get("user_id") == uid)]
        for sid in done:
            del _runs[sid]
    return jsonify({"cleared": len(done), "ok": True})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5002, threaded=True)
