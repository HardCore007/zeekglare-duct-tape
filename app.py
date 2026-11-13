#!/usr/bin/env python3
"""ZeekGlare — Intelligence Platform"""
import sys, os, pathlib

# Ensure Go binaries are on PATH for all subprocess calls
_go_bin = os.path.expanduser("~/go/bin")
if _go_bin not in os.environ.get("PATH", ""):
    os.environ["PATH"] = _go_bin + ":" + os.environ.get("PATH", "")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, render_template
from werkzeug.middleware.proxy_fix import ProxyFix
from core.db import configure_app, init_db
from core.auth_utils import login_required
from blueprints.auth   import auth_bp
from blueprints.admin  import admin_bp
from blueprints.alerts import alerts_bp
from blueprints.asn      import asn_bp
from blueprints.domain   import domain_bp
from blueprints.sessions import sessions_bp
from blueprints.recon    import recon_bp
from blueprints.dns      import dns_bp
from blueprints.ports    import ports_bp
from blueprints.osint    import osint_bp
from blueprints.export   import export_bp
from blueprints.schedule import schedule_bp
from blueprints.tools    import tools_bp
from blueprints.pd       import pd_bp
from blueprints.ai         import ai_bp
from blueprints.chat       import chat_bp
from blueprints.jsanalysis import jsanalysis_bp
from blueprints.feed       import feed_bp
from blueprints.caido      import caido_bp
from blueprints.burp       import burp_bp
from blueprints.fuzzer      import fuzzer_bp
from blueprints.wpscan      import wpscan_bp
from blueprints.threatblitz import tb_bp
from blueprints.ipmapper   import ipmapper_bp
from blueprints.paramhawk  import paramhawk_bp
from blueprints.telegram_bot import tg_bp
from blueprints.crawler     import crawler_bp
from blueprints.sudomy      import sudomy_bp
from blueprints.xploiter   import xploiter_bp
from blueprints.workflow    import workflow_bp
from blueprints.watchdog    import watchdog_bp
from blueprints.oneforall   import ofa_bp
from blueprints.cve         import cve_bp
from blueprints.recon_extra import recon_extra_bp
from blueprints.twofa       import twofa_bp
from blueprints.proxy       import proxy_bp as proxy_settings_bp
from blueprints.arena       import arena_bp
from blueprints.healthmon   import healthmon_bp
from blueprints.globalsearch import globalsearch_bp
from blueprints.apidocs     import apidocs_bp
from core import proxy_config as _proxy_config

# Install SOCKS5/HTTP proxy patch before blueprints register. This wraps
# requests.Session.request globally and mirrors the proxy into os.environ
# so subprocess-spawned CLI tools (nuclei, httpx, ffuf, gau, …) inherit it.
_proxy_config.install_requests_patch()

for d in ("data/sessions", "data/recon", "data/schedules"):
    pathlib.Path(d).mkdir(parents=True, exist_ok=True)

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_host=1, x_proto=1, x_prefix=1)
configure_app(app)

for bp in (auth_bp, admin_bp, alerts_bp,
           asn_bp, domain_bp, sessions_bp, recon_bp,
           dns_bp, ports_bp, osint_bp, export_bp, schedule_bp, tools_bp, pd_bp,
           ai_bp, chat_bp, jsanalysis_bp, feed_bp, caido_bp, burp_bp, fuzzer_bp, wpscan_bp,
           tb_bp, ipmapper_bp, paramhawk_bp, tg_bp, crawler_bp, sudomy_bp, xploiter_bp, workflow_bp, watchdog_bp,
           ofa_bp, cve_bp, recon_extra_bp, twofa_bp, proxy_settings_bp, arena_bp,
           healthmon_bp, globalsearch_bp, apidocs_bp):
    app.register_blueprint(bp)

init_db(app)


@app.after_request
def add_no_cache(response):
    if response.content_type and "text/html" in response.content_type:
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response


@app.route("/")
@login_required
def index():
    return render_template("index.html")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, threaded=True)
