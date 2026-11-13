#!/usr/bin/env python3
"""Xpl03tEr — Standalone exploitation dashboard (port 5001)."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

_go_bin = os.path.expanduser("~/go/bin")
if _go_bin not in os.environ.get("PATH", ""):
    os.environ["PATH"] = _go_bin + ":" + os.environ.get("PATH", "")

from flask import Flask, render_template, request, redirect
from werkzeug.middleware.proxy_fix import ProxyFix
from core.db import configure_app, init_db
from core.auth_utils import login_required, get_token_from_request, load_user_from_token
from blueprints.auth    import auth_bp
from blueprints.xploiter import xploiter_bp
from blueprints.apidocs import apidocs_bp

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_host=1, x_proto=1, x_prefix=1)
configure_app(app)
app.register_blueprint(auth_bp)
app.register_blueprint(xploiter_bp)
app.register_blueprint(apidocs_bp)
init_db(app)

@app.route("/")
def index():
    from flask import make_response as _mkr
    from core.auth_utils import TOKEN_COOKIE, TOKEN_EXPIRE_H
    token = get_token_from_request()
    user  = load_user_from_token(token) if token else None
    if not user:
        return redirect("/auth/login?next=/xploiter/")
    return render_template("xploiter.html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, threaded=True)
