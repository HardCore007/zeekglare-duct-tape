"""Auto API Docs — introspect all registered routes and emit a JSON OpenAPI-ish spec."""
import re
from flask import Blueprint, jsonify, current_app
from core.auth_utils import login_required

apidocs_bp = Blueprint("apidocs", __name__)


@apidocs_bp.route("/api/docs")
@login_required
def api_docs():
    """Return a JSON description of all registered routes."""
    routes = []
    for rule in current_app.url_map.iter_rules():
        if rule.endpoint == "static":
            continue
        methods = sorted(m for m in rule.methods if m not in ("OPTIONS", "HEAD"))
        # Try to find docstring from endpoint function
        view_func = current_app.view_functions.get(rule.endpoint)
        doc = (view_func.__doc__ or "").strip().split("\n")[0] if view_func else ""
        routes.append({
            "path": rule.rule,
            "methods": methods,
            "endpoint": rule.endpoint,
            "description": doc,
        })
    routes.sort(key=lambda r: r["path"])
    return jsonify({
        "title": "ZeekGlare API",
        "version": "1.0.0",
        "base_url": "/",
        "routes_count": len(routes),
        "routes": routes,
    })


@apidocs_bp.route("/api/docs/health")
@login_required
def api_docs_health():
    """Quick health-check for the API itself."""
    return jsonify({"status": "ok", "routes": len(list(current_app.url_map.iter_rules()))})
