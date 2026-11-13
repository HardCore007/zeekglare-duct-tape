"""Export blueprint — download sessions as CSV, JSON, HTML, PDF."""
import re, uuid
from flask import Blueprint, request, jsonify, Response
from core.session_manager import SessionManager
from services.exporter import export_csv, export_json, export_html, export_pdf

export_bp = Blueprint("export", __name__)


def _safe_filename(name):
    """Sanitise session name for use in a filename."""
    name = re.sub(r'[^\w\s\-.]', '', name)          # strip unsafe chars
    name = re.sub(r'\s+', '_', name.strip())         # spaces → underscores
    return name[:80] if name else 'export'


@export_bp.route("/api/export/<sid>/<fmt>")
def export_session(sid, fmt):
    fmt = fmt.lower()
    try:
        # Build filename from session title + random suffix
        session = SessionManager.get(sid)
        title = _safe_filename(session.get("name", "") if session else "")
        rand = str(uuid.uuid4())[:6]
        fname = f"{title}_{rand}.{fmt}" if title != "export" else f"zeekglare_{sid[:8]}_{rand}.{fmt}"

        if fmt == "json":
            data     = export_json(sid)
            mimetype = "application/json"
        elif fmt == "csv":
            data     = export_csv(sid)
            mimetype = "text/csv"
        elif fmt == "html":
            data     = export_html(sid)
            mimetype = "text/html"
        elif fmt == "pdf":
            data     = export_pdf(sid)
            mimetype = "application/pdf"
        else:
            return jsonify({"error": f"Unknown format: {fmt}"}), 400

        return Response(
            data,
            mimetype=mimetype,
            headers={
                "Content-Disposition": f'attachment; filename="{fname}"',
                "Content-Length": str(len(data)),
            },
        )
    except ValueError as e:
        return jsonify({"error": str(e)}), 404
    except Exception as e:
        return jsonify({"error": f"Export failed: {str(e)}"}), 500
