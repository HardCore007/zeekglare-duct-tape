from core.auth_utils import module_required
"""Scheduler blueprint — CRUD for recurring scans."""
from flask import Blueprint, request, jsonify
from services.scheduler import (
    list_schedules, add_schedule, remove_schedule, toggle_schedule,
)

schedule_bp = Blueprint("schedule", __name__)


@schedule_bp.route("/api/schedules", methods=["GET"])
@module_required("scheduler")
def get_schedules():
    return jsonify(list_schedules())


@schedule_bp.route("/api/schedules", methods=["POST"])
@module_required("scheduler")
def create_schedule():
    body = request.get_json(silent=True) or {}
    scan_type      = body.get("scan_type", "domain")
    target         = (body.get("target") or "").strip()
    interval_hours = int(body.get("interval_hours", 24))
    options        = body.get("options", {})

    if not target:
        return jsonify({"error": "target required"}), 400
    if scan_type not in ("asn", "domain"):
        return jsonify({"error": "scan_type must be asn or domain"}), 400
    if interval_hours < 1:
        return jsonify({"error": "interval_hours must be >= 1"}), 400

    s = add_schedule(scan_type, target, interval_hours, options)
    return jsonify(s), 201


@schedule_bp.route("/api/schedules/<sid>", methods=["DELETE"])
@module_required("scheduler")
def delete_schedule(sid):
    ok = remove_schedule(sid)
    if not ok:
        return jsonify({"error": "Not found"}), 404
    return jsonify({"ok": True})


@schedule_bp.route("/api/schedules/<sid>/toggle", methods=["POST"])
@module_required("scheduler")
@module_required("scheduler")
def toggle(sid):
    body    = request.get_json(silent=True) or {}
    enabled = bool(body.get("enabled", True))
    ok      = toggle_schedule(sid, enabled)
    if not ok:
        return jsonify({"error": "Not found"}), 404
    return jsonify({"ok": True, "enabled": enabled})
