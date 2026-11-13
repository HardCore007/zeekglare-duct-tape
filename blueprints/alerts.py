"""Alerts blueprint — per-user notification settings (Discord, Slack, Email, Webhook, sound)."""
import json
import requests as _req
from flask import Blueprint, request, jsonify, g
from core.db import db
from core.auth_utils import login_required
from services.notification_hub import test_channel

alerts_bp = Blueprint("alerts", __name__)


@alerts_bp.route("/api/alerts/settings", methods=["GET"])
@login_required
def get_settings():
    u = g.current_user
    settings = {}
    if u.settings_json:
        try:
            settings = json.loads(u.settings_json)
        except Exception:
            pass

    return jsonify({
        "alert_sound":      u.alert_sound if u.alert_sound is not None else True,
        "discord_webhook":  u.discord_webhook or "",
        "slack_webhook":    settings.get("slack_webhook", ""),
        "generic_webhook":  settings.get("generic_webhook", ""),
        "webhook_headers":  settings.get("webhook_headers", {}),
        "email_config":     settings.get("email_config", {}),
        "notification_channels": settings.get("notification_channels", {
            "discord": True,
            "slack": True,
            "webhook": True,
            "email": True,
        }),
    })


@alerts_bp.route("/api/alerts/settings", methods=["POST"])
@login_required
def save_settings():
    data = request.get_json(silent=True) or {}
    u    = g.current_user

    if "alert_sound" in data:
        u.alert_sound = bool(data["alert_sound"])

    if "discord_webhook" in data:
        webhook = (data["discord_webhook"] or "").strip()
        if webhook and not webhook.startswith("https://discord.com/api/webhooks/"):
            return jsonify({"error": "Invalid Discord webhook URL. Must start with https://discord.com/api/webhooks/"}), 400
        u.discord_webhook = webhook or None

    # Merge other settings into settings_json blob
    settings = {}
    if u.settings_json:
        try:
            settings = json.loads(u.settings_json)
        except Exception:
            pass

    if "slack_webhook" in data:
        sw = (data["slack_webhook"] or "").strip()
        if sw and not sw.startswith("https://hooks.slack.com/"):
            return jsonify({"error": "Invalid Slack webhook URL. Must start with https://hooks.slack.com/"}), 400
        settings["slack_webhook"] = sw or None

    if "generic_webhook" in data:
        gw = (data["generic_webhook"] or "").strip()
        if gw and not gw.startswith("http"):
            return jsonify({"error": "Invalid webhook URL. Must start with http(s)."}), 400
        settings["generic_webhook"] = gw or None

    if "webhook_headers" in data:
        settings["webhook_headers"] = data["webhook_headers"] if isinstance(data["webhook_headers"], dict) else {}

    if "email_config" in data:
        ec = data["email_config"]
        if not isinstance(ec, dict):
            return jsonify({"error": "email_config must be an object."}), 400
        settings["email_config"] = {
            "smtp_host": ec.get("smtp_host", "").strip(),
            "smtp_port": int(ec.get("smtp_port", 587)),
            "smtp_user": ec.get("smtp_user", "").strip(),
            "smtp_pass": ec.get("smtp_pass", "").strip(),
            "sender": ec.get("sender", "").strip(),
            "recipients": ec.get("recipients", []),
        }

    if "notification_channels" in data:
        nc = data["notification_channels"]
        if isinstance(nc, dict):
            settings["notification_channels"] = {
                "discord": bool(nc.get("discord", True)),
                "slack": bool(nc.get("slack", True)),
                "webhook": bool(nc.get("webhook", True)),
                "email": bool(nc.get("email", True)),
            }

    u.settings_json = json.dumps(settings)
    db.session.commit()
    return jsonify({"ok": True})


@alerts_bp.route("/api/alerts/test/<channel>", methods=["POST"])
@login_required
def test_any_channel(channel):
    u = g.current_user
    result = test_channel(u, channel)
    if result["ok"]:
        return jsonify(result)
    return jsonify(result), 400
