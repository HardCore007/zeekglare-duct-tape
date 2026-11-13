"""Unified notification dispatcher — Discord, Slack, Email (SMTP), Generic Webhook."""
import json
import threading
import smtplib
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime


def _discord_post(webhook_url: str, payload: dict):
    try:
        requests.post(webhook_url, json=payload, timeout=10)
    except Exception:
        pass


def _slack_post(webhook_url: str, payload: dict):
    try:
        requests.post(webhook_url, json=payload, timeout=10)
    except Exception:
        pass


def _generic_webhook_post(url: str, payload: dict, headers: dict = None):
    try:
        h = headers or {"Content-Type": "application/json"}
        requests.post(url, json=payload, headers=h, timeout=10)
    except Exception:
        pass


def _email_post(smtp_host: str, smtp_port: int, smtp_user: str, smtp_pass: str,
                sender: str, recipients: list, subject: str, body_html: str):
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = sender
        msg["To"] = ", ".join(recipients)
        msg.attach(MIMEText(body_html, "html"))

        if smtp_port == 465:
            server = smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=10)
        else:
            server = smtplib.SMTP(smtp_host, smtp_port, timeout=10)
            server.starttls()
        if smtp_user and smtp_pass:
            server.login(smtp_user, smtp_pass)
        server.sendmail(sender, recipients, msg.as_string())
        server.quit()
    except Exception:
        pass


def _build_payload(scan_type: str, target: str, findings: int, label: str,
                   username: str = "ZeekGlare", timestamp: str = None):
    ts = timestamp or datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    tool_label = label or scan_type.title()
    return {
        "scan_type": scan_type,
        "target": target,
        "findings": findings,
        "label": tool_label,
        "username": username,
        "timestamp": ts,
        "platform": "ZeekGlare Intelligence Platform",
    }


def _discord_embed(payload: dict):
    color = 0x22c55e if payload["findings"] > 0 else 0x3b82f6
    return {
        "embeds": [{
            "title": f"✅ Scan Complete — {payload['label']}",
            "description": (
                f"**Target:** `{payload['target']}`\n"
                f"**Findings:** {payload['findings']}\n"
                f"**Tool:** {payload['label']}\n"
                f"**User:** {payload['username']}\n"
                f"**Time:** {payload['timestamp']}"
            ),
            "color": color,
            "footer": {"text": payload["platform"]},
        }]
    }


def _slack_payload(payload: dict):
    color = "#22c55e" if payload["findings"] > 0 else "#3b82f6"
    return {
        "attachments": [{
            "color": color,
            "title": f"Scan Complete — {payload['label']}",
            "fields": [
                {"title": "Target", "value": payload["target"], "short": True},
                {"title": "Findings", "value": str(payload["findings"]), "short": True},
                {"title": "Tool", "value": payload["label"], "short": True},
                {"title": "User", "value": payload["username"], "short": True},
            ],
            "footer": payload["platform"],
            "ts": int(datetime.utcnow().timestamp()),
        }]
    }


def _email_html(payload: dict):
    color = "#22c55e" if payload["findings"] > 0 else "#3b82f6"
    return f"""<html><body style="font-family:sans-serif">
<h2 style="color:{color}">✅ Scan Complete — {payload['label']}</h2>
<table cellpadding="6">
<tr><td><b>Target</b></td><td>{payload['target']}</td></tr>
<tr><td><b>Findings</b></td><td>{payload['findings']}</td></tr>
<tr><td><b>Tool</b></td><td>{payload['label']}</td></tr>
<tr><td><b>User</b></td><td>{payload['username']}</td></tr>
<tr><td><b>Time</b></td><td>{payload['timestamp']}</td></tr>
</table>
<hr><p style="color:#666;font-size:12px">{payload['platform']}</p>
</body></html>"""


def dispatch(user_id: int, scan_type: str, target: str, findings: int, label: str = ""):
    """Fire notifications for a scan completion to all configured channels."""
    if not user_id:
        return

    def _send():
        try:
            from core.db import db
            from core.models import User
            from flask import current_app
            with current_app.app_context():
                user = User.query.get(user_id)
                if not user:
                    return

                settings = {}
                if user.settings_json:
                    try:
                        settings = json.loads(user.settings_json)
                    except Exception:
                        pass

                username = user.username
                payload = _build_payload(scan_type, target, findings, label, username)

                channels = settings.get("notification_channels", {})

                # Discord
                if channels.get("discord", True):
                    dw = user.discord_webhook or settings.get("discord_webhook", "")
                    if dw and dw.startswith("https://discord.com/api/webhooks/"):
                        _discord_post(dw, _discord_embed(payload))

                # Slack
                if channels.get("slack", True):
                    sw = settings.get("slack_webhook", "").strip()
                    if sw and sw.startswith("https://hooks.slack.com/"):
                        _slack_post(sw, _slack_payload(payload))

                # Generic Webhook
                if channels.get("webhook", True):
                    gw = settings.get("generic_webhook", "").strip()
                    if gw and gw.startswith("http"):
                        headers = settings.get("webhook_headers", {})
                        _generic_webhook_post(gw, payload, headers)

                # Email
                if channels.get("email", True):
                    ec = settings.get("email_config", {})
                    if ec.get("smtp_host") and ec.get("recipients"):
                        _email_post(
                            smtp_host=ec["smtp_host"],
                            smtp_port=ec.get("smtp_port", 587),
                            smtp_user=ec.get("smtp_user", ""),
                            smtp_pass=ec.get("smtp_pass", ""),
                            sender=ec.get("sender", ec.get("smtp_user", "zeekglare@localhost")),
                            recipients=ec["recipients"] if isinstance(ec["recipients"], list) else [ec["recipients"]],
                            subject=f"[ZeekGlare] {payload['label']} scan complete — {payload['target']}",
                            body_html=_email_html(payload),
                        )
        except Exception:
            pass

    t = threading.Thread(target=_send, daemon=True)
    t.start()


def test_channel(user, channel: str) -> dict:
    """Test a single notification channel and return a status dict."""
    settings = {}
    if user.settings_json:
        try:
            settings = json.loads(user.settings_json)
        except Exception:
            pass

    username = user.username
    payload = _build_payload("test", "zeekglare.local", 3, "Test Scan", username)

    if channel == "discord":
        dw = user.discord_webhook or settings.get("discord_webhook", "")
        if not dw:
            return {"ok": False, "error": "No Discord webhook configured."}
        if not dw.startswith("https://discord.com/api/webhooks/"):
            return {"ok": False, "error": "Invalid Discord webhook URL."}
        try:
            r = requests.post(dw, json=_discord_embed(payload), timeout=10)
            if r.status_code in (200, 204):
                return {"ok": True, "message": "Discord test sent!"}
            return {"ok": False, "error": f"Discord returned {r.status_code}: {r.text[:200]}"}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    if channel == "slack":
        sw = settings.get("slack_webhook", "").strip()
        if not sw:
            return {"ok": False, "error": "No Slack webhook configured."}
        if not sw.startswith("https://hooks.slack.com/"):
            return {"ok": False, "error": "Invalid Slack webhook URL."}
        try:
            r = requests.post(sw, json=_slack_payload(payload), timeout=10)
            if r.status_code == 200:
                return {"ok": True, "message": "Slack test sent!"}
            return {"ok": False, "error": f"Slack returned {r.status_code}: {r.text[:200]}"}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    if channel == "webhook":
        gw = settings.get("generic_webhook", "").strip()
        if not gw:
            return {"ok": False, "error": "No generic webhook URL configured."}
        if not gw.startswith("http"):
            return {"ok": False, "error": "Invalid webhook URL."}
        try:
            headers = settings.get("webhook_headers", {})
            r = requests.post(gw, json=payload, headers=headers, timeout=10)
            if r.status_code in (200, 201, 202, 204):
                return {"ok": True, "message": f"Webhook test sent! ({r.status_code})"}
            return {"ok": False, "error": f"Webhook returned {r.status_code}: {r.text[:200]}"}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    if channel == "email":
        ec = settings.get("email_config", {})
        if not ec.get("smtp_host"):
            return {"ok": False, "error": "No SMTP host configured."}
        if not ec.get("recipients"):
            return {"ok": False, "error": "No recipients configured."}
        try:
            _email_post(
                smtp_host=ec["smtp_host"],
                smtp_port=ec.get("smtp_port", 587),
                smtp_user=ec.get("smtp_user", ""),
                smtp_pass=ec.get("smtp_pass", ""),
                sender=ec.get("sender", ec.get("smtp_user", "zeekglare@localhost")),
                recipients=ec["recipients"] if isinstance(ec["recipients"], list) else [ec["recipients"]],
                subject="[ZeekGlare] Test Notification",
                body_html=_email_html(payload),
            )
            return {"ok": True, "message": "Email test sent!"}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    return {"ok": False, "error": f"Unknown channel: {channel}"}
