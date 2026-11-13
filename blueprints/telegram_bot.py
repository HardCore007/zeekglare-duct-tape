"""Telegram bot blueprint — config, lifecycle, test."""
import json, os, pathlib, threading
from flask import Blueprint, request, jsonify

tg_bp  = Blueprint("telegram_bot", __name__)
_bot   = None
_lock  = threading.Lock()
_CFG   = "data/telegram_config.json"


def _load():
    try:
        with open(_CFG) as f:
            return json.load(f)
    except Exception:
        return {}


def _save(cfg):
    pathlib.Path("data").mkdir(exist_ok=True)
    with open(_CFG, "w") as f:
        json.dump(cfg, f)


def _start(cfg):
    global _bot
    from services.telegram_service import TelegramBot
    with _lock:
        if _bot and _bot.is_running():
            return
        _bot = TelegramBot(
            token          = cfg["token"],
            allowed_chat_id= cfg.get("chat_id") or None,
            anthropic_key  = cfg.get("anthropic_key") or os.environ.get("ANTHROPIC_API_KEY", ""),
        )
        _bot.start()


def _stop():
    global _bot
    with _lock:
        if _bot:
            _bot.stop()
            _bot = None


# ── Routes ────────────────────────────────────────────────────────────────────

@tg_bp.route("/api/telegram/config", methods=["GET"])
def tg_get():
    cfg = _load()
    return jsonify({
        "enabled":    cfg.get("enabled", False),
        "chat_id":    cfg.get("chat_id", ""),
        "has_token":  bool(cfg.get("token")),
        "token_tail": ("…" + cfg["token"][-6:]) if cfg.get("token") else "",
        "running":    _bot is not None and _bot.is_running(),
    })


@tg_bp.route("/api/telegram/config", methods=["POST"])
def tg_post():
    body = request.get_json(silent=True) or {}
    cfg  = _load()
    if body.get("token"):
        cfg["token"] = body["token"]
    if "chat_id" in body:
        cfg["chat_id"] = body["chat_id"]
    if "enabled" in body:
        cfg["enabled"] = bool(body["enabled"])
    if "anthropic_key" in body:
        cfg["anthropic_key"] = body["anthropic_key"]
    _save(cfg)
    _stop()
    if cfg.get("enabled") and cfg.get("token"):
        try:
            _start(cfg)
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 500
    return jsonify({"ok": True, "running": _bot is not None and _bot.is_running()})


@tg_bp.route("/api/telegram/status")
def tg_status():
    return jsonify({"running": _bot is not None and _bot.is_running()})


@tg_bp.route("/api/telegram/test", methods=["POST"])
def tg_test():
    if not _bot or not _bot.is_running():
        return jsonify({"error": "Bot not running — enable it first."}), 400
    body    = request.get_json(silent=True) or {}
    chat_id = body.get("chat_id") or _load().get("chat_id")
    if not chat_id:
        return jsonify({"error": "No chat_id configured"}), 400
    _bot.send(chat_id,
        "✅ *ZeekGlare* bot is connected!\n\n"
        "Use /help to see available commands.\n"
        "_Send any message to chat with ZeekGlare AI._"
    )
    return jsonify({"ok": True})


@tg_bp.route("/api/telegram/stop", methods=["POST"])
def tg_stop_route():
    _stop()
    return jsonify({"ok": True})


# ── Auto-start on import ──────────────────────────────────────────────────────
def _auto_start():
    cfg = _load()
    if cfg.get("enabled") and cfg.get("token"):
        try:
            _start(cfg)
        except Exception as e:
            import logging
            logging.getLogger(__name__).error("Telegram auto-start: %s", e)

_auto_start()
