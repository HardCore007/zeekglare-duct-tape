"""SQLAlchemy models for ZeekGlare user management."""
from datetime import datetime
from core.db import db


class User(db.Model):
    __tablename__ = "users"
    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(64),  unique=True,  nullable=False, index=True)
    email         = db.Column(db.String(120), unique=True,  nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role          = db.Column(db.String(20),  default="user")    # "admin" | "user"
    status        = db.Column(db.String(20),  default="active")  # "active" | "suspended" | "disabled"
    created_at    = db.Column(db.DateTime,    default=datetime.utcnow)
    last_login    = db.Column(db.DateTime,    nullable=True)

    discord_webhook  = db.Column(db.String(512), nullable=True)   # Discord webhook URL
    alert_sound      = db.Column(db.Boolean, default=True)        # browser sound on scan complete
    settings_json    = db.Column(db.Text, nullable=True)          # JSON blob: all user settings (API keys, SSH configs, prefs)

    permissions   = db.relationship("UserToolPermission", backref="user",
                                    lazy="dynamic", cascade="all, delete-orphan")
    audit_logs    = db.relationship("AuditLog", backref="user",
                                    lazy="dynamic", cascade="all, delete-orphan")

    def to_dict(self, include_permissions=False):
        d = {
            "id":              self.id,
            "username":        self.username,
            "email":           self.email,
            "role":            self.role,
            "status":          self.status,
            "created_at":      self.created_at.isoformat() if self.created_at else None,
            "last_login":      self.last_login.isoformat() if self.last_login else None,
            "discord_webhook": self.discord_webhook or "",
            "alert_sound":     self.alert_sound if self.alert_sound is not None else True,
        }
        if include_permissions:
            d["permissions"] = [p.module_id for p in self.permissions.filter_by(enabled=True)]
        return d


class UserToolPermission(db.Model):
    __tablename__ = "user_tool_permissions"
    __table_args__ = (db.UniqueConstraint("user_id", "module_id"),)
    id        = db.Column(db.Integer, primary_key=True)
    user_id   = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    module_id = db.Column(db.String(80), nullable=False)   # e.g. "domain", "xploiter", "xss"
    enabled   = db.Column(db.Boolean, default=True)


class AuditLog(db.Model):
    __tablename__ = "audit_logs"
    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    username   = db.Column(db.String(64))
    action     = db.Column(db.String(120), nullable=False)
    details    = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    timestamp  = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    def to_dict(self):
        return {
            "id":         self.id,
            "user_id":    self.user_id,
            "username":   self.username,
            "action":     self.action,
            "details":    self.details,
            "ip_address": self.ip_address,
            "timestamp":  self.timestamp.isoformat() if self.timestamp else None,
        }


class LoginAttempt(db.Model):
    """Tracks login attempts for rate-limiting."""
    __tablename__ = "login_attempts"
    id         = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), index=True)
    username   = db.Column(db.String(64))
    success    = db.Column(db.Boolean, default=False)
    timestamp  = db.Column(db.DateTime, default=datetime.utcnow, index=True)


class ActiveSession(db.Model):
    """Tracks currently active user sessions."""
    __tablename__ = "active_sessions"
    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    username   = db.Column(db.String(64))
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(256))
    app_name   = db.Column(db.String(32))   # "zeekglare" | "xploiter" | "misc"
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen  = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id":         self.id,
            "user_id":    self.user_id,
            "username":   self.username,
            "ip_address": self.ip_address,
            "app_name":   self.app_name,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_seen":  self.last_seen.isoformat() if self.last_seen else None,
        }
