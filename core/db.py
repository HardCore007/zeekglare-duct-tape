"""Shared SQLAlchemy database instance for ZeekGlare auth system."""
import os, json, secrets, pathlib, stat
from flask_sqlalchemy import SQLAlchemy

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "data", "zeekglare_auth.db")

db = SQLAlchemy()


def get_secret_key() -> str:
    """Load or generate a persistent SECRET_KEY shared across all three apps."""
    cfg_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "data", "auth_config.json")
    pathlib.Path(os.path.dirname(cfg_path)).mkdir(parents=True, exist_ok=True)
    if os.path.exists(cfg_path):
        with open(cfg_path) as f:
            return json.load(f).get("secret_key", "")
    key = secrets.token_hex(48)
    with open(cfg_path, "w") as f:
        json.dump({"secret_key": key}, f, indent=2)
    os.chmod(cfg_path, stat.S_IRUSR | stat.S_IWUSR)
    return key


def configure_app(app):
    """Apply auth DB config to a Flask app instance (call before init_db)."""
    app.config["SECRET_KEY"] = get_secret_key()
    app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DB_PATH}"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = True
    db.init_app(app)


def init_db(app):
    """Create tables and seed default admin if no users exist.
    configure_app() must have been called first."""
    import core.models  # noqa: ensure models are registered with SQLAlchemy
    with app.app_context():
        db.create_all()
        _seed_admin()


def _seed_admin():
    from core.models import User  # noqa: local import to avoid circular
    from flask_bcrypt import Bcrypt
    bcrypt = Bcrypt()
    if User.query.count() == 0:
        raw_pw = os.environ.get("ZEEKGLARE_ADMIN_PASSWORD")
        if not raw_pw:
            print("[AUTH] Set ZEEKGLARE_ADMIN_PASSWORD to create the first administrator.")
            return
        if len(raw_pw) < 16:
            raise ValueError("ZEEKGLARE_ADMIN_PASSWORD must be at least 16 characters.")
        admin = User(
            username="admin",
            email="admin@zeekglare.local",
            password_hash=bcrypt.generate_password_hash(raw_pw).decode(),
            role="admin",
            status="active",
        )
        db.session.add(admin)
        db.session.commit()
        print("[AUTH] Created the initial admin account.")
