"""Two-Factor Authentication: TOTP and WebAuthn/Passkey support."""
import json, base64, threading, pathlib, secrets, time, io
from flask import Blueprint, request, jsonify, g

from core.db import db
from core.models import User
from core.auth_utils import (
    get_token_from_request, load_user_from_token, audit,
    generate_token, create_session, TOKEN_COOKIE, TOKEN_EXPIRE_H,
    get_user_modules,
)

twofa_bp = Blueprint("twofa", __name__)

# ── Storage (separate JSON file to avoid DB migration) ───────────────────────
_2FA_PATH = pathlib.Path("data/user_2fa.json")
_2FA_LOCK = threading.Lock()


def _load_2fa():
    try:
        with _2FA_PATH.open() as f:
            return json.load(f) or {}
    except Exception:
        return {}


def _save_2fa(data):
    try:
        _2FA_PATH.parent.mkdir(parents=True, exist_ok=True)
        with _2FA_PATH.open("w") as f:
            json.dump(data, f, indent=2)
        return True
    except Exception:
        return False


def _user_record(uid):
    data = _load_2fa()
    return data.get(str(uid), {})


def _set_user_record(uid, rec):
    with _2FA_LOCK:
        data = _load_2fa()
        if rec is None:
            data.pop(str(uid), None)
        else:
            data[str(uid)] = rec
        return _save_2fa(data)


def user_has_totp(uid):
    rec = _user_record(uid)
    return bool(rec.get("totp_enabled") and rec.get("totp_secret"))


def user_has_passkey(uid):
    rec = _user_record(uid)
    return bool(rec.get("passkeys"))


def verify_totp_code(uid, code):
    """Verify a 6-digit TOTP code against the stored secret."""
    try:
        import pyotp  # type: ignore
    except ImportError:
        return False
    rec = _user_record(uid)
    secret = rec.get("totp_secret")
    if not secret:
        return False
    try:
        return pyotp.TOTP(secret).verify(str(code).strip(), valid_window=1)
    except Exception:
        return False


# ── Auth helper ──────────────────────────────────────────────────────────────
def _require_user():
    token = get_token_from_request()
    user  = load_user_from_token(token) if token else None
    return user


# ── TOTP enrollment ──────────────────────────────────────────────────────────

@twofa_bp.route("/api/2fa/totp/status")
def totp_status():
    user = _require_user()
    if not user:
        return jsonify({"error": "Not authenticated"}), 401
    rec = _user_record(user.id)
    return jsonify({
        "enabled": bool(rec.get("totp_enabled")),
        "passkeys": [{"id": p["id"], "label": p.get("label", "Passkey"),
                      "created": p.get("created")} for p in rec.get("passkeys", [])],
    })


@twofa_bp.route("/api/2fa/totp/enroll", methods=["POST"])
def totp_enroll():
    """Generate a new TOTP secret and return provisioning URI + QR data URL."""
    user = _require_user()
    if not user:
        return jsonify({"error": "Not authenticated"}), 401
    try:
        import pyotp  # type: ignore
    except ImportError:
        return jsonify({"error": "TOTP support not installed on server (pip install pyotp)."}), 500

    secret = pyotp.random_base32()
    issuer = "ZeekGlare"
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=user.username, issuer_name=issuer)

    # Generate QR code as data URL (optional — UI can fall back to manual entry)
    qr_data_url = ""
    try:
        import qrcode  # type: ignore
        img = qrcode.make(uri)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        qr_data_url = "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()
    except Exception:
        pass

    # Stash pending secret (NOT enabled yet — must be confirmed)
    rec = _user_record(user.id)
    rec["totp_pending"] = secret
    _set_user_record(user.id, rec)

    return jsonify({
        "secret": secret,
        "uri": uri,
        "qr": qr_data_url,
        "issuer": issuer,
        "account": user.username,
    })


@twofa_bp.route("/api/2fa/totp/verify", methods=["POST"])
def totp_verify():
    """Confirm pending enrollment by verifying a code."""
    user = _require_user()
    if not user:
        return jsonify({"error": "Not authenticated"}), 401
    try:
        import pyotp  # type: ignore
    except ImportError:
        return jsonify({"error": "TOTP support not installed on server."}), 500

    data = request.get_json(silent=True) or {}
    code = (data.get("code") or "").strip()
    rec = _user_record(user.id)
    secret = rec.get("totp_pending")
    if not secret:
        return jsonify({"error": "No pending TOTP enrollment. Start enrollment first."}), 400
    if not pyotp.TOTP(secret).verify(code, valid_window=1):
        return jsonify({"error": "Invalid code. Please try again."}), 400

    # Generate recovery codes
    recovery = [secrets.token_hex(4).upper() for _ in range(8)]
    rec["totp_secret"] = secret
    rec["totp_enabled"] = True
    rec["totp_pending"] = None
    rec["recovery_codes"] = recovery
    _set_user_record(user.id, rec)

    audit("2fa_totp_enabled", f"User '{user.username}' enabled TOTP 2FA",
          user_id=user.id, username=user.username)
    return jsonify({"ok": True, "recovery_codes": recovery})


@twofa_bp.route("/api/2fa/totp/disable", methods=["POST"])
def totp_disable():
    user = _require_user()
    if not user:
        return jsonify({"error": "Not authenticated"}), 401
    data = request.get_json(silent=True) or {}
    code = (data.get("code") or "").strip()
    rec = _user_record(user.id)
    if not rec.get("totp_enabled"):
        return jsonify({"ok": True})
    # Require a valid current code to disable
    if not verify_totp_code(user.id, code):
        return jsonify({"error": "Enter a valid TOTP code to disable 2FA."}), 400
    rec["totp_enabled"] = False
    rec["totp_secret"] = None
    rec["recovery_codes"] = []
    _set_user_record(user.id, rec)
    audit("2fa_totp_disabled", f"User '{user.username}' disabled TOTP 2FA",
          user_id=user.id, username=user.username)
    return jsonify({"ok": True})


# ── 2FA challenge during login ───────────────────────────────────────────────
# Pending-2FA tokens are short-lived stubs handed out after password validation.
_PENDING_2FA = {}        # token -> {"user_id": int, "expires": float}
_PENDING_LOCK = threading.Lock()
_PENDING_TTL = 300       # 5 minutes


def issue_pending_2fa(user_id):
    tok = secrets.token_urlsafe(24)
    with _PENDING_LOCK:
        _PENDING_2FA[tok] = {"user_id": user_id, "expires": time.time() + _PENDING_TTL}
    return tok


def _consume_pending(token):
    now = time.time()
    with _PENDING_LOCK:
        # Purge expired
        for t in list(_PENDING_2FA.keys()):
            if _PENDING_2FA[t]["expires"] < now:
                _PENDING_2FA.pop(t, None)
        rec = _PENDING_2FA.get(token)
        return rec


# ── Passkey / WebAuthn ───────────────────────────────────────────────────────
_WEBAUTHN_CHALLENGES = {}   # user_id -> {"challenge": bytes, "expires": float}
_WA_LOCK = threading.Lock()
_WA_TTL = 300


def _b64u_encode(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _b64u_decode(s):
    if isinstance(s, str):
        s = s.encode()
    pad = b"=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _rp_info():
    """Derive Relying Party info from request host."""
    host = request.host.split(":")[0]
    return {"id": host, "name": "ZeekGlare Intelligence Platform",
            "origin": f"{request.scheme}://{request.host}"}


@twofa_bp.route("/api/2fa/passkey/register/begin", methods=["POST"])
def passkey_register_begin():
    user = _require_user()
    if not user:
        return jsonify({"error": "Not authenticated"}), 401
    try:
        from webauthn import generate_registration_options, options_to_json  # type: ignore
        from webauthn.helpers.structs import (
            PublicKeyCredentialDescriptor, AuthenticatorSelectionCriteria,
            ResidentKeyRequirement, UserVerificationRequirement,
        )
    except ImportError:
        return jsonify({"error": "WebAuthn library not installed (pip install webauthn)."}), 500

    rp = _rp_info()
    rec = _user_record(user.id)
    existing = rec.get("passkeys", []) or []
    exclude = [PublicKeyCredentialDescriptor(id=_b64u_decode(p["credential_id"]))
               for p in existing]

    opts = generate_registration_options(
        rp_id=rp["id"],
        rp_name=rp["name"],
        user_id=str(user.id).encode(),
        user_name=user.username,
        user_display_name=user.username,
        exclude_credentials=exclude,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
    )

    with _WA_LOCK:
        _WEBAUTHN_CHALLENGES[user.id] = {
            "challenge": opts.challenge,
            "expires": time.time() + _WA_TTL,
            "type": "register",
        }

    # Return in JSON form expected by browser navigator.credentials.create
    out = json.loads(options_to_json(opts))
    return jsonify(out)


@twofa_bp.route("/api/2fa/passkey/register/complete", methods=["POST"])
def passkey_register_complete():
    user = _require_user()
    if not user:
        return jsonify({"error": "Not authenticated"}), 401
    try:
        from webauthn import verify_registration_response  # type: ignore
    except ImportError:
        return jsonify({"error": "WebAuthn library not installed."}), 500

    body = request.get_json(silent=True) or {}
    cred = body.get("credential")
    label = (body.get("label") or "Passkey").strip()[:60]
    if not cred:
        return jsonify({"error": "Missing credential."}), 400

    with _WA_LOCK:
        ch_rec = _WEBAUTHN_CHALLENGES.get(user.id)
    if not ch_rec or ch_rec["expires"] < time.time():
        return jsonify({"error": "Challenge expired. Try again."}), 400

    rp = _rp_info()
    try:
        verification = verify_registration_response(
            credential=cred,
            expected_challenge=ch_rec["challenge"],
            expected_origin=rp["origin"],
            expected_rp_id=rp["id"],
        )
    except Exception as e:
        return jsonify({"error": f"Registration verification failed: {e}"}), 400

    rec = _user_record(user.id)
    passkeys = rec.get("passkeys", []) or []
    new_pk = {
        "id": secrets.token_hex(8),
        "credential_id": _b64u_encode(verification.credential_id),
        "public_key": _b64u_encode(verification.credential_public_key),
        "sign_count": verification.sign_count,
        "label": label,
        "created": time.strftime("%Y-%m-%d"),
    }
    passkeys.append(new_pk)
    rec["passkeys"] = passkeys
    _set_user_record(user.id, rec)
    with _WA_LOCK:
        _WEBAUTHN_CHALLENGES.pop(user.id, None)

    audit("passkey_registered", f"User '{user.username}' registered passkey '{label}'",
          user_id=user.id, username=user.username)
    return jsonify({"ok": True, "id": new_pk["id"]})


@twofa_bp.route("/api/2fa/passkey/<pkid>", methods=["DELETE"])
def passkey_delete(pkid):
    user = _require_user()
    if not user:
        return jsonify({"error": "Not authenticated"}), 401
    rec = _user_record(user.id)
    passkeys = rec.get("passkeys", []) or []
    new_list = [p for p in passkeys if p.get("id") != pkid]
    if len(new_list) == len(passkeys):
        return jsonify({"error": "Passkey not found."}), 404
    rec["passkeys"] = new_list
    _set_user_record(user.id, rec)
    audit("passkey_removed", f"User '{user.username}' removed passkey {pkid}",
          user_id=user.id, username=user.username)
    return jsonify({"ok": True})


@twofa_bp.route("/api/2fa/challenge", methods=["POST"])
def twofa_challenge():
    """Step 2 of login — submit TOTP code with the pending token."""
    from flask import make_response
    data = request.get_json(silent=True) or {}
    pending = data.get("pending") or ""
    code = (data.get("code") or "").strip()

    rec = _consume_pending(pending)
    if not rec:
        return jsonify({"error": "Challenge expired. Please sign in again."}), 401
    user = User.query.get(rec["user_id"])
    if not user:
        return jsonify({"error": "Account not found."}), 401

    # Try TOTP first, then recovery codes
    valid = False
    if verify_totp_code(user.id, code):
        valid = True
    else:
        ur = _user_record(user.id)
        codes = ur.get("recovery_codes") or []
        norm = code.replace("-", "").replace(" ", "").upper()
        if norm in codes:
            codes.remove(norm)
            ur["recovery_codes"] = codes
            _set_user_record(user.id, ur)
            valid = True

    if not valid:
        return jsonify({"error": "Invalid code."}), 401

    # Consume the pending token
    with _PENDING_LOCK:
        _PENDING_2FA.pop(pending, None)

    # Issue real session
    create_session(user, app_name="zeekglare")
    audit("login_success", f"User '{user.username}' completed 2FA challenge",
          user_id=user.id, username=user.username)
    token = generate_token(user)
    modules = list(get_user_modules(user))
    resp = make_response(jsonify({
        "ok": True,
        "user": user.to_dict(),
        "modules": modules,
        "redirect": "/",
    }))
    resp.set_cookie(
        TOKEN_COOKIE, token,
        httponly=True, samesite="Lax",
        max_age=TOKEN_EXPIRE_H * 3600, path="/",
    )
    return resp
