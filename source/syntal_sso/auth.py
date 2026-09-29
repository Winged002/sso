from __future__ import annotations

import base64

from bson import ObjectId
from flask import Blueprint, abort, current_app, flash, g, jsonify, redirect, render_template, request, session, url_for

from .db import db
from .security import hash_password, login_required, verify_password
from .acl import audit
from .util import public_id, utcnow
from .mailer import send_security_email
from .mfa import (
    encrypt_secret,
    generate_totp_secret,
    provisioning_uri,
    totp_configured,
    totp_enabled,
    totp_secret_for_user,
    verify_totp,
)
from . import passkeys

bp = Blueprint("auth", __name__)


def _security_notice(user, title, message, detail=None):
    email=(user.get("email") or "").strip()
    if not email:
        return
    try:
        base=current_app.config.get("PUBLIC_BASE_URL","https://sso.syntal.pro").rstrip("/")
        result=send_security_email(to=email,recipient_name=user.get("name"),title=title,message=message,detail=detail,action_url=base+url_for("auth.account")+"#security",action_label="Review security")
        if not result.get("ok") and result.get("configured"):
            current_app.logger.warning("Security email delivery failed for %s: %s",_user_id(user),result.get("error"))
    except Exception:
        current_app.logger.exception("Security notification could not be sent")


def _safe_next(value):
    return value if value and value.startswith("/") and not value.startswith("//") else None


def _user_id(user):
    return user.get("syntal_user_id") or str(user.get("_id"))


def _find_user(uid):
    if not uid:
        return None
    user = db().users.find_one({"syntal_user_id": uid, "status": {"$ne": "deleted"}})
    if user:
        return user
    try:
        return db().users.find_one({"_id": ObjectId(str(uid)), "status": {"$ne": "deleted"}})
    except Exception:
        return None


def _login_session(user, *, next_url=None, method="pwd", aal2=False):
    uid = _user_id(user)
    session.clear()
    session["user_id"] = uid
    session["syntal_user_id"] = uid
    session["session_epoch"] = user.get("session_epoch", 0)
    session["auth_time"] = int(utcnow().timestamp())
    session["amr"] = [method]
    session["acr"] = "urn:syntal:loa:2" if aal2 else "urn:syntal:loa:1"
    audit("account.login", user_id=uid, detail={"method": method, "acr": session["acr"]})
    return _safe_next(next_url) or url_for("organizations.dashboard")


def _begin_password_mfa(user, next_url):
    uid = _user_id(user)
    session.clear()
    session["preauth_user_id"] = uid
    session["preauth_next"] = _safe_next(next_url)
    session["preauth_amr"] = ["pwd"]
    session["preauth_started_at"] = int(utcnow().timestamp())


def _passkey_challenge(value):
    try:
        raw = str(value or "")
        return base64.urlsafe_b64decode(raw + "=" * ((4 - len(raw) % 4) % 4))
    except Exception:
        return b""


def _challenge_text(value: bytes):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


@bp.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("organizations.dashboard"))
    next_url = _safe_next(request.values.get("next"))
    invitation_id = (request.values.get("invitation") or "").strip()
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        user = db().users.find_one({"email": email, "status": {"$ne": "deleted"}})
        stored = (user or {}).get("password_hash") or (user or {}).get("password") or (user or {}).get("password_digest")
        if not user or not verify_password(stored, password):
            flash("Invalid email or password.", "error")
        elif user.get("status") not in (None, "active"):
            flash("This account is not active.", "error")
        elif user.get("email_verified") is False or user.get("verified") is False:
            flash("Verify your email before signing in.", "warning")
        elif totp_configured(user):
            _begin_password_mfa(user, next_url)
            return redirect(url_for("auth.mfa_verify"))
        else:
            return redirect(_login_session(user, next_url=next_url, method="pwd", aal2=False))
    return render_template(
        "auth/login.html",
        next_url=next_url,
        title="Sign in",
        passkey_ready=passkeys.library_ready(),
        invitation_id=invitation_id,
    )


@bp.route("/mfa/verify", methods=["GET", "POST"])
def mfa_verify():
    user = _find_user(session.get("preauth_user_id"))
    if not user:
        session.clear()
        return redirect(url_for("auth.login"))
    secret = totp_secret_for_user(user)
    if request.method == "POST":
        if not secret:
            flash("This account has MFA enabled, but its existing TOTP seed cannot be read by this release. Sign in with a registered passkey or repair MFA from the previous backup.", "error")
        elif verify_totp(secret, request.form.get("code")):
            target = session.get("preauth_next")
            return redirect(_login_session(user, next_url=target, method="otp", aal2=True))
        else:
            flash("Invalid authentication code.", "error")
    return render_template("auth/mfa_verify.html", title="Verify MFA", user=user)


@bp.post("/passkeys/login/options")
def passkey_login_options():
    if not passkeys.library_ready():
        return jsonify({"ok": False, "error": "Passkey support is unavailable on this server."}), 503
    mode = (request.json or {}).get("mode") if request.is_json else None
    if mode == "reauth" and g.user:
        user = g.user
    else:
        email = ((request.json or {}).get("email") or "").strip().lower() if request.is_json else ""
        user = db().users.find_one({"email": email, "status": {"$ne": "deleted"}})
        if user and user.get("status") not in (None, "active"):
            user = None
    if not user:
        return jsonify({"ok": False, "error": "No passkey is available for this account."}), 400
    try:
        options, challenge = passkeys.authentication_options(user)
    except Exception as exc:
        current = str(exc) if str(exc) else "Unable to start passkey authentication."
        return jsonify({"ok": False, "error": current}), 400
    session["passkey_login_user_id"] = _user_id(user)
    session["passkey_login_challenge"] = _challenge_text(challenge)
    session["passkey_login_next"] = _safe_next((request.json or {}).get("next"))
    session["passkey_login_mode"] = "reauth" if mode == "reauth" and g.user else "login"
    return jsonify({"ok": True, "publicKey": options})


@bp.post("/passkeys/login/verify")
def passkey_login_verify():
    if not passkeys.library_ready():
        return jsonify({"ok": False, "error": "Passkey support is unavailable on this server."}), 503
    payload = request.get_json(silent=True) or {}
    user = _find_user(session.get("passkey_login_user_id"))
    challenge = _passkey_challenge(session.get("passkey_login_challenge"))
    if not user or not challenge:
        return jsonify({"ok": False, "error": "Passkey authentication session expired."}), 400
    try:
        passkeys.verify_authentication(user, payload.get("credential") or payload, challenge)
    except Exception:
        current_app.logger.exception("Passkey authentication failed")
        return jsonify({"ok": False, "error": "Passkey verification failed."}), 401

    mode = session.get("passkey_login_mode")
    target = _safe_next(payload.get("next") or session.get("passkey_login_next"))
    if mode == "reauth" and g.user and _user_id(g.user) == _user_id(user):
        session["auth_time"] = int(utcnow().timestamp())
        session["acr"] = "urn:syntal:loa:2"
        amr = list(session.get("amr") or [])
        if "webauthn" not in amr:
            amr.append("webauthn")
        session["amr"] = amr
        for key in ("passkey_login_user_id", "passkey_login_challenge", "passkey_login_next", "passkey_login_mode"):
            session.pop(key, None)
        audit("account.step_up", user_id=_user_id(user), detail={"method": "webauthn"})
        return jsonify({"ok": True, "redirect": target or url_for("organizations.dashboard")})

    return jsonify({"ok": True, "redirect": _login_session(user, next_url=target, method="webauthn", aal2=True)})


@bp.route("/security/re-auth", methods=["GET", "POST"])
@login_required
def reauth():
    next_url = _safe_next(request.values.get("next"))
    invitation_id = (request.values.get("invitation") or "").strip() or url_for("organizations.dashboard")
    if request.method == "POST":
        secret = totp_secret_for_user(g.user)
        if not secret:
            flash("TOTP MFA is not available for this account. Use a registered passkey or configure TOTP in My account.", "error")
        elif verify_totp(secret, request.form.get("code")):
            session["auth_time"] = int(utcnow().timestamp())
            session["acr"] = "urn:syntal:loa:2"
            amr = list(session.get("amr") or [])
            if "otp" not in amr:
                amr.append("otp")
            session["amr"] = amr
            audit("account.step_up", user_id=_user_id(g.user), detail={"method": "otp"})
            return redirect(next_url)
        else:
            flash("Invalid authentication code.", "error")
    return render_template(
        "auth/re_auth.html",
        title="Verify it’s you",
        next_url=next_url,
        totp_available=totp_enabled(g.user),
        passkey_ready=passkeys.library_ready(),
        passkey_count=len(passkeys.summaries(g.user)) if passkeys.library_ready() else 0,
    )


@bp.post("/logout")
@login_required
def logout():
    uid = g.user.get("syntal_user_id")
    session.clear()
    audit("account.logout", user_id=uid)
    return redirect(url_for("auth.login"))


@bp.route("/account", methods=["GET", "POST"])
@login_required
def account():
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        if name:
            db().users.update_one({"_id": g.user["_id"]}, {"$set": {"name": name, "updated_at": utcnow()}})
            flash("Account updated.", "success")
            return redirect(url_for("auth.account"))
    pending = session.get("totp_setup_secret")
    credentials = passkeys.summaries(g.user) if passkeys.library_ready() else []
    return render_template(
        "account.html",
        title="My account",
        totp_configured=totp_configured(g.user),
        totp_readable=totp_enabled(g.user),
        totp_setup_secret=pending,
        totp_setup_uri=provisioning_uri(pending, g.user.get("email") or "account") if pending else None,
        passkey_ready=passkeys.library_ready(),
        passkeys=credentials,
    )


@bp.post("/account/mfa/totp/begin")
@login_required
def totp_begin():
    secret = generate_totp_secret()
    session["totp_setup_secret"] = secret
    audit("account.mfa_enrollment_started", user_id=_user_id(g.user), detail={"factor": "totp"})
    return redirect(url_for("auth.account") + "#security")


@bp.post("/account/mfa/totp/confirm")
@login_required
def totp_confirm():
    secret = session.get("totp_setup_secret")
    if not secret or not verify_totp(secret, request.form.get("code")):
        flash("The authentication code was not valid. TOTP was not enabled.", "error")
        return redirect(url_for("auth.account") + "#security")
    now = utcnow()
    db().users.update_one(
        {"_id": g.user["_id"]},
        {
            "$set": {
                "mfa.totp_enabled": True,
                "mfa.totp_secret_encrypted": encrypt_secret(f"totp:{_user_id(g.user)}", secret),
                "mfa.totp_enabled_at": now,
                "updated_at": now,
            },
            "$unset": {"mfa.totp_secret": "", "mfa.totp_seed": "", "totp_secret": "", "totp_seed": ""},
        },
    )
    session.pop("totp_setup_secret", None)
    audit("account.mfa_enabled", user_id=_user_id(g.user), detail={"factor": "totp"})
    _security_notice(g.user,"Authenticator MFA enabled","A time-based authenticator was enabled on your Syntal account.")
    flash("Authenticator MFA enabled.", "success")
    return redirect(url_for("auth.account") + "#security")


@bp.post("/account/mfa/totp/disable")
@login_required
def totp_disable():
    secret = totp_secret_for_user(g.user)
    if not secret or not verify_totp(secret, request.form.get("code")):
        flash("Enter a current authentication code before disabling MFA.", "error")
        return redirect(url_for("auth.account") + "#security")
    now = utcnow()
    db().users.update_one(
        {"_id": g.user["_id"]},
        {
            "$set": {"mfa.totp_enabled": False, "updated_at": now},
            "$unset": {
                "mfa.totp_secret_encrypted": "",
                "mfa.totp_secret": "",
                "mfa.totp_seed": "",
                "totp_secret": "",
                "totp_seed": "",
            },
        },
    )
    audit("account.mfa_disabled", user_id=_user_id(g.user), detail={"factor": "totp"})
    _security_notice(g.user,"Authenticator MFA disabled","The authenticator factor was removed from your Syntal account.")
    flash("Authenticator MFA disabled.", "success")
    return redirect(url_for("auth.account") + "#security")


@bp.post("/account/passkeys/options")
@login_required
def passkey_registration_options():
    if not passkeys.library_ready():
        return jsonify({"ok": False, "error": "Passkey support is unavailable on this server."}), 503
    try:
        options, challenge = passkeys.registration_options(g.user)
    except Exception:
        current_app.logger.exception("Passkey registration options failed")
        return jsonify({"ok": False, "error": "Unable to start passkey registration."}), 500
    session["passkey_registration_challenge"] = _challenge_text(challenge)
    return jsonify({"ok": True, "publicKey": options})


@bp.post("/account/passkeys/verify")
@login_required
def passkey_registration_verify():
    if not passkeys.library_ready():
        return jsonify({"ok": False, "error": "Passkey support is unavailable on this server."}), 503
    payload = request.get_json(silent=True) or {}
    challenge = _passkey_challenge(session.get("passkey_registration_challenge"))
    if not challenge:
        return jsonify({"ok": False, "error": "Passkey registration session expired."}), 400
    try:
        record_id = passkeys.verify_registration(
            g.user,
            payload.get("credential") or payload,
            challenge,
            name=(payload.get("name") or "Passkey").strip(),
        )
    except Exception as exc:
        current_app.logger.exception("Passkey registration failed")
        return jsonify({"ok": False, "error": str(exc) or "Passkey registration failed."}), 400
    session.pop("passkey_registration_challenge", None)
    db().users.update_one({"_id": g.user["_id"]}, {"$set": {"webauthn_enabled": True, "updated_at": utcnow()}})
    audit("account.passkey_added", user_id=_user_id(g.user), detail={"record_id": record_id})
    _security_notice(g.user,"Passkey added","A new passkey was registered for your Syntal account.",detail=(payload.get("name") or "Passkey").strip())
    return jsonify({"ok": True, "reload": True})


@bp.post("/account/passkeys/delete")
@login_required
def passkey_delete():
    collection = request.form.get("collection") or "webauthn_credentials"
    record_id = request.form.get("record_id") or ""
    if not passkeys.delete_credential(g.user, collection, record_id):
        abort(404)
    remaining = passkeys.summaries(g.user) if passkeys.library_ready() else []
    if not remaining:
        db().users.update_one({"_id": g.user["_id"]}, {"$set": {"webauthn_enabled": False, "updated_at": utcnow()}})
    audit("account.passkey_removed", user_id=_user_id(g.user), detail={"record_id": record_id, "collection": collection})
    _security_notice(g.user,"Passkey removed","A passkey was removed from your Syntal account.")
    flash("Passkey removed.", "success")
    return redirect(url_for("auth.account") + "#security")


@bp.route("/register", methods=["GET","POST"])
def register():
    invitation_id=(request.values.get("invitation") or "").strip()
    invitation=db().organization_invitations.find_one({"invitation_id":invitation_id,"status":"pending"}) if invitation_id else None
    if request.method=="POST":
        if not invitation:
            abort(400,"A valid invitation is required.")
        email=(invitation.get("email") or "").strip().lower()
        existing=db().users.find_one({"email":email,"status":{"$ne":"deleted"}})
        if existing:
            flash("An account already exists for this invitation. Sign in to continue.","warning")
            return redirect(url_for("auth.login",next=url_for("organizations.accept_invitation",invitation_id=invitation_id),invitation=invitation_id))
        name=(request.form.get("name") or "").strip()
        password=request.form.get("password") or ""
        confirm=request.form.get("confirm_password") or ""
        if not name:
            flash("Enter your name.","error")
        elif password!=confirm:
            flash("Passwords do not match.","error")
        else:
            try:
                password_hash=hash_password(password)
            except ValueError as exc:
                flash(str(exc),"error")
            else:
                now=utcnow(); uid=public_id("usr")
                doc={"syntal_user_id":uid,"email":email,"name":name,"password_hash":password_hash,"status":"active","email_verified":True,"verified":True,"session_epoch":0,"created_at":now,"updated_at":now}
                db().users.insert_one(doc)
                audit("account.created_from_invitation",user_id=uid,org_id=invitation.get("syntal_org_id"),detail={"invitation_id":invitation_id})
                target=url_for("organizations.accept_invitation",invitation_id=invitation_id)
                return redirect(_login_session(doc,next_url=target,method="pwd",aal2=False))
    return render_template("auth/register.html",title="Create account",invitation=invitation,invitation_id=invitation_id)
