from __future__ import annotations

import base64
import hashlib, secrets
from datetime import timedelta
from .lifecycle import (active_user,start_session,revoke_session,login_throttle,pending_fresh,require_recent,mutation_lock)
from .mfa import verify_totp_once,consume_recovery_code

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
    from .util import safe_next
    return safe_next(value)


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
    start_session(user,method,aal2)
    session['step_up_at']=int(utcnow().timestamp())
    session['step_up_acr']=session['acr']
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
        login_throttle("password",email)
        user = db().users.find_one({"email": email, "status": {"$ne": "deleted"}})
        stored = (user or {}).get("password_hash") or (user or {}).get("password") or (user or {}).get("password_digest")
        if not user or not verify_password(stored, password):
            flash("Invalid email or password.", "error")
        elif user.get("status") not in (None, "active"):
            flash("This account is not active.", "error")
        elif user.get("email_verified") is not True:
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
    if not active_user(user) or not pending_fresh("preauth_started_at"):
        session.clear()
        return redirect(url_for("auth.login"))
    secret = totp_secret_for_user(user)
    if request.method == "POST":
        login_throttle("mfa",_user_id(user))
        if not secret and not request.form.get("recovery_code"):
            flash("This account has MFA enabled, but its existing TOTP seed cannot be read by this release. Sign in with a registered passkey or repair MFA from the previous backup.", "error")
        elif verify_totp_once(user,request.form.get("code")) or consume_recovery_code(user,request.form.get("recovery_code")):
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
    login_throttle("passkey", (user or {}).get("email") or "unknown")
    if not active_user(user):
        return jsonify({"ok": False, "error": "No passkey is available for this account."}), 400
    try:
        options, challenge = passkeys.authentication_options(user)
    except Exception as exc:
        current = str(exc) if str(exc) else "Unable to start passkey authentication."
        return jsonify({"ok": False, "error": current}), 400
    session["passkey_login_started_at"]=int(utcnow().timestamp())
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
    if not active_user(user) or not challenge or not pending_fresh("passkey_login_started_at"):
        return jsonify({"ok": False, "error": "Passkey authentication session expired."}), 400
    login_throttle("passkey-verify",_user_id(user))
    try:
        passkeys.verify_authentication(user, payload.get("credential") or payload, challenge)
    except Exception:
        current_app.logger.exception("Passkey authentication failed")
        return jsonify({"ok": False, "error": "Passkey verification failed."}), 401

    mode = session.get("passkey_login_mode")
    target = _safe_next(payload.get("next") or session.get("passkey_login_next"))
    if mode == "reauth" and g.user and _user_id(g.user) == _user_id(user):
        session["auth_time"] = int(utcnow().timestamp())
        session["step_up_at"]=session["auth_time"]
        session["step_up_acr"]="urn:syntal:loa:2"
        session["reauth_authorize_binding"]=session.pop("pending_authorize_binding",None)
        session["acr"] = "urn:syntal:loa:2"
        amr = list(session.get("amr") or [])
        if "webauthn" not in amr:
            amr.append("webauthn")
        session["amr"] = amr
        for key in ("passkey_login_started_at", "passkey_login_user_id", "passkey_login_challenge", "passkey_login_next", "passkey_login_mode"):
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
        login_throttle('step-up',_user_id(g.user))
        strong=totp_configured(g.user) or bool(passkeys.summaries(g.user))
        ok=(verify_totp_once(g.user,request.form.get('code')) or consume_recovery_code(g.user,request.form.get('recovery_code'))) if strong else verify_password(g.user.get('password_hash') or g.user.get('password') or g.user.get('password_digest'),request.form.get('password'))
        if ok:
            session['auth_time']=int(utcnow().timestamp());session['step_up_at']=session['auth_time']
            session['acr']='urn:syntal:loa:2' if strong else 'urn:syntal:loa:1';session['step_up_acr']=session['acr']
            session['reauth_authorize_binding']=session.pop('pending_authorize_binding',None)
            session['amr']=list(set((session.get('amr') or [])+(['otp'] if strong else ['pwd'])))
            audit('account.step_up',user_id=_user_id(g.user))
            return redirect(next_url or url_for('auth.account'))
        flash('Verification failed. Use a fresh authenticator code or recovery code.','error')
    return render_template(
        "auth/re_auth.html",
        title="Verify it’s you",
        next_url=next_url,
        totp_available=totp_enabled(g.user),
        password_available=not (totp_configured(g.user) or bool(passkeys.summaries(g.user))),
        passkey_ready=passkeys.library_ready(),
        passkey_count=len(passkeys.summaries(g.user)) if passkeys.library_ready() else 0,
    )


@bp.post("/logout")
@login_required
def logout():
    uid = g.user.get("syntal_user_id")
    revoke_session(session.get("auth_session_id"),uid)
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
    required=require_recent(strong=totp_configured(g.user) or bool(passkeys.summaries(g.user)))
    if required:return required
    secret = generate_totp_secret()
    session["totp_setup_secret"] = secret
    session["totp_setup_started_at"]=int(utcnow().timestamp())
    session["totp_setup_uid"]=_user_id(g.user)
    audit("account.mfa_enrollment_started", user_id=_user_id(g.user), detail={"factor": "totp"})
    return redirect(url_for("auth.account") + "#security")


@bp.post("/account/mfa/totp/confirm")
@login_required
def totp_confirm():
    required=require_recent(strong=totp_configured(g.user) or bool(passkeys.summaries(g.user)))
    if required:return required
    secret = session.get("totp_setup_secret")
    if not secret or session.get("totp_setup_uid")!=_user_id(g.user) or not pending_fresh("totp_setup_started_at") or not verify_totp(secret, request.form.get("code")):
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
    session.pop("totp_setup_started_at",None)
    session.pop("totp_setup_uid",None)
    from .lifecycle import rotate_account_epoch
    rotate_account_epoch(g.user)
    audit("account.mfa_enabled", user_id=_user_id(g.user), detail={"factor": "totp"})
    _security_notice(g.user,"Authenticator MFA enabled","A time-based authenticator was enabled on your Syntal account.")
    flash("Authenticator MFA enabled.", "success")
    return redirect(url_for("auth.account") + "#security")


@bp.post("/account/mfa/totp/disable")
@login_required
def totp_disable():
    secret = totp_secret_for_user(g.user)
    login_throttle("totp-disable",_user_id(g.user))
    if not secret or not verify_totp_once(g.user,request.form.get("code")):
        flash("Enter a current authentication code before disabling MFA.", "error")
        return redirect(url_for("auth.account") + "#security")
    now = utcnow()
    db().users.update_one(
        {"_id": g.user["_id"]},
        {
            "$set": {"mfa.totp_enabled": False, "totp_enabled":False, "updated_at": now},
            "$unset": {
                "mfa.totp_secret_encrypted": "",
                "mfa.totp_secret": "",
                "mfa.totp_seed": "",
                "totp_secret": "",
                "totp_seed": "",
                "mfa.secret":"",
            },
        },
    )
    from .lifecycle import rotate_account_epoch
    rotate_account_epoch(g.user)
    audit("account.mfa_disabled", user_id=_user_id(g.user), detail={"factor": "totp"})
    _security_notice(g.user,"Authenticator MFA disabled","The authenticator factor was removed from your Syntal account.")
    flash("Authenticator MFA disabled.", "success")
    return redirect(url_for("auth.account") + "#security")


@bp.post("/account/passkeys/options")
@login_required
def passkey_registration_options():
    required=require_recent(strong=totp_configured(g.user) or bool(passkeys.summaries(g.user)))
    if required:return required
    if not passkeys.library_ready():
        return jsonify({"ok": False, "error": "Passkey support is unavailable on this server."}), 503
    try:
        options, challenge = passkeys.registration_options(g.user)
    except Exception:
        current_app.logger.exception("Passkey registration options failed")
        return jsonify({"ok": False, "error": "Unable to start passkey registration."}), 500
    session["passkey_registration_challenge"] = _challenge_text(challenge)
    session["passkey_registration_started_at"]=int(utcnow().timestamp())
    session["passkey_registration_uid"]=_user_id(g.user)
    return jsonify({"ok": True, "publicKey": options})


@bp.post("/account/passkeys/verify")
@login_required
def passkey_registration_verify():
    required=require_recent(strong=totp_configured(g.user) or bool(passkeys.summaries(g.user)))
    if required:return required
    if not passkeys.library_ready():
        return jsonify({"ok": False, "error": "Passkey support is unavailable on this server."}), 503
    payload = request.get_json(silent=True) or {}
    challenge = _passkey_challenge(session.get("passkey_registration_challenge"))
    if not challenge or not pending_fresh("passkey_registration_started_at") or session.get("passkey_registration_uid")!=_user_id(g.user):
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
    session.pop("passkey_registration_started_at",None)
    session.pop("passkey_registration_uid",None)
    db().users.update_one({"_id": g.user["_id"]}, {"$set": {"webauthn_enabled": True, "updated_at": utcnow()}})
    from .lifecycle import rotate_account_epoch
    rotate_account_epoch(g.user)
    audit("account.passkey_added", user_id=_user_id(g.user), detail={"record_id": record_id})
    _security_notice(g.user,"Passkey added","A new passkey was registered for your Syntal account.",detail=(payload.get("name") or "Passkey").strip())
    return jsonify({"ok": True, "reload": True})


@bp.post("/account/passkeys/delete")
@login_required
def passkey_delete():
    required=require_recent(strong=totp_configured(g.user) or bool(passkeys.summaries(g.user)))
    if required:return required
    collection = request.form.get("collection") or "webauthn_credentials"
    record_id = request.form.get("record_id") or ""
    if not passkeys.delete_credential(g.user, collection, record_id):
        abort(404)
    remaining = passkeys.summaries(g.user) if passkeys.library_ready() else []
    if not remaining:
        db().users.update_one({"_id": g.user["_id"]}, {"$set": {"webauthn_enabled": False, "updated_at": utcnow()}})
    from .lifecycle import rotate_account_epoch
    rotate_account_epoch(g.user)
    audit("account.passkey_removed", user_id=_user_id(g.user), detail={"record_id": record_id, "collection": collection})
    _security_notice(g.user,"Passkey removed","A passkey was removed from your Syntal account.")
    flash("Passkey removed.", "success")
    return redirect(url_for("auth.account") + "#security")


@bp.route("/register", methods=["GET","POST"])
def register():
    invitation_id=(request.values.get("invitation") or "").strip()
    invitation=db().organization_invitations.find_one({"invitation_id":invitation_id,"status":"pending","expire_at":{"$gt":utcnow()}}) if invitation_id else None
    if invitation and not db().organizations.find_one({"syntal_org_id":invitation.get("syntal_org_id"),"status":"active"}):invitation=None
    if invitation_id and not invitation:abort(400,"Invitation expired or unavailable. Request a new invitation.")

    # Signed-in users do not need a second account; /register becomes the
    # convenient entry point for creating another organization.
    if g.user and not invitation:
        return redirect(url_for("organizations.create_organization"))

    if request.method=="POST":
        # Preserve the v3.2 invitation flow exactly when a valid invitation is supplied.
        if invitation:
            login_throttle("invitation-signup",invitation.get("email", ""))
            if not db().organization_roles.find_one({"syntal_org_id":invitation.get("syntal_org_id"),"role_id":invitation.get("role_id"),"status":"active","key":{"$ne":"owner"}}):abort(400,"Invitation role unavailable.")
            email=(invitation.get("email") or "").strip().lower()
            existing=db().users.find_one({"email":email})
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
                    doc={"syntal_user_id":uid,"user_id":uid,"email":email,"name":name,"password_hash":password_hash,"status":"active","email_verified":True,"verified":True,"session_epoch":0,"created_at":now,"updated_at":now}
                    from pymongo.errors import DuplicateKeyError
                    from .schema import legacy_write_fields
                    doc.update(legacy_write_fields('users',doc))
                    try:db().users.insert_one(doc)
                    except DuplicateKeyError:
                        flash("An account already exists. Sign in to continue.","warning")
                        return redirect(url_for("auth.login"))
                    audit("account.created_from_invitation",user_id=uid,org_id=invitation.get("syntal_org_id"),detail={"invitation_id":invitation_id})
                    target=url_for("organizations.accept_invitation",invitation_id=invitation_id)
                    return redirect(_login_session(doc,next_url=target,method="pwd",aal2=False))
        else:
            email=(request.form.get("email") or "").strip().lower()
            name=(request.form.get("name") or "").strip()
            organization_name=(request.form.get("organization_name") or "").strip()
            password=request.form.get("password") or ""
            confirm=request.form.get("confirm_password") or ""
            existing=db().users.find_one({"email":email}) if email else None

            login_throttle("signup",email)
            if not email or len(email)>254 or not __import__("re").fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+",email):
                flash("Enter a valid email address.","error")
            elif existing:
                flash("An account with this email already exists. Sign in instead.","warning")
            elif not name:
                flash("Enter your name.","error")
            elif len(organization_name) < 2:
                flash("Enter an organization name with at least 2 characters.","error")
            elif len(organization_name) > 120:
                flash("Organization name must be 120 characters or fewer.","error")
            elif password!=confirm:
                flash("Passwords do not match.","error")
            else:
                try:
                    password_hash=hash_password(password)
                except ValueError as exc:
                    flash(str(exc),"error")
                else:
                    now=utcnow(); uid=public_id("usr")
                    doc={"syntal_user_id":uid,"user_id":uid,"email":email,"name":name,"password_hash":password_hash,"status":"active","email_verified":False,"verified":False,"session_epoch":0,"created_at":now,"updated_at":now,"registration_source":"self_service"}
                    from .schema import legacy_write_fields
                    doc.update(legacy_write_fields('users',doc))
                    try:
                        from .organizations import create_owned_organization
                        org, _membership=create_owned_organization(doc,organization_name,created_by=uid,signup=True)
                        audit("account.self_service_registered",user_id=uid,org_id=org["syntal_org_id"],detail={"email":email})
                    except Exception:
                        current_app.logger.exception("Self-service account registration failed")
                        flash("Account registration could not be completed. Please try again.","error")
                    else:
                        send_verification(doc)
                        flash("Account created. Confirm your email before signing in.","success")
                        return redirect(url_for("auth.verify_email"))

    return render_template("auth/register.html",title="Create account",invitation=invitation,invitation_id=invitation_id)



def send_verification(user):
    from .mailer import send_transactional_email
    from markupsafe import escape
    raw=secrets.token_urlsafe(36);now=utcnow()
    db().account_action_tokens.update_many({'syntal_user_id':_user_id(user),'purpose':'verify_email','used_at':None},{'$set':{'used_at':now}})
    db().account_action_tokens.insert_one({'token_hash':hashlib.sha256(raw.encode()).hexdigest(),'syntal_user_id':_user_id(user),'purpose':'verify_email','email':user['email'],'created_at':now,'expire_at':now+timedelta(hours=1),'used_at':None})
    link=current_app.config['PUBLIC_BASE_URL'].rstrip('/')+url_for('auth.verify_email',token=raw)
    result=send_transactional_email(to=user['email'],subject='Confirm your Syntal email',text_body='Confirm your email: '+link,html_body='<p>Confirm your Syntal email address.</p><p><a href="'+str(escape(link))+'">Confirm email</a></p>')
    if not result.get('ok'):current_app.logger.error('Email verification delivery failed for user %s',_user_id(user))
    return result.get('ok',False)


@bp.route('/verify-email',methods=['GET','POST'])
def verify_email():
    raw=request.values.get('token') or '';row=None
    if raw:row=db().account_action_tokens.find_one({'token_hash':hashlib.sha256(raw.encode()).hexdigest(),'purpose':'verify_email','used_at':None,'expire_at':{'$gt':utcnow()}})
    if request.method=='POST':
        login_throttle('email-verification',request.form.get('email') or (row or {}).get('syntal_user_id',''))
        if raw:
            from pymongo import ReturnDocument
            row=db().account_action_tokens.find_one_and_update({'token_hash':hashlib.sha256(raw.encode()).hexdigest(),'purpose':'verify_email','used_at':None,'expire_at':{'$gt':utcnow()}},{'$set':{'used_at':utcnow()}},return_document=ReturnDocument.AFTER)
            if not row:abort(400,'Verification link expired or already used.')
            user=db().users.find_one({'syntal_user_id':row['syntal_user_id'],'email':row['email'],'status':'active'})
            if not user:abort(400,'Account unavailable.')
            db().users.update_one({'_id':user['_id']},{'$set':{'email_verified':True,'verified':True,'email_verified_at':utcnow(),'verification_source':'email_token'}})
            audit('account.email_verified',user_id=row['syntal_user_id'])
            flash('Email confirmed. Sign in to continue.','success');return redirect(url_for('auth.login'))
        email=(request.form.get('email') or '').strip().lower()
        user=db().users.find_one({'email':email,'status':'active','email_verified':{'$ne':True}})
        if user:send_verification(user)
        flash('If the account needs verification, a new link has been sent.','success')
    return render_template('auth/verify_email.html',title='Confirm email',token=raw,token_valid=bool(row),standalone_auth=True)


@bp.get('/account/sessions')
@login_required
def sessions():
    rows=list(db().security_sessions.find({'syntal_user_id':_user_id(g.user),'expire_at':{'$gt':utcnow()}}).sort('created_at',-1).limit(100))
    return render_template('auth/sessions.html',title='Your sessions',sessions=rows,current_sid=session.get('auth_session_id'))


@bp.post('/account/sessions/<sid>/revoke')
@login_required
def session_revoke(sid):
    if not revoke_session(sid,_user_id(g.user)):abort(404)
    audit('account.session_revoked',user_id=_user_id(g.user),detail={'sid':sid})
    if sid==session.get('auth_session_id'):session.clear();return redirect(url_for('auth.login'))
    return redirect(url_for('auth.sessions'))


@bp.post('/account/recovery-codes')
@login_required
def recovery_codes():
    if not (totp_configured(g.user) or bool(passkeys.summaries(g.user))):abort(409,'Enable MFA before creating recovery codes.')
    required=require_recent(strong=True)
    if required:return required
    codes=[secrets.token_hex(12).upper() for _ in range(10)]
    db().users.update_one({'_id':g.user['_id']},{'$set':{'recovery_code_hashes':[hashlib.sha256(code.encode()).hexdigest() for code in codes],'recovery_codes_created_at':utcnow()}})
    audit('account.recovery_codes_created',user_id=_user_id(g.user))
    response=render_template('auth/recovery_codes.html',title='Save your recovery codes',codes=codes)
    return response


@bp.route('/forgot-password',methods=['GET','POST'])
def forgot_password():
    if request.method=='POST':
        from .mailer import send_transactional_email
        from markupsafe import escape
        email=(request.form.get('email') or '').strip().lower();login_throttle('password-reset',email)
        user=db().users.find_one({'email':email,'status':'active','email_verified':True})
        if user:
            raw=secrets.token_urlsafe(36);now=utcnow()
            db().account_action_tokens.update_many({'syntal_user_id':_user_id(user),'purpose':'password_reset','used_at':None},{'$set':{'used_at':now}})
            db().account_action_tokens.insert_one({'token_hash':hashlib.sha256(raw.encode()).hexdigest(),'syntal_user_id':_user_id(user),'purpose':'password_reset','expire_at':now+timedelta(minutes=30),'used_at':None,'session_epoch':user.get('session_epoch',0)})
            link=current_app.config['PUBLIC_BASE_URL'].rstrip('/')+url_for('auth.reset_password',token=raw)
            send_transactional_email(to=email,subject='Reset your Syntal password',text_body='Reset your password: '+link,html_body='<p><a href="'+str(escape(link))+'">Reset password</a></p>')
        flash('If the account is eligible, a password reset link has been sent.','success')
    return render_template('auth/forgot_password.html',title='Reset password',standalone_auth=True)


@bp.route('/reset-password',methods=['GET','POST'])
def reset_password():
    raw=request.values.get('token') or '';query={'token_hash':hashlib.sha256(raw.encode()).hexdigest(),'purpose':'password_reset','used_at':None,'expire_at':{'$gt':utcnow()}}
    row=db().account_action_tokens.find_one(query);user=_find_user((row or {}).get('syntal_user_id'))
    if not row or not active_user(user) or row.get('session_epoch')!=user.get('session_epoch',0):abort(400,'Reset link expired or unavailable.')
    strong=totp_configured(user) or bool(passkeys.summaries(user))
    if request.method=='POST':
        login_throttle('password-reset-confirm',_user_id(user))
        if strong and not (verify_totp_once(user,request.form.get('code')) or consume_recovery_code(user,request.form.get('recovery_code'))):
            flash('A fresh MFA code or unused recovery code is required.','error')
        elif request.form.get('password')!=request.form.get('confirm_password'):flash('Passwords do not match.','error')
        else:
            try:password_hash=hash_password(request.form.get('password'))
            except ValueError as exc:flash(str(exc),'error')
            else:
                from .lifecycle import rotate_account_epoch
                with mutation_lock('account-reset:'+_user_id(user)):
                    claimed=db().account_action_tokens.update_one(query,{'$set':{'used_at':utcnow()}})
                    if not claimed.modified_count:abort(409,'Reset already used.')
                    updated=db().users.update_one({'_id':user['_id'],'session_epoch':row['session_epoch']},{'$set':{'password_hash':password_hash,'updated_at':utcnow()}})
                    if not updated.matched_count:abort(409,'Account changed. Request a new reset link.')
                    session.clear();rotate_account_epoch(user)
                audit('account.password_reset',user_id=_user_id(user));flash('Password reset. Sign in again.','success');return redirect(url_for('auth.login'))
    return render_template('auth/reset_password.html',title='Choose a new password',token=raw,strong=strong,standalone_auth=True)
