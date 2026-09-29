from functools import wraps
import hashlib, hmac, secrets
from flask import abort, g, redirect, request, session, url_for
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError
from werkzeug.security import check_password_hash

_ph = PasswordHasher()


def hash_password(password):
    if not password or len(password) < 10:
        raise ValueError("Password must be at least 10 characters.")
    return _ph.hash(password)


def verify_password(stored, provided):
    if not stored or not provided:
        return False
    try:
        if stored.startswith("$argon2"):
            return _ph.verify(stored, provided)
        if stored.startswith(("pbkdf2:", "scrypt:")):
            return check_password_hash(stored, provided)
        if stored.startswith("sha256$"):
            _, salt, digest = stored.split("$", 2)
            test = hashlib.sha256((salt + provided).encode()).hexdigest()
            return hmac.compare_digest(test, digest)
    except (VerifyMismatchError, InvalidHashError, ValueError):
        return False
    return False


def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


def enforce_csrf():
    if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
        return
    if request.endpoint in {"oidc.token", "oidc.revoke", "oidc.introspect", "billing.stripe_webhook"}:
        return
    supplied = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
    expected = session.get("csrf_token")
    if not expected or not supplied or not hmac.compare_digest(str(expected), str(supplied)):
        abort(400, "Invalid CSRF token")


def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not getattr(g, "user", None):
            return redirect(url_for("auth.login", next=request.full_path if request.query_string else request.path))
        return fn(*args, **kwargs)
    return wrapped
