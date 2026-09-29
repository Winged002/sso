"""TOTP helpers with pre-v3 encrypted-secret compatibility.

Existing MFA records are read in-place. No database migration is performed.
New enrollments use the same AES-GCM envelope as the pre-v3 SSO:
``mfa.totp_secret_encrypted`` with AAD ``totp:{syntal_user_id}``.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import current_app


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    value = str(value or "")
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _secret_key() -> bytes:
    raw_value = current_app.config.get("ACCOUNT_SECRET_ENCRYPTION_KEY", "")
    if not raw_value:
        raise RuntimeError("ACCOUNT_SECRET_ENCRYPTION_KEY is required.")
    raw = _b64url_decode(raw_value)
    if len(raw) != 32:
        raise RuntimeError("ACCOUNT_SECRET_ENCRYPTION_KEY must decode to exactly 32 bytes.")
    return raw


def encrypt_secret(purpose: str, value: str) -> str:
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(_secret_key()).encrypt(
        nonce,
        value.encode("utf-8"),
        purpose.encode("utf-8"),
    )
    return _b64url(nonce + ciphertext)


def decrypt_secret(purpose: str, value: str) -> str:
    blob = _b64url_decode(value)
    if len(blob) < 13:
        raise ValueError("Encrypted secret is malformed.")
    plaintext = AESGCM(_secret_key()).decrypt(
        blob[:12],
        blob[12:],
        purpose.encode("utf-8"),
    )
    return plaintext.decode("utf-8")


def generate_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _text_secret(value):
    if value is None:
        return None
    if isinstance(value, bytes):
        try:
            value = value.decode("ascii")
        except UnicodeDecodeError:
            return None
    value = str(value).strip().replace(" ", "").upper()
    return value or None


def totp_secret_for_user(user: dict | None):
    """Return a readable TOTP seed without changing the stored user record."""
    user = user or {}
    mfa = user.get("mfa") if isinstance(user.get("mfa"), dict) else {}

    encrypted = mfa.get("totp_secret_encrypted")
    user_id = user.get("syntal_user_id")
    if encrypted and user_id:
        try:
            return _text_secret(decrypt_secret(f"totp:{user_id}", encrypted))
        except Exception:
            current_app.logger.exception("Could not decrypt TOTP secret for %s", user_id)

    # Compatibility for interim/plaintext records. v3.0.2 never writes these.
    candidates = [
        mfa.get("totp_secret"),
        mfa.get("secret"),
        mfa.get("totp_seed"),
        user.get("totp_secret"),
        user.get("totp_seed"),
    ]
    for candidate in candidates:
        value = _text_secret(candidate)
        if value:
            return value
    return None


def totp_configured(user: dict | None) -> bool:
    user = user or {}
    mfa = user.get("mfa") if isinstance(user.get("mfa"), dict) else {}
    explicit = mfa.get("totp_enabled")
    if explicit is None:
        explicit = user.get("totp_enabled")
    return bool(explicit)


def totp_enabled(user: dict | None) -> bool:
    return totp_configured(user) and bool(totp_secret_for_user(user))


def _decode_secret(secret: str) -> bytes:
    cleaned = _text_secret(secret) or ""
    padding = "=" * ((8 - len(cleaned) % 8) % 8)
    return base64.b32decode(cleaned + padding, casefold=True)


def totp_at(secret: str, timestamp: int | float | None = None, *, digits: int = 6, period: int = 30) -> str:
    timestamp = int(time.time() if timestamp is None else timestamp)
    counter = timestamp // period
    key = _decode_secret(secret)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = ((digest[offset] & 0x7F) << 24) | (digest[offset + 1] << 16) | (digest[offset + 2] << 8) | digest[offset + 3]
    return str(binary % (10 ** digits)).zfill(digits)


def verify_totp(secret: str | None, code: str | None, *, window: int = 1, timestamp: int | float | None = None) -> bool:
    if not secret or not code:
        return False
    normalized = "".join(ch for ch in str(code) if ch.isdigit())
    if len(normalized) != 6:
        return False
    now = int(time.time() if timestamp is None else timestamp)
    try:
        for shift in range(-window, window + 1):
            if hmac.compare_digest(totp_at(secret, now + shift * 30), normalized):
                return True
    except Exception:
        return False
    return False


def provisioning_uri(secret: str, email: str, issuer: str = "Syntal") -> str:
    label = quote(f"{issuer}:{email}", safe="")
    return f"otpauth://totp/{label}?secret={quote(secret)}&issuer={quote(issuer)}&algorithm=SHA1&digits=6&period=30"
