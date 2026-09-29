"""WebAuthn/passkey compatibility layer for Syntal SSO v3.0.2.

The module deliberately does not migrate credential data. It discovers the
credential collection/field shapes used by earlier SSO revisions and verifies
those records in-place. Newly registered passkeys use ``webauthn_credentials``
while retaining both canonical Syntal and legacy user identifiers.
"""
from __future__ import annotations

import base64
import json
from datetime import datetime, timezone

from bson import ObjectId
from bson.binary import Binary
from flask import current_app

from .db import db

_COLLECTION_CANDIDATES = (
    "webauthn_credentials",
    "passkeys",
    "passkey_credentials",
    "user_passkeys",
)


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(bytes(value)).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    value = str(value or "")
    return base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))


def _bytes(value):
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray, memoryview, Binary)):
        return bytes(value)
    if isinstance(value, str):
        # Most stored string credential IDs are base64url. Fall back to UTF-8
        # only for old experimental records that stored the raw textual ID.
        try:
            return _b64url_decode(value)
        except Exception:
            return value.encode("utf-8")
    return None


def _public_key_bytes(doc):
    for key in ("public_key", "credential_public_key", "public_key_cbor", "public_key_bytes"):
        value = _bytes(doc.get(key))
        if value:
            return value
    return None


def _credential_id_bytes(doc):
    for key in ("credential_id", "raw_id", "id"):
        value = _bytes(doc.get(key))
        if value:
            return value
    return None


def library_ready() -> bool:
    try:
        import webauthn  # noqa: F401
        return True
    except Exception:
        return False


def _user_queries(user):
    uid = user.get("syntal_user_id") or str(user.get("_id"))
    oid = user.get("_id")
    values = [
        {"syntal_user_id": uid},
        {"user_id": uid},
        {"user_id": str(oid)} if oid is not None else None,
        {"email": user.get("email")} if user.get("email") else None,
    ]
    if isinstance(oid, ObjectId):
        values.insert(2, {"user_id": oid})
    return [v for v in values if v]


def credential_documents(user):
    """Return compatible credential documents without modifying the database."""
    database = db()
    existing = set(database.list_collection_names())
    found = []
    seen = set()
    for name in _COLLECTION_CANDIDATES:
        if name not in existing:
            continue
        collection = database[name]
        docs = []
        for query in _user_queries(user):
            docs.extend(list(collection.find(query)))
        for doc in docs:
            cid = _credential_id_bytes(doc)
            pub = _public_key_bytes(doc)
            if not cid or not pub:
                continue
            identity = (name, str(doc.get("_id")))
            if identity in seen:
                continue
            seen.add(identity)
            found.append({"collection": name, "document": doc, "credential_id": cid, "public_key": pub})
    return found


def summaries(user):
    rows = []
    for item in credential_documents(user):
        doc = item["document"]
        rows.append({
            "record_id": str(doc.get("_id")),
            "collection": item["collection"],
            "credential_id": _b64url_encode(item["credential_id"]),
            "name": doc.get("name") or doc.get("device_name") or doc.get("device_type") or "Passkey",
            "created_at": doc.get("created_at"),
            "last_used": doc.get("last_used") or doc.get("last_used_at"),
            "transports": doc.get("transports") or [],
        })
    return rows


def _rp_id():
    explicit = current_app.config.get("WEBAUTHN_RP_ID")
    if explicit:
        return explicit
    base = current_app.config.get("PUBLIC_BASE_URL", "https://sso.syntal.pro")
    return base.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]


def _origin():
    return current_app.config.get("WEBAUTHN_ORIGIN") or current_app.config.get("PUBLIC_BASE_URL", "https://sso.syntal.pro").rstrip("/")


def authentication_options(user):
    from webauthn import generate_authentication_options, options_to_json
    from webauthn.helpers.structs import PublicKeyCredentialDescriptor, UserVerificationRequirement

    credentials = credential_documents(user)
    if not credentials:
        raise ValueError("No passkey is registered for this account")
    options = generate_authentication_options(
        rp_id=_rp_id(),
        allow_credentials=[PublicKeyCredentialDescriptor(id=item["credential_id"]) for item in credentials],
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    return json.loads(options_to_json(options)), bytes(options.challenge)


def verify_authentication(user, credential, expected_challenge: bytes):
    from webauthn import verify_authentication_response

    incoming = _b64url_decode((credential or {}).get("rawId") or (credential or {}).get("id") or "")
    match = None
    for item in credential_documents(user):
        if item["credential_id"] == incoming:
            match = item
            break
    if not match:
        raise ValueError("Passkey not recognized")

    doc = match["document"]
    verification = verify_authentication_response(
        credential=credential,
        expected_challenge=expected_challenge,
        expected_rp_id=_rp_id(),
        expected_origin=_origin(),
        credential_public_key=match["public_key"],
        credential_current_sign_count=int(doc.get("sign_count") or doc.get("current_sign_count") or 0),
        require_user_verification=False,
    )
    new_count = int(getattr(verification, "new_sign_count", doc.get("sign_count") or 0) or 0)
    db()[match["collection"]].update_one(
        {"_id": doc["_id"]},
        {"$set": {"sign_count": new_count, "last_used": datetime.now(timezone.utc)}},
    )
    return match


def registration_options(user):
    from webauthn import generate_registration_options, options_to_json
    from webauthn.helpers.structs import (
        AuthenticatorSelectionCriteria,
        PublicKeyCredentialDescriptor,
        ResidentKeyRequirement,
        UserVerificationRequirement,
    )

    uid = (user.get("syntal_user_id") or str(user.get("_id"))).encode("utf-8")
    existing = credential_documents(user)
    options = generate_registration_options(
        rp_id=_rp_id(),
        rp_name="Syntal",
        user_id=uid,
        user_name=user.get("email") or user.get("syntal_user_id") or str(user.get("_id")),
        user_display_name=user.get("name") or user.get("email") or "Syntal user",
        exclude_credentials=[PublicKeyCredentialDescriptor(id=item["credential_id"]) for item in existing],
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
    )
    return json.loads(options_to_json(options)), bytes(options.challenge)


def verify_registration(user, credential, expected_challenge: bytes, *, name="Passkey"):
    from webauthn import verify_registration_response

    verification = verify_registration_response(
        credential=credential,
        expected_challenge=expected_challenge,
        expected_rp_id=_rp_id(),
        expected_origin=_origin(),
        require_user_verification=False,
    )
    cid = bytes(verification.credential_id)
    pub = bytes(verification.credential_public_key)
    now = datetime.now(timezone.utc)
    user_oid = user.get("_id")
    doc = {
        "syntal_user_id": user.get("syntal_user_id") or str(user_oid),
        "user_id": user_oid,
        "credential_id": Binary(cid),
        "public_key": Binary(pub),
        "credential_public_key": Binary(pub),
        "sign_count": int(getattr(verification, "sign_count", 0) or 0),
        "name": (name or "Passkey")[:80],
        "device_type": (name or "Passkey")[:80],
        "transports": (credential or {}).get("response", {}).get("transports") or [],
        "created_at": now,
        "last_used": None,
    }
    collection = db().webauthn_credentials
    existing = collection.find_one({"credential_id": Binary(cid)})
    if existing:
        raise ValueError("This passkey is already registered")
    result = collection.insert_one(doc)
    return str(result.inserted_id)


def delete_credential(user, collection_name: str, record_id: str) -> bool:
    if collection_name not in _COLLECTION_CANDIDATES:
        return False
    candidates = [record_id]
    try:
        candidates.insert(0, ObjectId(record_id))
    except Exception:
        pass
    collection = db()[collection_name]
    for record_key in candidates:
        doc = collection.find_one({"_id": record_key})
        if not doc:
            continue
        allowed = any(collection.find_one({"_id": record_key, **query}) for query in _user_queries(user))
        if not allowed:
            return False
        return collection.delete_one({"_id": record_key}).deleted_count == 1
    return False
