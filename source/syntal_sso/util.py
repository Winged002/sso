from datetime import datetime, timezone
import secrets


def utcnow():
    return datetime.now(timezone.utc)


def public_id(prefix):
    return f"{prefix}_{secrets.token_urlsafe(18).replace('-', '').replace('_', '')[:24]}"


def first(value, default=None):
    return value if value not in (None, "") else default


def safe_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
