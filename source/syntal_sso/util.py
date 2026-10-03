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


def safe_next(value):
    from urllib.parse import urlsplit,unquote
    if not isinstance(value,str) or not value.startswith('/'):return None
    decoded=value
    for _ in range(2):decoded=unquote(decoded)
    if decoded.startswith('//') or '\\' in decoded or any(ord(c)<32 or ord(c)==127 for c in decoded):return None
    parsed=urlsplit(decoded)
    return value if not parsed.scheme and not parsed.netloc else None
