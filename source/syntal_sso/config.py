import os

class Config:
    VERSION = "4.0.0"
    SECRET_KEY = os.environ.get("SECRET_KEY") or os.environ.get("FLASK_SECRET_KEY") or ""
    MONGO_URI = os.environ.get("MONGO_URI", "mongodb://mongo:27017/syntal_identity")
    MONGO_DB = os.environ.get("MONGO_DB", "syntal_identity")
    REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")
    PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "https://sso.syntal.pro")
    SESSION_COOKIE_NAME = os.environ.get("SESSION_COOKIE_NAME", "syntal_session")
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_TYPE = "redis"
    SESSION_PERMANENT = False
    SESSION_USE_SIGNER = True
    SESSION_KEY_PREFIX = "syntal:sso:v4:"
    PREFERRED_URL_SCHEME = "https"
    OIDC_ISSUER = os.environ.get("OIDC_ISSUER", PUBLIC_BASE_URL).rstrip("/")
    OIDC_PRIVATE_KEY = os.environ.get("OIDC_PRIVATE_KEY", "") or os.environ.get("JWT_PRIVATE_KEY", "")
    OIDC_PRIVATE_KEY_FILE = os.environ.get("OIDC_PRIVATE_KEY_FILE", "") or os.environ.get("JWT_PRIVATE_KEY_FILE", "")
    OIDC_KEY_ID = os.environ.get("OIDC_KEY_ID", "syntal-v4-bootstrap")
    OIDC_HS256_SECRET = os.environ.get("OIDC_HS256_SECRET", "")
    ACCESS_TOKEN_TTL = int(os.environ.get("ACCESS_TOKEN_TTL", "300"))
    ID_TOKEN_TTL = int(os.environ.get("ID_TOKEN_TTL", "300"))
    REFRESH_TOKEN_TTL = int(os.environ.get("REFRESH_TOKEN_TTL", str(60*60*24*30)))
    STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY", "")
    STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
    ACCOUNT_SECRET_ENCRYPTION_KEY = os.environ.get("ACCOUNT_SECRET_ENCRYPTION_KEY", "")

    WEBAUTHN_RP_ID = os.environ.get("WEBAUTHN_RP_ID", "")
    WEBAUTHN_ORIGIN = os.environ.get("WEBAUTHN_ORIGIN", "")

    # SMTP / transactional email. Both SMTP_* and common legacy MAIL_* names are supported.
    SMTP_HOST = os.environ.get("SMTP_HOST") or os.environ.get("SMTP_SERVER") or os.environ.get("MAIL_SERVER") or os.environ.get("MAIL_HOST", "")
    SMTP_PORT = int(os.environ.get("SMTP_PORT") or os.environ.get("MAIL_PORT") or "587")
    SMTP_USERNAME = os.environ.get("SMTP_USERNAME") or os.environ.get("SMTP_USER") or os.environ.get("MAIL_USERNAME") or os.environ.get("MAIL_USER", "")
    SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD") or os.environ.get("SMTP_PASS") or os.environ.get("MAIL_PASSWORD", "")
    SMTP_FROM_EMAIL = os.environ.get("SMTP_FROM_EMAIL") or os.environ.get("SMTP_SENDER") or os.environ.get("MAIL_DEFAULT_SENDER") or os.environ.get("MAIL_FROM_EMAIL", "")
    SMTP_FROM_NAME = os.environ.get("SMTP_FROM_NAME") or os.environ.get("MAIL_FROM_NAME", "Syntal")
    SMTP_REPLY_TO = os.environ.get("SMTP_REPLY_TO") or os.environ.get("MAIL_REPLY_TO", "")
    SMTP_USE_TLS = (os.environ.get("SMTP_USE_TLS") or os.environ.get("MAIL_USE_TLS") or "true").strip().lower() in {"1","true","yes","on"}
    SMTP_USE_SSL = (os.environ.get("SMTP_USE_SSL") or os.environ.get("MAIL_USE_SSL") or "false").strip().lower() in {"1","true","yes","on"}
    SMTP_TIMEOUT = int(os.environ.get("SMTP_TIMEOUT", "12"))

    SESSION_MAX_AGE = int(os.environ.get("SESSION_MAX_AGE", "43200"))
    STEP_UP_MAX_AGE = int(os.environ.get("STEP_UP_MAX_AGE", "300"))
    MAX_CONTENT_LENGTH = 1024 * 1024
    API_AUDIENCE = os.environ.get("API_AUDIENCE", "syntal-api")
    INVITATION_TTL = int(os.environ.get("INVITATION_TTL", "604800"))
    REQUIRE_EMAIL_VERIFICATION = True
    LEGACY_API_CLIENT_IDS = [x.strip() for x in os.environ.get("LEGACY_API_CLIENT_IDS", "").split(",") if x.strip()]
    OIDC_ALLOW_HS256 = os.environ.get("OIDC_ALLOW_HS256", "false").lower() in {"true", "1"}

    SERVICE_TOKEN_TTL = int(os.environ.get("SERVICE_TOKEN_TTL", "300"))
    EVENT_WORKER_BATCH = int(os.environ.get("EVENT_WORKER_BATCH", "50"))
