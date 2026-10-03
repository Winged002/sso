#!/usr/bin/env python3
"""Read-only database/configuration preflight. Outputs no secrets or password hashes."""
import _bootstrap
import json,sys
from syntal_sso import create_app
from syntal_sso.db import db
from syntal_sso.schema import inspect_database
from syntal_sso.oidc import _signing_material
from syntal_sso.mfa import _secret_key
from cryptography.hazmat.primitives import serialization
app=create_app({'STARTUP_CHECKS':False,'VALIDATE_CONFIG':False,'SESSION_BACKEND_REQUIRED':False})
with app.app_context():
    try:report=inspect_database(db())
    except Exception as exc:print(json.dumps({'ready':False,'blockers':['Database unavailable: '+type(exc).__name__]}));sys.exit(1)
    if len(app.config.get('SECRET_KEY') or '')<32:report['blockers'].append('SECRET_KEY must contain at least 32 characters')
    try:
        algorithm,key=_signing_material()
        if algorithm=='RS256' and serialization.load_pem_private_key(key.encode(),password=None).key_size<2048:raise ValueError()
        report['signing_algorithm']=algorithm
    except Exception:report['blockers'].append('Persistent signing key is missing/invalid; legacy HS256 requires an explicit separate strong secret and opt-in')
    try:_secret_key()
    except Exception:report['blockers'].append('ACCOUNT_SECRET_ENCRYPTION_KEY must decode to 32 bytes; preserve the existing key')
    try:app.config['SESSION_REDIS'].ping()
    except Exception:report['blockers'].append('Redis session store unavailable')
    if not app.config.get('SMTP_HOST'):report['blockers'].append('SMTP_HOST is required for email verification and password recovery')
    report['ready']=not report['blockers'];print(json.dumps(report,default=str,indent=2))
    sys.exit(0 if report['ready'] else 1)
