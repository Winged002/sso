import base64, hashlib, os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import current_app


def _key():
    raw=(current_app.config.get('ACCOUNT_SECRET_ENCRYPTION_KEY') or '').strip()
    if not raw: raise RuntimeError('ACCOUNT_SECRET_ENCRYPTION_KEY is required for v4 encrypted secrets.')
    try:
        padded=raw+'='*((4-len(raw)%4)%4); key=base64.urlsafe_b64decode(padded.encode())
    except Exception:
        key=b''
    if len(key)!=32:
        key=hashlib.sha256(raw.encode()).digest()
    return key


def seal(value, purpose):
    if isinstance(value,str): value=value.encode()
    nonce=os.urandom(12); aad=('syntal-sso-v4:'+purpose).encode(); ct=AESGCM(_key()).encrypt(nonce,value,aad)
    return 'v1.'+base64.urlsafe_b64encode(nonce+ct).decode().rstrip('=')


def open_sealed(value, purpose):
    if not value or not value.startswith('v1.'): raise ValueError('Unsupported sealed secret')
    raw=value[3:]; raw += '='*((4-len(raw)%4)%4); blob=base64.urlsafe_b64decode(raw.encode())
    return AESGCM(_key()).decrypt(blob[:12],blob[12:],('syntal-sso-v4:'+purpose).encode())
