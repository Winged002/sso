from flask import Flask, g, jsonify, render_template, request
from flask_session import Session
from redis import Redis
from .config import Config
from .db import close_db, db
from .context import load_request_context, memberships_for_user
from .security import csrf_token, enforce_csrf
from .ui import nav_for_request


def create_app(config=None):
    app=Flask(__name__)
    app.config.from_object(Config)
    if config:app.config.update(config)
    if app.config.get('VALIDATE_CONFIG',True):
        if len(app.config.get('SECRET_KEY') or '')<32:raise RuntimeError('SECRET_KEY must contain at least 32 characters.')
        from .oidc import _signing_material
        from cryptography.hazmat.primitives import serialization
        with app.app_context():
            algorithm,key=_signing_material()
            if algorithm=='RS256':
                private=serialization.load_pem_private_key(key.encode(),password=None)
                if getattr(private,'key_size',0)<2048:raise RuntimeError('RSA signing key must be at least 2048 bits.')
        from .mfa import _secret_key
        with app.app_context():_secret_key()
    app.config["SESSION_REDIS"]=Redis.from_url(app.config["REDIS_URL"])
    if app.config.get('SESSION_BACKEND_REQUIRED',True):Session(app)
    if app.config.get('STARTUP_CHECKS',True):
        app.config['SESSION_REDIS'].ping()
        with app.app_context():
            db().command('ping')
            if not db().schema_versions.find_one({'_id':'security-v400'}):raise RuntimeError('Run deploy/migrate-v400.py before starting v4.0.0.')

    from .auth import bp as auth_bp
    from .organizations import bp as organizations_bp
    from .applications import bp as applications_bp
    from .access import bp as access_bp
    from .billing import bp as billing_bp
    from .oidc import bp as oidc_bp
    from .api import bp as api_bp
    from .compat import bp as compat_bp
    from .diagnostics import bp as diagnostics_bp
    from .enterprise import bp as enterprise_bp
    from .federation import bp as federation_bp
    from .scim import bp as scim_bp
    from .service_accounts import bp as service_accounts_bp
    from .signing_keys import bp as signing_keys_bp
    from .events import bp as events_bp
    for bp in [auth_bp,organizations_bp,applications_bp,access_bp,billing_bp,oidc_bp,api_bp,compat_bp,diagnostics_bp,enterprise_bp,federation_bp,scim_bp,service_accounts_bp,signing_keys_bp,events_bp]: app.register_blueprint(bp)

    @app.before_request
    def _before():
        load_request_context(); enforce_csrf()

    @app.context_processor
    def _globals():
        return {"current_user":getattr(g,"user",None),"current_org":getattr(g,"organization",None),"current_membership":getattr(g,"membership",None),"my_memberships":memberships_for_user(),"navigation":nav_for_request() if getattr(g,"user",None) else None,"csrf_token":csrf_token,"app_version":"4.0.0"}

    @app.after_request
    def _headers(response):
        if not request.path.startswith('/static/'):
            response.headers.setdefault('Cache-Control','no-store')
        response.headers.setdefault("X-Content-Type-Options","nosniff")
        response.headers.setdefault("X-Frame-Options","DENY")
        response.headers.setdefault("Referrer-Policy","no-referrer")
        response.headers.setdefault("Permissions-Policy","camera=(), microphone=(), geolocation=()")
        response.headers.setdefault("Content-Security-Policy","default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; script-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self' https:")
        return response

    @app.get("/health")
    @app.get("/healthz")
    def health(): return jsonify({"status":"ok","service":"syntal-sso","version":"4.0.0"})

    @app.get("/readyz")
    def ready():
        try:
            db().command("ping"); app.config["SESSION_REDIS"].ping(); return jsonify({"status":"ready","version":"4.0.0"})
        except Exception as exc:return jsonify({"status":"not_ready","error":"Required dependency unavailable"}),503

    @app.errorhandler(403)
    def forbidden(_): return render_template("errors/403.html",title="Access denied"),403
    @app.errorhandler(404)
    def not_found(_): return render_template("errors/404.html",title="Not found"),404
    @app.errorhandler(500)
    def server_error(_): return render_template("errors/500.html",title="Something went wrong"),500

    app.teardown_appcontext(close_db)
    return app
