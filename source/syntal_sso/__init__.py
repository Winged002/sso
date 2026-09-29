from flask import Flask, g, jsonify, render_template
from flask_session import Session
from redis import Redis
from .config import Config
from .db import close_db, db
from .context import load_request_context, memberships_for_user
from .security import csrf_token, enforce_csrf
from .ui import nav_for_request


def create_app():
    app=Flask(__name__)
    app.config.from_object(Config)
    try:
        app.config["SESSION_REDIS"]=Redis.from_url(app.config["REDIS_URL"])
        Session(app)
    except Exception:
        # Flask signed-cookie sessions remain a safe fallback if Redis is unavailable during startup.
        app.config["SESSION_TYPE"]="null"

    from .auth import bp as auth_bp
    from .organizations import bp as organizations_bp
    from .applications import bp as applications_bp
    from .access import bp as access_bp
    from .billing import bp as billing_bp
    from .oidc import bp as oidc_bp
    from .api import bp as api_bp
    from .compat import bp as compat_bp
    for bp in [auth_bp,organizations_bp,applications_bp,access_bp,billing_bp,oidc_bp,api_bp,compat_bp]: app.register_blueprint(bp)

    @app.before_request
    def _before():
        load_request_context(); enforce_csrf()

    @app.context_processor
    def _globals():
        return {"current_user":getattr(g,"user",None),"current_org":getattr(g,"organization",None),"current_membership":getattr(g,"membership",None),"my_memberships":memberships_for_user(),"navigation":nav_for_request() if getattr(g,"user",None) else None,"csrf_token":csrf_token,"app_version":"3.1.3"}

    @app.after_request
    def _headers(response):
        response.headers.setdefault("X-Content-Type-Options","nosniff")
        response.headers.setdefault("X-Frame-Options","DENY")
        response.headers.setdefault("Referrer-Policy","strict-origin-when-cross-origin")
        response.headers.setdefault("Permissions-Policy","camera=(), microphone=(), geolocation=()")
        response.headers.setdefault("Content-Security-Policy","default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; script-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self' https:")
        return response

    @app.get("/health")
    @app.get("/healthz")
    def health(): return jsonify({"status":"ok","service":"syntal-sso","version":"3.1.3"})

    @app.get("/readyz")
    def ready():
        try:
            db().command("ping"); return jsonify({"status":"ready","version":"3.1.3"})
        except Exception as exc:return jsonify({"status":"not_ready","error":str(exc)}),503

    @app.errorhandler(403)
    def forbidden(_): return render_template("errors/403.html",title="Access denied"),403
    @app.errorhandler(404)
    def not_found(_): return render_template("errors/404.html",title="Not found"),404
    @app.errorhandler(500)
    def server_error(_): return render_template("errors/500.html",title="Something went wrong"),500

    app.teardown_appcontext(close_db)
    return app
