#!/usr/bin/env python3
import _bootstrap,json
from syntal_sso import create_app
from syntal_sso.db import db
from syntal_sso.oidc import _signing_material
from syntal_sso.mfa import totp_configured,totp_secret_for_user
app=create_app()
with app.app_context():
    database=db();database.command('ping');app.config['SESSION_REDIS'].ping()
    required={'diagnostics.inspector','diagnostics.integrations','auth.verify_email','auth.sessions','auth.recovery_codes','api.members','api.organization_applications','oidc.token'}
    missing=sorted(required-set(app.view_functions))
    report={'version':app.config['VERSION'],'mongo':'ready','redis':'ready','schema_applied':bool(database.schema_versions.find_one({'_id':'security-v400'})),'signing_algorithm':_signing_material()[0],'missing_routes':missing,
        'public_users_needing_verification':database.users.count_documents({'registration_source':'self_service','email_verified':False})}
    users=list(database.users.find({'$or':[{'mfa.totp_enabled':True},{'totp_enabled':True}]}).limit(1000))
    report['mfa_users_checked']=len(users);report['mfa_users_unreadable']=sum(1 for u in users if not totp_secret_for_user(u))
    print(json.dumps(report,indent=2))
    if missing or not report['schema_applied'] or report['mfa_users_unreadable']:raise SystemExit(1)
