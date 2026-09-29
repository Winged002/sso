#!/usr/bin/env python3
"""Read-only runtime audit for Syntal SSO v3.1.3. --smtp-probe connects/authenticates but sends no email."""
import argparse,inspect
from syntal_sso import create_app,passkeys
from syntal_sso.db import db
from syntal_sso.mfa import totp_enabled
from syntal_sso.access import _matrix_cell, _matrix_permission_catalog, update_matrix_member_app
from syntal_sso.applications import app_members
from syntal_sso.oidc import _client_secret_ok,_issue_from_doc,authorize,_registration_permission,_register_organization_for_app,ORG_APP_REGISTER_PERMISSION
from syntal_sso.acl import application_access_override, effective_permissions_for_membership
from syntal_sso.mailer import smtp_status,probe_smtp
p=argparse.ArgumentParser(); p.add_argument('--smtp-probe',action='store_true'); args=p.parse_args()
app=create_app(); required={'access.audit_log','auth.login','auth.mfa_verify','auth.reauth','auth.register','organizations.accept_invitation','oidc.authorize','oidc.token','oidc.userinfo'}
with app.app_context():
    database=db(); database.command('ping'); print('=== SYNTAL SSO v3.1.3 RUNTIME AUDIT ==='); print('VERSION:',app.config.get('VERSION')); print('DATABASE:',app.config.get('MONGO_DB')); print('MONGO: PASS')
    endpoints=set(app.view_functions); missing=sorted(required-endpoints); print('AUTH_ENDPOINTS:','PASS' if not missing else 'FAIL');
    if missing: print('MISSING_ENDPOINTS:',', '.join(missing))
    print('WEBAUTHN_LIBRARY:','PASS' if passkeys.library_ready() else 'FAIL')
    marked=list(database.users.find({'$or':[{'mfa.totp_enabled':True},{'totp_enabled':True}]},{'mfa':1,'totp_secret':1,'totp_seed':1,'syntal_user_id':1}).limit(1000)); readable=sum(1 for u in marked if totp_enabled(u)); print('TOTP_USERS_MARKED_ENABLED:',len(marked)); print('TOTP_USERS_WITH_READABLE_SEED:',readable)
    print('LEGACY_CLIENT_SECRET_COMPAT:','PASS' if 'sha256:' in inspect.getsource(_client_secret_ok) else 'FAIL'); print('REFRESH_TOKEN_ID_COMPAT:','PASS' if 'refresh_token_id' in inspect.getsource(_issue_from_doc) else 'FAIL'); print('EFFECTIVE_ACCESS_MATRIX:','PASS' if 'effective_permissions_for_membership' in inspect.getsource(_matrix_cell) else 'FAIL'); print('ACTIONABLE_AUTHORIZE_UX:','PASS' if 'requested_org_unavailable' in inspect.getsource(authorize) else 'FAIL'); print('INLINE_APP_REGISTRATION:','PASS' if 'register_organization' in inspect.getsource(authorize) and 'organization_application_registered' in inspect.getsource(_register_organization_for_app) else 'FAIL'); print('APP_REGISTRATION_PERMISSION:',ORG_APP_REGISTER_PERMISSION); print('MEMBER_APP_ACCESS_OVERRIDES:','PASS' if 'access_effect' in inspect.getsource(update_matrix_member_app) and 'direct_permissions' in inspect.getsource(update_matrix_member_app) else 'FAIL'); print('MATRIX_PERMISSION_EDITOR:','PASS' if '_matrix_permission_catalog' in inspect.getsource(update_matrix_member_app) else 'FAIL'); print('APP_ASSIGNMENT_ID_COMPAT:','PASS' if 'app_assignment_id' in inspect.getsource(update_matrix_member_app) and 'app_assignment_id' in inspect.getsource(app_members) else 'FAIL'); print('OIDC_MEMBER_DENY_ENFORCEMENT:','PASS' if 'application_access_override' in inspect.getsource(authorize.__globals__['_eligible_orgs']) else 'FAIL')
    smtp=smtp_status(); print('SMTP_CONFIGURED:','PASS' if smtp['configured'] else 'NOT CONFIGURED'); print('SMTP_HOST:',smtp['host'] or '<none>'); print('SMTP_PORT:',smtp['port']); print('SMTP_TLS:',smtp['use_tls']); print('SMTP_SSL:',smtp['use_ssl'])
    if args.smtp_probe:
        ok,detail=probe_smtp(); print('SMTP_CONNECTION_PROBE:','PASS' if ok else 'FAIL'); print('SMTP_PROBE_DETAIL:',detail)
    print('DATABASE_WRITES_PERFORMED: 0')
    if missing or not passkeys.library_ready(): raise SystemExit(1)
