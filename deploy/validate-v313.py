#!/usr/bin/env python3
from pathlib import Path
import ast,re,sys
try: from jinja2 import Environment
except Exception: Environment=None
root=Path(sys.argv[1]).resolve() if len(sys.argv)>1 else Path(__file__).resolve().parents[1]/'source'
checks=[]
def check(name,ok,detail=''): checks.append((name,bool(ok),detail))
check('VERSION=3.1.3',(root/'VERSION').read_text().strip()=='3.1.3')
req=(root/'requirements.txt').read_text(); check('WebAuthn dependency','webauthn>=2.2,<3' in req)
for rel in ['syntal_sso/mfa.py','syntal_sso/passkeys.py','syntal_sso/mailer.py','syntal_sso/templates/email/invitation.html','syntal_sso/templates/email/security.html','syntal_sso/templates/organizations/invitation_accept.html']:
    check('exists '+rel,(root/rel).exists())
py_files=list((root/'syntal_sso').rglob('*.py')); parsed={}
for p in py_files:
    try: parsed[p]=ast.parse(p.read_text())
    except Exception as e: check('python parse '+str(p.relative_to(root)),False,str(e))
check('all Python parses',len(parsed)==len(py_files),f'{len(parsed)}/{len(py_files)}')
html_files=list((root/'syntal_sso/templates').rglob('*.html')); j_ok=True
if Environment:
    env=Environment()
    for p in html_files:
        try: env.parse(p.read_text())
        except Exception as e: check('jinja '+str(p.relative_to(root)),False,str(e)); j_ok=False
    check('all Jinja parses',j_ok,f'{len(html_files)} templates')
else: check('templates present',bool(html_files),f'{len(html_files)} templates')
endpoints={'static'}
for p,tree in parsed.items():
    bp_names={}
    for node in tree.body:
        if isinstance(node,ast.Assign) and isinstance(node.value,ast.Call) and isinstance(node.value.func,ast.Name) and node.value.func.id=='Blueprint' and node.targets and isinstance(node.targets[0],ast.Name) and node.value.args and isinstance(node.value.args[0],ast.Constant): bp_names[node.targets[0].id]=node.value.args[0].value
    for node in tree.body:
        if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):
            for dec in node.decorator_list:
                call=dec if isinstance(dec,ast.Call) else None; func=call.func if call else dec
                if isinstance(func,ast.Attribute) and isinstance(func.value,ast.Name) and func.value.id in bp_names and func.attr in {'route','get','post','put','patch','delete'}:
                    endpoint=node.name
                    if call:
                        for kw in call.keywords:
                            if kw.arg=='endpoint' and isinstance(kw.value,ast.Constant): endpoint=kw.value.value
                    endpoints.add(bp_names[func.value.id]+'.'+endpoint)
refs=[]; pat=re.compile(r"url_for\(\s*['\"]([^'\"]+)['\"]")
for p in list((root/'syntal_sso').rglob('*.py'))+html_files:
    for m in pat.finditer(p.read_text()): refs.append((m.group(1),p.relative_to(root)))
bad=[(r,str(p)) for r,p in refs if r not in endpoints]; check('literal url_for endpoints resolve',not bad,'; '.join(f'{r} @ {p}' for r,p in bad[:20]))
config=(root/'syntal_sso/config.py').read_text(); auth=(root/'syntal_sso/auth.py').read_text(); oidc=(root/'syntal_sso/oidc.py').read_text(); mail=(root/'syntal_sso/mailer.py').read_text(); org=(root/'syntal_sso/organizations.py').read_text(); css=(root/'syntal_sso/static/v3.css').read_text(); base=(root/'syntal_sso/templates/base.html').read_text(); access=(root/'syntal_sso/access.py').read_text(); matrix=(root/'syntal_sso/templates/access/matrix.html').read_text()
check('Config.VERSION=3.1.3','VERSION = "3.1.3"' in config)
init=(root/'syntal_sso/__init__.py').read_text(); check('health/context version=3.1.3','app_version":"3.1.3' in init and '"version":"3.1.3"' in init)
check('SMTP legacy aliases',all(x in config for x in ['SMTP_HOST','SMTP_SERVER','MAIL_SERVER','SMTP_USERNAME','SMTP_USER','MAIL_USERNAME','SMTP_PASSWORD','SMTP_PASS','MAIL_PASSWORD','SMTP_FROM_EMAIL','SMTP_SENDER','MAIL_DEFAULT_SENDER']))
check('SMTP TLS+SSL support','SMTP_USE_TLS' in config and 'SMTP_USE_SSL' in config and 'SMTP_SSL' in mail and 'starttls' in mail)
check('multipart transactional email','EmailMessage' in mail and 'add_alternative' in mail and 'set_content' in mail)
check('styled invitation email','email/invitation.html' in mail and 'Accept invitation' in (root/'syntal_sso/templates/email/invitation.html').read_text())
check('styled security email','email/security.html' in mail and 'Security notification' in (root/'syntal_sso/templates/email/security.html').read_text())
check('invitation delivery semantics','delivery_status' in org and 'last_sent_at' in org and '_deliver_invitation' in org and 'send_invitation_email' in org)
check('invitation acceptance route','def accept_invitation' in org and 'invitation_accepted' in org)
check('invitation account creation','account.created_from_invitation' in auth and 'hash_password' in auth)
check('security email hooks',all(x in auth for x in ['Authenticator MFA enabled','Authenticator MFA disabled','Passkey added','Passkey removed']))
check('unified glass tokens','Unified Glass Workspace' in css and '--glass-blur' in css and '.glass-hero' in css and '.ambient-layer' in css)
check('unified glass shell','ambient-layer' in base and 'glass-shell' in base and 'account-chip' in base)
check('adaptive theme','prefers-color-scheme:dark' in css)
check('responsive design','@media(max-width:1180px)' in css and '@media(max-width:640px)' in css)
check('legacy TOTP encryption','totp_secret_encrypted' in (root/'syntal_sso/mfa.py').read_text() and 'AESGCM' in (root/'syntal_sso/mfa.py').read_text())
check('legacy sha256 client secret compatibility','startswith("sha256:")' in oidc)
check('RS256 persistent key support','/app/oidc_private.pem' in oidc and 'RS256' in oidc)
check('owner concrete OIDC permissions','perms.update({f"{client_id}.access",f"{client_id}.admin"})' in oidc)
check('refresh token legacy id compatibility','"refresh_token_id":public_id("rt")' in oidc)
check('effective matrix helper','def _matrix_cell' in access and 'effective_permissions_for_membership' in access and 'entitlement_is_active' in access)
check('matrix renders effective state','matrix_cells' in matrix and 'cell.label' in matrix)
check('actionable authorize UX','standalone_auth=True' in oidc and 'requested_org_unavailable' in oidc and 'access_denied' in oidc)
check('dedicated app registration permission','ORG_APP_REGISTER_PERMISSION = "syntal.org_apps.register"' in oidc and 'syntal.org_apps.register' in access)
check('inline OAuth app registration','def _register_organization_for_app' in oidc and 'register_organization' in oidc and 'oidc.organization_application_registered' in oidc)
check('admin owner registration compatibility','role_key in {"owner", "admin"}' in oidc and 'syntal.org_apps.manage' in oidc)
check('authorize registration UI','registration_options' in (root/'syntal_sso/templates/auth/authorize.html').read_text() and 'Enable & continue' in (root/'syntal_sso/templates/auth/authorize.html').read_text())
check('member app override ACL helper','def application_access_override' in (root/'syntal_sso/acl.py').read_text() and 'access_effect' in (root/'syntal_sso/acl.py').read_text())
check('member direct permissions ACL','direct_permissions' in (root/'syntal_sso/acl.py').read_text() and 'perms.add(f"{client_id}.access")' in (root/'syntal_sso/acl.py').read_text())
check('member app deny strips inherited namespace','denied =' in (root/'syntal_sso/acl.py').read_text() and 'p.startswith(client_id + ".")' in (root/'syntal_sso/acl.py').read_text())
check('OIDC enforces member deny','application_access_override' in oidc and 'override == "deny"' in oidc)
check('matrix member app edit route','def update_matrix_member_app' in access and 'authorization.matrix_member_application_updated' in access)
check('matrix validates direct permissions','_matrix_permission_catalog' in access and 'Invalid application permission' in access)
check('matrix owner protection','Owner application access is protected' in access)
check('matrix inline editor UI','Save member access' in matrix and 'access_effect' in matrix and 'Direct permissions' in matrix and 'app_role_id' in matrix)
check('matrix editor glass styling','matrix-editor-dialog' in css and 'matrix-cell-button' in css)
check('legacy app_assignment_id compatibility','\"app_assignment_id\":new_assignment_id' in access)
applications=(root/'syntal_sso/applications.py').read_text()
check('application member writer legacy id compatibility','\"app_assignment_id\":new_assignment_id' in applications and '\"assignment_id\":new_assignment_id' in applications)
check('matrix writer dual assignment ids','\"app_assignment_id\":new_assignment_id' in access and '\"assignment_id\":new_assignment_id' in access)
check('no migration files',not [p for p in root.rglob('*') if p.is_file() and ('migration' in p.name.lower() or 'migrate' in p.name.lower())])
failed=[x for x in checks if not x[1]]
for name,ok,detail in checks: print(('PASS' if ok else 'FAIL'),name,('- '+detail if detail else ''))
print(f'\n{len(checks)-len(failed)}/{len(checks)} checks passed')
if failed: raise SystemExit(1)
