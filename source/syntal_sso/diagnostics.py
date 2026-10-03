"""Read-only access explanations and local integration configuration checks."""
from flask import Blueprint,abort,g,render_template,request,current_app
from .security import login_required
from .applications import _require_org,_catalog_applications
from .acl import require_permission,role_for_membership
from .policy import access_decision
from .db import db
from .oidc import _signing_material

bp=Blueprint('diagnostics',__name__)


@bp.get('/organizations/<org_id>/access/inspector')
@login_required
def inspector(org_id):
    org,_=_require_org(org_id,'syntal.roles.read');require_permission('syntal.members.read')
    members=list(db().memberships.find({'syntal_org_id':org_id,'status':{'$in':['active','suspended']}}))
    users={u['syntal_user_id']:u for u in db().users.find({'syntal_user_id':{'$in':[m['syntal_user_id'] for m in members]}})}
    apps=_catalog_applications(org_id);member=next((m for m in members if m.get('membership_id')==request.args.get('member')),None)
    app=next((a for a in apps if a['client_id']==request.args.get('application')),None)
    decision=access_decision(users.get(member['syntal_user_id']),org,member,app) if member and app else None
    assignments=list(db().organization_application_memberships.find({'syntal_org_id':org_id,'membership_id':{'$in':[member.get('membership_id'),str(member['_id'])]},'client_id':app['client_id'],'status':'active'})) if member and app else []
    return render_template('access/inspector.html',title='Member access inspector',organization=org,members=members,users=users,applications=apps,selected_member=member,selected_app=app,decision=decision,assignments=assignments,role=role_for_membership(org_id,member) if member else None)


@bp.get('/organizations/<org_id>/applications/diagnostics')
@login_required
def integrations(org_id):
    org,_=_require_org(org_id,'syntal.org_apps.manage');apps=_catalog_applications(org_id);checks=[]
    for app in apps:
        reasons=[]
        if app.get('status')!='active':reasons.append('Application suspended')
        if not app.get('oidc_enabled'):reasons.append('OIDC disabled')
        if not app.get('redirect_uris'):reasons.append('No callback registered')
        if app.get('client_type')!='public' and not app.get('client_secret_hash'):reasons.append('Client secret missing')
        if app.get('client_type')=='public' and not app.get('pkce_required'):reasons.append('Public client PKCE is enforced by server')
        if not app.get('api_access_enabled') and 'organization' in (app.get('scopes') or []):reasons.append('Directory API audience disabled; enable explicitly if required')
        checks.append({'app':app,'reasons':reasons})
    dependency_checks=[]
    try:db().command('ping');dependency_checks.append({'name':'MongoDB','ok':True})
    except Exception:dependency_checks.append({'name':'MongoDB','ok':False})
    try:current_app.config['SESSION_REDIS'].ping();dependency_checks.append({'name':'Session store','ok':True})
    except Exception:dependency_checks.append({'name':'Session store','ok':False})
    algorithm,_=_signing_material()
    counts={'active_sessions':db().security_sessions.count_documents({'revoked_at':None}),
        'revoked_refresh_tokens':db().oidc_refresh_tokens.count_documents({'syntal_org_id':org_id,'revoked_at':{'$ne':None}}),
        'pending_invitations':db().organization_invitations.count_documents({'syntal_org_id':org_id,'status':'pending'})}
    # Session count is restricted to org members, not the global population.
    ids=[m['syntal_user_id'] for m in db().memberships.find({'syntal_org_id':org_id,'status':'active'})]
    counts['active_sessions']=db().security_sessions.count_documents({'syntal_user_id':{'$in':ids},'revoked_at':None})
    return render_template('applications/diagnostics.html',title='Integration diagnostics',organization=org,checks=checks,dependencies=dependency_checks,algorithm=algorithm,issuer=current_app.config['OIDC_ISSUER'],counts=counts)
