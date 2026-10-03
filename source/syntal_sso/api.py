from flask import Blueprint, current_app, jsonify, request
import jwt
from .db import db
from .oidc import _decode, token_state
from .policy import access_decision, resolve_access
from .acl import has_permission, application_visible_to_org, entitlement_is_active, application_requires_entitlement_for_org, application_access_override

bp=Blueprint('api',__name__)


def _claims():
    auth=request.headers.get('Authorization','')
    if not auth.startswith('Bearer '):return None
    raw=auth[7:]
    try:
        try:claims=_decode(raw,audience=current_app.config['API_AUDIENCE'])
        except Exception:
            # Explicit, temporary audience compatibility only; never accept ID tokens.
            unsigned=jwt.decode(raw,options={'verify_signature':False});cid=unsigned.get('client_id')
            if cid not in current_app.config['LEGACY_API_CLIENT_IDS']:return None
            claims=_decode(raw,audience=cid)
        if 'organization' not in (claims.get('scope') or '').split() or not token_state(claims):return None
        app=db().applications.find_one({'client_id':claims.get('client_id')}) or {}
        if not app.get('api_access_enabled') and claims.get('client_id') not in current_app.config['LEGACY_API_CLIENT_IDS']:return None
        return claims
    except Exception:return None


def _authorized_orgs(claims):
    if not claims:return []
    # The token authorizes its selected org. Multi-org discovery is a separate capability.
    org=db().organizations.find_one({'syntal_org_id':claims.get('syntal_org_id'),'status':'active'})
    membership=db().memberships.find_one({'syntal_org_id':claims.get('syntal_org_id'),'syntal_user_id':claims.get('sub'),'status':'active'})
    return [{'syntal_org_id':org['syntal_org_id'],'name':org.get('name'),'display_name':org.get('display_name') or org.get('name')}] if org and membership else []


def _org_member(claims,org_id,permission):
    if not claims or claims.get('syntal_org_id')!=org_id:return None
    row=db().memberships.find_one({'syntal_org_id':org_id,'syntal_user_id':claims['sub'],'status':'active'})
    return row if row and has_permission(permission,row,org_id) else None


@bp.get('/v1/organizations')
def organizations():
    claims=_claims()
    if not claims:return jsonify({'error':'unauthorized'}),401
    return jsonify({'organizations':_authorized_orgs(claims)})


@bp.get('/v1/organizations/<org_id>/members')
def members(org_id):
    claims=_claims()
    if not claims:return jsonify({'error':'unauthorized'}),401
    if not _org_member(claims,org_id,'syntal.members.read'):return jsonify({'error':'forbidden'}),403
    rows=list(db().memberships.find({'syntal_org_id':org_id,'status':'active'}).sort('created_at',1))
    users={u['syntal_user_id']:u for u in db().users.find({'syntal_user_id':{'$in':[m['syntal_user_id'] for m in rows]},'status':{'$in':['active',None]}})}
    data=[{'membership_id':m.get('membership_id'),'syntal_user_id':m['syntal_user_id'],'email':users[m['syntal_user_id']].get('email'),'name':users[m['syntal_user_id']].get('name'),'role':m.get('role'),'role_id':m.get('role_id')} for m in rows if m['syntal_user_id'] in users]
    return jsonify({'members':data})


@bp.get('/v1/organizations/<org_id>/applications')
def organization_applications(org_id):
    claims=_claims()
    if not claims:return jsonify({'error':'unauthorized'}),401
    membership=_org_member(claims,org_id,'syntal.org_apps.read')
    if not membership:return jsonify({'error':'forbidden'}),403
    user=db().users.find_one({'syntal_user_id':claims['sub']});org=db().organizations.find_one({'syntal_org_id':org_id})
    entitlements={r['application']:r for r in db().organization_entitlements.find({'syntal_org_id':org_id}) if r.get('application')}
    data=[];provisioned_ids=[];allowed_ids=[]
    for app in db().applications.find({'status':{'$ne':'deleted'}}).sort('name',1):
        if not application_visible_to_org(app,org_id):continue
        cid=app.get('client_id')
        if not cid:continue
        required=application_requires_entitlement_for_org(app,org_id);ent=entitlements.get(cid)
        provisioned=app.get('status')=='active' and (not required or entitlement_is_active(ent))
        decision=access_decision(user,org,membership,app)
        if provisioned:provisioned_ids.append(cid)
        if decision['allowed']:allowed_ids.append(cid)
        data.append({'client_id':cid,'key':cid,'application':cid,'name':app.get('name') or cid,'display_name':app.get('display_name') or app.get('name') or cid,'description':app.get('description',''),'application_status':app.get('status'),'owner_type':app.get('owner_type') or 'syntal','owner_org_id':app.get('owner_org_id'),'distribution_scope':app.get('distribution_scope') or 'private','requires_entitlement':required,'provisioned':provisioned,'entitled':provisioned,'enabled':provisioned,'allowed':decision['allowed'],'member_allowed':decision['allowed'],'can_access':decision['allowed'],'status':(ent or {}).get('status') or ('active' if provisioned else 'inactive'),'entitlement_status':(ent or {}).get('status'),'access_effect':decision['access_effect'],'reasons':decision['reasons'],'url':app.get('launch_url') or app.get('application_url') or app.get('homepage_url') or app.get('url')})
    return jsonify({'syntal_org_id':org_id,'organization_id':org_id,'applications':data,'provisioned_applications':provisioned_ids,'allowed_applications':allowed_ids})


@bp.get('/v1/chat/organizations')
@bp.get('/v1/files/organizations')
@bp.get('/v1/board/organizations')
def product_organizations():return organizations()

@bp.get('/v1/chat/organizations/<org_id>/members')
@bp.get('/v1/files/organizations/<org_id>/members')
@bp.get('/v1/board/organizations/<org_id>/members')
def product_members(org_id):return members(org_id)


@bp.post('/v1/access/check')
def access_check():
    claims=_claims()
    if not claims:return jsonify({'error':'unauthorized'}),401
    payload=request.get_json(silent=True) or {}
    if not isinstance(payload,dict):return jsonify({'error':'invalid_request'}),400
    org_id=payload.get('organization_id') or payload.get('syntal_org_id');permission=payload.get('permission')
    if not isinstance(permission,str) or not isinstance(org_id,str):return jsonify({'error':'invalid_request'}),400
    cid=payload.get('application') or permission.split('.',1)[0]
    if not isinstance(cid,str) or org_id!=claims.get('syntal_org_id'):return jsonify({'allowed':False,'reasons':['token_organization_mismatch']}),403
    if cid!=claims.get('client_id'):return jsonify({'allowed':False,'reasons':['token_application_mismatch']}),403
    decision=resolve_access(claims['sub'],org_id,cid,permission)
    # Do not disclose the entire effective permission set through this endpoint.
    return jsonify({k:decision[k] for k in ('allowed','reasons','permission','application','entitlement_status','policy_version')})
