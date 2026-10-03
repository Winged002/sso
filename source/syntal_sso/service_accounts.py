import hashlib, hmac, secrets
from flask import Blueprint, abort, g, jsonify, redirect, render_template, request, url_for, current_app
from .db import db
from .security import login_required
from .acl import audit, require_permission, application_visible_to_org, active_entitlement
from .lifecycle import require_recent, serialize_org
from .util import public_id, utcnow

bp=Blueprint('service_accounts',__name__)

def _hash(value): return hashlib.sha256(value.encode()).hexdigest()

def _allowed_permissions(org_id,client_id,requested):
    app=db().applications.find_one({'client_id':client_id,'status':'active'})
    if not app or not application_visible_to_org(app,org_id): abort(400,'Application unavailable to organization')
    prefix=client_id+'.'; allowed={p for p in requested if isinstance(p,str) and p.startswith(prefix)}
    registered={x.get('permission') for x in db().organization_application_permissions.find({'syntal_org_id':org_id,'client_id':client_id,'status':'active'})}
    registered.update({client_id+'.access',client_id+'.admin'})
    return sorted(allowed & registered)

def authenticate(client_id,secret):
    row=db().service_accounts.find_one({'client_id':client_id,'status':'active'})
    if not row or not secret or not hmac.compare_digest(row.get('secret_hash',''),_hash(secret)): return None
    return row

@bp.route('/organizations/<org_id>/enterprise/service-accounts',methods=['GET','POST'])
@login_required
@serialize_org
def manage(org_id):
    if not g.organization or g.organization.get('syntal_org_id')!=org_id: abort(404)
    require_permission('syntal.service_accounts.manage')
    secret=None
    if request.method=='POST':
        require_recent(strong=True)
        name=(request.form.get('name') or '').strip(); app_id=(request.form.get('application') or '').strip()
        if not name or not app_id: abort(400)
        permissions=[x.strip() for x in request.form.getlist('permission') if x.strip()]
        permissions=_allowed_permissions(org_id,app_id,permissions)
        sid=public_id('svc'); client_id='svc_'+secrets.token_urlsafe(18).replace('-','').replace('_','')[:24]; secret=secrets.token_urlsafe(48)
        db().service_accounts.insert_one({'service_account_id':sid,'client_id':client_id,'secret_hash':_hash(secret),'name':name,'syntal_org_id':org_id,'application':app_id,'permissions':permissions,'status':'active','created_at':utcnow(),'created_by':g.user.get('syntal_user_id')})
        audit('service_account.created',org_id=org_id,detail={'service_account_id':sid,'client_id':client_id,'application':app_id})
    rows=list(db().service_accounts.find({'syntal_org_id':org_id},{'secret_hash':0}).sort('created_at',-1));apps=list(db().applications.find({'status':'active'}).sort('name',1))
    return render_template('enterprise/service_accounts.html',title='Service accounts',organization=g.organization,accounts=rows,applications=apps,new_secret=secret)

@bp.post('/organizations/<org_id>/enterprise/service-accounts/<sid>/revoke')
@login_required
@serialize_org
def revoke(org_id,sid):
    if not g.organization or g.organization.get('syntal_org_id')!=org_id: abort(404)
    require_permission('syntal.service_accounts.manage');require_recent(strong=True)
    row=db().service_accounts.find_one({'service_account_id':sid,'syntal_org_id':org_id})
    if not row: abort(404)
    db().service_accounts.update_one({'_id':row['_id']},{'$set':{'status':'revoked','revoked_at':utcnow()}});audit('service_account.revoked',org_id=org_id,detail={'service_account_id':sid})
    return redirect(url_for('service_accounts.manage',org_id=org_id))

@bp.post('/oauth/service-token')
def token():
    if request.form.get('grant_type')!='client_credentials': return jsonify(error='unsupported_grant_type'),400
    cid=request.form.get('client_id') or ''; secret=request.form.get('client_secret') or ''
    row=authenticate(cid,secret)
    if not row:return jsonify(error='invalid_client'),401
    app=db().applications.find_one({'client_id':row.get('application'),'status':'active'})
    if not app:return jsonify(error='invalid_client'),401
    if app.get('requires_entitlement',True) is not False and not active_entitlement(row['syntal_org_id'],row['application']):return jsonify(error='access_denied'),403
    from .oidc import _encode
    now=int(utcnow().timestamp());ttl=min(int(current_app.config.get('SERVICE_TOKEN_TTL',300)),900)
    claims={'iss':current_app.config['OIDC_ISSUER'],'sub':row['service_account_id'],'aud':current_app.config.get('API_AUDIENCE','syntal-api'),'iat':now,'exp':now+ttl,'jti':public_id('jwt'),'client_id':row['application'],'service_client_id':cid,'token_use':'access','scope':'organization permissions','syntal_org_id':row['syntal_org_id'],'application':row['application'],'permissions':row.get('permissions',[]),'actor_type':'service_account'}
    return jsonify(access_token=_encode(claims),token_type='Bearer',expires_in=ttl,scope=' '.join(row.get('permissions',[])))
