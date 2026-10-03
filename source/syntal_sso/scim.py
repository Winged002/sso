import hashlib,hmac,secrets
from flask import Blueprint, abort, g, jsonify, request, render_template
from .db import db
from .security import login_required, hash_password
from .acl import audit, require_permission
from .lifecycle import require_recent, serialize_org
from .util import public_id, utcnow

bp=Blueprint('scim',__name__)
SCIM='urn:ietf:params:scim:schemas:core:2.0:User'

def _hash(v):return hashlib.sha256(v.encode()).hexdigest()
def _error(status,detail):return jsonify(schemas=['urn:ietf:params:scim:api:messages:2.0:Error'],status=str(status),detail=detail),status

def _auth(org_id):
    auth=request.headers.get('Authorization','')
    if not auth.startswith('Bearer '):return None
    digest=_hash(auth[7:])
    for row in db().scim_tokens.find({'syntal_org_id':org_id,'status':'active'}):
        if hmac.compare_digest(row.get('token_hash',''),digest):return row
    return None

def _user_doc(user,membership):
    return {'schemas':[SCIM],'id':user.get('syntal_user_id'),'userName':user.get('email'),'displayName':user.get('name') or user.get('email'),'active':membership.get('status')=='active','emails':[{'value':user.get('email'),'primary':True}],'meta':{'resourceType':'User'}}

@bp.route('/organizations/<org_id>/enterprise/scim',methods=['GET','POST'])
@login_required
@serialize_org
def manage(org_id):
    if not g.organization or g.organization.get('syntal_org_id')!=org_id:abort(404)
    require_permission('syntal.scim.manage'); token=None
    if request.method=='POST':
        require_recent(strong=True);token=secrets.token_urlsafe(48);tid=public_id('scim')
        db().scim_tokens.insert_one({'scim_token_id':tid,'syntal_org_id':org_id,'name':(request.form.get('name') or 'SCIM token').strip(),'token_hash':_hash(token),'status':'active','created_at':utcnow(),'created_by':g.user.get('syntal_user_id')});audit('scim.token_created',org_id=org_id,detail={'scim_token_id':tid})
    rows=list(db().scim_tokens.find({'syntal_org_id':org_id},{'token_hash':0}).sort('created_at',-1))
    return render_template('enterprise/scim.html',title='SCIM provisioning',organization=g.organization,tokens=rows,new_token=token)

@bp.route('/scim/v2/<org_id>/Users',methods=['GET','POST'])
def users(org_id):
    if not _auth(org_id):return _error(401,'Invalid SCIM bearer token')
    if request.method=='GET':
        members=list(db().memberships.find({'syntal_org_id':org_id,'status':{'$ne':'deleted'}})); ids=[m.get('syntal_user_id') for m in members]; umap={u.get('syntal_user_id'):u for u in db().users.find({'syntal_user_id':{'$in':ids}})}
        resources=[_user_doc(umap[m['syntal_user_id']],m) for m in members if m.get('syntal_user_id') in umap]
        return jsonify(schemas=['urn:ietf:params:scim:api:messages:2.0:ListResponse'],totalResults=len(resources),startIndex=1,itemsPerPage=len(resources),Resources=resources)
    body=request.get_json(silent=True) or {};email=(body.get('userName') or '').strip().lower()
    if not email:return _error(400,'userName is required')
    user=db().users.find_one({'email':email})
    if not user:
        uid=public_id('usr');user={'syntal_user_id':uid,'user_id':uid,'email':email,'name':(body.get('displayName') or email).strip(),'status':'active','email_verified':False,'verified':False,'federated_only':True,'created_at':utcnow(),'registration_source':'scim'};db().users.insert_one(user)
    uid=user['syntal_user_id'];existing=db().memberships.find_one({'syntal_org_id':org_id,'syntal_user_id':uid})
    if not existing:
        role=db().organization_roles.find_one({'syntal_org_id':org_id,'key':'member','status':'active'}) or db().organization_roles.find_one({'syntal_org_id':org_id,'key':{'$ne':'owner'},'status':'active'})
        mid=public_id('mem');existing={'membership_id':mid,'syntal_org_id':org_id,'syntal_user_id':uid,'role_id':(role or {}).get('role_id'),'role':(role or {}).get('key','member'),'status':'active','created_at':utcnow(),'provisioned_by':'scim'};db().memberships.insert_one(existing)
    audit('scim.user_provisioned',org_id=org_id,user_id=uid,detail={'email':email});return jsonify(_user_doc(user,existing)),201

@bp.route('/scim/v2/<org_id>/Users/<uid>',methods=['GET','PUT','PATCH','DELETE'])
def user(org_id,uid):
    if not _auth(org_id):return _error(401,'Invalid SCIM bearer token')
    membership=db().memberships.find_one({'syntal_org_id':org_id,'syntal_user_id':uid}) ; user=db().users.find_one({'syntal_user_id':uid})
    if not membership or not user:return _error(404,'Resource not found')
    if request.method=='GET':return jsonify(_user_doc(user,membership))
    if request.method=='DELETE':db().memberships.update_one({'_id':membership['_id']},{'$set':{'status':'suspended','updated_at':utcnow()}});audit('scim.user_deactivated',org_id=org_id,user_id=uid);return '',204
    body=request.get_json(silent=True) or {};active=body.get('active')
    if request.method=='PATCH':
        for op in body.get('Operations',[]):
            if (op.get('path') or '').lower()=='active':active=op.get('value')
    if active is not None:db().memberships.update_one({'_id':membership['_id']},{'$set':{'status':'active' if bool(active) else 'suspended','updated_at':utcnow()}})
    if body.get('displayName'):db().users.update_one({'_id':user['_id']},{'$set':{'name':str(body['displayName']).strip(),'updated_at':utcnow()}})
    membership=db().memberships.find_one({'_id':membership['_id']});user=db().users.find_one({'_id':user['_id']});audit('scim.user_updated',org_id=org_id,user_id=uid);return jsonify(_user_doc(user,membership))
