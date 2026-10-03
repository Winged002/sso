"""Session, token-family and serialized mutation lifecycle helpers."""
from contextlib import contextmanager
from datetime import timedelta
import hashlib, secrets
from flask import abort, current_app, g, request, session
from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError
from .db import db
from .util import utcnow, public_id


def active_user(user):
    return bool(user and user.get('status') in (None,'active') and user.get('email_verified') is True)


def valid_session(sid,uid,epoch=None):
    row=db().security_sessions.find_one({'_id':sid,'syntal_user_id':uid,'revoked_at':None,'expire_at':{'$gt':utcnow()}}) if sid else None
    if not row:return False
    user=db().users.find_one({'syntal_user_id':uid})
    return active_user(user) and row.get('session_epoch',0)==user.get('session_epoch',0) and (epoch is None or epoch==user.get('session_epoch',0))


def start_session(user,method,aal2):
    session.clear()
    # regenerate only after non-empty contents: Flask-Session ignores an empty session.
    session['rotation_pending']=True
    regenerate=getattr(current_app.session_interface,'regenerate',None)
    if regenerate:regenerate(session)
    session.clear()
    uid=user.get('syntal_user_id') or str(user['_id']); now=utcnow(); sid=public_id('sid')
    db().security_sessions.insert_one({'_id':sid,'syntal_user_id':uid,'session_epoch':user.get('session_epoch',0),
        'created_at':now,'last_seen_at':now,'expire_at':now+timedelta(seconds=current_app.config['SESSION_MAX_AGE']),
        'revoked_at':None,'method':method,'aal2':bool(aal2),'user_agent':request.user_agent.string[:200]})
    session.update(user_id=uid,syntal_user_id=uid,session_epoch=user.get('session_epoch',0),auth_session_id=sid,
        auth_time=int(now.timestamp()),amr=['pwd','otp'] if method=='otp' else [method],
        acr='urn:syntal:loa:2' if aal2 else 'urn:syntal:loa:1')
    return sid


def revoke_session(sid,uid=None):
    query={'_id':sid}
    if uid:query['syntal_user_id']=uid
    row=db().security_sessions.find_one(query)
    if not row:return False
    now=utcnow()
    db().security_sessions.update_one(query,{'$set':{'revoked_at':now}})
    db().oidc_refresh_tokens.update_many({'sid':sid},{'$set':{'revoked_at':now}})
    return True


def revoke_member(uid,org_id):
    now=utcnow()
    db().oidc_refresh_tokens.update_many({'syntal_user_id':uid,'syntal_org_id':org_id},{'$set':{'revoked_at':now}})


def revoke_family(family_id):
    if not family_id:return
    now=utcnow()
    db().oidc_refresh_tokens.update_many({'family_id':family_id},{'$set':{'revoked_at':now}})
    db().oidc_token_families.update_one({'_id':family_id},{'$set':{'revoked_at':now}},upsert=True)


def family_active(family_id):
    if not family_id:return False
    row=db().oidc_token_families.find_one({'_id':family_id})
    return bool(row and row.get('revoked_at') is None and row.get('expire_at') and row['expire_at']>utcnow())


def throttle(action,identity,limit=10,period=300):
    """Shared fixed-window counter using Mongo's unique _id; no proxy-header trust."""
    bucket=int(utcnow().timestamp())//period
    key=hashlib.sha256(f'{action}:{identity}:{bucket}'.encode()).hexdigest()
    row=db().security_attempts.find_one_and_update({'_id':key},
        {'$inc':{'count':1},'$setOnInsert':{'expire_at':utcnow()+timedelta(seconds=period*2)}},
        upsert=True,return_document=ReturnDocument.AFTER)
    if row['count']>limit:abort(429,'Too many attempts. Try again later.')


def login_throttle(action,email=''):
    throttle(action+':ip',request.remote_addr or 'unknown',60,300)
    if email:throttle(action+':account',str(email).lower(),10,300)


def pending_fresh(key,ttl=300):
    started=session.get(key)
    return isinstance(started,(int,float)) and 0<=int(utcnow().timestamp())-started<=ttl


def require_recent(strong=False):
    if not pending_fresh('step_up_at',current_app.config['STEP_UP_MAX_AGE']) or (strong and session.get('step_up_acr')!='urn:syntal:loa:2'):
        if request.is_json:
            from flask import jsonify,url_for
            return jsonify({'ok':False,'error':'reauthentication_required','redirect':url_for('auth.reauth',next='/account#security')}),403
        from flask import redirect,url_for
        from .util import safe_next
        return redirect(url_for('auth.reauth',next=safe_next(request.form.get('return_to')) or '/account#security'))
    return None


@contextmanager
def mutation_lock(resource,ttl=30):
    """A standalone-Mongo compatible mutex. _id uniqueness serializes contenders."""
    token=secrets.token_urlsafe(24); now=utcnow()
    try:
        row=db().security_locks.find_one_and_update({'_id':resource,'$or':[{'expire_at':{'$lte':now}},{'expire_at':{'$exists':False}}]},
            {'$set':{'owner':token,'expire_at':now+timedelta(seconds=ttl)}},upsert=True,return_document=ReturnDocument.AFTER)
    except DuplicateKeyError:abort(409,'Another change is in progress. Retry shortly.')
    if not row or row.get('owner')!=token:abort(409)
    try:yield
    finally:db().security_locks.delete_one({'_id':resource,'owner':token})

def rotate_account_epoch(user):
    row=db().users.find_one_and_update({'_id':user['_id']},{'$inc':{'session_epoch':1}},return_document=ReturnDocument.AFTER)
    uid=user['syntal_user_id'];epoch=row.get('session_epoch',0);sid=session.get('auth_session_id');now=utcnow()
    db().security_sessions.update_many({'syntal_user_id':uid,'_id':{'$ne':sid}},{'$set':{'revoked_at':now}})
    db().oidc_refresh_tokens.update_many({'syntal_user_id':uid},{'$set':{'revoked_at':now}})
    if sid:
        db().security_sessions.update_one({'_id':sid,'syntal_user_id':uid},{'$set':{'session_epoch':epoch}})
        session['session_epoch']=epoch
    return epoch

def serialize_org(fn):
    from functools import wraps
    @wraps(fn)
    def wrapped(org_id,*args,**kwargs):
        if request.method=='GET':return fn(org_id,*args,**kwargs)
        with mutation_lock('organization:'+org_id):return fn(org_id,*args,**kwargs)
    return wrapped


def validate_role_grants(org_id,membership,key,permissions):
    from .acl import role_for_membership,has_permission
    owner=(role_for_membership(org_id,membership) or {}).get('key')=='owner'
    if key=='owner':abort(403,'Ownership is granted only through ownership transfer.')
    if not owner and any(p in {'*','syntal.admin'} or not has_permission(p,membership,org_id) for p in permissions):
        abort(403,'You cannot grant permissions beyond your own authority.')
    if any(not isinstance(p,str) or len(p)>160 or (p!='*' and '.' not in p) for p in permissions):abort(400,'Invalid permission')
