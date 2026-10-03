import hashlib,hmac,json,secrets,time
import requests
from flask import Blueprint, abort, g, redirect, render_template, request, url_for
from .db import db
from .security import login_required
from .acl import audit as acl_audit, require_permission
from .lifecycle import require_recent, serialize_org
from .crypto_store import seal, open_sealed
from .util import public_id, utcnow

bp=Blueprint('events',__name__)

def enqueue(event, org_id=None, user_id=None, detail=None):
    if not org_id:return
    now=utcnow(); payload={'id':public_id('evt'),'type':event,'created_at':now.isoformat(),'organization_id':org_id,'user_id':user_id,'data':detail or {}}
    for sub in db().event_subscriptions.find({'syntal_org_id':org_id,'status':'active'}):
        allowed=sub.get('events') or ['*']
        if '*' not in allowed and event not in allowed:continue
        db().event_deliveries.insert_one({'delivery_id':public_id('del'),'subscription_id':sub['subscription_id'],'syntal_org_id':org_id,'event':event,'payload':payload,'status':'pending','attempts':0,'next_attempt_at':now,'created_at':now})

def _sign(secret,timestamp,body):return hmac.new(secret.encode(),f'{timestamp}.{body}'.encode(),hashlib.sha256).hexdigest()

def deliver_one(delivery, session=requests):
    sub=db().event_subscriptions.find_one({'subscription_id':delivery['subscription_id'],'status':'active'})
    if not sub:
        db().event_deliveries.update_one({'_id':delivery['_id']},{'$set':{'status':'cancelled','updated_at':utcnow()}});return False
    body=json.dumps(delivery['payload'],separators=(',',':'),sort_keys=True);ts=str(int(time.time()));secret=open_sealed(sub['secret_sealed'],'event-secret:'+sub['subscription_id']).decode();sig=_sign(secret,ts,body)
    try:
        r=session.post(sub['url'],data=body,headers={'Content-Type':'application/json','Syntal-Event-Id':delivery['payload']['id'],'Syntal-Delivery-Id':delivery['delivery_id'],'Syntal-Signature':f't={ts},v1={sig}'},timeout=8,allow_redirects=False)
        ok=200<=r.status_code<300;status='delivered' if ok else 'pending';attempts=delivery.get('attempts',0)+1
        update={'status':status,'attempts':attempts,'last_status_code':r.status_code,'updated_at':utcnow()}
        if ok:update['delivered_at']=utcnow()
        else:update['next_attempt_at']=utcnow()+__import__('datetime').timedelta(seconds=min(3600,30*(2**min(attempts,6))))
    except Exception as exc:
        attempts=delivery.get('attempts',0)+1;update={'status':'dead' if attempts>=10 else 'pending','attempts':attempts,'last_error':type(exc).__name__,'updated_at':utcnow(),'next_attempt_at':utcnow()+__import__('datetime').timedelta(seconds=min(3600,30*(2**min(attempts,6))))}
    db().event_deliveries.update_one({'_id':delivery['_id']},{'$set':update});return update['status']=='delivered'

@bp.route('/organizations/<org_id>/enterprise/events',methods=['GET','POST'])
@login_required
@serialize_org
def manage(org_id):
    if not g.organization or g.organization.get('syntal_org_id')!=org_id:abort(404)
    require_permission('syntal.events.manage');secret=None
    if request.method=='POST':
        require_recent(strong=True);url=(request.form.get('url') or '').strip();events=[x.strip() for x in (request.form.get('events') or '*').split(',') if x.strip()]
        if not url.startswith('https://'):abort(400,'Event endpoint must use HTTPS')
        sid=public_id('sub');secret=secrets.token_urlsafe(48);db().event_subscriptions.insert_one({'subscription_id':sid,'syntal_org_id':org_id,'url':url,'events':events or ['*'],'secret_sealed':seal(secret,'event-secret:'+sid),'status':'active','created_at':utcnow(),'created_by':g.user.get('syntal_user_id')});acl_audit('event_subscription.created',org_id=org_id,detail={'subscription_id':sid,'url':url})
    rows=list(db().event_subscriptions.find({'syntal_org_id':org_id},{'secret_sealed':0}).sort('created_at',-1));return render_template('enterprise/events.html',title='Event delivery',organization=g.organization,subscriptions=rows,new_secret=secret)

@bp.post('/organizations/<org_id>/enterprise/events/<sid>/revoke')
@login_required
@serialize_org
def revoke(org_id,sid):
    if not g.organization or g.organization.get('syntal_org_id')!=org_id:abort(404)
    require_permission('syntal.events.manage');require_recent(strong=True);db().event_subscriptions.update_one({'subscription_id':sid,'syntal_org_id':org_id},{'$set':{'status':'revoked','revoked_at':utcnow()}});acl_audit('event_subscription.revoked',org_id=org_id,detail={'subscription_id':sid});return redirect(url_for('events.manage',org_id=org_id))
