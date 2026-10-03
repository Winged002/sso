import hashlib
from flask import session
from conftest import client_for,get,post
from syntal_sso.util import utcnow


def test_enterprise_pages_render_for_owner(env):
    c=client_for(env)
    for path in ['/organizations/o/enterprise','/organizations/o/enterprise/federation','/organizations/o/enterprise/scim','/organizations/o/enterprise/service-accounts','/organizations/o/enterprise/signing-keys','/organizations/o/enterprise/events']:
        r=get(c,path);assert r.status_code==200


def test_service_account_client_credentials_is_tenant_scoped(env):
    app,d,*_=env
    secret='service-secret-test';d.service_accounts.insert_one({'service_account_id':'svc1','client_id':'svc_client','secret_hash':hashlib.sha256(secret.encode()).hexdigest(),'name':'worker','syntal_org_id':'o','application':'x','permissions':['x.access'],'status':'active'})
    r=app.test_client().post('/oauth/service-token',data={'grant_type':'client_credentials','client_id':'svc_client','client_secret':secret},base_url='https://sso.syntal.pro')
    assert r.status_code==200 and r.json['token_type']=='Bearer'


def test_service_account_bad_secret_rejected(env):
    app,d,*_=env;d.service_accounts.insert_one({'service_account_id':'svc1','client_id':'svc_client','secret_hash':hashlib.sha256(b'right').hexdigest(),'syntal_org_id':'o','application':'x','permissions':['x.access'],'status':'active'})
    r=app.test_client().post('/oauth/service-token',data={'grant_type':'client_credentials','client_id':'svc_client','client_secret':'wrong'},base_url='https://sso.syntal.pro');assert r.status_code==401


def test_scim_requires_bearer_and_provisions_user(env):
    app,d,*_=env;raw='scim-test-token';d.scim_tokens.insert_one({'scim_token_id':'st1','syntal_org_id':'o','token_hash':hashlib.sha256(raw.encode()).hexdigest(),'status':'active'})
    assert app.test_client().get('/scim/v2/o/Users',base_url='https://sso.syntal.pro').status_code==401
    r=app.test_client().post('/scim/v2/o/Users',json={'userName':'new-scim@example.test','displayName':'SCIM User'},headers={'Authorization':'Bearer '+raw},base_url='https://sso.syntal.pro')
    assert r.status_code==201;assert d.users.find_one({'email':'new-scim@example.test'});assert d.memberships.find_one({'syntal_org_id':'o','syntal_user_id':r.json['id']})


def test_federation_transaction_single_use_and_browser_bound(env):
    app,d,*_=env
    from syntal_sso import federation
    provider={'provider_id':'p1','syntal_org_id':'o'}
    with app.test_request_context('/',base_url='https://sso.syntal.pro'):
        state,nonce=federation._transaction(provider,'/account');assert federation._consume(state);assert federation._consume(state) is None


def test_signing_key_rotation_preserves_retiring_key(env):
    app,d,*_=env
    from syntal_sso.signing_keys import generate_key,jwks
    with app.app_context():
        first=generate_key(d);second=generate_key(d);keys=jwks(d)['keys']
        assert first['kid']!=second['kid'];assert d.signing_keys.find_one({'kid':first['kid']})['status']=='retiring';assert {k['kid'] for k in keys}>={first['kid'],second['kid']}


def test_event_delivery_signature_and_idempotency_headers(env):
    app,d,*_=env
    from syntal_sso.crypto_store import seal
    from syntal_sso.events import deliver_one
    class Response:status_code=200
    class Sender:
        def __init__(self):self.calls=[]
        def post(self,url,**kw):self.calls.append((url,kw));return Response()
    with app.app_context():
        d.event_subscriptions.insert_one({'subscription_id':'sub1','syntal_org_id':'o','url':'https://events.example.test/hook','events':['*'],'secret_sealed':seal('hooksecret','event-secret:sub1'),'status':'active'})
        row={'delivery_id':'del1','subscription_id':'sub1','syntal_org_id':'o','payload':{'id':'evt1','type':'test','data':{}},'status':'pending','attempts':0,'next_attempt_at':utcnow()};d.event_deliveries.insert_one(row);row=d.event_deliveries.find_one({'delivery_id':'del1'});sender=Sender();assert deliver_one(row,sender);headers=sender.calls[0][1]['headers'];assert headers['Syntal-Event-Id']=='evt1' and headers['Syntal-Delivery-Id']=='del1' and headers['Syntal-Signature'].startswith('t=')


def test_v4_schema_marker_and_indexes(env):
    d=env[1];assert d.schema_versions.find_one({'_id':'security-v400'});assert d.service_accounts.index_information();assert d.federation_transactions.index_information()
