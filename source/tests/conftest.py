import sys,importlib,os
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import pytest,mongomock,fakeredis
from flask import session
from syntal_sso import create_app
from syntal_sso.schema import migrate
from syntal_sso.security import hash_password
from syntal_sso.util import utcnow

PASSWORD='correct-test-password-33'
HASH=hash_password(PASSWORD)

@pytest.fixture
def env(monkeypatch):
    # Set SSO_TEST_MONGO_URI/SSO_TEST_REDIS_URL to exercise real dependencies.
    if os.environ.get('SSO_TEST_MONGO_URI'):
        from pymongo import MongoClient
        mongo=MongoClient(os.environ['SSO_TEST_MONGO_URI'],tz_aware=True)
        import uuid
        database=mongo['syntal_test_'+uuid.uuid4().hex]
    else:database=mongomock.MongoClient(tz_aware=True).db
    if os.environ.get('SSO_TEST_REDIS_URL'):
        from redis import Redis
        redis=Redis.from_url(os.environ['SSO_TEST_REDIS_URL'])
    else:redis=fakeredis.FakeRedis()
    monkeypatch.setattr('syntal_sso.Redis.from_url',lambda _:redis)
    # Build routes, then substitute the same database across all imported modules.
    app=create_app({'TESTING':True,'VALIDATE_CONFIG':False,'STARTUP_CHECKS':False,'SECRET_KEY':'test-session-secret-'+'x'*40,'OIDC_ALLOW_HS256':True,'OIDC_HS256_SECRET':'test-signing-secret-'+'y'*40,'ACCOUNT_SECRET_ENCRYPTION_KEY':'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA','ACCESS_TOKEN_TTL':300,'SESSION_KEY_PREFIX':'test:'+__import__('uuid').uuid4().hex+':'})
    for name in ['db','auth','organizations','applications','access','api','acl','policy','lifecycle','mfa','oidc','context','passkeys','billing','diagnostics','enterprise','federation','scim','service_accounts','signing_keys','events','crypto_store']:
        module=importlib.import_module('syntal_sso.'+name)
        if hasattr(module,'db'):monkeypatch.setattr(module,'db',lambda:database)
    migrate(database)
    u={'syntal_user_id':'u','user_id':'u','email':'user@example.test','name':'Test User','status':'active','email_verified':True,'verified':True,'session_epoch':0,'password_hash':HASH,'created_at':utcnow()}
    o={'syntal_org_id':'o','org_id':'o','name':'Test Organization','status':'active','authorization_policy_version':1}
    m={'membership_id':'m','syntal_user_id':'u','syntal_org_id':'o','status':'active','role':'owner','role_id':'r-owner','created_at':utcnow()}
    c={'client_id':'x','name':'Test App','owner_type':'syntal','status':'active','oidc_enabled':True,'client_type':'public','pkce_required':True,'api_access_enabled':True,'redirect_uris':['https://client.example.test/cb'],'post_logout_redirect_uris':['https://client.example.test/out'],'scopes':['openid','email','profile','organization','permissions','offline_access'],'grant_types':['authorization_code','refresh_token']}
    for collection,document in [('users',u),('organizations',o),('memberships',m),('applications',c)]:database[collection].insert_one(document)
    database.organization_roles.insert_many([{'syntal_org_id':'o','role_id':'r-owner','key':'owner','name':'Owner','permissions':['*'],'status':'active'},{'syntal_org_id':'o','role_id':'r-admin','key':'admin','name':'Admin','permissions':['syntal.roles.read','syntal.roles.manage','syntal.members.read','syntal.members.manage','syntal.members.invite','syntal.org_apps.read','syntal.org_apps.manage','syntal.org_apps.register','x.access'],'status':'active'}])
    database.organization_entitlements.insert_one({'syntal_org_id':'o','application':'x','status':'active'})
    yield app,database,u,o,m,c
    if os.environ.get('SSO_TEST_MONGO_URI'):mongo.drop_database(database.name);mongo.close()


def client_for(env,role='owner',aal2=False):
    app,d,u,o,m,c=env
    d.memberships.update_one({'membership_id':'m'},{'$set':{'role':role,'role_id':'r-'+role}})
    from syntal_sso.auth import _login_session
    with app.test_request_context('/login',base_url='https://sso.syntal.pro'):
        _login_session(d.users.find_one({'syntal_user_id':'u'}),method='webauthn' if aal2 else 'pwd',aal2=aal2)
        data=dict(session);data['org_id']='o';data['csrf_token']='test-csrf'
    client=app.test_client()
    with client.session_transaction(base_url='https://sso.syntal.pro') as sess:sess.update(data)
    return client


def get(client,path,**kwargs):return client.get(path,base_url='https://sso.syntal.pro',**kwargs)
def post(client,path,data=None,**kwargs):return client.post(path,data={'csrf_token':'test-csrf',**(data or {})},base_url='https://sso.syntal.pro',**kwargs)


def issue(env,client=None,scope='openid email profile organization permissions offline_access'):
    app,d,u,o,m,c=env
    client=client or client_for(env)
    from syntal_sso.oidc import _issue_from_doc
    with client.session_transaction(base_url='https://sso.syntal.pro') as s:values=dict(s)
    with app.test_request_context('/'):
        return _issue_from_doc({'syntal_user_id':'u','syntal_org_id':'o','scope':scope,'sid':values['auth_session_id'],'session_epoch':0,'auth_time':values['auth_time'],'acr':values['acr'],'amr':values['amr']},d.applications.find_one({'client_id':'x'}))
