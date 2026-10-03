from datetime import timedelta
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit,parse_qs,urlencode
from types import SimpleNamespace
import hashlib,base64,time
import pytest,jwt
from flask import session,g
from conftest import client_for,get,post,issue,PASSWORD
from syntal_sso import policy,oidc,acl,auth,mfa,passkeys
from syntal_sso.util import utcnow
from syntal_sso.schema import inspect_database,migrate


def auth_url(**extra):
    verifier='v'*43;challenge=base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
    return '/oauth/authorize?'+urlencode({'client_id':'x','redirect_uri':'https://client.example.test/cb','response_type':'code','scope':'openid organization offline_access','code_challenge':challenge,'code_challenge_method':'S256',**extra})


@pytest.mark.parametrize('collection,query,changes,reason',[
 ('users',{'syntal_user_id':'u'},{'status':'suspended'},'account_not_active'),
 ('users',{'syntal_user_id':'u'},{'email_verified':False},'email_not_verified'),
 ('organizations',{'syntal_org_id':'o'},{'status':'suspended'},'organization_not_active'),
 ('memberships',{'membership_id':'m'},{'status':'suspended'},'membership_not_active'),
 ('applications',{'client_id':'x'},{'status':'suspended'},'application_not_active'),
 ('applications',{'client_id':'x'},{'owner_type':'organization','owner_org_id':'other','distribution_scope':'private'},'application_not_visible'),
 ('organization_entitlements',{'application':'x'},{'status':'inactive'},'product_not_entitled'),
 ('organization_entitlements',{'application':'x'},{'status':'active','valid_until':utcnow()-timedelta(seconds=1)},'product_not_entitled'),
])
def test_shared_policy_rejects_inactive_states(env,collection,query,changes,reason):
 app,d,*_=env;d[collection].update_one(query,{'$set':changes})
 with app.test_request_context('/'):
  decision=policy.resolve_access('u','o','x');assert not decision['allowed'];assert reason in decision['reasons']


def test_shared_policy_grants_owner_and_concrete_token_permissions(env):
 token=issue(env);claims=jwt.decode(token['access_token'],options={'verify_signature':False})
 assert 'x.access' in claims['permissions'] and 'x.admin' in claims['permissions'] and '*' not in claims['permissions']


@pytest.mark.parametrize('path,data',[
 ('/organizations/o/people/m/role',{'role_id':'r-owner'}),
 ('/organizations/o/access/roles',{'name':'Fake owner','key':'owner','permissions':'*'}),
 ('/organizations/o/access/roles/r-admin',{'name':'Admin','permissions':'*'}),
 ('/organizations/o/invitations',{'email':'new@example.test','role_id':'r-owner'}),
])
def test_admin_cannot_obtain_or_grant_ownership(env,path,data):
 client=client_for(env,'admin');r=post(client,path,data);assert r.status_code in (403,409)
 assert env[1].memberships.find_one({'membership_id':'m'})['role']=='admin'


@pytest.mark.parametrize('permission',['*','syntal.admin','syntal.organization.manage','other.access'])
def test_app_role_rejects_foreign_permissions(env,permission):
 r=post(client_for(env,'admin'),'/organizations/o/applications/x/roles',{'name':'Escalation','permissions':permission})
 assert r.status_code==400


def test_member_app_role_is_bound_to_application(env):
 app,d,*_=env;d.organization_application_roles.insert_one({'syntal_org_id':'o','client_id':'other','app_role_id':'foreign','status':'active','permissions':['other.admin']})
 r=post(client_for(env),'/organizations/o/applications/x/members',{'membership_id':'m','app_role_id':'foreign'})
 # Owners are protected; use admin target to test foreign app-role validation.
 client=client_for(env,'admin');r=post(client,'/organizations/o/applications/x/members',{'membership_id':'m','app_role_id':'foreign'});assert r.status_code==400


def test_deny_wins_over_wildcard_and_foreign_role(env):
 app,d,u,o,m,c=env;client=client_for(env,'admin')
 d.organization_roles.update_one({'role_id':'r-admin'},{'$set':{'permissions':['*']}})
 d.organization_application_roles.insert_one({'syntal_org_id':'o','client_id':'y','app_role_id':'ar','status':'active','permissions':['x.access','*']})
 d.organization_application_memberships.insert_many([{'syntal_org_id':'o','membership_id':'m','client_id':'x','status':'active','access_effect':'deny'},{'syntal_org_id':'o','membership_id':'m','client_id':'y','status':'active','app_role_id':'ar'}])
 with app.test_request_context('/'):
  membership=d.memberships.find_one({'membership_id':'m'});decision=policy.access_decision(u,o,membership,c)
  assert not decision['allowed'];assert 'member_application_denied' in decision['reasons'];assert 'x.access' not in acl.effective_permissions_for_membership('o',membership)
  assert not oidc._eligible_orgs(u,c)
  from syntal_sso.access import _matrix_cell
  assert not _matrix_cell('o',membership,c,{'status':'active'},None,{})['allowed']


def test_enabling_does_not_replace_deny(env):
 app,d,*_=env;client=client_for(env,'admin');d.organization_application_memberships.insert_one({'syntal_org_id':'o','membership_id':'m','client_id':'x','status':'active','access_effect':'deny'})
 assert post(client,'/organizations/o/applications/x/enable').status_code==302
 assert d.organization_application_memberships.find_one({'membership_id':'m'})['access_effect']=='deny'


@pytest.mark.parametrize('changes',[{'status':'suspended'},{'session_epoch':9},{'email_verified':False}])
def test_existing_browser_session_rejected_after_account_change(env,changes):
 client=client_for(env);env[1].users.update_one({'syntal_user_id':'u'},{'$set':changes});assert get(client,'/account').location.startswith('/login')


def test_session_revoke_is_owned_and_effective(env):
 client=client_for(env);tokens=issue(env,client)
 with client.session_transaction(base_url='https://sso.syntal.pro') as s:sid=s['auth_session_id']
 assert post(client,'/account/sessions/missing/revoke').status_code==404
 assert post(client,'/account/sessions/'+sid+'/revoke').status_code==302
 assert get(client,'/v1/organizations/o/members',headers={'Authorization':'Bearer '+tokens['access_token']}).status_code==401


def test_real_login_rotates_backend_session_id(env):
 app,d,*_=env;client=app.test_client();get(client,'/login')
 with client.session_transaction(base_url='https://sso.syntal.pro') as s:csrf=s['csrf_token'];before=s.sid
 r=client.post('/login',data={'csrf_token':csrf,'email':'user@example.test','password':PASSWORD},base_url='https://sso.syntal.pro')
 assert r.status_code==302
 with client.session_transaction(base_url='https://sso.syntal.pro') as s:assert s.sid!=before;assert s['auth_session_id']


def test_totp_replacement_requires_existing_factor(env):
 client=client_for(env);env[1].users.update_one({'syntal_user_id':'u'},{'$set':{'mfa':{'totp_enabled':True,'totp_secret':'JBSWY3DPEHPK3PXP'}}})
 assert '/security/re-auth' in post(client,'/account/mfa/totp/begin').location
 with client.session_transaction(base_url='https://sso.syntal.pro') as s:assert not s.get('totp_setup_secret')


def test_totp_code_is_single_use(env):
 app,d,u,*_=env;u['mfa']={'totp_enabled':True,'totp_secret':'JBSWY3DPEHPK3PXP'};code=mfa.totp_at(u['mfa']['totp_secret'])
 with app.app_context():assert mfa.verify_totp_once(u,code);assert not mfa.verify_totp_once(u,code)


def test_passkey_verifier_requires_user_verification(env,monkeypatch):
 app,d,u,*_=env;d.webauthn_credentials.insert_one({'syntal_user_id':'u','credential_id':b'abc','public_key':b'fake','sign_count':0})
 seen={}
 def verify(**kwargs):seen.update(kwargs);return SimpleNamespace(new_sign_count=1)
 monkeypatch.setattr('webauthn.verify_authentication_response',verify)
 with app.app_context():passkeys.verify_authentication(u,{'rawId':'YWJj'},b'challenge')
 assert seen['require_user_verification'] is True


def test_expired_preauth_cannot_complete(env):
 client=env[0].test_client()
 with client.session_transaction(base_url='https://sso.syntal.pro') as s:s.update(preauth_user_id='u',preauth_started_at=int(time.time())-600,csrf_token='test-csrf')
 assert post(client,'/mfa/verify',{'code':'123456'}).location=='/login'


def test_throttling_shared_counter(env):
 from syntal_sso.lifecycle import throttle
 from werkzeug.exceptions import TooManyRequests
 with env[0].test_request_context('/'):
  throttle('audit-test','u',1,300)
  with pytest.raises(TooManyRequests):throttle('audit-test','u',1,300)


def test_signup_is_unverified_and_email_token_is_single_use(env,monkeypatch):
 app,d,*_=env;sent=[]
 monkeypatch.setattr('syntal_sso.mailer.send_transactional_email',lambda **kw:sent.append(kw) or {'ok':True})
 client=app.test_client();get(client,'/register')
 with client.session_transaction(base_url='https://sso.syntal.pro') as s:csrf=s['csrf_token']
 r=client.post('/register',data={'csrf_token':csrf,'email':'new@example.test','name':'New Person','organization_name':'New Organization','password':PASSWORD,'confirm_password':PASSWORD},base_url='https://sso.syntal.pro')
 assert r.location=='/verify-email';user=d.users.find_one({'email':'new@example.test'});assert user['email_verified'] is False
 token=parse_qs(urlsplit(sent[0]['text_body'].split()[-1]).query)['token'][0]
 r=client.post('/verify-email',data={'csrf_token':csrf,'token':token},base_url='https://sso.syntal.pro');assert r.location=='/login';assert d.users.find_one({'_id':user['_id']})['email_verified'] is True
 assert client.post('/verify-email',data={'csrf_token':csrf,'token':token},base_url='https://sso.syntal.pro').status_code==400


def test_self_ownership_transfer_is_rejected(env):
 assert post(client_for(env),'/organizations/o/ownership',{'membership_id':'m'}).status_code==400
 assert env[1].memberships.find_one({'membership_id':'m'})['role']=='owner'


def test_stale_invitation_cannot_reactivate_membership(env):
 app,d,*_=env;client=client_for(env)
 d.organization_invitations.insert_one({'invitation_id':'inv','syntal_org_id':'o','email':'user@example.test','role_id':'r-admin','status':'pending','expire_at':utcnow()+timedelta(days=1)})
 d.memberships.update_one({'membership_id':'m'},{'$set':{'status':'suspended'}})
 assert post(client,'/invitations/inv/accept').status_code==409
 assert d.memberships.find_one({'membership_id':'m'})['status']=='suspended'


@pytest.mark.parametrize('token_name',['id_token','access_token'])
def test_directory_token_type_and_scope(env,token_name):
 client=client_for(env);tokens=issue(env,client,scope='openid')
 assert get(client,'/v1/organizations/o/members',headers={'Authorization':'Bearer '+tokens[token_name]}).status_code==401


def test_directory_tenant_boundary_and_access_api_csrf(env):
 client=client_for(env);tokens=issue(env,client);headers={'Authorization':'Bearer '+tokens['access_token']}
 assert get(client,'/v1/organizations/o/members',headers=headers).status_code==200
 assert get(client,'/v1/organizations/other/members',headers=headers).status_code==403
 r=client.post('/v1/access/check',json={'organization_id':'o','application':'x','permission':'x.access'},headers=headers,base_url='https://sso.syntal.pro');assert r.status_code==200 and r.json['allowed']
 r=client.post('/v1/access/check',json={'organization_id':'o','application':'other','permission':'x.access'},headers=headers,base_url='https://sso.syntal.pro');assert r.status_code==403


def test_pkce_required_and_wrong_verifier_does_not_consume_code(env):
 client=client_for(env)
 assert 'error=invalid_request' in get(client,auth_url(code_challenge='')).location
 response=get(client,auth_url());code=parse_qs(urlsplit(response.location).query)['code'][0]
 def exchange(verifier):return client.post('/oauth/token',data={'grant_type':'authorization_code','client_id':'x','code':code,'redirect_uri':'https://client.example.test/cb','code_verifier':verifier},base_url='https://sso.syntal.pro')
 assert exchange('wrong'*10).status_code==400;assert exchange('v'*43).status_code==200;assert exchange('v'*43).status_code==400


def refresh(client,value):return client.post('/oauth/token',data={'client_id':'x','grant_type':'refresh_token','refresh_token':value},base_url='https://sso.syntal.pro')


@pytest.mark.parametrize('change',['entitlement','deny','private','mfa','membership','organization'])
def test_refresh_rechecks_current_access(env,change):
 app,d,*_=env;client=client_for(env,'admin');tokens=issue(env,client)
 if change=='entitlement':d.organization_entitlements.update_one({'application':'x'},{'$set':{'status':'inactive'}})
 if change=='deny':d.organization_application_memberships.insert_one({'syntal_org_id':'o','membership_id':'m','client_id':'x','status':'active','access_effect':'deny'})
 if change=='private':d.applications.update_one({'client_id':'x'},{'$set':{'owner_type':'organization','owner_org_id':'other','distribution_scope':'private'}})
 if change=='mfa':d.applications.update_one({'client_id':'x'},{'$set':{'require_aal2':True}})
 if change=='membership':d.memberships.update_one({'membership_id':'m'},{'$set':{'status':'suspended'}})
 if change=='organization':d.organizations.update_one({'syntal_org_id':'o'},{'$set':{'status':'suspended'}})
 assert refresh(client,tokens['refresh_token']).status_code==400


def test_refresh_reuse_revokes_successor(env):
 client=client_for(env);original=issue(env,client);successor=refresh(client,original['refresh_token']).json
 assert successor['refresh_token']!=original['refresh_token'];assert refresh(client,original['refresh_token']).status_code==400
 assert refresh(client,successor['refresh_token']).status_code==400


def test_concurrent_refresh_never_creates_two_successors(env):
 app,d,*_=env;original=issue(env)
 def worker(_):return refresh(app.test_client(),original['refresh_token'])
 with ThreadPoolExecutor(max_workers=2) as pool:responses=list(pool.map(worker,range(2)))
 assert sum(r.status_code==200 for r in responses)<=1
 assert sum(r.status_code==400 for r in responses)>=1
 # A detected race/reuse fails closed by revoking the family, including any winner.
 assert d.oidc_token_families.find_one({})['revoked_at'] is not None


def test_introspection_checks_expiry_and_client(env):
 app,d,*_=env;client=client_for(env);original=issue(env,client)
 d.applications.update_one({'client_id':'x'},{'$set':{'client_type':'confidential','client_secret_hash':hashlib.sha256(b'secret').hexdigest()}})
 d.oidc_refresh_tokens.update_one({'token_hash':oidc._hash(original['refresh_token'])},{'$set':{'expire_at':utcnow()-timedelta(seconds=1)}})
 r=client.post('/oauth/introspect',data={'client_id':'x','client_secret':'secret','token':original['refresh_token']},base_url='https://sso.syntal.pro');assert r.status_code==200 and not r.json['active']


def test_logout_redirect_and_get_confirmation(env):
 client=client_for(env);assert get(client,'/oauth/logout?post_logout_redirect_uri=https://outside.example.test').status_code==400
 assert get(client,'/oauth/logout').status_code==200
 assert get(client,'/account').status_code==200


def test_oidc_silent_and_forced_login(env):
 assert 'error=login_required' in get(env[0].test_client(),auth_url(prompt='none')).location
 client=client_for(env);assert '/security/re-auth' in get(client,auth_url(prompt='login')).location


def test_id_token_scope_privacy_and_independent_ttl(env):
 env[0].config['ID_TOKEN_TTL']=120;token=issue(env,scope='openid')
 claims=jwt.decode(token['id_token'],options={'verify_signature':False});assert 'email' not in claims and 'name' not in claims;assert claims['exp']-claims['iat']==120


def test_unsigned_webhook_rejected(env):
 env[0].config['STRIPE_WEBHOOK_SECRET']='whsec-test'
 r=env[0].test_client().post('/stripe/webhook',json={'id':'evt_fake','type':'invoice.paid'},base_url='https://sso.syntal.pro')
 assert r.status_code==400 and env[1].stripe_events.count_documents({})==0


def test_signed_webhook_idempotency(env):
 import json,hmac
 app,d,*_=env;app.config['STRIPE_WEBHOOK_SECRET']='whsec-test';body=json.dumps({'id':'evt_real','type':'invoice.paid','object':'event'});timestamp=int(time.time());sig=hmac.new(b'whsec-test',f'{timestamp}.{body}'.encode(),hashlib.sha256).hexdigest()
 for _ in range(2):
  r=app.test_client().post('/stripe/webhook',data=body,headers={'Content-Type':'application/json','Stripe-Signature':f't={timestamp},v1={sig}'},base_url='https://sso.syntal.pro');assert r.status_code==200
 assert d.stripe_events.count_documents({})==1 and d.stripe_events.find_one({})['signature_verified']


def test_private_developer_catalog_and_audit_guards(env):
 client=client_for(env,'admin');d=env[1];d.applications.insert_one({'client_id':'private','name':'Hidden tenant app','owner_type':'organization','owner_org_id':'other','status':'active'})
 assert b'Hidden tenant app' not in get(client,'/developers').data
 assert get(client,'/organizations/o/access/audit').status_code==403


@pytest.mark.parametrize('path',['/','/account','/account/sessions','/security/re-auth','/organizations/o/access/matrix','/organizations/o/access/inspector?member=m&application=x','/organizations/o/applications/diagnostics','/organizations/o/applications/x/configuration'])
def test_new_and_existing_pages_render(env,path):
 r=get(client_for(env),path);assert r.status_code==200;assert r.headers['Cache-Control']=='no-store'


def test_configuration_fails_closed_without_signing_key(env):
 app=env[0];app.config.update(OIDC_PRIVATE_KEY='',OIDC_PRIVATE_KEY_FILE='',OIDC_HS256_SECRET='',OIDC_ALLOW_HS256=False)
 with app.app_context():
  with pytest.raises(RuntimeError):oidc._signing_material()


def test_legacy_id_aliases_and_migration_are_repeatable(env):
 d=env[1];d.organizations.create_index('org_id',unique=True)
 with env[0].test_request_context('/'):
  from syntal_sso.organizations import create_owned_organization
  org,_=create_owned_organization(env[2],'New organization');assert org['org_id']==org['syntal_org_id']
 first=d.users.find_one({'syntal_user_id':'u'})['session_epoch'];migrate(d);migrate(d)
 assert d.users.find_one({'syntal_user_id':'u'})['session_epoch']==first


def test_preflight_blocks_unknown_legacy_unique_fields(env):
 d=env[1];d.organizations.create_index('legacy_slug',unique=True)
 report=inspect_database(d);assert not report['ready'];assert any('legacy_slug' in x for x in report['blockers'])


def test_password_reset_requires_mfa_and_revokes_old_sessions(env,monkeypatch):
 app,d,*_=env;client=client_for(env);d.users.update_one({'syntal_user_id':'u'},{'$set':{'mfa':{'totp_enabled':True,'totp_secret':'JBSWY3DPEHPK3PXP'}}})
 raw='reset-token';d.account_action_tokens.insert_one({'token_hash':hashlib.sha256(raw.encode()).hexdigest(),'purpose':'password_reset','syntal_user_id':'u','session_epoch':0,'expire_at':utcnow()+timedelta(minutes=5),'used_at':None})
 r=post(client,'/reset-password',{'token':raw,'password':'new-password-33','confirm_password':'new-password-33'});assert r.status_code==200;assert b'required' in r.data
 r=post(client,'/reset-password',{'token':raw,'password':'new-password-33','confirm_password':'new-password-33','code':mfa.totp_at('JBSWY3DPEHPK3PXP')});assert r.status_code==302
 assert get(client,'/account').status_code==302


def test_forced_login_resumes_exact_authorization(env):
 client=client_for(env);r=get(client,auth_url(prompt='login'))
 target=parse_qs(urlsplit(r.location).query)['next'][0]
 r=post(client,'/security/re-auth',{'next':target,'password':PASSWORD});assert r.location==target
 r=get(client,target);assert r.location.startswith('https://client.example.test/cb?code=')
 assert '/security/re-auth' in get(client,target).location
 # The completed proof does not apply to a different OAuth request.
 assert '/security/re-auth' in get(client,auth_url(prompt='login',state='new-state')).location


def test_distributed_client_requires_remembered_consent(env):
 client=client_for(env);d=env[1]
 d.applications.update_one({'client_id':'x'},{'$set':{'owner_type':'organization','owner_org_id':'external','distribution_scope':'organizations'}})
 assert 'error=consent_required' in get(client,auth_url(prompt='none')).location
 r=get(client,auth_url());assert r.status_code==200 and b'Approve application access' in r.data
 fields={k:v[0] for k,v in parse_qs(urlsplit(auth_url()).query).items()}
 r=post(client,'/oauth/authorize',{**fields,'approve':'yes'});assert 'code=' in r.location
 assert 'code=' in get(client,auth_url(prompt='none')).location


def test_expired_passkey_challenge_never_calls_verifier(env,monkeypatch):
 client=env[0].test_client();called=[]
 monkeypatch.setattr(passkeys,'verify_authentication',lambda *a:called.append(a))
 with client.session_transaction(base_url='https://sso.syntal.pro') as s:s.update(passkey_login_user_id='u',passkey_login_challenge='YWJj',passkey_login_started_at=int(time.time())-600,csrf_token='test-csrf')
 r=client.post('/passkeys/login/verify',json={'csrf_token':'test-csrf','credential':{}},base_url='https://sso.syntal.pro');assert r.status_code==400;assert not called


def test_api_opt_out_revokes_existing_directory_token(env):
 client=client_for(env);token=issue(env,client)['access_token'];headers={'Authorization':'Bearer '+token}
 assert get(client,'/v1/organizations/o/members',headers=headers).status_code==200
 env[1].applications.update_one({'client_id':'x'},{'$set':{'api_access_enabled':False}})
 assert get(client,'/v1/organizations/o/members',headers=headers).status_code==401


def test_current_mfa_policy_rejects_old_access_token(env):
 client=client_for(env);token=issue(env,client)['access_token']
 env[1].applications.update_one({'client_id':'x'},{'$set':{'require_aal2':True}})
 assert get(client,'/oauth/userinfo',headers={'Authorization':'Bearer '+token}).status_code==401


def test_preflight_detects_planned_alias_collision(env):
 d=env[1];d.organizations.create_index('org_id',unique=True)
 d.organizations.update_one({'syntal_org_id':'o'},{'$unset':{'org_id':''}})
 d.organizations.insert_one({'syntal_org_id':'other','org_id':'o','status':'active'})
 assert any('alias backfill' in x for x in inspect_database(d)['blockers'])


def test_interrupted_registration_is_recoverable_and_idempotent(env,monkeypatch):
 app,d,*_=env
 from syntal_sso.organizations import create_owned_organization,complete_registration
 roles=d.organization_roles;collection_type=type(roles);original=collection_type.update_one
 def fail(self,*a,**kw):
  if self.name=='organization_roles':raise RuntimeError('injected storage failure')
  return original(self,*a,**kw)
 monkeypatch.setattr(collection_type,'update_one',fail)
 with app.test_request_context('/'):
  with pytest.raises(RuntimeError):create_owned_organization(env[2],'Recoverable organization')
  job=d.registration_jobs.find_one({'state':'pending'});assert job
  assert d.organizations.find_one({'syntal_org_id':job['organization']['syntal_org_id']})['status']=='provisioning'
  assert d.users.find_one({'syntal_user_id':'u'})
  monkeypatch.setattr(collection_type,'update_one',original)
  first=complete_registration(job['_id']);second=complete_registration(job['_id']);assert first==second
  assert d.organization_roles.count_documents({'syntal_org_id':first[0]['syntal_org_id']})==3
  assert d.memberships.count_documents({'syntal_org_id':first[0]['syntal_org_id']})==1
  assert d.registration_jobs.find_one({'_id':job['_id']})['state']=='complete'


def test_rs256_signing_and_type_validation(env):
 from cryptography.hazmat.primitives.asymmetric import rsa
 from cryptography.hazmat.primitives import serialization
 app=env[0];private=rsa.generate_private_key(public_exponent=65537,key_size=2048)
 app.config.update(OIDC_PRIVATE_KEY=private.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()).decode(),OIDC_ALLOW_HS256=False)
 tokens=issue(env)
 with app.app_context():
  assert oidc._decode(tokens['access_token'],audience='syntal-api')['token_use']=='access'
  assert oidc._decode(tokens['id_token'],audience='x')['token_use']=='id'
  with pytest.raises(jwt.InvalidAudienceError):oidc._decode(tokens['access_token'],audience='arbitrary')


def test_team_and_ownership_directory_require_read_authority(env):
 client=client_for(env,'admin');d=env[1]
 d.organization_roles.update_one({'role_id':'r-admin'},{'$set':{'permissions':['x.access']}})
 d.teams.insert_one({'syntal_org_id':'o','team_id':'t','name':'Team','status':'active'})
 assert get(client,'/organizations/o/teams/t').status_code==403
 assert get(client,'/organizations/o/ownership').status_code==403
 assert get(client,'/organizations/o/settings').status_code==403


@pytest.mark.parametrize('value',['https://evil.test','//evil.test','/\\evil.test','/%5cevil.test','/%2f%2fevil.test','/%0d%0aLocation:evil'])
def test_next_redirect_rejects_external_browser_normalization(value):
 from syntal_sso.util import safe_next
 assert safe_next(value) is None


def test_suspended_role_cannot_fall_back_to_owner(env):
 app,d,*_=env;d.organization_roles.update_one({'role_id':'r-owner'},{'$set':{'status':'suspended'}})
 with app.test_request_context('/'):
  assert not policy.resolve_access('u','o','x')['allowed']
  assert not acl.has_permission('syntal.organization.manage',d.memberships.find_one({'membership_id':'m'}),'o')
 assert not inspect_database(d)['ready']


def test_refresh_introspection_checks_new_mfa_requirement(env):
 app,d,*_=env;client=client_for(env);tokens=issue(env,client)
 d.applications.update_one({'client_id':'x'},{'$set':{'client_type':'confidential','client_secret_hash':hashlib.sha256(b'secret').hexdigest(),'token_endpoint_auth_method':'client_secret_post','require_aal2':True}})
 r=client.post('/oauth/introspect',data={'client_id':'x','client_secret':'secret','token':tokens['refresh_token']},base_url='https://sso.syntal.pro')
 assert r.status_code==200 and not r.json['active']


def test_concurrent_owner_demotions_keep_an_active_owner(env):
 app,d,*_=env
 d.users.insert_one({'syntal_user_id':'u2','user_id':'u2','email':'second@example.test','status':'active','email_verified':True})
 d.memberships.insert_one({'membership_id':'m2','syntal_user_id':'u2','syntal_org_id':'o','role':'owner','role_id':'r-owner','status':'active'})
 clients=[client_for(env),client_for(env)]
 def worker(i):return post(clients[i],'/organizations/o/people/'+['m','m2'][i]+'/role',{'role_id':'r-admin'}).status_code
 with ThreadPoolExecutor(max_workers=2) as pool:statuses=list(pool.map(worker,[0,1]))
 assert all(s in (302,403,409) for s in statuses)
 assert d.memberships.count_documents({'syntal_org_id':'o','status':'active','role':'owner'})>=1


def test_mutation_lock_rejects_contender_and_releases(env):
 from syntal_sso.lifecycle import mutation_lock
 from werkzeug.exceptions import Conflict
 with env[0].test_request_context('/'):
  with mutation_lock('test-resource'):
   with pytest.raises(Conflict):
    with mutation_lock('test-resource'):pytest.fail('contender entered')
  with mutation_lock('test-resource'):pass
