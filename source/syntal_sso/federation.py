import base64,hashlib,secrets,zlib
from urllib.parse import urlencode,urlparse
from datetime import datetime,timezone,timedelta
import jwt,requests
from flask import Blueprint,abort,current_app,g,redirect,render_template,request,session,url_for
from jwt import PyJWKClient
from lxml import etree
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from .db import db
from .security import login_required
from .acl import audit,require_permission
from .lifecycle import require_recent,serialize_org
from .crypto_store import seal,open_sealed
from .util import public_id,utcnow

bp=Blueprint('federation',__name__)
DS='http://www.w3.org/2000/09/xmldsig#';SAML='urn:oasis:names:tc:SAML:2.0:assertion';SAMLP='urn:oasis:names:tc:SAML:2.0:protocol'

def _hash(v):return hashlib.sha256(v.encode()).hexdigest()
def _https(value):
    p=urlparse(value or '');return p.scheme=='https' and bool(p.netloc) and not p.username and not p.password

def _provider(org_id,pid):return db().federation_providers.find_one({'syntal_org_id':org_id,'provider_id':pid,'status':'active'})

def _transaction(provider,next_url=None,request_id=None):
    raw=secrets.token_urlsafe(32);nonce=secrets.token_urlsafe(32);browser=secrets.token_urlsafe(32);session['federation_browser_proof']=browser
    db().federation_transactions.insert_one({'transaction_id':public_id('fedtx'),'provider_id':provider['provider_id'],'syntal_org_id':provider['syntal_org_id'],'state_hash':_hash(raw),'nonce_hash':_hash(nonce),'browser_hash':_hash(browser),'request_id':request_id,'next_url':next_url if isinstance(next_url,str) and next_url.startswith('/') else '/','used_at':None,'expire_at':utcnow()+timedelta(minutes=10),'created_at':utcnow()});return raw,nonce

def _consume(state):
    from pymongo import ReturnDocument
    row=db().federation_transactions.find_one_and_update({'state_hash':_hash(state or ''),'used_at':None,'expire_at':{'$gt':utcnow()}},{'$set':{'used_at':utcnow()}},return_document=ReturnDocument.AFTER)
    if not row:return None
    if _hash(session.get('federation_browser_proof',''))!=row.get('browser_hash'):return None
    return row

def _link_or_provision(provider,claims):
    subject=str(claims.get('sub') or '');email=(claims.get('email') or '').strip().lower();verified=claims.get('email_verified') is True
    if not subject:abort(400,'Federation subject missing')
    link=db().federated_identities.find_one({'provider_id':provider['provider_id'],'subject':subject})
    if link:return db().users.find_one({'syntal_user_id':link['syntal_user_id'],'status':'active'})
    if not email or not verified:abort(403,'Verified email is required for first federation sign-in')
    existing=db().users.find_one({'email':email,'status':{'$ne':'deleted'}});current=getattr(g,'user',None)
    if existing:
        if (current or {}).get('syntal_user_id')!=existing.get('syntal_user_id'):abort(409,'Existing account requires proof-based linking from an authenticated session')
        user=existing
    else:
        uid=public_id('usr');user={'syntal_user_id':uid,'user_id':uid,'email':email,'name':claims.get('name') or email,'status':'active','email_verified':True,'verified':True,'federated_only':True,'registration_source':'federation','created_at':utcnow(),'session_epoch':0};db().users.insert_one(user)
    db().federated_identities.insert_one({'federated_identity_id':public_id('fid'),'provider_id':provider['provider_id'],'syntal_org_id':provider['syntal_org_id'],'syntal_user_id':user['syntal_user_id'],'subject':subject,'email_at_link':email,'created_at':utcnow()})
    if not db().memberships.find_one({'syntal_org_id':provider['syntal_org_id'],'syntal_user_id':user['syntal_user_id']}):
        role=db().organization_roles.find_one({'syntal_org_id':provider['syntal_org_id'],'key':'member','status':'active'}) or db().organization_roles.find_one({'syntal_org_id':provider['syntal_org_id'],'key':{'$ne':'owner'},'status':'active'})
        db().memberships.insert_one({'membership_id':public_id('mem'),'syntal_org_id':provider['syntal_org_id'],'syntal_user_id':user['syntal_user_id'],'role_id':(role or {}).get('role_id'),'role':(role or {}).get('key','member'),'status':'active','created_at':utcnow(),'provisioned_by':'federation'})
    audit('federation.identity_linked',org_id=provider['syntal_org_id'],user_id=user['syntal_user_id'],detail={'provider_id':provider['provider_id']});return user

def _saml_time(value):
    if not value:return None
    return datetime.fromisoformat(value.replace('Z','+00:00')).astimezone(timezone.utc)

def _verify_xml_signature(root,cert_pem):
    sig=root.find('.//{%s}Signature'%DS)
    if sig is None:raise ValueError('Signed SAML response/assertion required')
    signed_info=sig.find('{%s}SignedInfo'%DS);sig_value=sig.findtext('{%s}SignatureValue'%DS)
    method=signed_info.find('{%s}SignatureMethod'%DS).get('Algorithm','') if signed_info is not None else ''
    if method not in {'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256','http://www.w3.org/2001/04/xmldsig-more#rsa-sha384'}:raise ValueError('Unsupported SAML signature algorithm')
    refs=signed_info.findall('{%s}Reference'%DS)
    if len(refs)!=1:raise ValueError('Exactly one SAML signature reference is required')
    uri=refs[0].get('URI','');
    if not uri.startswith('#'):raise ValueError('SAML signature reference must be same-document')
    target_id=uri[1:];targets=root.xpath('//*[@ID=$id]',id=target_id)
    if len(targets)!=1:raise ValueError('Ambiguous SAML signed element')
    target=targets[0]
    clone=etree.fromstring(etree.tostring(target));nested=clone.find('.//{%s}Signature'%DS)
    if nested is not None:nested.getparent().remove(nested)
    digest_method=refs[0].find('{%s}DigestMethod'%DS).get('Algorithm','');digest_value=refs[0].findtext('{%s}DigestValue'%DS)
    if digest_method!='http://www.w3.org/2001/04/xmlenc#sha256':raise ValueError('Unsupported SAML digest algorithm')
    canonical=etree.tostring(clone,method='c14n',exclusive=True,with_comments=False);actual=base64.b64encode(hashlib.sha256(canonical).digest()).decode()
    if not secrets.compare_digest(actual,digest_value or ''):raise ValueError('SAML digest mismatch')
    cert=x509.load_pem_x509_certificate(cert_pem.encode());signed_c14n=etree.tostring(signed_info,method='c14n',exclusive=True,with_comments=False);sig_bytes=base64.b64decode(sig_value)
    digest=hashes.SHA256() if method.endswith('sha256') else hashes.SHA384();cert.public_key().verify(sig_bytes,signed_c14n,padding.PKCS1v15(),digest)
    return target

def _saml_claims(provider,encoded,tx):
    raw=base64.b64decode(encoded,validate=True)
    if len(raw)>1024*1024:raise ValueError('SAML response too large')
    parser=etree.XMLParser(resolve_entities=False,no_network=True,remove_comments=True,huge_tree=False);root=etree.fromstring(raw,parser)
    if root.tag!='{%s}Response'%SAMLP:raise ValueError('Expected SAML Response')
    if root.get('InResponseTo')!=tx.get('request_id'):raise ValueError('SAML InResponseTo mismatch')
    cert_pem=open_sealed(provider['saml_certificate_sealed'],'saml-cert:'+provider['provider_id']).decode();signed=_verify_xml_signature(root,cert_pem)
    assertion=root.find('{%s}Assertion'%SAML)
    if assertion is None:raise ValueError('SAML Assertion missing')
    # Require the signature to cover the Response or this exact Assertion.
    if signed is not root and signed is not assertion and signed.get('ID')!=assertion.get('ID'):raise ValueError('SAML assertion is not signed')
    now=utcnow();conditions=assertion.find('{%s}Conditions'%SAML)
    if conditions is not None:
        nb=_saml_time(conditions.get('NotBefore'));na=_saml_time(conditions.get('NotOnOrAfter'))
        if nb and now<nb-timedelta(minutes=2):raise ValueError('SAML assertion not yet valid')
        if na and now>=na+timedelta(minutes=2):raise ValueError('SAML assertion expired')
        audiences=[x.text for x in conditions.findall('.//{%s}Audience'%SAML) if x.text]
        if provider.get('sp_entity_id') not in audiences:raise ValueError('SAML audience mismatch')
    subject=assertion.findtext('.//{%s}NameID'%SAML)
    attrs={}
    for a in assertion.findall('.//{%s}Attribute'%SAML):
        vals=[v.text for v in a.findall('{%s}AttributeValue'%SAML) if v.text];attrs[a.get('Name')]=vals[0] if vals else None
    email=(attrs.get('email') or attrs.get('mail') or attrs.get('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress') or subject or '').strip().lower()
    return {'sub':subject,'email':email,'email_verified':True,'name':attrs.get('displayName') or attrs.get('name') or email}

@bp.route('/organizations/<org_id>/enterprise/federation',methods=['GET','POST'])
@login_required
@serialize_org
def manage(org_id):
    if not g.organization or g.organization.get('syntal_org_id')!=org_id:abort(404)
    require_permission('syntal.federation.manage')
    if request.method=='POST':
        require_recent(strong=True);ptype=(request.form.get('type') or 'oidc').lower();name=(request.form.get('name') or '').strip();pid=public_id('idp')
        if ptype=='oidc':
            issuer=(request.form.get('issuer') or '').rstrip('/');client_id=(request.form.get('client_id') or '').strip();ae=(request.form.get('authorization_endpoint') or '').strip();te=(request.form.get('token_endpoint') or '').strip();jwks=(request.form.get('jwks_uri') or '').strip()
            if not name or not client_id or not all(_https(x) for x in [issuer,ae,te,jwks]):abort(400,'Federation endpoints must be HTTPS')
            secret=request.form.get('client_secret') or '';doc={'provider_id':pid,'syntal_org_id':org_id,'type':'oidc','name':name,'issuer':issuer,'client_id':client_id,'client_secret_sealed':seal(secret,'oidc-idp-secret:'+pid),'authorization_endpoint':ae,'token_endpoint':te,'jwks_uri':jwks,'scopes':['openid','profile','email'],'status':'active','created_at':utcnow(),'created_by':g.user.get('syntal_user_id')}
        elif ptype=='saml':
            sso=(request.form.get('sso_url') or '').strip();entity=(request.form.get('idp_entity_id') or '').strip();sp=(request.form.get('sp_entity_id') or (current_app.config['PUBLIC_BASE_URL'].rstrip('/')+'/saml/'+org_id)).strip();cert=(request.form.get('x509_certificate') or '').strip()
            if not name or not entity or not _https(sso) or 'BEGIN CERTIFICATE' not in cert:abort(400,'Valid SAML SSO URL and X.509 certificate are required')
            x509.load_pem_x509_certificate(cert.encode());doc={'provider_id':pid,'syntal_org_id':org_id,'type':'saml','name':name,'idp_entity_id':entity,'sso_url':sso,'sp_entity_id':sp,'saml_certificate_sealed':seal(cert,'saml-cert:'+pid),'status':'active','created_at':utcnow(),'created_by':g.user.get('syntal_user_id')}
        else:abort(400,'Unsupported federation type')
        db().federation_providers.insert_one(doc);audit('federation.provider_created',org_id=org_id,detail={'provider_id':pid,'type':ptype})
    rows=list(db().federation_providers.find({'syntal_org_id':org_id},{'client_secret_sealed':0,'saml_certificate_sealed':0}).sort('created_at',-1));return render_template('enterprise/federation.html',title='Federation',organization=g.organization,providers=rows)

@bp.get('/federation/<org_id>/<pid>/login')
def login(org_id,pid):
    provider=_provider(org_id,pid)
    if not provider:abort(404)
    if provider.get('type')=='oidc':
        state,nonce=_transaction(provider,request.args.get('next'));callback=current_app.config['PUBLIC_BASE_URL'].rstrip('/')+url_for('federation.callback',org_id=org_id,pid=pid)
        q={'client_id':provider['client_id'],'redirect_uri':callback,'response_type':'code','scope':' '.join(provider.get('scopes') or ['openid','profile','email']),'state':state,'nonce':nonce};return redirect(provider['authorization_endpoint']+'?'+urlencode(q))
    if provider.get('type')=='saml':
        rid='_'+public_id('saml').replace('-','_');state,_=_transaction(provider,request.args.get('next'),rid);acs=current_app.config['PUBLIC_BASE_URL'].rstrip('/')+url_for('federation.saml_acs',org_id=org_id,pid=pid)
        instant=utcnow().strftime('%Y-%m-%dT%H:%M:%SZ');xml=f'<samlp:AuthnRequest xmlns:samlp="{SAMLP}" ID="{rid}" Version="2.0" IssueInstant="{instant}" Destination="{provider["sso_url"]}" AssertionConsumerServiceURL="{acs}"><saml:Issuer xmlns:saml="{SAML}">{provider["sp_entity_id"]}</saml:Issuer></samlp:AuthnRequest>'
        compressor=zlib.compressobj(wbits=-15);encoded=base64.b64encode(compressor.compress(xml.encode())+compressor.flush()).decode();return redirect(provider['sso_url']+'?'+urlencode({'SAMLRequest':encoded,'RelayState':state}))
    abort(400)

@bp.get('/federation/<org_id>/<pid>/callback')
def callback(org_id,pid):
    provider=_provider(org_id,pid);tx=_consume(request.args.get('state'))
    if not provider or provider.get('type')!='oidc' or not tx or tx.get('provider_id')!=pid:abort(400,'Invalid or replayed federation transaction')
    code=request.args.get('code')
    if not code:abort(400,'Federation authorization code missing')
    callback=current_app.config['PUBLIC_BASE_URL'].rstrip('/')+url_for('federation.callback',org_id=org_id,pid=pid);secret=open_sealed(provider['client_secret_sealed'],'oidc-idp-secret:'+pid).decode()
    r=requests.post(provider['token_endpoint'],data={'grant_type':'authorization_code','code':code,'redirect_uri':callback,'client_id':provider['client_id'],'client_secret':secret},timeout=8);r.raise_for_status();id_token=r.json().get('id_token')
    if not id_token:abort(400,'Federation ID token missing')
    key=PyJWKClient(provider['jwks_uri'],cache_keys=True).get_signing_key_from_jwt(id_token).key;claims=jwt.decode(id_token,key,algorithms=['RS256','ES256'],audience=provider['client_id'],issuer=provider['issuer'],options={'require':['iss','sub','aud','exp','iat','nonce']})
    if _hash(str(claims.get('nonce') or ''))!=tx.get('nonce_hash'):abort(400,'Federation nonce mismatch')
    return _finish(provider,tx,claims)

@bp.post('/federation/<org_id>/<pid>/saml/acs')
def saml_acs(org_id,pid):
    provider=_provider(org_id,pid);tx=_consume(request.form.get('RelayState'))
    if not provider or provider.get('type')!='saml' or not tx or tx.get('provider_id')!=pid:abort(400,'Invalid or replayed federation transaction')
    try:claims=_saml_claims(provider,request.form.get('SAMLResponse') or '',tx)
    except Exception as exc:abort(400,'Invalid signed SAML response: '+str(exc))
    return _finish(provider,tx,claims)

def _finish(provider,tx,claims):
    user=_link_or_provision(provider,claims);from .auth import _login_session
    _login_session(user,method='federation',aal2=False);session['org_id']=provider['syntal_org_id'];session.pop('federation_browser_proof',None);audit('federation.login',org_id=provider['syntal_org_id'],user_id=user['syntal_user_id'],detail={'provider_id':provider['provider_id'],'type':provider['type']});return redirect(tx.get('next_url') or '/')
