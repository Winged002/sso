import base64, hashlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Blueprint, abort, g, jsonify, redirect, render_template, request, url_for
from .db import db
from .security import login_required
from .acl import audit, has_permission, require_permission
from .lifecycle import require_recent, serialize_org
from .crypto_store import seal, open_sealed
from .util import public_id, utcnow

bp=Blueprint('signing_keys',__name__)


def _b64(data): return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def public_jwk(row):
    pem=(row.get('public_pem') or '').encode(); public=serialization.load_pem_public_key(pem).public_numbers()
    n=public.n.to_bytes((public.n.bit_length()+7)//8,'big'); e=public.e.to_bytes((public.e.bit_length()+7)//8,'big')
    return {'kty':'RSA','use':'sig','alg':'RS256','kid':row['kid'],'n':_b64(n),'e':_b64(e)}

def active_key(database=None):
    database=database or db(); now=utcnow()
    return database.signing_keys.find_one({'purpose':'oidc','status':'active','$or':[{'not_before':{'$exists':False}},{'not_before':{'$lte':now}}]},sort=[('created_at',-1)])

def private_pem(row): return open_sealed(row['private_key_sealed'],'signing-key:'+row['kid']).decode()

def generate_key(database=None, *, activate=True, created_by=None):
    database=database or db(); now=utcnow(); kid=public_id('key')
    key=rsa.generate_private_key(public_exponent=65537,key_size=3072)
    private=key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()).decode()
    public=key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    fingerprint=hashlib.sha256(public.encode()).hexdigest()
    if activate:
        existing_active=database.signing_keys.find_one({'purpose':'oidc','status':'active'})
        if not existing_active:
            try:
                from flask import current_app
                bootstrap=current_app.config.get('OIDC_PRIVATE_KEY') or ''
                if bootstrap and 'BEGIN' in bootstrap:
                    bkey=serialization.load_pem_private_key(bootstrap.encode(),password=None)
                    bpub=bkey.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo).decode()
                    bkid=current_app.config.get('OIDC_KEY_ID') or 'syntal-bootstrap'
                    if not database.signing_keys.find_one({'kid':bkid}):
                        database.signing_keys.insert_one({'kid':bkid,'purpose':'oidc','algorithm':'RS256','status':'retiring','public_pem':bpub,'fingerprint_sha256':hashlib.sha256(bpub.encode()).hexdigest(),'created_at':now,'retiring_at':now,'imported_from':'bootstrap'})
            except Exception:
                pass
        database.signing_keys.update_many({'purpose':'oidc','status':'active'},{'$set':{'status':'retiring','retiring_at':now,'updated_at':now}})
    row={'kid':kid,'purpose':'oidc','algorithm':'RS256','status':'active' if activate else 'staged','private_key_sealed':seal(private,'signing-key:'+kid),'public_pem':public,'fingerprint_sha256':fingerprint,'created_at':now,'created_by':created_by}
    database.signing_keys.insert_one(row); return row

def jwks(database=None):
    database=database or db(); rows=database.signing_keys.find({'purpose':'oidc','status':{'$in':['active','retiring']}})
    return {'keys':[public_jwk(x) for x in rows]}

def resolve_public_key(kid,database=None):
    database=database or db(); row=database.signing_keys.find_one({'purpose':'oidc','kid':kid,'status':{'$in':['active','retiring']}})
    return (row.get('public_pem') if row else None)

@bp.route('/organizations/<org_id>/enterprise/signing-keys',methods=['GET','POST'])
@login_required
@serialize_org
def manage(org_id):
    if not g.organization or g.organization.get('syntal_org_id')!=org_id: abort(404)
    require_permission('syntal.security.manage')
    if request.method=='POST':
        require_recent(strong=True)
        row=generate_key(created_by=g.user.get('syntal_user_id')); audit('security.signing_key_rotated',org_id=org_id,detail={'kid':row['kid']})
        return redirect(url_for('signing_keys.manage',org_id=org_id))
    rows=list(db().signing_keys.find({'purpose':'oidc'},{'private_key_sealed':0}).sort('created_at',-1))
    return render_template('enterprise/signing_keys.html',title='Signing keys',organization=g.organization,keys=rows)

@bp.post('/organizations/<org_id>/enterprise/signing-keys/<kid>/retire')
@login_required
@serialize_org
def retire(org_id,kid):
    if not g.organization or g.organization.get('syntal_org_id')!=org_id: abort(404)
    require_permission('syntal.security.manage'); require_recent(strong=True)
    row=db().signing_keys.find_one({'kid':kid,'purpose':'oidc'})
    if not row: abort(404)
    if row.get('status')=='active': abort(409,'Rotate to a replacement key before retiring the active key.')
    db().signing_keys.update_one({'_id':row['_id']},{'$set':{'status':'retired','retired_at':utcnow()}});audit('security.signing_key_retired',org_id=org_id,detail={'kid':kid})
    return redirect(url_for('signing_keys.manage',org_id=org_id))
