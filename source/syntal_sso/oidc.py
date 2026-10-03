from datetime import timedelta
from urllib.parse import urlencode
import base64, hashlib, hmac, json, os, secrets
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Blueprint, abort, current_app, g, jsonify, redirect, render_template, request, session, url_for
from .db import db
from .acl import (
    active_entitlement, application_access_override, audit, bump_policy_version,
    effective_permissions_for_membership, role_for_membership,
    application_distributable, application_owned_by_org,
    application_requires_entitlement_for_org, application_visible_to_org,
)
from .security import verify_password
from .policy import access_decision, resolve_access
from .lifecycle import (active_user, valid_session, family_active, revoke_family, revoke_session, login_throttle, mutation_lock, throttle, require_recent)
from pymongo import ReturnDocument
import re
from .util import public_id, utcnow

bp = Blueprint("oidc", __name__)
SUPPORTED_SCOPES={"openid","profile","email","offline_access","organization","permissions"}


def _client(client_id):
    return db().applications.find_one({"client_id":client_id,"status":"active","oidc_enabled":True})


def _b64url(data: bytes):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _signing_material():
    value=current_app.config.get("OIDC_PRIVATE_KEY") or ""
    if value and "BEGIN" not in value and value.startswith("base64:"):
        value=base64.b64decode(value[7:]).decode()
    candidates=[current_app.config.get("OIDC_PRIVATE_KEY_FILE"),"/app/instance/oidc_private.pem","/app/instance/private.pem","/app/oidc_private.pem"]
    if not value:
        for p in candidates:
            if p and os.path.exists(p):
                value=open(p,"r",encoding="utf-8").read(); break
    if value and "BEGIN" in value:
        return "RS256",value
    secret=current_app.config.get("OIDC_HS256_SECRET")
    if current_app.config.get("OIDC_ALLOW_HS256") and secret and len(secret)>=32:
        return "HS256",secret
    raise RuntimeError("Persistent RSA signing key required. Explicit legacy HS256 requires its own strong secret and OIDC_ALLOW_HS256=true.")


def _public_jwk():
    try:
        from .signing_keys import active_key, public_jwk
        row=active_key()
        if row:return public_jwk(row)
    except Exception:
        pass
    alg,key=_signing_material()
    if alg!="RS256": return None
    private=serialization.load_pem_private_key(key.encode(),password=None)
    public=private.public_key().public_numbers()
    n=public.n.to_bytes((public.n.bit_length()+7)//8,"big"); e=public.e.to_bytes((public.e.bit_length()+7)//8,"big")
    return {"kty":"RSA","use":"sig","alg":"RS256","kid":current_app.config["OIDC_KEY_ID"],"n":_b64url(n),"e":_b64url(e)}


def _encode(claims):
    try:
        from .signing_keys import active_key, private_pem
        row=active_key()
        if row:return jwt.encode(claims,private_pem(row),algorithm="RS256",headers={"kid":row["kid"]})
    except Exception:
        pass
    alg,key=_signing_material(); headers={"kid":current_app.config["OIDC_KEY_ID"]} if alg=="RS256" else None
    return jwt.encode(claims,key,algorithm=alg,headers=headers)


def _decode(token,audience=None,verify_exp=True):
    unverified_header=jwt.get_unverified_header(token);kid=unverified_header.get("kid")
    if kid:
        try:
            from .signing_keys import resolve_public_key
            pem=resolve_public_key(kid)
            if pem:
                options={"verify_exp":verify_exp,"verify_aud":audience is not None,"require":["iss","sub","aud","iat","exp","jti"]}
                return jwt.decode(token,pem,algorithms=["RS256"],audience=audience,issuer=current_app.config["OIDC_ISSUER"],options=options)
        except Exception:
            pass
    alg,key=_signing_material()
    if alg=="RS256":
        private=serialization.load_pem_private_key(key.encode(),password=None); verify_key=private.public_key()
    else: verify_key=key
    options={"verify_exp":verify_exp,"verify_aud":audience is not None,"require":["iss","sub","aud","iat","exp","jti"]}
    return jwt.decode(token,verify_key,algorithms=[alg],audience=audience,issuer=current_app.config["OIDC_ISSUER"],options=options)

def _hash(raw): return hashlib.sha256(raw.encode()).hexdigest()

def _client_secret_ok(client,secret):
    stored=(client.get("client_secret_hash") or "").strip()
    if not stored:
        return client.get("client_type")=="public"
    digest=_hash(secret)
    # Pre-v3 canonical format: sha256:<hex>
    if stored.lower().startswith("sha256:"):
        expected=stored.split(":",1)[1].strip().lower()
        return len(expected)==64 and hmac.compare_digest(expected,digest)
    # v3 organization-created clients: bare SHA-256 hex
    if len(stored)==64 and all(c in "0123456789abcdef" for c in stored.lower()):
        return hmac.compare_digest(stored.lower(),digest)
    return verify_password(stored,secret)


def _authenticate_client():
    cid=request.form.get("client_id") or ""; secret=request.form.get("client_secret") or ""
    auth=request.headers.get("Authorization","")
    if auth.startswith("Basic "):
        try: cid,secret=base64.b64decode(auth[6:]).decode().split(":",1)
        except Exception: return None
    client=_client(cid)
    if not client: return None
    method=client.get("token_endpoint_auth_method","client_secret_post")
    if client.get("client_type")=="public" or method=="none": return client
    return client if _client_secret_ok(client,secret) else None


def _eligible_orgs(user,client):
    uid=user.get("syntal_user_id") or str(user.get("_id")); rows=[]
    for m in db().memberships.find({"syntal_user_id":uid,"status":"active"}):
        org=db().organizations.find_one({"syntal_org_id":m.get("syntal_org_id")})
        if access_decision(user,org,m,client)['allowed']:
            rows.append({"organization":org,"membership":m,"role":role_for_membership(org['syntal_org_id'],m)})
    return rows


ORG_APP_REGISTER_PERMISSION = "syntal.org_apps.register"


def _registration_permission(org_id, membership):
    """Return whether this membership may enable Syntal apps for the org.

    Owners and organization admins are intentionally supported without a data
    migration. Custom roles can receive ``syntal.org_apps.register``. Existing
    application managers keep the capability as a superset.
    """
    role = role_for_membership(org_id, membership) or {}
    role_key = (role.get("key") or membership.get("role") or membership.get("role_key") or "member").lower()
    perms = set(effective_permissions_for_membership(org_id, membership))
    allowed = (
        role_key in {"owner", "admin"}
        or "*" in perms
        or ORG_APP_REGISTER_PERMISSION in perms
        or "syntal.org_apps.manage" in perms
        or "syntal.admin" in perms
    )
    return allowed, role, perms


def _registration_supported(org, client):
    client_id = client.get("client_id") or ""
    org_id = org.get("syntal_org_id")
    if not client_id or client_id == "syntal":
        return False
    if not application_visible_to_org(client, org_id):
        return False
    if not application_requires_entitlement_for_org(client, org_id):
        return False
    if client.get("organization_registration_enabled", True) is False:
        return False
    if client.get("owner_type") == "organization":
        return application_distributable(client)
    return True


def _authorization_registration_options(user, client, eligible_ids=None):
    uid = user.get("syntal_user_id") or str(user.get("_id"))
    eligible_ids = set(eligible_ids or [])
    rows = []
    for membership in db().memberships.find({"syntal_user_id": uid, "status": "active"}):
        org_id = membership.get("syntal_org_id")
        org = db().organizations.find_one({"syntal_org_id": org_id, "status": "active"})
        if not org or org_id in eligible_ids:
            continue

        role = role_for_membership(org_id, membership) or {}
        perms = set(effective_permissions_for_membership(org_id, membership))
        entitlement = active_entitlement(org_id, client.get("client_id"))
        override = application_access_override(org_id, membership, client.get("client_id"))
        app_access = override != "deny" and (
            "*" in perms
            or f"{client.get('client_id')}.access" in perms
            or f"{client.get('client_id')}.admin" in perms
            or client.get("owner_org_id") == org_id
        )
        can_register, _role, _perms = _registration_permission(org_id, membership)
        supported = _registration_supported(org, client)
        needs_registration = supported and not entitlement

        if needs_registration:
            reason = (
                "Enable this application for the organization and continue."
                if can_register
                else "This application is not enabled for the organization."
            )
        elif entitlement and not app_access:
            reason = "The organization is enabled, but your role does not grant application access."
        elif not supported:
            reason = "This application cannot be enabled from the authorization screen."
        else:
            reason = "This organization cannot currently be used for this application."

        rows.append({
            "organization": org,
            "membership": membership,
            "role": role,
            "can_register": bool(needs_registration and can_register),
            "needs_registration": bool(needs_registration),
            "entitlement_active": bool(entitlement),
            "app_access": bool(app_access),
            "reason": reason,
        })
    return rows


def _grant_registration_actor_access(user, org_id, membership, client_id):
    perms=set(effective_permissions_for_membership(org_id,membership))
    if application_access_override(org_id,membership,client_id)=="deny":
        return False
    if "*" in perms or f"{client_id}.access" in perms or f"{client_id}.admin" in perms:
        return False
    membership_id=membership.get("membership_id") or str(membership.get("_id") or "")
    if not membership_id:
        return False
    uid=user.get("syntal_user_id") or str(user.get("_id"))
    now=utcnow(); assignment_id=public_id("aam")
    db().organization_application_memberships.update_one(
        {"syntal_org_id":org_id,"client_id":client_id,"membership_id":membership_id},
        {
            "$setOnInsert":{"app_assignment_id":assignment_id,"assignment_id":assignment_id,"created_at":now,"created_by":uid},
            "$set":{"access_effect":"allow","status":"active","updated_at":now,"updated_by":uid},
        },
        upsert=True,
    )
    return True


def _register_organization_for_app(user, org_id, client):
    uid = user.get("syntal_user_id") or str(user.get("_id"))
    membership = db().memberships.find_one({
        "syntal_org_id": org_id,
        "syntal_user_id": uid,
        "status": "active",
    })
    org = db().organizations.find_one({"syntal_org_id": org_id, "status": "active"})
    if not membership or not org:
        raise PermissionError("You are not an active member of this organization.")
    if not _registration_supported(org, client):
        raise PermissionError("This application cannot be enabled for this organization from authorization.")

    allowed, role, _perms = _registration_permission(org_id, membership)
    if not allowed:
        raise PermissionError("Your organization role cannot register applications.")

    client_id = client.get("client_id")
    now = utcnow()
    query = {"syntal_org_id": org_id, "application": client_id}
    existing = db().organization_entitlements.find_one(query) or {}
    if active_entitlement(org_id, client_id):
        self_access_granted=_grant_registration_actor_access(user,org_id,membership,client_id)
        if self_access_granted:
            bump_policy_version(org_id)
        return {"organization": org, "membership": membership, "role": role, "created": False, "self_access_granted": self_access_granted}

    db().organization_entitlements.update_one(
        query,
        {
            "$setOnInsert": {
                "entitlement_id": public_id("ent"),
                "syntal_org_id": org_id,
                "application": client_id,
                "billing_status": existing.get("billing_status") or "inactive",
                "source": existing.get("source") or "oauth_self_service",
                "created_at": now,
                "created_by": uid,
            },
            "$set": {
                "status": "active",
                "manual_override": "active",
                "registration_channel": "oauth_authorize",
                "registered_at": now,
                "registered_by": uid,
                "updated_at": now,
                "updated_by": uid,
            },
        },
        upsert=True,
    )
    self_access_granted=_grant_registration_actor_access(user,org_id,membership,client_id)
    bump_policy_version(org_id)
    audit(
        "oidc.organization_application_registered",
        org_id=org_id,
        user_id=uid,
        detail={
            "client_id": client_id,
            "role": role.get("key") or membership.get("role"),
            "permission": ORG_APP_REGISTER_PERMISSION,
            "previous_status": existing.get("status"),
            "self_access_granted": self_access_granted,
        },
    )
    return {"organization": org, "membership": membership, "role": role, "created": True, "self_access_granted": self_access_granted}

@bp.get("/.well-known/openid-configuration")
def discovery():
    issuer=current_app.config["OIDC_ISSUER"]
    return jsonify({"issuer":issuer,"authorization_endpoint":issuer+"/oauth/authorize","token_endpoint":issuer+"/oauth/token","userinfo_endpoint":issuer+"/oauth/userinfo","jwks_uri":issuer+"/.well-known/jwks.json","revocation_endpoint":issuer+"/oauth/revoke","introspection_endpoint":issuer+"/oauth/introspect","end_session_endpoint":issuer+"/oauth/logout","scopes_supported":sorted(SUPPORTED_SCOPES),"response_types_supported":["code"],"grant_types_supported":["authorization_code","refresh_token"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":[_signing_material()[0]],"code_challenge_methods_supported":["S256"]})

@bp.get("/.well-known/jwks.json")
def jwks():
    
    try:
        from .signing_keys import jwks as keyset
        keys=keyset().get("keys",[])
        if keys:return jsonify({"keys":keys})
    except Exception:
        pass
    jwk=_public_jwk(); return jsonify({"keys":[jwk] if jwk else []})

def _auth_requirements(client, organization):
    policy = organization.get("application_security_policy") or organization.get("security_policy") or {}
    require_aal2 = bool(
        client.get("require_aal2")
        or policy.get("require_aal2")
        or policy.get("require_mfa")
        or policy.get("require_mfa_for_org_apps")
    )
    ages = []
    for value in (client.get("max_age_seconds"), policy.get("max_age_seconds")):
        try:
            value = int(value or 0)
        except (TypeError, ValueError):
            value = 0
        if value > 0:
            ages.append(value)
    return {"require_aal2": require_aal2, "max_age_seconds": min(ages) if ages else 0}


def _authorize_continuation(values, selected_org_id):
    parameters = {}
    for key in ("client_id", "redirect_uri", "response_type", "scope", "state", "nonce", "code_challenge", "code_challenge_method", "prompt", "max_age"):
        value = values.get(key)
        if value:
            parameters[key] = value
    parameters["organization_id"] = selected_org_id
    return "/oauth/authorize?" + urlencode(parameters)


@bp.route("/oauth/authorize",methods=["GET","POST"])
def authorize():
    values=request.values
    client_id=values.get("client_id","")
    client=_client(client_id)
    redirect_uri=values.get("redirect_uri","")
    state=values.get("state","")

    if not client or redirect_uri not in (client.get("redirect_uris") or []):
        abort(400,"Invalid client or redirect URI")

    def app_error(error, description=None):
        payload={"error":error}
        if description: payload["error_description"]=description
        if state: payload["state"]=state
        return redirect(redirect_uri+("&" if "?" in redirect_uri else "?")+urlencode(payload))

    if values.get("response_type")!="code":
        return app_error("unsupported_response_type")

    scopes=[s for s in (values.get("scope") or "openid").split() if s]
    registered=set(client.get("scopes") or SUPPORTED_SCOPES)
    if "openid" not in scopes or not set(scopes).issubset(SUPPORTED_SCOPES) or not set(scopes).issubset(registered):
        return app_error("invalid_scope")

    prompt=set((values.get('prompt') or '').split())
    if 'none' in prompt and len(prompt)>1:return app_error('invalid_request')
    if prompt-{'none','login','consent','select_account'}:return app_error('invalid_request')
    challenge=values.get('code_challenge')
    method=values.get('code_challenge_method')
    if client.get('pkce_required') or client.get('client_type')=='public':
        if not challenge:return app_error('invalid_request','S256 PKCE is required.')
    if challenge and (method!='S256' or not re.fullmatch(r'[A-Za-z0-9_-]{43}',challenge)):
        return app_error('invalid_request','Invalid S256 PKCE challenge.')
    try:
        requested_age=int(values.get('max_age')) if values.get('max_age') is not None else None
        if requested_age is not None and requested_age<0:raise ValueError()
    except ValueError:return app_error('invalid_request','Invalid max_age.')
    if not g.user:
        if 'none' in prompt:return app_error('login_required')
        continuation=request.query_string.decode()
        return redirect("/login?"+urlencode({"next":"/oauth/authorize?"+continuation}))

    # Cancellation is an OAuth result, not a dead-end SSO page.
    if request.method=="POST" and values.get("cancel"):
        return app_error("access_denied","The authorization request was cancelled.")

    register_org_id=(request.form.get("register_organization") or "").strip() if request.method=="POST" else ""
    if register_org_id:
        required=require_recent()
        if required:return required
        try:
            _register_organization_for_app(g.user,register_org_id,client)
        except PermissionError as exc:
            return app_error("access_denied",str(exc))
        # Use a redirect so refresh cannot repeat the entitlement mutation. The
        # same OAuth request is resumed against the newly enabled organization.
        return redirect(_authorize_continuation(values,register_org_id))

    eligible=_eligible_orgs(g.user,client)
    eligible_ids={item["organization"].get("syntal_org_id") for item in eligible}
    registration_options=_authorization_registration_options(g.user,client,eligible_ids)
    explicit_requested=(values.get("organization_id") or values.get("org_id") or "").strip()
    requested=explicit_requested or session.get("org_id")
    selected=next((x for x in eligible if x["organization"].get("syntal_org_id")==requested),None)

    if request.method=="POST" and not selected:
        chosen=(request.form.get("organization_id") or "").strip()
        selected=next((x for x in eligible if x["organization"].get("syntal_org_id")==chosen),None)

    requested_org=None
    requested_org_unavailable=False
    if explicit_requested and not selected:
        requested_org=db().organizations.find_one(
            {"syntal_org_id":explicit_requested},
            {"_id":0,"syntal_org_id":1,"name":1,"display_name":1,"status":1},
        )
        requested_org_unavailable=True

    # An explicit organization supplied by the relying app must never be
    # silently replaced by a different organization. Give the user a clear
    # choice instead. prompt=none cannot display UI, so return an OAuth error.
    needs_selection=(
        requested_org_unavailable
        or (not selected and len(eligible)>1)
        or ('select_account' in prompt and request.method=='GET')
    )

    if needs_selection:
        if values.get("prompt")=="none":
            return app_error(
                "account_selection_required",
                "The requested organization is unavailable for this application."
                if requested_org_unavailable
                else "An organization must be selected.",
            )
        return render_template(
            "auth/authorize.html",
            title="Authorize application",
            client=client,
            organizations=eligible,
            values=values,
            scopes=scopes,
            standalone_auth=True,
            requested_org=requested_org,
            requested_org_id=explicit_requested,
            requested_org_unavailable=requested_org_unavailable,
            no_access=False,
            registration_options=registration_options,
        )

    if not selected:
        if len(eligible)==1:
            selected=eligible[0]
        elif not eligible:
            if values.get("prompt")=="none":
                return app_error("access_denied","No eligible organization has access to this application.")
            return render_template(
                "auth/authorize.html",
                title="Authorization unavailable",
                client=client,
                organizations=[],
                values=values,
                scopes=scopes,
                standalone_auth=True,
                requested_org=requested_org,
                requested_org_id=explicit_requested,
                requested_org_unavailable=bool(explicit_requested),
                no_access=not any(item.get("can_register") for item in registration_options),
                registration_options=registration_options,
            )

    selected_org_id=selected["organization"]["syntal_org_id"]
    session["org_id"]=selected_org_id
    requirements=_auth_requirements(client,selected["organization"])
    # A completed step-up is bound to this exact authorization request.
    request_binding=_hash(_authorize_continuation(values,selected_org_id))
    force_login='login' in prompt and session.get('reauth_authorize_binding')!=request_binding
    if requested_age is not None:
        requirements['max_age_seconds']=min(requirements['max_age_seconds'],requested_age) if requirements['max_age_seconds'] else requested_age
    now_epoch=int(utcnow().timestamp())
    auth_time=int(session.get("auth_time") or 0)
    needs_fresh=bool(requirements["max_age_seconds"] and (not auth_time or now_epoch-auth_time>requirements["max_age_seconds"]))
    needs_aal2=bool(requirements["require_aal2"] and session.get("acr")!="urn:syntal:loa:2")
    if needs_fresh or needs_aal2 or force_login or (requested_age==0 and session.get("reauth_authorize_binding")!=request_binding):
        if values.get("prompt")=="none":
            return app_error("interaction_required")
        continuation=_authorize_continuation(values,selected_org_id)
        session['pending_authorize_binding']=request_binding
        return redirect(url_for("auth.reauth",next=continuation))

    # Distributed clients require explicit scope consent, remembered per org/client.
    consent_key={'syntal_user_id':g.user['syntal_user_id'],'syntal_org_id':selected_org_id,'client_id':client_id}
    consent=db().oidc_consents.find_one(consent_key) or {}
    need_consent='consent' in prompt or not set(scopes).issubset(set(consent.get('scopes') or []))
    if need_consent and client.get('owner_type')=='organization' and client.get('owner_org_id')!=selected_org_id:
        if 'none' in prompt:return app_error('consent_required')
        if request.method!='POST' or values.get('approve')!='yes':
            return render_template('auth/consent.html',title='Approve application access',client=client,values=values,scopes=scopes,organization=selected['organization'],standalone_auth=True)
        db().oidc_consents.update_one(consent_key,{'$set':{'scopes':sorted(set(consent.get('scopes') or [])|set(scopes)),'updated_at':utcnow()}},upsert=True)
    raw=secrets.token_urlsafe(42)
    now=utcnow()
    doc={
        "code_hash":_hash(raw),
        "client_id":client_id,
        "redirect_uri":redirect_uri,
        "syntal_user_id":g.user.get("syntal_user_id"),
        "syntal_org_id":selected_org_id,
        "scope":" ".join(scopes),
        "nonce":values.get("nonce"),
        "code_challenge":values.get("code_challenge"),
        "code_challenge_method":values.get("code_challenge_method"),
        "auth_time":int(session.get("auth_time") or now_epoch),
        "acr":session.get("acr") or "urn:syntal:loa:1",
        "amr":list(session.get("amr") or ["pwd"]),
        "created_at":now,
        "expire_at":now+timedelta(minutes=10),
        "consumed_at":None,
        "sid":session.get("auth_session_id"),
        "session_epoch":g.user.get("session_epoch",0),
    }
    db().oidc_authorization_codes.insert_one(doc)
    # The proof authorizes this completion only; prompt=login/max_age=0 must
    # request a new proof on a subsequent authorization, even with identical parameters.
    session.pop('reauth_authorize_binding',None)
    audit(
        "oidc.authorization_code_issued",
        user_id=g.user.get("syntal_user_id"),
        org_id=doc["syntal_org_id"],
        detail={"client_id":client_id},
    )
    return redirect(redirect_uri+("&" if "?" in redirect_uri else "?")+urlencode({"code":raw,"state":state}))


def _consume_code(raw,client_id,redirect_uri,verifier):
    now=utcnow(); query={"code_hash":_hash(raw),"client_id":client_id,"redirect_uri":redirect_uri,"consumed_at":None,"expire_at":{"$gt":now}}
    row=db().oidc_authorization_codes.find_one(query)
    if not row:return None
    challenge=row.get('code_challenge')
    if challenge:
        if row.get('code_challenge_method')!='S256' or not re.fullmatch(r'[A-Za-z0-9._~-]{43,128}',verifier or ''):return None
        digest=_b64url(hashlib.sha256(verifier.encode()).digest())
        if not hmac.compare_digest(digest,challenge):return None
    return db().oidc_authorization_codes.find_one_and_update(query,{'$set':{'consumed_at':now}},return_document=ReturnDocument.AFTER)


def _token_claims(user,org,membership,client,scope,sid,nonce=None,auth_time=None,acr=None,amr=None):
    now=int(utcnow().timestamp()); cid=client['client_id']; org_id=org['syntal_org_id']
    role=role_for_membership(org_id,membership) or {}
    effective=set(effective_permissions_for_membership(org_id,membership))
    perms={p for p in effective if p.startswith(cid+'.')}
    if '*' in effective:
        perms.update({cid+'.access',cid+'.admin'})
        for collection in (db().permission_catalog,db().organization_application_permissions):
            for row in collection.find({'$or':[{'application':cid},{'client_id':cid}],'status':{'$ne':'deleted'}}):
                p=row.get('permission')
                if isinstance(p,str) and p.startswith(cid+'.'):perms.add(p)
    if cid+'.admin' in perms:perms.add(cid+'.access')
    audience=[cid,current_app.config['API_AUDIENCE']] if client.get('api_access_enabled') and 'organization' in scope.split() else cid
    claims={'iss':current_app.config['OIDC_ISSUER'],'sub':user['syntal_user_id'],'aud':audience,
        'client_id':cid,'iat':now,'exp':now+current_app.config['ACCESS_TOKEN_TTL'],'jti':public_id('jti'),
        'sid':sid,'scope':scope,'org_id':org_id,'syntal_org_id':org_id,'syntal_org_name':org.get('name'),
        'syntal_role':role.get('key') or membership.get('role'),'syntal_policy_version':org.get('authorization_policy_version',1),
        'permissions':sorted(perms),'auth_time':int(auth_time or now),'acr':acr or 'urn:syntal:loa:1',
        'amr':list(amr or ['pwd']),'session_epoch':user.get('session_epoch',0),'token_use':'access'}
    if nonce:claims['nonce']=nonce
    return claims


def _issue_from_doc(doc,client,refresh_family=None):
    uid=doc.get('syntal_user_id'); org_id=doc.get('syntal_org_id'); cid=client['client_id']
    if not resolve_access(uid,org_id,cid)['allowed'] or not valid_session(doc.get('sid'),uid,doc.get('session_epoch')):return None
    user=db().users.find_one({'syntal_user_id':uid});org=db().organizations.find_one({'syntal_org_id':org_id});membership=db().memberships.find_one({'syntal_user_id':uid,'syntal_org_id':org_id,'status':'active'})
    requirements=_auth_requirements(client,org);now=utcnow();auth_time=int(doc.get('auth_time') or 0)
    if requirements['require_aal2'] and doc.get('acr')!='urn:syntal:loa:2':return None
    if requirements['max_age_seconds'] and int(now.timestamp())-auth_time>requirements['max_age_seconds']:return None
    sid=doc['sid'];scope=doc.get('scope') or 'openid'
    if not set(scope.split()).issubset(set(client.get('scopes') or SUPPORTED_SCOPES)):return None
    claims=_token_claims(user,org,membership,client,scope,sid,doc.get('nonce'),auth_time,doc.get('acr'),doc.get('amr'))
    if refresh_family and not family_active(refresh_family):return None
    if refresh_family:claims['refresh_family_id']=refresh_family
    id_claims={k:v for k,v in claims.items() if k not in {'permissions','scope','client_id','refresh_family_id'}}
    id_claims.update(aud=cid,token_use='id',exp=int(now.timestamp())+current_app.config['ID_TOKEN_TTL'])
    if 'profile' in scope.split():id_claims['name']=user.get('name')
    if 'email' in scope.split():id_claims.update(email=user.get('email'),email_verified=True)
    result={'access_token':_encode(claims),'token_type':'Bearer','expires_in':current_app.config['ACCESS_TOKEN_TTL'],'scope':scope,'id_token':_encode(id_claims)}
    if 'offline_access' in scope.split() and 'refresh_token' in (client.get('grant_types') or []):
        family=refresh_family or public_id('rfam')
        if not refresh_family:
            db().oidc_token_families.insert_one({'_id':family,'sid':sid,'client_id':cid,'expire_at':now+timedelta(seconds=current_app.config['REFRESH_TOKEN_TTL']),'revoked_at':None})
        if not family_active(family):return None
        expiry=db().oidc_token_families.find_one({'_id':family})['expire_at'];raw=secrets.token_urlsafe(48)
        db().oidc_refresh_tokens.insert_one({'refresh_token_id':public_id('rt'),'token_hash':_hash(raw),'family_id':family,'client_id':cid,'syntal_user_id':uid,'syntal_org_id':org_id,'scope':scope,'sid':sid,'session_epoch':user.get('session_epoch',0),'auth_time':auth_time,'acr':claims['acr'],'amr':claims['amr'],'created_at':now,'expire_at':expiry,'used_at':None,'revoked_at':None})
        if not family_active(family):return None
        claims['refresh_family_id']=family;result['access_token']=_encode(claims);result['refresh_token']=raw
    return result


def token_state(claims,expected_client=None):
    if claims.get('token_use')!='access' or not claims.get('client_id') or not claims.get('sid'):return False
    cid=claims['client_id']
    if expected_client and cid!=expected_client:return False
    client=_client(cid)
    if not client or not set((claims.get('scope') or '').split()).issubset(set(client.get('scopes') or SUPPORTED_SCOPES)):return False
    if not valid_session(claims['sid'],claims.get('sub'),claims.get('session_epoch')):return False
    if claims.get('refresh_family_id') and not family_active(claims['refresh_family_id']):return False
    decision=resolve_access(claims.get('sub'),claims.get('syntal_org_id'),cid)
    org=db().organizations.find_one({'syntal_org_id':claims.get('syntal_org_id')}) or {}
    requirements=_auth_requirements(client,org)
    if requirements['require_aal2'] and claims.get('acr')!='urn:syntal:loa:2':return False
    if requirements['max_age_seconds'] and int(utcnow().timestamp())-int(claims.get('auth_time') or 0)>requirements['max_age_seconds']:return False
    # A stale JWT does not retain old permissions at SSO endpoints.
    return decision['allowed'] and claims.get('syntal_policy_version')==decision['policy_version']


@bp.post('/oauth/token')
def token():
    throttle('token-client',request.form.get('client_id',''),1000,60)
    throttle('token-ip',request.remote_addr or 'unknown',5000,60)
    client=_authenticate_client()
    if not client:return jsonify({'error':'invalid_client'}),401
    grant=request.form.get('grant_type')
    if grant not in (client.get('grant_types') or ['authorization_code']):return jsonify({'error':'unauthorized_client'}),400
    if grant=='authorization_code':
        doc=_consume_code(request.form.get('code',''),client['client_id'],request.form.get('redirect_uri',''),request.form.get('code_verifier',''))
        if not doc:return jsonify({'error':'invalid_grant'}),400
        result=_issue_from_doc(doc,client)
    elif grant=='refresh_token':
        raw=request.form.get('refresh_token','');now=utcnow();base={'token_hash':_hash(raw),'client_id':client['client_id']}
        row=db().oidc_refresh_tokens.find_one_and_update({**base,'used_at':None,'revoked_at':None,'expire_at':{'$gt':now}}, {'$set':{'used_at':now}},return_document=ReturnDocument.AFTER)
        if not row:
            previous=db().oidc_refresh_tokens.find_one(base)
            if previous and previous.get('used_at'):revoke_family(previous.get('family_id'))
            return jsonify({'error':'invalid_grant'}),400
        result=_issue_from_doc(row,client,refresh_family=row.get('family_id'))
        if not result:revoke_family(row.get('family_id'))
    else:return jsonify({'error':'unsupported_grant_type'}),400
    if not result:return jsonify({'error':'invalid_grant'}),400
    response=jsonify(result);response.headers['Cache-Control']='no-store';response.headers['Pragma']='no-cache';return response


@bp.get('/oauth/userinfo')
def userinfo():
    auth=request.headers.get('Authorization','')
    if not auth.startswith('Bearer '):return jsonify({'error':'invalid_token'}),401
    try:
        raw=auth[7:];unverified=jwt.decode(raw,options={'verify_signature':False});claims=_decode(raw,audience=unverified.get('client_id'))
        if not token_state(claims):raise ValueError()
    except Exception:return jsonify({'error':'invalid_token'}),401
    user=db().users.find_one({'syntal_user_id':claims['sub']});result={'sub':claims['sub']};scopes=set(claims['scope'].split())
    if 'profile' in scopes:result['name']=user.get('name')
    if 'email' in scopes:result.update(email=user.get('email'),email_verified=True)
    if 'organization' in scopes:result.update({k:claims.get(k) for k in ('syntal_org_id','syntal_org_name','syntal_role')})
    if 'permissions' in scopes:result['permissions']=claims.get('permissions',[])
    response=jsonify(result);response.headers['Cache-Control']='no-store';return response


@bp.post('/oauth/revoke')
def revoke():
    client=_authenticate_client()
    if not client:return jsonify({'error':'invalid_client'}),401
    row=db().oidc_refresh_tokens.find_one({'token_hash':_hash(request.form.get('token','')),'client_id':client['client_id']})
    if row:revoke_family(row.get('family_id'))
    else:
        try:
            claims=_decode(request.form.get('token',''),audience=client['client_id'])
            if claims.get('token_use')=='access' and claims.get('client_id')==client['client_id']:revoke_session(claims.get('sid'),claims.get('sub'))
        except Exception:pass
    return '',200


@bp.post('/oauth/introspect')
def introspect():
    client=_authenticate_client()
    if not client or client.get('client_type')=='public' or client.get('token_endpoint_auth_method')=='none':return jsonify({'active':False}),401
    raw=request.form.get('token','')
    try:
        claims=_decode(raw,audience=client['client_id'])
        if token_state(claims,client['client_id']):return jsonify({'active':True,**claims})
    except Exception:pass
    row=db().oidc_refresh_tokens.find_one({'token_hash':_hash(raw),'client_id':client['client_id'],'expire_at':{'$gt':utcnow()},'used_at':None,'revoked_at':None})
    ok=bool(row and family_active(row.get('family_id')) and valid_session(row.get('sid'),row.get('syntal_user_id'),row.get('session_epoch')) and resolve_access(row.get('syntal_user_id'),row.get('syntal_org_id'),client['client_id'])['allowed'])
    if ok:
        requirements=_auth_requirements(client,db().organizations.find_one({'syntal_org_id':row['syntal_org_id']}) or {})
        ok=not (requirements['require_aal2'] and row.get('acr')!='urn:syntal:loa:2') and not (requirements['max_age_seconds'] and int(utcnow().timestamp())-int(row.get('auth_time') or 0)>requirements['max_age_seconds'])
        ok=ok and set((row.get('scope') or '').split()).issubset(set(client.get('scopes') or SUPPORTED_SCOPES))
    return jsonify({'active':ok,**({'token_type':'refresh_token','client_id':client['client_id'],'sub':row['syntal_user_id'],'org_id':row['syntal_org_id'],'scope':row['scope']} if ok else {})})


@bp.route('/oauth/logout',methods=['GET','POST'])
def oauth_logout():
    client=None;hint=request.values.get('id_token_hint')
    if hint:
        try:
            unverified=jwt.decode(hint,options={'verify_signature':False});aud=unverified.get('aud')
            claims=_decode(hint,audience=aud,verify_exp=False)
            if claims.get('token_use')!='id':raise ValueError()
            client=_client(aud)
        except Exception:abort(400,'Invalid logout hint')
    destination=request.values.get('post_logout_redirect_uri')
    if destination and (not client or destination not in (client.get('post_logout_redirect_uris') or [])):abort(400,'Unregistered logout redirect')
    if request.method=='GET':return render_template('auth/logout.html',title='Sign out',values=request.args,standalone_auth=True)
    if session.get('auth_session_id'):revoke_session(session['auth_session_id'],session.get('user_id'))
    session.clear();post=destination or '/login';state=request.values.get('state')
    return redirect(post+((('&' if '?' in post else '?')+urlencode({'state':state})) if state else ''))
