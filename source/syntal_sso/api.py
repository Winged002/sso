from flask import Blueprint, g, jsonify, request
import jwt
from .db import db
from .oidc import _decode
from .acl import effective_permissions_for_membership, entitlement_is_active

bp = Blueprint("api", __name__)


def _claims():
    auth=request.headers.get("Authorization","")
    if not auth.startswith("Bearer "): return None
    raw=auth[7:]
    try:
        unverified=jwt.decode(raw,options={"verify_signature":False}); return _decode(raw,audience=unverified.get("aud"))
    except Exception:return None


def _authorized_orgs(claims):
    if not claims:return []
    uid=claims.get("sub")
    rows=list(db().memberships.find({"syntal_user_id":uid,"status":"active"}))
    ids=[r.get("syntal_org_id") for r in rows]
    orgs={o.get("syntal_org_id"):o for o in db().organizations.find({"syntal_org_id":{"$in":ids},"status":"active"})} if ids else {}
    return [{"syntal_org_id":i,"name":orgs[i].get("name"),"display_name":orgs[i].get("display_name") or orgs[i].get("name")} for i in ids if i in orgs]

@bp.get("/v1/organizations")
def organizations():
    claims=_claims()
    if not claims:return jsonify({"error":"unauthorized"}),401
    return jsonify({"organizations":_authorized_orgs(claims)})

@bp.get("/v1/organizations/<org_id>/members")
def members(org_id):
    claims=_claims()
    if not claims:return jsonify({"error":"unauthorized"}),401
    allowed={o["syntal_org_id"] for o in _authorized_orgs(claims)}
    if org_id not in allowed:return jsonify({"error":"forbidden"}),403
    rows=list(db().memberships.find({"syntal_org_id":org_id,"status":"active"}).sort("created_at",1)); ids=[m.get("syntal_user_id") for m in rows]
    users={u.get("syntal_user_id"):u for u in db().users.find({"syntal_user_id":{"$in":ids}})} if ids else {}
    data=[]
    for m in rows:
        u=users.get(m.get("syntal_user_id"),{}); data.append({"membership_id":m.get("membership_id"),"syntal_user_id":m.get("syntal_user_id"),"email":u.get("email"),"name":u.get("name"),"role":m.get("role"),"role_id":m.get("role_id")})
    return jsonify({"members":data})

# Stable product aliases retained for existing apps.
@bp.get("/v1/chat/organizations")
@bp.get("/v1/files/organizations")
@bp.get("/v1/board/organizations")
def product_organizations(): return organizations()

@bp.get("/v1/chat/organizations/<org_id>/members")
@bp.get("/v1/files/organizations/<org_id>/members")
@bp.get("/v1/board/organizations/<org_id>/members")
def product_members(org_id): return members(org_id)

@bp.post("/v1/access/check")
def access_check():
    claims=_claims()
    if not claims:return jsonify({"error":"unauthorized"}),401
    payload=request.get_json(silent=True) or {}; org_id=payload.get("organization_id") or payload.get("syntal_org_id"); permission=payload.get("permission"); application=payload.get("application") or (permission.split(".",1)[0] if permission else None)
    membership=db().memberships.find_one({"syntal_org_id":org_id,"syntal_user_id":claims.get("sub"),"status":"active"})
    if not membership:return jsonify({"allowed":False,"reasons":["membership_not_active"]})
    perms=set(effective_permissions_for_membership(org_id,membership)); ent=db().organization_entitlements.find_one({"syntal_org_id":org_id,"application":application}) if application else None
    app=db().applications.find_one({"client_id":application}) if application else None
    entitlement_ok=(application=="syntal") or (app and app.get("owner_type")=="organization" and app.get("owner_org_id")==org_id) or entitlement_is_active(ent)
    perm_ok="*" in perms or permission in perms or (application and f"{application}.admin" in perms)
    return jsonify({"allowed":bool(entitlement_ok and perm_ok),"permission":permission,"application":application,"entitlement_status":(ent or {}).get("status"),"reasons":[] if entitlement_ok and perm_ok else (["product_not_entitled"] if not entitlement_ok else [])+(["permission_not_granted"] if not perm_ok else [])})
