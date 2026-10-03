from bson import ObjectId
from flask import g, session
from .db import db
from .acl import effective_permissions_for_membership
from .lifecycle import active_user, valid_session


def _user_by_session_id(value):
    if not value:
        return None
    user = db().users.find_one({"syntal_user_id": value, "status": {"$ne": "deleted"}})
    if user:
        return user
    try:
        user = db().users.find_one({"_id": ObjectId(value), "status": {"$ne": "deleted"}})
        if user:
            return user
    except Exception:
        pass
    return db().users.find_one({"_id": value, "status": {"$ne": "deleted"}})


def load_request_context():
    g.user = None
    g.organization = None
    g.membership = None
    g.permissions = set()
    uid = session.get("user_id") or session.get("syntal_user_id") or session.get("uid")
    g.user = _user_by_session_id(uid)
    if not active_user(g.user) or not valid_session(session.get("auth_session_id"), (g.user or {}).get("syntal_user_id"), session.get("session_epoch")):
        g.user=None
        if uid:session.clear()
        return
    user_id = g.user.get("syntal_user_id") or str(g.user.get("_id"))
    org_id = session.get("org_id") or session.get("organization_id")
    membership = None
    if org_id:
        membership = db().memberships.find_one({"syntal_org_id": org_id, "syntal_user_id": user_id, "status": "active"})
    if not membership:
        membership = db().memberships.find_one({"syntal_user_id": user_id, "status": "active"}, sort=[("created_at", 1)])
        if membership:
            org_id = membership.get("syntal_org_id")
            session["org_id"] = org_id
    if membership and org_id:
        org = db().organizations.find_one({"syntal_org_id": org_id, "status": "active"})
        if org:
            g.membership = membership
            g.organization = org
            g.permissions = set(effective_permissions_for_membership(org_id, membership))


def memberships_for_user():
    if not getattr(g, "user", None):
        return []
    uid = g.user.get("syntal_user_id") or str(g.user.get("_id"))
    rows = list(db().memberships.find({"syntal_user_id": uid, "status": "active"}).sort("created_at", 1))
    org_ids = [r.get("syntal_org_id") for r in rows]
    orgs = {o.get("syntal_org_id"): o for o in db().organizations.find({"syntal_org_id": {"$in": org_ids}})} if org_ids else {}
    for row in rows:
        row["organization"] = orgs.get(row.get("syntal_org_id"))
    return rows
