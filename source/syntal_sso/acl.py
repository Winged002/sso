from flask import abort, g
from .db import db
from .util import utcnow, public_id

ACTIVE_ENTITLEMENT_STATUSES = {"active", "trial", "grace"}


def role_for_membership(org_id, membership):
    if not membership:
        return None
    q = {"syntal_org_id": org_id}
    if membership.get("role_id"):
        row = db().organization_roles.find_one({**q, "role_id": membership["role_id"]})
        if row:
            return row
    key = membership.get("role") or membership.get("role_key")
    if key:
        row = db().organization_roles.find_one({**q, "$or": [{"key": key}, {"name": key}]})
        if row:
            return row
    return {"key": key or "member", "name": (key or "member").title(), "permissions": membership.get("permissions") or []}


def _application_assignment_rows(org_id, membership):
    if not membership:
        return []
    mids = [membership.get("membership_id"), str(membership.get("_id") or "")]
    mids = [m for m in mids if m]
    if not mids:
        return []
    return list(db().organization_application_memberships.find({
        "syntal_org_id": org_id,
        "membership_id": {"$in": mids},
        "status": "active",
    }))


def application_access_override(org_id, membership, client_id):
    """Return inherit/allow/deny for one member/application pair."""
    for row in _application_assignment_rows(org_id, membership):
        if row.get("client_id") == client_id:
            effect = (row.get("access_effect") or "inherit").strip().lower()
            return effect if effect in {"inherit", "allow", "deny"} else "inherit"
    return "inherit"


def application_role_permissions(org_id, membership):
    rows = [r for r in _application_assignment_rows(org_id, membership) if (r.get("access_effect") or "inherit") != "deny"]
    role_ids = [r.get("app_role_id") for r in rows if r.get("app_role_id")]
    if not role_ids:
        return []
    perms = []
    for role in db().organization_application_roles.find({"syntal_org_id": org_id, "app_role_id": {"$in": role_ids}, "status": "active"}):
        perms.extend(role.get("permissions") or [])
    return perms


def effective_permissions_for_membership(org_id, membership):
    if not membership:
        return []
    role = role_for_membership(org_id, membership) or {}
    key = role.get("key") or membership.get("role")
    if key == "owner":
        # Owner remains privileged even when historical role records are incomplete.
        return ["*"]

    perms = set(role.get("permissions") or [])
    perms.update(membership.get("permissions") or [])
    rows = _application_assignment_rows(org_id, membership)

    # Per-member deny overrides inherited organization-role/app-role grants for
    # the selected application namespace.
    denied = {r.get("client_id") for r in rows if (r.get("access_effect") or "inherit") == "deny" and r.get("client_id")}
    if denied:
        perms = {p for p in perms if not any(p.startswith(client_id + ".") for client_id in denied)}

    role_ids = [r.get("app_role_id") for r in rows if r.get("app_role_id") and (r.get("access_effect") or "inherit") != "deny"]
    role_map = {}
    if role_ids:
        role_map = {r.get("app_role_id"): r for r in db().organization_application_roles.find({
            "syntal_org_id": org_id,
            "app_role_id": {"$in": role_ids},
            "status": "active",
        })}

    for row in rows:
        client_id = row.get("client_id")
        effect = (row.get("access_effect") or "inherit").strip().lower()
        if not client_id or effect == "deny":
            continue
        if effect == "allow":
            perms.add(f"{client_id}.access")
        for permission in row.get("direct_permissions") or []:
            if isinstance(permission, str) and permission.startswith(client_id + "."):
                perms.add(permission)
        app_role = role_map.get(row.get("app_role_id"))
        if app_role:
            perms.update(p for p in (app_role.get("permissions") or []) if isinstance(p, str))

    return sorted(perms)


def has_permission(permission, membership=None, org_id=None):
    membership = membership or getattr(g, "membership", None)
    org_id = org_id or (getattr(g, "organization", None) or {}).get("syntal_org_id")
    if not membership or not org_id:
        return False
    role = role_for_membership(org_id, membership) or {}
    role_key = role.get("key") or membership.get("role") or membership.get("role_key")
    namespace = permission.split(".", 1)[0]
    # A per-member app deny must beat broad inherited grants (including a
    # custom role carrying '*'). Organization owners remain protected.
    if namespace != "syntal" and role_key != "owner" and application_access_override(org_id, membership, namespace) == "deny":
        return False
    perms = set(effective_permissions_for_membership(org_id, membership))
    if "*" in perms or permission in perms:
        return True
    # Allow namespace-level admin permissions to cover namespace children.
    return f"{namespace}.admin" in perms or "syntal.admin" in perms


def require_permission(permission):
    if not has_permission(permission):
        abort(403)


def entitlement_is_active(entitlement):
    if not entitlement or entitlement.get("status") not in ACTIVE_ENTITLEMENT_STATUSES:
        return False
    if entitlement.get("status") == "grace" and entitlement.get("valid_until") and entitlement["valid_until"] < utcnow():
        return False
    return True


def active_entitlement(org_id, application):
    row = db().organization_entitlements.find_one({"syntal_org_id": org_id, "application": application})
    return row if entitlement_is_active(row) else None


def audit(event, *, org_id=None, user_id=None, detail=None):
    doc = {
        "audit_id": public_id("aud"),
        "event": event,
        "syntal_org_id": org_id,
        "syntal_user_id": user_id or ((getattr(g, "user", None) or {}).get("syntal_user_id")),
        "detail": detail or {},
        "created_at": utcnow(),
    }
    db().audit_events.insert_one(doc)
    return doc


def bump_policy_version(org_id):
    db().organizations.update_one({"syntal_org_id": org_id}, {"$inc": {"authorization_policy_version": 1}, "$set": {"updated_at": utcnow()}})
