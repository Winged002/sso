from flask import abort, g
from .db import db
from .util import utcnow, public_id

ACTIVE_ENTITLEMENT_STATUSES = {"active", "trial", "grace"}


def application_owned_by_org(app, org_id):
    return bool(
        app
        and app.get("owner_type") == "organization"
        and app.get("owner_org_id") == org_id
    )


def application_distributable(app):
    """Return whether an organization-owned client is explicitly multi-tenant.

    Organization-owned OAuth clients stay private by default. They become
    discoverable/enableable by other Syntal organizations only when the owning
    organization deliberately sets distribution_scope=organizations.
    """
    if not app or app.get("owner_type") != "organization":
        return False
    return (app.get("distribution_scope") or "private") == "organizations"


def application_visible_to_org(app, org_id):
    if not app or app.get("status") == "deleted":
        return False
    owner_type = app.get("owner_type")
    if owner_type == "organization":
        return application_owned_by_org(app, org_id) or application_distributable(app)
    # Syntal-owned and legacy global applications remain catalog-visible.
    return owner_type in {None, "syntal"}


def application_requires_entitlement_for_org(app, org_id):
    if not app or (app.get("client_id") or "") == "syntal":
        return False
    if app.get("requires_entitlement", True) is False:
        return False
    return not application_owned_by_org(app, org_id)


def role_for_membership(org_id, membership):
    if not membership:return None
    query={'syntal_org_id':org_id}
    if membership.get('role_id'):query['role_id']=membership['role_id']
    else:query['$or']=[{'key':membership.get('role') or membership.get('role_key')},{'name':membership.get('role') or membership.get('role_key')}]
    row=db().organization_roles.find_one(query)
    if row and row.get('status','active')=='active':return row
    return {'key':'unassigned','name':'Unavailable role','permissions':[]}


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
    pairs={(r.get("client_id"),r.get("app_role_id")) for r in rows}
    perms = []
    for role in db().organization_application_roles.find({"syntal_org_id": org_id, "app_role_id": {"$in": role_ids}, "status": "active"}):
        if (role.get("client_id"),role.get("app_role_id")) in pairs:
            perms.extend(p for p in (role.get("permissions") or []) if isinstance(p,str) and p.startswith(str(role.get("client_id"))+"."))
    return perms


def effective_permissions_for_membership(org_id, membership):
    if not membership:
        return []
    role = role_for_membership(org_id, membership) or {}
    key = role.get("key") or membership.get("role")
    if key == "unassigned":return []
    if key == "owner":
        # A bound, active owner role remains privileged.
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
            perms.update(p for p in (app_role.get("permissions") or []) if isinstance(p,str) and p.startswith(client_id+".") and app_role.get("client_id")==client_id)

    # App-role permissions are restricted to their own app even for historical data.
    if denied:
        perms = {p for p in perms if not any(p.startswith(cid + ".") for cid in denied)}
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
    if entitlement.get("valid_until") and entitlement["valid_until"] < utcnow():
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
    try:
        db().audit_events.insert_one(doc)
        try:
            from .events import enqueue
            enqueue(event,org_id=org_id,user_id=doc.get("syntal_user_id"),detail=detail or {})
        except Exception:
            from flask import current_app
            current_app.logger.exception("Event enqueue failed for %s", event)
    except Exception:
        from flask import current_app
        current_app.logger.exception("Audit persistence failed for event %s", event)
    return doc


def bump_policy_version(org_id):
    db().organizations.update_one({"syntal_org_id": org_id}, {"$inc": {"authorization_policy_version": 1}, "$set": {"updated_at": utcnow()}})
