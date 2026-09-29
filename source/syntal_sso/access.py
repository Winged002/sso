from flask import Blueprint, abort, g, redirect, render_template, request, url_for
from bson import ObjectId
from .db import db
from .security import login_required
from .acl import audit, bump_policy_version, effective_permissions_for_membership, entitlement_is_active, has_permission, require_permission, role_for_membership
from .util import public_id, utcnow

bp = Blueprint("access", __name__)


def _require_org(org_id, permission="syntal.roles.read"):
    uid=g.user.get("syntal_user_id") or str(g.user.get("_id"))
    org=db().organizations.find_one({"syntal_org_id":org_id,"status":{"$ne":"deleted"}})
    membership=db().memberships.find_one({"syntal_org_id":org_id,"syntal_user_id":uid,"status":"active"})
    if not org or not membership: abort(404)
    g.organization,g.membership=org,membership
    if permission and not has_permission(permission,membership,org_id): abort(403)
    return org,membership


def _available_permissions(org_id):
    perms=set()
    for role in db().organization_roles.find({"syntal_org_id":org_id,"status":{"$ne":"deleted"}}):
        perms.update(role.get("permissions") or [])
    for row in db().organization_application_permissions.find({"syntal_org_id":org_id,"status":"active"}):
        if row.get("permission"): perms.add(row["permission"])
    for app in db().applications.find({"status":"active"},{"client_id":1}):
        cid=app.get("client_id")
        if cid: perms.update({f"{cid}.access",f"{cid}.admin"})
    perms.update({"syntal.members.read","syntal.members.manage","syntal.members.invite","syntal.roles.read","syntal.roles.manage","syntal.org_apps.read","syntal.org_apps.register","syntal.org_apps.manage","syntal.billing.read","syntal.billing.manage","syntal.audit.read","syntal.organization.manage"})
    return sorted(perms)

@bp.route("/organizations/<org_id>/access/roles",methods=["GET","POST"])
@login_required
def roles(org_id):
    org,_=_require_org(org_id)
    if request.method=="POST":
        require_permission("syntal.roles.manage")
        name=(request.form.get("name") or "").strip(); key=(request.form.get("key") or name.lower().replace(" ","_")).strip()
        if not name: abort(400)
        role={"role_id":public_id("role"),"syntal_org_id":org_id,"key":key,"name":name,"description":(request.form.get("description") or "").strip(),"permissions":request.form.getlist("permissions"),"status":"active","created_at":utcnow(),"created_by":g.user.get("syntal_user_id")}
        db().organization_roles.insert_one(role); bump_policy_version(org_id); audit("authorization.role_created",org_id=org_id,detail={"role_id":role["role_id"],"key":key})
        return redirect(url_for("access.roles",org_id=org_id))
    rows=list(db().organization_roles.find({"syntal_org_id":org_id,"status":{"$ne":"deleted"}}).sort([("rank",-1),("name",1)]))
    counts={r.get("role_id"):db().memberships.count_documents({"syntal_org_id":org_id,"role_id":r.get("role_id"),"status":{"$in":["active","suspended"]}}) for r in rows}
    return render_template("access/roles.html",title="Roles",organization=org,roles=rows,counts=counts,permissions=_available_permissions(org_id),can_manage=has_permission("syntal.roles.manage"))

@bp.route("/organizations/<org_id>/access/roles/<role_id>",methods=["GET","POST"])
@login_required
def role_detail(org_id,role_id):
    org,_=_require_org(org_id); role=db().organization_roles.find_one({"syntal_org_id":org_id,"role_id":role_id,"status":{"$ne":"deleted"}})
    if not role: abort(404)
    if request.method=="POST":
        require_permission("syntal.roles.manage")
        if role.get("key")=="owner": abort(409,"The owner role is protected.")
        perms=request.form.getlist("permissions")
        db().organization_roles.update_one({"_id":role["_id"]},{"$set":{"name":(request.form.get("name") or role.get("name")).strip(),"description":(request.form.get("description") or "").strip(),"permissions":perms,"updated_at":utcnow()}}); bump_policy_version(org_id); audit("authorization.role_updated",org_id=org_id,detail={"role_id":role_id})
        return redirect(url_for("access.role_detail",org_id=org_id,role_id=role_id))
    members=list(db().memberships.find({"syntal_org_id":org_id,"role_id":role_id,"status":{"$in":["active","suspended"]}})); users={u.get("syntal_user_id"):u for u in db().users.find({"syntal_user_id":{"$in":[m.get("syntal_user_id") for m in members]}})} if members else {}
    return render_template("access/role_detail.html",title=role.get("name","Role"),organization=org,role=role,permissions=_available_permissions(org_id),members=members,users=users,can_manage=has_permission("syntal.roles.manage"))

@bp.get("/organizations/<org_id>/access/permissions")
@login_required
def permissions(org_id):
    org,_=_require_org(org_id)
    by_app={}
    for p in _available_permissions(org_id):
        by_app.setdefault(p.split(".",1)[0],[]).append(p)
    return render_template("access/permissions.html",title="Permissions",organization=org,permissions_by_app=by_app)

def _matrix_permission_catalog(org_id, client_id):
    permissions={f"{client_id}.access",f"{client_id}.admin"}
    for row in db().organization_application_permissions.find({"syntal_org_id":org_id,"client_id":client_id,"status":"active"}):
        permission=row.get("permission")
        if permission and permission.startswith(client_id + "."):
            permissions.add(permission)
    for role in db().organization_application_roles.find({"syntal_org_id":org_id,"client_id":client_id,"status":"active"}):
        for permission in role.get("permissions") or []:
            if isinstance(permission,str) and permission.startswith(client_id + "."):
                permissions.add(permission)
    return sorted(permissions)


def _target_membership(org_id, membership_id):
    target=db().memberships.find_one({"syntal_org_id":org_id,"membership_id":membership_id})
    if target:
        return target
    if ObjectId.is_valid(str(membership_id)):
        target=db().memberships.find_one({"syntal_org_id":org_id,"_id":ObjectId(str(membership_id))})
    return target


def _matrix_cell(org_id, membership, app, entitlement, assignment, app_roles):
    """Return effective and editable state for one member/application cell."""
    client_id = app.get("client_id") or ""
    effective = set(effective_permissions_for_membership(org_id, membership))
    role = role_for_membership(org_id, membership) or {}
    role_key = role.get("key") or membership.get("role") or membership.get("role_key") or "member"
    owner = role_key == "owner" or "*" in effective
    override = ((assignment or {}).get("access_effect") or "inherit").strip().lower()
    if override not in {"inherit","allow","deny"}:
        override="inherit"
    direct_permissions=sorted({p for p in ((assignment or {}).get("direct_permissions") or []) if isinstance(p,str) and p.startswith(client_id + ".")})
    manual_denied = override == "deny" and not owner
    manual_allowed = override == "allow"
    app_admin = f"{client_id}.admin" in effective
    app_access = f"{client_id}.access" in effective
    org_owned = app.get("owner_type") == "organization" and app.get("owner_org_id") == org_id
    permission_granted = owner or (not manual_denied and (app_admin or app_access or org_owned or manual_allowed))

    entitlement_required = (
        client_id != "syntal"
        and app.get("requires_entitlement", True)
        and not org_owned
    )
    entitled = (not entitlement_required) or entitlement_is_active(entitlement)
    member_active = membership.get("status") == "active"
    app_active = app.get("status", "active") == "active"
    allowed = member_active and app_active and entitled and permission_granted

    assigned_role = app_roles.get((client_id, (assignment or {}).get("app_role_id"))) if assignment else None
    assigned_name = (assigned_role or {}).get("name") or (assigned_role or {}).get("key") or (assignment or {}).get("app_role_id")

    if not member_active:
        label, tone, detail = "Suspended", "blocked", "Organization membership is suspended"
    elif not app_active:
        label, tone, detail = "App suspended", "blocked", "Application is not active"
    elif not entitled:
        label, tone, detail = "Not entitled", "blocked", "Organization entitlement is inactive"
    elif manual_denied:
        label, tone, detail = "Disabled", "blocked", "Disabled specifically for this member"
    elif owner:
        label, tone, detail = "Owner", "on", "Inherited from organization owner"
    elif app_admin:
        label, tone, detail = "Admin", "on", "Effective application administrator permission"
    elif assignment and assigned_name:
        label, tone, detail = "Access", "on", f"Application role: {assigned_name}"
    elif manual_allowed:
        label, tone, detail = "Enabled", "on", "Enabled specifically for this member"
    elif app_access:
        label, tone, detail = "Access", "on", "Effective application access permission"
    elif org_owned:
        label, tone, detail = "Access", "on", "Organization-owned application"
    else:
        label, tone, detail = "No access", "off", "No effective application access permission"

    return {
        "allowed": allowed,
        "label": label,
        "tone": tone,
        "detail": detail,
        "role_key": role_key,
        "owner": owner,
        "app_admin": app_admin,
        "app_access": app_access,
        "entitled": entitled,
        "entitlement_required": entitlement_required,
        "assignment": assignment,
        "assigned_role": assigned_role,
        "access_effect": override,
        "direct_permissions": direct_permissions,
    }


@bp.get("/organizations/<org_id>/access/matrix")
@login_required
def matrix(org_id):
    org,actor_membership=_require_org(org_id)
    memberships=list(db().memberships.find({"syntal_org_id":org_id,"status":{"$in":["active","suspended"]}}).sort("created_at",1))
    users={u.get("syntal_user_id"):u for u in db().users.find({"syntal_user_id":{"$in":[m.get("syntal_user_id") for m in memberships]}})} if memberships else {}
    apps=list(db().applications.find({"status":{"$ne":"deleted"},"client_id":{"$ne":"syntal"}}).sort("name",1))
    entitlements={e.get("application"):e for e in db().organization_entitlements.find({"syntal_org_id":org_id})}

    assignment_rows=list(db().organization_application_memberships.find({"syntal_org_id":org_id,"status":"active"}))
    assignments={}
    for row in assignment_rows:
        membership_id=row.get("membership_id")
        client_id=row.get("client_id")
        if membership_id and client_id:
            assignments[(membership_id,client_id)]=row

    role_rows=list(db().organization_application_roles.find({"syntal_org_id":org_id,"status":"active"}).sort("name",1))
    app_roles={(r.get("client_id"),r.get("app_role_id")):r for r in role_rows if r.get("client_id") and r.get("app_role_id")}
    app_roles_by_client={}
    for role in role_rows:
        app_roles_by_client.setdefault(role.get("client_id"),[]).append(role)
    permission_catalog={app.get("client_id"):_matrix_permission_catalog(org_id,app.get("client_id")) for app in apps}

    matrix_cells={}
    app_counts={app.get("client_id"):0 for app in apps}
    for membership in memberships:
        mids=[membership.get("membership_id"),str(membership.get("_id") or "")]
        for app in apps:
            client_id=app.get("client_id")
            assignment=next((assignments.get((mid,client_id)) for mid in mids if mid and assignments.get((mid,client_id))),None)
            cell=_matrix_cell(org_id,membership,app,entitlements.get(client_id),assignment,app_roles)
            matrix_cells[(str(membership.get("_id")),client_id)]=cell
            if cell["allowed"]:
                app_counts[client_id]=app_counts.get(client_id,0)+1

    return render_template(
        "access/matrix.html",
        title="Access matrix",
        organization=org,
        memberships=memberships,
        users=users,
        applications=apps,
        entitlements=entitlements,
        matrix_cells=matrix_cells,
        app_counts=app_counts,
        app_roles_by_client=app_roles_by_client,
        permission_catalog=permission_catalog,
        can_manage=has_permission("syntal.org_apps.manage",actor_membership,org_id),
    )


@bp.post("/organizations/<org_id>/access/matrix/members/<membership_id>/apps/<client_id>")
@login_required
def update_matrix_member_app(org_id,membership_id,client_id):
    _org,actor_membership=_require_org(org_id)
    if not has_permission("syntal.org_apps.manage",actor_membership,org_id):
        abort(403)

    target=_target_membership(org_id,membership_id)
    if not target or target.get("status") not in {"active","suspended"}:
        abort(404)
    target_role=role_for_membership(org_id,target) or {}
    if (target_role.get("key") or target.get("role") or target.get("role_key")) == "owner":
        abort(409,"Owner application access is protected by organization ownership.")

    app=db().applications.find_one({"client_id":client_id,"status":{"$ne":"deleted"}})
    if not app or client_id == "syntal":
        abort(404)

    effect=(request.form.get("access_effect") or "inherit").strip().lower()
    if effect not in {"inherit","allow","deny"}:
        abort(400,"Invalid access effect")

    allowed_permissions=set(_matrix_permission_catalog(org_id,client_id))
    direct_permissions=sorted(set(request.form.getlist("permissions")))
    if any(permission not in allowed_permissions for permission in direct_permissions):
        abort(400,"Invalid application permission")

    app_role_id=(request.form.get("app_role_id") or "").strip() or None
    if app_role_id:
        app_role=db().organization_application_roles.find_one({
            "syntal_org_id":org_id,
            "client_id":client_id,
            "app_role_id":app_role_id,
            "status":"active",
        })
        if not app_role:
            abort(400,"Invalid application role")

    candidate_membership_ids=[m for m in [target.get("membership_id"),str(target.get("_id") or "")] if m]
    before=db().organization_application_memberships.find_one({
        "syntal_org_id":org_id,
        "client_id":client_id,
        "membership_id":{"$in":candidate_membership_ids},
    }) or {}
    assignment_membership_id=before.get("membership_id") or target.get("membership_id") or str(target.get("_id"))
    query={"syntal_org_id":org_id,"client_id":client_id,"membership_id":assignment_membership_id}
    now=utcnow()
    new_assignment_id=public_id("aam")
    db().organization_application_memberships.update_one(
        query,
        {
            "$setOnInsert":{"app_assignment_id":new_assignment_id,"assignment_id":new_assignment_id,"created_at":now,"created_by":g.user.get("syntal_user_id")},
            "$set":{
                "access_effect":effect,
                "direct_permissions":direct_permissions,
                "app_role_id":app_role_id,
                "status":"active",
                "updated_at":now,
                "updated_by":g.user.get("syntal_user_id"),
            },
        },
        upsert=True,
    )
    bump_policy_version(org_id)
    policy_version=(db().organizations.find_one({"syntal_org_id":org_id},{"authorization_policy_version":1}) or {}).get("authorization_policy_version")
    audit(
        "authorization.matrix_member_application_updated",
        org_id=org_id,
        detail={
            "target_user_id":target.get("syntal_user_id"),
            "membership_id":assignment_membership_id,
            "application":client_id,
            "before_access_effect":before.get("access_effect") or "inherit",
            "after_access_effect":effect,
            "before_app_role_id":before.get("app_role_id"),
            "after_app_role_id":app_role_id,
            "before_direct_permissions":before.get("direct_permissions") or [],
            "after_direct_permissions":direct_permissions,
            "policy_version":policy_version,
        },
    )
    return redirect(url_for("access.matrix",org_id=org_id))

@bp.get("/organizations/<org_id>/access/decisions")
@login_required
def decisions(org_id):
    org,_=_require_org(org_id)
    query={"syntal_org_id":org_id}
    if request.args.get("application"): query["application"]=request.args["application"]
    if request.args.get("allowed") in {"true","false"}: query["allowed"]=request.args["allowed"]=="true"
    rows=list(db().authorization_decisions.find(query).sort("created_at",-1).limit(250))
    return render_template("access/decisions.html",title="Authorization decisions",organization=org,decisions=rows)

@bp.get("/organizations/<org_id>/access/audit")
@login_required
def audit_log(org_id):
    org,_=_require_org(org_id)
    query={"syntal_org_id":org_id}
    if request.args.get("event"): query["event"]={"$regex":request.args["event"],"$options":"i"}
    rows=list(db().audit_events.find(query).sort("created_at",-1).limit(300))
    return render_template("access/audit.html",title="Audit log",organization=org,audit_events=rows)
