from flask import Blueprint, abort, flash, g, redirect, render_template, request, url_for
import hashlib, secrets
from .db import db
from .security import login_required
from .acl import audit, bump_policy_version, has_permission, require_permission
from .util import public_id, utcnow

bp = Blueprint("applications", __name__)


def _require_org(org_id, permission="syntal.org_apps.read"):
    uid=g.user.get("syntal_user_id") or str(g.user.get("_id"))
    org=db().organizations.find_one({"syntal_org_id":org_id,"status":{"$ne":"deleted"}})
    membership=db().memberships.find_one({"syntal_org_id":org_id,"syntal_user_id":uid,"status":"active"})
    if not org or not membership: abort(404)
    g.organization,g.membership=org,membership
    if permission and not has_permission(permission,membership,org_id): abort(403)
    return org,membership


def _application(org_id, client_id):
    app=db().applications.find_one({"client_id":client_id,"owner_type":"organization","owner_org_id":org_id})
    if not app:
        app=db().applications.find_one({"client_id":client_id,"status":{"$ne":"deleted"}})
    if not app: abort(404)
    return app

@bp.route("/organizations/<org_id>/applications",methods=["GET","POST"])
@login_required
def index(org_id):
    org,_=_require_org(org_id)
    if request.method=="POST":
        require_permission("syntal.org_apps.manage")
        name=(request.form.get("name") or "").strip(); client_id=(request.form.get("client_id") or "").strip().lower()
        if not name or not client_id: abort(400)
        if db().applications.find_one({"client_id":client_id}): abort(409,"Client ID already exists")
        secret=secrets.token_urlsafe(32)
        doc={"client_id":client_id,"name":name,"display_name":name,"description":(request.form.get("description") or "").strip(),"owner_type":"organization","owner_org_id":org_id,"status":"active","oidc_enabled":True,"client_type":"confidential","client_secret_hash":hashlib.sha256(secret.encode()).hexdigest(),"redirect_uris":[],"post_logout_redirect_uris":[],"scopes":["openid","profile","email","organization","permissions","offline_access"],"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"created_at":utcnow(),"created_by":g.user.get("syntal_user_id")}
        db().applications.insert_one(doc); audit("organization_application.created",org_id=org_id,detail={"client_id":client_id}); bump_policy_version(org_id)
        flash(f"Application created. Store this client secret now: {secret}","secret")
        return redirect(url_for("applications.detail",org_id=org_id,client_id=client_id))
    apps=list(db().applications.find({"status":{"$ne":"deleted"},"$or":[{"owner_type":"organization","owner_org_id":org_id},{"owner_type":"syntal"},{"owner_type":{"$exists":False}}]}).sort("name",1))
    ents={e.get("application"):e for e in db().organization_entitlements.find({"syntal_org_id":org_id})}
    return render_template("applications/index.html",title="Applications",organization=org,applications=apps,entitlements=ents,can_manage=has_permission("syntal.org_apps.manage"))

@bp.get("/organizations/<org_id>/applications/<client_id>")
@login_required
def detail(org_id,client_id):
    _require_org(org_id); app=_application(org_id,client_id)
    return redirect(url_for("applications.app_overview",org_id=org_id,client_id=client_id))

@bp.get("/organizations/<org_id>/applications/<client_id>/overview")
@login_required
def app_overview(org_id,client_id):
    org,_=_require_org(org_id); app=_application(org_id,client_id)
    ent=db().organization_entitlements.find_one({"syntal_org_id":org_id,"application":client_id})
    role_count=db().organization_application_roles.count_documents({"syntal_org_id":org_id,"client_id":client_id,"status":"active"})
    member_count=db().organization_application_memberships.count_documents({"syntal_org_id":org_id,"client_id":client_id,"status":"active"})
    perm_count=db().organization_application_permissions.count_documents({"syntal_org_id":org_id,"client_id":client_id,"status":"active"})
    return render_template("applications/detail_overview.html",title=app.get("name",client_id),organization=org,application=app,entitlement=ent,role_count=role_count,member_count=member_count,perm_count=perm_count)

@bp.route("/organizations/<org_id>/applications/<client_id>/configuration",methods=["GET","POST"])
@login_required
def app_configuration(org_id,client_id):
    org,_=_require_org(org_id); app=_application(org_id,client_id)
    if request.method=="POST":
        require_permission("syntal.org_apps.manage")
        fields={"name":(request.form.get("name") or app.get("name") or client_id).strip(),"description":(request.form.get("description") or "").strip(),"status":request.form.get("status") if request.form.get("status") in {"active","suspended"} else app.get("status","active"),"require_aal2":bool(request.form.get("require_aal2"))}
        db().applications.update_one({"_id":app["_id"]},{"$set":{**fields,"updated_at":utcnow()}}); bump_policy_version(org_id); audit("organization_application.updated",org_id=org_id,detail={"client_id":client_id,"fields":list(fields)})
        return redirect(url_for("applications.app_configuration",org_id=org_id,client_id=client_id))
    return render_template("applications/detail_configuration.html",title=f"{app.get('name',client_id)} · Configuration",organization=org,application=app,can_manage=has_permission("syntal.org_apps.manage"))

@bp.route("/organizations/<org_id>/applications/<client_id>/permissions",methods=["GET","POST"])
@login_required
def app_permissions(org_id,client_id):
    org,_=_require_org(org_id); app=_application(org_id,client_id)
    if request.method=="POST":
        require_permission("syntal.org_apps.manage")
        suffix=(request.form.get("suffix") or "").strip().lower().replace(" ","_")
        name=(request.form.get("name") or suffix).strip()
        if not suffix: abort(400)
        permission=f"{client_id}.{suffix}"
        db().organization_application_permissions.update_one({"syntal_org_id":org_id,"client_id":client_id,"permission":permission},{"$setOnInsert":{"permission_id":public_id("perm"),"created_at":utcnow(),"created_by":g.user.get("syntal_user_id")},"$set":{"name":name,"description":(request.form.get("description") or "").strip(),"status":"active"}},upsert=True)
        bump_policy_version(org_id); audit("organization_application.permission_created",org_id=org_id,detail={"client_id":client_id,"permission":permission})
        return redirect(url_for("applications.app_permissions",org_id=org_id,client_id=client_id))
    perms=list(db().organization_application_permissions.find({"syntal_org_id":org_id,"client_id":client_id,"status":"active"}).sort("permission",1))
    return render_template("applications/detail_permissions.html",title=f"{app.get('name',client_id)} · Permissions",organization=org,application=app,permissions=perms,can_manage=has_permission("syntal.org_apps.manage"))

@bp.route("/organizations/<org_id>/applications/<client_id>/roles",methods=["GET","POST"])
@login_required
def app_roles(org_id,client_id):
    org,_=_require_org(org_id); app=_application(org_id,client_id)
    perms=list(db().organization_application_permissions.find({"syntal_org_id":org_id,"client_id":client_id,"status":"active"}).sort("permission",1))
    if request.method=="POST":
        require_permission("syntal.org_apps.manage")
        name=(request.form.get("name") or "").strip(); selected=request.form.getlist("permissions")
        if not name: abort(400)
        role={"app_role_id":public_id("arole"),"syntal_org_id":org_id,"client_id":client_id,"key":name.lower().replace(" ","_"),"name":name,"description":(request.form.get("description") or "").strip(),"permissions":selected,"status":"active","created_at":utcnow(),"created_by":g.user.get("syntal_user_id")}
        db().organization_application_roles.insert_one(role); bump_policy_version(org_id); audit("organization_application.role_created",org_id=org_id,detail={"client_id":client_id,"app_role_id":role["app_role_id"]})
        return redirect(url_for("applications.app_roles",org_id=org_id,client_id=client_id))
    roles=list(db().organization_application_roles.find({"syntal_org_id":org_id,"client_id":client_id,"status":"active"}).sort("name",1))
    return render_template("applications/detail_roles.html",title=f"{app.get('name',client_id)} · Roles",organization=org,application=app,roles=roles,permissions=perms,can_manage=has_permission("syntal.org_apps.manage"))

@bp.route("/organizations/<org_id>/applications/<client_id>/members",methods=["GET","POST"])
@login_required
def app_members(org_id,client_id):
    org,_=_require_org(org_id); app=_application(org_id,client_id)
    if request.method=="POST":
        require_permission("syntal.org_apps.manage")
        membership_id=request.form.get("membership_id"); app_role_id=request.form.get("app_role_id")
        if not membership_id: abort(400)
        if app_role_id:
            new_assignment_id=public_id("aam")
            db().organization_application_memberships.update_one({"syntal_org_id":org_id,"client_id":client_id,"membership_id":membership_id},{"$setOnInsert":{"app_assignment_id":new_assignment_id,"assignment_id":new_assignment_id,"created_at":utcnow()},"$set":{"app_role_id":app_role_id,"status":"active","updated_at":utcnow(),"updated_by":g.user.get("syntal_user_id")}},upsert=True)
        else:
            db().organization_application_memberships.update_one({"syntal_org_id":org_id,"client_id":client_id,"membership_id":membership_id},{"$set":{"status":"revoked","updated_at":utcnow()}})
        bump_policy_version(org_id); audit("organization_application.member_role_updated",org_id=org_id,detail={"client_id":client_id,"membership_id":membership_id,"app_role_id":app_role_id})
        return redirect(url_for("applications.app_members",org_id=org_id,client_id=client_id))
    memberships=list(db().memberships.find({"syntal_org_id":org_id,"status":"active"}).sort("created_at",1)); users={u.get("syntal_user_id"):u for u in db().users.find({"syntal_user_id":{"$in":[m.get("syntal_user_id") for m in memberships]}})} if memberships else {}
    roles=list(db().organization_application_roles.find({"syntal_org_id":org_id,"client_id":client_id,"status":"active"}).sort("name",1)); assignments={a.get("membership_id"):a for a in db().organization_application_memberships.find({"syntal_org_id":org_id,"client_id":client_id,"status":"active"})}
    return render_template("applications/detail_members.html",title=f"{app.get('name',client_id)} · Members",organization=org,application=app,memberships=memberships,users=users,roles=roles,assignments=assignments,can_manage=has_permission("syntal.org_apps.manage"))

@bp.route("/organizations/<org_id>/applications/<client_id>/oauth",methods=["GET","POST"])
@login_required
def app_oauth(org_id,client_id):
    org,_=_require_org(org_id); app=_application(org_id,client_id)
    if request.method=="POST":
        require_permission("syntal.org_apps.manage")
        redirects=[x.strip() for x in (request.form.get("redirect_uris") or "").splitlines() if x.strip()]
        logouts=[x.strip() for x in (request.form.get("post_logout_redirect_uris") or "").splitlines() if x.strip()]
        scopes=request.form.getlist("scopes") or app.get("scopes") or []
        db().applications.update_one({"_id":app["_id"]},{"$set":{"redirect_uris":redirects,"post_logout_redirect_uris":logouts,"scopes":scopes,"pkce_required":bool(request.form.get("pkce_required")),"updated_at":utcnow()}}); audit("organization_application.oauth_updated",org_id=org_id,detail={"client_id":client_id}); return redirect(url_for("applications.app_oauth",org_id=org_id,client_id=client_id))
    return render_template("applications/detail_oauth.html",title=f"{app.get('name',client_id)} · OAuth",organization=org,application=app,can_manage=has_permission("syntal.org_apps.manage"))

@bp.post("/organizations/<org_id>/applications/<client_id>/rotate-secret")
@login_required
def rotate_secret(org_id,client_id):
    _require_org(org_id); require_permission("syntal.org_apps.manage"); app=_application(org_id,client_id)
    secret=secrets.token_urlsafe(32); digest=hashlib.sha256(secret.encode()).hexdigest()
    db().applications.update_one({"_id":app["_id"]},{"$set":{"client_secret_hash":digest,"secret_rotated_at":utcnow()}}); audit("organization_application.secret_rotated",org_id=org_id,detail={"client_id":client_id}); flash(f"New client secret: {secret}","secret")
    return redirect(url_for("applications.app_secrets",org_id=org_id,client_id=client_id))

@bp.get("/organizations/<org_id>/applications/<client_id>/secrets")
@login_required
def app_secrets(org_id,client_id):
    org,_=_require_org(org_id); app=_application(org_id,client_id)
    return render_template("applications/detail_secrets.html",title=f"{app.get('name',client_id)} · Secrets",organization=org,application=app,can_manage=has_permission("syntal.org_apps.manage"))

@bp.route("/organizations/<org_id>/applications/security",methods=["GET","POST"])
@login_required
def security(org_id):
    org,_=_require_org(org_id)
    policy=org.get("application_security_policy") or org.get("security_policy") or {}
    if request.method=="POST":
        require_permission("syntal.org_apps.manage")
        new={"require_aal2":bool(request.form.get("require_aal2")),"max_age_seconds":int(request.form.get("max_age_seconds") or 0),"updated_at":utcnow()}
        db().organizations.update_one({"_id":org["_id"]},{"$set":{"application_security_policy":new,"updated_at":utcnow()}}); bump_policy_version(org_id); audit("organization.security_policy_updated",org_id=org_id,detail=new)
        return redirect(url_for("applications.security",org_id=org_id))
    return render_template("applications/security.html",title="Application security",organization=org,policy=policy,can_manage=has_permission("syntal.org_apps.manage"))

@bp.get("/developers")
@login_required
def developers():
    rows=list(db().applications.find({"status":{"$ne":"deleted"}}).sort("name",1))
    return render_template("applications/developers.html",title="Developer applications",applications=rows)
