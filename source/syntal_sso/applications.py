from flask import Blueprint, abort, flash, g, redirect, render_template, request, url_for
import hashlib, secrets
from .db import db
from .security import login_required
from .acl import (
    audit, bump_policy_version, effective_permissions_for_membership, entitlement_is_active,
    has_permission, require_permission, role_for_membership, application_distributable,
    application_owned_by_org, application_requires_entitlement_for_org,
    application_visible_to_org,
)
from .util import public_id, utcnow
from .acl import application_access_override
from .lifecycle import serialize_org,require_recent
import re

bp = Blueprint("applications", __name__)


def _require_org(org_id, permission="syntal.org_apps.read"):
    uid=g.user.get("syntal_user_id") or str(g.user.get("_id"))
    org=db().organizations.find_one({"syntal_org_id":org_id,"status":"active"})
    membership=db().memberships.find_one({"syntal_org_id":org_id,"syntal_user_id":uid,"status":"active"})
    if not org or not membership: abort(404)
    g.organization,g.membership=org,membership
    if permission and not has_permission(permission,membership,org_id): abort(403)
    return org,membership


def _application(org_id, client_id):
    app=db().applications.find_one({"client_id":client_id,"status":{"$ne":"deleted"}})
    if not app or not application_visible_to_org(app, org_id):
        abort(404)
    return app


def _catalog_applications(org_id):
    return [
        app for app in db().applications.find({"status":{"$ne":"deleted"}}).sort("name",1)
        if application_visible_to_org(app, org_id)
    ]


def _require_client_owner(org_id, app):
    if not application_owned_by_org(app, org_id):
        abort(403, "Only the application owner can change global client configuration.")


def _entitlement_state(org_id, app, entitlement=None):
    owned=application_owned_by_org(app,org_id)
    entitlement_required=application_requires_entitlement_for_org(app,org_id)
    registry_active=app.get("status")=="active"
    distributable=application_distributable(app)
    enabled=registry_active and ((not entitlement_required) or entitlement_is_active(entitlement))
    registration_supported=(
        entitlement_required
        and registry_active
        and app.get("organization_registration_enabled",True) is not False
        and (app.get("owner_type")!="organization" or distributable)
    )
    return {
        "owned":owned,"distributable":distributable,
        "entitlement_required":entitlement_required,"enabled":enabled,
        "registration_supported":registration_supported,"registry_active":registry_active,
    }


def _can_register(org_id, membership):
    return has_permission("syntal.org_apps.register",membership,org_id) or has_permission("syntal.org_apps.manage",membership,org_id)


def _return_after_app_action(org_id, client_id):
    if request.form.get("return_to")=="overview":
        return redirect(url_for("applications.app_overview",org_id=org_id,client_id=client_id))
    return redirect(url_for("applications.index",org_id=org_id))


def _grant_enabling_actor_access(org_id, membership, client_id):
    perms=set(effective_permissions_for_membership(org_id,membership))
    if application_access_override(org_id,membership,client_id)=="deny":return False
    if "*" in perms or f"{client_id}.access" in perms or f"{client_id}.admin" in perms:
        return False
    membership_id=membership.get("membership_id") or str(membership.get("_id") or "")
    if not membership_id:
        return False
    now=utcnow(); assignment_id=public_id("aam")
    db().organization_application_memberships.update_one(
        {"syntal_org_id":org_id,"client_id":client_id,"membership_id":membership_id},
        {
            "$setOnInsert":{"app_assignment_id":assignment_id,"assignment_id":assignment_id,"created_at":now},
            "$set":{"access_effect":"allow","status":"active","updated_at":now,"updated_by":g.user.get("syntal_user_id")},
        },
        upsert=True,
    )
    return True

@bp.route("/organizations/<org_id>/applications",methods=["GET","POST"])
@login_required
@serialize_org
def index(org_id):
    org,membership=_require_org(org_id)
    if request.method=="POST":
        require_permission("syntal.org_apps.manage")
        name=(request.form.get("name") or "").strip(); client_id=(request.form.get("client_id") or "").strip().lower()
        if not name or not re.fullmatch(r"[a-z][a-z0-9_-]{1,79}",client_id): abort(400)
        if db().applications.find_one({"client_id":client_id}): abort(409,"Client ID already exists")
        secret=secrets.token_urlsafe(32)
        doc={"client_id":client_id,"name":name,"display_name":name,"description":(request.form.get("description") or "").strip(),"owner_type":"organization","owner_org_id":org_id,"distribution_scope":"private","organization_registration_enabled":False,"status":"active","oidc_enabled":True,"client_type":"confidential","client_secret_hash":hashlib.sha256(secret.encode()).hexdigest(),"redirect_uris":[],"post_logout_redirect_uris":[],"scopes":["openid","profile","email","organization","permissions","offline_access"],"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"pkce_required":True,"api_access_enabled":False,"created_at":utcnow(),"created_by":g.user.get("syntal_user_id")}
        db().applications.insert_one(doc); audit("organization_application.created",org_id=org_id,detail={"client_id":client_id}); bump_policy_version(org_id)
        flash(f"Application created. Store this client secret now: {secret}","secret")
        return redirect(url_for("applications.detail",org_id=org_id,client_id=client_id))
    apps=_catalog_applications(org_id)
    ents={e.get("application"):e for e in db().organization_entitlements.find({"syntal_org_id":org_id})}
    app_states={app.get("client_id"):_entitlement_state(org_id,app,ents.get(app.get("client_id"))) for app in apps}
    return render_template("applications/index.html",title="Applications",organization=org,applications=apps,entitlements=ents,app_states=app_states,can_manage=has_permission("syntal.org_apps.manage",membership,org_id),can_register=_can_register(org_id,membership))

@bp.post("/organizations/<org_id>/applications/<client_id>/enable")
@login_required
@serialize_org
def enable_application(org_id,client_id):
    org,membership=_require_org(org_id)
    if not _can_register(org_id,membership): abort(403)
    app=_application(org_id,client_id)
    entitlement=db().organization_entitlements.find_one({"syntal_org_id":org_id,"application":client_id})
    state=_entitlement_state(org_id,app,entitlement)
    if not state["entitlement_required"]:
        flash("This application is already available to the organization.","success")
        return _return_after_app_action(org_id,client_id)
    if not state["registration_supported"]:
        abort(403,"This application cannot be enabled by the organization.")
    uid=g.user.get("syntal_user_id") or str(g.user.get("_id"))
    now=utcnow(); existing=entitlement or {}
    db().organization_entitlements.update_one(
        {"syntal_org_id":org_id,"application":client_id},
        {
            "$setOnInsert":{
                "entitlement_id":public_id("ent"),"syntal_org_id":org_id,"application":client_id,
                "billing_status":existing.get("billing_status") or "inactive",
                "source":existing.get("source") or "applications_ui",
                "created_at":now,"created_by":uid,
            },
            "$set":{
                "status":"active","manual_override":"active","registration_channel":"applications_ui",
                "registered_at":now,"registered_by":uid,"updated_at":now,"updated_by":uid,
            },
        },
        upsert=True,
    )
    self_access_granted=_grant_enabling_actor_access(org_id,membership,client_id)
    bump_policy_version(org_id)
    audit("organization_application.enabled",org_id=org_id,user_id=uid,detail={"client_id":client_id,"self_access_granted":self_access_granted})
    flash(f"{app.get('name') or client_id} is enabled for {org.get('display_name') or org.get('name') or 'this organization'}.","success")
    return _return_after_app_action(org_id,client_id)


@bp.post("/organizations/<org_id>/applications/<client_id>/disable")
@login_required
@serialize_org
def disable_application(org_id,client_id):
    org,membership=_require_org(org_id)
    if not _can_register(org_id,membership): abort(403)
    app=_application(org_id,client_id)
    entitlement=db().organization_entitlements.find_one({"syntal_org_id":org_id,"application":client_id})
    state=_entitlement_state(org_id,app,entitlement)
    if not state["entitlement_required"]:
        abort(400,"This application is organization-owned or does not require an entitlement.")
    uid=g.user.get("syntal_user_id") or str(g.user.get("_id")); now=utcnow()
    db().organization_entitlements.update_one(
        {"syntal_org_id":org_id,"application":client_id},
        {"$set":{"status":"inactive","manual_override":"inactive","registration_channel":"applications_ui","disabled_at":now,"disabled_by":uid,"updated_at":now,"updated_by":uid}},
        upsert=False,
    )
    bump_policy_version(org_id)
    audit("organization_application.disabled",org_id=org_id,user_id=uid,detail={"client_id":client_id})
    flash(f"{app.get('name') or client_id} is disabled for this organization. Member assignments were preserved.","success")
    return _return_after_app_action(org_id,client_id)


@bp.get("/organizations/<org_id>/applications/<client_id>")
@login_required
def detail(org_id,client_id):
    _require_org(org_id); app=_application(org_id,client_id)
    return redirect(url_for("applications.app_overview",org_id=org_id,client_id=client_id))

@bp.get("/organizations/<org_id>/applications/<client_id>/overview")
@login_required
def app_overview(org_id,client_id):
    org,membership=_require_org(org_id); app=_application(org_id,client_id)
    ent=db().organization_entitlements.find_one({"syntal_org_id":org_id,"application":client_id})
    state=_entitlement_state(org_id,app,ent)
    role_count=db().organization_application_roles.count_documents({"syntal_org_id":org_id,"client_id":client_id,"status":"active"})
    member_count=db().organization_application_memberships.count_documents({"syntal_org_id":org_id,"client_id":client_id,"status":"active"})
    perm_count=db().organization_application_permissions.count_documents({"syntal_org_id":org_id,"client_id":client_id,"status":"active"})
    return render_template("applications/detail_overview.html",title=app.get("name",client_id),organization=org,application=app,entitlement=ent,app_state=state,can_register=_can_register(org_id,membership),role_count=role_count,member_count=member_count,perm_count=perm_count)

@bp.route("/organizations/<org_id>/applications/<client_id>/configuration",methods=["GET","POST"])
@login_required
@serialize_org
def app_configuration(org_id,client_id):
    org,membership=_require_org(org_id); app=_application(org_id,client_id)
    owner_controls=application_owned_by_org(app,org_id)
    can_manage=has_permission("syntal.org_apps.manage",membership,org_id) and owner_controls
    if request.method=="POST":
        require_permission("syntal.org_apps.manage")
        _require_client_owner(org_id,app)
        required=require_recent()
        if required:return required
        distribution_scope=(request.form.get("distribution_scope") or "private").strip()
        if distribution_scope not in {"private","organizations"}: distribution_scope="private"
        fields={
            "name":(request.form.get("name") or app.get("name") or client_id).strip(),
            "description":(request.form.get("description") or "").strip(),
            "status":request.form.get("status") if request.form.get("status") in {"active","suspended"} else app.get("status","active"),
            "require_aal2":bool(request.form.get("require_aal2")),
            "api_access_enabled":bool(request.form.get("api_access_enabled")),
            "distribution_scope":distribution_scope,
            "organization_registration_enabled":distribution_scope=="organizations",
        }
        db().applications.update_one({"_id":app["_id"]},{"$set":{**fields,"updated_at":utcnow()}}); bump_policy_version(org_id); audit("organization_application.updated",org_id=org_id,detail={"client_id":client_id,"fields":list(fields),"distribution_scope":distribution_scope})
        return redirect(url_for("applications.app_configuration",org_id=org_id,client_id=client_id))
    return render_template("applications/detail_configuration.html",title=f"{app.get('name',client_id)} · Configuration",organization=org,application=app,can_manage=can_manage,owner_controls=owner_controls)

@bp.route("/organizations/<org_id>/applications/<client_id>/permissions",methods=["GET","POST"])
@login_required
@serialize_org
def app_permissions(org_id,client_id):
    org,_=_require_org(org_id); app=_application(org_id,client_id)
    if request.method=="POST":
        require_permission("syntal.org_apps.manage")
        suffix=(request.form.get("suffix") or "").strip().lower().replace(" ","_")
        name=(request.form.get("name") or suffix).strip()
        if not re.fullmatch(r"[a-z][a-z0-9_.-]{0,100}",suffix): abort(400)
        permission=f"{client_id}.{suffix}"
        db().organization_application_permissions.update_one({"syntal_org_id":org_id,"client_id":client_id,"permission":permission},{"$setOnInsert":{"permission_id":public_id("perm"),"created_at":utcnow(),"created_by":g.user.get("syntal_user_id")},"$set":{"name":name,"description":(request.form.get("description") or "").strip(),"status":"active"}},upsert=True)
        bump_policy_version(org_id); audit("organization_application.permission_created",org_id=org_id,detail={"client_id":client_id,"permission":permission})
        return redirect(url_for("applications.app_permissions",org_id=org_id,client_id=client_id))
    perms=list(db().organization_application_permissions.find({"syntal_org_id":org_id,"client_id":client_id,"status":"active"}).sort("permission",1))
    return render_template("applications/detail_permissions.html",title=f"{app.get('name',client_id)} · Permissions",organization=org,application=app,permissions=perms,can_manage=has_permission("syntal.org_apps.manage"))

@bp.route("/organizations/<org_id>/applications/<client_id>/roles",methods=["GET","POST"])
@login_required
@serialize_org
def app_roles(org_id,client_id):
    org,_=_require_org(org_id); app=_application(org_id,client_id)
    perms=list(db().organization_application_permissions.find({"syntal_org_id":org_id,"client_id":client_id,"status":"active"}).sort("permission",1))
    if request.method=="POST":
        require_permission("syntal.org_apps.manage")
        name=(request.form.get("name") or "").strip(); selected=request.form.getlist("permissions")
        if not name: abort(400)
        allowed={p['permission'] for p in perms if isinstance(p.get('permission'),str) and p['permission'].startswith(client_id+'.')}|{client_id+'.access',client_id+'.admin'}
        if any(p not in allowed for p in selected):abort(400,'Invalid application permission')
        role={"app_role_id":public_id("arole"),"syntal_org_id":org_id,"client_id":client_id,"key":name.lower().replace(" ","_"),"name":name,"description":(request.form.get("description") or "").strip(),"permissions":selected,"status":"active","created_at":utcnow(),"created_by":g.user.get("syntal_user_id")}
        db().organization_application_roles.insert_one(role); bump_policy_version(org_id); audit("organization_application.role_created",org_id=org_id,detail={"client_id":client_id,"app_role_id":role["app_role_id"]})
        return redirect(url_for("applications.app_roles",org_id=org_id,client_id=client_id))
    roles=list(db().organization_application_roles.find({"syntal_org_id":org_id,"client_id":client_id,"status":"active"}).sort("name",1))
    return render_template("applications/detail_roles.html",title=f"{app.get('name',client_id)} · Roles",organization=org,application=app,roles=roles,permissions=perms,can_manage=has_permission("syntal.org_apps.manage"))

@bp.route("/organizations/<org_id>/applications/<client_id>/members",methods=["GET","POST"])
@login_required
@serialize_org
def app_members(org_id,client_id):
    org,_=_require_org(org_id); app=_application(org_id,client_id)
    if request.method=="POST":
        require_permission("syntal.org_apps.manage")
        membership_id=request.form.get("membership_id"); app_role_id=request.form.get("app_role_id")
        if not membership_id: abort(400)
        target=db().memberships.find_one({'syntal_org_id':org_id,'membership_id':membership_id,'status':{'$in':['active','suspended']}})
        if not target:abort(404)
        if (role_for_membership(org_id,target) or {}).get('key')=='owner':abort(409,'Owner access is protected.')
        if app_role_id:
            app_role=db().organization_application_roles.find_one({'syntal_org_id':org_id,'client_id':client_id,'app_role_id':app_role_id,'status':'active'})
            if not app_role:abort(400,'Application role does not belong to this app.')
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
@serialize_org
def app_oauth(org_id,client_id):
    org,_=_require_org(org_id); app=_application(org_id,client_id)
    _require_client_owner(org_id,app)
    if request.method=="POST":
        require_permission("syntal.org_apps.manage")
        required=require_recent()
        if required:return required
        redirects=[x.strip() for x in (request.form.get("redirect_uris") or "").splitlines() if x.strip()]
        logouts=[x.strip() for x in (request.form.get("post_logout_redirect_uris") or "").splitlines() if x.strip()]
        from urllib.parse import urlsplit
        for uri in redirects+logouts:
            parsed=urlsplit(uri)
            if parsed.fragment or parsed.username or parsed.password or not parsed.hostname or (parsed.scheme!='https' and not (parsed.scheme=='http' and parsed.hostname in {'localhost','127.0.0.1','::1'})):abort(400,'Redirects must use HTTPS or a loopback HTTP address, with no fragment or credentials.')
        scopes=request.form.getlist("scopes") or app.get("scopes") or []
        from .oidc import SUPPORTED_SCOPES
        if not set(scopes).issubset(SUPPORTED_SCOPES):abort(400,'Invalid scope')
        db().applications.update_one({"_id":app["_id"]},{"$set":{"redirect_uris":redirects,"post_logout_redirect_uris":logouts,"scopes":scopes,"pkce_required":bool(request.form.get("pkce_required")),"updated_at":utcnow()}}); audit("organization_application.oauth_updated",org_id=org_id,detail={"client_id":client_id}); return redirect(url_for("applications.app_oauth",org_id=org_id,client_id=client_id))
    return render_template("applications/detail_oauth.html",title=f"{app.get('name',client_id)} · OAuth",organization=org,application=app,can_manage=has_permission("syntal.org_apps.manage"))

@bp.post("/organizations/<org_id>/applications/<client_id>/rotate-secret")
@login_required
@serialize_org
def rotate_secret(org_id,client_id):
    _require_org(org_id); require_permission("syntal.org_apps.manage"); app=_application(org_id,client_id); _require_client_owner(org_id,app)
    required=require_recent()
    if required:return required
    secret=secrets.token_urlsafe(32); digest=hashlib.sha256(secret.encode()).hexdigest()
    db().applications.update_one({"_id":app["_id"]},{"$set":{"client_secret_hash":digest,"secret_rotated_at":utcnow()}}); audit("organization_application.secret_rotated",org_id=org_id,detail={"client_id":client_id}); flash(f"New client secret: {secret}","secret")
    return redirect(url_for("applications.app_secrets",org_id=org_id,client_id=client_id))

@bp.get("/organizations/<org_id>/applications/<client_id>/secrets")
@login_required
def app_secrets(org_id,client_id):
    org,_=_require_org(org_id); app=_application(org_id,client_id); _require_client_owner(org_id,app)
    return render_template("applications/detail_secrets.html",title=f"{app.get('name',client_id)} · Secrets",organization=org,application=app,can_manage=has_permission("syntal.org_apps.manage"))

@bp.route("/organizations/<org_id>/applications/security",methods=["GET","POST"])
@login_required
@serialize_org
def security(org_id):
    org,_=_require_org(org_id)
    policy=org.get("application_security_policy") or org.get("security_policy") or {}
    if request.method=="POST":
        require_permission("syntal.org_apps.manage")
        required=require_recent()
        if required:return required
        try:age=int(request.form.get('max_age_seconds') or 0)
        except ValueError:abort(400,'Invalid authentication age')
        if age<0 or age>86400:abort(400,'Authentication age must be 0 to 86400 seconds.')
        new={"require_aal2":bool(request.form.get("require_aal2")),"max_age_seconds":age,"updated_at":utcnow()}
        db().organizations.update_one({"_id":org["_id"]},{"$set":{"application_security_policy":new,"updated_at":utcnow()}}); bump_policy_version(org_id); audit("organization.security_policy_updated",org_id=org_id,detail=new)
        return redirect(url_for("applications.security",org_id=org_id))
    return render_template("applications/security.html",title="Application security",organization=org,policy=policy,can_manage=has_permission("syntal.org_apps.manage"))

@bp.get("/developers")
@login_required
def developers():
    rows=_catalog_applications(g.organization["syntal_org_id"]) if g.organization else []
    return render_template("applications/developers.html",title="Developer applications",applications=rows)
