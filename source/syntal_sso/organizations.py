from flask import Blueprint, abort, current_app, flash, g, redirect, render_template, request, session, url_for
from .db import db
from .security import login_required
from .acl import audit, bump_policy_version, has_permission, require_permission, role_for_membership
from .context import memberships_for_user
from .util import public_id, utcnow
from .mailer import send_invitation_email

bp = Blueprint("organizations", __name__)


def _require_org(org_id):
    if not g.user:
        abort(401)
    uid = g.user.get("syntal_user_id") or str(g.user.get("_id"))
    org = db().organizations.find_one({"syntal_org_id": org_id, "status": {"$ne":"deleted"}})
    membership = db().memberships.find_one({"syntal_org_id": org_id, "syntal_user_id": uid, "status": "active"})
    if not org or not membership:
        abort(404)
    g.organization, g.membership = org, membership
    return org, membership


def _user_map(memberships):
    ids = [m.get("syntal_user_id") for m in memberships if m.get("syntal_user_id")]
    return {u.get("syntal_user_id"):u for u in db().users.find({"syntal_user_id":{"$in":ids}})} if ids else {}



def _invitation_accept_url(invitation_id):
    base = current_app.config.get("PUBLIC_BASE_URL", "https://sso.syntal.pro").rstrip("/")
    return base + url_for("organizations.accept_invitation", invitation_id=invitation_id)


def _deliver_invitation(org, inv, *, inviter_name):
    result = send_invitation_email(
        to=inv.get("email"),
        organization_name=org.get("display_name") or org.get("name") or "Syntal workspace",
        role_name=inv.get("role") or "member",
        inviter_name=inviter_name or "A workspace administrator",
        accept_url=_invitation_accept_url(inv["invitation_id"]),
    )
    now = utcnow()
    if result.get("ok"):
        db().organization_invitations.update_one(
            {"_id": inv["_id"]},
            {"$set": {"delivery_status": "sent", "last_sent_at": now, "updated_at": now}, "$unset": {"last_delivery_error": ""}},
        )
    else:
        db().organization_invitations.update_one(
            {"_id": inv["_id"]},
            {"$set": {"delivery_status": "failed", "last_delivery_error": (result.get("error") or "Delivery failed")[:500], "updated_at": now}},
        )
    return result


def _roles(org_id):
    return list(db().organization_roles.find({"syntal_org_id":org_id,"status":{"$ne":"deleted"}}).sort([("rank",-1),("name",1)]))

@bp.get("/")
@login_required
def dashboard():
    memberships = memberships_for_user()
    if g.organization:
        org_id = g.organization["syntal_org_id"]
        stats = {
            "members": db().memberships.count_documents({"syntal_org_id":org_id,"status":"active"}),
            "pending_invites": db().organization_invitations.count_documents({"syntal_org_id":org_id,"status":"pending"}),
            "applications": db().organization_entitlements.count_documents({"syntal_org_id":org_id,"status":{"$in":["active","trial","grace"]}}),
            "roles": db().organization_roles.count_documents({"syntal_org_id":org_id,"status":{"$ne":"deleted"}}),
        }
        activity = list(db().audit_events.find({"syntal_org_id":org_id}).sort("created_at",-1).limit(8))
    else:
        stats, activity = {}, []
    return render_template("dashboard.html", title="Dashboard", memberships=memberships, stats=stats, activity=activity)

@bp.get("/organizations")
@login_required
def index():
    return render_template("organizations/index.html", title="Organizations", memberships=memberships_for_user())

@bp.post("/organizations/<org_id>/select")
@login_required
def select(org_id):
    _require_org(org_id)
    session["org_id"] = org_id
    return redirect(request.form.get("next") or url_for("organizations.overview", org_id=org_id))

@bp.get("/organizations/<org_id>")
@login_required
def overview(org_id):
    org, membership = _require_org(org_id)
    recent = list(db().audit_events.find({"syntal_org_id":org_id}).sort("created_at",-1).limit(8))
    stats = {
        "members":db().memberships.count_documents({"syntal_org_id":org_id,"status":"active"}),
        "suspended":db().memberships.count_documents({"syntal_org_id":org_id,"status":"suspended"}),
        "invitations":db().organization_invitations.count_documents({"syntal_org_id":org_id,"status":"pending"}),
        "applications":db().organization_entitlements.count_documents({"syntal_org_id":org_id,"status":{"$in":["active","trial","grace"]}}),
    }
    return render_template("organizations/overview.html", title=org.get("display_name") or org.get("name") or "Organization", organization=org, stats=stats, recent=recent, membership=membership)

@bp.get("/organizations/<org_id>/people")
@login_required
def people(org_id):
    org, membership = _require_org(org_id)
    q = {"syntal_org_id":org_id,"status":{"$in":["active","suspended"]}}
    rows = list(db().memberships.find(q).sort("created_at",1))
    users = _user_map(rows)
    search = (request.args.get("q") or "").lower().strip()
    status = request.args.get("status") or ""
    prepared=[]
    for row in rows:
        u = users.get(row.get("syntal_user_id"),{})
        if search and search not in f"{u.get('name','')} {u.get('email','')}".lower():
            continue
        if status and row.get("status") != status:
            continue
        prepared.append({"membership":row,"user":u,"role":role_for_membership(org_id,row) or {}})
    return render_template("organizations/people.html", title="People", organization=org, people=prepared, roles=_roles(org_id), can_manage=has_permission("syntal.members.manage"))

@bp.get("/organizations/<org_id>/people/<membership_id>")
@login_required
def person_detail(org_id, membership_id):
    org,_ = _require_org(org_id)
    row = db().memberships.find_one({"syntal_org_id":org_id,"membership_id":membership_id}) or db().memberships.find_one({"syntal_org_id":org_id,"_id":membership_id})
    if not row: abort(404)
    user = db().users.find_one({"syntal_user_id":row.get("syntal_user_id")}) or {}
    app_assignments=list(db().organization_application_memberships.find({"syntal_org_id":org_id,"membership_id":row.get("membership_id"),"status":"active"}))
    teams=list(db().teams.find({"syntal_org_id":org_id,"member_ids":row.get("membership_id"),"status":{"$ne":"deleted"}}))
    return render_template("organizations/person_detail.html", title=user.get("name") or user.get("email") or "Person", organization=org, member=row, person=user, role=role_for_membership(org_id,row), roles=_roles(org_id), app_assignments=app_assignments, teams=teams)

@bp.post("/organizations/<org_id>/people/<membership_id>/role")
@login_required
def change_role(org_id,membership_id):
    _require_org(org_id); require_permission("syntal.members.manage")
    target=db().memberships.find_one({"syntal_org_id":org_id,"membership_id":membership_id})
    if not target: abort(404)
    role_id=request.form.get("role_id")
    role=db().organization_roles.find_one({"syntal_org_id":org_id,"role_id":role_id,"status":{"$ne":"deleted"}})
    if not role: abort(400)
    old=role_for_membership(org_id,target) or {}
    if old.get("key")=="owner" and role.get("key")!="owner":
        owners=db().memberships.count_documents({"syntal_org_id":org_id,"status":"active","$or":[{"role":"owner"},{"role_id":old.get("role_id")} ]})
        if owners <= 1:
            abort(409,"The last owner cannot be demoted.")
    db().memberships.update_one({"_id":target["_id"]},{"$set":{"role_id":role.get("role_id"),"role":role.get("key"),"updated_at":utcnow()}})
    bump_policy_version(org_id); audit("organization.member_role_changed",org_id=org_id,detail={"membership_id":membership_id,"role_id":role_id})
    return redirect(url_for("organizations.person_detail",org_id=org_id,membership_id=membership_id))

@bp.post("/organizations/<org_id>/people/<membership_id>/status")
@login_required
def change_status(org_id,membership_id):
    _require_org(org_id); require_permission("syntal.members.manage")
    target=db().memberships.find_one({"syntal_org_id":org_id,"membership_id":membership_id})
    if not target: abort(404)
    action=request.form.get("action")
    if action=="suspend": new="suspended"
    elif action=="reactivate": new="active"
    elif action=="remove": new="removed"
    else: abort(400)
    role=role_for_membership(org_id,target) or {}
    if role.get("key")=="owner" and new!="active":
        owners=sum(1 for m in db().memberships.find({"syntal_org_id":org_id,"status":"active"}) if (role_for_membership(org_id,m) or {}).get("key")=="owner")
        if owners<=1: abort(409,"The last owner cannot be suspended or removed.")
    db().memberships.update_one({"_id":target["_id"]},{"$set":{"status":new,"updated_at":utcnow()}})
    bump_policy_version(org_id); audit(f"organization.member_{action}",org_id=org_id,detail={"membership_id":membership_id})
    return redirect(url_for("organizations.people",org_id=org_id))

@bp.route("/organizations/<org_id>/invitations",methods=["GET","POST"])
@login_required
def invitations(org_id):
    org,_=_require_org(org_id)
    if request.method=="POST":
        require_permission("syntal.members.invite")
        email=(request.form.get("email") or "").strip().lower(); role_id=request.form.get("role_id")
        if not email: abort(400)
        role=db().organization_roles.find_one({"syntal_org_id":org_id,"role_id":role_id}) or db().organization_roles.find_one({"syntal_org_id":org_id,"key":"member"}) or {}
        now=utcnow()
        doc={"invitation_id":public_id("inv"),"syntal_org_id":org_id,"email":email,"role_id":role.get("role_id"),"role":role.get("key","member"),"status":"pending","delivery_status":"pending","created_at":now,"updated_at":now,"created_by":g.user.get("syntal_user_id")}
        result=db().organization_invitations.insert_one(doc); doc["_id"]=result.inserted_id
        delivery=_deliver_invitation(org,doc,inviter_name=g.user.get("name") or g.user.get("email"))
        audit("organization.invitation_created",org_id=org_id,detail={"email":email,"invitation_id":doc["invitation_id"],"delivery_status":"sent" if delivery.get("ok") else "failed"})
        if delivery.get("ok"):
            flash("Invitation email sent.","success")
        else:
            flash("Invitation created, but email delivery failed: "+(delivery.get("error") or "SMTP unavailable"),"warning")
        return redirect(url_for("organizations.invitations",org_id=org_id))
    rows=list(db().organization_invitations.find({"syntal_org_id":org_id}).sort("created_at",-1).limit(250))
    return render_template("organizations/invitations.html",title="Invitations",organization=org,invitations=rows,roles=_roles(org_id),can_manage=has_permission("syntal.members.invite"))

@bp.post("/organizations/<org_id>/invitations/<invitation_id>/<action>")
@login_required
def invitation_action(org_id,invitation_id,action):
    _require_org(org_id); require_permission("syntal.members.invite")
    if action not in {"revoke","resend"}: abort(404)
    inv=db().organization_invitations.find_one({"syntal_org_id":org_id,"invitation_id":invitation_id})
    if not inv: abort(404)
    if action=="revoke":
        db().organization_invitations.update_one({"_id":inv["_id"]},{"$set":{"status":"revoked","revoked_at":utcnow()}})
    else:
        db().organization_invitations.update_one({"_id":inv["_id"]},{"$set":{"status":"pending","delivery_status":"pending","updated_at":utcnow()}})
        inv["status"]="pending"
        delivery=_deliver_invitation(db().organizations.find_one({"syntal_org_id":org_id}) or {},inv,inviter_name=g.user.get("name") or g.user.get("email"))
        if delivery.get("ok"):
            flash("Invitation email resent.","success")
        else:
            flash("Invitation remains pending, but email delivery failed: "+(delivery.get("error") or "SMTP unavailable"),"warning")
    audit(f"organization.invitation_{action}d",org_id=org_id,detail={"invitation_id":invitation_id})
    return redirect(url_for("organizations.invitations",org_id=org_id))


@bp.route("/invitations/<invitation_id>/accept", methods=["GET","POST"])
def accept_invitation(invitation_id):
    inv=db().organization_invitations.find_one({"invitation_id":invitation_id,"status":"pending"})
    if not inv:
        return render_template("organizations/invitation_accept.html",title="Invitation unavailable",invitation=None,organization=None,standalone_auth=True),404
    org=db().organizations.find_one({"syntal_org_id":inv.get("syntal_org_id"),"status":{"$ne":"deleted"}})
    if not org:
        abort(404)
    if not g.user:
        return redirect(url_for("auth.login",next=request.path,invitation=invitation_id))
    if (g.user.get("email") or "").strip().lower() != (inv.get("email") or "").strip().lower():
        return render_template("organizations/invitation_accept.html",title="Invitation belongs to another account",invitation=inv,organization=org,email_mismatch=True,standalone_auth=True),403
    if request.method=="POST":
        uid=g.user.get("syntal_user_id") or str(g.user.get("_id"))
        membership=db().memberships.find_one({"syntal_org_id":inv["syntal_org_id"],"syntal_user_id":uid})
        now=utcnow()
        if membership:
            db().memberships.update_one({"_id":membership["_id"]},{"$set":{"status":"active","role_id":inv.get("role_id"),"role":inv.get("role") or "member","updated_at":now}})
        else:
            db().memberships.insert_one({"membership_id":public_id("mem"),"syntal_org_id":inv["syntal_org_id"],"syntal_user_id":uid,"role_id":inv.get("role_id"),"role":inv.get("role") or "member","status":"active","created_at":now,"updated_at":now})
        db().organization_invitations.update_one({"_id":inv["_id"]},{"$set":{"status":"accepted","accepted_at":now,"accepted_by":uid,"updated_at":now}})
        bump_policy_version(inv["syntal_org_id"])
        audit("organization.invitation_accepted",user_id=uid,org_id=inv["syntal_org_id"],detail={"invitation_id":invitation_id})
        session["org_id"]=inv["syntal_org_id"]
        flash("Invitation accepted. Welcome to the workspace.","success")
        return redirect(url_for("organizations.overview",org_id=inv["syntal_org_id"]))
    return render_template("organizations/invitation_accept.html",title="Join workspace",invitation=inv,organization=org,standalone_auth=True)


@bp.route("/organizations/<org_id>/teams",methods=["GET","POST"])
@login_required
def teams(org_id):
    org,_=_require_org(org_id)
    if request.method=="POST":
        require_permission("syntal.members.manage")
        name=(request.form.get("name") or "").strip()
        if not name: abort(400)
        doc={"team_id":public_id("team"),"syntal_org_id":org_id,"name":name,"description":(request.form.get("description") or "").strip(),"member_ids":[],"status":"active","created_at":utcnow(),"created_by":g.user.get("syntal_user_id")}
        db().teams.insert_one(doc); audit("organization.team_created",org_id=org_id,detail={"team_id":doc["team_id"]})
        return redirect(url_for("organizations.teams",org_id=org_id))
    rows=list(db().teams.find({"syntal_org_id":org_id,"status":{"$ne":"deleted"}}).sort("name",1))
    return render_template("organizations/teams.html",title="Teams",organization=org,teams=rows,can_manage=has_permission("syntal.members.manage"))

@bp.route("/organizations/<org_id>/teams/<team_id>",methods=["GET","POST"])
@login_required
def team_detail(org_id,team_id):
    org,_=_require_org(org_id); team=db().teams.find_one({"syntal_org_id":org_id,"team_id":team_id})
    if not team: abort(404)
    if request.method=="POST":
        require_permission("syntal.members.manage")
        member_ids=request.form.getlist("member_ids")
        db().teams.update_one({"_id":team["_id"]},{"$set":{"member_ids":member_ids,"updated_at":utcnow()}})
        audit("organization.team_members_updated",org_id=org_id,detail={"team_id":team_id,"member_count":len(member_ids)})
        return redirect(url_for("organizations.team_detail",org_id=org_id,team_id=team_id))
    members=list(db().memberships.find({"syntal_org_id":org_id,"status":"active"}).sort("created_at",1)); users=_user_map(members)
    return render_template("organizations/team_detail.html",title=team.get("name","Team"),organization=org,team=team,members=members,users=users,can_manage=has_permission("syntal.members.manage"))

@bp.route("/organizations/<org_id>/settings",methods=["GET","POST"])
@login_required
def settings(org_id):
    org,_=_require_org(org_id)
    if request.method=="POST":
        require_permission("syntal.organization.manage")
        fields={k:(request.form.get(k) or "").strip() for k in ["name","display_name","legal_name","billing_email","timezone","locale"]}
        db().organizations.update_one({"_id":org["_id"]},{"$set":{**fields,"updated_at":utcnow()}}); audit("organization.profile_updated",org_id=org_id,detail={"fields":list(fields)})
        return redirect(url_for("organizations.settings",org_id=org_id))
    return render_template("organizations/settings.html",title="Organization settings",organization=org,can_manage=has_permission("syntal.organization.manage"))

@bp.route("/organizations/<org_id>/ownership",methods=["GET","POST"])
@login_required
def ownership(org_id):
    org,membership=_require_org(org_id); current_role=role_for_membership(org_id,membership) or {}
    if request.method=="POST":
        if current_role.get("key")!="owner": abort(403)
        target_id=request.form.get("membership_id"); target=db().memberships.find_one({"syntal_org_id":org_id,"membership_id":target_id,"status":"active"})
        if not target: abort(404)
        owner_role=db().organization_roles.find_one({"syntal_org_id":org_id,"key":"owner"}) or {}; admin_role=db().organization_roles.find_one({"syntal_org_id":org_id,"key":"admin"}) or {}
        db().memberships.update_one({"_id":target["_id"]},{"$set":{"role":"owner","role_id":owner_role.get("role_id"),"updated_at":utcnow()}})
        db().memberships.update_one({"_id":membership["_id"]},{"$set":{"role":"admin","role_id":admin_role.get("role_id"),"updated_at":utcnow()}})
        bump_policy_version(org_id); audit("organization.ownership_transferred",org_id=org_id,detail={"target_membership_id":target_id})
        return redirect(url_for("organizations.people",org_id=org_id))
    members=list(db().memberships.find({"syntal_org_id":org_id,"status":"active"}).sort("created_at",1)); users=_user_map(members)
    return render_template("organizations/ownership.html",title="Ownership",organization=org,members=members,users=users,is_owner=current_role.get("key")=="owner")

@bp.route("/organizations/<org_id>/lifecycle",methods=["GET","POST"])
@login_required
def lifecycle(org_id):
    org,membership=_require_org(org_id); role=role_for_membership(org_id,membership) or {}
    if request.method=="POST":
        if role.get("key")!="owner": abort(403)
        action=request.form.get("action")
        if action not in {"suspend","reactivate"}: abort(400)
        status="suspended" if action=="suspend" else "active"
        db().organizations.update_one({"_id":org["_id"]},{"$set":{"status":status,"updated_at":utcnow()}}); audit(f"organization.{action}ed",org_id=org_id)
        return redirect(url_for("organizations.lifecycle",org_id=org_id))
    return render_template("organizations/lifecycle.html",title="Lifecycle",organization=org,is_owner=role.get("key")=="owner")
