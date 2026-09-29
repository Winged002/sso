from flask import Blueprint, abort, g, redirect, render_template, request, url_for
from .db import db
from .security import login_required
from .acl import audit, has_permission
from .util import utcnow

bp = Blueprint("billing", __name__)


def _require_org(org_id, manage=False):
    uid=g.user.get("syntal_user_id") or str(g.user.get("_id"))
    org=db().organizations.find_one({"syntal_org_id":org_id,"status":{"$ne":"deleted"}})
    membership=db().memberships.find_one({"syntal_org_id":org_id,"syntal_user_id":uid,"status":"active"})
    if not org or not membership: abort(404)
    g.organization,g.membership=org,membership
    perm="syntal.billing.manage" if manage else "syntal.billing.read"
    if not has_permission(perm,membership,org_id): abort(403)
    return org,membership


def _customer(org_id):
    return db().billing_customers.find_one({"syntal_org_id":org_id}) or {}

@bp.get("/organizations/<org_id>/billing")
@login_required
def overview(org_id):
    org,_=_require_org(org_id)
    subscriptions=list(db().billing_subscriptions.find({"syntal_org_id":org_id}).sort("updated_at",-1).limit(20))
    invoices=list(db().billing_invoices.find({"syntal_org_id":org_id}).sort("created_at",-1).limit(5))
    entitlements=list(db().organization_entitlements.find({"syntal_org_id":org_id}))
    return render_template("billing/overview.html",title="Billing",organization=org,customer=_customer(org_id),subscriptions=subscriptions,invoices=invoices,entitlements=entitlements)

@bp.get("/organizations/<org_id>/billing/subscriptions")
@login_required
def subscriptions(org_id):
    org,_=_require_org(org_id); rows=list(db().billing_subscriptions.find({"syntal_org_id":org_id}).sort("updated_at",-1))
    return render_template("billing/subscriptions.html",title="Subscriptions",organization=org,subscriptions=rows,customer=_customer(org_id))

@bp.get("/organizations/<org_id>/billing/usage")
@login_required
def usage(org_id):
    org,_=_require_org(org_id)
    collection = db().billing_usage if "billing_usage" in db().list_collection_names() else db().usage_records
    rows=list(collection.find({"syntal_org_id":org_id}).sort("period_start",-1).limit(500))
    return render_template("billing/usage.html",title="Usage",organization=org,usage_rows=rows)

@bp.get("/organizations/<org_id>/billing/invoices")
@login_required
def invoices(org_id):
    org,_=_require_org(org_id); rows=list(db().billing_invoices.find({"syntal_org_id":org_id}).sort("created_at",-1).limit(250))
    return render_template("billing/invoices.html",title="Invoices",organization=org,invoices=rows)

@bp.get("/organizations/<org_id>/billing/invoices/<invoice_id>")
@login_required
def invoice_detail(org_id,invoice_id):
    org,_=_require_org(org_id); inv=db().billing_invoices.find_one({"syntal_org_id":org_id,"invoice_id":invoice_id})
    if not inv: abort(404)
    return render_template("billing/invoice_detail.html",title=f"Invoice {invoice_id}",organization=org,invoice=inv)

@bp.route("/organizations/<org_id>/billing/profile",methods=["GET","POST"])
@login_required
def profile(org_id):
    org,_=_require_org(org_id)
    customer=_customer(org_id)
    if request.method=="POST":
        _require_org(org_id,manage=True)
        fields={"legal_name":(request.form.get("legal_name") or "").strip(),"billing_email":(request.form.get("billing_email") or "").strip(),"currency":(request.form.get("currency") or "USD").strip().upper(),"address":{"line1":(request.form.get("line1") or "").strip(),"line2":(request.form.get("line2") or "").strip(),"city":(request.form.get("city") or "").strip(),"postal_code":(request.form.get("postal_code") or "").strip(),"country":(request.form.get("country") or "").strip()},"updated_at":utcnow()}
        db().billing_customers.update_one({"syntal_org_id":org_id},{"$setOnInsert":{"syntal_org_id":org_id,"created_at":utcnow()},"$set":fields},upsert=True); audit("billing.profile_updated",org_id=org_id,detail={"fields":["legal_name","billing_email","currency","address"]})
        return redirect(url_for("billing.profile",org_id=org_id))
    return render_template("billing/profile.html",title="Billing profile",organization=org,customer=customer,can_manage=has_permission("syntal.billing.manage"))

@bp.post("/stripe/webhook")
def stripe_webhook():
    # v3 keeps the endpoint stable. Existing billing worker/reconciliation remains authoritative;
    # the webhook body is recorded only when an event id is available, without schema migration.
    payload=request.get_json(silent=True) or {}
    event_id=payload.get("id")
    if event_id:
        db().stripe_events.update_one({"event_id":event_id},{"$setOnInsert":{"event_id":event_id,"type":payload.get("type"),"payload":payload,"created_at":utcnow()}},upsert=True)
    return {"received":True}
