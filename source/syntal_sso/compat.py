from flask import Blueprint, redirect, url_for
from .security import login_required

bp=Blueprint("compat",__name__)

@bp.get("/organization")
@login_required
def organization(): return redirect(url_for("organizations.dashboard"),302)

@bp.get("/organizations/<org_id>/access")
@login_required
def access(org_id): return redirect(url_for("access.roles",org_id=org_id),301)

@bp.get("/organizations/<org_id>/access-matrix")
@login_required
def access_matrix(org_id): return redirect(url_for("access.matrix",org_id=org_id),301)

@bp.get("/organizations/<org_id>/billing/invoice/<invoice_id>")
@login_required
def invoice(org_id,invoice_id): return redirect(url_for("billing.invoice_detail",org_id=org_id,invoice_id=invoice_id),301)

@bp.get("/applications")
@login_required
def applications(): return redirect(url_for("applications.developers"),301)
