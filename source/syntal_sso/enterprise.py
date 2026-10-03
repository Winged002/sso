from flask import Blueprint,abort,g,render_template
from .security import login_required
from .acl import has_permission
from .lifecycle import serialize_org
bp=Blueprint('enterprise',__name__)
@bp.get('/organizations/<org_id>/enterprise')
@login_required
@serialize_org
def index(org_id):
    if not g.organization or g.organization.get('syntal_org_id')!=org_id:abort(404)
    cards=[('Federation','federation.manage','syntal.federation.manage'),('SCIM','scim.manage','syntal.scim.manage'),('Service accounts','service_accounts.manage','syntal.service_accounts.manage'),('Signing keys','signing_keys.manage','syntal.security.manage'),('Event delivery','events.manage','syntal.events.manage')]
    visible=[(name,endpoint) for name,endpoint,perm in cards if has_permission(perm)]
    return render_template('enterprise/index.html',title='Enterprise identity',organization=g.organization,cards=visible)
