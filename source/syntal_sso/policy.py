"""The single effective organization/application decision used by UI and grants."""
from .db import db
from .acl import (role_for_membership, effective_permissions_for_membership,
                  application_access_override, application_visible_to_org,
                  application_requires_entitlement_for_org, entitlement_is_active)


def access_decision(user, organization, membership, application, permission=None):
    reasons=[]
    org_id=(organization or {}).get('syntal_org_id')
    cid=(application or {}).get('client_id')
    if not user or user.get('status') not in (None,'active'):
        reasons.append('account_not_active')
    if not user or user.get('email_verified') is not True:
        reasons.append('email_not_verified')
    if not organization or organization.get('status')!='active':
        reasons.append('organization_not_active')
    uid=(user or {}).get('syntal_user_id') or str((user or {}).get('_id') or '')
    if not membership or membership.get('status')!='active' or membership.get('syntal_org_id')!=org_id or membership.get('syntal_user_id')!=uid:
        reasons.append('membership_not_active')
    if not application or application.get('status')!='active':
        reasons.append('application_not_active')
    if not application_visible_to_org(application,org_id):
        reasons.append('application_not_visible')
    entitlement=db().organization_entitlements.find_one({'syntal_org_id':org_id,'application':cid}) if org_id and cid else None
    required=application_requires_entitlement_for_org(application,org_id)
    if required and not entitlement_is_active(entitlement):
        reasons.append('product_not_entitled')
    role=role_for_membership(org_id,membership) or {}
    owner=role.get('key')=='owner'
    override=application_access_override(org_id,membership,cid) if membership and cid else 'inherit'
    effective=set(effective_permissions_for_membership(org_id,membership)) if membership else set()
    if override=='deny' and not owner:
        reasons.append('member_application_denied')
    wanted=permission or (f'{cid}.access' if cid else None)
    if wanted and (not cid or not wanted.startswith(cid+'.')):
        reasons.append('permission_application_mismatch')
    permitted=bool(wanted and ('*' in effective or wanted in effective or f'{cid}.admin' in effective))
    if not permitted:reasons.append('permission_not_granted')
    return {'allowed':not reasons,'reasons':reasons,'application':cid,'permission':wanted,
            'organization_id':org_id,'owner':owner,'access_effect':override,
            'effective_permissions':sorted(effective),'entitlement_required':required,
            'entitlement_status':(entitlement or {}).get('status'),'policy_version':(organization or {}).get('authorization_policy_version',1)}


def resolve_access(uid,org_id,cid,permission=None):
    database=db()
    return access_decision(database.users.find_one({'syntal_user_id':uid}),
        database.organizations.find_one({'syntal_org_id':org_id}),
        database.memberships.find_one({'syntal_org_id':org_id,'syntal_user_id':uid}),
        database.applications.find_one({'client_id':cid}),permission)
