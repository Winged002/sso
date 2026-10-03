"""Read-only upgrade inspection and explicit, repeatable security migration."""
from datetime import timedelta
from .util import utcnow

INDEXES=[
 ('users',[('syntal_user_id',1)],'v330_user_id',True,None),
 ('users',[('email',1)],'v330_email',True,None),
 ('organizations',[('syntal_org_id',1)],'v330_org_id',True,None),
 ('memberships',[('syntal_org_id',1),('syntal_user_id',1)],'v330_member_pair',True,None),
 ('memberships',[('membership_id',1)],'v330_membership_id',True,None),
 ('organization_roles',[('syntal_org_id',1),('key',1)],'v330_role_key',True,None),
 ('applications',[('client_id',1)],'v330_client_id',True,None),
 ('organization_entitlements',[('syntal_org_id',1),('application',1)],'v330_entitlement',True,None),
 ('organization_application_memberships',[('syntal_org_id',1),('client_id',1),('membership_id',1)],'v330_assignment',True,None),
 ('oidc_authorization_codes',[('code_hash',1)],'v330_code_hash',True,None),
 ('oidc_refresh_tokens',[('token_hash',1)],'v330_refresh_hash',True,None),
 ('organization_invitations',[('invitation_id',1)],'v330_invitation',True,None),
 ('stripe_events',[('event_id',1)],'v330_stripe_event',True,None),
 ('account_action_tokens',[('token_hash',1)],'v330_action_token',True,None),
 ('oidc_consents',[('syntal_user_id',1),('syntal_org_id',1),('client_id',1)],'v330_consent',True,None),
]
for name in ['security_attempts','security_otp_uses','security_locks','security_sessions','account_action_tokens','oidc_authorization_codes','oidc_refresh_tokens','oidc_token_families']:
 INDEXES.append((name,[('expire_at',1)],'v330_expiry',False,0))

# Historical scalar-ID indexes understood by this release. Unknown ones are blockers.
ALIASES={'users':{'user_id':'syntal_user_id'},'organizations':{'org_id':'syntal_org_id','organization_id':'syntal_org_id'}}
WRITE_FIELDS={
 'users':{'syntal_user_id','user_id','email','email_normalized','name','password_hash','status','email_verified','verified','session_epoch','created_at','updated_at','registration_source'},
 'organizations':{'syntal_org_id','org_id','organization_id','slug','name','display_name','status','authorization_policy_version','created_at','updated_at','created_by','registration_source'},
 'organization_roles':{'role_id','syntal_org_id','key','name','description','permissions','rank','status','created_at','created_by'},
 'memberships':{'membership_id','syntal_org_id','syntal_user_id','role_id','role','status','created_at','updated_at'},
 'organization_application_memberships':{'app_assignment_id','assignment_id','syntal_org_id','client_id','membership_id','access_effect','direct_permissions','app_role_id','status','created_at','updated_at','created_by','updated_by'},
 'organization_entitlements':{'entitlement_id','syntal_org_id','application','status','billing_status','source','created_at','updated_at','manual_override'},
 'applications':{'client_id','name','display_name','description','owner_type','owner_org_id','status','client_secret_hash','redirect_uris','created_at'},
}


def legacy_write_fields(collection, row):
    """Keep historical unique keys populated without changing existing slugs."""
    if collection == 'users':
        email = row.get('email')
        if not isinstance(email, str) or not email.strip():
            raise ValueError('A nonempty email is required for email_normalized')
        return {'email_normalized': email.strip().lower()}
    if collection == 'organizations':
        slug = row.get('slug')
        if slug is not None and slug != '':
            if not isinstance(slug, str):
                raise ValueError('An existing organization slug must be a string')
            return {'slug': slug}
        org_id = row.get('syntal_org_id')
        if not isinstance(org_id, str) or not org_id:
            raise ValueError('An organization ID is required for a missing slug')
        return {'slug': org_id}
    return {}


def _legacy_field_plan(database):
    """Check all compatibility writes and retained values before any mutation."""
    plan=[]; blockers=[]
    for collection,field in [('users','email_normalized'),('organizations','slug')]:
        rows=list(database[collection].find({}, {field:1,'email':1,'syntal_org_id':1}))
        current={}; planned={}
        for row in rows:
            value=row.get(field)
            if isinstance(value,str) and value:
                current.setdefault(value,[]).append(row['_id'])
        for row in rows:
            try: value=legacy_write_fields(collection,row)[field]
            except ValueError:
                blockers.append(f'{collection}: invalid source for legacy {field} on record {row["_id"]}')
                continue
            if value in planned:
                blockers.append(f'{collection}: planned legacy {field} values collide; resolve before migration')
            planned[value]=row['_id']
            if any(owner != row['_id'] for owner in current.get(value,[])):
                blockers.append(f'{collection}: planned legacy {field} conflicts with an existing value; resolve before migration')
            if row.get(field)!=value:
                plan.append((collection,row['_id'],{field:value}))
    return plan,blockers


def inspect_database(database):
    blockers=[];warnings=[];indexes={};counts={}
    legacy_plan,legacy_blockers=_legacy_field_plan(database)
    blockers.extend(legacy_blockers)
    if legacy_plan:warnings.append(f'{len(legacy_plan)} legacy slug/email_normalized fields will be backfilled or synchronized; existing organization slugs are preserved')
    for collection,fields,name,unique,ttl in INDEXES:
        if not unique:continue
        seen={}
        for row in database[collection].find({},dict([(k,1) for k,_ in fields])):
            values=tuple(row.get(k) for k,_ in fields)
            if any(v is None or v=='' for v in values):blockers.append(f'{collection}: missing required unique key {name} on record {row["_id"]}');continue
            normalized=tuple(v.strip().lower() if collection=='users' and k=='email' and isinstance(v,str) else v for (k,_),v in zip(fields,values))
            if normalized in seen:blockers.append(f'{collection}: duplicate key for {name}; resolve before migration')
            seen[normalized]=row['_id']
    for collection in database.list_collection_names():
        indexes[collection]=[{k:v for k,v in row.items() if k in {'name','key','unique','sparse','partialFilterExpression','expireAfterSeconds'}} for row in database[collection].list_indexes()]
        if collection in WRITE_FIELDS:
            for index in indexes[collection]:
                if index.get('unique') and not index.get('sparse') and not index.get('partialFilterExpression'):
                    missing=[k for k in index['key'] if k!='_id' and k not in WRITE_FIELDS[collection]]
                    if missing:blockers.append(f'{collection}: legacy unique index {index["name"]} requires unsupported fields {missing}')
        counts[collection]=database[collection].count_documents({})
    # Inspect the values that alias backfill will write, including collisions
    # with aliases already present. Do this before any migration writes.
    for collection,aliases in ALIASES.items():
        unique_fields={next(iter(i['key'])) for i in indexes.get(collection,[]) if i.get('unique') and len(i['key'])==1}
        for alias,source in aliases.items():
            if alias not in unique_fields:continue
            seen=set()
            for row in database[collection].find({}, {alias:1,source:1}):
                value=row.get(alias) or row.get(source)
                if value in seen:blockers.append(f'{collection}: planned alias backfill collides with unique {alias}')
                seen.add(value)
    broad_roles=database.organization_roles.count_documents({'key':{'$ne':'owner'},'permissions':{'$in':['*','syntal.admin']}})
    if broad_roles:warnings.append(f'{broad_roles} non-owner organization roles already contain broad grants; review and remove unauthorized legacy grants manually')
    pending=database.registration_jobs.count_documents({'state':{'$ne':'complete'}})
    if pending:warnings.append(f'{pending} incomplete registration jobs require review or recover-registrations-v330.py')
    missing_roles=0
    for member in database.memberships.find({'status':'active'}):
        role_query={'syntal_org_id':member.get('syntal_org_id'),'status':{'$nin':['deleted','suspended','inactive']}}
        role_query.update({'role_id':member['role_id']} if member.get('role_id') else {'key':member.get('role') or member.get('role_key')})
        if not database.organization_roles.find_one(role_query):missing_roles+=1
    if missing_roles:blockers.append(f'{missing_roles} active memberships have missing/inactive role bindings; repair before migration')
    invalid_roles=database.organization_application_roles.count_documents({'permissions':{'$in':['*','syntal.admin','syntal.organization.manage']}})
    if invalid_roles:warnings.append(f'{invalid_roles} app roles contain broad permissions; migration removes out-of-namespace app-role grants')
    public_verified=database.users.count_documents({'registration_source':'self_service','email_verified':True,'verification_source':{'$exists':False}})
    if public_verified:warnings.append(f'{public_verified} public-signup accounts need email reverification')
    warnings.append('All previous browser sessions and refresh tokens must be replaced by a new sign-in.')
    return {'ready':not blockers,'blockers':sorted(set(blockers)),'warnings':warnings,'counts':counts,'indexes':indexes}


def migrate(database):
    report=inspect_database(database)
    if report['blockers']:raise RuntimeError('Preflight blockers must be resolved first: '+'; '.join(report['blockers']))
    now=utcnow()
    legacy_plan,legacy_blockers=_legacy_field_plan(database)
    if legacy_blockers:raise RuntimeError('Legacy field conflicts: '+'; '.join(legacy_blockers))
    for collection,record_id,values in legacy_plan:
        database[collection].update_one({'_id':record_id},{'$set':values})
    for collection,aliases in ALIASES.items():
        for row in database[collection].find({}):
            values={alias:row[source] for alias,source in aliases.items() if not row.get(alias) and row.get(source)}
            if collection=='users' and isinstance(row.get('email'),str):values['email']=row['email'].strip().lower()
            if values:database[collection].update_one({'_id':row['_id']},{'$set':values})
    # Existing invitation links predate expiry guarantees: revoke instead of extending them.
    database.organization_invitations.update_many({'status':'pending','expire_at':{'$exists':False}},{'$set':{'status':'revoked','revoked_at':now,'migration_reason':'legacy_invitation_requires_resend'}})
    database.users.update_many({'registration_source':'self_service','email_verified':True,'verification_source':{'$exists':False}},{'$set':{'email_verified':False,'verified':False,'verification_required_reason':'public_signup_had_no_email_proof'}})
    for row in database.organization_application_roles.find({}):
        prefix=str(row.get('client_id') or '')+'.'
        clean=[p for p in row.get('permissions',[]) if isinstance(p,str) and p.startswith(prefix)]
        if clean!=row.get('permissions',[]):database.organization_application_roles.update_one({'_id':row['_id']},{'$set':{'permissions':clean,'security_migrated_at':now}})
    # Repair dual IDs while preserving existing values and records.
    for row in database.organization_application_memberships.find({}):
        from .util import public_id
        value=row.get('app_assignment_id') or row.get('assignment_id') or public_id('aam')
        database.organization_application_memberships.update_one({'_id':row['_id']},{'$set':{'app_assignment_id':value,'assignment_id':value}})
    for collection,fields,name,unique,ttl in INDEXES:
        # Reuse an equivalent index even if a prior release gave it another name.
        existing=list(database[collection].list_indexes())
        equivalent=next((i for i in existing if list(i['key'].items())==fields and bool(i.get('unique'))==unique and (ttl is None or i.get('expireAfterSeconds')==ttl)),None)
        if equivalent:continue
        kwargs={'name':name,'unique':unique}
        if ttl is not None:kwargs['expireAfterSeconds']=ttl
        database[collection].create_index(fields,**kwargs)
    if not database.schema_versions.find_one({'_id':'security-v330'}):
        database.oidc_refresh_tokens.update_many({}, {'$set':{'revoked_at':now}})
        database.security_sessions.update_many({}, {'$set':{'revoked_at':now}})
        database.oidc_authorization_codes.update_many({'consumed_at':None},{'$set':{'consumed_at':now}})
        database.users.update_many({}, {'$inc':{'session_epoch':1}})
        database.schema_versions.insert_one({'_id':'security-v330','applied_at':now,'version':'3.3.0'})
    return {'status':'applied','version':'3.3.0','preflight':report}

# v4 enterprise identity schema. v3.3 migration remains the compatibility foundation.
_migrate_v330 = migrate
V4_INDEXES = [
 ('service_accounts',[('client_id',1)],'v400_service_client',True,None),
 ('service_accounts',[('syntal_org_id',1),('service_account_id',1)],'v400_service_org_id',True,None),
 ('scim_tokens',[('scim_token_id',1)],'v400_scim_token',True,None),
 ('federation_providers',[('provider_id',1)],'v400_federation_provider',True,None),
 ('federated_identities',[('provider_id',1),('subject',1)],'v400_federated_subject',True,None),
 ('federation_transactions',[('state_hash',1)],'v400_federation_state',True,None),
 ('federation_transactions',[('expire_at',1)],'v400_federation_expiry',False,0),
 ('signing_keys',[('kid',1)],'v400_signing_kid',True,None),
 ('event_subscriptions',[('subscription_id',1)],'v400_event_subscription',True,None),
 ('event_deliveries',[('delivery_id',1)],'v400_event_delivery',True,None),
 ('event_deliveries',[('status',1),('next_attempt_at',1)],'v400_event_queue',False,None),
]
ENTERPRISE_ADMIN_PERMISSIONS=['syntal.federation.manage','syntal.scim.manage','syntal.service_accounts.manage','syntal.security.manage','syntal.events.manage']

def migrate(database):
    base=_migrate_v330(database); now=utcnow()
    for collection,fields,name,unique,ttl in V4_INDEXES:
        existing=list(database[collection].list_indexes())
        equivalent=next((i for i in existing if list(i['key'].items())==fields and bool(i.get('unique'))==unique and (ttl is None or i.get('expireAfterSeconds')==ttl)),None)
        if equivalent:continue
        kwargs={'name':name,'unique':unique}
        if ttl is not None:kwargs['expireAfterSeconds']=ttl
        database[collection].create_index(fields,**kwargs)
    for role in database.organization_roles.find({'key':'admin','status':'active'}):
        perms=list(role.get('permissions') or [])
        changed=False
        for permission in ENTERPRISE_ADMIN_PERMISSIONS:
            if permission not in perms:perms.append(permission);changed=True
        if changed:database.organization_roles.update_one({'_id':role['_id']},{'$set':{'permissions':perms,'updated_at':now}})
    if not database.schema_versions.find_one({'_id':'security-v400'}):
        database.schema_versions.insert_one({'_id':'security-v400','applied_at':now,'version':'4.0.0','base':'3.3.0'})
    return {'status':'applied','version':'4.0.0','preflight':base.get('preflight',{})}
