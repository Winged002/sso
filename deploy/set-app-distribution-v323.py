#!/usr/bin/env python3
"""Set an organization-owned application's distribution policy.

This is an explicit operational helper, not a database migration. Existing
organization-owned clients remain private unless this script or the owner UI is
used to publish them to other Syntal organizations.
"""
import _bootstrap
import argparse
from syntal_sso import create_app
from syntal_sso.db import db
from syntal_sso.util import utcnow

p=argparse.ArgumentParser()
p.add_argument('--client-id', required=True)
p.add_argument('--scope', choices=['private','organizations'], default='organizations')
a=p.parse_args()
app=create_app()
with app.app_context():
    row=db().applications.find_one({'client_id':a.client_id,'status':{'$ne':'deleted'}})
    if not row:
        raise SystemExit(f'Application not found: {a.client_id}')
    if row.get('owner_type') != 'organization' or not row.get('owner_org_id'):
        raise SystemExit('This helper only changes organization-owned applications.')
    enabled=a.scope == 'organizations'
    db().applications.update_one(
        {'_id':row['_id']},
        {'$set':{
            'distribution_scope':a.scope,
            'organization_registration_enabled':enabled,
            'updated_at':utcnow(),
        }},
    )
    print('client_id:',a.client_id)
    print('owner_org_id:',row.get('owner_org_id'))
    print('distribution_scope:',a.scope)
    print('organization_registration_enabled:',enabled)
