#!/usr/bin/env python3
"""Explicitly enable the directory API audience for a trusted relying app."""
import _bootstrap,argparse
from syntal_sso import create_app
from syntal_sso.db import db
from syntal_sso.util import utcnow
p=argparse.ArgumentParser();p.add_argument('--client-id',required=True);p.add_argument('--enabled',choices=['true','false'],default='true');args=p.parse_args()
app=create_app()
with app.app_context():
    row=db().applications.find_one({'client_id':args.client_id,'status':'active'})
    if not row:raise SystemExit('Active client not found')
    if 'organization' not in (row.get('scopes') or []):raise SystemExit('Client must have the organization scope registered')
    db().applications.update_one({'_id':row['_id']},{'$set':{'api_access_enabled':args.enabled=='true','updated_at':utcnow()}})
    print('Directory API access:',args.client_id,args.enabled)
    print('Sign in again or refresh to obtain a new token. Members must also have directory read permissions.')
