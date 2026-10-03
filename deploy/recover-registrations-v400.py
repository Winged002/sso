#!/usr/bin/env python3
"""Inspect or resume persisted registration plans. Never print the user payload."""
import _bootstrap
import argparse,json
from syntal_sso import create_app
from syntal_sso.db import db
from syntal_sso.organizations import complete_registration
p=argparse.ArgumentParser();p.add_argument('--apply',action='store_true');args=p.parse_args()
app=create_app()
with app.app_context():
    rows=list(db().registration_jobs.find({'state':{'$ne':'complete'}},{'user':0}))
    result=[]
    for row in rows:
        status=row.get('state')
        if args.apply and status=='pending':
            try:complete_registration(row['_id']);status='complete'
            except Exception as exc:status=type(exc).__name__
        result.append({'job_id':row['_id'],'organization_id':row.get('organization',{}).get('syntal_org_id'),'state':status})
    print(json.dumps(result,indent=2))
    if any(r['state']!='complete' for r in result):raise SystemExit(1)
