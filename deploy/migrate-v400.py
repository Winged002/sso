#!/usr/bin/env python3
"""Explicit security migration. Run with web stopped and a verified database backup."""
import _bootstrap
import argparse,json
from syntal_sso import create_app
from syntal_sso.db import db
from syntal_sso.schema import inspect_database,migrate
p=argparse.ArgumentParser();p.add_argument('--apply',action='store_true');p.add_argument('--backup-confirmed',action='store_true');args=p.parse_args()
if args.apply and not args.backup_confirmed:p.error('--apply requires --backup-confirmed')
app=create_app({'STARTUP_CHECKS':False,'VALIDATE_CONFIG':False,'SESSION_BACKEND_REQUIRED':False})
with app.app_context():
    report=migrate(db()) if args.apply else inspect_database(db())
    print(json.dumps(report,default=str,indent=2))
    if not args.apply and not report['ready']:raise SystemExit(1)
