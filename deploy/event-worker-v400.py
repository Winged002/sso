#!/usr/bin/env python3
"""Deliver pending Syntal SSO v4 signed event webhooks once; safe for cron/systemd repetition."""
import _bootstrap
from syntal_sso import create_app
from syntal_sso.db import db
from syntal_sso.events import deliver_one
from syntal_sso.util import utcnow
app=create_app({'STARTUP_CHECKS':False,'VALIDATE_CONFIG':False,'SESSION_BACKEND_REQUIRED':False})
with app.app_context():
    limit=int(app.config.get('EVENT_WORKER_BATCH',50));rows=list(db().event_deliveries.find({'status':'pending','next_attempt_at':{'$lte':utcnow()}}).sort('next_attempt_at',1).limit(limit));ok=0
    for row in rows:ok+=1 if deliver_one(row) else 0
    print({'processed':len(rows),'delivered':ok})
