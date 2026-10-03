#!/usr/bin/env python3
"""Restore previous code; never guesses or rewrites database state."""
from pathlib import Path
import argparse,datetime,os
p=argparse.ArgumentParser();p.add_argument('--root',default='/opt/syntal-sso/core');p.add_argument('--backup',required=True);p.add_argument('--web-stopped',action='store_true');p.add_argument('--database-restored',action='store_true');args=p.parse_args()
if not args.web_stopped or not args.database_restored:p.error('Stop web and restore the matching database backup before code rollback; acknowledge both flags.')
root=Path(args.root).resolve();backup=Path(args.backup).resolve()
if not root.is_dir() or not backup.is_dir() or root.parent!=backup.parent or not backup.name.startswith('.backup-v400-'):raise SystemExit('Invalid sibling code backup')
failed=root.parent/('.v400-rolled-back-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S-%f'))
os.rename(root,failed)
try:os.rename(backup,root)
except Exception:os.rename(failed,root);raise
print('Previous code restored. Rebuild and start the previous web service only after confirming the matched database restore.')
