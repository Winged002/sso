#!/usr/bin/env python3
from pathlib import Path
import argparse, os, shutil
p=argparse.ArgumentParser(); p.add_argument('--root',default='/opt/syntal-sso/core'); p.add_argument('--backup',required=True); a=p.parse_args()
root=Path(a.root).resolve(); backup=Path(a.backup).resolve()
if not backup.exists(): raise SystemExit(f'Backup not found: {backup}')
failed=root.parent/(root.name+'.failed-v313')
if failed.exists(): shutil.rmtree(failed)
if root.exists(): os.rename(root,failed)
os.rename(backup,root)
print('Rollback complete:',root)
