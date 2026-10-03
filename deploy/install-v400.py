#!/usr/bin/env python3
"""Install code only. Preflight and explicit migration precede starting the new web service."""
from pathlib import Path
import argparse,datetime,os,shutil,re
p=argparse.ArgumentParser();p.add_argument('--root',default='/opt/syntal-sso/core');p.add_argument('--web-stopped',action='store_true');args=p.parse_args()
if not args.web_stopped:p.error('Stop the web service before replacing code; acknowledge --web-stopped.')
root=Path(args.root).resolve();package=Path(__file__).resolve().parents[1];source=package/'source'
if not root.is_dir():raise SystemExit('Existing SSO directory not found')
if (source/'VERSION').read_text().strip()!='4.0.0':raise SystemExit('Invalid source payload')
stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S-%f');stage=root.parent/('.v400-stage-'+stamp);backup=root.parent/('.backup-v400-'+stamp)
shutil.copytree(source,stage,ignore=shutil.ignore_patterns('__pycache__','*.pyc','.pytest_cache'))
shutil.copytree(package/'deploy',stage/'deploy',ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
shutil.copy2(package/'README.md',stage/'RELEASE_README.md');shutil.copy2(package/'UPGRADE.md',stage/'UPGRADE.md')
for name in ['.env','.env.production','docker-compose.yml','compose.yml','compose.yaml','docker-compose.override.yml','docker-compose.override.yaml']:
    if (root/name).is_file():shutil.copy2(root/name,stage/name)
for name in ['instance','secrets','certs']:
    if (root/name).is_dir():shutil.copytree(root/name,stage/name,symlinks=True,dirs_exist_ok=True)
for pattern in ['*.pem','*.key','*.crt']:
    for file in root.glob(pattern):
        if file.is_file():shutil.copy2(file,stage/file.name)
for name in ['docker-compose.yml','compose.yml','compose.yaml','docker-compose.override.yml','docker-compose.override.yaml']:
    f=stage/name
    if f.exists():f.write_text(re.sub(r'syntal-sso:\d+\.\d+(?:\.\d+)?','syntal-sso:4.0.0',f.read_text()))
os.rename(root,backup)
try:os.rename(stage,root)
except Exception:os.rename(backup,root);raise
print('Installed v4.0.0 source. Database unchanged by this installer.')
print('Code backup:',backup)
print('Next: build the image, run preflight, apply migration after confirming the database backup, then start web. See UPGRADE.md.')
