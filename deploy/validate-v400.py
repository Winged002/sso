#!/usr/bin/env python3
"""Parse every Python/Jinja source and execute behavioral regressions."""
import _bootstrap
import ast,os,subprocess,sys
from pathlib import Path
from jinja2 import Environment,FileSystemLoader
root=Path(__file__).resolve().parents[1]
source=root/'source' if (root/'source'/'syntal_sso').exists() else root
python=list(source.rglob('*.py'))+list((root/'deploy').glob('*.py'))
for file in python:ast.parse(file.read_text(),filename=str(file))
templates=source/'syntal_sso'/'templates';env=Environment(loader=FileSystemLoader(templates))
for name in env.list_templates():env.parse(env.loader.get_source(env,name)[0])
print(f'Parsed {len(python)} Python files and {len(env.list_templates())} Jinja templates.',flush=True)
print('Database backend: '+('real MongoDB' if os.environ.get('SSO_TEST_MONGO_URI') else 'mongomock'),flush=True)
print('Session backend: '+('real Redis' if os.environ.get('SSO_TEST_REDIS_URL') else 'fakeredis'),flush=True)
sys.exit(subprocess.call([sys.executable,'-m','pytest','-q',str(source/'tests')]))
