#!/usr/bin/env python3
"""Atomic source replacement for Syntal SSO v3.1.3.

No database migration is performed. Existing environment files, Compose files,
OIDC/signing material and runtime state directories are preserved. SMTP settings
already present in the preserved environment are reused by v3.1.3.
"""
from pathlib import Path
import argparse, datetime, os, re, shutil

VERSION = "3.1.3"
PRESERVE_FILES = [".env", ".env.production", "docker-compose.yml", "compose.yml", "docker-compose.override.yml"]
PRESERVE_DIRS = ["instance", "secrets", "certs"]


def copy_preserved(old: Path, stage: Path):
    for name in PRESERVE_FILES:
        src = old / name
        if src.exists():
            shutil.copy2(src, stage / name)
    for name in PRESERVE_DIRS:
        src = old / name
        if src.exists():
            dst = stage / name
            if dst.exists(): shutil.rmtree(dst)
            shutil.copytree(src, dst, symlinks=True)
    for pattern in ("*.pem", "*.key", "*.crt"):
        for src in old.glob(pattern):
            if src.is_file(): shutil.copy2(src, stage / src.name)


def update_compose(stage: Path):
    for name in ("docker-compose.yml", "compose.yml", "docker-compose.override.yml"):
        path = stage / name
        if not path.exists(): continue
        text = path.read_text(errors="ignore")
        text = re.sub(r"syntal-sso:\d+\.\d+(?:\.\d+)?", "syntal-sso:3.1.3", text)
        path.write_text(text)


def main():
    parser=argparse.ArgumentParser(); parser.add_argument("--root",default="/opt/syntal-sso/core"); args=parser.parse_args()
    root=Path(args.root).resolve(); package=Path(__file__).resolve().parents[1]; source=package/"source"
    if not source.exists() or (source/"VERSION").read_text().strip()!=VERSION: raise SystemExit("Invalid v3.1.3 source payload")
    if not root.exists(): raise SystemExit(f"Current SSO root not found: {root}")
    forbidden=[p for p in source.rglob("*") if p.is_file() and ("migration" in p.name.lower() or "migrate" in p.name.lower())]
    if forbidden: raise SystemExit("Refusing install: migration-like files are present in source payload")
    parent=root.parent; stamp=datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    backup=parent/f".backup-v313-{stamp}"; stage=parent/f".v313-stage-{stamp}"
    if stage.exists(): shutil.rmtree(stage)
    shutil.copytree(source,stage,symlinks=True); copy_preserved(root,stage); update_compose(stage)
    os.rename(root,backup)
    try: os.rename(stage,root)
    except Exception:
        os.rename(backup,root); raise
    print("Syntal SSO v3.1.3 Assignment ID Compatibility installed")
    print(f"root:   {root}"); print(f"backup: {backup}")
    print("database migration: NONE"); print("Mongo/Redis volumes: untouched")
    print("preserved: env + compose + signing keys + secrets + certs + instance")
    print("included: v3.1 glass UI + SMTP + styled email templates + inline OAuth organization app registration + per-member app access/permissions matrix + v3.0.x compatibility fixes")

if __name__=="__main__": main()
