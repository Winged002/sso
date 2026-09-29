# Syntal SSO v3.1.3 — Assignment ID Compatibility

Compatibility hotfix for per-member application access writes.

## Fix

Existing Syntal databases may have a unique `app_assignment_id_1` index on `organization_application_memberships`. v3.1.2 created new member/app assignment records with only `assignment_id`, which caused MongoDB to index `app_assignment_id` as null and reject subsequent inserts.

v3.1.3 writes both `app_assignment_id` and `assignment_id` with the same generated value on every new assignment, while preserving existing records unchanged. Both the Access Matrix writer and the Application Members writer are covered.

No database migration or index change is required. Existing null legacy/transition records may remain; all new records receive non-null unique IDs.

## Validate

```bash
python3 deploy/validate-v313.py source
```

## Install

```bash
python3 deploy/install-v313.py --root /opt/syntal-sso/core
```

Then rebuild/recreate the `web` service and run `deploy/runtime-audit-v313.py` inside the container.
