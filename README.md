# Syntal SSO v3.1.3

**Assignment ID Compatibility Hotfix**

Syntal SSO v3.1.3 is a compatibility release for per-member application access assignments.

It fixes assignment creation against existing Syntal SSO databases that retain the legacy unique `app_assignment_id_1` MongoDB index on the `organization_application_memberships` collection.

No database migration or index modification is required.

---

## Overview

Syntal SSO provides centralized authentication, organization management, application registration, entitlements, and per-member access control for the Syntal platform.

This release specifically addresses compatibility between the current assignment model and databases created by earlier Syntal SSO releases.

### Release

- **Version:** `3.1.3`
- **Type:** Compatibility hotfix
- **Database migration:** Not required
- **Index migration:** Not required
- **Primary area:** Application membership assignments
- **Affected writers:**
  - Access Matrix
  - Application Members

---

## Fix

Existing Syntal databases may contain the following unique MongoDB index on `organization_application_memberships`:

```text
app_assignment_id_1
```

Syntal SSO v3.1.2 created new member/application assignment records using:

```text
assignment_id
```

but did not populate:

```text
app_assignment_id
```

Because the existing unique index continued to operate on `app_assignment_id`, MongoDB treated the missing field as `null`.

The first transitional record could therefore be created, but subsequent records could fail because multiple assignments attempted to occupy the same indexed `null` value.

Typical behavior included failed per-member application assignments despite otherwise valid organization, user, application, and permission data.

---

## v3.1.3 Behavior

Syntal SSO v3.1.3 generates one assignment identifier and writes it to both fields:

```json
{
  "app_assignment_id": "<generated-assignment-id>",
  "assignment_id": "<generated-assignment-id>"
}
```

The two identifiers are therefore identical for every newly created assignment.

This preserves compatibility with both:

- legacy code and indexes using `app_assignment_id`
- current code using `assignment_id`

Existing records are left unchanged.

---

## Compatibility

v3.1.3 is designed to work without modifying existing Syntal databases.

Existing records may contain:

```text
app_assignment_id = null
```

or may reflect an intermediate schema from previous releases.

These records do not need to be rewritten as part of this release.

All newly created assignment records receive a non-null unique identifier in both:

```text
app_assignment_id
assignment_id
```

The fix applies consistently to both assignment creation paths:

1. **Access Matrix writer**
2. **Application Members writer**

---

## Database Changes

No database migration is required.

Do **not** remove or recreate the existing `app_assignment_id_1` index solely for this release.

The compatibility layer intentionally supports databases where the legacy index remains present.

Existing data remains untouched.

---

## Source Validation

Validate the release before deployment:

```bash
python3 deploy/validate-v313.py source
```

The validation should confirm that the v3.1.3 source contains the assignment compatibility changes before the installation is applied.

---

## Install

Install v3.1.3 into the production Syntal SSO root:

```bash
python3 deploy/install-v313.py --root /opt/syntal-sso/core
```

After installation, rebuild and recreate the `web` service so the running container uses the updated source.

For a standard Docker Compose deployment:

```bash
cd /opt/syntal-sso/core

docker compose build web
docker compose up -d --force-recreate web
```

Verify that the service started successfully:

```bash
docker compose ps
```

Check recent application logs if necessary:

```bash
docker compose logs --tail=200 web
```

---

## Runtime Audit

After the new container is running, execute the v3.1.3 runtime audit inside the `web` service.

```bash
docker compose exec -T web \
  python /app/deploy/runtime-audit-v313.py
```

If the deployment layout places the audit script elsewhere inside the container, execute the corresponding installed path.

The runtime audit should verify the deployed application rather than only the source tree on the host.

---

## Functional Verification

After deployment, verify both assignment paths.

### Access Matrix

From the Syntal SSO administration interface:

1. Open an organization.
2. Open the Access Matrix.
3. Select a member and application.
4. Add or modify application access.
5. Save the assignment.
6. Repeat the operation for another member/application combination.

Multiple assignments should save without duplicate-key failures.

### Application Members

Open an application's member-management interface and create or modify access for multiple members.

Each newly created database record should contain both identifiers.

Example:

```json
{
  "app_assignment_id": "assign_xxxxxxxxx",
  "assignment_id": "assign_xxxxxxxxx"
}
```

The values must match and must not be null.

---

## Optional Database Verification

Assignment records can be inspected directly in MongoDB after deployment.

For newly created records, verify that both fields exist:

```javascript
db.organization_application_memberships.find(
  {},
  {
    app_assignment_id: 1,
    assignment_id: 1,
    organization_id: 1,
    application_id: 1,
    user_id: 1
  }
)
```

For new v3.1.3 assignments:

```text
app_assignment_id == assignment_id
```

and both values should be non-null.

Legacy or transitional records may remain unchanged.

---

## Deployment Summary

```bash
cd /opt/syntal-sso/core

# Validate source
python3 deploy/validate-v313.py source

# Install release
python3 deploy/install-v313.py --root /opt/syntal-sso/core

# Rebuild
docker compose build web

# Recreate
docker compose up -d --force-recreate web

# Verify container
docker compose ps

# Run runtime audit
docker compose exec -T web \
  python /app/deploy/runtime-audit-v313.py
```

---

## Upgrade Notes

Upgrading to v3.1.3:

- does not require MongoDB migration
- does not require rebuilding indexes
- does not rewrite existing assignments
- preserves legacy `app_assignment_id` compatibility
- preserves current `assignment_id` semantics
- fixes new assignment creation through the Access Matrix
- fixes new assignment creation through Application Members

The release is intended to be safe for existing Syntal SSO installations carrying historical database indexes and records.

---

## Syntal SSO

Syntal SSO is the identity and authorization layer for the Syntal application ecosystem, providing centralized authentication, organizations, application registration, entitlements, member access controls, and application-level permission management.
