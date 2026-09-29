# Release notes — Syntal SSO v3.1.3

## Fixed

- Fixed `DuplicateKeyError` on `organization_application_memberships.app_assignment_id`.
- New Access Matrix assignments now write legacy `app_assignment_id` and current `assignment_id` together.
- Application Members role assignment uses the same compatibility contract.
- Existing assignment identifiers are preserved because `$setOnInsert` only runs for new documents.

## Compatibility

- No database migration.
- No index deletion or recreation.
- All v3.1.2 per-member permission behavior is retained.
- All v3.1.x SMTP, glass UI, OIDC, inline registration, MFA and signing fixes are retained.
