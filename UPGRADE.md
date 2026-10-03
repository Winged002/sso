# Upgrade to Syntal SSO v4.0.0

Target installation path: `/opt/syntal-sso/core`.

## 1. Back up MongoDB and current SSO source

Create and verify a database backup before applying the v4 migration. The code installer also creates a timestamped source backup beside the live SSO directory, but that source backup is not a database backup.

## 2. Stop the web service

```bash
cd /opt/syntal-sso/core
docker compose stop web
```

Keep MongoDB and Redis available for preflight/migration unless your deployment topology requires otherwise.

## 3. Install v4 source

From the extracted release directory:

```bash
python3 deploy/install-v400.py --root /opt/syntal-sso/core --web-stopped
```

The installer preserves `.env`, Compose files, `instance/`, `secrets/`, `certs/` and PEM/key/certificate files.

## 4. Rebuild the image

```bash
cd /opt/syntal-sso/core
docker compose build web
```

## 5. Run read-only preflight

```bash
docker compose run --rm web python3 deploy/preflight-v400.py
```

Resolve every blocker before migration. The compatibility layer supports the known legacy `slug_1` and `email_normalized_1` indexes without dropping them.

## 6. Apply migration

Only after confirming the database backup:

```bash
docker compose run --rm web \
  python3 deploy/migrate-v400.py --apply --backup-confirmed
```

The migration first applies/revalidates the v3.3 security schema, then creates the v4 enterprise collections/indexes and adds enterprise management permissions to active organization admin roles. Existing owner wildcard authority is unchanged.

## 7. Run validation

```bash
docker compose run --rm web python3 deploy/validate-v400.py
```

This parses Python and Jinja sources and runs the complete test suite. Do not start the release if this command fails.

## 8. Start and audit

```bash
docker compose up -d web
docker compose exec -T web python3 deploy/runtime-audit-v400.py
curl -fsS https://sso.syntal.pro/healthz
curl -fsS https://sso.syntal.pro/readyz
```

Both health endpoints should report version `4.0.0` and readiness should be healthy.

## 9. Event delivery worker

Run the event worker repeatedly. Example cron cadence:

```bash
* * * * * cd /opt/syntal-sso/core && docker compose exec -T web python3 deploy/event-worker-v400.py >/var/log/syntal-sso-events.log 2>&1
```

For higher event volume, move the same delivery function to your existing worker system rather than increasing web-worker responsibilities.

## Signing-key rotation

The configured bootstrap RSA key remains usable until you explicitly rotate through the v4 Signing Keys page. On first managed rotation, v4 attempts to publish the previous configured RSA public key as `retiring` so existing signed tokens can continue to verify during the overlap period. Retire that old key only after the maximum token lifetime and any external JWKS caches have elapsed.

## Rollback

If failure occurs before database migration, restore the installer-created source backup and rebuild the previous image.

If migration has already been applied, use the verified pre-upgrade database backup for a full rollback. Do not assume restoring source files alone reverses schema or security-state changes.
