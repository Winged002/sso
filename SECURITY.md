# Security notes — v4.0.0

Federation does not link an external identity to an existing Syntal account based on email alone. First-time linking to an existing account requires that same Syntal account to already be authenticated in the browser. New federation-only users require a verified email claim.

OIDC federation transactions use single-use state, signed-token nonce validation, a ten-minute expiry and an originating-browser proof. SAML uses the same transaction protections and requires a signed response/assertion, configured X.509 trust, matching audience and `InResponseTo`, and valid time conditions.

Service-account secrets and SCIM bearer tokens are shown only at creation and stored as hashes. Federation client secrets, SAML certificates used as trust material, managed signing private keys and webhook signing secrets are sealed with the existing account-secret encryption key.

Webhook event endpoints must use HTTPS. Delivery signatures use `HMAC-SHA256(secret, timestamp + "." + raw_body)` and include stable event and delivery identifiers for receiver-side replay/idempotency handling.

Managed signing keys are RSA-3072. JWKS publishes active and retiring keys. Never retire an old key before all tokens signed by it and dependent verifier caches have expired.
