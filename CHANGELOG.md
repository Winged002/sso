# Changelog

## 4.0.0

- Added organization-scoped OIDC and SAML 2.0 federation.
- Added single-use, browser-bound federation transactions and proof-based existing-account linking.
- Added SCIM 2.0 user provisioning and deactivation.
- Added tenant-scoped service accounts and client-credentials JWT issuance.
- Added encrypted managed RSA signing keys with active/retiring/retired lifecycle and multi-key JWKS.
- Added signed organization event subscriptions and durable retryable event deliveries.
- Added enterprise administration pages and v4 role permissions.
- Integrated v3.3 legacy `slug_1` / `email_normalized_1` compatibility handling.
- Preserved v3.3 authorization, PKCE, session/MFA and refresh-token hardening.
