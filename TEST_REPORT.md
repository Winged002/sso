# v4.0.0 validation report

Validation performed in the artifact-generation runtime:

- Python AST/bytecode syntax validation: **PASS** — 45 Python files parsed/compiled.
- Jinja template parsing: **PASS** — 63 templates parsed.
- Required route-contract static audit: **PASS** for enterprise root, service-token, SCIM Users, SAML ACS and JWKS routes.
- v3.3 source base recovered from the previously generated `Syntal-SSO-v3.3.0.zip` release.
- v3.3 legacy-index compatibility hotfix applied before v4 changes.

The full behavioral pytest suite was **not executed in the artifact-generation runtime** because its isolated Python environment does not contain Flask/PyMongo/Redis/mongomock/fakeredis and outbound package installation is unavailable. This release therefore includes `deploy/validate-v400.py` as a mandatory deployment gate. It parses source/templates and then runs the complete packaged test suite in the SSO image, where the pinned dependencies are installed.

New v4 tests cover enterprise-page registration, service-account credentials, SCIM authentication/provisioning, federation transaction replay protection, signing-key overlap, signed event delivery and the v4 schema marker/indexes.
