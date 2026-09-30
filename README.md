# Syntal SSO

Central identity, authentication, organization management, application authorization, and access-control infrastructure for the Syntal platform.

**Current release: `v3.1.3`**

Syntal SSO is the shared identity layer used by Syntal applications to answer five fundamental questions:

- **Who is the user?**
- **Which organization are they operating in?**
- **Which Syntal applications can they access?**
- **What are they allowed to do inside those applications?**
- **How can every application trust the same identity without implementing authentication independently?**

Instead of every Syntal service maintaining its own users, passwords, sessions, roles, permissions, and organization membership, those responsibilities are centralized in Syntal SSO.

---

# What is Syntal SSO?

Syntal SSO is the authentication and authorization service for the Syntal ecosystem.

It provides a common identity system for applications such as:

- Syntal AI
- Newsjacking / NJS
- Blackbook
- Bluebook
- Planner
- Chat
- Boards
- Files
- Landing / Menu
- other internal or future Syntal applications

Applications delegate authentication to Syntal SSO instead of maintaining independent login systems.

A user signs into Syntal SSO once and can then enter authorized Syntal applications using the same identity.

Syntal SSO manages:

```text
User
 ├── Authentication
 ├── Security credentials
 ├── Organizations
 │    ├── Memberships
 │    ├── Roles
 │    ├── Applications
 │    └── Member application access
 │
 ├── Application entitlements
 ├── Permission overrides
 ├── OIDC authorization
 ├── Sessions
 └── Audit information
```

---

# Why does Syntal SSO exist?

A platform composed of multiple applications quickly becomes difficult to secure if every service implements identity independently.

Without a shared identity provider, each application may end up maintaining its own:

- account database
- password implementation
- MFA implementation
- sessions
- organization membership
- roles
- authorization logic
- application access lists
- account recovery
- audit trails
- login UI

That produces duplicated security-sensitive code and inconsistent authorization behavior.

Syntal SSO centralizes those responsibilities.

Instead of:

```text
NJS        → own accounts
Planner    → own accounts
Chat       → own accounts
Files      → own accounts
Blackbook  → own accounts
Bluebook   → own accounts
AI         → own accounts
```

Syntal uses:

```text
                  ┌─────────────────┐
                  │   Syntal SSO    │
                  │                 │
                  │ Identity        │
                  │ Authentication  │
                  │ Organizations   │
                  │ Entitlements    │
                  │ Permissions     │
                  └────────┬────────┘
                           │
          ┌────────────────┼────────────────┐
          │                │                │
          ▼                ▼                ▼
       Planner            NJS           Blackbook
          │                │                │
          ▼                ▼                ▼
        Chat             Files           Bluebook
                           │
                           ▼
                       Syntal AI
```

This makes authentication consistent while allowing individual applications to remain responsible for their own business logic.

---

# Where does Syntal SSO sit in the platform?

Syntal SSO sits between the user and Syntal applications.

In production, the service is exposed through:

```text
https://sso.syntal.pro
```

Individual applications redirect users to Syntal SSO when authentication is required.

A typical production flow looks like:

```text
Browser
   │
   │ Open application
   ▼
app.syntal.pro
   │
   │ No valid application session
   ▼
sso.syntal.pro
   │
   │ Authenticate
   │ Select / resolve organization
   │ Validate application access
   ▼
Authorization Code
   │
   ▼
app.syntal.pro/callback
   │
   │ Exchange code
   ▼
Authenticated application session
```

The application does not need the user's password.

It receives an identity assertion from the trusted SSO service.

---

# How does authentication work?

Syntal SSO supports centralized user authentication and an OIDC-style authorization flow for Syntal applications.

A simplified sequence is:

```text
1. User opens a Syntal application.

2. Application determines that there is no valid local session.

3. Application redirects the browser to Syntal SSO.

4. Syntal SSO authenticates the user.

5. Syntal SSO determines the user's organization context.

6. Application entitlement and access rules are evaluated.

7. Syntal SSO issues an authorization code.

8. The application exchanges that code for trusted identity information.

9. The application creates its local authenticated session.
```

This means credentials remain within the authentication service rather than being sent to every Syntal application.

---

# Authentication Methods

The SSO architecture supports multiple authentication and account-security mechanisms.

These include:

- password authentication
- authenticated browser sessions
- TOTP-based multi-factor authentication
- passkeys / WebAuthn
- recovery and compatibility paths
- application authorization
- refresh-token compatibility
- session lifecycle management

Security-sensitive functionality is centralized so downstream Syntal applications do not need to implement these mechanisms separately.

---

# Organizations

Syntal is organization-aware.

A single account may belong to one or more organizations.

An organization represents an administrative and authorization boundary.

For example:

```text
User
 │
 ├── Organization A
 │    ├── Planner
 │    ├── Chat
 │    └── Files
 │
 └── Organization B
      ├── NJS
      ├── Blackbook
      └── Syntal AI
```

The same user may have different roles and application permissions in different organizations.

Organization context is therefore part of authorization rather than merely a UI preference.

---

# Roles

Organizations can assign roles to members.

Typical role concepts include:

```text
Owner
Administrator
Member
```

Roles provide organization-level authority.

Application access is handled separately so an organization role does not automatically have to imply unrestricted access to every connected application.

This distinction allows Syntal to separate:

```text
Organization authority
```

from:

```text
Application entitlement
```

and:

```text
Application-specific permissions
```

---

# Application Registry

Applications using Syntal SSO are registered with the identity service.

An application registration defines information such as:

- application identity
- client identifier
- permitted redirect URIs
- organization availability
- required entitlements
- authorization behavior
- application permissions

Conceptually:

```text
Syntal SSO
   │
   ├── Application: Planner
   ├── Application: NJS
   ├── Application: Chat
   ├── Application: Files
   ├── Application: Blackbook
   ├── Application: Bluebook
   └── Application: Syntal AI
```

Redirect URI validation prevents authorization results from being sent to arbitrary destinations.

---

# Entitlements

Application registration alone does not mean every user can access the application.

Syntal SSO uses application entitlements to determine whether an organization or user is permitted to use a particular service.

For example:

```text
Organization
   │
   ├── planner.access
   ├── chat.access
   ├── files.access
   └── njs.access
```

An application can therefore exist globally while remaining inaccessible to organizations that have not been granted that service.

---

# Access Matrix

The Access Matrix provides fine-grained control over which organization members can access which applications.

Conceptually:

```text
                  Planner   NJS   Files   Chat
Alice                ✓       ✓      ✓       ✓
Bob                  ✓       -      ✓       ✓
Charlie              -       ✓      -       ✓
Dana                  ✓       -      -       -
```

This allows administrators to manage application access without changing organization membership.

A user may therefore:

```text
belong to an organization
```

but:

```text
not have access to every application belonging to that organization
```

---

# Permission Overrides

Syntal SSO also supports member/application-specific permission control.

Applications may expose permissions such as:

```text
njs.access
njs.admin
planner.access
planner.admin
files.access
files.admin
```

Permissions can be granted or denied at the member/application level.

This provides more precise authorization than a single global role.

The model can be viewed as:

```text
User
  +
Organization membership
  +
Organization role
  +
Application entitlement
  +
Application assignment
  +
Permission overrides
  =
Effective access
```

---

# Authorization Model

Syntal SSO separates authentication from authorization.

Authentication answers:

```text
Who are you?
```

Authorization answers:

```text
What are you allowed to access?
```

Effective access can depend on several layers:

```text
Authenticated user
        │
        ▼
Organization membership
        │
        ▼
Organization application entitlement
        │
        ▼
Member application assignment
        │
        ▼
Permission matrix / overrides
        │
        ▼
Application access
```

This allows applications to remain relatively simple while still enforcing centralized access policies.

---

# Example Login Flow

Assume a user opens:

```text
https://njs.syntal.pro
```

NJS detects that there is no authenticated session and redirects the browser to Syntal SSO.

Example conceptual request:

```text
https://sso.syntal.pro/authorize
    ?client_id=njs
    &redirect_uri=https://njs.syntal.pro/auth/callback
    &state=<random-state>
```

Syntal SSO then:

```text
1. verifies the user
2. verifies the client
3. verifies the redirect URI
4. resolves organization context
5. verifies NJS entitlement
6. verifies member application access
7. evaluates relevant permissions
8. creates an authorization result
```

The browser returns to:

```text
https://njs.syntal.pro/auth/callback
```

NJS exchanges the authorization response and creates an application session.

---

# Why applications keep their own sessions

Syntal SSO authenticates users, but each application can still maintain its own local web session.

That creates a useful separation:

```text
SSO
 └── proves identity and authorization

Application
 └── manages its own runtime session and business logic
```

Applications therefore do not need to send every request through the SSO service.

---

# Security Principles

Syntal SSO is designed around several core principles.

## Centralize sensitive authentication logic

Password handling, MFA, passkeys, authorization, identity sessions, and application registration belong in one security boundary.

## Validate redirect destinations

Authorization responses must only be delivered to registered redirect URIs.

## Separate authentication and authorization

Being signed in does not automatically mean the user may access every Syntal service.

## Separate organization membership and application access

Membership in an organization does not imply access to every application.

## Support explicit deny behavior

Permission overrides can be used to prevent access even when broader roles or defaults would otherwise permit it.

## Maintain compatibility

Schema changes and authorization changes should preserve existing deployments whenever practical.

---

# Deployment

The production Syntal SSO installation is designed to run as a containerized service behind a reverse proxy.

Typical architecture:

```text
Internet
   │
   ▼
Nginx
   │
   │ HTTPS
   ▼
Syntal SSO
   │
   ├── Web application
   │
   └── MongoDB
```

On the Syntal production host, the application root is:

```text
/opt/syntal-sso/core
```

The SSO web service uses the reserved host port:

```text
8003
```

Public HTTPS traffic is terminated by Nginx and routed to the application.

---

# Repository Structure

The exact structure may evolve, but the repository generally contains components similar to:

```text
.
├── app/
├── static/
├── templates/
├── deploy/
│   ├── install-*.py
│   ├── validate-*.py
│   └── runtime-audit-*.py
├── tests/
├── docker-compose.yml
├── Dockerfile
└── README.md
```

Important deployment tooling is kept under:

```text
deploy/
```

---

# Development

For local or controlled development environments, install the required dependencies and provide the expected environment configuration.

The application requires access to its persistence layer and security configuration.

Configuration should be supplied through environment variables or deployment secrets rather than hard-coded into the repository.

Do not commit:

```text
passwords
MongoDB credentials
OIDC secrets
encryption keys
WebAuthn secrets
SMTP passwords
production session secrets
private signing material
```

---

# Production Configuration

Production configuration typically includes settings for:

```text
MongoDB
session security
application base URL
OIDC / application clients
redirect URI validation
WebAuthn
TOTP encryption
SMTP
organization configuration
application entitlements
```

Secrets should be managed outside source control.

---

# Health Checking

The running service should expose or support deployment health verification.

Operational validation should confirm at minimum:

```text
Web service starts
MongoDB is reachable
authentication routes load
authorization routes load
application registration works
organization lookup works
entitlement checks work
access matrix checks work
```

Runtime auditing is preferred over checking only whether the container process exists.

---

# Validation Strategy

Syntal SSO releases use two distinct forms of validation.

## Source validation

Confirms that the expected implementation is present before deployment.

Example:

```bash
python3 deploy/validate-v313.py source
```

## Runtime audit

Confirms that the code actually running inside the deployed environment contains and executes the intended behavior.

This distinction prevents a common deployment failure where:

```text
host source = new version
container = old version
```

Both checks should be performed for production updates.

---

# Current Release

## v3.1.3 — Assignment ID Compatibility

Syntal SSO `v3.1.3` is a compatibility hotfix for per-member application assignments.

Existing Syntal databases may contain the unique MongoDB index:

```text
app_assignment_id_1
```

on:

```text
organization_application_memberships
```

Earlier assignment code transitioned toward:

```text
assignment_id
```

but new records created by `v3.1.2` did not always populate:

```text
app_assignment_id
```

With a unique legacy index still present, MongoDB could therefore treat multiple new records as having the same indexed null value and reject subsequent assignments.

---

# v3.1.3 Fix

Every newly created application assignment now receives one generated ID written into both fields:

```json
{
  "app_assignment_id": "<generated-assignment-id>",
  "assignment_id": "<generated-assignment-id>"
}
```

Therefore:

```text
app_assignment_id == assignment_id
```

for all new assignments.

The compatibility behavior is applied to both:

```text
Access Matrix writer
Application Members writer
```

Existing records remain unchanged.

---

# Why both IDs are written

The two fields represent a transition between schema generations.

Older deployments may still rely on:

```text
app_assignment_id
```

while current application code uses:

```text
assignment_id
```

Writing both fields allows the current application to remain compatible with databases retaining the original unique index.

This avoids an unnecessary production migration.

---

# Database Migration

No migration is required for `v3.1.3`.

Do not remove the existing:

```text
app_assignment_id_1
```

index simply to deploy this release.

Legacy and transitional records may remain unchanged.

New records receive valid non-null identifiers.

---

# Upgrade to v3.1.3

From the Syntal SSO host:

```bash
cd /opt/syntal-sso/core
```

Validate the release source:

```bash
python3 deploy/validate-v313.py source
```

Install the release:

```bash
python3 deploy/install-v313.py \
  --root /opt/syntal-sso/core
```

Rebuild the web service:

```bash
docker compose build web
```

Recreate the running service:

```bash
docker compose up -d --force-recreate web
```

Verify container state:

```bash
docker compose ps
```

Review logs:

```bash
docker compose logs --tail=200 web
```

---

# Runtime Audit

Run the release audit from inside the deployed web container:

```bash
docker compose exec -T web \
  python /app/deploy/runtime-audit-v313.py
```

The runtime audit should be used to confirm the actual deployed version, not merely the source files present on the host.

---

# Verify Assignment Compatibility

After deployment, create assignments using both supported UI paths.

## Access Matrix

Create application assignments for multiple users.

The writes should succeed without duplicate-key errors.

## Application Members

Add multiple members to an application.

Again, all writes should succeed.

New records should contain:

```json
{
  "app_assignment_id": "assign_xxxxxxxxx",
  "assignment_id": "assign_xxxxxxxxx"
}
```

Both IDs should:

```text
exist
be non-null
be identical
be unique per assignment
```

---

# MongoDB Verification

New assignments can be inspected directly:

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

For records created by `v3.1.3`:

```text
app_assignment_id == assignment_id
```

Legacy records may retain their previous representation.

---

# When should Syntal SSO be used?

A Syntal application should integrate with SSO whenever it needs authenticated access by Syntal users.

Use Syntal SSO when an application needs:

- user authentication
- organization context
- centralized login
- application entitlement checks
- member-level access control
- shared identity with other Syntal services
- SSO logout/session behavior
- centralized permission evaluation

An application generally should not create a separate password database when Syntal identity is sufficient.

---

# When should authorization stay inside the application?

Not every permission belongs in SSO.

Syntal SSO should primarily control:

```text
Can this identity enter this application?
What high-level permissions does this identity have?
```

The application itself should control domain-specific rules such as:

```text
Can this user edit this specific article?
Can this user delete this project?
Can this user modify this particular file?
Can this user approve this campaign?
```

This keeps the identity layer generic while allowing applications to enforce their own business rules.

---

# Where is identity enforced?

Authorization exists at multiple boundaries.

```text
Browser
   │
   ▼
Syntal SSO
   │
   ├── authentication
   ├── organizations
   ├── application access
   └── high-level permissions
   │
   ▼
Application
   │
   ├── authenticated session
   └── business-specific authorization
   │
   ▼
Application data
```

SSO is therefore one part of the security model, not a replacement for application-level authorization.

---

# Operational Model

A normal Syntal deployment follows this lifecycle:

```text
Develop
   ↓
Validate source
   ↓
Install
   ↓
Build container
   ↓
Recreate service
   ↓
Runtime audit
   ↓
Functional verification
   ↓
Production
```

This is particularly important for identity infrastructure because an apparently small change can affect every application that depends on SSO.

---

# Connected Syntal Services

Syntal SSO is intended to act as the common identity provider for the Syntal application family.

```text
                    Syntal SSO
                        │
        ┌───────────────┼───────────────┐
        │               │               │
        ▼               ▼               ▼
   Syntal AI           NJS          Blackbook
        │               │               │
        ▼               ▼               ▼
     Planner           Chat          Bluebook
        │               │
        ▼               ▼
      Files           Boards
```

New applications can join the ecosystem by registering an SSO client and implementing the expected authorization flow.

---

# Design Goal

The long-term purpose of Syntal SSO is straightforward:

> One identity, multiple organizations, multiple applications, one consistent authorization boundary.

Users should not need to maintain separate Syntal accounts for every service.

Application developers should not need to rebuild authentication infrastructure for every new product.

Administrators should have one place to determine who belongs to an organization and which Syntal applications they can access.

---

# Release

Current production line:

```text
Syntal SSO v3.1.3
```

Primary change:

```text
Assignment ID compatibility for legacy MongoDB indexes.
```

Migration required:

```text
No
```

Index modification required:

```text
No
```

Deployment validation:

```text
deploy/validate-v313.py
```

Runtime validation:

```text
deploy/runtime-audit-v313.py
```

---

# Project Status

Syntal SSO is active infrastructure for the Syntal platform.

Changes to authentication, OIDC behavior, organization resolution, entitlements, application registration, the Access Matrix, or permission enforcement should be treated as platform-level changes because they may affect multiple connected applications.

Security-sensitive changes should always be validated in both source and deployed runtime environments before being considered complete.
