# Migrating from `mrjim-auth` to Supabase Auth

The client names are deliberately familiar, but `mrjim-auth` and Supabase
Auth do not share a database schema, token issuer, API-key format, migration
history, or hosted control plane. Treat this as a planned identity-provider
migration, not as a package swap.

## What changes

`mrjim-auth` owns an `auth` schema in the project's PostgreSQL database. Its
users, identities, Argon2id password credentials, sessions, rotating refresh
tokens, one-time proofs, OAuth state, roles, permissions, API keys, audit log,
and rate-limit buckets are project data. Supabase Auth has its own managed
service and schema conventions. Do not point Supabase migrations at an
existing `mrjim-auth` database and do not rewrite the applied `auth` migration
files as part of a cutover.

The client response envelope is similar, but payloads and errors are not
interchangeable. Reconfigure the URL/key, replace the server verification
issuer, update redirect allowlists, and plan for active sessions to be
invalidated or re-established.

## Migration checklist

### 1. Inventory the source project

Before changing traffic, record:

- `auth.users` users, normalized email/phone values, confirmation timestamps,
  metadata, ban state, and soft-deletion state;
- `auth.identities` provider/subject pairs and only the safe identity profile
  fields;
- roles, permissions, inheritance, scoped assignments, and the application
  tables that reference user UUIDs;
- configured Google/OIDC redirect URLs and provider client settings;
- mailer templates, recovery/signup/invite behavior, rate-limit policy, and
  audit retention requirements;
- all clients and backend services that validate the current issuer/audience.

Never export raw access tokens, refresh tokens, password inputs, encryption
keys, token-hash keys, provider client secrets, or raw API keys.

### 2. Decide password handling explicitly

The source schema stores Argon2id password hashes. Do not assume that the
target provider accepts those hashes or that its password-hash parameters are
compatible. Choose one of these project policies:

1. use an officially supported password-hash import path after verifying the
   target's exact format and parameters;
2. require a password reset for every migrated account; or
3. run a controlled just-in-time migration only if both systems document the
   same verification format and the implementation has been independently
   reviewed.

Keep the old verifier read-only during a bounded transition if a seamless
cutover is required. Never copy password hashes into application metadata.

### 3. Map users and identities

Create a deterministic mapping from each source UUID to the target user ID.
Preserve email ownership and confirmation only when the target's import rules
allow it. Re-link OAuth identities using the target provider/subject contract;
do not copy encrypted verifiers or provider access/refresh tokens.

Keep the source-to-target mapping in a restricted migration table or an
encrypted migration artifact owned by the project. Validate uniqueness and
referential integrity before switching any application foreign keys.

### 4. Move roles and permissions separately

Supabase Auth does not make this package's dynamic `auth.roles`,
`auth.permissions`, `auth.role_permissions`, `auth.role_inheritance`, and
`auth.user_roles` model a drop-in replacement. Keep authorization in
project-owned application tables or translate it to the target's chosen RLS,
claims, or policy design. Re-test every backend authorization decision against
the target user IDs and session verification path.

Do not use a client-provided `app_metadata` value as the only authorization
source. Recompute or verify roles on the trusted backend.

### 5. Reconfigure OAuth and email

Register target callback URLs with Google/OIDC, update the project's exact
redirect allowlist, and verify PKCE state handling in a staging project. Test
sign-in, identity linking, unlinking, recovery, signup confirmation, invite,
and resend behavior with real provider test accounts.

Replace the project mailer integration as needed. A hosted mail provider is a
Supabase deployment choice, not a requirement of this SDK migration.

### 6. Replace server verification and secrets

Every API that validates `mrjim-auth` access tokens must switch from the old
issuer, audience, JWKS, and session assumptions to the target verifier. Rotate
or revoke source API keys, signing keys, encryption keys, token-hash keys, and
refresh-token families according to the project's incident/cutover policy.

The `createAdminClient` secret is never a user-session bearer token. Remove it
from application bundles, server logs, CI output, and cookies before cutover.

## Client call mapping

The common call shape can make the application change incremental:

```ts compile
import { createClient } from "mrjim-auth";

const auth = createClient(
  process.env.AUTH_URL!,
  process.env.AUTH_PUBLISHABLE_KEY!,
  { auth: { flowType: "pkce", storageKey: "web" } },
);

async function example(): Promise<void> {
  const result = await auth.auth.getUser();
  if (result.error !== null) {
    console.error(result.error.code);
  } else {
    console.log(result.data.user.email);
  }
}

void example();
```

During the migration, isolate the provider behind an application auth module
so route handlers do not depend on provider-specific error classes or raw
responses. Replace the module's implementation in a controlled release.

Typical call-level changes are:

| Current call | Migration action |
| --- | --- |
| `createClient(authUrl, publishableKey, options)` | Replace URL/key/options and verify browser/SSR storage behavior. |
| `auth.getSession()` | Treat as local cache only; use the target's server-authoritative user/session check. |
| `auth.getUser()` | Replace issuer-aware backend verification and handle target error codes. |
| `auth.signInWithOAuth()` | Re-register callbacks, preserve PKCE, and verify provider discovery/callback behavior. |
| `auth.getPermissions()` | Move to the application's target authorization service; this method is not a Supabase query/RLS substitute. |
| `auth.admin.*` | Replace with the target's trusted administration API and audit its authorization boundary. |
| `{ data, error }` | Keep the application wrapper, but normalize provider-specific payload/error differences at that boundary. |

Do not attempt to use `from`, `rpc`, `storage`, or `realtime` through this
package during the transition; those surfaces are explicitly outside v1.

## Cutover sequence

1. Build and validate the source inventory and UUID mapping.
2. Import a sanitized staging copy and run application, OAuth, recovery,
   authorization, and SSR tests against the target.
3. Freeze or queue writes, export a final delta, and reconcile duplicate/
   deleted/confirmed accounts.
4. Invalidate source sessions and rotate source secrets according to policy.
5. Deploy the target URL/key/configuration and target token verifier together.
6. Monitor sign-in, refresh, recovery, OAuth callback, authorization denials,
   and email delivery with correlation IDs.
7. Retain the source database read-only for the documented recovery window,
   then dispose of migration artifacts and secrets securely.

Keep a rollback decision separate from database rollback. The `mrjim-auth`
migration runner has no down operation, and a provider cutover should be
reversed by traffic/configuration policy only after confirming which identity
records and sessions were written in each system.

## No paid dependency requirement

This migration guide does not require a paid app, hosted migration service, or
special plugin. The source system can be self-hosted with the project's Node
runtime and PostgreSQL. Supabase hosting, email, database, storage, and
realtime are independent target choices and must be evaluated separately.
