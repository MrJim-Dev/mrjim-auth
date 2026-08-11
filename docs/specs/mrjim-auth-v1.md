# mrjim-auth v1 Technical Specification

**Status:** Proposed  
**Date:** 2026-08-10  
**Runtime:** Node.js 24 LTS, modern browsers, server-side JavaScript runtimes with Web `Request`/`Response` support  
**Database:** PostgreSQL 15 or newer  
**Package:** `mrjim-auth`

## 1. Outcome

`mrjim-auth` is a reusable authentication and authorization SDK installed into each project. Every project owns and operates its own backend, PostgreSQL database, signing keys, email delivery, OAuth credentials, redirect allowlist, rate limiting, and user records.

The SDK provides:

- a Supabase-inspired `client.auth` API for browser, mobile JavaScript, server, and SSR usage;
- framework-neutral HTTP handlers under `/auth/v1`;
- a clean PostgreSQL `auth` schema and explicit migration CLI;
- email/password, email verification, password recovery, magic-link/OTP, and Google OAuth flows;
- rotating access and refresh sessions;
- dynamic roles, permissions, role inheritance, scoped assignments, and authorization helpers;
- server-only user, role, permission, API-key, and audit administration;
- generated API references, OpenAPI output, security guidance, examples, and a Supabase migration guide.

This is not a hosted identity service. Installing projects do not call a central MrJim service and do not share users unless they deliberately configure a shared database or later add federation.

## 2. Goals

1. Make application code familiar to developers who already use Supabase Auth.
2. Keep all user and authorization data in the installing project's dedicated database.
3. Support browser clients, Node.js APIs, SSR, and server-only administration without leaking privileged code into browser bundles.
4. Preserve Hayahai's useful user/provider/session and resource-action permission concepts while removing shipping, tenant, passenger, port, vessel, TMS, and other business-specific fields.
5. Make roles and permissions data-driven rather than compiled enums.
6. Use secure defaults, explicit unsafe opt-ins, and auditable security-sensitive operations.
7. Treat documentation, examples, schema reference, migration notes, and compatibility tables as release artifacts.
8. Require only free/open-source libraries and project-owned infrastructure; paid SaaS products may appear only as optional adapters.

## 3. Non-goals for v1

- Database querying, realtime, storage, and edge-function APIs similar to the rest of `supabase-js`.
- A shared cross-project identity database or automatic SSO between projects.
- SMS/WhatsApp authentication.
- SAML, SCIM, enterprise directory sync, passkeys, or TOTP MFA.
- Acting as a general OAuth authorization server for third-party applications.
- Automatic production schema changes during application startup.
- Database-specific adapters other than PostgreSQL.
- Any paid application, hosted auth service, or commercial SaaS subscription as a required runtime, build, test, documentation, or release dependency.

The schema leaves room for MFA and additional OAuth/OIDC providers without promising those features in v1.

## 4. Design provenance

The design is informed by, but does not import or depend on, these Hayahai sources:

- `ayahay-client-api/src/modules/auth`: register, login, refresh, recovery, verification, profile, password change, logout, and token validation.
- `ayahay-client-api/src/modules/users`: server-side user search and administration.
- `ayahay-client-api/src/modules/roles` and `src/modules/permissions`: dynamic role-permission joins and `resource:action` authorization.
- `ayahay-client-api/src/database/db.d.ts`: users, providers, refresh tokens, verification tokens, roles, permissions, assignments, and login history.
- `ayahay-api-v2/src/modules/auth-sso`: provider discovery, verified provider identities, signed OAuth state, PKCE mobile exchange, identity linking, and unlink safety.
- `ayahay-api-v2/src/database/migrations/00000000000000_bootstrap_schema.ts` and OAuth migrations: PostgreSQL schema organization and migration precedent.

The new design intentionally does not copy these Hayahai behaviors:

- shipping-line, tenant, passenger, port, ship, cabin, TMS, or marketplace columns and seed data;
- plaintext refresh tokens or provider tokens;
- reset codes returned by development API responses or written to logs;
- user profile JSON in a JavaScript-readable cookie;
- authorization bypass through an empty permission decorator;
- a service key accepted from an ordinary browser cookie;
- unencrypted OAuth client secrets in ordinary tables;
- public user-existence lookup;
- permission management based only on a numeric role level.

## 5. Architecture

`mrjim-auth` is one published package with environment-safe subpath exports:

| Import | Runtime | Responsibility |
| --- | --- | --- |
| `mrjim-auth` | Browser or server | `createClient`, session state, auth methods, events, transport |
| `mrjim-auth/server` | Node.js only | Auth service, policy engine, token issuing, HTTP handler |
| `mrjim-auth/postgres` | Node.js only | PostgreSQL repositories and migrations |
| `mrjim-auth/express` | Node.js only | Express adapter |
| `mrjim-auth/nextjs` | Browser and server split exports | Browser singleton and per-request cookie clients |
| `mrjim-auth/testing` | Test only | Test server, fake mailer, deterministic clock, factories |

`package.json` export conditions must prevent `server`, `postgres`, password hashing, private-key, and migration code from entering browser bundles.

### Request flow

~~~text
Browser / mobile JS / SSR code
        |
        | mrjim-auth client methods
        v
Project backend: /auth/v1/*
        |
        | AuthServer + policy checks
        +---- PostgreSQL auth schema
        +---- Project mailer
        +---- Project OAuth credentials
        +---- Project signing/key provider
        +---- Project rate limiter and logger
~~~

No SDK method connects directly from a browser to PostgreSQL.

### Adapter trust boundary

Project-supplied repository, mailer, OAuth, key-provider, rate-limiter, logger,
cookie, and framework adapters are trusted executable code selected by the
project operator. They run in the same JavaScript process as `mrjim-auth`; the
SDK does not claim to sandbox an arbitrary hostile adapter or code that mutates
the realm before the SDK module is initialized.

Values returned or thrown by an adapter are nevertheless untrusted data. The
server boundary validates returned values, maps arbitrary thrown values to
fixed public errors, and never exposes adapter messages, stacks, causes,
details, recipient identifiers, tokens, codes, or provider secrets. Security-
sensitive identity bookkeeping captures the required JavaScript intrinsics at
module initialization so a callback cannot change those decisions by
temporarily replacing mutable prototype methods while it executes.

## 6. Package initialization

### Browser or isomorphic client

~~~ts
import { createClient } from "mrjim-auth";

const client = createClient(
  "https://project.example.com/auth/v1",
  process.env.NEXT_PUBLIC_AUTH_PUBLISHABLE_KEY,
  {
    auth: {
      autoRefreshToken: true,
      persistSession: true,
      detectSessionInUrl: true,
      flowType: "pkce",
      storageKey: "project-auth",
    },
    global: {
      headers: { "x-client-name": "project-web" },
    },
  },
);
~~~

### Server

~~~ts
import { createAuthServer } from "mrjim-auth/server";
import { createPostgresAdapter } from "mrjim-auth/postgres";

const auth = createAuthServer({
  baseUrl: "https://project.example.com/auth/v1",
  siteUrl: "https://project.example.com",
  database: createPostgresAdapter({ connectionString: process.env.DATABASE_URL }),
  signingKeys: {
    issuer: "https://project.example.com/auth/v1",
    audience: "project",
    activeKeyId: process.env.AUTH_ACTIVE_KEY_ID,
    keys: loadProjectSigningKeys(),
  },
  secrets: {
    tokenHashKey: process.env.AUTH_TOKEN_HASH_KEY,
    encryptionKey: process.env.AUTH_ENCRYPTION_KEY,
  },
  email: projectMailer,
  oauth: {
    google: {
      clientId: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    },
  },
  redirects: {
    allowed: ["https://project.example.com/auth/callback"],
  },
  authorization: {
    defaultRoleKeys: ["user"],
    allowWildcards: true,
  },
});
~~~

Configuration validation is synchronous and fail-closed. The server must refuse startup when signing keys, token hashing keys, encryption keys required by configured features, or redirect rules are invalid.
`AUTH_TOKEN_HASH_KEY` and `AUTH_ENCRYPTION_KEY` string values are canonical,
unpadded base64url encodings of at least 32 bytes of random material. Direct
server APIs may instead receive a `Uint8Array` containing at least 32 bytes;
short keys are rejected before any OAuth operation.

## 7. Client options

The client follows the current Supabase shape where useful:

~~~ts
export interface ClientOptions {
  auth?: {
    autoRefreshToken?: boolean;       // browser default true; server default false
    persistSession?: boolean;         // browser default true; server default false
    detectSessionInUrl?: boolean;     // browser default true; server default false
    flowType?: "pkce";                // only PKCE is supported
    storage?: SupportedStorage;
    storageKey?: string;
    lock?: LockFunction;
    debug?: boolean | ((message: string, context?: unknown) => void);
    skipAutoInitialize?: boolean;
  };
  global?: {
    fetch?: typeof fetch;
    headers?: Record<string, string>;
  };
}

export interface SupportedStorage {
  getItem(key: string): string | null | Promise<string | null>;
  setItem(key: string, value: string): void | Promise<void>;
  removeItem(key: string): void | Promise<void>;
}
~~~

Server and SSR clients require request-local instances. A server client must never be cached globally with user-specific cookies.

## 8. Return and error contract

Public SDK methods resolve instead of throwing for expected HTTP/auth failures:

~~~ts
type AuthResult<T> =
  | { data: T; error: null }
  | { data: null; error: AuthError };

interface AuthError {
  name: "AuthError";
  message: string;
  status: number;
  code: string;
}
~~~

Programming and configuration errors, such as malformed server configuration or unavailable cryptographic primitives, throw synchronously.

HTTP errors use one stable shape:

~~~json
{
  "error": {
    "code": "invalid_credentials",
    "message": "Invalid login credentials",
    "request_id": "uuid"
  }
}
~~~

Error messages for login, signup conflict, recovery, OTP, and lookup must not disclose whether a usable account exists.

## 9. Supabase-inspired SDK surface

### Public `client.auth` methods

| Method | v1 behavior |
| --- | --- |
| `signUp({ email, password, options })` | Create user, assign configured defaults, send confirmation if enabled |
| `signInWithPassword({ email, password })` | Authenticate and create a rotating session |
| `signInWithOtp({ email, options })` | Send a magic link or email OTP using a project template |
| `verifyOtp({ email, token, type })` | Consume a one-time token and create or confirm a session |
| `signInWithOAuth({ provider, options })` | Start Google or configured OIDC authorization-code plus PKCE flow |
| `exchangeCodeForSession(code)` | Exchange a one-time authorization code after redirect |
| `resetPasswordForEmail(email, options)` | Send a non-enumerating recovery email |
| `resend({ type, email, options })` | Resend signup or recovery confirmation subject to rate limits |
| `getSession()` | Return locally persisted session; does not claim server validation |
| `getUser(jwt?)` | Ask the auth server for an authoritative current user |
| `setSession({ access_token, refresh_token })` | Validate or refresh and persist a supplied session |
| `refreshSession(session?)` | Rotate refresh token and return a new session |
| `updateUser(attributes)` | Update password, email, phone, or user metadata under policy |
| `getUserIdentities()` | Return linked login identities without provider secrets |
| `linkIdentity({ provider, options })` | Start authenticated OAuth identity linking |
| `unlinkIdentity(identity)` | Remove identity only when another login method remains |
| `signOut({ scope })` | Revoke `local`, `global`, or `others` sessions |
| `onAuthStateChange(callback)` | Emit lifecycle events and return an unsubscribe handle |
| `startAutoRefresh()` / `stopAutoRefresh()` | Control refresh scheduling |
| `dispose()` | Stop timers, channel listeners, and subscriptions |

Auth events are `INITIAL_SESSION`, `SIGNED_IN`, `SIGNED_OUT`, `TOKEN_REFRESHED`, `USER_UPDATED`, and `PASSWORD_RECOVERY`.

### Authorization methods

~~~ts
await client.auth.getPermissions({ scope: { type: "organization", id: "org_123" } });
await serverAuth.authorize(request, {
  all: ["invoice.read", "invoice.update"],
  scope: { type: "organization", id: "org_123" },
});
~~~

Authorization checks are authoritative only on the server. Browser permission data is for interface behavior and must not replace backend enforcement.

### Server-only administration

~~~ts
admin.auth.admin.listUsers({ page: 1, perPage: 50 });
admin.auth.admin.getUserById(userId);
admin.auth.admin.findUser({ email });
admin.auth.admin.createUser(attributes);
admin.auth.admin.updateUserById(userId, attributes);
admin.auth.admin.deleteUser(userId, { soft: true });
admin.auth.admin.inviteUserByEmail(email, options);

admin.auth.admin.listRoles();
admin.auth.admin.createRole(role);
admin.auth.admin.updateRole(roleId, patch);
admin.auth.admin.deleteRole(roleId);
admin.auth.admin.setRolePermissions(roleId, permissionIds);
admin.auth.admin.setRoleInheritance(roleId, inheritedRoleIds);
admin.auth.admin.assignRole(userId, roleId, scope);
admin.auth.admin.unassignRole(userId, roleId, scope);

admin.auth.admin.listPermissions();
admin.auth.admin.createPermission(permission);
admin.auth.admin.updatePermission(permissionId, patch);
admin.auth.admin.deletePermission(permissionId);
~~~

The admin namespace requires a secret API key or a trusted in-process server context. Importing it from a browser entry must fail at build time.

## 10. HTTP API

All routes use `/auth/v1` by default. The project may mount the handler elsewhere, but `baseUrl` must match the public issuer.

| Method and path | SDK method | Access |
| --- | --- | --- |
| `POST /signup` | `signUp` | Publishable |
| `POST /token?grant_type=password` | `signInWithPassword` | Publishable |
| `POST /token?grant_type=refresh_token` | `refreshSession` | Publishable plus refresh token |
| `POST /otp` | `signInWithOtp` | Publishable |
| `POST /verify` | `verifyOtp` | Publishable |
| `POST /recover` | `resetPasswordForEmail` | Publishable |
| `POST /resend` | `resend` | Publishable |
| `GET /providers` | provider discovery | Publishable |
| `GET /authorize` | `signInWithOAuth` / `linkIdentity` | Publishable; user required for linking |
| `GET /callback/:provider` | OAuth callback | Signed state |
| `POST /exchange` | `exchangeCodeForSession` | One-time code and PKCE verifier |
| `GET /user` | `getUser` | User |
| `PUT /user` | `updateUser` | User |
| `GET /user/identities` | `getUserIdentities` | User |
| `DELETE /user/identities/:id` | `unlinkIdentity` | User |
| `GET /user/permissions` | `getPermissions` | User |
| `POST /logout` | `signOut` | User or refresh token |
| `GET /.well-known/jwks.json` | JWT verification keys | Public |
| `GET /admin/users` and `/admin/users/:id` | user administration | Secret/admin permission |
| `GET/POST/PATCH/DELETE /admin/roles` | role administration | Secret/admin permission |
| `PUT /admin/roles/:id/inheritance` | role inheritance | Secret/admin permission |
| `GET/POST/PATCH/DELETE /admin/permissions` | permission administration | Secret/admin permission |
| `PUT/DELETE /admin/users/:id/roles/:roleId` | role assignment | Secret/admin permission |
| `GET /admin/audit` | audit search | Secret/admin permission |

The OpenAPI document is generated from the same Zod schemas used by route validation.

## 11. Canonical data model

All tables are inside a PostgreSQL schema named exactly `auth`. No table, column, index, constraint, or function contains `mrjim`. No shipping or Hayahai business field is present.

### Identity and credentials

| Table | Required fields and constraints |
| --- | --- |
| `auth.users` | `id uuid PK`, nullable `email` and `phone`, normalized counterparts with partial unique indexes, confirmation timestamps, `last_sign_in_at`, `banned_until`, `user_metadata jsonb`, `app_metadata jsonb`, timestamps, `deleted_at` |
| `auth.identities` | `id uuid PK`, `user_id FK`, `provider`, `provider_subject`, optional normalized email, safe `identity_data jsonb`, timestamps, unique `(provider, provider_subject)` |
| `auth.password_credentials` | `user_id PK/FK`, Argon2id `password_hash`, `password_updated_at` |

Passwords are never stored in `users` or `identities`. Provider access and refresh tokens are not returned in identity records. A provider adapter may persist encrypted provider tokens only when a project explicitly enables downstream provider API access.

### Sessions and one-time flows

| Table | Required fields and constraints |
| --- | --- |
| `auth.sessions` | `id uuid PK`, `user_id FK`, `aal smallint`, IP/user-agent context, created/refreshed/expiry/revocation timestamps |
| `auth.refresh_tokens` | `id uuid PK`, `session_id FK`, HMAC token hash, `family_id`, parent/replacement links, issue/use/expiry/revocation timestamps |
| `auth.one_time_tokens` | `id uuid PK`, optional `user_id FK`, `purpose`, HMAC token hash, target, redirect, metadata, attempt count, expiry/consumption timestamps |
| `auth.oauth_states` | state hash, provider, flow, PKCE challenge, encrypted verifier when server-held, redirect target, optional linking user, expiry/consumption timestamps |

One-time token purposes are `signup`, `email_change`, `recovery`, `magic_link`, `email_otp`, and `invite`.

### Dynamic authorization

| Table | Required fields and constraints |
| --- | --- |
| `auth.roles` | `id uuid PK`, lowercase `key UNIQUE`, display name, description, `rank`, `is_system`, timestamps |
| `auth.permissions` | `id uuid PK`, lowercase `key UNIQUE`, `resource`, `action`, description, timestamps |
| `auth.role_permissions` | composite PK `(role_id, permission_id)` |
| `auth.role_inheritance` | composite PK `(role_id, inherits_role_id)` with cycle prevention |
| `auth.user_roles` | user, role, optional `scope_type` and `scope_id`, assigner, assignment/expiry timestamps; unique assignment key |

Permission keys use `resource.action`, for example `invoice.read`. Optional wildcards are `invoice.*` and `*.*`. There are no explicit denies in v1; effective access is the union of direct and inherited permissions. Expired assignments are ignored.

`rank` governs whether one administrator may modify another role; it never grants permissions by itself. Destructive role changes run in a transaction and enforce configured protected-role and minimum-assignment policies.

### Operations

| Table | Required fields and constraints |
| --- | --- |
| `auth.api_keys` | key ID/prefix, HMAC hash, `publishable` or `secret` kind, scopes, last-use/expiry/revocation timestamps |
| `auth.audit_log` | immutable event ID, actor user/key/session, action, target, IP/user-agent, redacted metadata, outcome, timestamp |
| `auth.schema_migrations` | version, checksum, applied timestamp, package version |

The audit log replaces separate login and user-history tables. Secrets, password hashes, raw bearer tokens, reset codes, OAuth authorization codes, and provider tokens are forbidden in audit metadata.

## 12. Session and token policy

- Access tokens are ES256 JWTs with `iss`, `aud`, `sub`, `sid`, `aal`, `iat`, `exp`, and optional non-authoritative role/permission snapshot claims.
- The default access-token lifetime is 15 minutes.
- Refresh tokens are opaque 256-bit random values with a default 30-day lifetime.
- Refresh tokens rotate on every use. Reuse of an already-used token revokes its entire token family.
- Only HMAC-SHA-256 token digests are stored.
- Signing private keys remain in environment/KMS-backed configuration. Public keys are exposed through JWKS and include `kid`.
- Key rotation allows one active signer and multiple verification-only keys.
- Password reset revokes all sessions by default; projects can configure current-session preservation only through an explicit policy.
- `getSession()` reads storage and is not proof that the token is currently accepted. `getUser()` performs server validation.

## 13. Password, email, and recovery policy

- Password hashing uses Argon2id with versioned parameters stored in the encoded hash. The initial floor is 64 MiB memory, three iterations, and one lane.
- Successful login opportunistically rehashes credentials below the configured floor.
- Email normalization trims and lowercases only. It does not strip plus-addressing or Gmail dots.
- Signup, login, OTP, resend, and recovery have per-IP and per-identifier rate-limit hooks.
- Recovery and verification tokens are random, HMAC-hashed, one-time, and purpose-bound.
- Recovery tokens expire after 15 minutes; signup verification expires after 24 hours.
- OTP verification allows at most five failures before consuming the token.
- Mail delivery uses a project-supplied adapter and template variables documented by version.
- Production responses and logs never include raw codes or links containing bearer credentials.

## 14. OAuth and identity-linking policy

- v1 ships Google plus a generic OIDC provider adapter.
- Browser, SSR, and mobile JavaScript use authorization code with PKCE S256.
- State is random, HMAC-bound to flow type and redirect intent, short-lived, and single-use.
- Redirect targets must exactly match or safely derive from the configured allowlist.
- Mobile deep-link callbacks exchange a 60-second one-time code; provider tokens are never placed in a deep-link URL.
- Existing identities match by `(provider, provider_subject)`.
- Linking to an authenticated user requires a fresh session and signed linking state.
- Automatic linking by verified email is disabled by default. When explicitly enabled, the provider must attest that the email is verified and the action is audited.
- Unlinking is rejected when it would remove the user's final usable login method.
- OAuth provider client secrets are supplied from environment/KMS configuration and are not persisted in the v1 database schema.

## 15. Browser, SSR, and server behavior

### Browser

- Default storage is `localStorage` when available.
- Cross-tab state uses `BroadcastChannel` with a storage-event fallback.
- A process-wide lock prevents concurrent refresh rotation in multiple tabs.
- Auto-refresh runs only while appropriate for the runtime lifecycle.
- `detectSessionInUrl` consumes and removes OAuth/recovery parameters before notifying subscribers.

### SSR

- `createServerClient` accepts a cookie adapter with `getAll` and `setAll`.
- A fresh client is constructed per request.
- Middleware may refresh sessions and emit updated cookies.
- Read-only server components must not attempt cookie writes.
- A secret admin client is always separate from a user-session client.

### Node API

- `createAuthServer` is framework neutral and handles Web `Request` objects.
- Express and Next.js adapters translate their request/response types.
- Project routes and business services call `authorize` with explicit permissions and scope.
- Trusted in-process administration does not require a network round trip but still creates audit events.

## 16. Migration behavior

The CLI commands are:

~~~text
mrjim-auth init
mrjim-auth migrate status
mrjim-auth migrate up
mrjim-auth migrate verify
mrjim-auth keys generate
mrjim-auth doctor
~~~

Rules:

- migrations are ordered, checksum-protected SQL files;
- migration execution uses a PostgreSQL advisory lock and a transaction per migration;
- production application startup never runs migrations implicitly;
- `migrate verify` checks tables, indexes, constraints, required extensions, and migration checksums;
- destructive rollback is not offered for the baseline schema;
- projects may copy SQL files into Prisma, Drizzle, Kysely, Supabase CLI, or another migration system;
- migrations create only the `auth` schema and required extensions;
- no default business roles or permissions are inserted;
- a project's own seed creates its default roles, permissions, and assignment rules.

## 17. Documentation contract

Every public method or option requires:

1. exported TypeScript types and TSDoc;
2. a generated API reference entry;
3. one browser example and, when relevant, one server/SSR example;
4. request/response or behavior contract tests;
5. an entry in the Supabase compatibility matrix;
6. a changelog entry when behavior changes.

Implementation progress is tracked in `docs/implementation-status.md`. Every completed task updates its status, verification evidence, remaining work, and blocker log before its commit is reviewed.

Required documentation:

- `README.md`: purpose, install, five-minute setup;
- `docs/getting-started.md`;
- `docs/concepts/architecture.md` and `sessions.md`;
- `docs/reference/client.md`, `server.md`, `schema.md`, and generated OpenAPI;
- `docs/guides/email-password.md`, `google-oauth.md`, `ssr-nextjs.md`, `express.md`, and `roles-permissions.md`;
- `docs/guides/migrating-to-supabase.md` with method and schema mappings;
- `docs/security.md` with deployment checklist and incident procedures;
- `docs/compatibility/supabase-auth.md` listing compatible, different, and unsupported methods;
- `CHANGELOG.md` and versioned migration notes.

Documentation examples are compiled and tested in CI.

## 18. Testing and release gates

The release pipeline must pass:

- unit tests for validation, errors, storage, event ordering, token hashing, PKCE, redirect checks, and permission matching;
- PostgreSQL integration tests against every migration and repository;
- concurrency tests for duplicate signup, refresh rotation, reuse detection, OTP consumption, OAuth code exchange, and role updates;
- HTTP contract tests for every route and stable error code;
- browser tests for persisted sessions, cross-tab events, OAuth URL cleanup, and refresh locking;
- SSR tests proving request-local clients and correct cookie writes;
- authorization tests for direct roles, inherited roles, scopes, wildcards, expiration, protected roles, and last-assignment rules;
- security tests for enumeration resistance, CSRF/state, open redirects, token replay, identity-link takeover, secret-key browser rejection, and audit redaction;
- package export tests proving browser bundles do not contain `pg`, password hashing, private-key loaders, or migration code;
- generated OpenAPI and documentation link/example checks;
- migration from the prior released schema and fresh-install migration tests.

No release is complete until the reference Express API and Next.js example both authenticate against a fresh PostgreSQL database.

## 19. Compatibility promise

The compatibility target is familiarity and a low-effort migration path, not byte-for-byte Supabase implementation compatibility.

- Method names, argument shapes, `{ data, error }` results, session events, and common options match Supabase where practical.
- MrJim-specific functionality lives under `auth.admin` or explicit server helpers.
- The package never implements unrelated `from`, `rpc`, storage, or realtime namespaces.
- Differences in cookies, refresh-token policy, unsupported providers, error codes, and database schema are documented.
- A compatibility test suite locks the supported surface and prevents accidental drift.

Current Supabase references used for this contract:

- https://supabase.com/docs/reference/javascript/initializing
- https://supabase.com/docs/reference/javascript/auth
- https://supabase.com/docs/reference/javascript/auth-signup
- https://supabase.com/docs/reference/javascript/auth-onauthstatechange
- https://supabase.com/docs/reference/javascript/auth-exchangecodeforsession
- https://supabase.com/docs/guides/auth/server-side

## 20. Acceptance criteria

v1 is accepted when:

1. A new Node.js project can install the package, apply the `auth` migrations, mount the handler, and create its first user without Supabase.
2. The same project can sign up, confirm email, sign in, refresh, recover a password, update a user, and sign out through `client.auth`.
3. Google OAuth works through PKCE on browser and mobile-style callback exchange.
4. Roles and permissions can be created at runtime, assigned with optional scope, and enforced server-side.
5. Browser, Express, and Next.js SSR examples pass automated tests.
6. Refresh replay, account-link takeover, open redirect, user enumeration, secret exposure, and cross-request SSR leakage tests fail closed.
7. Fresh and incremental migration verification passes on PostgreSQL 15, 16, and 17.
8. The published browser entry contains no server-only dependencies.
9. API reference, OpenAPI, schema reference, security guide, and Supabase migration guide are published with the package.
