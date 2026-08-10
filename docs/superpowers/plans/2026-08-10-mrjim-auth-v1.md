# mrjim-auth v1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a production-ready Node.js authentication SDK with a Supabase-inspired client API, project-owned PostgreSQL `auth` schema, browser and server runtimes, Google OAuth, rotating sessions, and dynamic role-based authorization.

**Architecture:** Publish one `mrjim-auth` package with environment-safe subpath exports. A framework-neutral `AuthServer` owns security-sensitive behavior, a PostgreSQL adapter owns durable records and migrations, and browser/SSR clients call project-hosted `/auth/v1` endpoints through a Supabase-shaped `client.auth` interface.

**Tech Stack:** Node.js 24 LTS, TypeScript 6, ESM, pnpm, PostgreSQL 15+, Kysely, `pg`, Zod, `jose`, Argon2id, `openid-client`, Vitest, Testcontainers, Playwright, TypeDoc, and Zod-generated OpenAPI.

## Global Constraints

- The published package name is exactly `mrjim-auth`.
- The database schema is exactly `auth`; database objects must not include `mrjim`.
- Do not add shipping-line, tenant, passenger, port, vessel, cabin, TMS, marketplace, or other Hayahai business fields.
- Browser code must not import PostgreSQL, password hashing, private keys, migrations, admin secrets, or Node-only modules.
- All expected SDK failures return `{ data, error }`; configuration and programming failures throw.
- PostgreSQL migrations are explicit, checksum-protected, advisory-locked, and never run automatically at application startup.
- OAuth uses authorization code plus PKCE S256, signed state, exact redirect allowlists, and one-time callback codes.
- Refresh tokens rotate once; replay revokes the entire token family.
- Roles, permissions, inheritance, and scoped assignments are data-driven.
- Every public method ships with TSDoc, tested documentation examples, compatibility status, and stable error codes.
- The authoritative product contract is `docs/specs/mrjim-auth-v1.md`.

---

## File Structure

~~~text
package.json                         Root scripts and pinned toolchain
pnpm-workspace.yaml                  Workspace package and examples
tsconfig.base.json                   Strict shared TypeScript settings
vitest.workspace.ts                  Unit and integration test projects

packages/mrjim-auth/
  package.json                       Export map and CLI binary
  tsconfig.json
  src/
    index.ts                         Browser-safe public createClient export
    shared/
      types.ts                       User, Session, Identity, Role, Permission
      result.ts                      AuthResult helpers
      errors.ts                      Stable AuthError classes and codes
      config.ts                      Client/server option schemas
      contracts.ts                   Repository, mailer, limiter, key contracts
    client/
      auth-client.ts                 Supabase-inspired auth namespace
      transport.ts                   Fetch and error normalization
      storage.ts                     Storage abstraction
      events.ts                      Auth events and subscriptions
      lock.ts                        Refresh concurrency lock
      pkce.ts                        Browser PKCE utilities
      initialize.ts                  Stored/redirect session initialization
    server/
      index.ts                       Node-only exports
      create-auth-server.ts          Composition root
      auth-server.ts                 Framework-neutral request handler
      users.ts                       User and credential lifecycle
      sessions.ts                    Access/refresh sessions
      tokens.ts                      JWT, JWKS, opaque token hashing
      one-time-tokens.ts             Verify/recovery/magic-link tokens
      oauth.ts                       OAuth/OIDC orchestration
      authorization.ts               Effective permissions and enforcement
      admin.ts                       Server-only administration
      audit.ts                       Redacted security events
      routes/                        Zod route contracts and handlers
    postgres/
      index.ts                       PostgreSQL public exports
      adapter.ts                     Repository implementation
      migrate.ts                     Migration runner
      migrations/*.sql               Ordered schema migrations
      manifest.ts                    Versions and checksums
    adapters/
      express.ts                     Express request adapter
      nextjs-browser.ts              Next.js browser singleton helper
      nextjs-server.ts               Per-request cookie client
    cli/
      index.ts                       CLI entrypoint
      commands/*.ts                  init, migrate, keys, doctor
    testing/
      index.ts                       Public test helpers
      fake-clock.ts
      fake-mailer.ts
      test-server.ts
  test/
    unit/
    integration/
    contract/
    browser/

examples/
  express-api/                       Project-owned backend example
  nextjs-app-router/                 Browser plus SSR example

docs/
  specs/mrjim-auth-v1.md
  getting-started.md
  concepts/
  reference/
  guides/
  compatibility/supabase-auth.md
  security.md
~~~

### Task 1: Scaffold the workspace and enforce runtime-safe package exports

**Files:**
- Create: `package.json`
- Create: `pnpm-workspace.yaml`
- Create: `tsconfig.base.json`
- Create: `vitest.workspace.ts`
- Create: `packages/mrjim-auth/package.json`
- Create: `packages/mrjim-auth/tsconfig.json`
- Create: `packages/mrjim-auth/src/index.ts`
- Create: `packages/mrjim-auth/src/server/index.ts`
- Create: `packages/mrjim-auth/src/postgres/index.ts`
- Test: `packages/mrjim-auth/test/contract/package-exports.spec.ts`

**Interfaces:**
- Produces: package exports `mrjim-auth`, `mrjim-auth/server`, `mrjim-auth/postgres`, `mrjim-auth/express`, `mrjim-auth/nextjs`, and `mrjim-auth/testing`.
- Produces: root commands `pnpm build`, `pnpm typecheck`, `pnpm test`, `pnpm lint`, and `pnpm docs:check`.

- [ ] **Step 1: Write the export-boundary test**

~~~ts
import { describe, expect, it } from "vitest";

describe("package export boundaries", () => {
  it("keeps the root entry browser safe", async () => {
    const root = await import("../../src/index.js");
    expect(Object.keys(root)).toEqual(expect.arrayContaining(["createClient"]));
    expect(root).not.toHaveProperty("createAuthServer");
    expect(root).not.toHaveProperty("createPostgresAdapter");
  });
});
~~~

- [ ] **Step 2: Run the test and verify the missing package fails**

Run: `pnpm vitest run packages/mrjim-auth/test/contract/package-exports.spec.ts`  
Expected: FAIL because the package entries do not exist.

- [ ] **Step 3: Create the workspace manifests**

Set `engines.node` to `>=24`, `type` to `module`, and the package export map so `.` points only to the browser-safe client build. Point every server subpath to a distinct compiled file and mark `sideEffects` as `false`.

~~~json
{
  "name": "mrjim-auth",
  "type": "module",
  "engines": { "node": ">=24" },
  "exports": {
    ".": { "types": "./dist/index.d.ts", "import": "./dist/index.js" },
    "./server": { "types": "./dist/server/index.d.ts", "import": "./dist/server/index.js" },
    "./postgres": { "types": "./dist/postgres/index.d.ts", "import": "./dist/postgres/index.js" },
    "./express": { "types": "./dist/adapters/express.d.ts", "import": "./dist/adapters/express.js" },
    "./nextjs": { "types": "./dist/adapters/nextjs-browser.d.ts", "import": "./dist/adapters/nextjs-browser.js" },
    "./nextjs/server": { "types": "./dist/adapters/nextjs-server.d.ts", "import": "./dist/adapters/nextjs-server.js" },
    "./testing": { "types": "./dist/testing/index.d.ts", "import": "./dist/testing/index.js" }
  },
  "bin": { "mrjim-auth": "./dist/cli/index.js" },
  "sideEffects": false
}
~~~

- [ ] **Step 4: Add strict TypeScript and build configuration**

Enable `strict`, `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`, `verbatimModuleSyntax`, declarations, source maps, and ESM-compatible module resolution. Configure separate browser and Node build entries.

- [ ] **Step 5: Install dependencies and run workspace checks**

Run: `pnpm install && pnpm typecheck && pnpm build && pnpm vitest run packages/mrjim-auth/test/contract/package-exports.spec.ts`  
Expected: all commands PASS.

- [ ] **Step 6: Commit**

~~~bash
git add package.json pnpm-workspace.yaml tsconfig.base.json vitest.workspace.ts packages/mrjim-auth
git commit -m "chore: scaffold mrjim-auth package"
~~~

### Task 2: Define shared types, results, errors, and configuration

**Files:**
- Create: `packages/mrjim-auth/src/shared/types.ts`
- Create: `packages/mrjim-auth/src/shared/result.ts`
- Create: `packages/mrjim-auth/src/shared/errors.ts`
- Create: `packages/mrjim-auth/src/shared/config.ts`
- Create: `packages/mrjim-auth/src/shared/contracts.ts`
- Test: `packages/mrjim-auth/test/unit/shared-contracts.spec.ts`

**Interfaces:**
- Produces: `AuthResult<T>`, `AuthError`, `User`, `Identity`, `Session`, `Role`, `Permission`, `AuthChangeEvent`, `ClientOptions`, `AuthServerOptions`, `SupportedStorage`, `Mailer`, `RateLimiter`, `KeyProvider`, and repository interfaces.
- Consumed by: every later task.

- [ ] **Step 1: Write type and error contract tests**

~~~ts
import { describe, expect, it } from "vitest";
import { authFailure, authSuccess } from "../../src/shared/result.js";
import { AuthApiError } from "../../src/shared/errors.js";

describe("AuthResult", () => {
  it("uses mutually exclusive data and error fields", () => {
    expect(authSuccess({ user: null })).toEqual({ data: { user: null }, error: null });
    expect(authFailure(new AuthApiError("invalid_credentials", 401, "Invalid login credentials")))
      .toMatchObject({ data: null, error: { code: "invalid_credentials", status: 401 } });
  });
});
~~~

- [ ] **Step 2: Run the test and verify missing exports fail**

Run: `pnpm vitest run packages/mrjim-auth/test/unit/shared-contracts.spec.ts`  
Expected: FAIL with unresolved shared modules.

- [ ] **Step 3: Implement the canonical public types**

~~~ts
export interface Session {
  access_token: string;
  refresh_token: string;
  token_type: "bearer";
  expires_in: number;
  expires_at: number;
  user: User;
}

export type AuthChangeEvent =
  | "INITIAL_SESSION"
  | "SIGNED_IN"
  | "SIGNED_OUT"
  | "TOKEN_REFRESHED"
  | "USER_UPDATED"
  | "PASSWORD_RECOVERY";

export type AuthResult<T> =
  | { data: T; error: null }
  | { data: null; error: AuthError };
~~~

Define `User` with identity-safe fields and metadata, `Role` and `Permission` with UUIDs and lowercase keys, and `Identity` without provider credentials.

- [ ] **Step 4: Implement validated configuration**

Use Zod schemas to enforce HTTPS production URLs, `flowType: "pkce"`, access TTL from 300 to 3600 seconds, refresh TTL from 3600 seconds to 90 days, exact redirect URLs, non-empty issuer/audience, and required key material. Export inferred TypeScript types.

- [ ] **Step 5: Run type and unit checks**

Run: `pnpm typecheck && pnpm vitest run packages/mrjim-auth/test/unit/shared-contracts.spec.ts`  
Expected: PASS.

- [ ] **Step 6: Commit**

~~~bash
git add packages/mrjim-auth/src/shared packages/mrjim-auth/test/unit/shared-contracts.spec.ts
git commit -m "feat: define auth contracts and configuration"
~~~

### Task 3: Create the clean PostgreSQL auth schema and migration CLI

**Files:**
- Create: `packages/mrjim-auth/src/postgres/migrations/0001_core.sql`
- Create: `packages/mrjim-auth/src/postgres/migrations/0002_authorization.sql`
- Create: `packages/mrjim-auth/src/postgres/migrations/0003_oauth_operations.sql`
- Create: `packages/mrjim-auth/src/postgres/manifest.ts`
- Create: `packages/mrjim-auth/src/postgres/migrate.ts`
- Create: `packages/mrjim-auth/src/cli/index.ts`
- Create: `packages/mrjim-auth/src/cli/commands/migrate.ts`
- Create: `packages/mrjim-auth/src/cli/commands/doctor.ts`
- Test: `packages/mrjim-auth/test/integration/migrations.spec.ts`

**Interfaces:**
- Produces: `migrate(pool, { direction: "up" })`, `migrationStatus(pool)`, and `verifySchema(pool)`.
- Produces tables listed in `docs/specs/mrjim-auth-v1.md` section 11.
- Consumed by: PostgreSQL repository and all integration tests.

- [ ] **Step 1: Write fresh-install and naming tests**

~~~ts
it("creates only clean auth objects", async () => {
  await migrate(pool, { direction: "up" });
  const objects = await listAuthObjects(pool);
  expect(objects).toEqual(expect.arrayContaining([
    "users", "identities", "password_credentials", "sessions",
    "refresh_tokens", "one_time_tokens", "oauth_states", "roles",
    "permissions", "role_permissions", "role_inheritance", "user_roles",
    "api_keys", "audit_log", "schema_migrations",
  ]));
  expect(JSON.stringify(objects)).not.toMatch(/mrjim|shipping|tenant|passenger|vessel|cabin|tms/i);
});
~~~

Add tests for unique normalized email, unique provider subject, refresh-token hash uniqueness, role-inheritance cycle rejection, scoped assignment uniqueness, audit immutability, and checksum mismatch rejection.

- [ ] **Step 2: Run the migration test against PostgreSQL**

Run: `pnpm vitest run packages/mrjim-auth/test/integration/migrations.spec.ts`  
Expected: FAIL because migrations and runner are missing.

- [ ] **Step 3: Implement `0001_core.sql`**

Create `pgcrypto` and `auth`, then create `users`, `identities`, `password_credentials`, `sessions`, `refresh_tokens`, and `one_time_tokens` with the exact columns and constraints from the specification. Use partial unique indexes for non-null normalized email/phone and cascading deletes from users to credentials, identities, sessions, and one-time tokens.

~~~sql
CREATE SCHEMA IF NOT EXISTS auth;

CREATE TABLE auth.users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email text,
  email_normalized text,
  phone text,
  phone_normalized text,
  email_confirmed_at timestamptz,
  phone_confirmed_at timestamptz,
  last_sign_in_at timestamptz,
  banned_until timestamptz,
  user_metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  app_metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz
);

CREATE UNIQUE INDEX users_email_normalized_key
  ON auth.users (email_normalized) WHERE email_normalized IS NOT NULL;
~~~

- [ ] **Step 4: Implement authorization and operations migrations**

`0002_authorization.sql` creates roles, permissions, role-permission joins, role inheritance, and scoped user-role assignments. Add a deferred constraint trigger that recursively rejects inheritance cycles.

`0003_oauth_operations.sql` creates OAuth state, API key, audit, and schema migration records. Add a trigger that rejects `UPDATE` and `DELETE` on `auth.audit_log`.

- [ ] **Step 5: Implement deterministic migration execution**

Acquire `pg_advisory_lock(hashtext('auth.schema_migrations'))`, verify SHA-256 checksums from `manifest.ts`, run each unapplied migration in a transaction, record package version/checksum, and release the lock in `finally`. Do not implement baseline rollback.

- [ ] **Step 6: Implement CLI commands and schema verification**

`migrate status` prints applied/pending/checksum state, `migrate up` applies migrations, and `migrate verify` checks all required tables/indexes/constraints. `doctor` validates PostgreSQL version, extensions, key lengths, URL configuration, and migration state without changing data.

- [ ] **Step 7: Run migration verification**

Run: `pnpm vitest run packages/mrjim-auth/test/integration/migrations.spec.ts && pnpm --filter mrjim-auth exec mrjim-auth migrate verify`  
Expected: PASS against the disposable test database.

- [ ] **Step 8: Commit**

~~~bash
git add packages/mrjim-auth/src/postgres packages/mrjim-auth/src/cli packages/mrjim-auth/test/integration/migrations.spec.ts
git commit -m "feat: add clean auth schema migrations"
~~~

### Task 4: Implement repository boundaries and the PostgreSQL adapter

**Files:**
- Modify: `packages/mrjim-auth/src/shared/contracts.ts`
- Create: `packages/mrjim-auth/src/postgres/adapter.ts`
- Create: `packages/mrjim-auth/src/postgres/repositories/users.ts`
- Create: `packages/mrjim-auth/src/postgres/repositories/sessions.ts`
- Create: `packages/mrjim-auth/src/postgres/repositories/authorization.ts`
- Create: `packages/mrjim-auth/src/postgres/repositories/operations.ts`
- Test: `packages/mrjim-auth/test/integration/postgres-adapter.spec.ts`

**Interfaces:**
- Produces: `createPostgresAdapter({ pool | connectionString }): AuthRepository`.
- Produces transactional `users`, `sessions`, `authorization`, and `operations` repositories.
- Consumed by: user, session, OAuth, authorization, and admin services.

- [ ] **Step 1: Write repository integration tests**

Create a user and identity transaction, reject duplicate normalized email, atomically consume a one-time token once, atomically rotate a refresh token once, resolve inherited scoped permissions, and append an immutable audit event.

~~~ts
const first = await repository.oneTimeTokens.consume(tokenHash, "recovery", now);
const second = await repository.oneTimeTokens.consume(tokenHash, "recovery", now);
expect(first).not.toBeNull();
expect(second).toBeNull();
~~~

- [ ] **Step 2: Run tests and verify adapter failures**

Run: `pnpm vitest run packages/mrjim-auth/test/integration/postgres-adapter.spec.ts`  
Expected: FAIL because repository implementations are missing.

- [ ] **Step 3: Implement repository interfaces**

Use separate interfaces with exact transaction-aware methods: `UserRepository.findById/findByNormalizedEmail/create/update/softDelete`, `SessionRepository.create/findRefreshForUpdate/rotate/revokeSession/revokeFamily/revokeUserSessions`, `AuthorizationRepository.effectivePermissions/assignRole/unassignRole/setRolePermissions/setRoleInheritance`, and `OperationsRepository.appendAudit/findApiKeyByHash`.

- [ ] **Step 4: Implement Kysely-backed repositories**

Use parameterized Kysely queries, `FOR UPDATE` for token and protected-role changes, explicit column lists, and transaction objects passed through a common `transaction(callback)` method. Never use views for writes.

- [ ] **Step 5: Run integration tests**

Run: `pnpm vitest run packages/mrjim-auth/test/integration/postgres-adapter.spec.ts`  
Expected: PASS.

- [ ] **Step 6: Commit**

~~~bash
git add packages/mrjim-auth/src/shared/contracts.ts packages/mrjim-auth/src/postgres packages/mrjim-auth/test/integration/postgres-adapter.spec.ts
git commit -m "feat: implement postgres auth repositories"
~~~

### Task 5: Implement JWT access tokens and rotating refresh sessions

**Files:**
- Create: `packages/mrjim-auth/src/server/tokens.ts`
- Create: `packages/mrjim-auth/src/server/sessions.ts`
- Create: `packages/mrjim-auth/src/server/jwks.ts`
- Test: `packages/mrjim-auth/test/unit/tokens.spec.ts`
- Test: `packages/mrjim-auth/test/integration/session-rotation.spec.ts`

**Interfaces:**
- Produces: `TokenService.issueAccessToken(user, session)`, `verifyAccessToken(jwt)`, `hashOpaqueToken(token)`, and `jwks()`.
- Produces: `SessionService.create(user, context)`, `refresh(refreshToken, context)`, and `signOut(session, scope)`.
- Consumed by: HTTP routes, OAuth, clients, and authorization.

- [ ] **Step 1: Write signing and rotation tests**

Assert ES256 claims `iss`, `aud`, `sub`, `sid`, `aal`, `iat`, `exp`, and `kid`. Assert that one refresh succeeds, concurrent second use returns `refresh_token_reused`, and the family becomes revoked.

- [ ] **Step 2: Run tests and verify failures**

Run: `pnpm vitest run packages/mrjim-auth/test/unit/tokens.spec.ts packages/mrjim-auth/test/integration/session-rotation.spec.ts`  
Expected: FAIL because token/session services are missing.

- [ ] **Step 3: Implement cryptographic token primitives**

Use `jose` for ES256 signing/verification. Generate 32-byte refresh tokens with `crypto.randomBytes` and store only `HMAC-SHA-256(tokenHashKey, token)`. Compare digests with constant-time comparison.

- [ ] **Step 4: Implement transactional refresh rotation**

Lock the token row, reject expiry/revocation/previous use, mark it used, insert the replacement with the same family and parent link, update the session, and return a fresh access/refresh pair. When a used token is presented, revoke all family tokens and the session before returning an error.

- [ ] **Step 5: Implement logout scopes**

`local` revokes the current session, `global` revokes every user session, and `others` revokes all except the current session. Emit redacted audit events for each.

- [ ] **Step 6: Run token and concurrency tests**

Run: `pnpm vitest run packages/mrjim-auth/test/unit/tokens.spec.ts packages/mrjim-auth/test/integration/session-rotation.spec.ts`  
Expected: PASS.

- [ ] **Step 7: Commit**

~~~bash
git add packages/mrjim-auth/src/server/tokens.ts packages/mrjim-auth/src/server/sessions.ts packages/mrjim-auth/src/server/jwks.ts packages/mrjim-auth/test
git commit -m "feat: add rotating auth sessions"
~~~

### Task 6: Implement users, passwords, email verification, OTP, and recovery

**Files:**
- Create: `packages/mrjim-auth/src/server/users.ts`
- Create: `packages/mrjim-auth/src/server/passwords.ts`
- Create: `packages/mrjim-auth/src/server/one-time-tokens.ts`
- Create: `packages/mrjim-auth/src/server/email.ts`
- Create: `packages/mrjim-auth/src/testing/fake-mailer.ts`
- Test: `packages/mrjim-auth/test/integration/user-lifecycle.spec.ts`
- Test: `packages/mrjim-auth/test/contract/enumeration-resistance.spec.ts`

**Interfaces:**
- Produces: `UserService.signUp/signIn/updateUser/changePassword`.
- Produces: `OneTimeTokenService.issue/verify/resend`.
- Produces: project `Mailer.send({ template, to, variables })` contract.
- Consumed by: HTTP routes and OAuth.

- [ ] **Step 1: Write complete lifecycle tests**

Test signup with default roles, email verification, password login, rehash, generic duplicate signup response, magic link, OTP five-attempt consumption, recovery, password change, session revocation, banned user, and soft-deleted user.

- [ ] **Step 2: Write enumeration equivalence tests**

For existing and nonexistent email addresses, assert identical status, body shape, and error code for recovery, resend, OTP, and signup when concealment is enabled.

- [ ] **Step 3: Run tests and verify failures**

Run: `pnpm vitest run packages/mrjim-auth/test/integration/user-lifecycle.spec.ts packages/mrjim-auth/test/contract/enumeration-resistance.spec.ts`  
Expected: FAIL because lifecycle services are missing.

- [ ] **Step 4: Implement password and email normalization**

Use Argon2id with 64 MiB memory, three iterations, and one lane. Store the encoded hash and rehash on successful login when parameters are below policy. Normalize email by Unicode normalization, trim, and lowercase without provider-specific rewriting.

- [ ] **Step 5: Implement purpose-bound one-time tokens**

Generate 32 random bytes, store only the HMAC digest, bind to purpose/target/redirect, enforce 15-minute recovery and 24-hour signup expiry, increment failed attempts atomically, and consume at five failures or first success.

- [ ] **Step 6: Implement mailer calls and audit redaction**

Send `confirmation`, `magic_link`, `email_otp`, `recovery`, and `invite` templates. Pass raw tokens only to the mailer call in memory. Audit template name, user ID, and outcome without recipient secrets or bearer links.

- [ ] **Step 7: Run lifecycle tests**

Run: `pnpm vitest run packages/mrjim-auth/test/integration/user-lifecycle.spec.ts packages/mrjim-auth/test/contract/enumeration-resistance.spec.ts`  
Expected: PASS.

- [ ] **Step 8: Commit**

~~~bash
git add packages/mrjim-auth/src/server packages/mrjim-auth/src/testing/fake-mailer.ts packages/mrjim-auth/test
git commit -m "feat: add user and recovery lifecycle"
~~~

### Task 7: Implement Google OAuth, generic OIDC, PKCE, and identity safety

**Files:**
- Create: `packages/mrjim-auth/src/client/pkce.ts`
- Create: `packages/mrjim-auth/src/server/oauth.ts`
- Create: `packages/mrjim-auth/src/server/oauth-providers.ts`
- Create: `packages/mrjim-auth/src/server/routes/oauth.ts`
- Test: `packages/mrjim-auth/test/unit/pkce.spec.ts`
- Test: `packages/mrjim-auth/test/integration/oauth.spec.ts`

**Interfaces:**
- Produces: `OAuthService.authorize`, `callback`, `exchangeCode`, `linkIdentity`, and `unlinkIdentity`.
- Produces: `OAuthProvider` interface and built-in `google`/generic OIDC adapters.
- Consumed by: HTTP handler and client auth methods.

- [ ] **Step 1: Write PKCE and redirect tests**

Use RFC 7636 S256 vectors. Reject plain PKCE, expired state, state replay, callback code replay, mismatched redirect, unallowlisted redirect, and wrong verifier.

- [ ] **Step 2: Write account-link tests**

Assert provider-subject login, authenticated linking, identity collision rejection, default rejection of email auto-link, optional verified-email auto-link, and refusal to unlink the final login method.

- [ ] **Step 3: Run OAuth tests and verify failures**

Run: `pnpm vitest run packages/mrjim-auth/test/unit/pkce.spec.ts packages/mrjim-auth/test/integration/oauth.spec.ts`  
Expected: FAIL because OAuth services are missing.

- [ ] **Step 4: Implement OAuth state and callback exchange**

Use random state persisted as an HMAC hash, signed flow metadata, exact redirect allowlists, PKCE S256, ten-minute state expiry, and a 60-second one-time callback code. Never put access or refresh tokens in callback URLs.

- [ ] **Step 5: Implement provider adapters**

Use `openid-client` discovery for generic OIDC. The Google adapter requires `openid email profile` scopes, validates issuer/audience/nonce, reads stable `sub`, and trusts email linking only when `email_verified` is true.

- [ ] **Step 6: Implement provider discovery and identity unlinking**

`GET /providers` returns enabled provider names and public capabilities only. Identity responses exclude provider access tokens, refresh tokens, client IDs, and secrets.

- [ ] **Step 7: Run OAuth tests**

Run: `pnpm vitest run packages/mrjim-auth/test/unit/pkce.spec.ts packages/mrjim-auth/test/integration/oauth.spec.ts`  
Expected: PASS.

- [ ] **Step 8: Commit**

~~~bash
git add packages/mrjim-auth/src/client/pkce.ts packages/mrjim-auth/src/server/oauth* packages/mrjim-auth/src/server/routes/oauth.ts packages/mrjim-auth/test
git commit -m "feat: add secure oauth and identity linking"
~~~

### Task 8: Implement dynamic roles, permissions, inheritance, and scopes

**Files:**
- Create: `packages/mrjim-auth/src/server/authorization.ts`
- Create: `packages/mrjim-auth/src/server/routes/permissions.ts`
- Test: `packages/mrjim-auth/test/unit/permission-matcher.spec.ts`
- Test: `packages/mrjim-auth/test/integration/authorization.spec.ts`

**Interfaces:**
- Produces: `AuthorizationService.getPermissions(userId, scope?)` and `authorize(subject, requirement)`.
- Permission requirements: `{ any?: string[]; all?: string[]; scope?: { type: string; id: string } }`.
- Consumed by: application server helpers, auth administration, and `client.auth.getPermissions`.

- [ ] **Step 1: Write permission-matching tests**

Cover direct permissions, multiple-role union, recursive inheritance, `invoice.*`, `*.*`, scope exact match, global assignment, expired assignment, missing permission, and cycle rejection.

- [ ] **Step 2: Run authorization tests and verify failures**

Run: `pnpm vitest run packages/mrjim-auth/test/unit/permission-matcher.spec.ts packages/mrjim-auth/test/integration/authorization.spec.ts`  
Expected: FAIL because authorization is missing.

- [ ] **Step 3: Implement normalized permission matching**

Validate lowercase `resource.action` keys, expand direct and inherited roles with a recursive CTE, filter expired assignments, and deduplicate permissions. Rank must not add implicit permissions.

- [ ] **Step 4: Implement server enforcement**

Return `403 insufficient_permission` with request ID but not the user's full permission list. Attach resolved permissions to request-local context so multiple checks in one request reuse one database read.

- [ ] **Step 5: Implement current-user permission endpoint**

`GET /user/permissions` accepts optional validated `scope_type` and `scope_id` query parameters and returns normalized permission keys for UI use.

- [ ] **Step 6: Run authorization tests**

Run: `pnpm vitest run packages/mrjim-auth/test/unit/permission-matcher.spec.ts packages/mrjim-auth/test/integration/authorization.spec.ts`  
Expected: PASS.

- [ ] **Step 7: Commit**

~~~bash
git add packages/mrjim-auth/src/server/authorization.ts packages/mrjim-auth/src/server/routes/permissions.ts packages/mrjim-auth/test
git commit -m "feat: add dynamic authorization"
~~~

### Task 9: Build the framework-neutral HTTP API and OpenAPI contract

**Files:**
- Create: `packages/mrjim-auth/src/server/auth-server.ts`
- Create: `packages/mrjim-auth/src/server/create-auth-server.ts`
- Create: `packages/mrjim-auth/src/server/routes/contracts.ts`
- Create: `packages/mrjim-auth/src/server/routes/public.ts`
- Create: `packages/mrjim-auth/src/server/routes/user.ts`
- Create: `packages/mrjim-auth/src/server/openapi.ts`
- Test: `packages/mrjim-auth/test/contract/http-api.spec.ts`

**Interfaces:**
- Produces: `createAuthServer(options): AuthServer`.
- `AuthServer.handle(request: Request): Promise<Response>`.
- `AuthServer.authorize(request, requirement): Promise<AuthSubject>`.
- Consumed by: Express and Next.js adapters and examples.

- [ ] **Step 1: Write route contract tests**

Exercise every public/user endpoint from specification section 10. Assert status, snake_case JSON, `{ data, error }` client normalization, request ID, CORS, body-size limit, content type, and stable error codes.

- [ ] **Step 2: Run route tests and verify failures**

Run: `pnpm vitest run packages/mrjim-auth/test/contract/http-api.spec.ts`  
Expected: FAIL because the handler is missing.

- [ ] **Step 3: Implement Zod route contracts**

Define one input/output schema per route and derive OpenAPI components from the same definitions. Reject unknown security-sensitive fields. Set a 64 KiB JSON body limit and normalize email before services.

- [ ] **Step 4: Implement request dispatch and authentication**

Route by method/path, validate publishable or secret API key, verify bearer token where required, call services, and map known errors to stable responses. Set `Cache-Control: no-store` on every session or user response.

- [ ] **Step 5: Generate OpenAPI**

Expose `generateOpenApiDocument()` and write `docs/reference/openapi.json` in the docs build. Include examples and security schemes for publishable key, secret key, and bearer token.

- [ ] **Step 6: Run contract tests**

Run: `pnpm vitest run packages/mrjim-auth/test/contract/http-api.spec.ts`  
Expected: PASS.

- [ ] **Step 7: Commit**

~~~bash
git add packages/mrjim-auth/src/server packages/mrjim-auth/test/contract/http-api.spec.ts docs/reference/openapi.json
git commit -m "feat: expose auth http contract"
~~~

### Task 10: Implement the browser-safe Supabase-inspired client

**Files:**
- Create: `packages/mrjim-auth/src/client/transport.ts`
- Create: `packages/mrjim-auth/src/client/storage.ts`
- Create: `packages/mrjim-auth/src/client/events.ts`
- Create: `packages/mrjim-auth/src/client/lock.ts`
- Create: `packages/mrjim-auth/src/client/initialize.ts`
- Create: `packages/mrjim-auth/src/client/auth-client.ts`
- Modify: `packages/mrjim-auth/src/index.ts`
- Test: `packages/mrjim-auth/test/unit/auth-client.spec.ts`
- Test: `packages/mrjim-auth/test/browser/session-lifecycle.spec.ts`

**Interfaces:**
- Produces: `createClient(authUrl, publishableKey?, options?): MrJimAuthClient`.
- Produces every `client.auth` method and event listed in specification section 9.
- Consumed by: browser and Next.js examples.

- [ ] **Step 1: Write client method-shape tests**

Mock fetch and assert URL, method, headers, body, and `AuthResult` for signup, password login, OTP, verification, recovery, user, update, refresh, OAuth, identity, permission, and logout methods.

- [ ] **Step 2: Write browser lifecycle tests**

Test `INITIAL_SESSION`, persistence, refresh before expiry, one refresh across two tabs, OAuth/recovery URL consumption, `SIGNED_OUT` propagation, unsubscribe, and idempotent `dispose`.

- [ ] **Step 3: Run client tests and verify failures**

Run: `pnpm vitest run packages/mrjim-auth/test/unit/auth-client.spec.ts && pnpm playwright test packages/mrjim-auth/test/browser/session-lifecycle.spec.ts`  
Expected: FAIL because the client is missing.

- [ ] **Step 4: Implement transport and storage**

Use injected `fetch`, merge global headers, always send `apikey` when configured, normalize non-2xx responses into `AuthApiError`, and support synchronous or asynchronous storage.

- [ ] **Step 5: Implement eventing, locking, and initialization**

Use `BroadcastChannel` with storage-event fallback, a lock keyed by `storageKey`, URL-safe PKCE detection, and ordered synchronous event dispatch. Remove consumed URL credentials with `history.replaceState`.

- [ ] **Step 6: Implement all public auth methods**

Match the method names, argument shapes, return nesting, sign-out scopes, and event behavior in the specification. `getSession` reads storage; `getUser` always calls the server.

- [ ] **Step 7: Run client and browser tests**

Run: `pnpm vitest run packages/mrjim-auth/test/unit/auth-client.spec.ts && pnpm playwright test packages/mrjim-auth/test/browser/session-lifecycle.spec.ts`  
Expected: PASS.

- [ ] **Step 8: Commit**

~~~bash
git add packages/mrjim-auth/src/client packages/mrjim-auth/src/index.ts packages/mrjim-auth/test
git commit -m "feat: add browser auth client"
~~~

### Task 11: Add server, Express, and Next.js SSR integration

**Files:**
- Create: `packages/mrjim-auth/src/adapters/express.ts`
- Create: `packages/mrjim-auth/src/adapters/nextjs-browser.ts`
- Create: `packages/mrjim-auth/src/adapters/nextjs-server.ts`
- Create: `packages/mrjim-auth/src/server/cookies.ts`
- Test: `packages/mrjim-auth/test/contract/express-adapter.spec.ts`
- Test: `packages/mrjim-auth/test/contract/nextjs-ssr.spec.ts`

**Interfaces:**
- Produces: `toExpressHandler(authServer)`.
- Produces: `createBrowserClient(authUrl, key, options)`.
- Produces: `createServerClient(authUrl, key, { cookies, headers? })`.
- Cookie adapter: `getAll(): Cookie[]` and `setAll(cookies: CookieToSet[]): void | Promise<void>`.

- [ ] **Step 1: Write adapter tests**

Assert Express body/header/cookie translation, Next per-request isolation, refreshed cookie writes, read-only cookie behavior, proxy headers, and absence of secret admin APIs from browser exports.

- [ ] **Step 2: Run adapter tests and verify failures**

Run: `pnpm vitest run packages/mrjim-auth/test/contract/express-adapter.spec.ts packages/mrjim-auth/test/contract/nextjs-ssr.spec.ts`  
Expected: FAIL because adapters are missing.

- [ ] **Step 3: Implement the Express adapter**

Translate Express requests into Web `Request`, stream the Web `Response` status/headers/body back, preserve multiple `Set-Cookie` headers, and derive client IP only from configured trusted proxy headers.

- [ ] **Step 4: Implement Next.js helpers**

Browser helper returns one singleton per module realm and storage key. Server helper constructs a fresh client each call, reads cookies through `getAll`, persists rotated sessions through `setAll`, and never stores user state globally.

- [ ] **Step 5: Run adapter tests**

Run: `pnpm vitest run packages/mrjim-auth/test/contract/express-adapter.spec.ts packages/mrjim-auth/test/contract/nextjs-ssr.spec.ts`  
Expected: PASS.

- [ ] **Step 6: Commit**

~~~bash
git add packages/mrjim-auth/src/adapters packages/mrjim-auth/src/server/cookies.ts packages/mrjim-auth/test/contract
git commit -m "feat: add express and nextjs auth adapters"
~~~

### Task 12: Implement secret/admin clients, API keys, auditing, and rate limits

**Files:**
- Create: `packages/mrjim-auth/src/server/admin.ts`
- Create: `packages/mrjim-auth/src/server/api-keys.ts`
- Create: `packages/mrjim-auth/src/server/audit.ts`
- Create: `packages/mrjim-auth/src/server/rate-limit.ts`
- Create: `packages/mrjim-auth/src/server/routes/admin.ts`
- Create: `packages/mrjim-auth/src/cli/commands/keys.ts`
- Test: `packages/mrjim-auth/test/integration/admin.spec.ts`
- Test: `packages/mrjim-auth/test/contract/audit-redaction.spec.ts`

**Interfaces:**
- Produces `auth.admin` methods listed in specification section 9.
- Produces `mrjim-auth keys generate --kind publishable|secret --name NAME`.
- Produces pluggable `RateLimiter.consume(key, policy)` with PostgreSQL fallback.

- [ ] **Step 1: Write administration authorization tests**

Assert secret key use, delegated `auth.users.manage`/`auth.roles.manage`/`auth.permissions.manage` permissions, browser-secret rejection, pagination, soft deletion, role assignment scope, rank enforcement, protected-role minimum, and transaction rollback.

- [ ] **Step 2: Write audit and rate-limit tests**

Assert raw tokens/passwords/secrets are redacted, audit rows are immutable, API keys are stored only as HMAC hashes, and login/recovery/OTP limits use separate buckets.

- [ ] **Step 3: Run tests and verify failures**

Run: `pnpm vitest run packages/mrjim-auth/test/integration/admin.spec.ts packages/mrjim-auth/test/contract/audit-redaction.spec.ts`  
Expected: FAIL because admin services are missing.

- [ ] **Step 4: Implement API keys and server-only client**

Generate 32-byte values with visible prefixes, persist only HMAC hashes, validate kind/scopes/expiry/revocation, and update `last_used_at` asynchronously. Reject secret keys when `Origin` or browser fetch metadata indicates a browser request.

- [ ] **Step 5: Implement transactional administration**

Implement user, role, permission, role-inheritance, assignment, and audit listing methods. Lock affected roles/assignments for rank and minimum-assignment checks. Every mutation writes one audit outcome in the same transaction.

- [ ] **Step 6: Implement rate-limit hooks**

Define named policies for signup, login by IP and email, recovery, resend, OTP issue, OTP verify, OAuth start, and admin mutation. Return `429 rate_limit_exceeded` and `Retry-After`.

- [ ] **Step 7: Run administration tests**

Run: `pnpm vitest run packages/mrjim-auth/test/integration/admin.spec.ts packages/mrjim-auth/test/contract/audit-redaction.spec.ts`  
Expected: PASS.

- [ ] **Step 8: Commit**

~~~bash
git add packages/mrjim-auth/src/server packages/mrjim-auth/src/cli/commands/keys.ts packages/mrjim-auth/test
git commit -m "feat: add auth administration controls"
~~~

### Task 13: Build documentation and runnable examples

**Files:**
- Create: `README.md`
- Create: `docs/getting-started.md`
- Create: `docs/concepts/architecture.md`
- Create: `docs/concepts/sessions.md`
- Create: `docs/reference/client.md`
- Create: `docs/reference/server.md`
- Create: `docs/reference/schema.md`
- Create: `docs/guides/email-password.md`
- Create: `docs/guides/google-oauth.md`
- Create: `docs/guides/ssr-nextjs.md`
- Create: `docs/guides/express.md`
- Create: `docs/guides/roles-permissions.md`
- Create: `docs/guides/migrating-to-supabase.md`
- Create: `docs/compatibility/supabase-auth.md`
- Create: `docs/security.md`
- Create: `CHANGELOG.md`
- Create: `examples/express-api/**`
- Create: `examples/nextjs-app-router/**`
- Test: `packages/mrjim-auth/test/contract/docs-examples.spec.ts`

**Interfaces:**
- Produces: tested five-minute setup, API reference, schema reference, OpenAPI, security checklist, and Supabase compatibility matrix.
- Produces: runnable Express and Next.js examples against a fresh PostgreSQL database.

- [ ] **Step 1: Write documentation example compilation tests**

Extract fenced TypeScript examples tagged `compile`, compile them with the package declarations, and fail on unknown exports or type errors. Check every public method appears in `docs/reference/client.md` or `server.md`.

- [ ] **Step 2: Run docs tests and verify missing documentation fails**

Run: `pnpm vitest run packages/mrjim-auth/test/contract/docs-examples.spec.ts`  
Expected: FAIL because required documents and examples are missing.

- [ ] **Step 3: Write the getting-started and reference documentation**

Document install, migration, server mount, browser client, environment variables, Google callback setup, role seeding, permission enforcement, session options, errors, and production checklist using complete runnable examples.

- [ ] **Step 4: Write the Supabase compatibility guide**

Use three statuses: `Compatible`, `Different`, and `Unsupported in v1`. Map `createClient`, auth options, all v1 methods/events, admin methods, response nesting, and SSR behavior. Explicitly state that `from`, `rpc`, storage, realtime, phone auth, MFA, anonymous auth, and SAML are not provided.

- [ ] **Step 5: Build runnable examples**

The Express example mounts `/auth/v1`, applies migrations via an explicit script, seeds `user` and `admin` roles, and protects `GET /invoices` with `invoice.read`. The Next.js example supports signup, login, Google OAuth callback, recovery, server-rendered profile, permission-aware navigation, and logout.

- [ ] **Step 6: Run examples and documentation checks**

Run: `pnpm docs:check && pnpm --filter express-api test && pnpm --filter nextjs-app-router test`  
Expected: PASS against a fresh disposable PostgreSQL database.

- [ ] **Step 7: Commit**

~~~bash
git add README.md CHANGELOG.md docs examples packages/mrjim-auth/test/contract/docs-examples.spec.ts
git commit -m "docs: publish auth guides and examples"
~~~

### Task 14: Run security, compatibility, migration, and release verification

**Files:**
- Create: `packages/mrjim-auth/test/security/auth-abuse.spec.ts`
- Create: `packages/mrjim-auth/test/contract/supabase-surface.spec.ts`
- Create: `packages/mrjim-auth/test/contract/browser-bundle.spec.ts`
- Create: `packages/mrjim-auth/test/integration/version-upgrade.spec.ts`
- Create: `scripts/release-check.mjs`
- Create: `docs/release-checklist.md`
- Modify: `CHANGELOG.md`

**Interfaces:**
- Produces: `pnpm release:check` as the single release gate.
- Verifies all acceptance criteria in `docs/specs/mrjim-auth-v1.md` section 20.

- [ ] **Step 1: Write abuse-path tests**

Cover credential stuffing limits, user enumeration, refresh replay, stolen callback code without verifier, state replay, open redirect, OAuth identity collision, final-identity unlink, CSRF-sensitive cookie requests, expired scoped roles, secret key in browser context, audit injection, and oversized metadata.

- [ ] **Step 2: Write compatibility and bundle tests**

Compile representative Supabase-shaped calls against `mrjim-auth`. Bundle the root entry for a browser and assert the output does not contain `node:crypto`, `pg`, Argon2, private-key loading, migrations, or admin implementation strings.

- [ ] **Step 3: Write fresh and upgrade migration tests**

Run a fresh install and an upgrade from each committed migration boundary on PostgreSQL 15, 16, and 17. Verify checksums, indexes, constraints, and data preservation.

- [ ] **Step 4: Run targeted security tests**

Run: `pnpm vitest run packages/mrjim-auth/test/security packages/mrjim-auth/test/contract/supabase-surface.spec.ts packages/mrjim-auth/test/contract/browser-bundle.spec.ts packages/mrjim-auth/test/integration/version-upgrade.spec.ts`  
Expected: PASS.

- [ ] **Step 5: Implement and run the release gate**

`scripts/release-check.mjs` runs formatting, lint, typecheck, unit tests, PostgreSQL integration tests, browser tests, docs checks, package build, export checks, `npm pack --dry-run`, and both examples.

Run: `pnpm release:check`  
Expected: PASS with zero skipped security or migration suites.

- [ ] **Step 6: Inspect the packed artifact**

Run: `pnpm --filter mrjim-auth pack --pack-destination ./artifacts` and inspect the tarball file list. Confirm SQL migrations, declarations, source maps, README, and license are present; source tests, environment files, local databases, and secrets are absent.

- [ ] **Step 7: Record v1 release readiness**

Update `CHANGELOG.md` with the supported SDK surface, schema migration versions, known differences from Supabase, and exact Node/PostgreSQL support. Complete `docs/release-checklist.md` with command output references.

- [ ] **Step 8: Commit**

~~~bash
git add packages/mrjim-auth/test scripts/release-check.mjs docs/release-checklist.md CHANGELOG.md
git commit -m "test: verify mrjim-auth v1 release"
~~~

## Execution order and review gates

Tasks 1-4 establish package, contracts, schema, and persistence. Tasks 5-8 build independently reviewable auth/session/OAuth/authorization services. Tasks 9-12 expose and integrate the runtime surfaces. Tasks 13-14 make documentation and release verification mandatory.

Do not begin a task until the preceding task's focused tests pass. At each commit, run `pnpm typecheck` plus the focused command listed in that task. Before release, `pnpm release:check` must pass from a clean checkout with a fresh PostgreSQL database.
