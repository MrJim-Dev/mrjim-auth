# mrjim-auth Implementation Status

**Plan:** `docs/superpowers/plans/2026-08-10-mrjim-auth-v1.md`  
**Branch:** `feat/mrjim-auth-v1`  
**Last updated:** 2026-08-11

## Current state

Task 1, its review fixes, Task 2, and Task 2 Review Fix Passes 1, 2, and 3 are
complete in this worktree. The
package workspace, strict ESM TypeScript configuration, browser-safe public
entrypoint, Node-only build targets, export map, shared auth contracts,
validated Zod configuration, recursive redaction boundaries, local verification
commands, and handoff reports are present. The published package manifest is
named exactly `mrjim-auth`.

Task 2 defines the browser-safe result, error, identity, session, role,
permission, client-option, server-option, adapter, mailer, limiter, and key
provider contracts. Expected API failures use mutually exclusive `{ data,
error }` values; configuration and programming failures remain throw-based.
Production base/site/redirect URL, PKCE, TTL, and key-material rules are
validated by Zod 4.4.3. Signing-key `issuer` and `audience` are required
non-empty identifiers; only configured OIDC provider `issuer` values use the
HTTP(S) URL schema. Public identity claims and one-time-token/audit metadata
are runtime-sanitized and fail closed. Public error codes are constrained and
enumeration-sensitive internal codes are mapped to generic public codes. No
database, password hashing, migration, OAuth provider credential, or Node-only
implementation was added.

Task 1 does not implement authentication behavior or create database objects.
The future PostgreSQL work must create only the clean `auth` schema; no `mrjim`
objects or Hayahai/shipping business fields have been added here.

Task 1 exposes only the documented experimental `createClient` scaffold. It
returns an immutable empty object and performs no authentication work. The
server, Next.js server, and testing subpaths remain loadable export-map targets
without unfinished public functions. The PostgreSQL subpath is now the
implemented Task 3 migration and Task 4 repository boundary.

Task 4 implements the complete internal PostgreSQL repository aggregate with
the exact-pinned free/open-source Kysely 0.29.5 PostgresDialect over the Task 3
`auth` schema. The adapter has typed table/row mappings, explicit column
lists, parameterized queries, transaction-scoped aggregates, atomic
one-time/OAuth consumption, active-owner session/credential boundaries,
refresh rotation/revocation lineage with one stable lock order, scoped
recursive permission resolution, role-system immutability and deterministic
relationship locks, redacted immutable audit append, identity/password/API-key
boundaries, and caller-owned versus internally owned pool lifecycle. It never
runs migrations on construction and is exported only from the Node PostgreSQL
subpath.

Task 5 implements the Node-only ES256 token/session boundary. `TokenService`
issues and verifies issuer/audience/session-bound access JWTs with protected
`kid` selection, rotation-aware public JWKS, and HMAC-SHA-256 opaque-token
digests. `SessionService` creates 256-bit opaque refresh sessions, rotates
refresh families through real PostgreSQL transactions with one concurrent
winner, commits replay containment independently of the discovery transaction,
and implements exact local/global/others logout scopes with redacted audit
events. Review Fix Pass 1 adds a bounded/redacted server-context boundary,
pre-transaction PostgreSQL IP validation, a service-owned clock, strict
session/user/state/timestamp checks for access-token issuance, public-only
private-JWK handling, and distinct revoked-versus-reused refresh outcomes.
Review Fix Pass 2 replaces heuristic user-agent redaction with a deterministic
`ua-sha256:` fingerprint-only durable representation and maps unexpected
repository, audit, transaction, and replay-containment failures to a fixed
public `internal_error` result while preserving classified configuration and
programming throws. Browser exports remain unchanged and do not import the
server boundary.
This Task 5 subsection is historical. Task 6 behavior and its review-fix
evidence are recorded in the Task 6 subsection below.

Task 6 implements the Node-only user/password and email lifecycle boundary.
Review Fix Pass 1 additionally closes the redirect/account oracle, binds OTP
failure accounting to the presented digest, adds session-subject authorization
for self-service mutations, rechecks user credentials under lock before
session issuance, rejects banned users during session create/refresh, and
keeps email changes pending until exact proof is consumed. `UserService`
orchestrates signup with configured default roles, optional email confirmation,
password sign-in with opportunistic Argon2id rehash, generic duplicate-signup
concealment, OTP/magic-link verification, resend and recovery,
proof-gated profile/password/email updates, banned/soft-deleted rejection,
and default all-session revocation after password reset/change/email-change
confirmation. `PasswordService` uses the exact-pinned free/open-source
`argon2@0.44.0` package with an Argon2id floor of 64 MiB, three iterations,
and exactly one lane; malformed, unsupported, and over-cap PHC inputs take
the fixed dummy verification path. `EmailService` applies only Unicode
normalization, trim, and lowercase and enforces exact configured redirects.

`OneTimeTokenService` generates 32-byte random bearer values, persists only
HMAC-SHA-256 digests, binds purpose/target/redirect, enforces the 15-minute
recovery and 24-hour signup limits, and delivers the five project-owned mail
templates through the injected `Mailer` boundary. The PostgreSQL repository
uses the existing unique `token_hash` index and `attempt_count`/maximum-five
schema contract for an atomic digest-bound OTP failure update; no schema
migration was necessary. `FakeMailer` is bundled only for tests/examples.
Raw tokens, passwords, hashes, recipient emails, and bearer links do not enter
public results or audit metadata, and the browser root/export remains free of
the Node-only lifecycle boundary.
Review Fix Pass 2 preserves refresh replay containment for banned/deleted
owners, makes email-change proof consumption and mutation one transaction,
conceals expected issuance delivery/persistence/audit failures with a safe
project-owned observability hook, and moves issuance rate-limit hooks before
redirect validation. It also replaces the reset race fixture with the real
recovery-reset transaction path and adds deterministic ban-vs-session races.
Historical Review Fix Pass 3 added the adapter-error sanitization boundary and
recovery-verification limiter ordering. Historical Review Fix Pass 4 moved the
trusted failure payload out of marker fields and removed all
exception/name/code/shape trust for `email_exists`, but its class marker still
had a constructor-reachable registration path. Current Review Fix Pass 5
replaces that class with a factory-created null-prototype exact-identity token.
Only the exact marker can restore a service-created policy error; every
arbitrary adapter value maps to fixed `internal_error`, while the service-owned
duplicate precheck retains its documented conflict. The final reviewer then
escalated same-realm prototype replacement after the fifth fix pass. The
controller resolution captures `WeakMap`, `WeakSet`, `Object.create`, and
`Object.freeze` intrinsics at module initialization and adds direct regression
coverage. Project-supplied adapters are trusted executable code, while all
values returned or thrown by them remain untrusted and sanitized. This
resolution was independently confirmed against simultaneous replacement of
all captured methods. Task 6 is approved with no remaining Critical or
Important findings.

Task 7 implements the Node-only Google/OIDC OAuth boundary and browser-safe
RFC 7636 S256 helpers. `OAuthService` creates exact-redirect, flow-bound,
HMAC-digested, ten-minute single-use state rows with encrypted verifier/nonce
material; callback processing consumes state once, validates the injected
provider profile, and issues only a durable HMAC-digested `oauth_callback`
one-time code with a database-enforced maximum 60-second TTL. Code exchange
consumes that row atomically with session creation, so concurrent replays have
one winner and a failed session transaction leaves the code available for a
retry. Provider-subject sign-in, fresh-session signed linking, collision
rejection, verified-email-only opt-in auto-linking, safe identity projection,
redacted audit events, and final-login-method unlink protection are included.

Task 7 Fix Pass 1 closes the independent review findings. Fresh-session status
and state creation now share a lock-scoped transaction; the originating session
UUID is durably persisted inside the existing encrypted state payload and is
revalidated under lock during callback and direct linking. Verified-email
matches are locked including soft-deleted rows, with banned/deleted rejection
before identity or callback-code writes. Every OAuth provider/repository call
uses the hardened adapter boundary, and private transaction results plus
conflict-returning PostgreSQL inserts prevent arbitrary thrown or returned
adapter values from selecting public errors. Returned identities are validated
and copied into safe projections before they can reach service results. OAuth
user creation now resolves and assigns configured default roles atomically and
rolls back when a role is missing. State-only callbacks recover default or
alternate exact redirects; the route requires only provider `code` and
`state`.

OIDC issuer configuration and provider construction require HTTPS. A local
self-hosted HTTPS fixture now verifies real discovery, token exchange, PKCE,
redirect/state/nonce binding, issuer/audience/sub claims, ID-token signatures,
and JWKS without external network access. OAuth HMAC/encryption material must
contain at least 32 decoded bytes, using canonical unpadded base64url strings or
direct `Uint8Array` values. Fix Pass 1 passed 51 focused tests, five selected
PostgreSQL race tests, 45 provider/export/migration tests, and the full 188-test
suite. Independent re-review is pending; approval is not claimed.

Task 7 Fix Pass 2 makes OAuth-state and identity adapter projections immutable
exact-binding snapshots. Callback state fields are read once inside the adapter
boundary, byte arrays and dates are copied, and the returned state digest is
constant-time matched to the requested digest before provider or database
work. Identity find/create projections bind provider, subject, and expected
owner; every exchange/list/unlink projection must belong to the requested user
and have `identity_data.sub` equal to `provider_subject`. Mismatches fail closed
and transaction-scoped paths roll back token, identity, user, and session work.
Shared configuration now uses the same canonical unpadded base64url rule as
service construction, rejecting whitespace and noncanonical trailing bits at
the 32-byte boundary. Pass 2 passed 58 focused tests, five selected PostgreSQL
race tests, 45 provider/export/migration tests, 12 explicit export/browser
tests, and the full 195-test suite. Bohr re-review is pending; approval is not
claimed.

Task 7 Fix Pass 3 captures and binds all state-snapshot Buffer, typed-array,
Date, array, copy, freeze, and equality operations before adapters can execute.
Callback preserves a private expected digest, passes a separate repository
copy, immediately copies mutable returned fields, and uses only its immutable
snapshot. Identity snapshots use captured freeze, while repository collections
are copied by trusted index reads and validated through captured iteration;
adapter-owned `map` is never called. Realm mutation can no longer retain a
wrong state digest, substitute a foreign find/create identity, disclose a
foreign list element, create a session from an unvalidated exchange identity,
or delete another user's identity. Pass 3 passed 59 focused tests, five
selected PostgreSQL race tests, 45 provider/export/migration tests, 12 explicit
export/browser tests, and the full 196-test suite. Same-reviewer re-review is
pending; approval is not claimed.

Task 7 Fix Pass 4 removes the final inherited identity-selection operation.
Both callback-code exchange and unlink now use one module-local numeric helper
that searches only the validated immutable snapshot and never calls inherited
or collection-owned `.find`. The one table-driven regression mutates
`Array.prototype.find` from a returned-item getter and restores it in `finally`;
exchange returns the fixed `invalid_request` error without session creation or
callback-code consumption, while unlink returns the fixed `not_found` error
without `deleteById` or foreign deletion. Database snapshots remain unchanged.
Targeted RED was 2 failed with 26 skipped; identical-command GREEN was 2 passed
with 26 skipped. Pass 4 then passed 61 focused tests, five selected PostgreSQL
races, 45 provider/export/migration tests, the 23-test migration suite, the
12-test export/browser suite, and the final 198-test full suite. The first full
run exposed one existing wall-clock-sensitive JWT assertion after its fixed
token crossed expiry (197 passed, 1 failed); direct verification now uses that
test's injected `NOW`, and its seven-test file plus the full rerun pass. No
production token behavior or additional test case changed. No migration,
dependency, manifest, or lockfile changed. The same independent reviewer
approved Task 7 at `bfa3bff84bf28ef3868fc6b7a9418fbd419f2e30` and closed all
original and fix-pass findings. Independent verification passed the targeted
2/2 regression, 7/7 token tests, 61/61 focused tests, five selected PostgreSQL
races, 45/45 provider/export/migration tests, 23/23 migration tests, 12/12
export/browser tests, and the complete 198/198 suite, together with frozen
install, build, typecheck, lint, docs, packed-consumer, byte-identity, and
whitespace checks.

The forward-only `0005_oauth_callback` migration is required because the
immutable `0001–0004` `one_time_tokens_purpose_check` cannot accept the new
durable callback purpose. It adds only the new purpose and its `<= 60 seconds`
expiry check; byte/checksum assertions preserve `0001–0004` unchanged. No
callback code is kept in process memory or represented as a self-contained
reusable token.

Task 8's third post-pass route-boundary hardening resolution is independently
approved against clean baseline
`b81a12f83471b2b46a141d1c0b618228a5cd3771`. It closes exactly the two
validated High findings. `permissionsRoute` now calls `getPermissions`
synchronously inside a fail-closed boundary, snapshots direct arrays before
any await, rejects own/inherited `then` properties without invoking them, and
normalizes only screened native-compatible Promise sources through a
package-owned native Promise bridge. Plain thenables, Promise subclasses,
custom constructor/species shapes, malformed/sparse/accessor/oversized arrays,
and rejection fail closed. The raw source is never awaited or cached.

The shared route response factory now adds an own immutable,
non-enumerable `then: undefined` data property to every captured native
Response before the async route boundary. Captured JSON/Response intrinsics
and null-prototype snapshots preserve the exact 200/400/401/405/500 contracts;
fixed service failures remain no-store 500 `internal_error` with bounded
request IDs and no adapter value/message. Earlier blanket wording is narrowed:
the route return boundary is protected; body reads are asserted after polluted
prototypes are restored because Node/Undici has a separate internal stream
reader boundary.

Third post-pass RED was source 2 failed/40 passed across the 42-test focused
group and packed 1 failed/22 skipped (23), before production edits. Identical
GREEN is source 42/42 and packed 1/1 (22 skipped). The full suite is 17 files
and 240/240 tests. Repository/shared is 36/36, migration/state is 24/24, and
export/browser is 15/15. The deterministic 100,000-row/10,000-requirement
source performance group is 2/2 in 709ms test time; the packed fresh
install/import/adversarial run includes the deterministic 100,000-row result
and passed in 9.14s. Frozen install, build, typecheck, lint, docs check,
direct root/server/browser imports (3/3), packed install/import, diff check,
and protected hashes pass. No migration, manifest, lockfile, dependency,
direct-user-permission model, paid service, hosted service, or runtime-network
dependency changed. The same independent Luna reviewer approved resolution
commit `000a960fe9e3783223916e3ffa484d042ba7b7b9`; security scan
`b547872f-8453-4f5b-aff4-34174f0cd124` sealed with zero reportable findings.
Task 8 has no product blocker. Tasks 9-14 remain.

Task 8 Fix Pass 1 was implemented pending fresh independent review. `AuthorizationService`
consumes the existing PostgreSQL authorization repository, whose recursive CTE
expands active assigned roles and inherited roles with `UNION` duplicate
elimination and deterministic permission-key ordering. Direct grants mean only
direct `role_permissions` rows on assigned roles; no direct user-permission
table or grant was added. Exact, resource-wildcard, and global-wildcard
matching is canonical lowercase and ranked exact > resource wildcard > global
wildcard; role rank never grants access. Global assignments apply to a
requested scope, while scoped assignments require the exact type/id pair and
are filtered at the supplied operation time.

Fix Pass 1 validates plain request objects, snapshots numeric arrays and
complete permission records through captured intrinsics, binds one own UUID
subject snapshot, rejects NUL scope identities, and replaces service-lifetime
caching with an explicit immutable request context. The guard returns a
redacted `insufficient_permission` 403 with a bounded request ID. The
user-permission route binds its subject once, validates optional scope query
pairs, and returns only sorted permission keys under `{ data, error }`.
Write-time cycle rejection and diamond deduplication remain covered by local
PostgreSQL tests; the report intentionally does not claim an independent
corrupted-cycle read regression. No migration or dependency was added.

## Required dependency policy

- Required runtime, build, test, documentation, and release dependencies must be free/open-source.
- The SDK must run on project-owned Node.js and PostgreSQL infrastructure.
- Google OAuth, SMTP, and other external integrations are adapters configured by each project; no paid plan is required by `mrjim-auth`.
- A paid SaaS product must never be required to build, test, document, deploy, or operate the core package.

Task 1 has no runtime dependencies. Its local development dependencies are
`@types/node`, TypeScript, Vitest, and the free/open-source `esbuild` package,
which is used only to prove browser-platform bundle resolution in the contract
test.

Task 2 adds the free/open-source, exact-pinned `zod@4.4.3` runtime dependency
to the `mrjim-auth` package and records it in `pnpm-lock.yaml`. No paid SaaS or
hosted service is required.

Task 4 adds the free/open-source, exact-pinned `kysely@0.29.5` runtime
dependency. PostgreSQL remains project-owned through the existing `pg` pool
or a caller-selected local/project connection string; no hosted database,
Docker service, or paid application is required.

Task 5 adds the free/open-source, exact-pinned `jose@6.2.8` runtime
dependency (MIT; project `panva/jose`). It is used only by the Node server
token/JWKS boundary; no paid or hosted service is required.

Task 6 adds the free/open-source, exact-pinned `argon2@0.44.0` runtime
dependency (MIT; project `ranisalt/node-argon2`). It is a self-hostable native
Argon2 implementation used only by the Node server password boundary. Mail
delivery and rate limiting remain injected project-owned interfaces; no paid
mailer, hosted identity provider, hosted rate limiter, Redis service, or remote
database is required. The lifecycle integration tests use only disposable
local PostgreSQL 16 clusters.

Task 7 adds the free/open-source, exact-pinned `openid-client@6.8.4` runtime
dependency (MIT; project `panva/openid-client`) for discovery and validated
authorization-code exchange. Its exact-pinned `oauth4webapi@3.8.6` transitive
dependency is also MIT-licensed and project-owned by `panva/oauth4webapi`.
Tests inject deterministic provider adapters and use disposable local
PostgreSQL. Fix Pass 1 additionally uses a local Node.js HTTPS OIDC server with
the existing pinned `jose` dependency to exercise discovery and JWKS/signature
validation. No live Google, hosted OIDC, paid mail, Redis, Docker, remote
database, external network, or paid SaaS service is required.

## Task progress

| Task | Status | Verification |
| --- | --- | --- |
| 1. Workspace and exports | Complete | Review Fix Pass 2 checks passed on 2026-08-11 |
| 2. Shared contracts | Complete — Review Fix Pass 3 | Review RED/GREEN tests, full suite, build, typecheck, lint, docs, frozen-lockfile, and diff checks passed on 2026-08-11 |
| 3. PostgreSQL schema and CLI | Complete — Review Fix Pass 3 | Review RED/GREEN integration, canonical catalog verification, packed-install CLI, full suite (52 tests), build, typecheck, lint, docs, frozen-install, and diff checks recorded in Task 3 report |
| 4. PostgreSQL repositories | Complete — Review Fix Pass 2 | Immutable 0001-0003 history, explicit 0004 hardening upgrade, deterministic corruption restoration, review RED/GREEN adapter and migration integration, full suite, build, typecheck, lint, frozen-install, packed CLI, docs, and diff checks recorded in Task 4 report |
| 5. JWT and sessions | Complete — Review Fix Pass 2 | Pass-2 RED/GREEN evidence, frozen install, build, full suite (93 tests), typecheck, lint, docs, package exports, and diff checks recorded below; post-fix security scan finalization remains blocked by missing `snapshotDigest` metadata and was not retried |
| 6. Users and recovery | Complete — escalation resolved and approved | Pass 5 RED/GREEN (50 focused/mandated, 154 full), ten isolated PostgreSQL races, controller intrinsic-tampering regressions (52/52 mandated and 156/156 full), and final same-reviewer adversarial confirmation passed with no remaining Critical/Important findings |
| 7. OAuth and identities | Complete — Fix Pass 4 approved | Same-reviewer approval closed all findings; targeted 2/2, token 7/7, focused 61/61, selected races 5/5, provider/export/migration 45/45, migration 23/23, export/browser 12/12, full 198/198, packed consumer, protected-file identity, and clean-diff evidence recorded in Task 7 report |
| 8. Dynamic authorization | Complete — third post-pass route-boundary hardening approved | Same-reviewer approval and sealed zero-finding security scan; 42/42 focused source, packed 1/1 (22 skipped), 240/240 full, 24/24 migration/state, 36/36 repository/shared-contract, 15/15 export/browser, frozen install, build, typecheck, lint, docs, direct imports, packed install/import, diff, and protected-hash gates; evidence in Task 8 report |
| 9. HTTP and OpenAPI | In progress — implementation brief committed | Fresh Luna TDD implementation and independent review are the current gate; no implementation result is claimed yet |
| 10. Browser client | Pending | Not run |
| 11. Express and Next.js | Pending | Not run |
| 12. Administration controls | Pending | Not run |
| 13. Documentation and examples | Pending | Not run |
| 14. Release verification | Pending | Not run |

## Blockers

The scoped post-fix security scan did not finalize because its canonical manifest was missing the required
`scan.target.snapshotDigest` value and the scanner returned exactly:
`scan.target.snapshotDigest: expected a non-empty string`. The scan was not
retried, and this handoff does not claim a no-findings result for the fix
range; an independent reviewer will re-review the code separately. The
historical Task 5 scope excluded OAuth provider exchanges, authorization
enforcement, HTTP routes, browser refresh orchestration, framework adapters,
administration, and the broader Task 13 documentation surface; those remain
later Tasks 7-14. The optional security scanner was not invoked for Task 6,
per the Task 6 handoff constraint. This is a tooling-evidence limitation, not
a product blocker; independent source review approved Task 6.

The final reviewer also observed one non-blocking harness residual: the packed
CLI migration test exceeded Vitest's default five-second timeout under that
review run, then passed within seven seconds when rerun with a bounded
30-second timeout. The controller's plain `pnpm test` run passed 156/156. A
per-test timeout should be considered during Task 14 release hardening.

Task 7 Fix Pass 4 blockers: none. The same independent reviewer approved the
final range and closed every Task 7 finding. No paid or hosted service is
needed for review or operation.

## Remaining work

Task 8's third post-pass route-boundary hardening resolution is complete and
independently approved. Task 9 is the current handoff state; Tasks 9-14 remain,
with independent review after each task, followed by the whole-branch review
and release handoff. In particular, later work must use
the clean `auth` schema and explicit migration CLI from Task 3 to implement
auth/session/OAuth/RBAC behavior, HTTP and browser/SSR surfaces,
administration, examples, and release verification.

## Task 4 scope and verification

Task 4 changes and handoff evidence are recorded in
`.superpowers/sdd/2026-08-10-mrjim-auth-v1/task-4-report.md`. The focused
integration test starts only a disposable local PostgreSQL cluster with
`initdb`/`pg_ctl`, explicitly migrates it, and never reads generic
`DATABASE_URL`. It covers the complete Task 2 aggregate, transaction rollback,
normalized-email uniqueness races, one-time/OAuth consume races, refresh
locking and rotation races, session/family/user revocation, active-owner
filtering, replacement expiry/lineage, role inheritance and scope expiry,
diamond deduplication, deterministic permission replacement/deletion, system
role immutability, cycle rollback, CRUD mappings, SQL-injection-like values,
audit/one-time metadata redaction and rollback, OAuth flow validation, and pool
ownership. Migration tests also verify the database one-time metadata validator
and exact OAuth flow check; the canonical verifier is exercised after both
fresh installation and incremental 0004 upgrade; browser boundary fixtures
reject static and dynamic Kysely imports.

Final evidence before commit:

- `pnpm vitest run packages/mrjim-auth/test/integration/postgres-adapter.spec.ts` — 1 file, 16/16 tests passed.
- `pnpm typecheck` — passed.
- `pnpm build` — passed; browser and Node targets compiled and migration assets copied.
- `pnpm docs:check` — passed (2 required documents).
- `pnpm test` — 5 files, 69/69 tests passed; includes immutable migration provenance/schema checks, browser boundary checks, and packed-install CLI coverage.
- `pnpm install --frozen-lockfile` — passed; lockfile is up to date.
- `pnpm lint` — passed; strict TypeScript check completed.
- `git diff --check` — passed.

Remaining work is Tasks 7-14. This historical Task 5 section does not
implement password hashing or
verification, email/OTP/recovery, OAuth/provider exchange, authorization
enforcement decisions, HTTP routes, browser clients, framework adapters,
administration APIs, examples, or release artifacts.

## Task 5 scope and verification — Review Fix Pass 1 (historical)

Task 5 changes are:

Detailed handoff evidence is recorded in
`.superpowers/sdd/2026-08-10-mrjim-auth-v1/task-5-report.md`.

- `packages/mrjim-auth/src/server/tokens.ts` — ES256 access-token issuance and
  fail-closed verification plus HMAC-SHA-256 opaque-token hashing;
- `packages/mrjim-auth/src/server/jwks.ts` — strict P-256/ES256 key import and
  public JWKS conversion;
- `packages/mrjim-auth/src/server/sessions.ts` — session creation, rotating
  refresh families, replay containment, exact logout scopes, and redacted
  audit events;
- `packages/mrjim-auth/src/postgres/repositories/sessions.ts` — preserves
  used/revoked refresh rows for replay classification while retaining the
  existing deterministic PostgreSQL lock order and lineage checks;
- `packages/mrjim-auth/src/server/index.ts`, package dependency/lock metadata,
  and export-boundary tests;
- `packages/mrjim-auth/test/unit/tokens.spec.ts` and
  `packages/mrjim-auth/test/integration/session-rotation.spec.ts` — focused
  unit and disposable real-PostgreSQL concurrency coverage.

No migration was necessary. Migrations `0001`-`0004`, migration provenance,
verifier, and packing assets were not rewritten or added to. The integration
fixture explicitly starts a disposable local PostgreSQL cluster, applies the
existing migrations, and removes only that temporary cluster. Review Fix Pass
1 changed no migration or dependency files; the exact-pinned free/open-source
MIT `jose@6.2.8` remains from the original Task 5 implementation. No paid or
hosted service was added or required.

Review Fix Pass 1 resolves all six reviewer findings:

1. `SessionService` normalizes context before any transaction, drops invalid
   IP addresses to `null`, removes controls, redacts bearer/basic/JWT/opaque
   token, PEM, and sensitive-assignment patterns, and bounds user-agent data to
   512 code points for both session and audit persistence.
2. Invalid IP context can no longer abort replay containment. A real
   PostgreSQL regression proves invalid-IP replay returns
   `refresh_token_reused` and durably revokes the complete family and owning
   session.
3. Caller-controlled `SessionContext.now` was removed. Both services use an
   injected service clock; backdated caller context cannot revive an expired
   session or refresh token.
4. `TokenService.issueAccessToken` validates UUIDs, user/session ownership,
   user/session active state, AAL, timestamp ordering, future timestamps, and
   session expiry, then caps JWT expiry at the owning session expiry.
5. Private JWK inputs are converted to public P-256 material before JWKS
   export, export failures become deterministic `AuthConfigurationError`s,
   and regression coverage proves no private JWK fields are published.
6. A revoked-but-never-used refresh token returns ordinary `invalid_token`
   without replay containment or a reuse audit; used/replaced tokens retain
   `refresh_token_reused` containment. Known `invalid_refresh_lineage` errors
   also map to the stable `{ data, error }` contract.

Strict TDD evidence for Review Fix Pass 1:

- RED against reviewed HEAD `a81a40dd9b039fbf28817741d31a915b1ec81097`:
  `pnpm vitest run packages/mrjim-auth/test/unit/tokens.spec.ts packages/mrjim-auth/test/integration/session-rotation.spec.ts`
  ran 2 files and 16 tests with 9 failed and 7 passed. Failures covered
  private-JWK JWKS export, invalid session records, session-expiry capping,
  hostile/invalid context, invalid-IP replay containment, caller time
  backdating, invalid-lineage mapping, and revoked-token classification.
- GREEN: the same exact command passed with 2 files and 16/16 tests.
- Implementation commit: `e94ee61f09ed3979aca78bcfd2c28cf63c6d53cf`.

Final verification evidence:

- `pnpm install --frozen-lockfile` — passed; lockfile up to date.
- `pnpm build` — passed; browser and Node targets compiled and migration assets copied.
- `pnpm test` — passed; 7 files and 86 tests.
- `pnpm typecheck` — passed.
- `pnpm lint` — passed.
- `pnpm docs:check` — passed (2 required documents).
- `git diff --check` — passed.
- `pnpm view jose@6.2.8 license repository.url --json` — MIT, `panva/jose`.
- Scoped post-fix Codex Security diff scan was started for
  `a81a40dd9b039fbf28817741d31a915b1ec81097..e94ee61f09ed3979aca78bcfd2c28cf63c6d53cf`
  and its three changed server source worklist rows received full-file
  discovery receipts. Finalization failed because the canonical manifest did
  not contain `scan.target.snapshotDigest`; the exact scanner error was
  `scan.target.snapshotDigest: expected a non-empty string`. It was not
  retried. No finalized result, including no no-findings result, is claimed
  for this fix range.

## Task 5 scope and verification — Review Fix Pass 2

Review Fix Pass 2 began from clean HEAD
`a7a1f1d354e21e3464d82331cfc3e08e9a3eae3` and changed only the session
service, shared durable-field comments, and focused tests. The implementation
commit is `b63a98639118086d94a542b21413e81ae321c4d9`.

The two unresolved findings are resolved as follows:

1. User-agent context is now fail-closed at the durable boundary. Every
   non-empty caller value is replaced before persistence with a deterministic
   `ua-sha256:` plus 64 lowercase hexadecimal SHA-256 digest (74 characters
   total); empty or non-string values become `null`. The raw value is never
   written to either `auth.sessions.user_agent` or audit rows. Real PostgreSQL
   coverage exercises embedded 43-character base64url/opaque tokens, quoted
   multi-word passwords, CR/LF, C0/C1 controls including U+0085, NUL, bidi and
   format controls, very long input, and ordinary user-agents. It verifies
   bounded format, no source substring, session/audit consistency, and
   deterministic correlation for repeated ordinary values. Public and internal
   comments now document the fingerprint-only representation.
2. Unexpected repository, database, audit, and transaction failures in
   `create`, `refresh`, and `signOut` now return `{ data: null, error }` with
   stable `internal_error`, HTTP 500, and fixed `Internal authentication error`
   text; operational details are not copied into the result. A replay whose
   containment transaction fails also returns `internal_error` rather than
   claiming `refresh_token_reused`. `AuthConfigurationError` and
   `AuthProgrammingError` remain throws. The deliberate
   `invalid_refresh_lineage` and `refresh_token_not_rotatable` mappings still
   return ordinary `invalid_token`.

Strict TDD evidence for Review Fix Pass 2:

- RED against `a7a1f1d354e21e3464d82331cfc3e08e9a3eae3`:
  `pnpm vitest run packages/mrjim-auth/test/unit/tokens.spec.ts packages/mrjim-auth/test/unit/session-service.spec.ts packages/mrjim-auth/test/integration/session-rotation.spec.ts`
  ran 3 files and 23 tests with 7 failed and 16 passed. The failures were the
  fingerprint-only durable assertions and six operational-error boundary
  assertions.
- GREEN: the same focused command passed with 3 files and 23/23 tests.
- Full frozen verification passed: `pnpm install --frozen-lockfile`,
  `pnpm build`, `pnpm test` (8 files, 93 tests), `pnpm typecheck`, `pnpm lint`,
  `pnpm docs:check`, the package export contract (1 file, 10 tests), and
  `git diff --check`.
- Review Fix Pass 2 changed no migration, package manifest, or lockfile files;
  migrations `0001`-`0004` remain byte-identical. The only runtime dependency
  remains exact-pinned free/open-source MIT `jose@6.2.8`; no paid or hosted
  service is required.
- The failed post-fix security scanner was not retried. Its documented error
  remains `scan.target.snapshotDigest: expected a non-empty string`; no
  finalized no-findings result is claimed for either fix pass.

## Task 6 scope and verification — Review Fix Pass 4 (historical)

Task 6 implementation is present in this worktree and is pending the same
independent review. The scope remains limited to
users, passwords, email verification, OTP, recovery, injected mail/rate-limit
boundaries, and the narrow repository/session contracts needed by those flows.
It does not add OAuth/provider adapters, RBAC APIs, HTTP routes, clients,
framework adapters, administration APIs, or Task 7+ behavior.

Historical Passes 1-3 fixed the earlier independent-review findings. Historical
Pass 4 fixed the mutable trusted-marker payload and forgeable `email_exists`
classification findings, but its class marker retained a constructor-reachable
registration path. Current Pass 5 closes that residual marker-forging path and
stabilizes the normalized-email race fixture:

- validates and canonicalizes both configured redirect boundaries before any
  account lookup, preserving deep public-result equality for existing,
  nonexistent, and duplicate concealed issuance paths;
- attributes OTP failures to the presented HMAC digest through the existing
  unique `one_time_tokens.token_hash` index, preserving purpose/target binding,
  exact redirect binding for success, first-success/fifth-failure consumption,
  and concurrent row-atomic updates;
- replaces arbitrary user-ID mutations with verified access-token subject plus
  active durable-session/user locks, requires current-password proof for
  ordinary password changes, rejects `app_metadata`, and keeps recovery reset
  as a separate capability path;
- re-reads the user and credential under lock before password sign-in session
  creation, and rejects banned/deleted users during session create/refresh;
- leaves the current email active while issuing a purpose-bound pending
  `email_change` token and applies the target only after exact proof, with
  uniqueness-race handling and all-session revocation;
- strictly parses/caps Argon2id PHC values before native verification and routes
  malformed, unsupported, oversized, or non-lane-1 hashes through fixed dummy
  work while still verifying valid weaker hashes for rehash;
- reuses the Task 5 canonical IP normalization for limiter keys and audit
  context.
- retains locked refresh lineage for banned/deleted owners so reused tokens
  are classified and durably contained while unused tokens fail closed;
- consumes email-change tokens inside the same transaction as user locking,
  normalized-email uniqueness handling, session revocation, and audit, with
  rollback/retryability on downstream failure;
- maps expected mailer, persistence, and audit issuance failures to the same
  concealed public success result as nonexistent accounts and exposes only
  redacted action/template/outcome/request-fingerprint/error-class signals;
- counts invalid redirects after the per-IP and per-identifier limiter hooks,
  replaces the direct-SQL reset race with the real recovery-reset path, and
  adds committed-ban races for session creation and refresh.
- treats all unclassified values crossing injected mailer, repository, audit,
  limiter, or observer boundaries as opaque and returns the fixed
  `internal_error`; only private service-created failures can preserve trusted
  prevalidation/configuration policy errors;
- makes concealed existing/missing/duplicate issuance results deeply equal
  even when an adapter throws an `AuthApiError`, ordinary `Error`, string, or
  exotic object containing email, token, code, link, redirect, or provider
  data; observer payloads retain only fixed action/template/outcome/error class
  and canonical IP/UA fingerprints.

Changed production files include `server/users.ts`, `passwords.ts`,
`one-time-tokens.ts`, `sessions.ts`, `server/index.ts`, PostgreSQL users/session
repositories, shared contracts/config, and the existing Task 6 test/export
surfaces. `FakeMailer` remains the bundled in-memory test/example adapter.

Strict regression TDD evidence:

- The Pass 1 regression suites were written before these production fixes.
- RED command:
  `pnpm vitest run packages/mrjim-auth/test/integration/user-lifecycle.spec.ts packages/mrjim-auth/test/contract/enumeration-resistance.spec.ts packages/mrjim-auth/test/unit/password-work-path.spec.ts`
  produced 3 files, 13 failed and 10 passed. Failures reproduced the redirect
  oracle, non-canonical IP keys, digest-unbound OTP counting, arbitrary
  self-service writes, proofless password/email changes, banned session
  issuance, stale-password session issuance after reset commit, and unsafe
  Argon2 native work paths.
- Focused GREEN after the fixes: 4 files, 27/27 tests passed, including the
  real PostgreSQL mixed-resend/correct-vs-wrong races, authorization cases,
  email-change proof/replay/duplicate behavior, and mocked Argon2 work-path
  assertions. The mandated two-file Task 6 command also passes.

Review Fix Pass 2 regression evidence:

- RED command from clean baseline `71e9d2e`:
  `pnpm vitest run packages/mrjim-auth/test/integration/user-lifecycle.spec.ts packages/mrjim-auth/test/contract/enumeration-resistance.spec.ts`
  produced 2 files, 26 tests, 8 failed and 18 passed. Failures were the
  banned/deleted replay oracle, pre-transaction email-change consumption
  (duplicate, blocked-owner, and injected repository/audit failures), public
  operational-failure leakage, and rate-limit-after-redirect ordering.
- GREEN on the same mandated command after implementation: 2 files, 27/27
  tests passed. The integration file is 18/18 and the enumeration contract is
  10/10. The added tests include durable replay read-back, real recovery-reset
  ordering, committed-ban create/refresh races, normalized-email uniqueness
  races, rollback/retryability, observer redaction, and deep public equality.

Review Fix Pass 4 regression evidence:

- RED from clean baseline `34e96e7`:
  `pnpm vitest run packages/mrjim-auth/test/contract/enumeration-resistance.spec.ts`
  produced 1 file, 27 tests, 8 failed and 19 passed. The mandated
  lifecycle/enumeration command also produced 2 files, 45 tests, 9 failed and
  36 passed. Failures covered transaction-mutated/cloned/proxied trusted
  markers, trusted configuration restoration, forged/real/subclass/proxy
  `email_exists` errors, and the normalized-email race result.
- GREEN: the focused contract suite passed with 1 file and 29/29 tests; the
  mandated lifecycle/enumeration command passed with 2 files and 47/47 tests.
  The full matrix passed with 12 files and 151/151 tests.
- `pnpm install --frozen-lockfile`, `pnpm build`, `pnpm typecheck`,
  `pnpm lint`, `pnpm docs:check`, package exports (11/11), migrations (24/24),
  and `git diff --check` passed. No migration, dependency, package manifest,
  or lockfile change was made. Pass 4 is historical and made no approval or
  final blocker disposition claim.

No schema change was required. Migrations `0001`-`0004`, their manifest
checksums, schema contract, verifier, packing/copy checks, and incremental
migration tests remain byte-identical/unchanged. The existing unique
`one_time_tokens_token_hash_key` supports the digest-bound update, while the
existing `attempt_count` constraint and transaction enforce the maximum of
five. No `0005` migration was introduced.

The exact-pinned free/open-source `argon2@0.44.0` dependency is MIT and
self-hostable. Mail delivery and rate limiting are injected project-owned
interfaces; tests use `FakeMailer` and disposable local PostgreSQL 16 only.
No paid application, hosted identity vendor, hosted mail provider, hosted
limiter, Redis service, or remote database is required. The optional security
scanner was not invoked, as required; this pass makes no scanner or reviewer
approval claim and returns to the same independent reviewer.

Final command evidence and the remaining Tasks 7-14 are recorded in
`.superpowers/sdd/2026-08-10-mrjim-auth-v1/task-6-report.md`.

The Pass 1 implementation commit is historical: `f674967` (`fix: harden task 6 auth lifecycle`).
Pass 2 code/tests are historical and committed as `601599e`; Pass 2 docs SHA is
`b42cc95`. Pass 3 code/tests are historical and committed as `ea8437b`; its
documentation/report SHAs are `5068a60`, `0f06f1e`, `70d7fb4`, and `34e96e7`.
Historical Pass 4 code/tests are committed as `24a5ca6`; the initial
documentation/status/report follow-up is `e86b6ff` with final evidence
amended in `8d3a752`. The final Pass 4 report-only follow-ups are `d2a7411`
and `03483fd`; `03483fd` is the Pass 5 baseline.

## Task 6 scope and verification — escalation resolved and approved

Pass 5 is the fifth and final allowed fix pass for the Task 6 review range. It
is limited to the constructor-reachable trusted-marker finding and the
nondeterministic normalized-email race test. It does not add OAuth/provider
adapters, RBAC APIs, HTTP routes, clients, framework adapters, administration
APIs, or Task 7+ behavior. The same independent reviewer approved the final
controller resolution range with no remaining Critical or Important findings.

Pass 5 changes the trusted failure marker from a class instance to a fresh,
frozen `Object.create(null)` token. The token has no constructor, prototype,
own fields, symbols, error surface, or payload. A private `WeakMap` stores the
trusted service error and exact identity lookup is the only restoration path;
clones, proxies, wrappers, structured clones, serialized values, and forged
objects map to fixed `internal_error`. The adapter failure marker uses the same
constructorless identity design.

The real disposable-PostgreSQL normalized-email race test now issues both
tokens before installing a test-only transaction wrapper. For the exact target,
the wrapper waits after each transaction-scoped duplicate precheck and releases
only after both arrivals, with a bounded 10-second timeout and `finally`
release. It asserts one success, one fixed `internal_error` race loser, one
target owner, one consumed winner token, and one unconsumed/retryable loser;
the committed duplicate precheck conflict test remains separate.

Pass 5 TDD and verification evidence:

- RED from clean baseline `03483fda554493b0a563e972dcd8f0c7e4762a6f`:
  the focused two-file command collected 50 tests and had 1 failure/49
  passes. The constructor-forged marker restored the injected `AuthApiError`;
  the barrier lifecycle test passed because the barrier is a test-only
  scheduling fixture.
- GREEN: the focused and mandated two-file commands each passed with 2 files
  and 50/50 tests (18 lifecycle, 32 enumeration).
- The isolated race test passed 10/10 separate invocations, each 1/1 selected
  test, against disposable PostgreSQL 16, with no sleeps or unbounded waits.
- `pnpm install --frozen-lockfile`, `pnpm build`, `pnpm test` (12 files,
  154/154), `pnpm typecheck`, `pnpm lint`, `pnpm docs:check`, package exports
  (11/11), migration/manifest/packing checks (24/24), and `git diff --check`
  passed. The post-documentation diff check and clean-tree result are recorded
  in the final Pass 5 report amendment.
- Manual marker introspection/serialization/redaction, browser-boundary, and
  dependency/license checks found no secret-bearing marker/public/audit data,
  no Node leakage into browser exports, and only the existing exact-pinned MIT
  `argon2@0.44.0` free/self-hostable dependency. No paid/hosted service or
  remote database is required; the excluded scanner was not invoked.

No migration, package manifest, lockfile, repository contract, or dependency
change was required. Migrations `0001`-`0004`, their manifest/checksums, schema
contract, verifier, packing/copy checks, and incremental tests remain unchanged;
no `0005` migration was added.

Pass 5 code/tests are committed as `6f29e9e`. The documentation/status/report
commit is `cef8816b7be463b98ee8e50df7def9bb5d908191`; the Pass 5 final
documentation amendment is `d6762c99d1984143f4da8f317f8163c903c99408`.
The controller escalation-resolution commit is
`113fee45d999c4fead4b0c5c4d3f57ff01474e3d`. The historical
Pass 4 report-only commits `d2a7411` and `03483fd` remain recorded above.

The final Pass 5 reviewer confirmed all mandated and full-suite checks but
escalated one Important same-process concern: an adapter callback could replace
`WeakMap.prototype.get/set` or `WeakSet.prototype.add/has` while the
transaction boundary was active. Because five delegated fix passes were
already exhausted, the controller resolved the escalation directly. The
boundary now captures those methods, plus `Object.create` and `Object.freeze`,
before any adapter executes and never dispatches security-sensitive identity
operations through mutable prototype properties afterward. Direct regressions
replace each affected prototype method and prove the original trusted failure
and fixed adapter marker remain authoritative. The mandated two-file command
passes with 52/52 tests (18 lifecycle, 34 enumeration); full post-resolution
verification also passes frozen install, build, 156/156 tests, typecheck, lint,
docs check, 11/11 package-export checks, 24/24 migration checks, migration
immutability, and `git diff --check`. Same-reviewer confirmation replaced all
four WeakMap/WeakSet methods plus `Object.create` and `Object.freeze`
simultaneously and preserved exact trusted-error identity, fixed adapter-error
classification, frozen null-prototype markers, and secret redaction. Task 6 is
approved.

## Task 3 scope and verification (historical)

Task 3 adds the exact 15-table `auth` schema in three ordered SQL migrations;
Task 4 preserves those three files byte-for-byte and adds the explicit fourth
hardening migration,
the SHA-256 manifest, the transactional/advisory-locked `up` runner, read-only
status and schema verification, and the `migrate status|up|verify` and
read-only `doctor` CLI commands. The built package copies SQL into
`dist/postgres/migrations`, marks the CLI binary executable, and includes those
assets through the package `files` list. The browser entrypoints remain free of
PostgreSQL and migration imports.

The integration suite always starts its own disposable local PostgreSQL cluster
in an OS temporary directory using the available Homebrew binaries and stops
and removes the exact cluster in nested `finally`/`afterAll` paths. Generic
`DATABASE_URL` is deliberately ignored by the fixture; there is no external
database override and no supplied database is mutated.

Task 3 RED evidence: before the migration modules and runner existed,
`pnpm vitest run packages/mrjim-auth/test/integration/migrations.spec.ts`
failed during collection with `Cannot find module
../../src/cli/commands/doctor.js`.

Task 3 Review Fix Pass 1, Pass 2, and Pass 3 GREEN evidence and remaining commands are
appended to `.superpowers/sdd/2026-08-10-mrjim-auth-v1/task-3-report.md`.
Coverage includes
clean naming with the canonical forbidden list, exact typed column/default
inventory, normalized/provider/digest uniqueness and blank rejection, strong
Argon2id and expiry/TTL checks, cascades, deferred inheritance cycles, scoped
assignment uniqueness, recursive database-bound audit redaction and
immutability, checksum/history fail-closed behavior, same-client lock release,
fresh bootstrap races, idempotence, read-only status/verify/doctor, canonical
catalog tamper detection, and a real packed-consumer CLI run. Pass 2 adds the
strict flat audit allowlist and reviewer examples, complete function contract
hashes, all relevant auth catalog relation/type kinds with `hayahai` and
`ayahay` coverage, and per-migration `introducedIn` provenance that remains
valid across package upgrades. Pass 3 adds real partitioned-index coverage for
PostgreSQL `pg_class.relkind = 'I'`; the final full suite is 52/52.

At the Task 3 handoff, remaining work was Tasks 4-14. The current worktree has
since completed Tasks 4 and 5; password hashing, OAuth, authorization
evaluation, HTTP/client surfaces, administration, generated references, and
release-gate coverage remain later tasks. No external blocker was encountered;
local PostgreSQL 16.14 and the free/open-source `pg` dependency were
sufficient.

## Task 2 scope

The Task 2 changes are:

- `packages/mrjim-auth/src/shared/types.ts` — identity-safe `User`,
  `Identity`, `Session`, `Role`, `Permission`, event, metadata, storage, and
  option type foundations;
- `packages/mrjim-auth/src/shared/result.ts` — `AuthResult<T>` and result
  helpers;
- `packages/mrjim-auth/src/shared/errors.ts` — stable error codes, API error
  serialization, and throw-only configuration/programming error classes;
- `packages/mrjim-auth/src/shared/config.ts` — Zod client/server schemas and
  inferred option types;
- `packages/mrjim-auth/src/shared/contracts.ts` — mailer, limiter, key,
  transaction-neutral repository, session, token, authorization, and audit
  boundaries;
- `packages/mrjim-auth/test/unit/shared-contracts.spec.ts` — original 9 focused
  contract tests plus review coverage;
- `packages/mrjim-auth/package.json` and `pnpm-lock.yaml` — exact-pinned
  `zod@4.4.3` dependency;
- `.superpowers/sdd/2026-08-10-mrjim-auth-v1/task-2-report.md` — full handoff
  report.

RED evidence: `pnpm vitest run
packages/mrjim-auth/test/unit/shared-contracts.spec.ts` failed before test
collection because `../../src/shared/result.js` did not exist.

GREEN evidence: the same focused command passed with 1 file and 9 tests;
`pnpm typecheck` passed after implementation.

## Task 2 Review Fix Pass 1

Review Fix Pass 1 is complete and remains limited to Task 2 shared contracts.
The review adds 16 focused tests covering the security and completeness
findings:

- `sanitizeIdentityData` and `safeIdentityDataSchema` now allow only documented
  scalar public claims and remove top-level, camelCase, nested, private-key,
  and provider-token fields from raw claims.
- `PublicAuthErrorCode` is a closed union. Internal/admin-only codes are
  separate and map enumeration-sensitive signup, login, recovery, OTP, resend,
  and lookup outcomes to generic public codes before `AuthResult` creation.
- `authRepositorySchema` requires every Task 2 aggregate/member function and
  rejects `{}` or malformed/missing password, OAuth-state, role, permission,
  and other repository methods.
- `RedactedMetadata`, `redactedMetadataSchema`, and
  `sanitizeRedactedMetadata` recursively remove token, hash, password, OAuth
  code, provider-secret, and private-key metadata from one-time-token and audit
  contracts.
- UUIDs and lowercase keys are branded/validated at runtime; role keys are
  lowercase and permission keys must match `resource.action`, `resource.*`, or
  `*.*`.
- Client base, server base/site, OIDC issuer, and redirect URLs accept only
  `http:`/`https:`; production requires HTTPS for base/site/redirect values and
  redirects remain exact. Signing-key `issuer` and `audience` are required
  non-empty identifiers, not URL-validated fields.

Password credentials, OAuth state, role/permission CRUD, assignment, and audit
repository boundaries are present but explicitly `@internal` and transaction
neutral. They are not package-root exports until their later implementation
tasks. No generated API/OpenAPI artifacts are claimed in this Task 2 status;
those remain Task 13 work.

Review RED evidence: the new focused test run failed with exit code 1 and 7
contract failures before the review implementation. Review GREEN evidence:
the focused run passed with 1 file and 16 tests, and `pnpm typecheck` passed.

## Task 2 Review Fix Pass 2

Review Fix Pass 2 is complete and remains limited to the five reported Task 2
contract regressions:

- `SafeIdentityData` is now a unique-branded output of the strict runtime
  allowlist/sanitizer. `Identity.identity_data` requires that brand, while
  compile-time tests reject structurally untrusted objects without deliberate
  unsafe casts. Identity URL fields are non-empty HTTP(S) URLs and reject
  objectively credential-bearing query/fragment values.
- Redacted metadata now covers case/style variants of OTP and one-time codes,
  verifier/code-verifier/PKCE verifier, cookie/set-cookie, session bearer
  material, authorization codes, and raw bearer links. Safe provider labels and
  justified provider/session/organization IDs remain available.
- All HTTP(S) schemas guard `new URL` after syntactic validation. Malformed
  client, server base/site, redirect, and OIDC values return `success: false`
  without throwing.
- `AuthorizationScope.id` is a branded non-empty `ScopeIdentifier` supporting
  project IDs such as `org_123`; UUID branding remains required for database
  entity IDs.
- Status/report wording distinguishes non-empty signing-key `issuer` and
  `audience` identifiers from HTTP(S)-validated OIDC provider issuer URLs.

No Task 3 work, database object, paid dependency, or generated artifact was
added.

Pass 2 RED evidence: the focused run reported 5 failing tests out of 18, and
`pnpm typecheck` reported the missing scope schema plus two unused compile-time
expectations. Pass 2 GREEN evidence: the focused run passed with 1 file and 18
tests, and `pnpm typecheck` passed.

## Task 2 Review Fix Pass 3

Review Fix Pass 3 is complete and limited to two technical hardenings:

- The exported `safeIdentityDataSchema` and its
  `publicIdentityDataSchema` alias now apply the same detectable-credential
  refinement as `sanitizeIdentityData` before producing the private brand.
  Direct brand-producing calls reject Bearer, JWT, PEM/private-key,
  provider-token, and credential-bearing avatar URL values while strict keys
  and compile-time branding remain enforced.
- Redacted metadata now denies bare normalized `session` keys in nested and
  case/style variants. Explicit `session_id` and `sessionId` keys remain safe
  identifier exceptions under the documented policy; opaque raw session values
  do not survive.

No other approved Task 2 area changed, and no Task 3 work or dependency was
added.

Pass 3 RED evidence: the focused run reported 2 failing tests out of 20
before the two production changes. Pass 3 GREEN evidence: the focused run
passed with 1 file and 20 tests, and `pnpm typecheck` passed.

## Task 1 scope

The Task 1 changes are:

- root `package.json`, `pnpm-workspace.yaml`, `pnpm-lock.yaml`, and `tsconfig.base.json`;
- root `vitest.workspace.ts` and `scripts/check-docs.mjs`;
- `packages/mrjim-auth/package.json` and its browser, Node, and typecheck configs;
- minimal source entrypoints for the browser client, server, PostgreSQL, Express,
  Next.js browser/server, testing, and CLI export targets;
- `packages/mrjim-auth/test/contract/package-exports.spec.ts`;
- this status document and the Task 1 handoff report.

The root `mrjim-auth` export contains only the documented `createClient`
scaffold. Server, PostgreSQL, adapter, testing, and CLI targets use distinct
compiled files but do not expose unfinished functions. The browser build
compiles the root and Next.js browser entry with DOM types and no Node types;
the Node build compiles only the server-side targets.

The contract test imports the built package through its self-reference, checks
every declared export and target, verifies the temporary root example, confirms
later-task subpaths are empty, and bundles the browser entries with esbuild's
browser platform. The bundle test rejects static and literal dynamic imports of
Node built-ins and bare server-only dependencies such as `pg`.

## Final verification evidence

- `pnpm install --frozen-lockfile` — passed; lockfile was up to date.
- `pnpm typecheck` — passed.
- `pnpm build` — passed; browser and Node TypeScript builds completed.
- `pnpm test` — passed; Task 1 contract test passed (1 file, 6 tests), with a
  fresh package build executed by the test script.
- `pnpm vitest run packages/mrjim-auth/test/contract/package-exports.spec.ts` — passed (1 file, 6 tests) after `pnpm build`.
- `pnpm lint` — passed.
- `pnpm docs:check` — passed; 2 required documents found.

Task 2 original final verification before Review Fix Pass 1:

- `pnpm install --frozen-lockfile` — passed; lockfile was up to date.
- `pnpm test` — passed; browser and Node builds completed, 2 files and 15
  tests passed.
- `pnpm typecheck` — passed.
- `pnpm lint` — passed.
- `pnpm docs:check` — passed; 2 required documents found.
- `git diff --check` — passed with no whitespace errors.

Task 2 Review Fix Pass 1 final verification:

- `pnpm vitest run packages/mrjim-auth/test/unit/shared-contracts.spec.ts` —
  passed; 1 file and 16 tests.
- `pnpm build` — passed; browser and Node TypeScript builds completed.
- `pnpm test` — passed; fresh build completed, 2 files and 22 tests passed.
- `pnpm install --frozen-lockfile` — passed; lockfile was up to date and
  resolution was skipped.
- `pnpm typecheck` — passed.
- `pnpm lint` — passed.
- `pnpm docs:check` — passed; 2 required documents found.
- `git diff --check` — passed with no whitespace errors.

Task 2 Review Fix Pass 2 final verification:

- `pnpm vitest run packages/mrjim-auth/test/unit/shared-contracts.spec.ts` —
  passed; 1 file and 18 tests.
- `pnpm build` — passed; browser and Node TypeScript builds completed.
- `pnpm test` — passed; fresh build completed, 2 files and 24 tests passed.
- `pnpm install --frozen-lockfile` — passed; lockfile was up to date and
  resolution was skipped.
- `pnpm typecheck` — passed.
- `pnpm lint` — passed.
- `pnpm docs:check` — passed; 2 required documents found.
- `git diff --check` — passed with no whitespace errors.

Task 2 Review Fix Pass 3 final verification:

- `pnpm vitest run packages/mrjim-auth/test/unit/shared-contracts.spec.ts` —
  passed; 1 file and 20 tests.
- `pnpm build` — passed; browser and Node TypeScript builds completed.
- `pnpm test` — passed; fresh build completed, 2 files and 26 tests passed.
- `pnpm install --frozen-lockfile` — passed; lockfile was up to date and
  resolution was skipped.
- `pnpm typecheck` — passed.
- `pnpm lint` — passed.
- `pnpm docs:check` — passed; 2 required documents found after the final
  Pass 3 status/report edits.
- `git diff --check` — passed with no whitespace errors after the final Pass 3
  status/report edits.

Task 2 self-review found no PostgreSQL, password-hasher, private-key loader,
migration, admin-secret, provider-credential, or Node-only imports in the
shared source. Repository contracts are adapter-neutral and define no database
objects or Hayahai/shipping fields. Full auth behavior remains intentionally
unimplemented for later tasks.

No paid SaaS or hosted service was used or required for these checks.

## Task 7 final verification

- Mandatory RED: `pnpm vitest run packages/mrjim-auth/test/unit/pkce.spec.ts packages/mrjim-auth/test/integration/oauth.spec.ts` failed before implementation with 2 files and 0 tests because the new PKCE/OAuth modules were absent.
- Mandatory GREEN: the same focused command passed with 2 files and 11 tests.
- Provider/export/migration checks: `pnpm vitest run packages/mrjim-auth/test/unit/oauth-providers.spec.ts packages/mrjim-auth/test/contract/package-exports.spec.ts packages/mrjim-auth/test/integration/migrations.spec.ts` passed with 3 files and 40 tests.
- `pnpm test` — passed; 15 files and 173 tests, including a fresh build.
- `pnpm install --frozen-lockfile` — passed; lockfile up to date, resolution skipped.
- `pnpm build` — passed; browser and Node TypeScript builds completed.
- `pnpm typecheck` — passed.
- `pnpm lint` — passed.
- `pnpm docs:check` — passed; 2 required documents found.
- `git diff --check` — passed with no whitespace errors.
