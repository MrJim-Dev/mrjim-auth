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
server, PostgreSQL, adapter, Next.js server, and testing subpaths remain
loadable export-map targets but intentionally expose no unfinished public
functions until their later tasks implement them.

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

## Task progress

| Task | Status | Verification |
| --- | --- | --- |
| 1. Workspace and exports | Complete | Review Fix Pass 2 checks passed on 2026-08-11 |
| 2. Shared contracts | Complete — Review Fix Pass 3 | Review RED/GREEN tests, full suite, build, typecheck, lint, docs, frozen-lockfile, and diff checks passed on 2026-08-11 |
| 3. PostgreSQL schema and CLI | Complete — Review Fix Pass 3 | Review RED/GREEN integration, canonical catalog verification, packed-install CLI, full suite (52 tests), build, typecheck, lint, docs, frozen-install, and diff checks recorded in Task 3 report |
| 4. PostgreSQL repositories | Pending | Not run |
| 5. JWT and sessions | Pending | Not run |
| 6. Users and recovery | Pending | Not run |
| 7. OAuth and identities | Pending | Not run |
| 8. Dynamic authorization | Pending | Not run |
| 9. HTTP and OpenAPI | Pending | Not run |
| 10. Browser client | Pending | Not run |
| 11. Express and Next.js | Pending | Not run |
| 12. Administration controls | Pending | Not run |
| 13. Documentation and examples | Pending | Not run |
| 14. Release verification | Pending | Not run |

## Blockers

There is no external blocker for Task 3. Task 3 deliberately does not start
repositories, auth flows, OAuth exchanges, authorization enforcement, HTTP
routes, clients, adapters, administration, or the broader Task 13 documentation
surface.

## Remaining work

Execute Tasks 4-14 with independent review after each task, then complete the
whole-branch review and release handoff. In particular, later work must use
the clean `auth` schema and explicit migration CLI from Task 3 to implement
auth/session/OAuth/RBAC behavior, HTTP and browser/SSR surfaces,
administration, examples, and release verification.

## Task 3 scope and verification

Task 3 adds the exact 15-table `auth` schema in three ordered SQL migrations,
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

Remaining work is Tasks 4-14. PostgreSQL repository behavior, password hashing,
session rotation, OAuth, authorization evaluation, HTTP/client surfaces,
administration, generated references, and release-gate coverage are not part of
Task 3. No external blocker was encountered; local PostgreSQL 16.14 and the
free/open-source `pg` dependency were sufficient.

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
