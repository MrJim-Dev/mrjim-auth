# mrjim-auth Implementation Status

**Plan:** `docs/superpowers/plans/2026-08-10-mrjim-auth-v1.md`  
**Branch:** `feat/mrjim-auth-v1`  
**Last updated:** 2026-08-11

## Current state

Task 1, Review Fix Pass 1, and Task 2 are complete in this worktree. The
package workspace, strict ESM TypeScript configuration, browser-safe public
entrypoint, Node-only build targets, export map, shared auth contracts,
validated Zod configuration, local verification commands, and handoff reports
are present. The published package manifest is named exactly `mrjim-auth`.

Task 2 defines the browser-safe result, error, identity, session, role,
permission, client-option, server-option, adapter, mailer, limiter, and key
provider contracts. Expected API failures use mutually exclusive `{ data,
error }` values; configuration and programming failures remain throw-based.
Production URL, PKCE, TTL, redirect, issuer/audience, and key-material rules
are validated by Zod 4.4.3. No database, password hashing, migration, OAuth
provider credential, or Node-only implementation was added.

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
| 2. Shared contracts | Complete | RED/GREEN unit tests, build, typecheck, lint, docs, and frozen-lockfile checks passed on 2026-08-11 |
| 3. PostgreSQL schema and CLI | Pending | Not run |
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

There is no external blocker for Task 2. Tasks 3-14 remain intentionally
pending; this handoff does not start database migrations, repositories, auth
flows, OAuth, authorization enforcement, HTTP routes, clients, adapters,
administration, or release documentation.

## Remaining work

Execute Tasks 3-14 with independent review after each task, then complete the
whole-branch review and release handoff. In particular, later work must use
these shared contracts to implement the clean `auth` PostgreSQL schema and
explicit migration CLI, auth/session/OAuth/RBAC behavior, HTTP and browser/SSR
surfaces, administration, examples, and release verification.

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
- `packages/mrjim-auth/test/unit/shared-contracts.spec.ts` — 9 focused
  contract tests;
- `packages/mrjim-auth/package.json` and `pnpm-lock.yaml` — exact-pinned
  `zod@4.4.3` dependency;
- `.superpowers/sdd/2026-08-10-mrjim-auth-v1/task-2-report.md` — full handoff
  report.

RED evidence: `pnpm vitest run
packages/mrjim-auth/test/unit/shared-contracts.spec.ts` failed before test
collection because `../../src/shared/result.js` did not exist.

GREEN evidence: the same focused command passed with 1 file and 9 tests;
`pnpm typecheck` passed after implementation.

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

Task 2 final verification:

- `pnpm install --frozen-lockfile` — passed; lockfile was up to date.
- `pnpm test` — passed; browser and Node builds completed, 2 files and 15
  tests passed.
- `pnpm typecheck` — passed.
- `pnpm lint` — passed.
- `pnpm docs:check` — passed; 2 required documents found.
- `git diff --check` — passed with no whitespace errors.

Task 2 self-review found no PostgreSQL, password-hasher, private-key loader,
migration, admin-secret, provider-credential, or Node-only imports in the
shared source. Repository contracts are adapter-neutral and define no database
objects or Hayahai/shipping fields. Full auth behavior remains intentionally
unimplemented for later tasks.

No paid SaaS or hosted service was used or required for these checks.
