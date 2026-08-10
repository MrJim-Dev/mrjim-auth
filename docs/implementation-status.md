# mrjim-auth Implementation Status

**Plan:** `docs/superpowers/plans/2026-08-10-mrjim-auth-v1.md`  
**Branch:** `feat/mrjim-auth-v1`  
**Last updated:** 2026-08-10

## Current state

Task 1 is complete in this worktree. The package workspace, strict ESM
TypeScript configuration, browser-safe public entrypoint, Node-only entrypoints,
export map, local verification commands, and Task 1 handoff report are present.
The published package manifest is named exactly `mrjim-auth`.

Task 1 does not implement authentication behavior or create database objects.
The future PostgreSQL work must create only the clean `auth` schema; no `mrjim`
objects or Hayahai/shipping business fields have been added here.

## Required dependency policy

- Required runtime, build, test, documentation, and release dependencies must be free/open-source.
- The SDK must run on project-owned Node.js and PostgreSQL infrastructure.
- Google OAuth, SMTP, and other external integrations are adapters configured by each project; no paid plan is required by `mrjim-auth`.
- A paid SaaS product must never be required to build, test, document, deploy, or operate the core package.

Task 1 has no runtime dependencies. Its local development dependencies are
`@types/node`, TypeScript, and Vitest.

## Task progress

| Task | Status | Verification |
| --- | --- | --- |
| 1. Workspace and exports | Complete | Final Task 1 checks passed on 2026-08-10 |
| 2. Shared contracts | Pending | Not run |
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

There is no external blocker for Task 1. Release and later feature work remain
blocked by the intentionally pending Tasks 2-14; this handoff does not start
those tasks.

## Remaining work

Execute Tasks 2-14 with independent review after each task, then complete the
whole-branch review and release handoff. In particular, later work must define
the `{ data, error }` result contract, implement the clean `auth` PostgreSQL
schema and explicit migration CLI, and prove that browser bundles cannot reach
Node/server modules.

## Task 1 scope

The Task 1 changes are:

- root `package.json`, `pnpm-workspace.yaml`, `pnpm-lock.yaml`, and `tsconfig.base.json`;
- root `vitest.workspace.ts` and `scripts/check-docs.mjs`;
- `packages/mrjim-auth/package.json` and its browser, Node, and typecheck configs;
- minimal source entrypoints for the browser client, server, PostgreSQL, Express,
  Next.js browser/server, testing, and CLI export targets;
- `packages/mrjim-auth/test/contract/package-exports.spec.ts`;
- this status document and the Task 1 handoff report.

The root `mrjim-auth` export contains only the browser client entry. Server,
PostgreSQL, adapter, testing, and CLI targets use distinct compiled files.
The browser build compiles the root and Next.js browser entry with DOM types and
no Node types; the Node build compiles only the server-side targets.

## Final verification evidence

- `pnpm install --frozen-lockfile` — passed; lockfile was up to date.
- `pnpm typecheck` — passed.
- `pnpm build` — passed; browser and Node TypeScript builds completed.
- `pnpm test` — passed; Task 1 contract test passed (1 file, 1 test).
- `pnpm vitest run packages/mrjim-auth/test/contract/package-exports.spec.ts` — passed (1 file, 1 test).
- `pnpm lint` — passed.
- `pnpm docs:check` — passed; 2 required documents found.

No paid SaaS or hosted service was used or required for these checks.
