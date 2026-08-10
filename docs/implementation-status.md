# mrjim-auth Implementation Status

**Plan:** `docs/superpowers/plans/2026-08-10-mrjim-auth-v1.md`  
**Branch:** `feat/mrjim-auth-v1`  
**Last updated:** 2026-08-10

## Current state

Planning and worktree setup are complete. Implementation has not started.

## Required dependency policy

- Required runtime, build, test, documentation, and release dependencies must be free/open-source.
- The SDK must run on project-owned Node.js and PostgreSQL infrastructure.
- Google OAuth, SMTP, and other external integrations are adapters configured by each project; no paid plan is required by `mrjim-auth`.
- A paid SaaS product must never be required to build, test, document, deploy, or operate the core package.

## Task progress

| Task | Status | Verification |
| --- | --- | --- |
| 1. Workspace and exports | Pending | Not run |
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

No blockers identified.

## Remaining work

Execute Tasks 1-14 with an implementation subagent and independent review after each task, then complete the whole-branch review and release handoff.
