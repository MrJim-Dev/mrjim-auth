# Architecture

mrjim-auth separates a browser-safe client from a project-owned trust boundary.

```text
Browser / mobile web
  createClient(...).auth
          |
          | HTTPS /auth/v1
          v
Project Node.js process
  AuthServer + framework adapter
  password, token, session, OAuth, authorization services
          |
          | parameterized transactions
          v
Project PostgreSQL database
  auth schema
```

The browser owns PKCE verifiers and local session persistence. It never receives
database credentials, OAuth client secrets, signing keys, admin API keys, or
refresh-token digests. Browser permission data is useful for navigation only.

The Node.js process validates configuration synchronously, parses strict HTTP
contracts, applies rate limits, verifies passwords and proofs, rotates sessions,
signs access tokens, enforces authorization, and writes immutable audit events.
The Fetch-native `AuthServer.handle(Request)` boundary makes framework adapters
small and testable.

PostgreSQL is authoritative for users, identities, credentials, sessions,
one-time proofs, OAuth state, roles, permissions, assignments, API keys,
rate-limit buckets, audits, and migration history. Sensitive reusable values are
stored as digests or encrypted material where the protocol requires recovery.

## Project ownership

Every application has its own backend and database. The package supplies schema
and behavior but does not operate a control plane. There is no global mrjim-auth
tenant, user directory, or vendor account. Cross-project SSO is possible only if
you deliberately build and operate that shared identity boundary.

## Replaceable edges

Mail delivery and rate limiting are interfaces. Use project SMTP and the bundled
PostgreSQL limiter for a completely self-hosted deployment. Google OAuth and OIDC
talk directly to the configured provider; no paid broker is required.

## Failure model

Expected HTTP/auth failures use stable public codes and `{ data, error }`.
Configuration and programming errors throw. Security-sensitive mutations use
database transactions and row locks. Unknown, malformed, or ambiguous boundary
data fails closed and responses are non-cacheable.
