# Security and production checklist

mrjim-auth provides security boundaries, but the installing project owns the
deployment, keys, database, email, monitoring, backups, and incident response.

## Secrets and keys

- Keep database URLs, private signing keys, OAuth client secrets, token-hash
  keys, encryption keys, and admin API keys server-only.
- Generate token-hash and encryption keys from at least 32 random bytes.
- Use ES256 signing keys with stable key IDs. Publish verification keys through
  JWKS and retain old public keys until issued access tokens expire.
- API keys are shown once; only domain-separated HMAC digests are stored.
- Never put secrets in source control, browser bundles, URLs, logs, metrics,
  audit metadata, exception messages, or analytics tools.

## HTTP and browser

- Use HTTPS for every production URL and redirect.
- Mount the server at the configured base path and use exact origin/redirect
  allowlists. Wildcard redirects are rejected.
- Configure Express proxy trust only when the exact proxy hop count is known.
- Keep security headers from the auth response; do not weaken `no-store`.
- Treat `getSession()` and browser permissions as advisory. Authorize with
  backend-validated `getUser()`, JWT/session verification, and database-backed
  permission enforcement.
- Use CSRF-aware same-site deployment and the secure cookie adapter for SSR.

## Database and migrations

- Give the runtime database role only the privileges it needs. Restrict direct
  access to `auth` tables from application users.
- Run `migrate status`, `migrate up`, and `migrate verify` in a controlled
  release step, never implicitly on every server start.
- Fail deployment on checksum drift or unexpected migration history.
- Back up before upgrade and rehearse restore plus forward migration.
- Protect database logs and query telemetry from credentials and proofs.

## Abuse controls

- Use `PostgresRateLimiter` for horizontally scaled deployments; the in-memory
  limiter is process-local and intended for single-process development/tests.
- Keep separate buckets for signup, login IP, login identifier, recovery,
  resend, OTP issue/verify, OAuth start, and admin mutation.
- Preserve bounded `Retry-After` responses and add edge limits appropriate to
  your application without exposing account existence.

## Email and OAuth

- Render known template names only and avoid logging template variables.
- Make one-time links short-lived, purpose-bound, single-use, and exact-redirect
  bound; the built-in services enforce these properties.
- Register only the exact Google/OIDC callback URLs you operate.
- Monitor provider failures using stable categories; do not expose upstream
  tokens or protocol details to clients.

## Operations

- Alert on unusual login/recovery/admin rates and repeated refresh replay.
- Retain immutable, redacted audit records according to project policy.
- Correlate incidents with request IDs and actor/session identifiers, not raw
  credentials.
- Test revocation, key rotation, recovery, database outage, mail failure, and
  rate-limit behavior before production.
- Pin and audit package versions; run the release verification suite on every
  upgrade.

## Reporting a vulnerability

Do not open a public issue containing credentials, proofs, exploit payloads, or
private user data. Contact the project maintainer through its private security
channel and include the affected version, impact, and a minimal redacted
reproduction.
