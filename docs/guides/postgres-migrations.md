# PostgreSQL schema and migration CLI

Task 3 installs a project-owned PostgreSQL 15+ authentication schema. The
database is changed only by an explicit migration command; importing the
package or starting an application does not run migrations.

## Apply and inspect migrations

Set `DATABASE_URL` to the project database, then run the commands from the
installed package:

```sh
mrjim-auth migrate status
mrjim-auth migrate up
mrjim-auth migrate verify
```

`status` and `verify` are read-only. `up` takes a session-scoped advisory lock,
checks every recorded SHA-256 checksum, and applies each pending SQL file in
its own transaction. There is no baseline down or rollback command in v1.

The package contains the SQL files in its built and packed `dist` output:

- `0001_core.sql` — `pgcrypto`, migration bookkeeping, users, identities,
  password credentials, sessions, refresh tokens, and one-time tokens;
- `0002_authorization.sql` — roles, permissions, joins, inheritance cycle
  prevention, and scoped user-role assignments;
- `0003_oauth_operations.sql` — OAuth state, API keys, and immutable audit
  records.

The only application schema created is `auth`, with these 15 tables:

```text
users, identities, password_credentials, sessions, refresh_tokens,
one_time_tokens, oauth_states, roles, permissions, role_permissions,
role_inheritance, user_roles, api_keys, audit_log, schema_migrations
```

No default roles or permissions are inserted. A project owns its own seed data.

## Doctor

`mrjim-auth doctor` performs read-only checks for `DATABASE_URL`, PostgreSQL
15+, `pgcrypto`, migration state, and the minimum 32-byte
`AUTH_TOKEN_HASH_KEY` and `AUTH_ENCRYPTION_KEY` values. In production it also
requires `AUTH_BASE_URL`, `AUTH_SITE_URL`, and any
`AUTH_ALLOWED_REDIRECTS` to be HTTPS URLs. It reports check names and boolean
outcomes, never secret values.

The schema stores only token digests, not raw bearer values. Role inheritance
cycles are rejected by a deferred database constraint trigger, scoped role
assignments have separate global/scoped uniqueness keys, and audit rows reject
both updates and deletes.
