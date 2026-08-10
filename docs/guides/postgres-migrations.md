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

The migration manifest is authoritative: callers cannot inject another SQL
manifest or package version. Each applied row records its positive
`migration_order`, version, SHA-256 checksum, applied timestamp, and package
version. The runner rejects unknown, duplicate, gapped, and out-of-order
history before writing.

The only application schema created is `auth`, with these 15 tables:

```text
users, identities, password_credentials, sessions, refresh_tokens,
one_time_tokens, oauth_states, roles, permissions, role_permissions,
role_inheritance, user_roles, api_keys, audit_log, schema_migrations
```

No default roles or permissions are inserted. A project owns its own seed data.

The verifier checks column PostgreSQL types/UDTs, nullability and critical
defaults, full index definitions and predicates, constraint expressions and
foreign-key actions, function properties, and enabled trigger definitions.
The canonical forbidden-name list for auth tables, columns, indexes,
constraints, functions, and non-internal triggers is:

```text
mrjim, shipping, tenant, passenger, port, vessel, cabin, tms, marketplace
```

Audit metadata is enforced at the database boundary. Recursive nested/case/
style variants of passwords, hashes, bearer/JWT material, reset or OTP codes,
OAuth authorization codes/verifiers, provider tokens/secrets,
cookies/sessions, and private keys are rejected by both a JSONB check and a
before-insert trigger. Audit rows remain immutable.

Database-bound invariants also require Argon2id v=19 with at least
`m=65536,t=3,p=1`, expiry after issued/created timestamps, recovery tokens at
most 15 minutes, signup tokens at most 24 hours, and OAuth state at most 10
minutes. Stronger Argon2id parameters remain valid.

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

Integration tests always create and destroy their own local PostgreSQL cluster
in an OS temporary directory; generic `DATABASE_URL` is ignored by the test
fixture. The packed-install test runs `pnpm pack`, installs that tarball into
a temporary consumer, and executes the installed `node_modules/.bin/mrjim-auth`
against the disposable database.
