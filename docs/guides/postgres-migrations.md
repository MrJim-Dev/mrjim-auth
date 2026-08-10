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
manifest or package version. Each immutable manifest entry has an
`introducedIn` release (currently `0.1.0`). Each applied row records its
positive `migration_order`, version, SHA-256 checksum, applied timestamp, and
that migration's own introduction version. A later package release does not
invalidate older rows; tampering with a row's provenance does. The runner
rejects unknown, duplicate, gapped, and out-of-order history before writing.

The only application schema created is `auth`, with these 15 tables:

```text
users, identities, password_credentials, sessions, refresh_tokens,
one_time_tokens, oauth_states, roles, permissions, role_permissions,
role_inheritance, user_roles, api_keys, audit_log, schema_migrations
```

No default roles or permissions are inserted. A project owns its own seed data.

The verifier checks column PostgreSQL types/UDTs, nullability and critical
defaults, full index definitions and predicates, constraint expressions and
foreign-key actions, complete function signatures/properties/configuration and
normalized body hashes, and enabled trigger definitions. It inspects every
relevant `pg_class` relation kind (tables, partitioned tables, indexes,
sequences, views, materialized views, composite relations, and foreign
tables), plus columns, constraints, functions, types, and non-internal
triggers. The canonical forbidden-name list is:

```text
mrjim, shipping, tenant, passenger, port, vessel, cabin, tms, marketplace, hayahai, ayahay
```

Audit metadata is enforced at the database boundary by a deterministic
recursive SQL validator, a JSONB check, and a before-insert trigger. V1 accepts
only this flat, exact-key allowlist; unknown keys fail even when their values
look harmless:

- bounded enum-like strings: `event` and `reason` (`[a-z][a-z0-9_.:-]{0,63}`),
  `error_code` (`[A-Za-z][A-Za-z0-9_.:-]{0,63}`), `operation`
  (`[a-z][a-z0-9_.:-]{0,63}`), `provider`
  (`[a-z][a-z0-9_.:-]{0,31}`), and `status`
  (`[a-z][a-z0-9_.:-]{0,31}`);
- UUID identifier strings: `user_id`, `session_id`, `api_key_id`, and
  `target_id`; `request_id` is a bounded `[A-Za-z0-9][A-Za-z0-9_-]{0,127}`
  identifier;
- booleans: `success`, `changed`, and `dry_run`;
- non-negative bounded integers from 0 through 1,000,000: `count`,
  `attempt_count`, and `rank`;
- `changed_fields`, an array of at most 32 lowercase field names, each at most
  64 characters.

No arbitrary nested object is accepted; the only array shape is the documented
flat `changed_fields` string array. String values are also rejected when they
look like bearer/basic credentials, JWTs, PEM/private keys, credential-bearing
URLs, Argon2/bcrypt/scrypt/PBKDF2 hashes, long hex digests, or common
secret-like prefixes. Actor, target, session, and API-key identifiers belong
in dedicated columns or the explicitly safe `*_id` keys above. Audit rows
remain immutable.

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

## PostgreSQL repository adapter

Task 4 adds the complete internal repository aggregate behind the PostgreSQL
subpath:

```ts
import { createPostgresAdapter } from "mrjim-auth/postgres";

const repository = createPostgresAdapter({ connectionString });
await repository.transaction(async (transaction) => {
  const user = await transaction.users.create({ email: "user@example.com" });
  await transaction.passwordCredentials.upsert(user.id, passwordHash);
});
await repository.close();
```

`createPostgresAdapter` accepts exactly one of a caller-owned `pg.Pool` or a
connection string. It uses the exact-pinned, free/open-source `kysely` package
with `PostgresDialect`, qualifies all statements to the `auth` schema, uses
explicit column lists, and parameterizes values. Construction never runs
migrations; call `migrate(pool, { direction: "up" })` explicitly first.

The returned `transaction(callback)` aggregate is bound to one PostgreSQL
transaction. A callback rejection rolls back all writes. `sessions.findRefreshForUpdate`
throws an adapter `transaction_required` error outside that scope because a
row lock returned after autocommit would be an unsafe lock illusion. Refresh
rotation and protected role/relationship changes wrap themselves in an atomic
transaction when called on the root aggregate. One-time-token and OAuth-state
consumption use one conditional `UPDATE ... RETURNING` statement, so only one
concurrent caller can consume a matching, unexpired, unconsumed, under-attempt
record.

The database remains authoritative for normalized-email uniqueness. The
`users_email_normalized_key` violation maps to the internal `email_exists`
adapter error; unrelated PostgreSQL errors, including JSON, foreign-key, and
deferred role-cycle constraints, are preserved. Refresh rows retain their
family, parent, replacement, used, expiry, and revocation invariants. Replay
response policy is intentionally deferred to Task 5.

Repository reads map snake_case rows to the shared Supabase-shaped user,
identity, role, permission, session, and internal credential records. Public
identity mapping validates the safe scalar identity allowlist and never
returns password hashes, provider access tokens, refresh tokens, or raw key
values. `appendAudit` accepts the branded redacted metadata contract while
the Task 3 database validator and immutable triggers remain defense in depth.

For lifecycle ownership, `close()` is idempotent and ends only a pool created
from `connectionString`; it is a no-op for a caller-supplied pool, which the
caller must close. No hosted database, paid service, Docker container, or
automatic startup migration is required.
