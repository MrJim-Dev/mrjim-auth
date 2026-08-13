# PostgreSQL schema reference

`mrjim-auth/postgres` supplies a project-owned PostgreSQL 15+ schema under the
clean `auth` namespace. The schema is generic authentication and authorization
infrastructure: it contains no package-brand, shipping, or Hayahai domain
columns. Applications can add their own tables and foreign keys outside the
auth contract.

## Migration API

The package ships six ordered SQL files. Importing the package, constructing a
repository, or creating an `AuthServer` does not change the database.

```ts compile
import {
  migrate,
  migrationStatus,
  verifySchema,
  MIGRATIONS,
} from "mrjim-auth/postgres";

declare const pool: Parameters<typeof migrate>[0];

async function example(): Promise<void> {
  const applied = await migrate(pool, { direction: "up" });
  const status = await migrationStatus(pool);
  const verification = await verifySchema(pool);
  console.log(MIGRATIONS.length, applied.applied, status.length, verification.ok);
}

void example();
```

`migrate` supports only `{ direction: "up" }`. It acquires the
`auth.schema_migrations` advisory lock, validates the recorded history, and
applies each pending file in its own transaction. There is no automatic
startup migration, baseline command, or rollback/down operation in v1.

| Order | File | Contents |
| ---: | --- | --- |
| 1 | `0001_core.sql` | `pgcrypto`, migration bookkeeping, users, identities, password credentials, sessions, refresh tokens, and one-time tokens. |
| 2 | `0002_authorization.sql` | Roles, permissions, role-permission joins, role inheritance with deferred cycle protection, and scoped user-role assignments. |
| 3 | `0003_oauth_operations.sql` | OAuth state, API keys, redacted immutable audit log, and audit metadata validator. |
| 4 | `0004_repository_hardening.sql` | One-time-token metadata redaction and exact OAuth flow constraint (`sign_in` or `link_identity`). |
| 5 | `0005_oauth_callback.sql` | `oauth_callback` one-time-token purpose with a maximum 60-second lifetime. |
| 6 | `0006_admin_operations.sql` | API-key names, dotted permission resources, admin/audit indexes, and durable rate-limit buckets. |
| 7 | `0007_legacy_bcrypt_passwords.sql` | Transitional bcrypt password verification and constraint support; successful login rehashes to Argon2id. |

Every manifest entry exposes `migrationOrder`, `version`, `fileName`, `sql`,
`checksum`, and `introducedIn`. Checksums are SHA-256 of the packaged SQL.
Applied rows retain the package introduction version and are rejected when
history is unknown, duplicated, gapped, out of order, or tampered with.

## Required objects

The required `auth` tables are:

```text
schema_migrations
users
identities
password_credentials
sessions
refresh_tokens
one_time_tokens
oauth_states
roles
permissions
role_permissions
role_inheritance
user_roles
api_keys
audit_log
rate_limit_buckets
```

`schema_migrations` is package bookkeeping. The remaining tables are the
runtime auth model. The SQL uses UUID primary keys, `timestamptz` lifecycle
fields, JSONB objects for constrained metadata, and foreign keys within the
`auth` schema.

## Tables and relationships

### Accounts and credentials

- `auth.users` stores `id`, email/phone and normalized lookup values,
  confirmation timestamps, `last_sign_in_at`, `banned_until`, user/app JSONB
  metadata, lifecycle timestamps, and nullable `deleted_at`. Normalized email
  and phone values have partial unique indexes. Deletion is soft at the service
  boundary and cascades only where the database relationship requires it.
- `auth.identities` links a user to a lowercase provider and provider subject,
  optional email values, safe provider profile data, and timestamps. The pair
  `(provider, provider_subject)` is unique.
- `auth.password_credentials` stores one Argon2id password hash per user and
  its update time. Raw passwords are never stored.
- `auth.sessions` stores the user, assurance level (`aal` 1–3), optional
  network/user-agent context, creation/refresh/expiry timestamps, and
  revocation. `auth.refresh_tokens` stores only a 32-byte digest plus family,
  parent/replacement lineage, use/expiry, and revocation state.
- `auth.one_time_tokens` stores purpose-bound token digests for signup, email
  change, recovery, magic link, email OTP, invite, and OAuth callback flows.
  Attempt counts, redirects, metadata, expiry, and consumption are constrained.

Relationships are `users -> identities`, `password_credentials`, `sessions`,
and `one_time_tokens`; `sessions -> refresh_tokens`; and all user-owned rows
are scoped by foreign keys. Repository rotation and token consumption require
transactions so a concurrent caller cannot consume or rotate the same proof.

### OAuth and operations

- `auth.oauth_states` binds a provider, `sign_in`/`link_identity` flow, PKCE
  challenge, optional encrypted verifier, exact redirect, optional linking
  user, and a short expiry. State hashes are 32-byte digests and state rows are
  single-use.
- `auth.api_keys` stores a prefix/name, a 32-byte key digest, kind
  (`publishable` or `secret`), scopes, last-use/expiry/revocation timestamps,
  and creation time. Raw key material is written once by the key-generation
  command and is not recoverable from the database.
- `auth.audit_log` stores actor user/key/session IDs, action and target fields,
  request context, safe metadata, outcome, and occurrence time. Rows are
  immutable; metadata is flat, allowlisted, bounded, recursively checked, and
  rejects credential-like strings.
- `auth.rate_limit_buckets` stores a digest-keyed bucket and window counters
  for a durable PostgreSQL rate limiter. It is optional at runtime but part of
  the verified schema.

### Dynamic roles and permissions

- `auth.roles` has a unique lowercase `key`, name, description, non-negative
  administrative `rank`, and `is_system` protection flag. Rank controls
  administrative policy; it does not itself grant an application permission.
- `auth.permissions` has a unique lowercase `key` equal to
  `resource.action`, with separate `resource`, `action`, and description
  fields. v1 supports exact permissions, `resource.*`, and `*.*`; it has no
  explicit deny rows.
- `auth.role_permissions` connects roles to permissions.
- `auth.role_inheritance` connects a role to roles it inherits. A deferred
  trigger rejects cycles.
- `auth.user_roles` assigns a role globally or to a `(scope_type, scope_id)`
  pair, with optional assigning user and expiry. Both global and scoped
  assignments have separate uniqueness indexes.

The server calculates effective permissions from direct and inherited roles,
scope, and expiry. The database and server both protect role mutations with
stable lock ordering and policy checks.

## PostgreSQL adapter

```ts compile
import { createPostgresAdapter } from "mrjim-auth/postgres";

const repository = createPostgresAdapter({
  connectionString: process.env.DATABASE_URL!,
});

async function example(): Promise<void> {
  await repository.transaction(async (transaction) => {
    const user = await transaction.users.findByNormalizedEmail("user@example.com");
    if (user !== null) console.log(user.id);
  });

  await repository.close();
}

void example();
```

`createPostgresAdapter` accepts exactly one caller-owned `pg.Pool` or a
connection string. It uses parameterized Kysely/PostgreSQL queries and
qualifies auth tables. `close()` ends only a pool created from the connection
string; a caller-owned pool remains the caller's responsibility.

The complete adapter exposes user, identity, password, session, one-time-token,
OAuth-state, authorization, role, permission, operations, and admin
repositories. `transaction(callback)` passes a transaction-scoped aggregate;
the callback's rejection rolls back. Migration and schema verification are
explicit operations and must be run by deployment tooling.

## Invariants and upgrade rules

- Password hashes must be Argon2id v=19 with at least `m=65536,t=3,p=1`.
- Recovery proofs expire within 15 minutes; signup proofs within 24 hours;
  OAuth state within 10 minutes; OAuth callback proofs within 60 seconds.
- Refresh-token, session, role-inheritance, and one-time-token mutations are
  transactionally serialized and preserve lineage/cycle invariants.
- Foreign keys and unique indexes enforce identity, normalized-contact,
  assignment, and key uniqueness.
- The migration manifest is append-only. A future package release should add a
  new ordered SQL file and checksum; it must not rewrite an applied file.

The schema can be self-hosted with PostgreSQL 15 or newer. No paid database,
hosted auth vendor, Docker service, or external migration service is required.
