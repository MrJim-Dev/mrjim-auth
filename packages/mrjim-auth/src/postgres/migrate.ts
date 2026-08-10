import type { Pool, PoolClient } from "pg";
import {
  MIGRATIONS,
  PACKAGE_VERSION,
  type MigrationDefinition,
} from "./manifest.js";

const minimumPostgresVersion = 150000;
const advisoryLockSql = "hashtext('auth.schema_migrations')";

export const REQUIRED_TABLES = [
  "users",
  "identities",
  "password_credentials",
  "sessions",
  "refresh_tokens",
  "one_time_tokens",
  "oauth_states",
  "roles",
  "permissions",
  "role_permissions",
  "role_inheritance",
  "user_roles",
  "api_keys",
  "audit_log",
  "schema_migrations",
] as const;

const requiredColumns: Readonly<Record<(typeof REQUIRED_TABLES)[number], readonly string[]>> = {
  users: [
    "id",
    "email",
    "email_normalized",
    "phone",
    "phone_normalized",
    "email_confirmed_at",
    "phone_confirmed_at",
    "last_sign_in_at",
    "banned_until",
    "user_metadata",
    "app_metadata",
    "created_at",
    "updated_at",
    "deleted_at",
  ],
  identities: [
    "id",
    "user_id",
    "provider",
    "provider_subject",
    "email",
    "email_normalized",
    "identity_data",
    "created_at",
    "updated_at",
  ],
  password_credentials: ["user_id", "password_hash", "password_updated_at"],
  sessions: [
    "id",
    "user_id",
    "aal",
    "ip_address",
    "user_agent",
    "created_at",
    "refreshed_at",
    "expires_at",
    "revoked_at",
  ],
  refresh_tokens: [
    "id",
    "session_id",
    "token_hash",
    "family_id",
    "parent_id",
    "replacement_id",
    "issued_at",
    "used_at",
    "expires_at",
    "revoked_at",
  ],
  one_time_tokens: [
    "id",
    "user_id",
    "purpose",
    "token_hash",
    "target",
    "redirect",
    "metadata",
    "attempt_count",
    "expires_at",
    "consumed_at",
  ],
  oauth_states: [
    "id",
    "state_hash",
    "provider",
    "flow",
    "pkce_challenge",
    "encrypted_verifier",
    "redirect_target",
    "linking_user_id",
    "expires_at",
    "consumed_at",
    "created_at",
  ],
  roles: ["id", "key", "name", "description", "rank", "is_system", "created_at", "updated_at"],
  permissions: [
    "id",
    "key",
    "resource",
    "action",
    "description",
    "created_at",
    "updated_at",
  ],
  role_permissions: ["role_id", "permission_id"],
  role_inheritance: ["role_id", "inherits_role_id"],
  user_roles: [
    "user_id",
    "role_id",
    "scope_type",
    "scope_id",
    "assigned_by",
    "assigned_at",
    "expires_at",
  ],
  api_keys: [
    "id",
    "prefix",
    "key_hash",
    "kind",
    "scopes",
    "last_used_at",
    "expires_at",
    "revoked_at",
    "created_at",
  ],
  audit_log: [
    "id",
    "actor_user_id",
    "actor_key_id",
    "actor_session_id",
    "action",
    "target_type",
    "target_id",
    "ip_address",
    "user_agent",
    "metadata",
    "outcome",
    "occurred_at",
  ],
  schema_migrations: ["version", "checksum", "applied_at", "package_version"],
};

const requiredIndexes = [
  "users_email_normalized_key",
  "users_phone_normalized_key",
  "identities_provider_subject_key",
  "refresh_tokens_token_hash_key",
  "one_time_tokens_token_hash_key",
  "roles_key_unique",
  "permissions_key_unique",
  "user_roles_global_key",
  "user_roles_scoped_key",
  "oauth_states_state_hash_key",
  "api_keys_key_hash_key",
  "api_keys_prefix_key",
] as const;

const requiredConstraints = [
  "schema_migrations_pkey",
  "schema_migrations_version_check",
  "schema_migrations_checksum_check",
  "schema_migrations_package_version_check",
  "users_pkey",
  "users_user_metadata_object_check",
  "users_app_metadata_object_check",
  "users_email_normalized_check",
  "users_phone_normalized_check",
  "identities_pkey",
  "identities_provider_check",
  "identities_provider_subject_check",
  "identities_email_normalized_check",
  "identities_identity_data_object_check",
  "identities_user_id_fkey",
  "identities_provider_subject_key",
  "password_credentials_pkey",
  "password_credentials_hash_check",
  "password_credentials_user_id_fkey",
  "sessions_pkey",
  "sessions_aal_check",
  "sessions_user_id_fkey",
  "refresh_tokens_pkey",
  "refresh_tokens_token_hash_length_check",
  "refresh_tokens_parent_check",
  "refresh_tokens_replacement_check",
  "refresh_tokens_session_id_fkey",
  "refresh_tokens_parent_id_fkey",
  "refresh_tokens_replacement_id_fkey",
  "refresh_tokens_token_hash_key",
  "one_time_tokens_pkey",
  "one_time_tokens_purpose_check",
  "one_time_tokens_token_hash_length_check",
  "one_time_tokens_target_check",
  "one_time_tokens_attempt_count_check",
  "one_time_tokens_metadata_object_check",
  "one_time_tokens_user_id_fkey",
  "one_time_tokens_token_hash_key",
  "roles_pkey",
  "roles_key_check",
  "roles_name_check",
  "roles_rank_check",
  "roles_key_unique",
  "permissions_pkey",
  "permissions_resource_check",
  "permissions_action_check",
  "permissions_key_check",
  "permissions_wildcard_check",
  "permissions_key_unique",
  "role_permissions_pkey",
  "role_permissions_role_id_fkey",
  "role_permissions_permission_id_fkey",
  "role_inheritance_pkey",
  "role_inheritance_role_id_fkey",
  "role_inheritance_inherits_role_id_fkey",
  "user_roles_scope_pair_check",
  "user_roles_user_id_fkey",
  "user_roles_role_id_fkey",
  "user_roles_assigned_by_fkey",
  "oauth_states_pkey",
  "oauth_states_state_hash_length_check",
  "oauth_states_provider_check",
  "oauth_states_flow_check",
  "oauth_states_pkce_challenge_check",
  "oauth_states_redirect_target_check",
  "oauth_states_linking_user_id_fkey",
  "oauth_states_state_hash_key",
  "api_keys_pkey",
  "api_keys_prefix_check",
  "api_keys_key_hash_length_check",
  "api_keys_kind_check",
  "api_keys_key_hash_key",
  "api_keys_prefix_key",
  "audit_log_pkey",
  "audit_log_action_check",
  "audit_log_target_type_check",
  "audit_log_metadata_object_check",
  "audit_log_outcome_check",
] as const;

const requiredTriggers = ["role_inheritance_cycle_guard", "audit_log_immutable_guard"] as const;
const requiredFunctions = ["prevent_role_inheritance_cycle", "reject_audit_mutation"] as const;

const requiredForeignKeyActions: Readonly<Record<string, "c" | "n">> = {
  identities_user_id_fkey: "c",
  password_credentials_user_id_fkey: "c",
  sessions_user_id_fkey: "c",
  refresh_tokens_session_id_fkey: "c",
  refresh_tokens_parent_id_fkey: "n",
  refresh_tokens_replacement_id_fkey: "n",
  one_time_tokens_user_id_fkey: "c",
  role_permissions_role_id_fkey: "c",
  role_permissions_permission_id_fkey: "c",
  role_inheritance_role_id_fkey: "c",
  role_inheritance_inherits_role_id_fkey: "c",
  user_roles_user_id_fkey: "c",
  user_roles_role_id_fkey: "c",
  user_roles_assigned_by_fkey: "n",
  oauth_states_linking_user_id_fkey: "n",
};

interface DatabaseRow {
  readonly [column: string]: any;
}

type QueryExecutor = Pool | PoolClient;

/** A migration runner failure that is safe for the CLI to summarize. */
export class MigrationError extends Error {
  readonly code = "migration_error";

  constructor(message: string, options?: { readonly cause?: unknown }) {
    super(message, options);
    this.name = "MigrationError";
  }
}

export type MigrationState = "applied" | "pending" | "checksum_mismatch";

export interface MigrationStatus {
  readonly version: string;
  readonly checksum: string;
  readonly expectedChecksum: string | null;
  readonly appliedAt: Date | null;
  readonly packageVersion: string | null;
  readonly state: MigrationState;
}

export interface MigrationRunResult {
  readonly applied: readonly string[];
}

export interface MigrationOptions {
  readonly direction: "up";
  readonly manifest?: readonly MigrationDefinition[];
  readonly packageVersion?: string;
}

export interface SchemaVerification {
  readonly ok: boolean;
  readonly errors: readonly string[];
  readonly tables: readonly string[];
  readonly extensionVersion: string | null;
  readonly postgresVersion: number | null;
}

async function queryRows(executor: QueryExecutor, text: string, values: readonly unknown[] = []): Promise<DatabaseRow[]> {
  const result = await executor.query(text, values as any[]);
  return result.rows as DatabaseRow[];
}

async function tableExists(executor: QueryExecutor): Promise<boolean> {
  const rows = await queryRows(
    executor,
    "SELECT to_regclass('auth.schema_migrations') IS NOT NULL AS exists",
  );
  return rows[0]?.exists === true;
}

async function appliedRows(executor: QueryExecutor): Promise<DatabaseRow[]> {
  if (!(await tableExists(executor))) return [];
  return queryRows(
    executor,
    `SELECT version, checksum, applied_at, package_version
       FROM auth.schema_migrations
      ORDER BY version`,
  );
}

function manifestMap(manifest: readonly MigrationDefinition[]): Map<string, MigrationDefinition> {
  return new Map(manifest.map((migration) => [migration.version, migration]));
}

function validateAppliedRows(
  rows: readonly DatabaseRow[],
  manifest: readonly MigrationDefinition[],
): void {
  const known = manifestMap(manifest);
  for (const row of rows) {
    const version = String(row.version);
    const expected = known.get(version);
    if (!expected) {
      throw new MigrationError(`Unknown applied migration version: ${version}`);
    }
    if (String(row.checksum) !== expected.checksum) {
      throw new MigrationError(`Migration checksum mismatch for ${version}`);
    }
  }
}

/** Apply ordered migrations with one session advisory lock and one transaction per migration. */
export async function migrate(
  pool: Pool,
  options: MigrationOptions,
): Promise<MigrationRunResult> {
  if (options.direction !== "up") {
    throw new MigrationError("Only migration direction 'up' is supported");
  }
  const manifest = options.manifest ?? MIGRATIONS;
  const packageVersion = options.packageVersion ?? PACKAGE_VERSION;
  const client = await pool.connect();
  let lockAcquired = false;
  const applied: string[] = [];

  try {
    await client.query(`SELECT pg_advisory_lock(${advisoryLockSql})`);
    lockAcquired = true;
    const existingRows = await appliedRows(client);
    validateAppliedRows(existingRows, manifest);
    const appliedVersions = new Set(existingRows.map((row) => String(row.version)));

    for (const migration of manifest) {
      if (appliedVersions.has(migration.version)) continue;

      await client.query("BEGIN");
      try {
        await client.query(migration.sql);
        await client.query(
          `INSERT INTO auth.schema_migrations (version, checksum, package_version)
           VALUES ($1, $2, $3)`,
          [migration.version, migration.checksum, packageVersion],
        );
        await client.query("COMMIT");
      } catch (error) {
        await client.query("ROLLBACK").catch(() => undefined);
        throw new MigrationError(`Migration ${migration.version} failed`, { cause: error });
      }
      appliedVersions.add(migration.version);
      applied.push(migration.version);
    }

    return { applied };
  } finally {
    if (lockAcquired) {
      await client.query(`SELECT pg_advisory_unlock(${advisoryLockSql})`).catch(() => undefined);
    }
    client.release();
  }
}

/** Read the ordered migration state without creating a schema, table, lock, or row. */
export async function migrationStatus(pool: Pool): Promise<readonly MigrationStatus[]> {
  const rows = await appliedRows(pool);
  const appliedByVersion = new Map(rows.map((row) => [String(row.version), row]));
  const knownVersions = new Set(MIGRATIONS.map((migration) => migration.version));
  const statuses: MigrationStatus[] = MIGRATIONS.map((migration) => {
    const applied = appliedByVersion.get(migration.version);
    if (!applied) {
      return {
        version: migration.version,
        checksum: migration.checksum,
        expectedChecksum: migration.checksum,
        appliedAt: null,
        packageVersion: null,
        state: "pending",
      };
    }
    const checksum = String(applied.checksum);
    return {
      version: migration.version,
      checksum,
      expectedChecksum: migration.checksum,
      appliedAt: (applied.applied_at as Date | null) ?? null,
      packageVersion: (applied.package_version as string | null) ?? null,
      state: checksum === migration.checksum ? "applied" : "checksum_mismatch",
    };
  });
  for (const row of rows) {
    const version = String(row.version);
    if (knownVersions.has(version)) continue;
    statuses.push({
      version,
      checksum: String(row.checksum),
      expectedChecksum: null,
      appliedAt: (row.applied_at as Date | null) ?? null,
      packageVersion: (row.package_version as string | null) ?? null,
      state: "checksum_mismatch",
    });
  }
  return statuses;
}

async function actualAuthTables(pool: Pool): Promise<string[]> {
  const rows = await queryRows(
    pool,
    `SELECT table_name
       FROM information_schema.tables
      WHERE table_schema = 'auth' AND table_type = 'BASE TABLE'
      ORDER BY table_name`,
  );
  return rows.map((row) => String(row.table_name));
}

/** Verify schema shape, security objects, required extension/version, and migration checksums read-only. */
export async function verifySchema(pool: Pool): Promise<SchemaVerification> {
  const errors: string[] = [];
  let extensionVersion: string | null = null;
  let postgresVersion: number | null = null;
  const tables = await actualAuthTables(pool);

  if (!tables.length) errors.push("auth schema is missing");
  for (const table of REQUIRED_TABLES) {
    if (!tables.includes(table)) errors.push(`required table is missing: auth.${table}`);
  }
  for (const table of tables) {
    if (!REQUIRED_TABLES.includes(table as (typeof REQUIRED_TABLES)[number])) {
      errors.push(`unexpected table in auth schema: auth.${table}`);
    }
  }

  const versionRows = await queryRows(pool, "SHOW server_version_num");
  const versionValue = Number(versionRows[0]?.server_version_num);
  postgresVersion = Number.isFinite(versionValue) ? versionValue : null;
  if (postgresVersion === null || postgresVersion < minimumPostgresVersion) {
    errors.push("PostgreSQL 15 or newer is required");
  }

  const extensionRows = await queryRows(
    pool,
    "SELECT extversion FROM pg_extension WHERE extname = 'pgcrypto'",
  );
  extensionVersion = (extensionRows[0]?.extversion as string | undefined) ?? null;
  if (!extensionVersion) errors.push("required extension pgcrypto is missing");

  const columnRows = await queryRows(
    pool,
    `SELECT table_name, column_name
       FROM information_schema.columns
      WHERE table_schema = 'auth'
      ORDER BY table_name, ordinal_position`,
  );
  for (const table of REQUIRED_TABLES) {
    const actual = columnRows
      .filter((row) => row.table_name === table)
      .map((row) => String(row.column_name));
    const expected = requiredColumns[table];
    if (actual.join("\u0000") !== expected.join("\u0000")) {
      errors.push(`columns do not match for auth.${table}`);
    }
  }

  const indexRows = await queryRows(
    pool,
    `SELECT indexname FROM pg_indexes WHERE schemaname = 'auth'`,
  );
  const indexes = new Set(indexRows.map((row) => String(row.indexname)));
  for (const index of requiredIndexes) {
    if (!indexes.has(index)) errors.push(`required index is missing: auth.${index}`);
  }

  const constraintRows = await queryRows(
    pool,
    `SELECT conname FROM pg_constraint AS constraint_row
      JOIN pg_namespace AS namespace_row ON namespace_row.oid = constraint_row.connamespace
     WHERE namespace_row.nspname = 'auth'`,
  );
  const constraints = new Set(constraintRows.map((row) => String(row.conname)));
  for (const constraint of requiredConstraints) {
    if (!constraints.has(constraint)) errors.push(`required constraint is missing: auth.${constraint}`);
  }

  const foreignKeyRows = await queryRows(
    pool,
    `SELECT constraint_row.conname, constraint_row.confdeltype
       FROM pg_constraint AS constraint_row
       JOIN pg_namespace AS namespace_row ON namespace_row.oid = constraint_row.connamespace
      WHERE constraint_row.contype = 'f'
        AND namespace_row.nspname = 'auth'`,
  );
  const foreignKeyActions = new Map(foreignKeyRows.map((row) => [String(row.conname), String(row.confdeltype)]));
  for (const [constraint, action] of Object.entries(requiredForeignKeyActions)) {
    if (foreignKeyActions.get(constraint) !== action) {
      errors.push(`foreign-key delete action is wrong: auth.${constraint}`);
    }
  }

  const triggerRows = await queryRows(
    pool,
    `SELECT trigger_name
       FROM information_schema.triggers
      WHERE event_object_schema = 'auth'`,
  );
  const triggers = new Set(triggerRows.map((row) => String(row.trigger_name)));
  for (const trigger of requiredTriggers) {
    if (!triggers.has(trigger)) errors.push(`required trigger is missing: auth.${trigger}`);
  }

  const functionRows = await queryRows(
    pool,
    `SELECT routine_name
       FROM information_schema.routines
      WHERE routine_schema = 'auth'`,
  );
  const functions = new Set(functionRows.map((row) => String(row.routine_name)));
  for (const functionName of requiredFunctions) {
    if (!functions.has(functionName)) errors.push(`required function is missing: auth.${functionName}`);
  }

  const forbiddenRows = await queryRows(
    pool,
    `SELECT c.relname AS object_name
       FROM pg_class AS c
       JOIN pg_namespace AS n ON n.oid = c.relnamespace
      WHERE n.nspname = 'auth'
     UNION ALL
     SELECT a.attname
       FROM pg_attribute AS a
       JOIN pg_class AS c ON c.oid = a.attrelid
       JOIN pg_namespace AS n ON n.oid = c.relnamespace
      WHERE n.nspname = 'auth' AND a.attnum > 0 AND NOT a.attisdropped
     UNION ALL
     SELECT con.conname
       FROM pg_constraint AS con
       JOIN pg_namespace AS n ON n.oid = con.connamespace
      WHERE n.nspname = 'auth'
     UNION ALL
     SELECT p.proname
       FROM pg_proc AS p
       JOIN pg_namespace AS n ON n.oid = p.pronamespace
      WHERE n.nspname = 'auth'`,
  );
  if (forbiddenRows.some((row) => /mrjim|hayahai|shipping|tenant|passenger|vessel|cabin|tms/i.test(String(row.object_name)))) {
    errors.push("forbidden business or package object name exists in auth schema");
  }

  try {
    const statuses = await migrationStatus(pool);
    for (const status of statuses) {
      if (status.state !== "applied") errors.push(`migration is not clean: ${status.version}`);
    }
  } catch {
    errors.push("migration state could not be read");
  }

  return {
    ok: errors.length === 0,
    errors,
    tables,
    extensionVersion,
    postgresVersion,
  };
}
