import { spawn } from "node:child_process";
import { createHmac } from "node:crypto";
import { mkdtemp, mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Pool } from "pg";
import { runCli } from "../../src/cli/runner.js";
import { runDoctor } from "../../src/cli/commands/doctor.js";
import { runMigrateCommand } from "../../src/cli/commands/migrate.js";
import { MIGRATIONS } from "../../src/postgres/manifest.js";
import { FORBIDDEN_AUTH_NAMES } from "../../src/postgres/internal/schema-contract.js";
import {
  migrate,
  migrationStatus,
  verifySchema,
} from "../../src/postgres/migrate.js";

const packageVersion = "0.1.0";
const immutableMigrationChecksums = {
  "0001_core": "542cb353f119e1e0d5f655d7611edefd301eb3cdc6cb9afcef0211f398ba3c4f",
  "0002_authorization": "c203903f1c7e00ed8a0ecc5e4b6de743447bd1e2c88f21682df6761381a887d6",
  "0003_oauth_operations": "af1c65925dbb63c0dacb332ff429b4cc6911482dc7cd1f560a73221016850b58",
  "0004_repository_hardening": "22aa84110fb82deaaf79d2640c78141aca7e1bd88c0de97616af7dbb7a4b2909",
  "0005_oauth_callback": "acc1e42358d6aa1b5b2cbb8bdd4ed97fd6838f6ef0b3a2796c8ff2d20e91f500",
} as const;
const packageRoot = resolve(fileURLToPath(new URL("../../", import.meta.url)));
const workspaceRoot = resolve(packageRoot, "../..");
const originalDatabaseUrl = process.env.DATABASE_URL;
const ignoredGenericDatabaseUrl = "postgresql://not-used.invalid:5432/not-a-test-database";
process.env.DATABASE_URL = ignoredGenericDatabaseUrl;
const runSerialPackageLifecycleTests = process.env.MRJIM_AUTH_SERIAL_PACK_TESTS === "1";

const requiredTables = [
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
  "rate_limit_buckets",
  "schema_migrations",
] as const;

const expectedColumns: Record<(typeof requiredTables)[number], readonly string[]> = {
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
    "created_at",
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
    "name",
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
  rate_limit_buckets: [
    "key_digest",
    "bucket",
    "window_start",
    "window_end",
    "count",
    "created_at",
    "updated_at",
  ],
  schema_migrations: ["version", "migration_order", "checksum", "applied_at", "package_version"],
};

type Cluster = {
  root: string;
  dataDirectory: string;
  socketDirectory: string;
};

type CommandOptions = {
  readonly ignoreOutput?: boolean;
  readonly errorLogPath?: string;
  readonly cwd?: string;
  readonly env?: NodeJS.ProcessEnv;
};

type CommandResult = {
  readonly code: number | null;
  readonly stdout: string;
  readonly stderr: string;
};

let pool: Pool;
let cluster: Cluster | undefined;
let disposable: DisposablePostgres | undefined;

async function runCommand(
  command: string,
  args: readonly string[],
  options: CommandOptions = {},
): Promise<void> {
  const result = await runCommandResult(command, args, options);
  if (result.code === 0) return;
  const log = options.errorLogPath
    ? await readFile(options.errorLogPath, "utf8").catch(() => "")
    : "";
  throw new Error(`${command} ${args.join(" ")} exited with code ${result.code ?? "unknown"}${result.stderr || log ? `: ${(result.stderr || log).trim()}` : ""}`);
}

async function runCommandResult(
  command: string,
  args: readonly string[],
  options: CommandOptions = {},
): Promise<CommandResult> {
  return new Promise<CommandResult>((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      env: options.env,
      stdio: options.ignoreOutput ? "ignore" : ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout?.on("data", (chunk: Buffer) => {
      stdout += chunk.toString();
    });
    child.stderr?.on("data", (chunk: Buffer) => {
      stderr += chunk.toString();
    });
    child.once("error", reject);
    child.once("close", (code) => {
      resolve({ code, stdout, stderr });
    });
  });
}

type DisposablePostgres = {
  readonly cluster: Cluster;
  readonly pool: Pool;
};

async function startDisposablePostgres(label: string): Promise<DisposablePostgres> {
  const root = await mkdtemp(join(tmpdir(), `${label}-`));
  const dataDirectory = join(root, "data");
  const socketDirectory = join(root, "socket");
  const disposableCluster = { root, dataDirectory, socketDirectory };

  try {
    await mkdir(socketDirectory);
    await runCommand("initdb", [
      "--pgdata",
      dataDirectory,
      "--auth=trust",
      "--username=postgres",
      "--no-locale",
      "--encoding=UTF8",
    ]);
    await runCommand("pg_ctl", [
      "--pgdata",
      dataDirectory,
      "--log",
      join(root, "postgres.log"),
      "--options",
      `-h '' -k ${socketDirectory}`,
      "--wait",
      "start",
    ], { ignoreOutput: true, errorLogPath: join(root, "postgres.log") });

    const disposablePool = new Pool({
      connectionString: `postgresql://postgres@localhost/postgres?host=${encodeURIComponent(socketDirectory)}`,
      max: 10,
    });
    try {
      await disposablePool.query("SELECT version()");
      return { cluster: disposableCluster, pool: disposablePool };
    } catch (error) {
      await disposablePool.end().catch(() => undefined);
      throw error;
    }
  } catch (error) {
    await runCommand("pg_ctl", [
      "--pgdata",
      dataDirectory,
      "--mode=immediate",
      "--wait",
      "stop",
    ], { ignoreOutput: true }).catch(() => undefined);
    await rm(root, { recursive: true, force: true });
    throw error;
  }
}

async function stopDisposablePostgres(disposable: DisposablePostgres): Promise<void> {
  try {
    await disposable.pool.end();
  } finally {
    try {
      await runCommand("pg_ctl", [
        "--pgdata",
        disposable.cluster.dataDirectory,
        "--mode=immediate",
        "--wait",
        "stop",
      ], { ignoreOutput: true }).catch(() => undefined);
    } finally {
      await rm(disposable.cluster.root, { recursive: true, force: true });
    }
  }
}

async function queryRows(query: string, values: readonly unknown[] = []): Promise<Record<string, unknown>[]> {
  const result = await pool.query(query, values as unknown[]);
  return result.rows as Record<string, unknown>[];
}

async function applyTask11BaseHistory(legacyPool: Pool): Promise<void> {
  const client = await legacyPool.connect();
  try {
    await client.query("BEGIN");
    for (const migration of MIGRATIONS.slice(0, 5)) {
      await client.query(migration.sql);
      await client.query(
        `INSERT INTO auth.schema_migrations
          (version, migration_order, checksum, package_version)
         VALUES ($1, $2, $3, $4)`,
        [migration.version, migration.migrationOrder, migration.checksum, migration.introducedIn],
      );
    }
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

async function scalar<T>(query: string, values: readonly unknown[] = []): Promise<T> {
  const rows = await queryRows(query, values);
  const value = rows[0]?.value;
  return value as T;
}

async function createUser(overrides: { emailNormalized?: string | null; phoneNormalized?: string | null } = {}): Promise<string> {
  const rows = await queryRows(
    `INSERT INTO auth.users (email, email_normalized, phone, phone_normalized)
     VALUES ('User@example.com', $1, '+639171234567', $2)
     RETURNING id`,
    [overrides.emailNormalized ?? null, overrides.phoneNormalized ?? null],
  );
  return String(rows[0]?.id);
}

async function createRole(key: string): Promise<string> {
  const rows = await queryRows(
    `INSERT INTO auth.roles (key, name, rank)
     VALUES ($1, $1, 10)
     RETURNING id`,
    [key],
  );
  return String(rows[0]?.id);
}

async function createSession(userId: string): Promise<string> {
  const rows = await queryRows(
    `INSERT INTO auth.sessions (user_id, expires_at)
     VALUES ($1, now() + interval '1 hour')
     RETURNING id`,
    [userId],
  );
  return String(rows[0]?.id);
}

async function expectDatabaseError(operation: () => Promise<unknown>, pattern: RegExp): Promise<void> {
  await expect(operation()).rejects.toThrow(pattern);
}

async function authTables(): Promise<string[]> {
  const rows = await queryRows(
    `SELECT table_name
       FROM information_schema.tables
      WHERE table_schema = 'auth' AND table_type = 'BASE TABLE'
      ORDER BY table_name`,
  );
  return rows.map((row) => String(row.table_name));
}

async function authObjectNames(): Promise<string[]> {
  const rows = await queryRows(
    `SELECT c.relname AS object_name
       FROM pg_class AS c
       JOIN pg_namespace AS n ON n.oid = c.relnamespace
      WHERE n.nspname = 'auth'
     UNION ALL
     SELECT con.conname
       FROM pg_constraint AS con
       JOIN pg_namespace AS n ON n.oid = con.connamespace
      WHERE n.nspname = 'auth'
     UNION ALL
     SELECT a.attname
       FROM pg_attribute AS a
       JOIN pg_class AS c ON c.oid = a.attrelid
       JOIN pg_namespace AS n ON n.oid = c.relnamespace
      WHERE n.nspname = 'auth' AND a.attnum > 0 AND NOT a.attisdropped
     UNION ALL
     SELECT p.proname
       FROM pg_proc AS p
       JOIN pg_namespace AS n ON n.oid = p.pronamespace
      WHERE n.nspname = 'auth'
     UNION ALL
     SELECT t.typname
       FROM pg_type AS t
       JOIN pg_namespace AS n ON n.oid = t.typnamespace
      WHERE n.nspname = 'auth' AND t.typisdefined
     UNION ALL
     SELECT t.tgname
       FROM pg_trigger AS t
       JOIN pg_class AS c ON c.oid = t.tgrelid
       JOIN pg_namespace AS n ON n.oid = c.relnamespace
      WHERE n.nspname = 'auth' AND NOT t.tgisinternal
      ORDER BY object_name`,
  );
  return rows.map((row) => String(row.object_name));
}

async function authSchemaExists(): Promise<boolean> {
  return scalar<boolean>("SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'auth') AS value");
}

async function countRows(table: string): Promise<number> {
  return scalar<number>(`SELECT count(*)::int AS value FROM auth.${table}`);
}

function localDatabaseUrl(): string {
  if (!cluster) throw new Error("Local PostgreSQL cluster is not initialized");
  return `postgresql://postgres@localhost/postgres?host=${encodeURIComponent(cluster.socketDirectory)}`;
}

describe("Task 3 PostgreSQL migrations", () => {
  beforeAll(async () => {
    disposable = await startDisposablePostgres("mrjim-auth-task3");
    cluster = disposable.cluster;
    pool = disposable.pool;
  }, 120_000);

  afterAll(async () => {
    try {
      if (disposable) await stopDisposablePostgres(disposable);
    } finally {
      if (originalDatabaseUrl === undefined) delete process.env.DATABASE_URL;
      else process.env.DATABASE_URL = originalDatabaseUrl;
    }
  });

  it("ignores generic DATABASE_URL and always uses the disposable local cluster", async () => {
    expect(process.env.DATABASE_URL).toBe(ignoredGenericDatabaseUrl);
    expect(localDatabaseUrl()).toContain(encodeURIComponent(cluster?.socketDirectory ?? ""));
    expect(localDatabaseUrl()).not.toBe(ignoredGenericDatabaseUrl);
    expect(await scalar<boolean>("SELECT current_database() = 'postgres' AS value")).toBe(true);
  });

  it("reports pending migrations without creating database objects", async () => {
    expect(await authSchemaExists()).toBe(false);

    const before = await migrationStatus(pool);
    expect(before).toHaveLength(MIGRATIONS.length);
    expect(before.every((migration) => migration.state === "pending")).toBe(true);
    const verification = await verifySchema(pool);
    expect(verification.ok).toBe(false);
    expect(verification.errors).toContain("auth schema is missing");
    expect(await authSchemaExists()).toBe(false);
  });

  it("upgrades the immutable 0001-0005 history with only admin/rate-limit migration 0006", async () => {
    expect(MIGRATIONS.map((migration) => migration.version)).toEqual([
      "0001_core",
      "0002_authorization",
      "0003_oauth_operations",
      "0004_repository_hardening",
      "0005_oauth_callback",
      "0006_admin_operations",
    ]);
    expect(MIGRATIONS.find((migration) => migration.version === "0001_core")?.checksum).toBe(
      immutableMigrationChecksums["0001_core"],
    );
    expect(MIGRATIONS.find((migration) => migration.version === "0002_authorization")?.checksum).toBe(
      immutableMigrationChecksums["0002_authorization"],
    );
    expect(MIGRATIONS.find((migration) => migration.version === "0003_oauth_operations")?.checksum).toBe(
      immutableMigrationChecksums["0003_oauth_operations"],
    );
    expect(MIGRATIONS.find((migration) => migration.version === "0004_repository_hardening")?.checksum).toBe(
      immutableMigrationChecksums["0004_repository_hardening"],
    );
    expect(MIGRATIONS.find((migration) => migration.version === "0005_oauth_callback")?.checksum).toBe(
      immutableMigrationChecksums["0005_oauth_callback"],
    );
    expect(MIGRATIONS.slice(0, 5).every((migration) => migration.introducedIn === packageVersion)).toBe(true);

    const legacy = await startDisposablePostgres("mja4-inc");
    try {
      await applyTask11BaseHistory(legacy.pool);
      const before = await migrationStatus(legacy.pool);
      expect(before.slice(0, 5).every((migration) => migration.state === "applied")).toBe(true);
      expect(before[5]?.state).toBe("pending");

      const result = await migrate(legacy.pool, { direction: "up" });
      expect(result.applied).toEqual(["0006_admin_operations"]);

      const after = await migrationStatus(legacy.pool);
      expect(after.map((migration) => migration.version)).toEqual(
        MIGRATIONS.map((migration) => migration.version),
      );
      expect(after.every((migration) => migration.state === "applied")).toBe(true);
      expect((await verifySchema(legacy.pool)).ok).toBe(true);
    } finally {
      await stopDisposablePostgres(legacy);
    }
  }, 120_000);

  it("creates exactly the clean auth tables and columns", async () => {
    await migrate(pool, { direction: "up" });

    expect(await authTables()).toEqual([...requiredTables].sort());
    const columns = await queryRows(
      `SELECT table_name, column_name
         FROM information_schema.columns
        WHERE table_schema = 'auth'
        ORDER BY table_name, ordinal_position`,
    );
    for (const table of requiredTables) {
      expect(
        columns.filter((row) => row.table_name === table).map((row) => String(row.column_name)),
      ).toEqual(expectedColumns[table]);
    }

    const forbiddenPattern = new RegExp(FORBIDDEN_AUTH_NAMES.join("|"), "i");
    expect((await authObjectNames()).join(" ")).not.toMatch(forbiddenPattern);
    expect(MIGRATIONS.map((migration) => migration.sql).join(" ")).not.toMatch(forbiddenPattern);
  });

  it("accepts dotted dynamic permission resources while preserving legacy resources", async () => {
    await pool.query(
      `INSERT INTO auth.permissions (key, resource, action)
       VALUES ('auth.roles.manage', 'auth.roles', 'manage'), ('users.read', 'users', 'read')`,
    );
    await expectDatabaseError(
      () => pool.query(
        `INSERT INTO auth.permissions (key, resource, action)
         VALUES ('Auth.roles.manage', 'Auth.roles', 'manage')`,
      ),
      /permissions_(resource|key)_check/i,
    );
    await expectDatabaseError(
      () => pool.query(
        `INSERT INTO auth.permissions (key, resource, action)
         VALUES ('auth.roles/invalid.manage', 'auth.roles/invalid', 'manage')`,
      ),
      /permissions_(resource|key)_check/i,
    );
  });

  it("records ordered checksums, is idempotent, and verifies the schema", async () => {
    const firstStatus = await migrationStatus(pool);
    expect(firstStatus.map((migration) => migration.version)).toEqual(
      MIGRATIONS.map((migration) => migration.version),
    );
    expect(firstStatus.every((migration) => migration.state === "applied")).toBe(true);
    expect(firstStatus.map((migration) => migration.checksum)).toEqual(
      MIGRATIONS.map((migration) => migration.checksum),
    );
    expect(firstStatus.map((migration) => migration.packageVersion)).toEqual(
      MIGRATIONS.map((migration) => migration.introducedIn),
    );

    const appliedAt = firstStatus.map((migration) => migration.appliedAt);
    const secondRun = await migrate(pool, { direction: "up" });
    expect(secondRun.applied).toEqual([]);
    expect((await migrationStatus(pool)).map((migration) => migration.appliedAt)).toEqual(appliedAt);

    const verification = await verifySchema(pool);
    expect(verification.ok).toBe(true);
    expect(verification.errors).toEqual([]);
  });

  it("enforces non-null normalized email and phone uniqueness", async () => {
    const firstUser = await createUser({ emailNormalized: "user@example.com", phoneNormalized: "+639171234567" });
    expect(firstUser).toMatch(/[0-9a-f-]{36}/);
    await createUser({ emailNormalized: null, phoneNormalized: null });

    await expectDatabaseError(
      () => createUser({ emailNormalized: "user@example.com", phoneNormalized: null }),
      /users_email_normalized_key/i,
    );
    await expectDatabaseError(
      () => createUser({ emailNormalized: null, phoneNormalized: "+639171234567" }),
      /users_phone_normalized_key/i,
    );
    await expectDatabaseError(
      () => createUser({ emailNormalized: "   ", phoneNormalized: null }),
      /users_email_normalized_check/i,
    );
    await expectDatabaseError(
      () => createUser({ emailNormalized: null, phoneNormalized: "   " }),
      /users_phone_normalized_check/i,
    );
    const identityUserId = await createUser();
    await expectDatabaseError(
      () => pool.query(
        `INSERT INTO auth.identities (user_id, provider, provider_subject, email_normalized)
         VALUES ($1, 'oidc', 'blank-email', '   ')`,
        [identityUserId],
      ),
      /identities_email_normalized_check/i,
    );
  });

  it("enforces provider subject and digest uniqueness with token length checks", async () => {
    const userId = await createUser();
    const otherUserId = await createUser();
    await pool.query(
      `INSERT INTO auth.identities (user_id, provider, provider_subject, email, email_normalized)
       VALUES ($1, 'google', 'subject-1', 'User@example.com', 'user@example.com')`,
      [userId],
    );
    await expectDatabaseError(
      () => pool.query(
        `INSERT INTO auth.identities (user_id, provider, provider_subject)
         VALUES ($1, 'google', 'subject-1')`,
        [otherUserId],
      ),
      /identities_provider_subject_key/i,
    );

    const sessionId = await createSession(userId);
    const familyId = "00000000-0000-4000-8000-000000000010";
    const hash = Buffer.alloc(32, 1);
    await pool.query(
      `INSERT INTO auth.refresh_tokens (session_id, token_hash, family_id, expires_at)
       VALUES ($1, $2, $3, now() + interval '1 hour')`,
      [sessionId, hash, familyId],
    );
    await expectDatabaseError(
      () => pool.query(
        `INSERT INTO auth.refresh_tokens (session_id, token_hash, family_id, expires_at)
         VALUES ($1, $2, $3, now() + interval '1 hour')`,
        [sessionId, hash, familyId],
      ),
      /refresh_tokens_token_hash_key/i,
    );
    await expectDatabaseError(
      () => pool.query(
        `INSERT INTO auth.refresh_tokens (session_id, token_hash, family_id, expires_at)
         VALUES ($1, $2, $3, now() + interval '1 hour')`,
        [sessionId, Buffer.alloc(31, 2), familyId],
      ),
      /refresh_tokens_token_hash_length_check/i,
    );

    await pool.query(
      `INSERT INTO auth.one_time_tokens (user_id, purpose, token_hash, target, expires_at)
       VALUES ($1, 'recovery', $2, 'user@example.com', now() + interval '15 minutes')`,
      [userId, Buffer.alloc(32, 3)],
    );
    await expectDatabaseError(
      () => pool.query(
        `INSERT INTO auth.one_time_tokens (user_id, purpose, token_hash, target, expires_at)
         VALUES ($1, 'not-a-purpose', $2, 'user@example.com', now() + interval '15 minutes')`,
        [userId, Buffer.alloc(32, 4)],
      ),
      /one_time_tokens_purpose_check/i,
    );
    await expectDatabaseError(
      () => pool.query(
        `INSERT INTO auth.one_time_tokens (user_id, purpose, token_hash, target, expires_at)
         VALUES ($1, 'recovery', $2, 'user@example.com', now() + interval '15 minutes')`,
        [userId, Buffer.alloc(31, 5)],
      ),
      /one_time_tokens_token_hash_length_check/i,
    );
  });

  it("enforces Argon2id floors and token expiry boundaries", async () => {
    const weakHashCases = [
      "$argon2id$v=18$m=65536,t=3,p=1$c2FsdA$aGFzaA",
      "$argon2id$v=19$m=32768,t=3,p=1$c2FsdA$aGFzaA",
      "$argon2id$v=19$m=65536,t=2,p=1$c2FsdA$aGFzaA",
      "$argon2id$v=19$m=65536,t=3,p=0$c2FsdA$aGFzaA",
      "$argon2id$v=19$m=65536,t=3,p=1$not a valid hash",
    ];
    for (const passwordHash of weakHashCases) {
      const userId = await createUser();
      await expectDatabaseError(
        () => pool.query(
          `INSERT INTO auth.password_credentials (user_id, password_hash)
           VALUES ($1, $2)`,
          [userId, passwordHash],
        ),
        /password_credentials_hash_check/i,
      );
    }

    const validUserId = await createUser();
    await pool.query(
      `INSERT INTO auth.password_credentials (user_id, password_hash)
       VALUES ($1, '$argon2id$v=19$m=65536,t=3,p=1$c2FsdA$aGFzaA')`,
      [validUserId],
    );
    const strongerUserId = await createUser();
    await pool.query(
      `INSERT INTO auth.password_credentials (user_id, password_hash)
       VALUES ($1, '$argon2id$v=19$m=131072,t=4,p=2$c2FsdA$aGFzaA')`,
      [strongerUserId],
    );

    const sessionId = await createSession(validUserId);
    await expectDatabaseError(
      () => pool.query(
        `INSERT INTO auth.refresh_tokens
          (session_id, token_hash, family_id, issued_at, expires_at)
         VALUES ($1, $2, $3, '2020-01-01T00:00:00Z', '2019-12-31T23:59:59Z')`,
        [sessionId, Buffer.alloc(32, 31), "00000000-0000-4000-8000-000000000031"],
      ),
      /refresh_tokens_expiry_check/i,
    );

    await expectDatabaseError(
      () => pool.query(
        `INSERT INTO auth.one_time_tokens
          (user_id, purpose, token_hash, target, created_at, expires_at)
         VALUES ($1, 'recovery', $2, 'recovery@example.com', now() - interval '20 minutes', now())`,
        [validUserId, Buffer.alloc(32, 32)],
      ),
      /one_time_tokens_recovery_ttl_check/i,
    );
    await expectDatabaseError(
      () => pool.query(
        `INSERT INTO auth.one_time_tokens
          (user_id, purpose, token_hash, target, created_at, expires_at)
         VALUES ($1, 'signup', $2, 'signup@example.com', now() - interval '25 hours', now())`,
        [validUserId, Buffer.alloc(32, 33)],
      ),
      /one_time_tokens_signup_ttl_check/i,
    );
    await expectDatabaseError(
      () => pool.query(
        `INSERT INTO auth.one_time_tokens
          (user_id, purpose, token_hash, target, created_at, expires_at)
         VALUES ($1, 'invite', $2, 'invite@example.com', now(), now() - interval '1 second')`,
        [validUserId, Buffer.alloc(32, 34)],
      ),
      /one_time_tokens_expiry_check/i,
    );
    await expectDatabaseError(
      () => pool.query(
        `INSERT INTO auth.one_time_tokens
          (user_id, purpose, token_hash, target, metadata, expires_at)
         VALUES ($1, 'invite', $2, 'invite@example.com', $3::jsonb, now() + interval '1 hour')`,
        [validUserId, Buffer.alloc(32, 37), JSON.stringify({ token: "raw-secret" })],
      ),
      /one_time_tokens_metadata_redaction_check/i,
    );

    await expectDatabaseError(
      () => pool.query(
        `INSERT INTO auth.oauth_states
          (state_hash, provider, flow, pkce_challenge, redirect_target, created_at, expires_at)
         VALUES ($1, 'google', 'sign_in', 'challenge', 'https://example.com/callback', now(), now() + interval '11 minutes')`,
        [Buffer.alloc(32, 35)],
      ),
      /oauth_states_ttl_check/i,
    );
    await expectDatabaseError(
      () => pool.query(
        `INSERT INTO auth.oauth_states
          (state_hash, provider, flow, pkce_challenge, redirect_target, created_at, expires_at)
         VALUES ($1, 'google', 'invalid_flow', 'challenge', 'https://example.com/callback', now(), now() + interval '1 minute')`,
        [Buffer.alloc(32, 38)],
      ),
      /oauth_states_flow_check/i,
    );
    await expectDatabaseError(
      () => pool.query(
        `INSERT INTO auth.api_keys (prefix, key_hash, kind, name, created_at, expires_at)
         VALUES ('sk_expired', $1, 'secret', 'expired-key', now(), now() - interval '1 second')`,
        [Buffer.alloc(32, 36)],
      ),
      /api_keys_expiry_check/i,
    );
  });

  it("rejects role-inheritance self references and deferred cycles", async () => {
    const roleA = await createRole("role_a");
    const roleB = await createRole("role_b");
    const roleC = await createRole("role_c");

    await expectDatabaseError(
      () => pool.query(
        `INSERT INTO auth.role_inheritance (role_id, inherits_role_id) VALUES ($1, $1)`,
        [roleA],
      ),
      /role_inheritance_cycle/i,
    );
    await pool.query(
      `INSERT INTO auth.role_inheritance (role_id, inherits_role_id)
       VALUES ($1, $2), ($2, $3)`,
      [roleA, roleB, roleC],
    );

    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await client.query(
        `INSERT INTO auth.role_inheritance (role_id, inherits_role_id) VALUES ($1, $2)`,
        [roleC, roleA],
      );
      await expect(client.query("COMMIT")).rejects.toThrow(/role_inheritance_cycle/i);
      await client.query("ROLLBACK").catch(() => undefined);
    } finally {
      client.release();
    }
  });

  it("enforces scoped assignment uniqueness and scope pairing", async () => {
    const userId = await createUser();
    const roleId = await createRole("scoped_role");
    await pool.query(
      `INSERT INTO auth.user_roles (user_id, role_id) VALUES ($1, $2)`,
      [userId, roleId],
    );
    await expectDatabaseError(
      () => pool.query(`INSERT INTO auth.user_roles (user_id, role_id) VALUES ($1, $2)`, [userId, roleId]),
      /user_roles_global_key/i,
    );

    await pool.query(
      `INSERT INTO auth.user_roles (user_id, role_id, scope_type, scope_id)
       VALUES ($1, $2, 'project', 'project-1')`,
      [userId, roleId],
    );
    await expectDatabaseError(
      () => pool.query(
        `INSERT INTO auth.user_roles (user_id, role_id, scope_type, scope_id)
         VALUES ($1, $2, 'project', 'project-1')`,
        [userId, roleId],
      ),
      /user_roles_scoped_key/i,
    );
    await expectDatabaseError(
      () => pool.query(
        `INSERT INTO auth.user_roles (user_id, role_id, scope_type)
         VALUES ($1, $2, 'project')`,
        [userId, roleId],
      ),
      /user_roles_scope_pair_check/i,
    );
  });

  it("cascades user-owned records and preserves immutable audit actor ids", async () => {
    const userId = await createUser();
    const roleId = await createRole("cascade_role");
    const sessionId = await createSession(userId);
    const apiKeyRows = await queryRows(
      `INSERT INTO auth.api_keys (prefix, key_hash, kind, name, scopes)
       VALUES ('pk_test', $1, 'publishable', 'test-key', ARRAY['invoice.read'])
       RETURNING id`,
      [Buffer.alloc(32, 7)],
    );
    const apiKeyId = String(apiKeyRows[0]?.id);
    await pool.query(
      `INSERT INTO auth.identities (user_id, provider, provider_subject)
       VALUES ($1, 'oidc', 'cascade-subject')`,
      [userId],
    );
    await pool.query(
      `INSERT INTO auth.password_credentials (user_id, password_hash)
       VALUES ($1, '$argon2id$v=19$m=65536,t=3,p=1$c2FsdA$aGFzaA')`,
      [userId],
    );
    await pool.query(
      `INSERT INTO auth.refresh_tokens (session_id, token_hash, family_id, expires_at)
       VALUES ($1, $2, $3, now() + interval '1 hour')`,
      [sessionId, Buffer.alloc(32, 8), "00000000-0000-4000-8000-000000000011"],
    );
    await pool.query(
      `INSERT INTO auth.one_time_tokens (user_id, purpose, token_hash, target, expires_at)
       VALUES ($1, 'invite', $2, 'cascade@example.com', now() + interval '1 hour')`,
      [userId, Buffer.alloc(32, 9)],
    );
    await pool.query(
      `INSERT INTO auth.oauth_states
        (state_hash, provider, flow, pkce_challenge, redirect_target, linking_user_id, expires_at)
       VALUES ($1, 'google', 'sign_in', 'challenge', 'https://example.com/callback', $2, now() + interval '1 minute')`,
      [Buffer.alloc(32, 10), userId],
    );
    await pool.query(
      `INSERT INTO auth.user_roles (user_id, role_id, assigned_by)
       VALUES ($1, $2, $1)`,
      [userId, roleId],
    );
    await pool.query(
      `INSERT INTO auth.audit_log
        (actor_user_id, actor_key_id, actor_session_id, action, target_type, metadata, outcome)
       VALUES ($1, $2, $3, 'user.created', 'user', '{"success":true}', 'success')`,
      [userId, apiKeyId, sessionId],
    );

    await pool.query("DELETE FROM auth.users WHERE id = $1", [userId]);

    const cascadedRecords = [
      ["identities", "user_id", userId],
      ["password_credentials", "user_id", userId],
      ["sessions", "user_id", userId],
      ["refresh_tokens", "session_id", sessionId],
      ["one_time_tokens", "user_id", userId],
      ["user_roles", "user_id", userId],
    ] as const;
    for (const [table, column, value] of cascadedRecords) {
      expect(await scalar<number>(`SELECT count(*)::int AS value FROM auth.${table} WHERE ${column} = $1`, [value])).toBe(0);
    }
    expect(await scalar<string>("SELECT linking_user_id::text AS value FROM auth.oauth_states WHERE state_hash = $1", [Buffer.alloc(32, 10)])).toBe(null);
    expect(await scalar<string>("SELECT actor_user_id::text AS value FROM auth.audit_log WHERE actor_key_id = $1", [apiKeyId])).toBe(userId);
    expect(await scalar<string>("SELECT actor_session_id::text AS value FROM auth.audit_log WHERE actor_key_id = $1", [apiKeyId])).toBe(sessionId);
  });

  it("keeps audit rows immutable", async () => {
    const rows = await queryRows(
      `INSERT INTO auth.audit_log (action, target_type, metadata, outcome)
       VALUES ('login', 'session', '{"success":true}', 'success')
       RETURNING id`,
    );
    const id = String(rows[0]?.id);
    await expectDatabaseError(
      () => pool.query("UPDATE auth.audit_log SET action = 'changed' WHERE id = $1", [id]),
      /audit_log_immutable/i,
    );
    await expectDatabaseError(
      () => pool.query("DELETE FROM auth.audit_log WHERE id = $1", [id]),
      /audit_log_immutable/i,
    );
    expect(await countRows("audit_log")).toBeGreaterThan(0);
  });

  it("enforces the documented flat audit metadata allowlist at the database boundary", async () => {
    await pool.query(
      `INSERT INTO auth.audit_log (action, target_type, metadata, outcome)
       VALUES ('safe.event', 'user', $1::jsonb, 'success')`,
      [JSON.stringify({
        event: "password_reset_requested",
        reason: "user_requested",
        error_code: "AUTH_FAILED",
        provider: "google",
        operation: "login",
        status: "success",
        user_id: "00000000-0000-4000-8000-000000000001",
        session_id: "00000000-0000-4000-8000-000000000002",
        api_key_id: "00000000-0000-4000-8000-000000000003",
        target_id: "00000000-0000-4000-8000-000000000004",
        request_id: "req-1",
        success: true,
        dry_run: false,
        changed: true,
        count: 2,
        attempt_count: 1,
        rank: 10,
        changed_fields: ["email_normalized", "phone_normalized"],
      })],
    );

    const forbiddenMetadata = [
      { code: "123456" },
      { credential: "raw-password" },
      { api_key: "sk_live_123456789" },
      { password: "raw-password" },
      { nested: { passwordHash: "$argon2id$v=19$m=65536,t=3,p=1$c2FsdA$aGFzaA" } },
      { reason: "Bearer abc.def.ghi" },
      { reason: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature" },
      { reason: "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----" },
      { reason: "https://user:password@example.com/token" },
      { reason: "sk_live_123456789" },
      { changed_fields: [{ name: "email" }] },
      { result: { status: "success" } },
    ];

    for (const metadata of forbiddenMetadata) {
      await expectDatabaseError(
        () => pool.query(
          `INSERT INTO auth.audit_log (action, target_type, metadata, outcome)
           VALUES ('unsafe.event', 'user', $1::jsonb, 'failure')`,
          [JSON.stringify(metadata)],
        ),
        /audit_metadata_redaction/i,
      );
    }
  });

  it("rejects forbidden auth names across relation kinds, types, and triggers", async () => {
    await pool.query("CREATE TABLE auth.hayahai_data (id integer NOT NULL)");
    try {
      const verification = await verifySchema(pool);
      expect(verification.ok).toBe(false);
      expect(verification.errors.join(" ")).toMatch(/hayahai_data/i);
    } finally {
      await pool.query("DROP TABLE auth.hayahai_data");
    }

    await pool.query("CREATE SEQUENCE auth.mrjim_sequence");
    try {
      const verification = await verifySchema(pool);
      expect(verification.ok).toBe(false);
      expect(verification.errors.join(" ")).toMatch(/mrjim_sequence/i);
    } finally {
      await pool.query("DROP SEQUENCE auth.mrjim_sequence");
    }

    await pool.query("CREATE TYPE auth.ayahay_kind AS ENUM ('safe')");
    try {
      const verification = await verifySchema(pool);
      expect(verification.ok).toBe(false);
      expect(verification.errors.join(" ")).toMatch(/ayahay_kind/i);
    } finally {
      await pool.query("DROP TYPE auth.ayahay_kind");
    }

    await pool.query(
      "CREATE TRIGGER ayahay_guard BEFORE INSERT ON auth.audit_log FOR EACH ROW EXECUTE FUNCTION auth.audit_metadata_redaction_guard()",
    );
    try {
      const verification = await verifySchema(pool);
      expect(verification.ok).toBe(false);
      expect(verification.errors.join(" ")).toMatch(/ayahay_guard/i);
    } finally {
      await pool.query("DROP TRIGGER ayahay_guard ON auth.audit_log");
    }
  });

  it("rejects forbidden names on PostgreSQL partitioned indexes", async () => {
    await pool.query(
      `CREATE TABLE auth.safe_partitioned_data (
         id integer NOT NULL,
         bucket integer NOT NULL
       ) PARTITION BY RANGE (bucket)`,
    );
    try {
      await pool.query(
        `CREATE TABLE auth.safe_partitioned_data_p1
           PARTITION OF auth.safe_partitioned_data
           FOR VALUES FROM (0) TO (100)`,
      );
      await pool.query(
        "CREATE INDEX mrjim_partitioned_idx ON auth.safe_partitioned_data (bucket)",
      );

      const verification = await verifySchema(pool);
      expect(verification.ok).toBe(false);
      expect(verification.errors).toContain(
        "forbidden auth partitioned_index name exists: mrjim_partitioned_idx",
      );
    } finally {
      await pool.query("DROP TABLE auth.safe_partitioned_data CASCADE");
    }
  });

  it("fails closed on checksum mismatch and releases the advisory lock", async () => {
    const version = MIGRATIONS[0]?.version;
    const expectedChecksum = MIGRATIONS[0]?.checksum;
    if (!version || !expectedChecksum) throw new Error("Task 3 manifest is empty");
    await pool.query("UPDATE auth.schema_migrations SET checksum = repeat('0', 64) WHERE version = $1", [version]);
    try {
      await expect(migrate(pool, { direction: "up" })).rejects.toThrow(/checksum mismatch/i);
      const status = await migrationStatus(pool);
      expect(status.find((migration) => migration.version === version)?.state).toBe("checksum_mismatch");

      const client = await pool.connect();
      try {
        const result = await client.query("SELECT pg_try_advisory_lock(hashtext('auth.schema_migrations')) AS locked");
        expect(result.rows[0]?.locked).toBe(true);
        await client.query("SELECT pg_advisory_unlock(hashtext('auth.schema_migrations'))");
      } finally {
        client.release();
      }
    } finally {
      await pool.query("UPDATE auth.schema_migrations SET checksum = $1 WHERE version = $2", [expectedChecksum, version]);
    }
  });

  it("fails canonical verification after representative catalog tampering", async () => {
    const tamperCases = [
      {
        name: "column type",
        apply: "ALTER TABLE auth.users ALTER COLUMN email TYPE varchar USING email::varchar",
        restore: "ALTER TABLE auth.users ALTER COLUMN email TYPE text USING email::text",
        expected: /column/i,
      },
      {
        name: "column nullability",
        apply: "ALTER TABLE auth.users ALTER COLUMN email SET NOT NULL",
        restore: "ALTER TABLE auth.users ALTER COLUMN email DROP NOT NULL",
        expected: /column/i,
      },
      {
        name: "partial index predicate",
        apply: "DROP INDEX auth.users_email_normalized_key; CREATE UNIQUE INDEX users_email_normalized_key ON auth.users (email_normalized) WHERE email_normalized IS NULL",
        restore: "DROP INDEX auth.users_email_normalized_key; CREATE UNIQUE INDEX users_email_normalized_key ON auth.users (email_normalized) WHERE email_normalized IS NOT NULL",
        expected: /index/i,
      },
      {
        name: "check constraint expression",
        apply: "ALTER TABLE auth.users DROP CONSTRAINT users_phone_normalized_check; ALTER TABLE auth.users ADD CONSTRAINT users_phone_normalized_check CHECK (phone_normalized IS NULL OR btrim(phone_normalized) = phone_normalized)",
        restore: "ALTER TABLE auth.users DROP CONSTRAINT users_phone_normalized_check; ALTER TABLE auth.users ADD CONSTRAINT users_phone_normalized_check CHECK (phone_normalized IS NULL OR (phone_normalized = btrim(phone_normalized) AND btrim(phone_normalized) <> ''))",
        expected: /constraint/i,
      },
      {
        name: "foreign-key action",
        apply: "ALTER TABLE auth.identities DROP CONSTRAINT identities_user_id_fkey; ALTER TABLE auth.identities ADD CONSTRAINT identities_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users (id) ON DELETE RESTRICT",
        restore: "ALTER TABLE auth.identities DROP CONSTRAINT identities_user_id_fkey; ALTER TABLE auth.identities ADD CONSTRAINT identities_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users (id) ON DELETE CASCADE",
        expected: /foreign|constraint/i,
      },
      {
        name: "function volatility",
        apply: "ALTER FUNCTION auth.audit_metadata_is_safe(jsonb) VOLATILE",
        restore: "ALTER FUNCTION auth.audit_metadata_is_safe(jsonb) IMMUTABLE",
        expected: /function/i,
      },
      {
        name: "trigger enabled state",
        apply: "ALTER TABLE auth.audit_log DISABLE TRIGGER audit_log_immutable_guard",
        restore: "ALTER TABLE auth.audit_log ENABLE TRIGGER audit_log_immutable_guard",
        expected: /trigger/i,
      },
    ] as const;

    for (const tamperCase of tamperCases) {
      await pool.query(tamperCase.apply);
      try {
        const verification = await verifySchema(pool);
        expect(verification.ok, tamperCase.name).toBe(false);
        expect(verification.errors.join(" "), tamperCase.name).toMatch(tamperCase.expected);
      } finally {
        await pool.query(tamperCase.restore);
      }
      expect((await verifySchema(pool)).ok, `${tamperCase.name} restore`).toBe(true);
    }

    const originalDefinitionRows = await queryRows(
      "SELECT pg_get_functiondef('auth.audit_metadata_is_safe(jsonb)'::regprocedure) AS value",
    );
    const originalDefinition = String(originalDefinitionRows[0]?.value ?? "");
    expect(originalDefinition).toContain("audit_metadata_is_safe");
    await pool.query(`
      CREATE OR REPLACE FUNCTION auth.audit_metadata_is_safe(metadata jsonb)
      RETURNS boolean
      LANGUAGE sql
      IMMUTABLE
      PARALLEL SAFE
      SET search_path = pg_catalog, auth
      AS $$ SELECT true /* WITH RECURSIVE regexp_replace privatekey jsonb_array_elements */ $$;
    `);
    try {
      const verification = await verifySchema(pool);
      expect(verification.ok, "behavior-changing function body").toBe(false);
      expect(verification.errors.join(" "), "behavior-changing function body").toMatch(/function/i);
    } finally {
      await pool.query(originalDefinition);
    }
    expect((await verifySchema(pool)).ok, "function body restore").toBe(true);
  });

  it("rejects unknown, duplicate, gapped, and out-of-order migration history", async () => {
    await expectDatabaseError(
      () => pool.query(
        `INSERT INTO auth.schema_migrations (version, migration_order, checksum, package_version)
         VALUES ($1, 1, repeat('a', 64), $2)`,
        [MIGRATIONS[0]?.version, packageVersion],
      ),
      /schema_migrations_(pkey|migration_order)/i,
    );
    await pool.query(
      `INSERT INTO auth.schema_migrations (version, migration_order, checksum, package_version)
       VALUES ('0004_unknown', 7, repeat('a', 64), $1)`,
      [packageVersion],
    );

    try {
      await expect(migrate(pool, { direction: "up" })).rejects.toThrow(/unknown|history|order|contiguous/i);
    } finally {
      await pool.query("DELETE FROM auth.schema_migrations WHERE version = '0004_unknown'");
    }

    const originalOrders = MIGRATIONS.map((_, index) => index + 1);
    await pool.query("UPDATE auth.schema_migrations SET migration_order = migration_order + 10");
    await pool.query(
      `UPDATE auth.schema_migrations
          SET migration_order = CASE version
            WHEN '0001_core' THEN 2
            WHEN '0002_authorization' THEN 1
            WHEN '0003_oauth_operations' THEN 3
            WHEN '0004_repository_hardening' THEN 4
            WHEN '0005_oauth_callback' THEN 5
            WHEN '0006_admin_operations' THEN 6
          END`,
    );
    try {
      await expect(migrate(pool, { direction: "up" })).rejects.toThrow(/history|order|contiguous/i);
    } finally {
      await pool.query("UPDATE auth.schema_migrations SET migration_order = migration_order + 10");
      for (const [index, migration] of MIGRATIONS.entries()) {
        await pool.query(
          "UPDATE auth.schema_migrations SET migration_order = $1 WHERE version = $2",
          [originalOrders[index], migration.version],
        );
      }
    }

    await pool.query("UPDATE auth.schema_migrations SET migration_order = 8 WHERE version = '0006_admin_operations'");
    await pool.query("UPDATE auth.schema_migrations SET migration_order = 6 WHERE version = '0002_authorization'");
    await pool.query("UPDATE auth.schema_migrations SET migration_order = 7 WHERE version = '0003_oauth_operations'");
    try {
      await expect(migrate(pool, { direction: "up" })).rejects.toThrow(/history|order|contiguous/i);
    } finally {
      await pool.query("UPDATE auth.schema_migrations SET migration_order = migration_order + 10 WHERE version IN ('0002_authorization', '0003_oauth_operations')");
      await pool.query("UPDATE auth.schema_migrations SET migration_order = 2 WHERE version = '0002_authorization'");
      await pool.query("UPDATE auth.schema_migrations SET migration_order = 3 WHERE version = '0003_oauth_operations'");
      await pool.query("UPDATE auth.schema_migrations SET migration_order = 6 WHERE version = '0006_admin_operations'");
    }
  });

  it("makes concurrent migrate calls safe on the same advisory lock", async () => {
    const results = await Promise.all([
      migrate(pool, { direction: "up" }),
      migrate(pool, { direction: "up" }),
    ]);
    expect(results[0]?.applied).toEqual([]);
    expect(results[1]?.applied).toEqual([]);
    const verification = await verifySchema(pool);
    expect(verification.ok).toBe(true);
  });

  it("wins a fresh-database concurrent bootstrap race without partial state", async () => {
    const fresh = await startDisposablePostgres("mrjim-auth-task3-race");
    try {
      const results = await Promise.all([
        migrate(fresh.pool, { direction: "up" }),
        migrate(fresh.pool, { direction: "up" }),
      ]);
      expect(results.map((result) => [...result.applied].sort()).sort()).toEqual([
        [],
        MIGRATIONS.map((migration) => migration.version),
      ]);
      expect((await verifySchema(fresh.pool)).ok).toBe(true);
    } finally {
      await stopDisposablePostgres(fresh);
    }
  });

  it("keeps command status and doctor read-only while validating configuration", async () => {
    const before = await countRows("schema_migrations");
    const output: string[] = [];
    await runMigrateCommand(pool, "status", (line) => output.push(line));
    expect(output.join("\n")).toContain("0001_core");
    expect(output.join("\n")).toContain("applied");

    const report = await runDoctor(pool, {
      DATABASE_URL: localDatabaseUrl(),
      AUTH_TOKEN_HASH_KEY: "t".repeat(32),
      AUTH_ENCRYPTION_KEY: "e".repeat(32),
      AUTH_BASE_URL: "https://example.com/auth/v1",
      AUTH_SITE_URL: "https://example.com",
      AUTH_ALLOWED_REDIRECTS: "https://example.com/callback",
    });
    expect(report.ok, JSON.stringify(report)).toBe(true);
    expect(report.errors).toEqual([]);
    expect(JSON.stringify(report)).not.toContain("t".repeat(32));
    expect(await countRows("schema_migrations")).toBe(before);

    const invalidReport = await runDoctor(pool, {
      DATABASE_URL: localDatabaseUrl(),
      AUTH_TOKEN_HASH_KEY: "short",
      AUTH_ENCRYPTION_KEY: "short",
      AUTH_BASE_URL: "http://example.com/auth/v1",
    });
    expect(invalidReport.ok).toBe(false);
    expect(invalidReport.errors.join(" ")).toMatch(/key|https|redirect/i);
    expect(JSON.stringify(invalidReport)).not.toContain("short");
    expect(await countRows("schema_migrations")).toBe(before);
  });

  it("returns zero for CLI verification and nonzero for clear usage errors", async () => {
    const output: string[] = [];
    const errors: string[] = [];
    const environment = {
      DATABASE_URL: localDatabaseUrl(),
      AUTH_TOKEN_HASH_KEY: "t".repeat(32),
      AUTH_ENCRYPTION_KEY: "e".repeat(32),
      AUTH_BASE_URL: "https://example.com/auth/v1",
      AUTH_SITE_URL: "https://example.com",
      AUTH_ALLOWED_REDIRECTS: "https://example.com/callback",
    };
    await expect(runCli(["migrate", "verify"], environment, (line) => output.push(line), (line) => errors.push(line))).resolves.toBe(0);
    expect(output).toContain("schema: verified");
    expect(errors).toEqual([]);

    await expect(runCli(["migrate", "down"], environment, undefined, (line) => errors.push(line))).resolves.toBe(1);
    expect(errors.join("\n")).toContain("Usage:");
    expect(errors.join("\n")).not.toContain(environment.AUTH_TOKEN_HASH_KEY);

    const hashKey = "01".repeat(32);
    const keyOutput: string[] = [];
    const keyErrors: string[] = [];
    await expect(runCli(
      ["keys", "generate", "--kind", "secret", "--name", "task12-deploy"],
      { ...environment, MRJIM_AUTH_API_KEY_HASH_KEY: hashKey },
      (line) => keyOutput.push(line),
      (line) => keyErrors.push(line),
    )).resolves.toBe(0);
    expect(keyErrors).toEqual([]);
    expect(keyOutput).toHaveLength(1);
    expect(keyOutput[0]).toMatch(/^sk_[A-Za-z0-9_-]{43}$/u);
    const persisted = await queryRows("SELECT name, prefix, key_hash, scopes FROM auth.api_keys WHERE name = $1", ["task12-deploy"]);
    expect(persisted).toHaveLength(1);
    expect(persisted[0]).toMatchObject({ name: "task12-deploy", prefix: keyOutput[0]!.slice(0, 11), scopes: ["auth.*"] });
    expect(Buffer.from(persisted[0]!.key_hash as Buffer)).toEqual(createHmac("sha256", Buffer.from(hashKey, "hex")).update(`apikey\0${keyOutput[0]}`).digest());
    expect(JSON.stringify(persisted)).not.toContain(keyOutput[0]!);

    const invalidSecret = "do-not-echo-this-secret";
    await expect(runCli(
      ["keys", "generate", "--kind", "secret", "--name", "invalid-key"],
      { ...environment, MRJIM_AUTH_API_KEY_HASH_KEY: invalidSecret },
      undefined,
      (line) => keyErrors.push(line),
    )).resolves.toBe(1);
    expect(keyErrors.join("\n")).not.toContain(invalidSecret);
    expect(await scalar<number>("SELECT count(*)::int AS value FROM auth.api_keys WHERE name = 'invalid-key'")).toBe(0);
  });

  it.skipIf(!runSerialPackageLifecycleTests)("installs the packed package and executes its real shim-backed CLI", async () => {
    await migrate(pool, { direction: "up" });
    const consumerRoot = await mkdtemp(join(tmpdir(), "mrjim-auth-consumer-"));
    try {
      await writeFile(
        join(consumerRoot, "package.json"),
        JSON.stringify({ name: "mrjim-auth-consumer", private: true, type: "module" }, null, 2),
      );
      const packResult = await runCommandResult(
        "pnpm",
        ["--filter", "mrjim-auth", "pack", "--pack-destination", consumerRoot],
        { cwd: workspaceRoot },
      );
      expect(packResult.code, packResult.stderr).toBe(0);
      const tarballName = (await readdir(consumerRoot)).find((entry) => entry.endsWith(".tgz"));
      if (!tarballName) throw new Error("pnpm pack did not create a tarball");
      const tarball = join(consumerRoot, tarballName);
      await writeFile(
        join(consumerRoot, "package.json"),
        JSON.stringify({
          name: "mrjim-auth-consumer",
          private: true,
          type: "module",
          dependencies: { "mrjim-auth": `file:${tarball}` },
        }, null, 2),
      );

      const installResult = await runCommandResult(
        "pnpm",
        ["--dir", consumerRoot, "install", "--ignore-workspace", "--lockfile=false"],
        { cwd: workspaceRoot },
      );
      expect(installResult.code, installResult.stderr).toBe(0);
      for (const migration of MIGRATIONS) {
        await expect(
          readFile(join(consumerRoot, "node_modules/mrjim-auth/dist/postgres/migrations", migration.fileName), "utf8"),
        ).resolves.toBe(migration.sql);
      }

      const packedBoundaryResult = await runCommandResult(
        process.execPath,
        [
          "--input-type=module",
          "-e",
          `
            const root = await import("mrjim-auth");
            const server = await import("mrjim-auth/server");
            const browser = await import("mrjim-auth/client/pkce");
            const express = await import("mrjim-auth/express");
            const next = await import("mrjim-auth/nextjs");
            const nextServer = await import("mrjim-auth/nextjs/server");
            if (typeof root.createClient !== "function") throw new Error("packed root import failed");
            if (typeof server.AuthorizationService !== "function") throw new Error("packed server import failed");
            if (typeof browser.generateCodeVerifier !== "function") throw new Error("packed browser import failed");
            if (typeof express.toExpressHandler !== "function") throw new Error("packed Express adapter import failed");
            if (typeof next.createBrowserClient !== "function") throw new Error("packed Next browser adapter import failed");
            if (typeof nextServer.createServerClient !== "function") throw new Error("packed Next server adapter import failed");

            const packedOidcProvider = new server.OidcOAuthProvider({
              name: "oidc",
              clientId: "client",
              clientSecret: "secret",
              issuer: "https://issuer.example",
            });
            const originalPackedSetPrototypeOf = Object.setPrototypeOf;
            let packedPrototypeSetterCalls = 0;
            try {
              Object.setPrototypeOf = (..._args) => {
                packedPrototypeSetterCalls += 1;
                throw new Error("packed-round8-setPrototypeOf-sentinel");
              };
              const packedProviderError = new server.OAuthProviderError("provider failure");
              if (!(packedProviderError instanceof Error) || !(packedProviderError instanceof server.OAuthProviderError)) {
                throw new Error("packed OAuthProviderError prototype repair failed");
              }
              let packedOidcError;
              try {
                await packedOidcProvider.authorizationUrl({
                  clientId: "client",
                  redirectUri: "https://project.example.com/auth/callback",
                  state: "provider-state-sentinel",
                  nonce: "provider-nonce-sentinel",
                  scopes: ["openid"],
                  codeChallenge: "client-challenge",
                  codeChallengeMethod: "plain",
                });
              } catch (error) {
                packedOidcError = error;
              }
              if (!(packedOidcError instanceof server.OAuthProviderError) || String(packedOidcError).includes("packed-round8-setPrototypeOf-sentinel")) {
                throw new Error("packed OIDC error boundary failed");
              }
            } finally {
              Object.setPrototypeOf = originalPackedSetPrototypeOf;
            }
            if (packedPrototypeSetterCalls !== 0) throw new Error("packed prototype setter was consulted");

            const packedProviderService = {
              listProviders: () => [{
                name: "google",
                scopes: ["openid"],
                capabilities: { authorization_code: true, pkce: true, identity_linking: true },
                clientSecret: "packed-provider-secret-sentinel",
                token: {
                  value: "packed-provider-token-sentinel",
                  verifier: "packed-provider-verifier-sentinel",
                  code: "packed-provider-code-sentinel",
                  payload: "packed-provider-payload-sentinel",
                },
              }],
              authorize: () => ({ data: null, error: null }),
              callback: () => ({ data: null, error: null }),
              exchangeCode: () => ({ data: null, error: null }),
              listIdentities: () => ({ data: [], error: null }),
              unlinkIdentity: () => ({ data: null, error: null }),
            };
            const packedProviderResponse = server.providersRoute(packedProviderService);
            const packedProviderBody = await packedProviderResponse.text();
            if (packedProviderResponse.status !== 200 ||
                packedProviderBody.includes("packed-provider-secret-sentinel") ||
                packedProviderBody.includes("packed-provider-token-sentinel") ||
                packedProviderBody.includes("packed-provider-verifier-sentinel") ||
                packedProviderBody.includes("packed-provider-code-sentinel") ||
                packedProviderBody.includes("packed-provider-payload-sentinel")) {
              throw new Error("packed provider discovery allowlist leaked extra fields");
            }
            const packedServerProviderService = {
              ...packedProviderService,
              listProviders: () => [{
                name: "google",
                scopes: ["openid"],
                capabilities: { authorization_code: true, pkce: true, identity_linking: true },
              }],
            };

            const { createHmac: packedCreateHmac, generateKeyPairSync: packedGenerateKeyPairSync } = await import("node:crypto");
            const packedApiKey = "pk_packed_round7";
            const packedHashKey = new Uint8Array(32);
            const packedEncryptionKey = new Uint8Array(32);
            for (let packedIndex = 0; packedIndex < 32; packedIndex += 1) {
              packedHashKey[packedIndex] = packedIndex + 1;
              packedEncryptionKey[packedIndex] = packedIndex + 41;
            }
            const packedSigningPair = packedGenerateKeyPairSync("ec", { namedCurve: "P-256" });
            const packedSigningKey = packedSigningPair.privateKey.export({ type: "pkcs8", format: "pem" }).toString();
            const packedApiKeyRecord = {
              id: "00000000-0000-4000-8000-000000000904",
              prefix: packedApiKey.slice(0, 8),
              kind: "publishable",
              scopes: [],
              key_hash: packedCreateHmac("sha256", packedHashKey).update("apikey" + String.fromCharCode(0) + packedApiKey).digest(),
              expires_at: null,
              revoked_at: null,
            };
            const packedNoop = async () => undefined;
            const packedRepository = {
              transaction: async (callback) => callback(packedRepository),
              users: { findById: packedNoop, findByIdForUpdate: packedNoop, findByNormalizedEmail: packedNoop, findByNormalizedEmailForUpdate: packedNoop, findByNormalizedPhoneForUpdate: packedNoop, create: packedNoop, createWithId: packedNoop, createIfAvailable: packedNoop, update: packedNoop, softDelete: packedNoop },
              identities: { findByProviderSubject: packedNoop, listByUserId: packedNoop, create: packedNoop, createIfAvailable: packedNoop, deleteById: packedNoop },
              passwordCredentials: { findByUserId: packedNoop, upsert: packedNoop, deleteByUserId: packedNoop },
              sessions: { create: packedNoop, findByIdForUpdate: packedNoop, findRefreshForUpdate: packedNoop, rotate: packedNoop, revokeSession: packedNoop, revokeFamily: packedNoop, revokeUserSessions: packedNoop },
              oneTimeTokens: { issue: packedNoop, consume: packedNoop, consumeBound: packedNoop, recordFailure: packedNoop },
              oauthStates: { create: packedNoop, consume: packedNoop },
              authorization: { effectivePermissions: packedNoop, assignRole: packedNoop, unassignRole: packedNoop, setRolePermissions: packedNoop, setRoleInheritance: packedNoop },
              roles: { list: packedNoop, findById: packedNoop, create: packedNoop, update: packedNoop, delete: packedNoop },
              permissions: { list: packedNoop, findById: packedNoop, create: packedNoop, update: packedNoop, delete: packedNoop },
              operations: { appendAudit: packedNoop, findApiKeyByHash: async () => packedApiKeyRecord },
            };
            const packedServer = server.createAuthServer({
              environment: "test",
              baseUrl: "https://project.example.com/auth/v1",
              siteUrl: "https://project.example.com",
              database: packedRepository,
              signingKeys: { issuer: "https://project.example.com/auth/v1", audience: "project", activeKeyId: "test", keys: { test: packedSigningKey } },
              secrets: { tokenHashKey: packedHashKey, encryptionKey: packedEncryptionKey },
              email: { send: packedNoop },
              redirects: { allowed: ["https://project.example.com/auth/callback"] },
              services: {
                users: { signUp: packedNoop, signIn: packedNoop, signInWithOtp: packedNoop, verifyOtp: packedNoop, resetPasswordForEmail: packedNoop, resetPassword: packedNoop, resend: packedNoop, updateUser: packedNoop },
                sessions: { refresh: packedNoop, authorizeSession: packedNoop, signOut: packedNoop, revokeRefreshToken: packedNoop },
                tokens: { verifyAccessToken: packedNoop, jwks: packedNoop },
                authorization: { getPermissions: packedNoop, authorize: packedNoop },
                oauth: packedServerProviderService,
              },
            });
            const packedBaselineResponse = await packedServer.handle(new Request("https://project.example.com/auth/v1/providers", { headers: { apikey: packedApiKey } }));
            if (packedBaselineResponse.status !== 200) throw new Error("packed AuthServer baseline failed: " + packedBaselineResponse.status);
            const originalPackedRouteSetPrototypeOf = Object.setPrototypeOf;
            let packedRouteSetterCalls = 0;
            let packedInvalidOidcResponse;
            try {
              Object.setPrototypeOf = (..._args) => {
                packedRouteSetterCalls += 1;
                throw new Error("packed-round8-http-setPrototypeOf-sentinel");
              };
              packedInvalidOidcResponse = await packedServer.handle(new Request("https://project.example.com/auth/v1/authorize?provider=google&code_challenge=client-challenge&code_challenge_method=plain", {
                headers: { apikey: packedApiKey, "x-request-id": "packed-round8-request" },
              }));
            } finally {
              Object.setPrototypeOf = originalPackedRouteSetPrototypeOf;
            }
            const packedInvalidOidcBody = await packedInvalidOidcResponse.text();
            if (packedRouteSetterCalls !== 0 || packedInvalidOidcResponse.status !== 400 ||
                !packedInvalidOidcBody.includes('"code":"invalid_request"') ||
                !packedInvalidOidcBody.includes('"request_id":"packed-round8-request"') ||
                packedInvalidOidcBody.includes("packed-round8-http-setPrototypeOf-sentinel")) {
              throw new Error("packed AuthServer prototype-setting error boundary failed");
            }
            const originalPackedSetDelete = Set.prototype.delete;
            let packedServerResponse;
            try {
              Set.prototype.delete = () => { throw new Error("packed-set-delete-sentinel"); };
              packedServerResponse = await packedServer.handle(new Request("https://project.example.com/auth/v1/providers", { headers: { apikey: packedApiKey } }));
            } finally {
              Set.prototype.delete = originalPackedSetDelete;
            }
            if (packedServerResponse?.status !== 200) throw new Error("packed AuthServer Set.delete boundary failed: " + String(packedServerResponse?.status ?? "none"));
            const packedServerBody = await packedServerResponse.text();
            if (packedServerBody.includes("packed-set-delete-sentinel")) {
              throw new Error("packed AuthServer intrinsic sentinel escaped");
            }
            const user = {
              user_id: "00000000-0000-4000-8000-000000000001",
              request_id: "packed-request",
            };
            const permission = {
              id: "00000000-0000-4000-8000-000000000010",
              key: "invoice.read",
              resource: "invoice",
              action: "read",
              description: null,
              created_at: "2026-08-11T00:00:00.000Z",
              updated_at: "2026-08-11T00:00:00.000Z",
            };
            const genuine = server.createAuthorizationRequestContext(user);
            if (genuine === null) throw new Error("packed context creation failed");
            const forged = Object.create(Object.getPrototypeOf(genuine));
            Object.defineProperty(forged, "subject", {
              configurable: true,
              enumerable: true,
              value: genuine.subject,
              writable: false,
            });
            const symbols = Object.getOwnPropertySymbols(genuine);
            for (const symbol of symbols) {
              const descriptor = Object.getOwnPropertyDescriptor(genuine, symbol);
              if (descriptor !== undefined) Object.defineProperty(forged, symbol, descriptor);
            }
            const loaderSymbol = symbols.find((symbol) => {
              const descriptor = Object.getOwnPropertyDescriptor(genuine, symbol);
              return descriptor !== undefined && Object.prototype.hasOwnProperty.call(descriptor, "value") && typeof descriptor.value === "function";
            });
            if (loaderSymbol !== undefined) {
              Object.defineProperty(forged, loaderSymbol, {
                configurable: true,
                enumerable: false,
                value: async () => ["invoice.read"],
                writable: false,
              });
            }

            const emptyService = new server.AuthorizationService({
              repository: { authorization: { effectivePermissions: async () => [] } },
              clock: () => new Date("2026-08-11T00:00:00.000Z"),
            });
            let forgedRejected = false;
            try {
              await emptyService.authorize(user, { all: ["invoice.read"] }, forged);
            } catch (error) {
              forgedRejected = error?.code === "insufficient_permission";
            }
            if (!forgedRejected) throw new Error("packed forged context was accepted");

            let emptyReads = 0;
            const grantService = new server.AuthorizationService({
              repository: { authorization: { effectivePermissions: async () => [permission] } },
              clock: () => new Date("2026-08-11T00:00:00.000Z"),
            });
            const countingEmptyService = new server.AuthorizationService({
              repository: { authorization: { effectivePermissions: async () => { emptyReads += 1; return []; } } },
              clock: () => new Date("2026-08-11T00:00:00.000Z"),
            });
            const context = server.createAuthorizationRequestContext(user);
            if (context === null) throw new Error("packed second context creation failed");
            await grantService.authorize(user, { all: ["invoice.read"] }, context);
            let denied = false;
            try {
              await countingEmptyService.authorize(user, { all: ["invoice.read"] }, context);
            } catch (error) {
              denied = error?.code === "insufficient_permission";
            }
            if (!denied || emptyReads !== 1) throw new Error("packed context cache crossed service boundaries");

            const resolvingThenable = { then(resolve) { resolve([permission]); } };
            const directThenableService = new server.AuthorizationService({
              repository: { authorization: { effectivePermissions: () => resolvingThenable } },
              clock: () => new Date("2026-08-11T00:00:00.000Z"),
            });
            let directThenableRejected = false;
            try {
              await directThenableService.authorize(user, { all: ["invoice.read"] });
            } catch (error) {
              directThenableRejected = error?.code === "insufficient_permission";
            }
            if (!directThenableRejected) throw new Error("packed non-native thenable was accepted");

            let getterReads = 0;
            const getterThenable = {};
            Object.defineProperty(getterThenable, "then", {
              configurable: true,
              get() {
                getterReads += 1;
                return (resolve) => resolve([permission]);
              },
            });
            const getterThenableService = new server.AuthorizationService({
              repository: { authorization: { effectivePermissions: () => getterThenable } },
              clock: () => new Date("2026-08-11T00:00:00.000Z"),
            });
            let getterThenableRejected = false;
            try {
              await getterThenableService.authorize(user, { all: ["invoice.read"] });
            } catch (error) {
              getterThenableRejected = error?.code === "insufficient_permission";
            }
            if (!getterThenableRejected || getterReads !== 0) throw new Error("packed thenable getter was observed");

            const syncGrantService = new server.AuthorizationService({
              repository: { authorization: { effectivePermissions: () => [permission] } },
              clock: () => new Date("2026-08-11T00:00:00.000Z"),
            });
            let pollutedThenRejected = false;
            await withObjectPrototypeProperty("then", {
              configurable: true,
              enumerable: false,
              value(resolve) { resolve([permission]); },
              writable: true,
            }, async () => {
              try {
                await syncGrantService.authorize(user, { all: ["invoice.read"] });
              } catch (error) {
                pollutedThenRejected = error?.code === "insufficient_permission";
              }
            });
            if (!pollutedThenRejected) throw new Error("packed Object.prototype.then bypassed validation");

            let rejectedThenableRejected = false;
            try {
              await new server.AuthorizationService({
                repository: { authorization: { effectivePermissions: () => ({ then(_resolve, reject) { reject(new Error("thenable rejection")); } }) } },
                clock: () => new Date("2026-08-11T00:00:00.000Z"),
              }).authorize(user, { all: ["invoice.read"] });
            } catch (error) {
              rejectedThenableRejected = error?.code === "insufficient_permission";
            }
            if (!rejectedThenableRejected) throw new Error("packed rejected thenable escaped");

            let nativePromiseRejected = false;
            try {
              await new server.AuthorizationService({
                repository: { authorization: { effectivePermissions: () => Promise.resolve([permission]) } },
                clock: () => new Date("2026-08-11T00:00:00.000Z"),
              }).authorize(user, { all: ["invoice.read"] });
            } catch {
              nativePromiseRejected = true;
            }
            if (nativePromiseRejected) throw new Error("packed native Promise was rejected");

            let speciesReads = 0;
            class ForgedPromise extends Promise {
              static get [Symbol.species]() {
                speciesReads += 1;
                return Promise;
              }
            }
            const subclassPromise = new ForgedPromise((resolve) => resolve([permission]));
            let subclassRejected = false;
            try {
              await new server.AuthorizationService({
                repository: { authorization: { effectivePermissions: () => subclassPromise } },
                clock: () => new Date("2026-08-11T00:00:00.000Z"),
              }).authorize(user, { all: ["invoice.read"] });
            } catch (error) {
              subclassRejected = error?.code === "insufficient_permission";
            }
            if (!subclassRejected || speciesReads !== 0) throw new Error("packed Promise subclass/species was observed");

            let constructorReads = 0;
            const constructorPromise = Promise.resolve([permission]);
            Object.defineProperty(constructorPromise, "constructor", {
              configurable: true,
              get() {
                constructorReads += 1;
                return Promise;
              },
            });
            let constructorRejected = false;
            try {
              await new server.AuthorizationService({
                repository: { authorization: { effectivePermissions: () => constructorPromise } },
                clock: () => new Date("2026-08-11T00:00:00.000Z"),
              }).authorize(user, { all: ["invoice.read"] });
            } catch (error) {
              constructorRejected = error?.code === "insufficient_permission";
            }
            if (!constructorRejected || constructorReads !== 0) throw new Error("packed Promise constructor was observed");

            let nativeRejectionHandled = false;
            try {
              await new server.AuthorizationService({
                repository: { authorization: { effectivePermissions: () => Promise.reject(new Error("native rejection")) } },
                clock: () => new Date("2026-08-11T00:00:00.000Z"),
              }).authorize(user, { all: ["invoice.read"] });
            } catch (error) {
              nativeRejectionHandled = error?.code === "insufficient_permission";
            }
            if (!nativeRejectionHandled) throw new Error("packed native Promise rejection escaped");

            let rebasedSpeciesReads = 0;
            let rebasedConstructorReads = 0;
            let rebasedThenReads = 0;
            let rebasedSettlementThenReads = 0;
            class RebasedPromise extends Promise {
              static get [Symbol.species]() {
                rebasedSpeciesReads += 1;
                return Promise;
              }
            }
            Object.defineProperty(RebasedPromise.prototype, "constructor", {
              configurable: true,
              get() {
                rebasedConstructorReads += 1;
                throw new Error("packed rebased constructor hook must not run");
              },
            });
            Object.defineProperty(RebasedPromise.prototype, "then", {
              configurable: true,
              get() {
                rebasedThenReads += 1;
                throw new Error("packed rebased then hook must not run");
              },
            });
            let settleRebased;
            const rebasedSettlement = {};
            const rebasedPromise = new RebasedPromise((resolve) => { settleRebased = resolve; });
            const rebasedService = new server.AuthorizationService({
              repository: {
                authorization: {
                  effectivePermissions: () => {
                    Object.setPrototypeOf(rebasedPromise, Promise.prototype);
                    queueMicrotask(() => {
                      settleRebased(rebasedSettlement);
                      Object.defineProperty(rebasedSettlement, "then", {
                        configurable: true,
                        get() {
                          rebasedSettlementThenReads += 1;
                          throw new Error("packed settlement then hook must not run");
                        },
                      });
                    });
                    return rebasedPromise;
                  },
                },
              },
              clock: () => new Date("2026-08-11T00:00:00.000Z"),
            });
            let rebasedRejected = false;
            try {
              await rebasedService.authorize(user, { all: ["invoice.read"] });
            } catch (error) {
              rebasedRejected = error?.code === "insufficient_permission";
            }
            if (!rebasedRejected || rebasedSpeciesReads !== 0 || rebasedConstructorReads !== 0 || rebasedThenReads !== 0 || rebasedSettlementThenReads !== 0) {
              throw new Error("packed rebased Promise crossed the provenance boundary");
            }

            const largePermissions = new Array(100000);
            for (let index = 0; index < largePermissions.length; index += 1) {
              const resource = "resource_" + index.toString(36);
              largePermissions[index] = {
                id: permission.id,
                key: resource + ".read",
                resource,
                action: "read",
                description: null,
                created_at: permission.created_at,
                updated_at: permission.updated_at,
              };
            }
            const largeService = new server.AuthorizationService({
              repository: { authorization: { effectivePermissions: async () => largePermissions } },
              clock: () => new Date("2026-08-11T00:00:00.000Z"),
            });
            const largeResult = await largeService.getPermissions(user.user_id);
            if (largeResult.length !== 100000 || largeResult[0] !== "resource_0.read" || largeResult[99999] !== "resource_zzz.read") {
              throw new Error("packed indexed permission result was not deterministic");
            }

            async function withObjectPrototypeProperty(name, descriptor, callback) {
              const original = Object.getOwnPropertyDescriptor(Object.prototype, name);
              Object.defineProperty(Object.prototype, name, descriptor);
              try {
                return await callback();
              } finally {
                if (original === undefined) {
                  Reflect.deleteProperty(Object.prototype, name);
                } else {
                  Object.defineProperty(Object.prototype, name, original);
                }
              }
            }

            const publicArrayMarker = (value, expected) => {
              if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) return "bad";
              const spread = [...value];
              const loop = [];
              for (const key of value) loop.push(key);
              const mapped = value.map((key) => key);
              const iteratorResult = value[Symbol.iterator]().next();
              const included = expected.length === 0
                ? value.includes("invoice.read") === false
                : value.includes(expected[0]);
              return spread.length === expected.length &&
                loop.length === expected.length &&
                mapped.length === expected.length &&
                iteratorResult.value === expected[0] &&
                included
                ? "ok"
                : "bad";
            };
            const shieldedPublicRows = [permission];
            Object.setPrototypeOf(shieldedPublicRows, null);
            const shieldedEmptyPublicRows = [];
            Object.setPrototypeOf(shieldedEmptyPublicRows, null);
            const publicService = new server.AuthorizationService({
              repository: { authorization: { effectivePermissions: () => shieldedPublicRows } },
              clock: () => new Date("2026-08-11T00:00:00.000Z"),
            });
            const emptyPublicService = new server.AuthorizationService({
              repository: { authorization: { effectivePermissions: () => shieldedEmptyPublicRows } },
              clock: () => new Date("2026-08-11T00:00:00.000Z"),
            });
            const publicResult = await publicService.getPermissions(user.user_id);
            const publicResultCopy = await publicService.getPermissions(user.user_id);
            if (
              publicArrayMarker(publicResult, ["invoice.read"]) !== "ok" ||
              publicResult === publicResultCopy ||
              !Object.isFrozen(publicResult) ||
              Object.getOwnPropertyDescriptor(publicResult, "then")?.value !== undefined ||
              Object.getOwnPropertyDescriptor(publicResult, "then")?.enumerable !== false ||
              Reflect.set(publicResult, "0", "forged")
            ) throw new Error("packed public permission array contract failed");
            const emptyPublicResult = await emptyPublicService.getPermissions(user.user_id);
            const invalidPublicResult = await emptyPublicService.getPermissions("not-a-uuid");
            if (
              publicArrayMarker(emptyPublicResult, []) !== "ok" ||
              publicArrayMarker(invalidPublicResult, []) !== "ok" ||
              !Object.isFrozen(emptyPublicResult) ||
              Reflect.set(emptyPublicResult, "0", "forged")
            ) throw new Error("packed empty public permission array contract failed");

            const scalarUnderThenPollution = async (target, service, expected) => {
              const original = Object.getOwnPropertyDescriptor(target, "then");
              Object.defineProperty(target, "then", {
                configurable: true,
                enumerable: false,
                value(resolve) { resolve("polluted"); },
                writable: true,
              });
              try {
                const resultPromise = service.getPermissions(user.user_id);
                return await resultPromise.then((result) => publicArrayMarker(result, expected));
              } finally {
                if (original === undefined) Reflect.deleteProperty(target, "then");
                else Object.defineProperty(target, "then", original);
              }
            };
            if (await scalarUnderThenPollution(Object.prototype, publicService, ["invoice.read"]) !== "ok") {
              throw new Error("packed Object.prototype.then public array boundary failed");
            }
            if (await scalarUnderThenPollution(Array.prototype, publicService, ["invoice.read"]) !== "ok") {
              throw new Error("packed Array.prototype.then public array boundary failed");
            }
            if (await scalarUnderThenPollution(Object.prototype, emptyPublicService, []) !== "ok") {
              throw new Error("packed Object.prototype.then empty array boundary failed");
            }
            if (await scalarUnderThenPollution(Array.prototype, emptyPublicService, []) !== "ok") {
              throw new Error("packed Array.prototype.then empty array boundary failed");
            }

            const scopedOnlyService = new server.AuthorizationService({
              repository: { authorization: { effectivePermissions: async (_userId, scope) => scope?.type === "tenant" && scope.id === "tenant_1" ? [permission] : [] } },
              clock: () => new Date("2026-08-11T00:00:00.000Z"),
            });
            let unscopedRejected = false;
            await withObjectPrototypeProperty("scope", { configurable: true, enumerable: false, value: { type: "tenant", id: "tenant_1" }, writable: true }, async () => {
              try {
                await scopedOnlyService.authorize(user, { all: ["invoice.read"] });
              } catch (error) {
                unscopedRejected = error?.code === "insufficient_permission";
              }
            });
            if (!unscopedRejected) throw new Error("packed normalized requirement inherited scope");

            let pollutionPassed = true;
            await withObjectPrototypeProperty("any", { configurable: true, enumerable: false, value: ["secret.read"], writable: true }, async () => {
              try {
                await grantService.authorize(user, { all: ["invoice.read"] });
              } catch {
                pollutionPassed = false;
              }
            });
            await withObjectPrototypeProperty("all", { configurable: true, enumerable: false, value: ["secret.read"], writable: true }, async () => {
              try {
                await grantService.authorize(user, { any: ["invoice.read"] });
              } catch {
                pollutionPassed = false;
              }
            });
            for (const name of ["scope", "any", "all"]) {
              await withObjectPrototypeProperty(name, { configurable: true, enumerable: false, get() { throw new Error("packed inherited requirement getter"); } }, async () => {
                try {
                  await grantService.authorize(user, name === "all" ? { any: ["invoice.read"] } : { all: ["invoice.read"] });
                } catch {
                  pollutionPassed = false;
                }
              });
            }
            if (!pollutionPassed) throw new Error("packed normalized requirement inherited any/all");

            const deniedService = new server.AuthorizationService({
              repository: { authorization: { effectivePermissions: async () => [] } },
              clock: () => new Date("2026-08-11T00:00:00.000Z"),
            });
            let pollutedRequestError;
            await withObjectPrototypeProperty("request_id", { configurable: true, enumerable: false, value: "x".repeat(1000), writable: true }, async () => {
              try {
                await deniedService.authorize({ user_id: user.user_id }, { all: ["invoice.read"] });
              } catch (error) {
                pollutedRequestError = error;
              }
            });
            if (pollutedRequestError?.code !== "insufficient_permission" || pollutedRequestError.request_id.length > 128) {
              throw new Error("packed request id was inherited or unbounded");
            }
            let inheritedRequestGetterError;
            await withObjectPrototypeProperty("request_id", { configurable: true, enumerable: false, get() { throw new Error("packed inherited request id getter"); } }, async () => {
              try {
                await deniedService.authorize({ user_id: user.user_id }, { all: ["invoice.read"] });
              } catch (error) {
                inheritedRequestGetterError = error;
              }
            });
            if (inheritedRequestGetterError?.code !== "insufficient_permission" || inheritedRequestGetterError.request_id.length > 128) {
              throw new Error("packed inherited request id getter escaped");
            }
            const ownRequestSubject = { user_id: user.user_id };
            Object.defineProperty(ownRequestSubject, "request_id", { configurable: true, get() { throw new Error("packed own request id getter"); } });
            let accessorRequestError;
            try {
              await deniedService.authorize(ownRequestSubject, { all: ["invoice.read"] });
            } catch (error) {
              accessorRequestError = error;
            }
            if (accessorRequestError?.code !== "insufficient_permission" || accessorRequestError.request_id.length > 128) {
              throw new Error("packed own request id getter escaped");
            }
            let validRequestError;
            try {
              await deniedService.authorize({ user_id: user.user_id, request_id: "packed-valid" }, { all: ["invoice.read"] });
            } catch (error) {
              validRequestError = error;
            }
            if (validRequestError?.code !== "insufficient_permission" || validRequestError.request_id !== "packed-valid") {
              throw new Error("packed valid request id was not preserved");
            }

            const routeService = new server.AuthorizationService({
              repository: { authorization: { effectivePermissions: async () => [permission] } },
              clock: () => new Date("2026-08-11T00:00:00.000Z"),
            });
            const routeUnknownRequest = new Request("https://project.example.com/user/permissions?unknown=grant");
            const routeDuplicateRequest = new Request("https://project.example.com/user/permissions?scope_type=tenant&scope_type=other&scope_id=one");
            const originalKeys = URLSearchParams.prototype.keys;
            const iterator = originalKeys.call(new URLSearchParams("unknown=grant"));
            const iteratorPrototype = Object.getPrototypeOf(iterator);
            const originalNext = iteratorPrototype.next;
            try {
              URLSearchParams.prototype.keys = (() => { throw new Error("packed keys tampered"); });
              iteratorPrototype.next = () => ({ done: true, value: undefined });
              const unknownResponse = await server.permissionsRoute(routeService, routeUnknownRequest, user);
              const duplicateResponse = await server.permissionsRoute(routeService, routeDuplicateRequest, user);
              if (unknownResponse.status !== 400 || duplicateResponse.status !== 400) throw new Error("packed query iterator tampering bypassed validation");
            } finally {
              URLSearchParams.prototype.keys = originalKeys;
              iteratorPrototype.next = originalNext;
            }
            const nulRequest = new Request("https://project.example.com/user/permissions?scope_type=tenant&scope_id=tenant%00one");
            const originalIncludes = String.prototype.includes;
            try {
              String.prototype.includes = () => false;
              const nulResponse = await server.permissionsRoute(routeService, nulRequest, user);
              if (nulResponse.status !== 400) throw new Error("packed NUL scope validation bypassed");
            } finally {
              String.prototype.includes = originalIncludes;
            }

            const originalRegExpTest = RegExp.prototype.test;
            const originalRegExpExec = RegExp.prototype.exec;
            const regexpCases = [
              ["test", () => true],
              ["test", () => false],
              ["test", () => { throw new Error("packed test tampered"); }],
              ["exec", () => ["forged"]],
              ["exec", () => null],
              ["exec", () => { throw new Error("packed exec tampered"); }],
            ];
            for (let caseIndex = 0; caseIndex < regexpCases.length; caseIndex += 1) {
              const [target, value] = regexpCases[caseIndex];
              try {
                if (target === "test") RegExp.prototype.test = value;
                else RegExp.prototype.exec = value;
                let invalidRequestError;
                try {
                  await deniedService.authorize({ user_id: user.user_id, request_id: "x".repeat(129) }, { all: ["invoice.read"] });
                } catch (error) {
                  invalidRequestError = error;
                }
                if (invalidRequestError?.code !== "insufficient_permission" || invalidRequestError.request_id.length > 128) {
                  throw new Error("packed manual request id validator failed");
                }
                await grantService.authorize({ user_id: user.user_id, request_id: "A_valid-1" }, { all: ["invoice.read"] });
                if (caseIndex === 3) {
                  const uppercaseResponse = await server.permissionsRoute(routeService, new Request("https://project.example.com/user/permissions?scope_type=TENANT&scope_id=one"), user);
                  if (uppercaseResponse.status !== 400) throw new Error("packed manual scope type validator failed");
                  const validScopeResponse = await server.permissionsRoute(routeService, new Request("https://project.example.com/user/permissions?scope_type=tenant&scope_id=one"), user);
                  if (validScopeResponse.status !== 200) throw new Error("packed valid scope type rejected");
                }
              } finally {
                RegExp.prototype.test = originalRegExpTest;
                RegExp.prototype.exec = originalRegExpExec;
              }
            }

            const nativeURL = URL;
            const nativeRequest = Request;
            const nativeHeaders = Headers;
            const postRequest = new Request("https://project.example.com/user/permissions", { method: "POST" });
            const unknownAccessorRequest = new Request(
              "https://project.example.com/user/permissions?unknown=grant",
              { headers: { "x-request-id": "packed-original" } },
            );
            const requestMethodDescriptor = Object.getOwnPropertyDescriptor(nativeRequest.prototype, "method");
            const requestUrlDescriptor = Object.getOwnPropertyDescriptor(nativeRequest.prototype, "url");
            const requestHeadersDescriptor = Object.getOwnPropertyDescriptor(nativeRequest.prototype, "headers");
            const urlSearchParamsDescriptor = Object.getOwnPropertyDescriptor(nativeURL.prototype, "searchParams");
            const urlSearchDescriptor = Object.getOwnPropertyDescriptor(nativeURL.prototype, "search");
            const headersGetDescriptor = Object.getOwnPropertyDescriptor(nativeHeaders.prototype, "get");
            const accessorOriginalKeys = URLSearchParams.prototype.keys;
            const accessorIterator = accessorOriginalKeys.call(new URLSearchParams("unknown=grant"));
            const accessorIteratorPrototype = Object.getPrototypeOf(accessorIterator);
            const accessorOriginalNext = accessorIteratorPrototype.next;
            const globalURLDescriptor = Object.getOwnPropertyDescriptor(globalThis, "URL");
            const restoreDescriptor = (target, name, descriptor) => {
              if (descriptor === undefined) Reflect.deleteProperty(target, name);
              else Object.defineProperty(target, name, descriptor);
            };
            try {
              Object.defineProperty(nativeRequest.prototype, "method", { configurable: true, get: () => "GET" });
              Object.defineProperty(nativeRequest.prototype, "url", { configurable: true, get: () => "https://project.example.com/user/permissions" });
              Object.defineProperty(nativeRequest.prototype, "headers", { configurable: true, get: () => new nativeHeaders({ "x-request-id": "packed-forged" }) });
              Object.defineProperty(nativeURL.prototype, "searchParams", { configurable: true, get: () => new URLSearchParams() });
              Object.defineProperty(nativeURL.prototype, "search", { configurable: true, get: () => "" });
              Object.defineProperty(nativeHeaders.prototype, "get", { configurable: true, writable: true, value: () => "packed-forged" });
              URLSearchParams.prototype.keys = (() => (function* emptyKeys() {})());
              accessorIteratorPrototype.next = () => ({ done: true, value: undefined });
              const FakeURL = function FakeURL() { return Object.create(nativeURL.prototype); };
              Object.defineProperty(globalThis, "URL", { configurable: true, writable: true, value: FakeURL });

              const postResponse = await server.permissionsRoute(routeService, postRequest, user);
              if (postResponse.status !== 405) throw new Error("packed POST was converted to GET");
              const unknownResponse = await server.permissionsRoute(routeService, unknownAccessorRequest, user);
              if (unknownResponse.status !== 400) throw new Error("packed request accessor hid unknown query");
              const unknownBody = await unknownResponse.json();
              if (unknownBody.error?.request_id !== "packed-original") throw new Error("packed request accessor changed request id");
            } finally {
              restoreDescriptor(nativeRequest.prototype, "method", requestMethodDescriptor);
              restoreDescriptor(nativeRequest.prototype, "url", requestUrlDescriptor);
              restoreDescriptor(nativeRequest.prototype, "headers", requestHeadersDescriptor);
              restoreDescriptor(nativeURL.prototype, "searchParams", urlSearchParamsDescriptor);
              restoreDescriptor(nativeURL.prototype, "search", urlSearchDescriptor);
              restoreDescriptor(nativeHeaders.prototype, "get", headersGetDescriptor);
              URLSearchParams.prototype.keys = accessorOriginalKeys;
              accessorIteratorPrototype.next = accessorOriginalNext;
              restoreDescriptor(globalThis, "URL", globalURLDescriptor);
            }

            const shieldedResponseRequests = [
              { request: new Request("https://project.example.com/user/permissions"), subject: user },
              { request: new Request("https://project.example.com/user/permissions?unknown=grant"), subject: user },
              { request: new Request("https://project.example.com/user/permissions", { method: "POST" }), subject: user },
              { request: new Request("https://project.example.com/user/permissions"), subject: undefined },
            ];
            async function runResponseSet() {
              const results = [];
              for (let index = 0; index < shieldedResponseRequests.length; index += 1) {
                const entry = shieldedResponseRequests[index];
                try {
                  const response = await server.permissionsRoute(routeService, entry.request, entry.subject);
                  results.push({ status: response.status, text: await response.text() });
                } catch (error) {
                  results.push({ error });
                }
              }
              return results;
            }
            function assertResponseSet(results) {
              if (results.length !== 4) throw new Error("packed response count changed");
              for (let index = 0; index < results.length; index += 1) {
                if (results[index].error !== undefined) throw new Error("packed response primitive escaped");
              }
              if (results[0].status !== 200 || results[1].status !== 400 || results[2].status !== 405 || results[3].status !== 401) {
                throw new Error("packed response status changed");
              }
              const successBody = JSON.parse(results[0].text);
              if (successBody.data?.permissions?.length !== 1 || successBody.data.permissions[0] !== "invoice.read" || successBody.error !== null) {
                throw new Error("packed success response body was forged");
              }
              const invalidBody = JSON.parse(results[1].text);
              const methodBody = JSON.parse(results[2].text);
              const unauthorizedBody = JSON.parse(results[3].text);
              if (invalidBody.error?.code !== "invalid_request" || methodBody.error?.code !== "invalid_request" || unauthorizedBody.error?.code !== "unauthorized") {
                throw new Error("packed error response body was forged");
              }
            }
            const responseDescriptor = Object.getOwnPropertyDescriptor(globalThis, "Response");
            const stringify = JSON.stringify;
            try {
              Object.defineProperty(globalThis, "Response", {
                configurable: true,
                writable: true,
                value: class ForgedResponse {
                  constructor() { throw new Error("packed global Response was used"); }
                },
              });
              let responseResults = await runResponseSet();
              restoreDescriptor(globalThis, "Response", responseDescriptor);
              assertResponseSet(responseResults);

              JSON.stringify = () => { throw new Error("packed global JSON.stringify was used"); };
              responseResults = await runResponseSet();
              JSON.stringify = stringify;
              assertResponseSet(responseResults);

              responseResults = await withObjectPrototypeProperty("toJSON", {
                configurable: true,
                enumerable: false,
                value: () => "forged packed response",
                writable: true,
              }, runResponseSet);
              assertResponseSet(responseResults);
              responseResults = await withObjectPrototypeProperty("toJSON", {
                configurable: true,
                enumerable: false,
                get() { throw new Error("packed Object.prototype.toJSON was used"); },
              }, runResponseSet);
              assertResponseSet(responseResults);
            } finally {
              restoreDescriptor(globalThis, "Response", responseDescriptor);
              JSON.stringify = stringify;
            }

            const malformedRouteRequest = new Request("https://project.example.com/user/permissions", {
              headers: { "x-request-id": "packed-internal" },
            });
            const throwingLength = new Proxy([], {
              getOwnPropertyDescriptor(target, property) {
                if (property === "length") throw new Error("packed secret length accessor");
                return Reflect.getOwnPropertyDescriptor(target, property);
              },
            });
            let throwingIndexReads = 0;
            const throwingIndex = [];
            Object.defineProperty(throwingIndex, "0", {
              configurable: true,
              get() {
                throwingIndexReads += 1;
                throw new Error("packed secret index accessor");
              },
            });
            let secretAccessorReads = 0;
            const secretAccessor = [];
            Object.defineProperty(secretAccessor, "0", {
              configurable: true,
              get() {
                secretAccessorReads += 1;
                return "secret.read";
              },
            });
            const sparse = new Array(1);
            const oversized = [];
            oversized.length = 100001;
            const malformedRouteServices = [
              () => null,
              () => Promise.reject(new Error("packed secret adapter rejection")),
              () => Promise.resolve(throwingLength),
              () => throwingIndex,
              () => secretAccessor,
              () => [123],
              () => sparse,
              () => oversized,
            ];
            for (let caseIndex = 0; caseIndex < malformedRouteServices.length; caseIndex += 1) {
              const malformedService = { getPermissions: malformedRouteServices[caseIndex] };
              let malformedResponse;
              let malformedThrown;
              try {
                malformedResponse = await server.permissionsRoute(malformedService, malformedRouteRequest, user);
              } catch (error) {
                malformedThrown = error;
              }
              if (malformedThrown !== undefined || malformedResponse?.status !== 500) {
                throw new Error("packed malformed permission output escaped");
              }
              const malformedBody = await malformedResponse.text();
              if (!malformedBody.includes('"code":"internal_error"') ||
                  !malformedBody.includes('"status":500') ||
                  !malformedBody.includes('"request_id":"packed-internal"') ||
                  !malformedBody.includes("Internal authentication error") ||
                  malformedBody.includes("secret")) {
                throw new Error("packed malformed permission output was leaked");
              }
            }
            if (throwingIndexReads !== 0 || secretAccessorReads !== 0) {
              throw new Error("packed route permission accessors were invoked");
            }

            const directRouteService = (value) => ({ getPermissions: () => value });
            const malformedRouteService = { getPermissions: () => null };
            const packedRouteMarker = async (serviceLike) => {
              try {
                const result = await server.permissionsRoute(serviceLike, malformedRouteRequest, user);
                if (!(result instanceof Response)) {
                  return "non-response:" + (Array.isArray(result) ? result[0] : typeof result);
                }
                const body = await result.text();
                return String(result.status) + ":" + body.includes('"code":"internal_error"') + ":" + body.includes("secret.read") + ":" + body.includes("invoice.read");
              } catch (error) {
                return "throw:" + (error?.message ?? "unknown");
              }
            };
            const packedRouteResponse = (serviceLike) => server.permissionsRoute(serviceLike, malformedRouteRequest, user);
            if (await packedRouteMarker(directRouteService(["invoice.read"])) !== "200:false:false:true" ||
                await packedRouteMarker(directRouteService([])) !== "200:false:false:false") {
              throw new Error("packed valid direct route array contract failed");
            }
            let packedOwnThenReads = 0;
            const packedOwnThenArray = ["invoice.read"];
            Object.defineProperty(packedOwnThenArray, "then", {
              configurable: true,
              get() {
                packedOwnThenReads += 1;
                throw new Error("packed own route array then getter must not run");
              },
            });
            if (await packedRouteMarker(directRouteService(packedOwnThenArray)) !== "500:true:false:false" || packedOwnThenReads !== 0) {
              throw new Error("packed own direct route then getter escaped");
            }
            const packedThenModes = ["throw", "resolve", "self"];
            const originalArrayThenDescriptor = Object.getOwnPropertyDescriptor(Array.prototype, "then");
            const restoreArrayThen = () => {
              if (originalArrayThenDescriptor === undefined) Reflect.deleteProperty(Array.prototype, "then");
              else Object.defineProperty(Array.prototype, "then", originalArrayThenDescriptor);
            };
            for (let modeIndex = 0; modeIndex < packedThenModes.length; modeIndex += 1) {
              const mode = packedThenModes[modeIndex];
              let thenCalls = 0;
              let response;
              let thrown;
              try {
                Object.defineProperty(Array.prototype, "then", {
                  configurable: true,
                  enumerable: false,
                  value(resolve) {
                    thenCalls += 1;
                    if (mode === "throw") throw new Error("packed route then hook must not run");
                    if (mode === "resolve") {
                      const forged = ["secret.read"];
                      Object.setPrototypeOf(forged, null);
                      resolve(forged);
                      return;
                    }
                    if (thenCalls > 2) throw new Error("bounded packed self-resolving route then hook");
                    resolve(this);
                  },
                  writable: true,
                });
                try {
                  response = await packedRouteResponse(directRouteService(["invoice.read"]));
                } catch (error) {
                  thrown = error;
                }
              } finally {
                restoreArrayThen();
              }
              if (thrown !== undefined || response?.status !== 500) throw new Error("packed Array.prototype.then route bypassed screening");
              const body = await response.text();
              if (!body.includes('"code":"internal_error"') || body.includes("secret.read") || thenCalls !== 0) {
                throw new Error("packed Array.prototype.then route bypassed screening");
              }
            }
            for (let modeIndex = 0; modeIndex < packedThenModes.length; modeIndex += 1) {
              const mode = packedThenModes[modeIndex];
              let thenCalls = 0;
              const response = await withObjectPrototypeProperty("then", {
                configurable: true,
                enumerable: false,
                value(resolve) {
                  thenCalls += 1;
                  if (mode === "throw") throw new Error("packed route then hook must not run");
                  if (mode === "resolve") {
                    const forged = ["secret.read"];
                    Object.setPrototypeOf(forged, null);
                    resolve(forged);
                    return;
                  }
                  if (thenCalls > 2) throw new Error("bounded packed self-resolving route then hook");
                  resolve(this);
                },
                writable: true,
              }, () => packedRouteResponse(directRouteService(["invoice.read"])));
              const body = await response.text();
              if (response.status !== 500 || !body.includes('"code":"internal_error"') || body.includes("secret.read") || thenCalls !== 0) {
                throw new Error("packed Object.prototype.then route bypassed screening");
              }
            }
            const packedPlainThenable = { then(resolve) { resolve(["secret.read"]); } };
            if (await packedRouteMarker(directRouteService(packedPlainThenable)) !== "500:true:false:false") {
              throw new Error("packed plain route thenable was accepted");
            }
            class ForgedRoutePromise extends Promise {}
            const packedSubclassPromise = new ForgedRoutePromise((resolve) => resolve(["invoice.read"]));
            if (await packedRouteMarker(directRouteService(packedSubclassPromise)) !== "500:true:false:false") {
              throw new Error("packed route Promise subclass was accepted");
            }
            if (await packedRouteMarker(directRouteService(Promise.resolve(["invoice.read"]))) !== "200:false:false:true") {
              throw new Error("packed native route Promise was rejected");
            }
            if (await packedRouteMarker(directRouteService(Promise.reject(new Error("packed secret route rejection")))) !== "500:true:false:false") {
              throw new Error("packed native route rejection escaped");
            }

            const responseRequests = [
              { request: new Request("https://project.example.com/user/permissions"), subject: user },
              { request: new Request("https://project.example.com/user/permissions?unknown=grant"), subject: user },
              { request: new Request("https://project.example.com/user/permissions", { method: "POST" }), subject: user },
              { request: new Request("https://project.example.com/user/permissions"), subject: undefined },
              { request: new Request("https://project.example.com/user/permissions"), subject: user },
            ];
            const responseRouteService = new server.AuthorizationService({
              repository: { authorization: { effectivePermissions: () => [permission] } },
              clock: () => new Date("2026-08-11T00:00:00.000Z"),
            });
            const responseServices = [responseRouteService, responseRouteService, responseRouteService, responseRouteService, malformedRouteService];
            const runShieldedResponseSet = async (capturedResponses) => {
              const outputs = [];
              for (let index = 0; index < responseRequests.length; index += 1) {
                const entry = responseRequests[index];
                try {
                  const response = await server.permissionsRoute(responseServices[index], entry.request, entry.subject);
                  if (!(response instanceof Response)) {
                    outputs.push("non-response");
                    continue;
                  }
                  capturedResponses.push(response);
                  outputs.push(String(response.status));
                } catch {
                  outputs.push("threw");
                }
              }
              return outputs.join("|");
            };
            for (let modeIndex = 0; modeIndex < packedThenModes.length; modeIndex += 1) {
              const mode = packedThenModes[modeIndex];
              let thenCalls = 0;
              const capturedResponses = [];
              const marker = await withObjectPrototypeProperty("then", {
                configurable: true,
                enumerable: false,
                value(resolve) {
                  thenCalls += 1;
                  if (mode === "throw") throw new Error("packed response then hook must not run");
                  if (mode === "resolve") {
                    const forged = ["secret.read"];
                    Object.setPrototypeOf(forged, null);
                    resolve(forged);
                    return;
                  }
                  if (thenCalls > 2) throw new Error("bounded packed self-resolving response then hook");
                  resolve(this);
                },
                writable: true,
              }, () => runShieldedResponseSet(capturedResponses));
              if (marker !== "200|400|405|401|500" || thenCalls !== 0) {
                throw new Error("packed response then shielding failed");
              }
              const bodyCodes = [];
              for (let responseIndex = 0; responseIndex < capturedResponses.length; responseIndex += 1) {
                const response = capturedResponses[responseIndex];
                const body = await response.text();
                bodyCodes.push(body.includes('"code":"internal_error"')
                  ? "internal_error"
                  : body.includes('"code":"invalid_request"')
                    ? "invalid_request"
                    : body.includes('"code":"unauthorized"')
                      ? "unauthorized"
                      : "success");
              }
              if (bodyCodes.join("|") !== "success|invalid_request|invalid_request|unauthorized|internal_error") {
                throw new Error("packed response body contract changed");
              }
            }

            let invalidRouteThrew = false;
            let invalidRouteResponse;
            try {
              invalidRouteResponse = await server.permissionsRoute(routeService, Object.create(Request.prototype), user);
            } catch {
              invalidRouteThrew = true;
            }
            if (invalidRouteThrew || invalidRouteResponse?.status !== 400) throw new Error("packed invalid request accessor was not fail closed");

            const configurationRepository = { authorization: { effectivePermissions: async () => [permission] } };
            await withObjectPrototypeProperty("repository", configurationRepository, async () => {
              let rejected = false;
              try { new server.AuthorizationService({}); } catch { rejected = true; }
              if (!rejected) throw new Error("packed inherited repository was accepted");
            });
            await withObjectPrototypeProperty("authorization", configurationRepository.authorization, async () => {
              let rejected = false;
              try { new server.AuthorizationService({ repository: {} }); } catch { rejected = true; }
              if (!rejected) throw new Error("packed inherited authorization was accepted");
            });
            await withObjectPrototypeProperty("effectivePermissions", configurationRepository.authorization.effectivePermissions, async () => {
              let rejected = false;
              try { new server.AuthorizationService({ repository: { authorization: {} } }); } catch { rejected = true; }
              if (!rejected) throw new Error("packed inherited effectivePermissions was accepted");
            });
            await withObjectPrototypeProperty("clock", () => new Date("invalid"), async () => {
              try { new server.AuthorizationService({ repository: configurationRepository }); } catch { throw new Error("packed inherited clock controlled service"); }
            });

            const accessorOptions = {};
            Object.defineProperty(accessorOptions, "repository", { configurable: true, get() { throw new Error("packed repository getter"); } });
            try { new server.AuthorizationService(accessorOptions); throw new Error("packed repository accessor was accepted"); } catch (error) { if (error?.message === "packed repository accessor was accepted") throw error; }
            const accessorRepository = {};
            Object.defineProperty(accessorRepository, "authorization", { configurable: true, get() { throw new Error("packed authorization getter"); } });
            try { new server.AuthorizationService({ repository: accessorRepository }); throw new Error("packed authorization accessor was accepted"); } catch (error) { if (error?.message === "packed authorization accessor was accepted") throw error; }
            const accessorAuthorization = {};
            Object.defineProperty(accessorAuthorization, "effectivePermissions", { configurable: true, get() { throw new Error("packed effectivePermissions getter"); } });
            try { new server.AuthorizationService({ repository: { authorization: accessorAuthorization } }); throw new Error("packed effectivePermissions accessor was accepted"); } catch (error) { if (error?.message === "packed effectivePermissions accessor was accepted") throw error; }
            const accessorClockOptions = { repository: configurationRepository };
            Object.defineProperty(accessorClockOptions, "clock", { configurable: true, get() { throw new Error("packed clock getter"); } });
            try { new server.AuthorizationService(accessorClockOptions); throw new Error("packed clock accessor was accepted"); } catch (error) { if (error?.message === "packed clock accessor was accepted") throw error; }

            const seenTimes = [];
            const timeRepository = { authorization: { effectivePermissions: async (_userId, _scope, options) => { seenTimes.push(options?.now); return [permission]; } } };
            const originalDate = Date;
            const originalGetTime = Date.prototype.getTime;
            const originalNumberIsFinite = Number.isFinite;
            const originalDateDescriptor = Object.getOwnPropertyDescriptor(globalThis, "Date");
            try {
              Date.prototype.getTime = () => Number.POSITIVE_INFINITY;
              const getTimeService = new server.AuthorizationService({ repository: timeRepository, clock: () => new Date("2026-08-11T00:00:00.000Z") });
              if ((await getTimeService.getPermissions(user.user_id)).length !== 1) throw new Error("packed captured Date.getTime failed");
              Number.isFinite = () => false;
              const finiteService = new server.AuthorizationService({ repository: timeRepository, clock: () => new Date("2026-08-11T00:00:00.000Z") });
              if ((await finiteService.getPermissions(user.user_id)).length !== 1) throw new Error("packed captured Number.isFinite failed");
              Object.defineProperty(globalThis, "Date", { configurable: true, writable: true, value: class FakeDate { constructor() { return {}; } } });
              const reassignedDateService = new server.AuthorizationService({ repository: timeRepository, clock: () => new originalDate("2026-08-11T00:00:00.000Z") });
              if ((await reassignedDateService.getPermissions(user.user_id)).length !== 1) throw new Error("packed captured Date constructor failed");
              const defaultClockService = new server.AuthorizationService({ repository: timeRepository });
              if ((await defaultClockService.getPermissions(user.user_id)).length !== 1) throw new Error("packed default clock used live Date");
            } finally {
              originalDate.prototype.getTime = originalGetTime;
              Number.isFinite = originalNumberIsFinite;
              restoreDescriptor(globalThis, "Date", originalDateDescriptor);
            }
            class DateSubclass extends originalDate {}
            try { new server.AuthorizationService({ repository: timeRepository, clock: () => new DateSubclass(originalGetTime.call(new originalDate("2026-08-11T00:00:00.000Z"))) }); } catch { throw new Error("packed Date subclass was rejected"); }
            let invalidClockRejected = false;
            try { new server.AuthorizationService({ repository: timeRepository, clock: () => new originalDate(Number.NaN) }); } catch { invalidClockRejected = true; }
            if (!invalidClockRejected) throw new Error("packed invalid Date was accepted");
            invalidClockRejected = false;
            try { new server.AuthorizationService({ repository: timeRepository, clock: () => ({}) }); } catch { invalidClockRejected = true; }
            if (!invalidClockRejected) throw new Error("packed custom clock value was accepted");

            const expiryMillis = originalGetTime.call(new originalDate("2026-08-11T00:00:01.000Z"));
            const expiryRepository = { authorization: { effectivePermissions: async (_userId, _scope, options) => originalGetTime.call(options.now) < expiryMillis ? [permission] : [] } };
            const beforeExpiry = new server.AuthorizationService({ repository: expiryRepository, clock: () => new originalDate(expiryMillis - 1) });
            if ((await beforeExpiry.getPermissions(user.user_id)).length !== 1) throw new Error("packed pre-expiry grant was denied");
            const atExpiry = new server.AuthorizationService({ repository: expiryRepository, clock: () => new originalDate(expiryMillis) });
            if ((await atExpiry.getPermissions(user.user_id)).length !== 0) throw new Error("packed expired grant was accepted");
            const snapshotService = new server.AuthorizationService({ repository: timeRepository, clock: () => new originalDate("2026-08-11T00:00:00.000Z") });
            await snapshotService.getPermissions(user.user_id);
            await snapshotService.getPermissions(user.user_id);
            if (seenTimes[0] === undefined || seenTimes[0] === seenTimes[1] || seenTimes[0] === new originalDate("2026-08-11T00:00:00.000Z")) throw new Error("packed operation time was not snapshotted");
          `,
        ],
        { cwd: consumerRoot },
      );
      expect(packedBoundaryResult.code, packedBoundaryResult.stderr).toBe(0);

      const cliEnvironment = {
        ...process.env,
        DATABASE_URL: localDatabaseUrl(),
        AUTH_TOKEN_HASH_KEY: "t".repeat(32),
        AUTH_ENCRYPTION_KEY: "e".repeat(32),
        AUTH_BASE_URL: "https://example.com/auth/v1",
        AUTH_SITE_URL: "https://example.com",
        AUTH_ALLOWED_REDIRECTS: "https://example.com/callback",
      };
      const bin = join(consumerRoot, "node_modules/.bin/mrjim-auth");
      const statusResult = await runCommandResult(bin, ["migrate", "status"], { cwd: consumerRoot, env: cliEnvironment });
      expect(statusResult.code, statusResult.stderr).toBe(0);
      expect(statusResult.stdout).toContain("0001_core");

      const upResult = await runCommandResult(bin, ["migrate", "up"], { cwd: consumerRoot, env: cliEnvironment });
      expect(upResult.code, upResult.stderr).toBe(0);
      expect(upResult.stdout).toContain("applied: none");

      const verifyResult = await runCommandResult(bin, ["migrate", "verify"], { cwd: consumerRoot, env: cliEnvironment });
      expect(verifyResult.code, verifyResult.stderr).toBe(0);
      expect(verifyResult.stdout).toContain("schema: verified");

      const doctorResult = await runCommandResult(bin, ["doctor"], { cwd: consumerRoot, env: cliEnvironment });
      expect(doctorResult.code, doctorResult.stderr).toBe(0);
      expect(doctorResult.stdout).toContain('"ok": true');

      const invalidUsageResult = await runCommandResult(bin, ["migrate", "down"], { cwd: consumerRoot, env: cliEnvironment });
      expect(invalidUsageResult.code).not.toBe(0);
      expect(invalidUsageResult.stderr).toContain("Usage:");
    } finally {
      await rm(consumerRoot, { recursive: true, force: true });
    }
  }, 30_000);
});
