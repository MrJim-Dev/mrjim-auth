import { spawn } from "node:child_process";
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
const packageRoot = resolve(fileURLToPath(new URL("../../", import.meta.url)));
const workspaceRoot = resolve(packageRoot, "../..");
const originalDatabaseUrl = process.env.DATABASE_URL;
const ignoredGenericDatabaseUrl = "postgresql://not-used.invalid:5432/not-a-test-database";
process.env.DATABASE_URL = ignoredGenericDatabaseUrl;

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
        `INSERT INTO auth.oauth_states
          (state_hash, provider, flow, pkce_challenge, redirect_target, created_at, expires_at)
         VALUES ($1, 'google', 'login', 'challenge', 'https://example.com/callback', now(), now() + interval '11 minutes')`,
        [Buffer.alloc(32, 35)],
      ),
      /oauth_states_ttl_check/i,
    );
    await expectDatabaseError(
      () => pool.query(
        `INSERT INTO auth.api_keys (prefix, key_hash, kind, created_at, expires_at)
         VALUES ('sk_expired', $1, 'secret', now(), now() - interval '1 second')`,
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
      `INSERT INTO auth.api_keys (prefix, key_hash, kind, scopes)
       VALUES ('pk_test', $1, 'publishable', ARRAY['invoice.read'])
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
       VALUES ($1, 'google', 'login', 'challenge', 'https://example.com/callback', $2, now() + interval '1 minute')`,
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
       VALUES ('0004_unknown', 4, repeat('a', 64), $1)`,
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

    await pool.query("UPDATE auth.schema_migrations SET migration_order = 4 WHERE version = '0002_authorization'");
    await pool.query("UPDATE auth.schema_migrations SET migration_order = 5 WHERE version = '0003_oauth_operations'");
    try {
      await expect(migrate(pool, { direction: "up" })).rejects.toThrow(/history|order|contiguous/i);
    } finally {
      await pool.query("UPDATE auth.schema_migrations SET migration_order = migration_order - 2 WHERE version IN ('0002_authorization', '0003_oauth_operations')");
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
  });

  it("installs the packed package and executes its real shim-backed CLI", async () => {
    const consumerRoot = await mkdtemp(join(tmpdir(), "mrjim-auth-consumer-"));
    try {
      await writeFile(
        join(consumerRoot, "package.json"),
        JSON.stringify({ name: "mrjim-auth-consumer", private: true, type: "module" }, null, 2),
      );
      await runCommand("pnpm", ["build"], { cwd: workspaceRoot });
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
  });
});
