import { spawn } from "node:child_process";
import { mkdtemp, mkdir, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Pool } from "pg";
import { runCli } from "../../src/cli/index.js";
import { runDoctor } from "../../src/cli/commands/doctor.js";
import { runMigrateCommand } from "../../src/cli/commands/migrate.js";
import { MIGRATIONS } from "../../src/postgres/manifest.js";
import {
  migrate,
  migrationStatus,
  verifySchema,
} from "../../src/postgres/migrate.js";

const packageVersion = "0.1.0";
const testDatabaseUrl = process.env.MRJIM_AUTH_TEST_DATABASE_URL?.trim()
  || process.env.DATABASE_URL?.trim()
  || undefined;

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

type Cluster = {
  root: string;
  dataDirectory: string;
  socketDirectory: string;
};

let pool: Pool;
let cluster: Cluster | undefined;

async function runCommand(
  command: string,
  args: readonly string[],
  options: { readonly ignoreOutput?: boolean; readonly errorLogPath?: string } = {},
): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const child = spawn(command, args, {
      stdio: options.ignoreOutput ? "ignore" : ["ignore", "pipe", "pipe"],
    });
    let stderr = "";
    child.stderr?.on("data", (chunk: Buffer) => {
      stderr += chunk.toString();
    });
    child.once("error", reject);
    child.once("close", async (code) => {
      if (code === 0) resolve();
      else {
        const log = options.errorLogPath
          ? await readFile(options.errorLogPath, "utf8").catch(() => "")
          : "";
        reject(new Error(`${command} ${args.join(" ")} exited with code ${code ?? "unknown"}${stderr || log ? `: ${(stderr || log).trim()}` : ""}`));
      }
    });
  });
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
     SELECT p.proname
       FROM pg_proc AS p
       JOIN pg_namespace AS n ON n.oid = p.pronamespace
      WHERE n.nspname = 'auth'
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
    if (testDatabaseUrl) {
      pool = new Pool({ connectionString: testDatabaseUrl, max: 10 });
      await pool.query("SELECT 1");
      return;
    }

    const root = await mkdtemp(join(tmpdir(), "mrjim-auth-task3-"));
    const dataDirectory = join(root, "data");
    const socketDirectory = join(root, "socket");
    cluster = { root, dataDirectory, socketDirectory };
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

    pool = new Pool({ connectionString: localDatabaseUrl(), max: 10 });
    await pool.query("SELECT version()");
  }, 120_000);

  afterAll(async () => {
    await pool?.end();
    if (cluster) {
      await runCommand("pg_ctl", [
        "--pgdata",
        cluster.dataDirectory,
        "--mode=immediate",
        "--wait",
        "stop",
      ], { ignoreOutput: true }).catch(() => undefined);
      await rm(cluster.root, { recursive: true, force: true });
    }
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

    const objectNames = (await authObjectNames()).join(" ");
    expect(objectNames).not.toMatch(/mrjim|hayahai|shipping|tenant|passenger|vessel|cabin|tms/i);
    expect(MIGRATIONS.map((migration) => migration.sql).join(" ")).not.toMatch(
      /shipping|tenant|passenger|vessel|cabin|tms/i,
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
    expect(firstStatus.every((migration) => migration.packageVersion === packageVersion)).toBe(true);

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
       VALUES ($1, '$argon2id$v=19$m=65536,t=3,p=1$hash')`,
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
       VALUES ($1, $2, $3, 'user.created', 'user', '{"safe":true}', 'success')`,
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
       VALUES ('login', 'session', '{"safe":true}', 'success')
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

  it("keeps command status and doctor read-only while validating configuration", async () => {
    const before = await countRows("schema_migrations");
    const output: string[] = [];
    await runMigrateCommand(pool, "status", (line) => output.push(line));
    expect(output.join("\n")).toContain("0001_core");
    expect(output.join("\n")).toContain("applied");

    const report = await runDoctor(pool, {
      DATABASE_URL: testDatabaseUrl ?? localDatabaseUrl(),
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
      DATABASE_URL: testDatabaseUrl ?? localDatabaseUrl(),
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
      DATABASE_URL: testDatabaseUrl ?? localDatabaseUrl(),
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
});
