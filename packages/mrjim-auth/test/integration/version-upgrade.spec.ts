import { execFileSync, spawn } from "node:child_process";
import { accessSync, constants } from "node:fs";
import { mkdtemp, mkdir, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it } from "vitest";
import { Pool } from "pg";
import {
  REQUIRED_CONSTRAINTS,
  REQUIRED_INDEXES,
  constraintMatches,
  indexMatches,
} from "../../src/postgres/internal/schema-contract.js";
import { readSchemaCatalog } from "../../src/postgres/internal/catalog.js";
import { MIGRATIONS } from "../../src/postgres/manifest.js";
import { migrate, migrationStatus, verifySchema } from "../../src/postgres/migrate.js";

const REQUIRED_POSTGRES_VERSIONS = [15, 16, 17] as const;
type PostgresMajor = (typeof REQUIRED_POSTGRES_VERSIONS)[number];

const EXPECTED_MIGRATIONS = [
  {
    version: "0001_core",
    checksum: "542cb353f119e1e0d5f655d7611edefd301eb3cdc6cb9afcef0211f398ba3c4f",
  },
  {
    version: "0002_authorization",
    checksum: "c203903f1c7e00ed8a0ecc5e4b6de743447bd1e2c88f21682df6761381a887d6",
  },
  {
    version: "0003_oauth_operations",
    checksum: "af1c65925dbb63c0dacb332ff429b4cc6911482dc7cd1f560a73221016850b58",
  },
  {
    version: "0004_repository_hardening",
    checksum: "22aa84110fb82deaaf79d2640c78141aca7e1bd88c0de97616af7dbb7a4b2909",
  },
  {
    version: "0005_oauth_callback",
    checksum: "acc1e42358d6aa1b5b2cbb8bdd4ed97fd6838f6ef0b3a2796c8ff2d20e91f500",
  },
  {
    version: "0006_admin_operations",
    checksum: "9f2c434215f7b9adf33f918271de725a57f7577ea232268b1f0d3691df0caadd",
  },
] as const;

type CommandOptions = {
  readonly cwd?: string;
  readonly env?: NodeJS.ProcessEnv;
  readonly ignoreOutput?: boolean;
  readonly errorLogPath?: string;
};

type CommandResult = {
  readonly code: number | null;
  readonly stdout: string;
  readonly stderr: string;
};

type PostgresCandidate = {
  readonly version: PostgresMajor;
  readonly binDirectory: string;
};

type PostgresRuntime = PostgresCandidate & {
  readonly root: string;
  readonly dataDirectory: string;
  readonly socketDirectory: string;
  readonly adminPool: Pool;
  databaseCounter: number;
};

type Sentinel = {
  readonly userId: string;
  readonly identityId: string;
  readonly passwordUserId: string;
  readonly sessionId: string;
  readonly refreshTokenId: string;
  readonly refreshTokenHashHex: string;
  readonly oneTimeTokenId: string;
  readonly callbackTokenId: string | undefined;
  readonly roleId: string | undefined;
  readonly parentRoleId: string | undefined;
  readonly permissionId: string | undefined;
  readonly oauthStateId: string | undefined;
  readonly apiKeyId: string | undefined;
  readonly apiKeyPrefix: string | undefined;
  readonly apiKeyHashHex: string | undefined;
  readonly apiKeyName: string | undefined;
  readonly auditId: string | undefined;
  readonly email: string;
  readonly emailNormalized: string;
  readonly boundary: number;
};

type Row = Record<string, unknown>;

function runCommandResult(
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
    child.once("close", (code) => resolve({ code, stdout, stderr }));
  });
}

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
  const detail = (result.stderr || result.stdout || log).trim();
  throw new Error(
    `${command} ${args.join(" ")} exited with code ${result.code ?? "unknown"}${detail ? `: ${detail}` : ""}`,
  );
}

function postgresEnvironment(binDirectory: string): NodeJS.ProcessEnv {
  return {
    ...process.env,
    LANG: "C",
    LC_ALL: "C",
    PATH: `${binDirectory}:${process.env.PATH ?? ""}`,
  };
}

function standardHomebrewPaths(version: PostgresMajor): readonly string[] {
  return [
    `/opt/homebrew/opt/postgresql@${version}/bin`,
    `/usr/local/opt/postgresql@${version}/bin`,
  ];
}

function describeCandidate(binDirectory: string, version: PostgresMajor): string | undefined {
  const requiredBinaries = ["initdb", "pg_ctl", "postgres"] as const;
  const missing = requiredBinaries.filter((binary) => {
    try {
      accessSync(join(binDirectory, binary), constants.X_OK);
      return false;
    } catch {
      return true;
    }
  });
  if (missing.length > 0) {
    return `missing ${missing.join(", ")}`;
  }
  try {
    const output = execFileSync(join(binDirectory, "postgres"), ["--version"], {
      env: postgresEnvironment(binDirectory),
      encoding: "utf8",
    });
    const actualVersion = /^postgres \(PostgreSQL\) (\d+)/iu.exec(output.trim())?.[1];
    if (actualVersion !== String(version)) {
      return `postgres reports ${actualVersion ?? "an unknown version"}`;
    }
  } catch (error) {
    return `postgres --version failed: ${error instanceof Error ? error.message : String(error)}`;
  }
  return undefined;
}

function discoverPostgres(version: PostgresMajor): {
  readonly candidate?: PostgresCandidate;
  readonly problem: string;
} {
  const environmentName = `MRJIM_AUTH_PG${version}_BIN_DIR`;
  const configured = process.env[environmentName]?.trim();
  const candidates = configured ? [configured] : standardHomebrewPaths(version);
  const problems: string[] = [];
  for (const binDirectory of candidates) {
    const problem = describeCandidate(binDirectory, version);
    if (!problem) {
      return {
        candidate: { version, binDirectory },
        problem: "",
      };
    }
    problems.push(`${binDirectory}: ${problem}`);
  }
  return {
    problem: `${environmentName} or standard Homebrew paths checked (${problems.join("; ")})`,
  };
}

function parseRequestedVersions(): {
  readonly versions: readonly PostgresMajor[];
  readonly problem?: string;
} {
  const focus = process.env.MRJIM_AUTH_PG_FOCUS?.trim();
  if (!focus) return { versions: REQUIRED_POSTGRES_VERSIONS };
  const values = focus.split(",").map((value) => value.trim()).filter(Boolean);
  const invalid = values.filter(
    (value) => !REQUIRED_POSTGRES_VERSIONS.includes(Number(value) as PostgresMajor),
  );
  if (values.length === 0 || invalid.length > 0) {
    return {
      versions: [],
      problem: `MRJIM_AUTH_PG_FOCUS must contain only 15, 16, or 17; received ${JSON.stringify(focus)}`,
    };
  }
  return {
    versions: [...new Set(values.map((value) => Number(value) as PostgresMajor))],
  };
}

const requestedVersions = parseRequestedVersions();
const discovered = requestedVersions.problem
  ? []
  : requestedVersions.versions.map((version) => discoverPostgres(version));
const availableMatrix = discovered.flatMap((result) => result.candidate ? [result.candidate] : []);
const missingVersions = requestedVersions.problem
  ? []
  : discovered.flatMap((result, index) => result.candidate ? [] : [requestedVersions.versions[index]!]);
const matrixFailure = requestedVersions.problem
  ?? (missingVersions.length > 0
    ? [
      `Task 14 PostgreSQL migration matrix cannot run: missing required PostgreSQL ${missingVersions.join(", ")} binary version${missingVersions.length === 1 ? "" : "s"}.`,
      "Provide executable initdb, pg_ctl, and postgres directories with MRJIM_AUTH_PG15_BIN_DIR, MRJIM_AUTH_PG16_BIN_DIR, or MRJIM_AUTH_PG17_BIN_DIR, or use the standard Homebrew paths /opt/homebrew/opt/postgresql@<major>/bin and /usr/local/opt/postgresql@<major>/bin.",
      "The default matrix requires PostgreSQL 15, 16, and 17; an explicit local focused run may set MRJIM_AUTH_PG_FOCUS=16 (or a comma-separated subset). No software is installed by this test.",
      ...discovered.flatMap((result, index) => result.candidate ? [] : [`PostgreSQL ${requestedVersions.versions[index]!}: ${result.problem}`]),
    ].join(" ")
    : undefined);

async function queryRows(pool: Pool, text: string, values: readonly unknown[] = []): Promise<readonly Row[]> {
  const result = await pool.query(text, [...values]);
  return result.rows as Row[];
}

function quoteIdentifier(identifier: string): string {
  return `"${identifier.replaceAll('"', '""')}"`;
}

function runtimeConnectionString(socketDirectory: string, database: string): string {
  return `postgresql://postgres@localhost/${database}?host=${encodeURIComponent(socketDirectory)}`;
}

async function startRuntime(candidate: PostgresCandidate): Promise<PostgresRuntime> {
  const root = await mkdtemp(join(tmpdir(), `mrjim-auth-pg${candidate.version}-`));
  const dataDirectory = join(root, "data");
  const socketDirectory = join(root, "socket");
  const logPath = join(root, "postgres.log");
  const environment = postgresEnvironment(candidate.binDirectory);
  let adminPool: Pool | undefined;
  let started = false;
  try {
    await mkdir(socketDirectory);
    await runCommand(join(candidate.binDirectory, "initdb"), [
      "--pgdata",
      dataDirectory,
      "--auth=trust",
      "--username=postgres",
      "--no-locale",
      "--encoding=UTF8",
    ], { env: environment });
    await runCommand(join(candidate.binDirectory, "pg_ctl"), [
      "--pgdata",
      dataDirectory,
      "--log",
      logPath,
      "--options",
      `-h '' -k ${socketDirectory}`,
      "--wait",
      "start",
    ], { env: environment, ignoreOutput: true, errorLogPath: logPath });
    started = true;
    adminPool = new Pool({
      connectionString: runtimeConnectionString(socketDirectory, "postgres"),
      max: 2,
    });
    const versionResult = await adminPool.query("SHOW server_version_num");
    const serverVersion = String(versionResult.rows[0]?.server_version_num ?? "");
    if (!serverVersion.startsWith(String(candidate.version))) {
      throw new Error(`started PostgreSQL ${serverVersion || "unknown"}, expected ${candidate.version}`);
    }
    return {
      ...candidate,
      root,
      dataDirectory,
      socketDirectory,
      adminPool,
      databaseCounter: 0,
    };
  } catch (error) {
    await adminPool?.end().catch(() => undefined);
    if (started) {
      await runCommand(join(candidate.binDirectory, "pg_ctl"), [
        "--pgdata",
        dataDirectory,
        "--mode=immediate",
        "--wait",
        "stop",
      ], { env: environment, ignoreOutput: true }).catch(() => undefined);
    }
    await rm(root, { recursive: true, force: true });
    throw error;
  }
}

async function stopRuntime(runtime: PostgresRuntime): Promise<void> {
  try {
    await runtime.adminPool.end();
  } finally {
    try {
      await runCommand(join(runtime.binDirectory, "pg_ctl"), [
        "--pgdata",
        runtime.dataDirectory,
        "--mode=immediate",
        "--wait",
        "stop",
      ], { env: postgresEnvironment(runtime.binDirectory), ignoreOutput: true });
    } finally {
      await rm(runtime.root, { recursive: true, force: true });
    }
  }
}

async function withDatabase<T>(
  runtime: PostgresRuntime,
  label: string,
  callback: (pool: Pool) => Promise<T>,
): Promise<T> {
  runtime.databaseCounter += 1;
  const database = `mrjim_auth_${runtime.version}_${label}_${process.pid}_${runtime.databaseCounter}`;
  const identifier = quoteIdentifier(database);
  await runtime.adminPool.query(`CREATE DATABASE ${identifier}`);
  const pool = new Pool({ connectionString: runtimeConnectionString(runtime.socketDirectory, database), max: 4 });
  try {
    await pool.query("SELECT current_database()");
    return await callback(pool);
  } finally {
    await pool.end();
    await runtime.adminPool.query(`DROP DATABASE ${identifier}`).catch(() => undefined);
  }
}

async function applyCommittedBoundary(pool: Pool, boundary: number): Promise<void> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    for (const migration of MIGRATIONS.slice(0, boundary)) {
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
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

function sentinelId(boundary: number, slot: number): string {
  return `00000000-0000-4000-8000-${String(boundary * 100 + slot).padStart(12, "0")}`;
}

async function seedSentinels(pool: Pool, boundary: number): Promise<Sentinel> {
  const userId = sentinelId(boundary, 1);
  const identityId = sentinelId(boundary, 2);
  const sessionId = sentinelId(boundary, 3);
  const refreshTokenId = sentinelId(boundary, 4);
  const familyId = sentinelId(boundary, 5);
  const oneTimeTokenId = sentinelId(boundary, 6);
  const callbackTokenId = boundary >= 5 ? sentinelId(boundary, 7) : undefined;
  const email = `migration-sentinel-${boundary}@example.test`;
  const emailNormalized = email.toLowerCase();
  const passwordHash = "$argon2id$v=19$m=65536,t=3,p=1$c2FsdA$aGFzaA";
  const roleId = boundary >= 2 ? sentinelId(boundary, 8) : undefined;
  const parentRoleId = boundary >= 2 ? sentinelId(boundary, 9) : undefined;
  const permissionId = boundary >= 2 ? sentinelId(boundary, 10) : undefined;
  const oauthStateId = boundary >= 3 ? sentinelId(boundary, 11) : undefined;
  const apiKeyId = boundary >= 3 ? sentinelId(boundary, 12) : undefined;
  const apiKeyPrefix = boundary >= 3 ? `sk_sentinel_${boundary}` : undefined;
  const auditId = boundary >= 3 ? sentinelId(boundary, 13) : undefined;
  const refreshTokenHashHex = Buffer.alloc(32, boundary + 10).toString("hex");
  const apiKeyHashHex = boundary >= 3 ? Buffer.alloc(32, boundary + 50).toString("hex") : undefined;
  const apiKeyName = boundary >= 3
    ? boundary < 6 ? apiKeyPrefix : `sentinel key ${boundary}`
    : undefined;
  const sentinel: Sentinel = {
    userId,
    identityId,
    passwordUserId: userId,
    sessionId,
    refreshTokenId,
    refreshTokenHashHex,
    oneTimeTokenId,
    callbackTokenId,
    roleId,
    parentRoleId,
    permissionId,
    oauthStateId,
    apiKeyId,
    apiKeyPrefix,
    apiKeyHashHex,
    apiKeyName,
    auditId,
    email,
    emailNormalized,
    boundary,
  };
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query(
      `INSERT INTO auth.users
        (id, email, email_normalized, phone, phone_normalized, user_metadata, app_metadata)
       VALUES ($1, $2, $3, '+639171234567', '+639171234567', $4::jsonb, $5::jsonb)`,
      [userId, email, emailNormalized, JSON.stringify({ marker: "migration-sentinel" }), JSON.stringify({ boundary })],
    );
    await client.query(
      `INSERT INTO auth.identities
        (id, user_id, provider, provider_subject, email, email_normalized, identity_data)
       VALUES ($1, $2, 'google', $3, $4, $5, $6::jsonb)`,
      [identityId, userId, `sentinel-subject-${boundary}`, email, emailNormalized, JSON.stringify({ marker: "migration-sentinel" })],
    );
    await client.query(
      `INSERT INTO auth.password_credentials (user_id, password_hash, password_updated_at)
       VALUES ($1, $2, '2099-01-01T00:00:00Z')`,
      [userId, passwordHash],
    );
    await client.query(
      `INSERT INTO auth.sessions (id, user_id, created_at, refreshed_at, expires_at)
       VALUES ($1, $2, '2099-01-01T00:00:00Z', '2099-01-01T00:00:00Z', '2099-01-02T00:00:00Z')`,
      [sessionId, userId],
    );
    await client.query(
      `INSERT INTO auth.refresh_tokens
        (id, session_id, token_hash, family_id, issued_at, expires_at)
       VALUES ($1, $2, $3, $4, '2099-01-01T00:00:00Z', '2099-01-02T00:00:00Z')`,
      [refreshTokenId, sessionId, Buffer.from(refreshTokenHashHex, "hex"), familyId],
    );
    await client.query(
      `INSERT INTO auth.one_time_tokens
        (id, user_id, purpose, token_hash, target, metadata, created_at, expires_at)
       VALUES ($1, $2, 'invite', $3, $4, $5::jsonb, '2099-01-01T00:00:00Z', '2099-01-01T00:05:00Z')`,
      [oneTimeTokenId, userId, Buffer.alloc(32, boundary + 20), email, JSON.stringify({ event: "migration_sentinel" })],
    );
    if (boundary >= 5 && callbackTokenId) {
      await client.query(
        `INSERT INTO auth.one_time_tokens
          (id, user_id, purpose, token_hash, target, metadata, created_at, expires_at)
         VALUES ($1, $2, 'oauth_callback', $3, $4, $5::jsonb, '2099-01-01T00:00:00Z', '2099-01-01T00:00:30Z')`,
        [callbackTokenId, userId, Buffer.alloc(32, boundary + 30), email, JSON.stringify({ event: "oauth_callback_sentinel" })],
      );
    }
    if (boundary >= 2 && roleId && parentRoleId && permissionId) {
      await client.query(
        `INSERT INTO auth.roles (id, key, name, description, rank)
         VALUES ($1, $2, $3, 'migration sentinel role', 10),
                ($4, $5, $6, 'migration sentinel parent', 5)`,
        [roleId, `sentinel_role_${boundary}`, `Sentinel role ${boundary}`, parentRoleId, `sentinel_parent_${boundary}`, `Sentinel parent ${boundary}`],
      );
      await client.query(
        `INSERT INTO auth.permissions (id, key, resource, action, description)
         VALUES ($1, 'sentinel.read', 'sentinel', 'read', 'migration sentinel permission')`,
        [permissionId],
      );
      await client.query(
        "INSERT INTO auth.role_permissions (role_id, permission_id) VALUES ($1, $2)",
        [roleId, permissionId],
      );
      await client.query(
        "INSERT INTO auth.role_inheritance (role_id, inherits_role_id) VALUES ($1, $2)",
        [roleId, parentRoleId],
      );
      await client.query(
        "INSERT INTO auth.user_roles (user_id, role_id, assigned_by) VALUES ($1, $2, $1)",
        [userId, roleId],
      );
    }
    if (boundary >= 3 && oauthStateId && apiKeyId && apiKeyPrefix && apiKeyHashHex && auditId) {
      await client.query(
        `INSERT INTO auth.oauth_states
          (id, state_hash, provider, flow, pkce_challenge, redirect_target, expires_at, created_at)
         VALUES ($1, $2, 'google', 'link_identity', 'sentinel-challenge', 'https://example.test/oauth/callback', '2099-01-01T00:05:00Z', '2099-01-01T00:00:00Z')`,
        [oauthStateId, Buffer.alloc(32, boundary + 40)],
      );
      if (boundary < 6) {
        await client.query(
          `INSERT INTO auth.api_keys (id, prefix, key_hash, kind, scopes)
           VALUES ($1, $2, $3, 'secret', ARRAY['auth.*', 'sentinel.read']::text[])`,
          [apiKeyId, apiKeyPrefix, Buffer.from(apiKeyHashHex, "hex")],
        );
      } else {
        await client.query(
          `INSERT INTO auth.api_keys (id, prefix, key_hash, kind, scopes, name)
           VALUES ($1, $2, $3, 'secret', ARRAY['auth.*', 'sentinel.read']::text[], $4)`,
          [apiKeyId, apiKeyPrefix, Buffer.from(apiKeyHashHex, "hex"), apiKeyName],
        );
      }
      await client.query(
        `INSERT INTO auth.audit_log
          (id, actor_user_id, action, target_type, target_id, metadata, outcome)
         VALUES ($1, $2, 'migration_sentinel', 'user', $2, $3::jsonb, 'success')`,
        [auditId, userId, JSON.stringify({ event: "migration_sentinel", status: "created" })],
      );
    }
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
  return sentinel;
}

async function assertBoundaryState(pool: Pool, boundary: number): Promise<void> {
  const status = await migrationStatus(pool);
  expect(status.slice(0, boundary).map((migration) => migration.state)).toEqual(
    Array.from({ length: boundary }, () => "applied"),
  );
  expect(status.slice(boundary).map((migration) => migration.state)).toEqual(
    Array.from({ length: MIGRATIONS.length - boundary }, () => "pending"),
  );
}

async function assertMigrationHistory(pool: Pool): Promise<void> {
  const rows = await queryRows(
    pool,
    `SELECT version, migration_order, checksum, package_version, applied_at IS NOT NULL AS applied
       FROM auth.schema_migrations
      ORDER BY migration_order`,
  );
  expect(rows).toHaveLength(EXPECTED_MIGRATIONS.length);
  expect(rows.map((row) => String(row.version))).toEqual(EXPECTED_MIGRATIONS.map((migration) => migration.version));
  expect(rows.map((row) => Number(row.migration_order))).toEqual(EXPECTED_MIGRATIONS.map((_, index) => index + 1));
  expect(rows.map((row) => String(row.checksum))).toEqual(EXPECTED_MIGRATIONS.map((migration) => migration.checksum));
  expect(rows.map((row) => String(row.package_version))).toEqual(MIGRATIONS.map((migration) => migration.introducedIn));
  expect(rows.every((row) => row.applied === true)).toBe(true);
}

async function assertCurrentCatalog(pool: Pool): Promise<void> {
  const verification = await verifySchema(pool);
  expect(verification.ok, verification.errors.join("; ")).toBe(true);
  expect(verification.postgresVersion).not.toBeNull();
  expect(verification.postgresVersion ?? 0).toBeGreaterThanOrEqual(150000);

  const catalog = await readSchemaCatalog(pool);
  const constraintBackedIndexes = REQUIRED_CONSTRAINTS
    .filter((constraint) => constraint.constraintType === "p" || constraint.constraintType === "u")
    .map((constraint) => constraint.constraintName);
  const expectedIndexNames = [
    ...new Set([...REQUIRED_INDEXES.map((index) => index.indexName), ...constraintBackedIndexes]),
  ];
  expect(catalog.indexes.map((index) => index.index_name).sort()).toEqual(
    expectedIndexNames.sort(),
  );
  for (const expected of REQUIRED_INDEXES) {
    expect(
      indexMatches(catalog.indexes.find((index) => index.index_name === expected.indexName), expected),
      `index contract ${expected.indexName}`,
    ).toBe(true);
  }
  expect(catalog.constraints.map((constraint) => constraint.constraint_name).sort()).toEqual(
    REQUIRED_CONSTRAINTS.map((constraint) => constraint.constraintName).sort(),
  );
  for (const expected of REQUIRED_CONSTRAINTS) {
    expect(
      constraintMatches(
        catalog.constraints.find((constraint) => constraint.constraint_name === expected.constraintName),
        expected,
      ),
      `constraint contract ${expected.constraintName}`,
    ).toBe(true);
  }
}

async function assertSentinels(pool: Pool, sentinel: Sentinel): Promise<void> {
  const userRows = await queryRows(
    pool,
    `SELECT email, email_normalized, user_metadata->>'marker' AS marker, app_metadata->>'boundary' AS boundary
       FROM auth.users WHERE id = $1`,
    [sentinel.userId],
  );
  expect(userRows).toEqual([{
    email: sentinel.email,
    email_normalized: sentinel.emailNormalized,
    marker: "migration-sentinel",
    boundary: String(sentinel.boundary),
  }]);
  expect(await queryRows(pool, "SELECT user_id FROM auth.password_credentials WHERE user_id = $1", [sentinel.passwordUserId])).toHaveLength(1);
  expect(await queryRows(pool, "SELECT provider_subject FROM auth.identities WHERE id = $1", [sentinel.identityId])).toEqual([
    { provider_subject: `sentinel-subject-${sentinel.boundary}` },
  ]);
  expect(await queryRows(
    pool,
    "SELECT user_id, expires_at > created_at AS valid FROM auth.sessions WHERE id = $1",
    [sentinel.sessionId],
  )).toEqual([{ user_id: sentinel.userId, valid: true }]);
  expect(await queryRows(
    pool,
    "SELECT session_id, encode(token_hash, 'hex') AS token_hash FROM auth.refresh_tokens WHERE id = $1",
    [sentinel.refreshTokenId],
  )).toEqual([{ session_id: sentinel.sessionId, token_hash: sentinel.refreshTokenHashHex }]);
  expect(await queryRows(
    pool,
    `SELECT purpose, target, metadata->>'event' AS event
       FROM auth.one_time_tokens WHERE id = $1`,
    [sentinel.oneTimeTokenId],
  )).toEqual([{ purpose: "invite", target: sentinel.email, event: "migration_sentinel" }]);
  if (sentinel.callbackTokenId) {
    expect(await queryRows(
      pool,
      "SELECT purpose, metadata->>'event' AS event FROM auth.one_time_tokens WHERE id = $1",
      [sentinel.callbackTokenId],
    )).toEqual([{ purpose: "oauth_callback", event: "oauth_callback_sentinel" }]);
  }
  if (sentinel.roleId && sentinel.parentRoleId && sentinel.permissionId) {
    expect(await queryRows(
      pool,
      `SELECT rp.permission_id, ri.inherits_role_id, ur.user_id
         FROM auth.role_permissions AS rp
         JOIN auth.role_inheritance AS ri ON ri.role_id = rp.role_id
         JOIN auth.user_roles AS ur ON ur.role_id = rp.role_id
        WHERE rp.role_id = $1`,
      [sentinel.roleId],
    )).toEqual([{
      permission_id: sentinel.permissionId,
      inherits_role_id: sentinel.parentRoleId,
      user_id: sentinel.userId,
    }]);
  }
  if (sentinel.oauthStateId) {
    expect(await queryRows(
      pool,
      "SELECT provider, flow, pkce_challenge FROM auth.oauth_states WHERE id = $1",
      [sentinel.oauthStateId],
    )).toEqual([{ provider: "google", flow: "link_identity", pkce_challenge: "sentinel-challenge" }]);
  }
  if (sentinel.apiKeyId && sentinel.apiKeyPrefix && sentinel.apiKeyHashHex && sentinel.apiKeyName) {
    expect(await queryRows(
      pool,
      `SELECT prefix, encode(key_hash, 'hex') AS key_hash, kind, scopes, name
         FROM auth.api_keys WHERE id = $1`,
      [sentinel.apiKeyId],
    )).toEqual([{
      prefix: sentinel.apiKeyPrefix,
      key_hash: sentinel.apiKeyHashHex,
      kind: "secret",
      scopes: ["auth.*", "sentinel.read"],
      name: sentinel.apiKeyName,
    }]);
  }
  if (sentinel.auditId) {
    expect(await queryRows(
      pool,
      `SELECT actor_user_id, action, metadata->>'event' AS event, outcome
         FROM auth.audit_log WHERE id = $1`,
      [sentinel.auditId],
    )).toEqual([{
      actor_user_id: sentinel.userId,
      action: "migration_sentinel",
      event: "migration_sentinel",
      outcome: "success",
    }]);
  }
}

async function runFreshInstall(runtime: PostgresRuntime): Promise<void> {
  await withDatabase(runtime, "fresh", async (pool) => {
    const pending = await migrationStatus(pool);
    expect(pending.every((migration) => migration.state === "pending")).toBe(true);
    const result = await migrate(pool, { direction: "up" });
    expect(result.applied).toEqual(MIGRATIONS.map((migration) => migration.version));
    await assertMigrationHistory(pool);
    await assertCurrentCatalog(pool);

    const sentinel = await seedSentinels(pool, 6);
    expect((await migrate(pool, { direction: "up" })).applied).toEqual([]);
    await assertSentinels(pool, sentinel);
  });
}

async function runUpgradeFromBoundary(runtime: PostgresRuntime, boundary: number): Promise<void> {
  await withDatabase(runtime, `upgrade${boundary}`, async (pool) => {
    await applyCommittedBoundary(pool, boundary);
    await assertBoundaryState(pool, boundary);
    const sentinel = await seedSentinels(pool, boundary);
    const result = await migrate(pool, { direction: "up" });
    expect(result.applied).toEqual(MIGRATIONS.slice(boundary).map((migration) => migration.version));
    expect((await migrate(pool, { direction: "up" })).applied).toEqual([]);
    await assertMigrationHistory(pool);
    await assertCurrentCatalog(pool);
    await assertSentinels(pool, sentinel);
  });
}

it("requires the default PostgreSQL 15/16/17 matrix, or an explicit focused matrix", () => {
  if (matrixFailure) throw new Error(matrixFailure);
  expect(matrixFailure).toBeUndefined();
});

it("matches every committed migration version and checksum", () => {
  expect(MIGRATIONS).toHaveLength(EXPECTED_MIGRATIONS.length);
  expect(MIGRATIONS.map((migration) => migration.version)).toEqual(EXPECTED_MIGRATIONS.map((migration) => migration.version));
  expect(MIGRATIONS.map((migration) => migration.migrationOrder)).toEqual([1, 2, 3, 4, 5, 6]);
  expect(MIGRATIONS.map((migration) => migration.checksum)).toEqual(EXPECTED_MIGRATIONS.map((migration) => migration.checksum));
});

if (!matrixFailure) {
  for (const candidate of availableMatrix) {
    it(
      `runs fresh install and upgrades from 0001 through 0005 on PostgreSQL ${candidate.version}`,
      async () => {
        const runtime = await startRuntime(candidate);
        try {
          await runFreshInstall(runtime);
          for (const boundary of [1, 2, 3, 4, 5]) {
            await runUpgradeFromBoundary(runtime, boundary);
          }
        } finally {
          await stopRuntime(runtime);
        }
      },
      600_000,
    );
  }
}
