import { spawn } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, mkdir, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Pool } from "pg";
import { migrate } from "../../src/postgres/migrate.js";
import { createPostgresAdapter, type PostgresAdapter } from "../../src/postgres/adapter.js";
import type { KeyProvider } from "../../src/shared/contracts.js";
import type { Session, User } from "../../src/shared/types.js";
import { uuidSchema } from "../../src/shared/types.js";
import { SessionService } from "../../src/server/sessions.js";
import { TokenService } from "../../src/server/tokens.js";

type DisposablePostgres = {
  readonly root: string;
  readonly dataDirectory: string;
  readonly socketDirectory: string;
  readonly pool: Pool;
};

type CommandResult = {
  readonly code: number | null;
  readonly stdout: string;
  readonly stderr: string;
};

const NOW = new Date("2026-08-11T05:00:00.000Z");
const REFRESH_TTL_SECONDS = 30 * 24 * 60 * 60;
const TOKEN_HASH_KEY = Uint8Array.from({ length: 32 }, (_, index) => index + 1);

let disposable: DisposablePostgres | undefined;
let repository: PostgresAdapter | undefined;
let pool: Pool | undefined;
let tokenService: TokenService | undefined;
let sessionService: SessionService | undefined;

async function runCommandResult(command: string, args: readonly string[]): Promise<CommandResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk: Buffer) => {
      stdout += chunk.toString();
    });
    child.stderr.on("data", (chunk: Buffer) => {
      stderr += chunk.toString();
    });
    child.once("error", reject);
    child.once("close", (code) => resolve({ code, stdout, stderr }));
  });
}

async function runCommand(command: string, args: readonly string[], logPath?: string): Promise<void> {
  const result = await runCommandResult(command, args);
  if (result.code === 0) return;
  const log = logPath === undefined ? "" : await readFile(logPath, "utf8").catch(() => "");
  throw new Error(`${command} ${args.join(" ")} failed: ${(result.stderr || log).trim()}`);
}

async function startPostgres(): Promise<DisposablePostgres> {
  const root = await mkdtemp(join(tmpdir(), "mrjim-auth-task5-"));
  const dataDirectory = join(root, "data");
  const socketDirectory = join(root, "socket");
  const logPath = join(root, "postgres.log");
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
      logPath,
      "--options",
      `-h '' -k ${socketDirectory}`,
      "--wait",
      "start",
    ], logPath);
    const disposablePool = new Pool({
      connectionString: `postgresql://postgres@localhost/postgres?host=${encodeURIComponent(socketDirectory)}`,
      max: 12,
    });
    await disposablePool.query("SELECT 1");
    return { root, dataDirectory, socketDirectory, pool: disposablePool };
  } catch (error) {
    await runCommand("pg_ctl", ["--pgdata", dataDirectory, "--mode=immediate", "--wait", "stop"]).catch(() => undefined);
    await rm(root, { recursive: true, force: true });
    throw error;
  }
}

async function stopPostgres(value: DisposablePostgres): Promise<void> {
  try {
    await value.pool.end();
  } finally {
    await runCommand("pg_ctl", [
      "--pgdata",
      value.dataDirectory,
      "--mode=immediate",
      "--wait",
      "stop",
    ]).catch(() => undefined);
    await rm(value.root, { recursive: true, force: true });
  }
}

function requireRepository(): PostgresAdapter {
  if (repository === undefined) throw new Error("repository not initialized");
  return repository;
}

function requirePool(): Pool {
  if (pool === undefined) throw new Error("pool not initialized");
  return pool;
}

function requireSessionService(): SessionService {
  if (sessionService === undefined) throw new Error("session service not initialized");
  return sessionService;
}

function requireTokenService(): TokenService {
  if (tokenService === undefined) throw new Error("token service not initialized");
  return tokenService;
}

function makeKeyProvider(): KeyProvider {
  const pair = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const privateKey = pair.privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const publicKey = pair.publicKey.export({ type: "spki", format: "pem" }).toString();
  return {
    getActiveKeyId: () => "task5",
    getSigningKey: () => privateKey,
    getVerificationKeys: () => new Map([["task5", publicKey]]),
  };
}

function makeUser(overrides: Partial<User> = {}): User {
  const base: User = {
    id: uuidSchema.parse("00000000-0000-4000-8000-000000000201"),
    email: "session-user@example.com",
    phone: null,
    email_confirmed_at: "2026-08-11T00:00:00.000Z",
    phone_confirmed_at: null,
    confirmed_at: "2026-08-11T00:00:00.000Z",
    last_sign_in_at: null,
    banned_until: null,
    user_metadata: {},
    app_metadata: {},
    created_at: "2026-08-11T00:00:00.000Z",
    updated_at: "2026-08-11T00:00:00.000Z",
    deleted_at: null,
  };
  return { ...base, ...overrides };
}

async function createUser(email: string): Promise<User> {
  return requireRepository().users.create({ email });
}

function requireData<T>(result: { data: T | null; error: unknown }): T {
  if (result.data === null) throw new Error(`expected success, got ${JSON.stringify(result.error)}`);
  return result.data;
}

async function sessionRows(sessionId: string) {
  return (await requirePool().query<{
    readonly id: string;
    readonly session_id: string;
    readonly family_id: string;
    readonly parent_id: string | null;
    readonly replacement_id: string | null;
    readonly token_hash: Buffer;
    readonly used_at: Date | null;
    readonly revoked_at: Date | null;
  }>(
    `SELECT id, session_id, family_id, parent_id, replacement_id, token_hash, used_at, revoked_at
       FROM auth.refresh_tokens
      WHERE session_id = $1
      ORDER BY issued_at, id`,
    [sessionId],
  )).rows;
}

describe("Task 5 rotating PostgreSQL sessions", () => {
  beforeAll(async () => {
    disposable = await startPostgres();
    pool = disposable.pool;
    await migrate(pool, { direction: "up" });
    repository = createPostgresAdapter({ pool });
    tokenService = new TokenService({
      issuer: "https://project.example.com/auth/v1",
      audience: "project",
      keyProvider: makeKeyProvider(),
      tokenHashKey: TOKEN_HASH_KEY,
      accessTokenTtlSeconds: 900,
      clock: () => NOW,
    });
    sessionService = new SessionService({
      repository,
      tokens: tokenService,
      refreshTokenTtlSeconds: REFRESH_TTL_SECONDS,
      clock: () => NOW,
    });
  }, 120_000);

  afterAll(async () => {
    try {
      await repository?.close();
    } finally {
      if (disposable !== undefined) await stopPostgres(disposable);
    }
  });

  it("creates a session with a 32-byte opaque token digest and a verifiable access token", async () => {
    const user = await createUser("session-create@example.com");
    const session = requireData(await requireSessionService().create(user, {
      ip_address: "127.0.0.1",
      user_agent: "task5-test",
    }));

    expect(session.refresh_token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const claims = requireData(await requireTokenService().verifyAccessToken(session.access_token));
    expect(claims).toMatchObject({ sub: user.id, sid: expect.any(String), aal: 1 });
    expect(claims.exp - claims.iat).toBe(900);

    const rows = await sessionRows(claims.sid);
    expect(rows).toHaveLength(1);
    expect(rows[0]?.token_hash.byteLength).toBe(32);
    expect(rows[0]?.token_hash).toEqual(
      Buffer.from(requireTokenService().hashOpaqueToken(session.refresh_token)),
    );
    expect(rows[0]?.token_hash.toString("utf8")).not.toContain(session.refresh_token);
  });

  it("rotates one refresh winner while preserving family and parent lineage", async () => {
    const user = await createUser("session-refresh@example.com");
    const initial = requireData(await requireSessionService().create(user, {}));
    const initialClaims = requireData(await requireTokenService().verifyAccessToken(initial.access_token));

    const refreshed = requireData(await requireSessionService().refresh(initial.refresh_token, {}));
    const replacementClaims = requireData(await requireTokenService().verifyAccessToken(refreshed.access_token));
    expect(replacementClaims.sid).toBe(initialClaims.sid);
    expect(refreshed.refresh_token).not.toBe(initial.refresh_token);

    const rows = await sessionRows(initialClaims.sid);
    expect(rows).toHaveLength(2);
    const parent = rows.find((row) => row.parent_id === null);
    const replacement = rows.find((row) => row.parent_id === parent?.id);
    expect(parent?.used_at).not.toBeNull();
    expect(parent?.replacement_id).toBe(replacement?.id);
    expect(replacement?.family_id).toBe(parent?.family_id);
    expect(replacement?.token_hash).toEqual(
      Buffer.from(requireTokenService().hashOpaqueToken(refreshed.refresh_token)),
    );
    expect(replacement?.revoked_at).toBeNull();
  });

  it("returns refresh_token_reused and durably revokes the whole family and owning session", async () => {
    const user = await createUser("session-reuse@example.com");
    const initial = requireData(await requireSessionService().create(user, {}));

    const results = await Promise.all([
      requireSessionService().refresh(initial.refresh_token, { ip_address: "127.0.0.1" }),
      requireSessionService().refresh(initial.refresh_token, { ip_address: "127.0.0.1" }),
    ]);
    expect(results.filter((result) => result.data !== null)).toHaveLength(1);
    expect(results.filter((result) => result.error?.code === "refresh_token_reused")).toHaveLength(1);

    const winner = results.find((result) => result.data !== null);
    if (winner?.data === null || winner?.data === undefined) throw new Error("rotation winner missing");
    const claims = requireData(await requireTokenService().verifyAccessToken(winner.data.access_token));
    const rows = await sessionRows(claims.sid);
    expect(rows.length).toBe(2);
    expect(rows.every((row) => row.revoked_at !== null)).toBe(true);

    const sessionState = (await requirePool().query<{ readonly revoked_at: Date | null }>(
      "SELECT revoked_at FROM auth.sessions WHERE id = $1",
      [claims.sid],
    )).rows[0];
    expect(sessionState?.revoked_at).not.toBeNull();

    const auditRows = (await requirePool().query<{ readonly metadata: Record<string, unknown>; readonly action: string }>(
      "SELECT action, metadata FROM auth.audit_log WHERE actor_session_id = $1 ORDER BY occurred_at, id",
      [claims.sid],
    )).rows;
    expect(auditRows.some((row) => row.action === "session.refresh_reused")).toBe(true);
    expect(JSON.stringify(auditRows)).not.toContain(initial.refresh_token);
  });

  it("implements local, others, and global logout scopes exactly", async () => {
    const localUser = await createUser("logout-local@example.com");
    const local = requireData(await requireSessionService().create(localUser, {}));
    const localClaims = requireData(await requireTokenService().verifyAccessToken(local.access_token));
    expect((await requireSessionService().signOut(local, "local")).error).toBeNull();
    expect((await requirePool().query<{ readonly revoked_at: Date | null }>(
      "SELECT revoked_at FROM auth.sessions WHERE id = $1",
      [localClaims.sid],
    )).rows[0]?.revoked_at).not.toBeNull();

    const othersUser = await createUser("logout-others@example.com");
    const current = requireData(await requireSessionService().create(othersUser, {}));
    const other = requireData(await requireSessionService().create(othersUser, {}));
    const currentClaims = requireData(await requireTokenService().verifyAccessToken(current.access_token));
    const otherClaims = requireData(await requireTokenService().verifyAccessToken(other.access_token));
    expect((await requireSessionService().signOut(current, "others")).error).toBeNull();
    const othersStates = (await requirePool().query<{ readonly id: string; readonly revoked_at: Date | null }>(
      "SELECT id, revoked_at FROM auth.sessions WHERE user_id = $1 ORDER BY id",
      [othersUser.id],
    )).rows;
    expect(othersStates.find((row) => row.id === currentClaims.sid)?.revoked_at).toBeNull();
    expect(othersStates.find((row) => row.id === otherClaims.sid)?.revoked_at).not.toBeNull();

    const globalUser = await createUser("logout-global@example.com");
    const globalA = requireData(await requireSessionService().create(globalUser, {}));
    const globalB = requireData(await requireSessionService().create(globalUser, {}));
    expect((await requireSessionService().signOut(globalA, "global")).error).toBeNull();
    const globalStates = (await requirePool().query<{ readonly revoked_at: Date | null }>(
      "SELECT revoked_at FROM auth.sessions WHERE user_id = $1",
      [globalUser.id],
    )).rows;
    expect(globalStates).toHaveLength(2);
    expect(globalStates.every((row) => row.revoked_at !== null)).toBe(true);
    expect(globalB.refresh_token).not.toBe("");
  });
});
