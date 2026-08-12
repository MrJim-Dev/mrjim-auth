import { spawn } from "node:child_process";
import { mkdtemp, mkdir, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Pool } from "pg";
import {
  ADMIN_MUTATION_RATE_LIMIT_POLICY,
  InMemoryRateLimiter,
  LOGIN_IDENTIFIER_RATE_LIMIT_POLICY,
  LOGIN_IP_RATE_LIMIT_POLICY,
  OAUTH_START_RATE_LIMIT_POLICY,
  OTP_ISSUE_RATE_LIMIT_POLICY,
  OTP_VERIFY_RATE_LIMIT_POLICY,
  PostgresRateLimiter,
  RECOVERY_RATE_LIMIT_POLICY,
  RESEND_RATE_LIMIT_POLICY,
  SIGNUP_RATE_LIMIT_POLICY,
  type RateLimitQueryExecutor,
} from "../../src/server/rate-limit.js";
import type { RateLimitPolicy } from "../../src/shared/contracts.js";
import { migrate } from "../../src/postgres/migrate.js";

const HMAC_KEY = new Uint8Array(32).fill(7);
const NOW = new Date("2026-08-12T00:00:00.000Z");

const namedPolicies = [
  SIGNUP_RATE_LIMIT_POLICY,
  LOGIN_IP_RATE_LIMIT_POLICY,
  LOGIN_IDENTIFIER_RATE_LIMIT_POLICY,
  RECOVERY_RATE_LIMIT_POLICY,
  RESEND_RATE_LIMIT_POLICY,
  OTP_ISSUE_RATE_LIMIT_POLICY,
  OTP_VERIFY_RATE_LIMIT_POLICY,
  OAUTH_START_RATE_LIMIT_POLICY,
  ADMIN_MUTATION_RATE_LIMIT_POLICY,
] as const;

type Cluster = {
  readonly root: string;
  readonly dataDirectory: string;
  readonly socketDirectory: string;
};

type DisposablePostgres = {
  readonly cluster: Cluster;
  readonly pool: Pool;
};

async function command(
  executable: string,
  args: readonly string[],
  options: { readonly logPath?: string; readonly cwd?: string } = {},
): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const child = spawn(executable, args, { cwd: options.cwd, stdio: ["ignore", "ignore", "pipe"] });
    let stderr = "";
    child.stderr.on("data", (chunk: Buffer) => { stderr += chunk.toString(); });
    child.once("error", reject);
    child.once("close", async (code) => {
      if (code === 0) {
        resolve();
        return;
      }
      const log = options.logPath === undefined ? "" : await readFile(options.logPath, "utf8").catch(() => "");
      reject(new Error(`${executable} failed: ${(stderr || log).trim()}`));
    });
  });
}

async function startPostgres(label: string): Promise<DisposablePostgres> {
  const root = await mkdtemp(join(tmpdir(), `${label}-`));
  const dataDirectory = join(root, "data");
  const socketDirectory = join(root, "socket");
  const cluster = { root, dataDirectory, socketDirectory };
  try {
    await mkdir(socketDirectory);
    await command("initdb", ["--pgdata", dataDirectory, "--auth=trust", "--username=postgres", "--no-locale", "--encoding=UTF8"]);
    await command("pg_ctl", [
      "--pgdata", dataDirectory,
      "--log", join(root, "postgres.log"),
      "--options", `-h '' -k ${socketDirectory}`,
      "--wait", "start",
    ], { logPath: join(root, "postgres.log") });
    const pool = new Pool({
      connectionString: `postgresql://postgres@localhost/postgres?host=${encodeURIComponent(socketDirectory)}`,
      max: 12,
    });
    await pool.query("SELECT 1");
    return { cluster, pool };
  } catch (error) {
    await command("pg_ctl", ["--pgdata", dataDirectory, "--mode=immediate", "--wait", "stop"]).catch(() => undefined);
    await rm(root, { recursive: true, force: true });
    throw error;
  }
}

async function stopPostgres(value: DisposablePostgres): Promise<void> {
  try {
    await value.pool.end();
  } finally {
    await command("pg_ctl", [
      "--pgdata", value.cluster.dataDirectory,
      "--mode=immediate", "--wait", "stop",
    ]).catch(() => undefined);
    await rm(value.cluster.root, { recursive: true, force: true });
  }
}

function policy(overrides: Partial<RateLimitPolicy> = {}): RateLimitPolicy {
  return {
    limit: 2,
    windowSeconds: 10,
    bucket: "test-login",
    ...overrides,
  };
}

describe("Task 12 rate-limit adapters", () => {
  it("exports frozen, operation-specific named policies", () => {
    expect(namedPolicies.every((value) => Object.isFrozen(value))).toBe(true);
    expect(namedPolicies.map((value) => value.bucket)).toEqual([
      "signup",
      "login:ip",
      "login:identifier",
      "recovery",
      "resend",
      "otp:issue",
      "otp:verify",
      "oauth:start",
      "admin:mutation",
    ]);
    expect(LOGIN_IP_RATE_LIMIT_POLICY).not.toBe(LOGIN_IDENTIFIER_RATE_LIMIT_POLICY);
    expect(LOGIN_IP_RATE_LIMIT_POLICY).not.toEqual(LOGIN_IDENTIFIER_RATE_LIMIT_POLICY);
  });

  it("enforces an exact in-memory concurrent winner and keeps buckets independent", async () => {
    let current = NOW;
    const limiter = new InMemoryRateLimiter({ clock: () => new Date(current) });
    const decisions = await Promise.all(
      Array.from({ length: 8 }, () => limiter.consume("same-caller", policy({ limit: 3 }))),
    );

    expect(decisions.filter((value) => value.allowed)).toHaveLength(3);
    expect(decisions.filter((value) => !value.allowed)).toHaveLength(5);
    for (const decision of decisions.filter((value) => !value.allowed)) {
      expect(decision.retryAfterSeconds).toBeGreaterThanOrEqual(1);
      expect(decision.retryAfterSeconds).toBeLessThanOrEqual(10);
      expect(Number.isInteger(decision.retryAfterSeconds)).toBe(true);
    }

    await expect(limiter.consume("same-caller", policy({ bucket: "different-operation", limit: 1 })))
      .resolves.toMatchObject({ allowed: true, remaining: 0 });
    current = new Date(NOW.getTime() + 11_000);
    await expect(limiter.consume("same-caller", policy({ limit: 1 })))
      .resolves.toMatchObject({ allowed: true, remaining: 0 });
  });

  it("rejects malformed keys, policies, clocks, and accessor-backed inputs", async () => {
    expect(() => new InMemoryRateLimiter({ clock: () => new Date("invalid") })).toThrow(/clock/i);
    const limiter = new InMemoryRateLimiter({ clock: () => new Date(NOW) });
    await expect(limiter.consume("", policy())).rejects.toThrow(/key/i);
    await expect(limiter.consume("caller", { limit: 0, windowSeconds: 10 })).rejects.toThrow(/policy|limit/i);
    await expect(limiter.consume("caller", { limit: 1, windowSeconds: 10, bucket: "" })).rejects.toThrow(/bucket/i);

    let reads = 0;
    const hostilePolicy = Object.create(null) as Record<string, unknown>;
    Object.defineProperty(hostilePolicy, "limit", {
      configurable: true,
      get: () => { reads += 1; throw new Error("policy-secret"); },
    });
    await expect(limiter.consume("caller", hostilePolicy as never)).rejects.toThrow(/policy/i);
    expect(reads).toBe(0);
  });

  let disposable: DisposablePostgres | undefined;

  beforeAll(async () => {
    disposable = await startPostgres("mrjim-auth-task12-rate-limit");
    await migrate(disposable.pool, { direction: "up" });
  }, 120_000);

  afterAll(async () => {
    if (disposable !== undefined) await stopPostgres(disposable);
  });

  it("atomically allows exactly the configured PostgreSQL limit and persists only digests", async () => {
    if (disposable === undefined) throw new Error("PostgreSQL fixture is unavailable");
    const limiter = new PostgresRateLimiter({ pool: disposable.pool, hmacKey: HMAC_KEY });
    const decisions = await Promise.all(
      Array.from({ length: 9 }, () => limiter.consume("ip:198.51.100.20", policy({ limit: 3, windowSeconds: 60, bucket: "login:ip" }))),
    );
    expect(decisions.filter((value) => value.allowed)).toHaveLength(3);
    expect(decisions.filter((value) => !value.allowed)).toHaveLength(6);
    expect(decisions.filter((value) => !value.allowed).every((value) => Number.isInteger(value.retryAfterSeconds))).toBe(true);

    await expect(limiter.consume("ip:198.51.100.20", policy({ limit: 1, bucket: "oauth:start" })))
      .resolves.toMatchObject({ allowed: true });

    const rows = await disposable.pool.query<{ key_digest: Buffer; bucket: string; count: number }>(
      "SELECT key_digest, bucket, count FROM auth.rate_limit_buckets ORDER BY bucket",
    );
    expect(rows.rows).toHaveLength(2);
    expect(rows.rows.every((row) => row.key_digest.byteLength === 32)).toBe(true);
    expect(rows.rows.map((row) => row.key_digest.toString("utf8"))).not.toContain("ip:198.51.100.20");
    expect(rows.rows.map((row) => row.bucket)).toEqual(["login:ip", "oauth:start"]);
  });

  it("uses database time, cleans expired rows, and fails closed on malformed adapter output", async () => {
    const calls: Array<{ readonly sql: string; readonly values: readonly unknown[] }> = [];
    const executor: RateLimitQueryExecutor = {
      query: async <Row extends object>(sql: string, values: readonly unknown[]) => {
        calls.push({ sql, values });
        return {
          rows: [{ allowed: false, remaining: 0, retry_after_seconds: 4 } as Row],
        };
      },
    };
    const limiter = new PostgresRateLimiter({ pool: executor, hmacKey: HMAC_KEY });
    await expect(limiter.consume("raw-key-must-not-be-sent", policy())).resolves.toMatchObject({
      allowed: false,
      retryAfterSeconds: 4,
    });
    expect(calls[0]?.sql).toContain("clock_timestamp()");
    expect(calls[0]?.sql).toContain("ON CONFLICT");
    expect(calls[0]?.values).not.toContain("raw-key-must-not-be-sent");
    expect(calls[0]?.values.some((value) => value instanceof Uint8Array && value.byteLength === 32)).toBe(true);

    if (disposable === undefined) throw new Error("PostgreSQL fixture is unavailable");
    await disposable.pool.query(
      `INSERT INTO auth.rate_limit_buckets
        (key_digest, bucket, window_start, window_end, count)
       VALUES ($1, 'expired', now() - interval '2 minutes', now() - interval '1 minute', 1)`,
      [Buffer.alloc(32, 91)],
    );
    const realLimiter = new PostgresRateLimiter({ pool: disposable.pool, hmacKey: HMAC_KEY });
    await realLimiter.consume("cleanup-caller", policy({ bucket: "cleanup" }));
    const expired = await disposable.pool.query<{ count: number }>(
      "SELECT count(*)::int AS count FROM auth.rate_limit_buckets WHERE bucket = 'expired'",
    );
    expect(expired.rows[0]?.count).toBe(0);

    const malformed: RateLimitQueryExecutor = {
      query: async () => ({ rows: [{ allowed: "yes" }] }),
    };
    const malformedLimiter = new PostgresRateLimiter({ pool: malformed, hmacKey: HMAC_KEY });
    await expect(malformedLimiter.consume("adapter-caller", policy())).rejects.toThrow(/adapter|decision/i);
    await expect(malformedLimiter.consume("adapter-secret-caller", policy())).rejects.not.toThrow(/adapter-secret-caller/);
  });
});
