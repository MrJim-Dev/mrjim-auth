import { spawn } from "node:child_process";
import { createHmac, generateKeyPairSync, randomUUID } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { Pool } from "pg";
import {
  AuditService,
  AuthorizationService,
  createAuthServer,
  OAuthService,
  PasswordService,
  SessionService,
  TokenService,
  type OAuthProvider,
  type OAuthProviderProfile,
} from "../../src/server/index.js";
import { migrate } from "../../src/postgres/migrate.js";
import { createPostgresAdapter, type PostgresAdapter } from "../../src/postgres/adapter.js";
import type {
  AuthRepository,
  AuditEventInput,
  AuditEventRecord,
  KeyProvider,
  RateLimiter,
} from "../../src/shared/contracts.js";
import type { AuthResult } from "../../src/shared/result.js";
import {
  lowercaseKeySchema,
  permissionKeySchema,
  roleKeySchema,
  sanitizeIdentityData,
  scopeIdentifierSchema,
  uuidSchema,
  type Identity,
  type User,
} from "../../src/shared/types.js";
import type { AuditStore } from "../../src/server/audit.js";

const NOW = new Date("2026-08-12T00:00:00.000Z");
const BASE_URL = "https://project.example.com/auth/v1";
const SITE_URL = "https://project.example.com";
const CALLBACK = "https://project.example.com/auth/callback";
const EVIL_ORIGIN = "https://attacker.example.com";
const EVIL_REDIRECT = "https://attacker.example.com/callback";
const TOKEN_HASH_KEY = Uint8Array.from({ length: 32 }, (_, index) => index + 1);
const ENCRYPTION_KEY = Uint8Array.from({ length: 32 }, (_, index) => index + 41);
const SECRET_SENTINEL = "raw-security-secret-9f3d";

type DisposablePostgres = {
  readonly root: string;
  readonly dataDirectory: string;
  readonly socketDirectory: string;
  readonly pool: Pool;
};

let disposable: DisposablePostgres | undefined;
let repository: PostgresAdapter | undefined;
let now = new Date(NOW);

async function command(
  executable: string,
  args: readonly string[],
  options: { readonly logPath?: string } = {},
): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const child = spawn(executable, args, { stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk: Buffer) => { stdout += chunk.toString(); });
    child.stderr.on("data", (chunk: Buffer) => { stderr += chunk.toString(); });
    child.once("error", reject);
    child.once("close", async (code) => {
      if (code === 0) {
        resolve();
        return;
      }
      const log = options.logPath === undefined ? "" : await readFile(options.logPath, "utf8").catch(() => "");
      reject(new Error(`${executable} exited with ${code ?? "unknown"}: ${(stderr || stdout || log).trim()}`));
    });
  });
}

async function startPostgres(): Promise<DisposablePostgres> {
  const root = await mkdtemp(join(tmpdir(), "mrjim-auth-security-"));
  const dataDirectory = join(root, "data");
  const socketDirectory = join(root, "socket");
  const logPath = join(root, "postgres.log");
  try {
    await mkdir(socketDirectory);
    await command("initdb", [
      "--pgdata", dataDirectory,
      "--auth=trust",
      "--username=postgres",
      "--no-locale",
      "--encoding=UTF8",
    ]);
    await command("pg_ctl", [
      "--pgdata", dataDirectory,
      "--log", logPath,
      "--options", `-h '' -k ${socketDirectory}`,
      "--wait", "start",
    ], { logPath });
    const pool = new Pool({
      connectionString: `postgresql://postgres@localhost/postgres?host=${encodeURIComponent(socketDirectory)}`,
      max: 16,
    });
    await pool.query("SELECT 1");
    return { root, dataDirectory, socketDirectory, pool };
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
      "--pgdata", value.dataDirectory,
      "--mode=immediate", "--wait", "stop",
    ]).catch(() => undefined);
    await rm(value.root, { recursive: true, force: true });
  }
}

function requirePool(): Pool {
  if (disposable === undefined) throw new Error("PostgreSQL fixture is unavailable");
  return disposable.pool;
}

function requireRepository(): PostgresAdapter {
  if (repository === undefined) throw new Error("PostgreSQL repository is unavailable");
  return repository;
}

function keyProvider(): KeyProvider {
  const pair = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return {
    getActiveKeyId: () => "security-test",
    getSigningKey: () => pair.privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    getVerificationKeys: () => new Map([
      ["security-test", pair.publicKey.export({ type: "spki", format: "pem" }).toString()],
    ]),
  };
}

function tokenServices(currentRepository: AuthRepository = requireRepository()): {
  readonly tokens: TokenService;
  readonly sessions: SessionService;
} {
  const tokens = new TokenService({
    issuer: BASE_URL,
    audience: "project",
    keyProvider: keyProvider(),
    tokenHashKey: TOKEN_HASH_KEY,
    clock: () => now,
  });
  return {
    tokens,
    sessions: new SessionService({ repository: currentRepository, tokens, clock: () => now }),
  };
}

function unwrap<T>(result: AuthResult<T>): T {
  if (result.data === null) throw new Error(`expected success, got ${JSON.stringify(result.error)}`);
  return result.data;
}

async function createApiKey(kind: "publishable" | "secret"): Promise<{ readonly raw: string; readonly id: string }> {
  const pool = requirePool();
  const raw = `${kind === "secret" ? "sk" : "pk"}_${randomUUID().replaceAll("-", "")}`;
  const id = uuidSchema.parse(randomUUID());
  const prefix = raw.slice(0, 11);
  const digest = createHmac("sha256", TOKEN_HASH_KEY).update(`apikey\0${raw}`, "utf8").digest();
  await pool.query(
    `INSERT INTO auth.api_keys
       (id, prefix, key_hash, kind, name, scopes, created_at, expires_at, revoked_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, NULL, NULL)`,
    [id, prefix, digest, kind, `security-${kind}-${id.slice(0, 8)}`, [], now],
  );
  return { raw, id };
}

function createServer(rateLimiter?: RateLimiter) {
  return createAuthServer({
    environment: "test",
    baseUrl: BASE_URL,
    siteUrl: SITE_URL,
    database: requireRepository(),
    signingKeys: {
      issuer: BASE_URL,
      audience: "project",
      activeKeyId: "security-test",
      keys: { "security-test": keyProvider().getSigningKey() },
    },
    secrets: { tokenHashKey: TOKEN_HASH_KEY, encryptionKey: ENCRYPTION_KEY },
    email: { send: async () => undefined },
    redirects: { allowed: [CALLBACK] },
    ...(rateLimiter === undefined ? {} : { rateLimiter }),
  });
}

function request(
  apiKey: string,
  path: string,
  init: RequestInit = {},
): Request {
  const headers = new Headers(init.headers);
  headers.set("apikey", apiKey);
  return new Request(`${BASE_URL}${path}`, { ...init, headers });
}

async function responseJson(response: Response): Promise<Record<string, unknown>> {
  return await response.json() as Record<string, unknown>;
}

function providerProfile(subject: string, email: string): OAuthProviderProfile {
  return {
    provider: "google",
    subject,
    issuer: "https://accounts.google.com",
    email,
    emailVerified: true,
    claims: sanitizeIdentityData({ sub: subject, email, email_verified: true }),
  };
}

function testProvider(): OAuthProvider {
  return {
    name: "google",
    clientId: "google-security-client",
    scopes: ["openid", "email", "profile"],
    capabilities: { authorization_code: true, pkce: true, identity_linking: true },
    authorizationUrl: (input) => `https://accounts.example/authorize?client_id=${input.clientId}&redirect_uri=${encodeURIComponent(input.redirectUri)}&state=${input.state}&code_challenge=${input.codeChallenge}&code_challenge_method=S256`,
    exchange: async (input) => providerProfile(`callback-${input.code}`, `${input.code}@example.com`),
  };
}

function oauthService(provider: OAuthProvider = testProvider()): OAuthService {
  const { sessions } = tokenServices();
  return new OAuthService({
    repository: requireRepository(),
    sessions,
    providers: [provider],
    tokenHashKey: TOKEN_HASH_KEY,
    encryptionKey: ENCRYPTION_KEY,
    allowedRedirects: [CALLBACK],
    clock: () => now,
  });
}

describe("Task 14 authentication abuse acceptance paths", () => {
  beforeAll(async () => {
    disposable = await startPostgres();
    await migrate(disposable.pool, { direction: "up" });
    repository = createPostgresAdapter({ pool: disposable.pool });
  }, 120_000);

  beforeEach(() => {
    now = new Date(NOW);
  });

  afterAll(async () => {
    await repository?.close();
    if (disposable !== undefined) await stopPostgres(disposable);
  }, 120_000);

  it("rate-limits credential stuffing by both IP and normalized identifier before password work", async () => {
    const calls: Array<{ readonly key: string; readonly limit: number; readonly bucket: string }> = [];
    const limiter: RateLimiter = {
      consume: async (key, policy) => {
        calls.push({ key, limit: policy.limit, bucket: policy.bucket ?? "" });
        return { allowed: false, remaining: 0, retryAfterSeconds: 30 };
      },
    };
    const apiKey = await createApiKey("publishable");
    const server = createServer(limiter);
    const response = await server.handle(request(apiKey.raw, "/token?grant_type=password", {
      method: "POST",
      headers: { "content-type": "application/json", "x-request-id": "stuffing-test" },
      body: JSON.stringify({ email: "victim@example.com", password: "wrong-password" }),
    }));

    expect(response.status).toBe(429);
    expect(response.headers.get("retry-after")).toBe("1");
    expect(await responseJson(response)).toMatchObject({ error: { code: "rate_limit_exceeded" } });
    expect(calls).toHaveLength(2);
    expect(calls.map((call) => call.key)).toEqual(expect.arrayContaining([
      "ip:unknown",
      "identifier:victim@example.com",
    ]));
    expect(calls.every((call) => call.limit === 10 && call.bucket === "sign_in")).toBe(true);
  });

  it("returns indistinguishable public results for existing and missing users", async () => {
    const current = requireRepository();
    const email = `enumeration-${randomUUID()}@example.com`;
    const user = await current.users.create({
      email,
      email_confirmed_at: NOW,
      confirmed_at: NOW,
    });
    const password = new PasswordService();
    await current.passwordCredentials.upsert(user.id, await password.hash("correct horse battery staple"), NOW);

    const apiKey = await createApiKey("publishable");
    const server = createServer();
    const existingSignIn = await server.handle(request(apiKey.raw, "/token?grant_type=password", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, password: "wrong password" }),
    }));
    const missingSignIn = await server.handle(request(apiKey.raw, "/token?grant_type=password", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: `missing-${randomUUID()}@example.com`, password: "wrong password" }),
    }));
    const existingSignInBody = await responseJson(existingSignIn);
    const missingSignInBody = await responseJson(missingSignIn);
    expect(existingSignIn.status).toBe(401);
    expect(missingSignIn.status).toBe(401);
    expect(existingSignInBody.error).toMatchObject({ code: "invalid_credentials", message: "Invalid login credentials" });
    expect(missingSignInBody.error).toMatchObject({ code: "invalid_credentials", message: "Invalid login credentials" });

    const existingRecovery = await server.handle(request(apiKey.raw, "/recover", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, redirect_to: CALLBACK }),
    }));
    const missingRecovery = await server.handle(request(apiKey.raw, "/recover", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: `missing-recovery-${randomUUID()}@example.com`, redirect_to: CALLBACK }),
    }));
    expect(existingRecovery.status).toBe(200);
    expect(missingRecovery.status).toBe(200);
    expect(await responseJson(existingRecovery)).toEqual(await responseJson(missingRecovery));
  });

  it("contains refresh-token replay by revoking the whole refresh family", async () => {
    const user = await requireRepository().users.create({ email: `refresh-${randomUUID()}@example.com` });
    const { sessions } = tokenServices();
    const created = unwrap(await sessions.create(user, { ip_address: "198.51.100.20", user_agent: "security-test" }));
    const rotated = unwrap(await sessions.refresh(created.refresh_token));
    expect(rotated.refresh_token).not.toBe(created.refresh_token);

    const replay = await sessions.refresh(created.refresh_token);
    expect(replay).toMatchObject({ data: null, error: { code: "refresh_token_reused", status: 401 } });
    expect(await sessions.refresh(rotated.refresh_token)).toMatchObject({
      data: null,
      error: expect.objectContaining({ code: expect.stringMatching(/invalid_token|session_expired|refresh_token_reused/) }),
    });
    const audit = await requirePool().query<{ action: string; metadata: Record<string, unknown> }>(
      "SELECT action, metadata FROM auth.audit_log WHERE action = 'session.refresh_reused' ORDER BY occurred_at DESC LIMIT 1",
    );
    expect(audit.rows[0]).toMatchObject({ action: "session.refresh_reused" });
    expect(JSON.stringify(audit.rows[0]?.metadata)).not.toContain(created.refresh_token);
  });

  it("rejects a stolen OAuth callback code without its verifier and consumes state once", async () => {
    const service = oauthService();
    const authorized = unwrap(await service.authorize({ provider: "google", redirectTo: CALLBACK }));
    const callback = unwrap(await service.callback({
      provider: "google",
      code: `provider-${randomUUID()}`,
      state: authorized.state,
      redirectTo: CALLBACK,
    }));

    expect(await service.exchangeCode({
      code: callback.code,
      codeVerifier: "b".repeat(43),
      redirectTo: CALLBACK,
    })).toMatchObject({ data: null, error: { code: "invalid_token", status: 401 } });
    expect(unwrap(await service.exchangeCode({
      code: callback.code,
      codeVerifier: authorized.codeVerifier,
      redirectTo: CALLBACK,
    })).identity.provider).toBe("google");
    expect(await service.callback({
      provider: "google",
      code: `provider-replay-${randomUUID()}`,
      state: authorized.state,
      redirectTo: CALLBACK,
    })).toMatchObject({ data: null, error: { code: "oauth_state_invalid" } });
  });

  it("rejects open redirects before OAuth state is issued", async () => {
    const result = await oauthService().authorize({ provider: "google", redirectTo: EVIL_REDIRECT });
    expect(result).toMatchObject({ data: null, error: { code: "redirect_not_allowed", status: 400 } });
  });

  it("rejects OAuth identity collision and account-link takeover attempts", async () => {
    const service = oauthService();
    const firstProfile = providerProfile(`collision-${randomUUID()}`, `collision-${randomUUID()}@example.com`);
    const first = unwrap(await service.signInFromProfile(firstProfile));
    const second = unwrap(await service.signInFromProfile(providerProfile(
      `other-${randomUUID()}`,
      `other-${randomUUID()}@example.com`,
    )));

    expect(await service.linkIdentity({ session: second.session }, firstProfile)).toMatchObject({
      data: null,
      error: { code: "identity_already_linked", status: 409 },
    });
    const owner = await requireRepository().identities.findByProviderSubject("google", firstProfile.subject);
    expect(owner?.user_id).toBe(first.user.id);
    expect(owner?.user_id).not.toBe(second.user.id);
  });

  it("refuses to unlink the final usable identity", async () => {
    const service = oauthService();
    const created = unwrap(await service.signInFromProfile(providerProfile(
      `unlink-${randomUUID()}`,
      `unlink-${randomUUID()}@example.com`,
    )));
    const identities = await requireRepository().identities.listByUserId(created.user.id);
    const identity = identities[0] as Identity | undefined;
    if (identity === undefined) throw new Error("OAuth identity was not persisted");

    expect(await service.unlinkIdentity({ session: created.session }, identity.id)).toMatchObject({
      data: null,
      error: { code: "identity_unlink_not_allowed", status: 400 },
    });
  });

  it("does not authorize an expired scoped role", async () => {
    const current = requireRepository();
    const user = await current.users.create({ email: `scope-expiry-${randomUUID()}@example.com` });
    const suffix = randomUUID().slice(0, 8);
    const resource = lowercaseKeySchema.parse(`tenant_${suffix}`);
    const role = await current.roles.create({
      key: roleKeySchema.parse(`expired_${suffix}`),
      name: "Expired scoped role",
      rank: 1,
    });
    const permission = await current.permissions.create({
      key: permissionKeySchema.parse(`${resource}.read`),
      resource,
      action: lowercaseKeySchema.parse("read"),
    });
    const scope = { type: "tenant", id: scopeIdentifierSchema.parse(`tenant_${suffix}`) };
    await current.authorization.setRolePermissions(role.id, [permission.id]);
    await current.authorization.assignRole({
      user_id: user.id,
      role_id: role.id,
      scope,
      expires_at: new Date(NOW.getTime() + 1_000),
    }, { now: NOW });

    const service = new AuthorizationService({
      repository: current,
      clock: () => new Date(NOW.getTime() + 2_000),
    });
    expect(await service.getPermissions(user.id, scope)).toEqual([]);
    await expect(service.authorize({ user_id: user.id }, { all: [permission.key] })).rejects.toMatchObject({
      code: "insufficient_permission",
      status: 403,
    });
  });

  it("rejects CSRF-sensitive cookie requests from an untrusted browser origin", async () => {
    const apiKey = await createApiKey("publishable");
    const server = createServer();
    const response = await server.handle(request(apiKey.raw, "/signup", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        origin: EVIL_ORIGIN,
        cookie: "mrjim_session=attacker-controlled",
        "sec-fetch-site": "cross-site",
        "sec-fetch-mode": "cors",
      },
      body: JSON.stringify({ email: `csrf-${randomUUID()}@example.com`, password: "correct horse battery staple" }),
    }));

    expect(response.status).toBe(403);
    expect(await responseJson(response)).toMatchObject({ error: { code: "forbidden" } });
  });

  it("rejects secret API keys in browser-origin requests", async () => {
    const apiKey = await createApiKey("secret");
    const server = createServer();
    const response = await server.handle(request(apiKey.raw, "/signup", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        origin: SITE_URL,
        "sec-fetch-site": "same-origin",
        "sec-fetch-mode": "cors",
      },
      body: JSON.stringify({ email: `secret-browser-${randomUUID()}@example.com`, password: "correct horse battery staple" }),
    }));

    expect(response.status).toBe(403);
    expect(await responseJson(response)).toMatchObject({ error: { code: "forbidden" } });
  });

  it("redacts audit injection at the service and PostgreSQL boundaries", async () => {
    const appended: unknown[] = [];
    const row: AuditEventRecord = {
      id: uuidSchema.parse(randomUUID()),
      actor_user_id: null,
      actor_key_id: null,
      actor_session_id: null,
      action: "security.legacy",
      target_type: "user",
      target_id: null,
      ip_address: null,
      user_agent: null,
      metadata: { event: "legacy", nested: { password: SECRET_SENTINEL, visible: "kept" } } as never,
      outcome: "failure",
      occurred_at: NOW,
    };
    const store: AuditStore = {
      append: async (input: AuditEventInput) => { appended.push(input); },
      list: async () => ({ events: [row], total: 1 }),
    };
    const audit = new AuditService({ store, clock: () => now });
    const rejected = await audit.append({
      action: "security.injected",
      target_type: "user",
      metadata: { event: "injected", nested: { password: SECRET_SENTINEL } } as never,
      outcome: "failure",
    });
    expect(rejected).toMatchObject({ data: null, error: { code: "invalid_request" } });
    expect(appended).toHaveLength(0);

    const listed = unwrap(await audit.list());
    expect(listed.events[0]?.metadata).toEqual({ event: "legacy", nested: { visible: "kept" } });
    expect(JSON.stringify(listed)).not.toContain(SECRET_SENTINEL);

    await expect(requirePool().query(
      `INSERT INTO auth.audit_log (action, target_type, metadata, outcome, occurred_at)
       VALUES ('security.injected', 'user', $1::jsonb, 'failure', $2)`,
      [JSON.stringify({ password: SECRET_SENTINEL }), NOW],
    )).rejects.toThrow(/audit_metadata_redaction|redaction/i);
  });

  it("rejects oversized user metadata before allocating or persisting it", async () => {
    const apiKey = await createApiKey("publishable");
    const server = createServer();
    const body = JSON.stringify({
      email: `oversized-${randomUUID()}@example.com`,
      password: "correct horse battery staple",
      options: { data: { payload: "x".repeat(70 * 1024) } },
    });
    const response = await server.handle(request(apiKey.raw, "/signup", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body,
    }));

    expect(new TextEncoder().encode(body).byteLength).toBeGreaterThan(64 * 1024);
    expect(response.status).toBe(413);
    expect(await responseJson(response)).toMatchObject({ error: { code: "invalid_request" } });
  });
});
