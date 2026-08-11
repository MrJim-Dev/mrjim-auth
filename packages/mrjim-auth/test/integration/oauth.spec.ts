import { generateKeyPairSync } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm } from "node:fs/promises";
import { spawn } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Pool } from "pg";
import type { AuthRepository, KeyProvider } from "../../src/shared/contracts.js";
import { migrate } from "../../src/postgres/migrate.js";
import { createPostgresAdapter, type PostgresAdapter } from "../../src/postgres/adapter.js";
import { sanitizeIdentityData, uuidSchema, type Identity, type User } from "../../src/shared/types.js";
import { SessionService } from "../../src/server/sessions.js";
import { TokenService } from "../../src/server/tokens.js";
import {
  GoogleOAuthProvider,
  OAuthProviderError,
  type OAuthProvider,
  type OAuthProviderProfile,
} from "../../src/server/oauth-providers.js";
import { OAuthService } from "../../src/server/oauth.js";
import { callbackRoute, providersRoute } from "../../src/server/routes/oauth.js";

const NOW = new Date("2026-08-11T06:00:00.000Z");
const CALLBACK = "https://project.example.com/auth/callback";
const ALT_CALLBACK = "https://project.example.com/auth/alternate";
const TOKEN_HASH_KEY = Uint8Array.from({ length: 32 }, (_, index) => index + 1);

type DisposablePostgres = {
  readonly root: string;
  readonly dataDirectory: string;
  readonly pool: Pool;
};

let disposable: DisposablePostgres | undefined;
let repository: PostgresAdapter | undefined;
let now = NOW;

async function command(commandName: string, args: readonly string[], logPath?: string): Promise<void> {
  const result = await new Promise<{ readonly code: number | null; readonly stderr: string }>((resolve, reject) => {
    const child = spawn(commandName, args, { stdio: ["ignore", "ignore", "pipe"] });
    let stderr = "";
    child.stderr.on("data", (chunk: Buffer) => { stderr += chunk.toString(); });
    child.once("error", reject);
    child.once("close", (code) => resolve({ code, stderr }));
  });
  if (result.code === 0) return;
  const log = logPath === undefined ? "" : await readFile(logPath, "utf8").catch(() => "");
  throw new Error(`${commandName} ${args.join(" ")} failed: ${(result.stderr || log).trim()}`);
}

async function startPostgres(): Promise<DisposablePostgres> {
  const root = await mkdtemp(join(tmpdir(), "mrjim-auth-task7-oauth-"));
  const dataDirectory = join(root, "data");
  const socketDirectory = join(root, "socket");
  const logPath = join(root, "postgres.log");
  try {
    await mkdir(socketDirectory);
    await command("initdb", ["--pgdata", dataDirectory, "--auth=trust", "--username=postgres", "--no-locale", "--encoding=UTF8"]);
    await command("pg_ctl", ["--pgdata", dataDirectory, "--log", logPath, "--options", `-h '' -k ${socketDirectory}`, "--wait", "start"], logPath);
    const pool = new Pool({
      connectionString: `postgresql://postgres@localhost/postgres?host=${encodeURIComponent(socketDirectory)}`,
      max: 16,
    });
    await pool.query("SELECT 1");
    return { root, dataDirectory, pool };
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
    await command("pg_ctl", ["--pgdata", value.dataDirectory, "--mode=immediate", "--wait", "stop"]).catch(() => undefined);
    await rm(value.root, { recursive: true, force: true });
  }
}

function keyProvider(): KeyProvider {
  const pair = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return {
    getActiveKeyId: () => "task7",
    getSigningKey: () => pair.privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    getVerificationKeys: () => new Map([
      ["task7", pair.publicKey.export({ type: "spki", format: "pem" }).toString()],
    ]),
  };
}

function createServices(currentRepository: AuthRepository = requireRepository()) {
  const tokens = new TokenService({
    issuer: "https://project.example.com/auth/v1",
    audience: "project",
    keyProvider: keyProvider(),
    tokenHashKey: TOKEN_HASH_KEY,
    clock: () => now,
  });
  const sessions = new SessionService({ repository: currentRepository, tokens, clock: () => now });
  return { tokens, sessions };
}

function requireRepository(): PostgresAdapter {
  if (repository === undefined) throw new Error("repository is not initialized");
  return repository;
}

function unwrap<T>(result: { readonly data: T | null; readonly error: unknown }): T {
  if (result.data === null) throw new Error(`expected success, got ${JSON.stringify(result.error)}`);
  return result.data;
}

function profile(overrides: Partial<OAuthProviderProfile> = {}): OAuthProviderProfile {
  const subject = overrides.subject ?? "google-subject-1";
  const email = overrides.email === undefined ? "alice@example.com" : overrides.email;
  const emailVerified = overrides.emailVerified ?? false;
  return {
    provider: "google",
    subject,
    issuer: "https://accounts.google.com",
    email,
    emailVerified,
    claims: sanitizeIdentityData({
      sub: subject,
      email: email ?? undefined,
      email_verified: email === null ? undefined : emailVerified,
      name: "Alice",
    }),
    ...overrides,
  };
}

function deterministicProvider(overrides: Partial<OAuthProvider> = {}): OAuthProvider {
  return {
    name: "google",
    clientId: "google-client-id",
    scopes: ["openid", "email", "profile"],
    capabilities: { authorization_code: true, pkce: true, identity_linking: true },
    authorizationUrl: (input) => `https://provider.example/authorize?client_id=${input.clientId}&redirect_uri=${encodeURIComponent(input.redirectUri)}&response_type=code&scope=${encodeURIComponent(input.scopes.join(" "))}&state=${input.state}&nonce=${input.nonce}&code_challenge=${input.codeChallenge}&code_challenge_method=S256`,
    exchange: async (input) => {
      if (input.code === "wrong-verifier") throw new OAuthProviderError("provider rejected verifier");
      return profile();
    },
    ...overrides,
  };
}

describe("Task 7 OAuth and identity safety", () => {
  beforeAll(async () => {
    disposable = await startPostgres();
    await migrate(disposable.pool, { direction: "up" });
    repository = createPostgresAdapter({ pool: disposable.pool });
  }, 120_000);

  afterAll(async () => {
    await repository?.close();
    if (disposable !== undefined) await stopPostgres(disposable);
  });

  it("applies a forward-only callback migration without rewriting 0001-0004", async () => {
    const rows = await disposable?.pool.query<{ version: string }>(
      "SELECT version FROM auth.schema_migrations ORDER BY migration_order",
    );
    expect(rows?.rows.map((row) => row.version)).toContain("0005_oauth_callback");
    expect(await disposable?.pool.query<{ purpose: string }>(
      "SELECT pg_get_constraintdef(c.oid) AS definition FROM pg_constraint c JOIN pg_class t ON t.oid = c.conrelid WHERE t.relname = 'one_time_tokens' AND c.conname = 'one_time_tokens_purpose_check'",
    )).toMatchObject({ rows: [{ definition: expect.stringContaining("oauth_callback") }] });
    expect(await disposable?.pool.query<{ purpose: string }>(
      "SELECT pg_get_constraintdef(c.oid) AS definition FROM pg_constraint c JOIN pg_class t ON t.oid = c.conrelid WHERE t.relname = 'one_time_tokens' AND c.conname = 'one_time_tokens_oauth_callback_ttl_check'",
    )).toMatchObject({ rows: [{ definition: expect.stringContaining("00:01:00") }] });
  });

  it("binds authorization to exact redirect, flow, PKCE S256, nonce, and one-use state", async () => {
    const { sessions } = createServices();
    const service = new OAuthService({
      repository: requireRepository(),
      sessions,
      providers: [deterministicProvider()],
      tokenHashKey: TOKEN_HASH_KEY,
      encryptionKey: Uint8Array.from({ length: 32 }, (_, index) => index + 41),
      allowedRedirects: [CALLBACK, ALT_CALLBACK],
      clock: () => now,
    });
    expect(service.listProviders()).toEqual([{
      name: "google",
      scopes: ["openid", "email", "profile"],
      capabilities: { authorization_code: true, pkce: true, identity_linking: true },
    }]);
    expect(JSON.stringify(service.listProviders())).not.toMatch(/client.?id|secret|token/i);
    const discoveryResponse = providersRoute(service, new Request("https://project.example.com/providers"));
    expect(discoveryResponse.headers.get("cache-control")).toBe("no-store");
    expect(await discoveryResponse.json()).toMatchObject({ data: [{ name: "google" }], error: null });
    expect(await service.authorize({ provider: "bad provider", redirectTo: CALLBACK })).toMatchObject({
      data: null,
      error: { code: "invalid_request" },
    });
    const authorized = unwrap(await service.authorize({ provider: "google", redirectTo: CALLBACK }));
    expect(authorized.url).toContain("code_challenge_method=S256");
    expect(authorized.url).not.toContain("client_secret");
    expect(authorized.url).not.toContain("refresh_token");
    const callback = unwrap(await service.callback({
      provider: "google",
      code: "provider-code",
      state: authorized.state,
      redirectTo: CALLBACK,
    }));
    expect(callback.redirect).toBe(CALLBACK);
    expect(callback.url).toContain("code=");
    expect(callback.url).not.toContain("access_token");
    expect(callback.url).not.toContain("refresh_token");
    const callbackRedirectResponse = await callbackRoute(
      service,
      "google",
      new Request(`https://project.example.com/callback?code=provider-code&state=${encodeURIComponent(unwrap(await service.authorize({ provider: "google", redirectTo: CALLBACK })).state)}&redirect_to=${encodeURIComponent(CALLBACK)}`),
    );
    expect(callbackRedirectResponse.status).toBe(303);
    expect(callbackRedirectResponse.headers.get("cache-control")).toBe("no-store");
    expect(callbackRedirectResponse.headers.get("location")).not.toMatch(/access_token|refresh_token/i);
    expect(await service.callback({ provider: "google", code: "provider-code", state: authorized.state, redirectTo: CALLBACK })).toMatchObject({
      data: null,
      error: { code: "oauth_state_invalid" },
    });
    expect(await service.exchangeCode({ code: callback.code, codeVerifier: "not-the-verifier", redirectTo: CALLBACK })).toMatchObject({
      data: null,
      error: { code: "invalid_token" },
    });
    expect(await service.exchangeCode({ code: callback.code, codeVerifier: authorized.codeVerifier, redirectTo: ALT_CALLBACK })).toMatchObject({
      data: null,
      error: { code: "invalid_token" },
    });
    expect(await service.exchangeCode({ code: callback.code, codeVerifier: authorized.codeVerifier, redirectTo: "https://evil.example.com/callback" })).toMatchObject({
      data: null,
      error: { code: "redirect_not_allowed" },
    });
    const expiringAuthorized = unwrap(await service.authorize({ provider: "google", redirectTo: CALLBACK }));
    const expiringCallback = unwrap(await service.callback({ provider: "google", code: "provider-code", state: expiringAuthorized.state, redirectTo: CALLBACK }));
    now = new Date(NOW.getTime() + 60 * 1000);
    expect(await service.exchangeCode({ code: expiringCallback.code, codeVerifier: expiringAuthorized.codeVerifier, redirectTo: CALLBACK })).toMatchObject({
      data: null,
      error: { code: "invalid_token" },
    });
    now = NOW;
    const exchanged = unwrap(await service.exchangeCode({ code: callback.code, codeVerifier: authorized.codeVerifier, redirectTo: CALLBACK }));
    expect(exchanged.session.user.email).toBe("alice@example.com");
    expect(await service.exchangeCode({ code: callback.code, codeVerifier: authorized.codeVerifier, redirectTo: CALLBACK })).toMatchObject({
      data: null,
      error: { code: "invalid_token" },
    });
  });

  it("rejects plain PKCE and expires state at ten minutes", async () => {
    const { sessions } = createServices();
    const service = new OAuthService({
      repository: requireRepository(),
      sessions,
      providers: [deterministicProvider()],
      tokenHashKey: TOKEN_HASH_KEY,
      encryptionKey: Uint8Array.from({ length: 32 }, (_, index) => index + 41),
      allowedRedirects: [CALLBACK],
      clock: () => now,
    });
    const authorized = unwrap(await service.authorize({ provider: "google", redirectTo: CALLBACK }));
    expect(await service.callback({
      provider: "google",
      code: "provider-code",
      state: authorized.state,
      redirectTo: CALLBACK,
      codeChallengeMethod: "plain",
    })).toMatchObject({ data: null, error: { code: "oauth_state_invalid" } });
    now = new Date(NOW.getTime() + 10 * 60 * 1000);
    expect(await service.callback({ provider: "google", code: "provider-code", state: authorized.state, redirectTo: CALLBACK })).toMatchObject({
      data: null,
      error: { code: "oauth_state_invalid" },
    });
    now = NOW;
  });

  it("signs in by provider subject, links only with a fresh session, and rejects collisions", async () => {
    const { sessions } = createServices();
    const service = new OAuthService({
      repository: requireRepository(),
      sessions,
      providers: [deterministicProvider({ exchange: async () => profile({ subject: "signed-link-subject", email: "signed-link@example.com" }) })],
      tokenHashKey: TOKEN_HASH_KEY,
      encryptionKey: Uint8Array.from({ length: 32 }, (_, index) => index + 41),
      allowedRedirects: [CALLBACK],
      clock: () => now,
      allowVerifiedEmailAutoLink: false,
    });
    const first = unwrap(await service.signInFromProfile(profile({ subject: "subject-a", email: "a@example.com" })));
    expect(first.identity.provider_subject).toBe("subject-a");
    const same = unwrap(await service.signInFromProfile(profile({ subject: "subject-a", email: "other@example.com" })));
    expect(same.user.id).toBe(first.user.id);
    const second = unwrap(await service.signInFromProfile(profile({ subject: "subject-b", email: "b@example.com" })));
    const owner = await service.linkIdentity(
      { session: second.session },
      profile({ subject: "subject-a", email: "a@example.com" }),
    );
    expect(owner).toMatchObject({ data: null, error: { code: "identity_already_linked" } });
    expect(await service.linkIdentity({ session: first.session }, profile({ subject: "subject-c", email: "c@example.com" }))).toMatchObject({
      data: expect.objectContaining({ identity: expect.objectContaining({ provider_subject: "subject-c" }) }),
    });
    const linkStart = unwrap(await service.linkIdentity({ session: first.session }, { provider: "google", redirectTo: CALLBACK }));
    if (!("state" in linkStart)) throw new Error("expected authenticated linking authorization");
    const linkedCallback = unwrap(await service.callback({ provider: "google", code: "provider-code", state: linkStart.state, redirectTo: CALLBACK }));
    const linked = unwrap(await service.exchangeCode({ code: linkedCallback.code, codeVerifier: linkStart.codeVerifier, redirectTo: CALLBACK }));
    expect(linked.user.id).toBe(first.user.id);
    expect(linked.identity.provider_subject).toBe("signed-link-subject");
    now = new Date(NOW.getTime() + 5 * 60 * 1000 + 1);
    expect(await service.linkIdentity({ session: first.session }, profile({ subject: "subject-d", email: "d@example.com" }))).toMatchObject({
      data: null,
      error: { code: "unauthorized" },
    });
    now = NOW;
  });

  it("keeps email auto-link opt-in and requires provider-verified email", async () => {
    const { sessions } = createServices();
    const service = new OAuthService({
      repository: requireRepository(),
      sessions,
      providers: [deterministicProvider()],
      tokenHashKey: TOKEN_HASH_KEY,
      encryptionKey: Uint8Array.from({ length: 32 }, (_, index) => index + 41),
      allowedRedirects: [CALLBACK],
      clock: () => now,
      allowVerifiedEmailAutoLink: true,
    });
    const passwordUser = await requireRepository().users.create({ email: "verified-link@example.com" });
    const unverified = await service.signInFromProfile(profile({ subject: "unverified", email: passwordUser.email ?? "", emailVerified: false }));
    expect(unverified).toMatchObject({ data: null, error: { code: "conflict" } });
    const verified = unwrap(await service.signInFromProfile(profile({ subject: "verified", email: passwordUser.email ?? "", emailVerified: true })));
    expect(verified.user.id).toBe(passwordUser.id);
    const audit = await disposable?.pool.query<{ action: string; metadata: Record<string, unknown> }>(
      "SELECT action, metadata FROM auth.audit_log WHERE target_id = $1 ORDER BY occurred_at DESC LIMIT 5",
      [verified.identity.id],
    );
    expect(audit?.rows.some((row) => row.action === "identity.email_auto_linked" && row.metadata.provider === "google")).toBe(true);
    expect(JSON.stringify(audit?.rows)).not.toMatch(/access_token|refresh_token|client_secret|code_verifier/i);
  });

  it("refuses to unlink the final usable login method and exposes only safe identities", async () => {
    const { sessions } = createServices();
    const service = new OAuthService({
      repository: requireRepository(),
      sessions,
      providers: [deterministicProvider()],
      tokenHashKey: TOKEN_HASH_KEY,
      encryptionKey: Uint8Array.from({ length: 32 }, (_, index) => index + 41),
      allowedRedirects: [CALLBACK],
      clock: () => now,
    });
    const created = unwrap(await service.signInFromProfile(profile({ subject: "unlink-subject", email: "unlink@example.com" })));
    const identity = (await requireRepository().identities.listByUserId(created.user.id))[0] as Identity;
    expect(JSON.stringify(identity)).not.toMatch(/access_token|refresh_token|client_secret|client_id/i);
    expect(await service.unlinkIdentity({ session: created.session }, identity.id)).toMatchObject({
      data: null,
      error: { code: "identity_unlink_not_allowed" },
    });
  });

  it("allows exactly one concurrent callback-code exchange and rolls back identity/session writes", async () => {
    const { sessions } = createServices();
    const service = new OAuthService({
      repository: requireRepository(),
      sessions,
      providers: [deterministicProvider({ exchange: async () => profile({ subject: "race-subject", email: "race@example.com" }) })],
      tokenHashKey: TOKEN_HASH_KEY,
      encryptionKey: Uint8Array.from({ length: 32 }, (_, index) => index + 41),
      allowedRedirects: [CALLBACK],
      clock: () => now,
    });
    const authorized = unwrap(await service.authorize({ provider: "google", redirectTo: CALLBACK }));
    const callback = unwrap(await service.callback({ provider: "google", code: "provider-code", state: authorized.state, redirectTo: CALLBACK }));
    const results = await Promise.all([
      service.exchangeCode({ code: callback.code, codeVerifier: authorized.codeVerifier, redirectTo: CALLBACK }),
      service.exchangeCode({ code: callback.code, codeVerifier: authorized.codeVerifier, redirectTo: CALLBACK }),
    ]);
    expect(results.filter((result) => result.data !== null)).toHaveLength(1);
    expect(results.filter((result) => result.error?.code === "invalid_token")).toHaveLength(1);
  });

  it("rolls back callback-code consumption when session creation fails", async () => {
    const brokenKeys = keyProvider();
    const failingTokens = new TokenService({
      issuer: "https://project.example.com/auth/v1",
      audience: "project",
      keyProvider: {
        ...brokenKeys,
        getSigningKey: () => { throw new Error("deterministic signing failure"); },
      },
      tokenHashKey: TOKEN_HASH_KEY,
      clock: () => now,
    });
    const failingSessions = new SessionService({ repository: requireRepository(), tokens: failingTokens, clock: () => now });
    const failingService = new OAuthService({
      repository: requireRepository(),
      sessions: failingSessions,
      providers: [deterministicProvider({ exchange: async () => profile({ subject: "rollback-subject", email: "rollback@example.com" }) })],
      tokenHashKey: TOKEN_HASH_KEY,
      encryptionKey: Uint8Array.from({ length: 32 }, (_, index) => index + 41),
      allowedRedirects: [CALLBACK],
      clock: () => now,
    });
    const authorized = unwrap(await failingService.authorize({ provider: "google", redirectTo: CALLBACK }));
    const callback = unwrap(await failingService.callback({ provider: "google", code: "provider-code", state: authorized.state, redirectTo: CALLBACK }));
    const before = await disposable?.pool.query<{ count: string }>("SELECT count(*)::text AS count FROM auth.sessions");
    expect(await failingService.exchangeCode({ code: callback.code, codeVerifier: authorized.codeVerifier, redirectTo: CALLBACK })).toMatchObject({
      data: null,
      error: { code: "internal_error" },
    });
    const after = await disposable?.pool.query<{ count: string }>("SELECT count(*)::text AS count FROM auth.sessions");
    expect(after?.rows[0]?.count).toBe(before?.rows[0]?.count);

    const { sessions } = createServices();
    const healthyService = new OAuthService({
      repository: requireRepository(),
      sessions,
      providers: [deterministicProvider({ exchange: async () => profile({ subject: "rollback-subject", email: "rollback@example.com" }) })],
      tokenHashKey: TOKEN_HASH_KEY,
      encryptionKey: Uint8Array.from({ length: 32 }, (_, index) => index + 41),
      allowedRedirects: [CALLBACK],
      clock: () => now,
    });
    expect((await healthyService.exchangeCode({ code: callback.code, codeVerifier: authorized.codeVerifier, redirectTo: CALLBACK })).data).not.toBeNull();
  });
});
