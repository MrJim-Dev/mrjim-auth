import { createHash, generateKeyPairSync } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm } from "node:fs/promises";
import { spawn } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Pool } from "pg";
import type { AuthRepository, KeyProvider, OAuthStateRecord } from "../../src/shared/contracts.js";
import { AuthApiError, AuthConfigurationError } from "../../src/shared/errors.js";
import { migrate } from "../../src/postgres/migrate.js";
import { createPostgresAdapter, type PostgresAdapter } from "../../src/postgres/adapter.js";
import { roleKeySchema, sanitizeIdentityData, uuidSchema, type Identity, type User, type UUID } from "../../src/shared/types.js";
import { SessionService } from "../../src/server/sessions.js";
import { TokenService } from "../../src/server/tokens.js";
import {
  GoogleOAuthProvider,
  OAuthProviderError,
  type OAuthProvider,
  type OAuthProviderProfile,
} from "../../src/server/oauth-providers.js";
import { OAuthService, type OAuthServiceOptions } from "../../src/server/oauth.js";
import { callbackRoute, providersRoute } from "../../src/server/routes/oauth.js";

const NOW = new Date("2026-08-11T06:00:00.000Z");
const CALLBACK = "https://project.example.com/auth/callback";
const ALT_CALLBACK = "https://project.example.com/auth/alternate";
const TOKEN_HASH_KEY = Uint8Array.from({ length: 32 }, (_, index) => index + 1);
const ENCRYPTION_KEY = Uint8Array.from({ length: 32 }, (_, index) => index + 41);

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

type TestOAuthServiceOptions = {
  readonly repository?: AuthRepository;
  readonly provider?: OAuthProvider;
  readonly allowVerifiedEmailAutoLink?: boolean;
  readonly defaultRoleKeys?: readonly string[];
  readonly allowedRedirects?: readonly string[];
};

function createOAuthService(options: TestOAuthServiceOptions = {}): OAuthService {
  const currentRepository = options.repository ?? requireRepository();
  const { sessions } = createServices(currentRepository);
  return new OAuthService({
    repository: currentRepository,
    sessions,
    providers: [options.provider ?? deterministicProvider()],
    tokenHashKey: TOKEN_HASH_KEY,
    encryptionKey: ENCRYPTION_KEY,
    allowedRedirects: options.allowedRedirects ?? [CALLBACK, ALT_CALLBACK],
    allowVerifiedEmailAutoLink: options.allowVerifiedEmailAutoLink ?? false,
    defaultRoleKeys: options.defaultRoleKeys ?? [],
    clock: () => now,
  } as OAuthServiceOptions & { readonly defaultRoleKeys: readonly string[] });
}

function deferred(): { readonly promise: Promise<void>; readonly resolve: () => void } {
  let release: (() => void) | undefined;
  const promise = new Promise<void>((resolve) => { release = resolve; });
  return { promise, resolve: () => release?.() };
}

async function latestSessionId(userId: UUID): Promise<UUID> {
  const row = await disposable?.pool.query<{ id: string }>(
    "SELECT id::text FROM auth.sessions WHERE user_id = $1 ORDER BY created_at DESC, id DESC LIMIT 1",
    [userId],
  );
  return uuidSchema.parse(row?.rows[0]?.id);
}

function hostileRepository(
  base: PostgresAdapter,
  operation: "state" | "identity" | "identity_value",
): AuthRepository {
  const fail = async (): Promise<never> => {
    if (operation === "state") throw new AuthApiError("conflict", 409, "adapter-controlled OAuth error");
    throw { code: "identity_exists", message: "adapter-controlled identity error" };
  };
  const wrap = (transaction: AuthRepository): AuthRepository => ({
    ...transaction,
    oauthStates: operation === "state"
      ? { ...transaction.oauthStates, create: fail }
      : transaction.oauthStates,
    identities: operation === "identity"
      ? {
          ...transaction.identities,
          create: fail,
          createIfAvailable: fail,
        } as AuthRepository["identities"]
      : operation === "identity_value"
        ? {
            ...transaction.identities,
            createIfAvailable: async () => new AuthApiError(
              "conflict",
              409,
              "adapter-controlled identity value",
            ) as unknown as Identity,
          }
      : transaction.identities,
  });
  return {
    ...base,
    oauthStates: operation === "state" ? { ...base.oauthStates, create: fail } : base.oauthStates,
    transaction: (callback) => base.transaction((transaction) => callback(wrap(transaction))),
  };
}

function hostileTransactionValueRepository(base: PostgresAdapter): AuthRepository {
  return {
    ...base,
    transaction: async <T>(): Promise<T> => new AuthApiError(
      "conflict",
      409,
      "adapter-controlled transaction value",
    ) as unknown as T,
  };
}

function projectedIdentityRepository(
  base: PostgresAdapter,
  project: (identities: AuthRepository["identities"]) => AuthRepository["identities"],
): AuthRepository {
  const wrap = (current: AuthRepository): AuthRepository => ({
    ...current,
    identities: project(current.identities),
  });
  return {
    ...wrap(base),
    transaction: (callback) => base.transaction((transaction) => callback(wrap(transaction))),
  };
}

async function latestOAuthStateRecord(): Promise<OAuthStateRecord> {
  if (disposable === undefined) throw new Error("PostgreSQL is not initialized");
  const result = await disposable.pool.query<{
    id: string;
    state_hash: Buffer;
    provider: string;
    flow: OAuthStateRecord["flow"];
    pkce_challenge: string;
    encrypted_verifier: Buffer | null;
    redirect: string;
    linking_user_id: string | null;
    expires_at: Date;
    consumed_at: Date | null;
  }>(
    "SELECT id::text, state_hash, provider, flow, pkce_challenge, encrypted_verifier, redirect_target AS redirect, linking_user_id::text, expires_at, consumed_at FROM auth.oauth_states ORDER BY created_at DESC, ctid DESC LIMIT 1",
  );
  const row = result.rows[0];
  if (row === undefined) throw new Error("OAuth state was not persisted");
  return {
    id: uuidSchema.parse(row.id),
    state_hash: Uint8Array.from(row.state_hash),
    provider: row.provider,
    flow: row.flow,
    pkce_challenge: row.pkce_challenge,
    encrypted_verifier: row.encrypted_verifier === null ? null : Uint8Array.from(row.encrypted_verifier),
    redirect: row.redirect,
    linking_user_id: row.linking_user_id === null ? null : uuidSchema.parse(row.linking_user_id),
    expires_at: row.expires_at,
    consumed_at: row.consumed_at,
  };
}

async function databaseMutationSnapshot(): Promise<Record<string, string>> {
  if (disposable === undefined) throw new Error("PostgreSQL is not initialized");
  const result = await disposable.pool.query<Record<string, string>>(
    "SELECT (SELECT count(*)::text FROM auth.users) AS users, (SELECT count(*)::text FROM auth.identities) AS identities, (SELECT count(*)::text FROM auth.sessions) AS sessions, (SELECT count(*)::text FROM auth.one_time_tokens) AS one_time_tokens, (SELECT count(*)::text FROM auth.audit_log) AS audit_log, (SELECT count(*)::text FROM auth.oauth_states WHERE consumed_at IS NOT NULL) AS consumed_states",
  );
  const row = result.rows[0];
  if (row === undefined) throw new Error("Database snapshot failed");
  return row;
}

function identityListWithOverriddenMap(
  elements: readonly Identity[],
  mapped: readonly Identity[] = elements,
): readonly Identity[] {
  const value = [...elements];
  Object.defineProperty(value, "map", {
    configurable: true,
    value: () => mapped,
  });
  return value;
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

  it("binds the internal callback handle to a client-held PKCE verifier without leaking provider inputs", async () => {
    const clientVerifier = "a".repeat(43);
    const clientChallenge = createHash("sha256").update(clientVerifier, "utf8").digest("base64url");
    let providerInput: { readonly code: string; readonly state: string; readonly codeVerifier: string } | undefined;
    const provider = deterministicProvider({
      exchange: async (input) => {
        providerInput = input;
        return profile({ subject: "client-pkce-subject", email: "client-pkce@example.com" });
      },
    });
    const service = createOAuthService({ provider });
    const authorized = unwrap(await service.authorize({
      provider: "google",
      redirectTo: CALLBACK,
      codeChallenge: clientChallenge,
    } as any));
    const providerCode = "provider-code-wire-sentinel";
    const callback = unwrap(await service.callback({
      provider: "google",
      code: providerCode,
      state: authorized.state,
      redirectTo: CALLBACK,
    }));
    expect(JSON.stringify(callback)).not.toContain(providerCode);
    expect(JSON.stringify(callback)).not.toContain(authorized.state);
    expect(providerInput).toMatchObject({ code: providerCode, state: authorized.state });
    expect(providerInput?.codeVerifier).not.toBe(clientVerifier);
    const audit = await disposable?.pool.query<{ metadata: Record<string, unknown> }>(
      "SELECT metadata FROM auth.audit_log WHERE action = 'oauth.callback.created' ORDER BY occurred_at DESC LIMIT 1",
    );
    expect(JSON.stringify(audit?.rows)).not.toContain(providerCode);
    expect(JSON.stringify(audit?.rows)).not.toContain(authorized.state);

    const exchanged = await service.exchangeCode({
      code: callback.code,
      codeVerifier: clientVerifier,
      redirectTo: CALLBACK,
    });
    expect(exchanged.error).toBeNull();
    expect(exchanged.data?.identity.provider_subject).toBe("client-pkce-subject");
  });

  it("captures OAuth adapter and clock callbacks without invoking hostile accessors", async () => {
    const { sessions } = createServices();
    const providerAccessor = deterministicProvider() as any;
    let providerGetterCalls = 0;
    Object.defineProperty(providerAccessor, "authorizationUrl", {
      configurable: true,
      enumerable: true,
      get: () => {
        providerGetterCalls += 1;
        throw new Error("oauth-provider-getter-sentinel");
      },
    });
    expect(() => new OAuthService({
      repository: requireRepository(),
      sessions,
      providers: [providerAccessor],
      tokenHashKey: TOKEN_HASH_KEY,
      encryptionKey: ENCRYPTION_KEY,
      allowedRedirects: [CALLBACK],
    })).toThrow();
    expect(providerGetterCalls).toBe(0);

    const thenableProvider = deterministicProvider() as any;
    let providerThenCalls = 0;
    Object.defineProperty(thenableProvider.authorizationUrl, "then", {
      configurable: true,
      value: () => { providerThenCalls += 1; },
    });
    expect(() => new OAuthService({
      repository: requireRepository(),
      sessions,
      providers: [thenableProvider],
      tokenHashKey: TOKEN_HASH_KEY,
      encryptionKey: ENCRYPTION_KEY,
      allowedRedirects: [CALLBACK],
    })).toThrow(AuthConfigurationError);
    expect(providerThenCalls).toBe(0);

    const provider = deterministicProvider() as any;
    const options = {
      repository: requireRepository(),
      sessions,
      providers: [provider],
      tokenHashKey: TOKEN_HASH_KEY,
      encryptionKey: ENCRYPTION_KEY,
      allowedRedirects: [CALLBACK],
    } as any;
    let clockGetterCalls = 0;
    Object.defineProperty(options, "clock", {
      configurable: true,
      enumerable: true,
      get: () => {
        clockGetterCalls += 1;
        throw new Error("oauth-clock-getter-sentinel");
      },
    });
    expect(() => new OAuthService(options)).toThrow();
    expect(clockGetterCalls).toBe(0);

    const thenableClock = (() => now) as (() => Date) & { then?: () => void };
    let clockThenCalls = 0;
    Object.defineProperty(thenableClock, "then", {
      configurable: true,
      value: () => { clockThenCalls += 1; },
    });
    expect(() => new OAuthService({
      repository: requireRepository(),
      sessions,
      providers: [deterministicProvider()],
      tokenHashKey: TOKEN_HASH_KEY,
      encryptionKey: ENCRYPTION_KEY,
      allowedRedirects: [CALLBACK],
      clock: thenableClock,
    })).toThrow(AuthConfigurationError);
    expect(clockThenCalls).toBe(0);

    const service = createOAuthService({ provider });
    provider.authorizationUrl = () => { throw new Error("swapped-provider-callback"); };
    const authorized = await service.authorize({ provider: "google", redirectTo: CALLBACK });
    expect(authorized.error).toBeNull();

    const { sessions: mutableSessions } = createServices();
    const sessionService = new OAuthService({
      repository: requireRepository(),
      sessions: mutableSessions,
      providers: [deterministicProvider()],
      tokenHashKey: TOKEN_HASH_KEY,
      encryptionKey: ENCRYPTION_KEY,
      allowedRedirects: [CALLBACK],
    });
    mutableSessions.create = () => { throw new Error("swapped-session-callback"); };
    const signedIn = await sessionService.signInFromProfile(profile({ subject: "captured-session-subject", email: "captured-session@example.com" }));
    expect(signedIn.error).toBeNull();
  });

  it("rejects thenable OAuth session dependencies without invoking them", () => {
    const createOAuth = (candidate: SessionService) => new OAuthService({
      repository: requireRepository(),
      sessions: candidate,
      providers: [deterministicProvider()],
      tokenHashKey: TOKEN_HASH_KEY,
      encryptionKey: ENCRYPTION_KEY,
      allowedRedirects: [CALLBACK],
    });
    const cases: readonly [string, (sessions: SessionService, calls: { value: number }) => void][] = [
      ["own data", (sessions, calls) => Object.defineProperty(sessions, "then", {
        configurable: true,
        value: () => { calls.value += 1; },
      })],
      ["own accessor", (sessions, calls) => Object.defineProperty(sessions, "then", {
        configurable: true,
        get: () => { calls.value += 1; throw new Error("session-then-sentinel"); },
      })],
      ["inherited data", (sessions, calls) => {
        const prototype = Object.create(Object.getPrototypeOf(sessions));
        Object.defineProperty(prototype, "then", { configurable: true, value: () => { calls.value += 1; } });
        Object.setPrototypeOf(sessions, prototype);
      }],
      ["inherited accessor", (sessions, calls) => {
        const prototype = Object.create(Object.getPrototypeOf(sessions));
        Object.defineProperty(prototype, "then", {
          configurable: true,
          get: () => { calls.value += 1; throw new Error("inherited-session-then-sentinel"); },
        });
        Object.setPrototypeOf(sessions, prototype);
      }],
      ["poisoned prototype", (sessions, calls) => {
        const prototype = Object.create(Object.getPrototypeOf(sessions), {
          then: {
            configurable: true,
            get: () => { calls.value += 1; throw new Error("poisoned-session-then-sentinel"); },
          },
        });
        Object.setPrototypeOf(sessions, prototype);
      }],
    ];

    for (const [label, install] of cases) {
      const sessions = createServices().sessions;
      const calls = { value: 0 };
      install(sessions, calls);
      let thrown: unknown;
      try {
        createOAuth(sessions);
      } catch (error) {
        thrown = error;
      }
      expect(thrown, label).toBeInstanceOf(AuthConfigurationError);
      expect(String(thrown), label).not.toContain("sentinel");
      expect(calls.value, label).toBe(0);
    }

    const callable = Object.assign(() => undefined, {
      create: () => undefined,
      authorizeSession: () => undefined,
    }) as unknown as SessionService;
    Object.setPrototypeOf(callable, SessionService.prototype);
    let callableThenCalls = 0;
    Object.defineProperty(callable, "then", {
      configurable: true,
      value: () => { callableThenCalls += 1; },
    });
    expect(() => createOAuth(callable)).toThrow(AuthConfigurationError);
    expect(callableThenCalls).toBe(0);
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

  it("resolves default and alternate persisted redirects from state without callback redirect_to", async () => {
    const service = createOAuthService();
    const defaultFlow = unwrap(await service.authorize({ provider: "google", redirectTo: CALLBACK }));
    const defaultCallback = unwrap(await service.callback({
      provider: "google",
      code: "default-provider-code",
      state: defaultFlow.state,
    }));
    expect(defaultCallback.redirect).toBe(CALLBACK);

    const alternateFlow = unwrap(await service.authorize({ provider: "google", redirectTo: ALT_CALLBACK }));
    expect(await service.callback({
      provider: "google",
      code: "alternate-provider-code",
      state: alternateFlow.state,
      redirectTo: CALLBACK,
    })).toMatchObject({ data: null, error: { code: "oauth_state_invalid" } });

    const response = await callbackRoute(
      service,
      "google",
      new Request(`https://project.example.com/callback?code=alternate-provider-code&state=${encodeURIComponent(alternateFlow.state)}`),
    );
    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toMatch(/^https:\/\/project\.example\.com\/auth\/alternate\?code=/);
  });

  it("makes fresh-session validation and linking-state creation atomic against revocation", async () => {
    const entered = deferred();
    const release = deferred();
    const racingProvider = deterministicProvider({
      authorizationUrl: async (input) => {
        entered.resolve();
        await release.promise;
        return `https://provider.example/authorize?state=${input.state}&code_challenge=${input.codeChallenge}&code_challenge_method=S256`;
      },
    });
    const service = createOAuthService({ provider: racingProvider });
    const signedIn = unwrap(await service.signInFromProfile(profile({
      subject: "state-race-owner",
      email: "state-race-owner@example.com",
    })));
    const before = await disposable?.pool.query<{ count: string }>(
      "SELECT count(*)::text AS count FROM auth.oauth_states WHERE linking_user_id = $1 AND consumed_at IS NULL",
      [signedIn.user.id],
    );
    const attempt = service.authorize({
      provider: "google",
      redirectTo: CALLBACK,
      flow: "link_identity",
      subject: { session: signedIn.session },
    });
    await entered.promise;
    await requireRepository().sessions.revokeSession(await latestSessionId(signedIn.user.id), { now });
    release.resolve();
    expect(await attempt).toMatchObject({ data: null, error: { code: "unauthorized" } });
    const after = await disposable?.pool.query<{ count: string }>(
      "SELECT count(*)::text AS count FROM auth.oauth_states WHERE linking_user_id = $1 AND consumed_at IS NULL",
      [signedIn.user.id],
    );
    expect(after?.rows[0]?.count).toBe(before?.rows[0]?.count);
  });

  it("revalidates the persisted originating session during a revocation callback race", async () => {
    const entered = deferred();
    const release = deferred();
    const linkedSubject = "callback-race-linked-subject";
    const service = createOAuthService({
      provider: deterministicProvider({
        exchange: async () => {
          entered.resolve();
          await release.promise;
          return profile({ subject: linkedSubject, email: "callback-race-linked@example.com" });
        },
      }),
    });
    const signedIn = unwrap(await service.signInFromProfile(profile({
      subject: "callback-race-owner",
      email: "callback-race-owner@example.com",
    })));
    const authorization = unwrap(await service.authorize({
      provider: "google",
      redirectTo: CALLBACK,
      flow: "link_identity",
      subject: { session: signedIn.session },
    }));
    const attempt = service.callback({ provider: "google", code: "provider-code", state: authorization.state });
    await entered.promise;
    await requireRepository().sessions.revokeSession(await latestSessionId(signedIn.user.id), { now });
    release.resolve();
    expect(await attempt).toMatchObject({ data: null, error: { code: "unauthorized" } });
    const state = await disposable?.pool.query<{ consumed_at: Date | null }>(
      "SELECT consumed_at FROM auth.oauth_states WHERE linking_user_id = $1 ORDER BY created_at DESC LIMIT 1",
      [signedIn.user.id],
    );
    expect(state?.rows[0]?.consumed_at).not.toBeNull();
    expect((await disposable?.pool.query(
      "SELECT id FROM auth.identities WHERE provider = 'google' AND provider_subject = $1",
      [linkedSubject],
    ))?.rows).toHaveLength(0);
    expect((await disposable?.pool.query(
      "SELECT id FROM auth.one_time_tokens WHERE user_id = $1 AND purpose = 'oauth_callback' AND consumed_at IS NULL",
      [signedIn.user.id],
    ))?.rows).toHaveLength(0);
  });

  it("rejects an expired originating session before callback identity or code writes", async () => {
    const linkedSubject = "expired-link-subject";
    const service = createOAuthService({
      provider: deterministicProvider({
        exchange: async () => profile({ subject: linkedSubject, email: "expired-link@example.com" }),
      }),
    });
    const signedIn = unwrap(await service.signInFromProfile(profile({
      subject: "expired-link-owner",
      email: "expired-link-owner@example.com",
    })));
    const authorization = unwrap(await service.authorize({
      provider: "google",
      redirectTo: CALLBACK,
      flow: "link_identity",
      subject: { session: signedIn.session },
    }));
    await disposable?.pool.query(
      "UPDATE auth.sessions SET expires_at = $2 WHERE id = $1",
      [await latestSessionId(signedIn.user.id), new Date(NOW.getTime() + 1_000)],
    );
    now = new Date(NOW.getTime() + 2_000);
    try {
      expect(await service.callback({ provider: "google", code: "provider-code", state: authorization.state }))
        .toMatchObject({ data: null, error: { code: "unauthorized" } });
    } finally {
      now = NOW;
    }
    expect((await disposable?.pool.query(
      "SELECT id FROM auth.identities WHERE provider = 'google' AND provider_subject = $1",
      [linkedSubject],
    ))?.rows).toHaveLength(0);
    expect((await disposable?.pool.query(
      "SELECT id FROM auth.one_time_tokens WHERE user_id = $1 AND purpose = 'oauth_callback'",
      [signedIn.user.id],
    ))?.rows).toHaveLength(0);
  });

  it.each(["banned", "deleted"] as const)(
    "rejects a committed %s verified-email account before callback mutation",
    async (accountState) => {
      const email = `${accountState}-callback-account@example.com`;
      const user = await requireRepository().users.create({ email });
      const service = createOAuthService({
        allowVerifiedEmailAutoLink: true,
        provider: deterministicProvider({
          exchange: async () => profile({
            subject: `${accountState}-callback-subject`,
            email,
            emailVerified: true,
          }),
        }),
      });
      const authorization = unwrap(await service.authorize({ provider: "google", redirectTo: CALLBACK }));
      if (accountState === "banned") {
        await requireRepository().users.update(user.id, { banned_until: new Date(NOW.getTime() + 60 * 60 * 1000) });
      } else {
        await requireRepository().users.softDelete(user.id, NOW);
      }
      expect(await service.callback({ provider: "google", code: "provider-code", state: authorization.state }))
        .toMatchObject({ data: null, error: { code: "unauthorized" } });
      expect((await disposable?.pool.query(
        "SELECT id FROM auth.identities WHERE provider = 'google' AND provider_subject = $1",
        [`${accountState}-callback-subject`],
      ))?.rows).toHaveLength(0);
      expect((await disposable?.pool.query(
        "SELECT id FROM auth.one_time_tokens WHERE user_id = $1 AND purpose = 'oauth_callback'",
        [user.id],
      ))?.rows).toHaveLength(0);
    },
  );

  it("fails closed when a ban commits while a verified-email provider exchange is in flight", async () => {
    const email = "ban-callback-race@example.com";
    const user = await requireRepository().users.create({ email });
    const entered = deferred();
    const release = deferred();
    const providerSubject = "ban-callback-race-subject";
    const service = createOAuthService({
      allowVerifiedEmailAutoLink: true,
      provider: deterministicProvider({
        exchange: async () => {
          entered.resolve();
          await release.promise;
          return profile({ subject: providerSubject, email, emailVerified: true });
        },
      }),
    });
    const authorization = unwrap(await service.authorize({ provider: "google", redirectTo: CALLBACK }));
    const attempt = service.callback({ provider: "google", code: "provider-code", state: authorization.state });
    await entered.promise;
    await requireRepository().users.update(user.id, { banned_until: new Date(NOW.getTime() + 60 * 60 * 1000) });
    release.resolve();
    expect(await attempt).toMatchObject({ data: null, error: { code: "unauthorized" } });
    expect((await disposable?.pool.query(
      "SELECT id FROM auth.identities WHERE provider = 'google' AND provider_subject = $1",
      [providerSubject],
    ))?.rows).toHaveLength(0);
  });

  it("sanitizes hostile provider and repository errors and returned adapter values", async () => {
    const throwingProvider = deterministicProvider({
      authorizationUrl: async () => { throw new AuthApiError("conflict", 409, "provider-controlled error"); },
    });
    expect(await createOAuthService({ provider: throwingProvider }).authorize({ provider: "google", redirectTo: CALLBACK }))
      .toMatchObject({ data: null, error: { code: "oauth_provider_error", status: 502 } });

    const returnedErrorProvider = deterministicProvider({
      authorizationUrl: async () => new AuthApiError("conflict", 409, "provider-controlled value") as unknown as string,
    });
    expect(await createOAuthService({ provider: returnedErrorProvider }).authorize({ provider: "google", redirectTo: CALLBACK }))
      .toMatchObject({ data: null, error: { code: "oauth_provider_error", status: 502 } });

    expect(await createOAuthService({
      repository: hostileRepository(requireRepository(), "state"),
    }).authorize({ provider: "google", redirectTo: CALLBACK })).toMatchObject({
      data: null,
      error: { code: "internal_error", status: 500 },
    });

    expect(await createOAuthService({
      repository: hostileRepository(requireRepository(), "identity"),
    }).signInFromProfile(profile({ subject: "hostile-identity-subject", email: null }))).toMatchObject({
      data: null,
      error: { code: "internal_error", status: 500 },
    });

    expect(await createOAuthService({
      repository: hostileRepository(requireRepository(), "identity_value"),
    }).signInFromProfile(profile({ subject: "hostile-identity-value", email: null }))).toMatchObject({
      data: null,
      error: { code: "internal_error", status: 500 },
    });

    expect(await createOAuthService({
      repository: hostileTransactionValueRepository(requireRepository()),
    }).authorize({ provider: "google", redirectTo: CALLBACK })).toMatchObject({
      data: null,
      error: { code: "internal_error", status: 500 },
    });

    const hostileProfile = { ...profile({ subject: "hostile-returned-profile", email: null }) };
    Object.defineProperty(hostileProfile, "subject", {
      enumerable: true,
      get: () => { throw new AuthApiError("conflict", 409, "provider-controlled profile getter"); },
    });
    expect(await createOAuthService().signInFromProfile(hostileProfile)).toMatchObject({
      data: null,
      error: { code: "oauth_provider_error", status: 502 },
    });
  });

  it("rejects an OAuth-state projection bound to a different digest before provider or database work", async () => {
    let projectedState: OAuthStateRecord | null = null;
    let providerCalls = 0;
    const base = requireRepository();
    const projectedRepository: AuthRepository = {
      ...base,
      oauthStates: {
        ...base.oauthStates,
        consume: async () => projectedState,
      },
    };
    const service = createOAuthService({
      repository: projectedRepository,
      provider: deterministicProvider({
        exchange: async () => {
          providerCalls += 1;
          return profile({ subject: "wrong-state-digest-subject", email: null });
        },
      }),
    });
    const authorized = unwrap(await service.authorize({ provider: "google", redirectTo: CALLBACK }));
    const stored = await latestOAuthStateRecord();
    const wrongDigest = Uint8Array.from(stored.state_hash);
    wrongDigest[0] = (wrongDigest[0] ?? 0) ^ 0xff;
    projectedState = { ...stored, state_hash: wrongDigest };
    const before = await databaseMutationSnapshot();

    expect(await service.callback({
      provider: "google",
      code: "provider-code",
      state: authorized.state,
      redirectTo: CALLBACK,
    })).toMatchObject({ data: null, error: { code: "internal_error", status: 500 } });
    expect(providerCalls).toBe(0);
    expect(await databaseMutationSnapshot()).toEqual(before);
  });

  it("uses one OAuth-state snapshot when a getter changes after validation", async () => {
    let projectedState: OAuthStateRecord | null = null;
    let providerCalls = 0;
    let encryptedVerifierReads = 0;
    const base = requireRepository();
    const projectedRepository: AuthRepository = {
      ...base,
      oauthStates: {
        ...base.oauthStates,
        consume: async () => projectedState,
      },
    };
    const service = createOAuthService({
      repository: projectedRepository,
      provider: deterministicProvider({
        exchange: async () => {
          providerCalls += 1;
          return profile({ subject: "changing-state-getter-subject", email: null });
        },
      }),
    });
    const authorized = unwrap(await service.authorize({ provider: "google", redirectTo: CALLBACK }));
    const stored = await latestOAuthStateRecord();
    const changing = { ...stored, pkce_challenge: "A".repeat(43) };
    Object.defineProperty(changing, "encrypted_verifier", {
      enumerable: true,
      get: () => {
        encryptedVerifierReads += 1;
        if (encryptedVerifierReads === 1) return stored.encrypted_verifier;
        throw new AuthApiError("conflict", 409, "adapter-controlled state getter");
      },
    });
    projectedState = changing;
    const before = await databaseMutationSnapshot();

    expect(await service.callback({
      provider: "google",
      code: "provider-code",
      state: authorized.state,
      redirectTo: CALLBACK,
    })).toMatchObject({ data: null, error: { code: "oauth_state_invalid", status: 400 } });
    expect(encryptedVerifierReads).toBe(1);
    expect(providerCalls).toBe(0);
    expect(await databaseMutationSnapshot()).toEqual(before);
  });

  it("rejects a wrong state digest when projection accessors mutate realm intrinsics", async () => {
    let projectedState: OAuthStateRecord | null = null;
    let requestedDigest: Uint8Array | null = null;
    let providerCalls = 0;
    const base = requireRepository();
    const projectedRepository: AuthRepository = {
      ...base,
      oauthStates: {
        ...base.oauthStates,
        consume: async (stateHash) => {
          requestedDigest = Uint8Array.from(stateHash);
          return projectedState;
        },
      },
    };
    const service = createOAuthService({
      repository: projectedRepository,
      provider: deterministicProvider({
        exchange: async () => {
          providerCalls += 1;
          return profile({ subject: "realm-mutated-state-subject", email: null });
        },
      }),
    });
    const authorized = unwrap(await service.authorize({ provider: "google", redirectTo: CALLBACK }));
    const stored = await latestOAuthStateRecord();
    const wrongDigest = Uint8Array.from(stored.state_hash);
    wrongDigest[0] = (wrongDigest[0] ?? 0) ^ 0xff;
    const projection = { ...stored, state_hash: wrongDigest };
    const originalBufferFrom = Buffer.from;
    const originalTypedArrayFrom = Uint8Array.from;
    const originalDateGetTime = Date.prototype.getTime;
    const originalFreeze = Object.freeze;
    let digestCopies = 0;
    Object.defineProperty(projection, "id", {
      enumerable: true,
      get: () => {
        Buffer.from = ((...args: unknown[]) => {
          const source = args[0];
          if (source instanceof Uint8Array && source.byteLength === 32 && digestCopies < 2) {
            digestCopies += 1;
            if (requestedDigest === null) throw new Error("requested state digest was not captured");
            return originalBufferFrom(requestedDigest);
          }
          return Reflect.apply(originalBufferFrom, Buffer, args) as Buffer;
        }) as typeof Buffer.from;
        Uint8Array.from = ((source: ArrayLike<number>) =>
          source instanceof Uint8Array ? source : originalTypedArrayFrom(source)) as typeof Uint8Array.from;
        Date.prototype.getTime = function getTime() {
          return Reflect.apply(originalDateGetTime, this, []) as number;
        };
        Object.freeze = ((value: unknown) => value) as typeof Object.freeze;
        return stored.id;
      },
    });
    projectedState = projection;
    const before = await databaseMutationSnapshot();

    const result = await service.callback({
      provider: "google",
      code: "provider-code",
      state: authorized.state,
      redirectTo: CALLBACK,
    }).finally(() => {
      Buffer.from = originalBufferFrom;
      Uint8Array.from = originalTypedArrayFrom;
      Date.prototype.getTime = originalDateGetTime;
      Object.freeze = originalFreeze;
    });
    expect(result).toMatchObject({ data: null, error: { code: "internal_error", status: 500 } });
    expect(providerCalls).toBe(0);
    expect(await databaseMutationSnapshot()).toEqual(before);
  });

  it("rejects a found identity when mutable freeze substitutes another owner", async () => {
    let projectedIdentity: Identity | null = null;
    const base = requireRepository();
    const projectedRepository = projectedIdentityRepository(base, (identities) => ({
      ...identities,
      findByProviderSubject: async (providerName, providerSubject, options) =>
        projectedIdentity ?? identities.findByProviderSubject(providerName, providerSubject, options),
    }));
    const service = createOAuthService({ repository: projectedRepository });
    const owner = unwrap(await service.signInFromProfile(profile({
      subject: "projected-find-owner",
      email: "projected-find-owner@example.com",
    })));
    const ownerIdentity = (await base.identities.listByUserId(owner.user.id))[0];
    if (ownerIdentity === undefined) throw new Error("found identity was not persisted");
    const requestedSubject = "projected-find-requested";
    const originalFreeze = Object.freeze;
    const projection = {
      ...ownerIdentity,
      user_id: "00000000-0000-4000-8000-000000000001" as UUID,
      provider_subject: requestedSubject,
      identity_data: sanitizeIdentityData({ ...ownerIdentity.identity_data, sub: requestedSubject }),
    };
    Object.defineProperty(projection, "id", {
      enumerable: true,
      get: () => {
        Object.freeze = ((value: unknown) => {
          if (typeof value === "object" && value !== null && "provider_subject" in value) return ownerIdentity;
          return originalFreeze(value);
        }) as typeof Object.freeze;
        return ownerIdentity.id;
      },
    });
    projectedIdentity = projection;
    const beforeSessions = await disposable?.pool.query<{ count: string }>("SELECT count(*)::text AS count FROM auth.sessions");

    const result = await service.signInFromProfile(profile({
      subject: requestedSubject,
      email: null,
    })).finally(() => { Object.freeze = originalFreeze; });
    expect(result).toMatchObject({ data: null, error: { code: "unauthorized", status: 401 } });
    const afterSessions = await disposable?.pool.query<{ count: string }>("SELECT count(*)::text AS count FROM auth.sessions");
    expect(afterSessions?.rows[0]?.count).toBe(beforeSessions?.rows[0]?.count);
  });

  it("does not disclose a substituted identity owner when mutable freeze runs during create", async () => {
    const base = requireRepository();
    const otherUser = await base.users.create({ email: "projected-create-other@example.com" });
    const originalFreeze = Object.freeze;
    const projectedRepository = projectedIdentityRepository(base, (identities) => ({
      ...identities,
      createIfAvailable: async (input, options) => {
        const created = await identities.createIfAvailable(input, options);
        if (created === null) return null;
        const projection = { ...created };
        Object.defineProperty(projection, "id", {
          enumerable: true,
          get: () => {
            Object.freeze = ((value: unknown) => {
              if (typeof value === "object" && value !== null && "provider_subject" in value) {
                return { ...created, user_id: otherUser.id };
              }
              return originalFreeze(value);
            }) as typeof Object.freeze;
            return created.id;
          },
        });
        return projection;
      },
    }));
    const service = createOAuthService({ repository: projectedRepository });
    const email = "projected-create-owner@example.com";
    const subject = "projected-create-subject";

    const result = await service.signInFromProfile(profile({ subject, email }))
      .finally(() => { Object.freeze = originalFreeze; });
    const created = unwrap(result);
    expect(created.identity.user_id).toBe(created.user.id);
    expect(created.identity.user_id).not.toBe(otherUser.id);
  });

  it("rolls back callback exchange when the identity list projects another owner", async () => {
    let projectedList: readonly Identity[] | null = null;
    const base = requireRepository();
    const projectedRepository = projectedIdentityRepository(base, (identities) => ({
      ...identities,
      listByUserId: async (userId, options) => projectedList ?? identities.listByUserId(userId, options),
    }));
    const service = createOAuthService({
      repository: projectedRepository,
      provider: deterministicProvider({
        exchange: async () => profile({ subject: "projected-exchange-subject", email: null }),
      }),
    });
    const authorized = unwrap(await service.authorize({ provider: "google", redirectTo: CALLBACK }));
    const callback = unwrap(await service.callback({ provider: "google", code: "provider-code", state: authorized.state }));
    const identity = await base.identities.findByProviderSubject("google", "projected-exchange-subject");
    if (identity === null) throw new Error("callback identity was not persisted");
    const otherUser = await base.users.create({ email: "projected-exchange-other@example.com" });
    const foreignProjection = { ...identity, user_id: otherUser.id };
    projectedList = identityListWithOverriddenMap([foreignProjection]);
    const beforeSessions = await disposable?.pool.query<{ count: string }>("SELECT count(*)::text AS count FROM auth.sessions");

    expect(await service.exchangeCode({
      code: callback.code,
      codeVerifier: authorized.codeVerifier,
      redirectTo: CALLBACK,
    })).toMatchObject({ data: null, error: { code: "internal_error", status: 500 } });
    const afterSessions = await disposable?.pool.query<{ count: string }>("SELECT count(*)::text AS count FROM auth.sessions");
    expect(afterSessions?.rows[0]?.count).toBe(beforeSessions?.rows[0]?.count);
    projectedList = null;
    expect((await service.exchangeCode({
      code: callback.code,
      codeVerifier: authorized.codeVerifier,
      redirectTo: CALLBACK,
    })).data).not.toBeNull();
  });

  it("fails closed when a listed identity claim subject differs from its provider subject", async () => {
    let projectedList: readonly Identity[] | null = null;
    const base = requireRepository();
    const projectedRepository = projectedIdentityRepository(base, (identities) => ({
      ...identities,
      listByUserId: async (userId, options) => projectedList ?? identities.listByUserId(userId, options),
    }));
    const service = createOAuthService({ repository: projectedRepository });
    const signedIn = unwrap(await service.signInFromProfile(profile({
      subject: "projected-list-subject",
      email: "projected-list@example.com",
    })));
    const identity = (await base.identities.listByUserId(signedIn.user.id))[0];
    if (identity === undefined) throw new Error("listed identity was not persisted");
    const mismatchedProjection = {
      ...identity,
      identity_data: sanitizeIdentityData({ ...identity.identity_data, sub: "different-list-subject" }),
    };
    projectedList = identityListWithOverriddenMap([mismatchedProjection]);

    expect(await service.listIdentities({ session: signedIn.session })).toMatchObject({
      data: null,
      error: { code: "internal_error", status: 500 },
    });
  });

  it("refuses unlink when the identity list projects an identity owned by another user", async () => {
    let projectedList: readonly Identity[] | null = null;
    const base = requireRepository();
    const projectedRepository = projectedIdentityRepository(base, (identities) => ({
      ...identities,
      listByUserId: async (userId, options) => projectedList ?? identities.listByUserId(userId, options),
    }));
    const service = createOAuthService({ repository: projectedRepository });
    const owner = unwrap(await service.signInFromProfile(profile({
      subject: "projected-unlink-owner",
      email: "projected-unlink-owner@example.com",
    })));
    const other = unwrap(await service.signInFromProfile(profile({
      subject: "projected-unlink-other",
      email: "projected-unlink-other@example.com",
    })));
    const ownerIdentity = (await base.identities.listByUserId(owner.user.id))[0];
    const otherIdentity = (await base.identities.listByUserId(other.user.id))[0];
    if (ownerIdentity === undefined || otherIdentity === undefined) throw new Error("unlink identities were not persisted");
    projectedList = identityListWithOverriddenMap([otherIdentity, ownerIdentity]);

    expect(await service.unlinkIdentity({ session: owner.session }, otherIdentity.id)).toMatchObject({
      data: null,
      error: { code: "internal_error", status: 500 },
    });
    expect(await base.identities.findByProviderSubject(otherIdentity.provider, otherIdentity.provider_subject)).not.toBeNull();
  });

  it.each(["exchange", "unlink"] as const)(
    "selects the %s identity only from the validated immutable snapshot",
    async (operation) => {
      const base = requireRepository();
      const originalFind = Array.prototype.find;
      let projectedList: readonly Identity[] | null = null;
      let injectedIdentity: Identity | null = null;
      let sessionCreateCalls = 0;
      let deleteByIdCalls = 0;
      const wrap = (current: AuthRepository): AuthRepository => ({
        ...current,
        identities: {
          ...current.identities,
          listByUserId: async (userId, options) =>
            projectedList ?? current.identities.listByUserId(userId, options),
          deleteById: async (identityId, options) => {
            deleteByIdCalls += 1;
            await current.identities.deleteById(identityId, options);
          },
        },
        sessions: {
          ...current.sessions,
          create: async (input, options) => {
            sessionCreateCalls += 1;
            return current.sessions.create(input, options);
          },
        },
      });
      const attackedRepository: AuthRepository = {
        ...wrap(base),
        transaction: (callback) => base.transaction((transaction) => callback(wrap(transaction))),
      };
      const installInheritedFind = (source: Identity, projectedId: UUID): Identity => {
        const projection = { ...source };
        Object.defineProperty(projection, "id", {
          enumerable: true,
          get: () => {
            Array.prototype.find = (() => injectedIdentity) as unknown as typeof Array.prototype.find;
            return projectedId;
          },
        });
        return projection;
      };

      try {
        if (operation === "exchange") {
          const subject = "inherited-find-exchange-subject";
          const service = createOAuthService({
            repository: attackedRepository,
            provider: deterministicProvider({
              exchange: async () => profile({ subject, email: null }),
            }),
          });
          const authorized = unwrap(await service.authorize({ provider: "google", redirectTo: CALLBACK }));
          const callback = unwrap(await service.callback({
            provider: "google",
            code: "provider-code",
            state: authorized.state,
          }));
          const persistedIdentity = await base.identities.findByProviderSubject("google", subject);
          if (persistedIdentity === null) throw new Error("callback identity was not persisted");
          injectedIdentity = persistedIdentity;
          projectedList = [installInheritedFind(
            persistedIdentity,
            uuidSchema.parse("00000000-0000-4000-8000-000000000101"),
          )];
          sessionCreateCalls = 0;
          deleteByIdCalls = 0;
          const before = await databaseMutationSnapshot();
          const callbackToken = await disposable?.pool.query<{ id: string; consumed_at: Date | null }>(
            "SELECT id::text, consumed_at FROM auth.one_time_tokens WHERE purpose = 'oauth_callback' AND metadata->>'target_id' = $1",
            [persistedIdentity.id],
          );
          const callbackTokenId = uuidSchema.parse(callbackToken?.rows[0]?.id);
          expect(callbackToken?.rows[0]?.consumed_at).toBeNull();

          const result = await service.exchangeCode({
            code: callback.code,
            codeVerifier: authorized.codeVerifier,
            redirectTo: CALLBACK,
          });

          expect(result).toMatchObject({
            data: null,
            error: {
              name: "AuthError",
              code: "invalid_request",
              status: 400,
              message: "OAuth identity is unavailable",
            },
          });
          expect(sessionCreateCalls).toBe(0);
          expect(deleteByIdCalls).toBe(0);
          expect(await databaseMutationSnapshot()).toEqual(before);
          expect(await disposable?.pool.query<{ consumed_at: Date | null }>(
            "SELECT consumed_at FROM auth.one_time_tokens WHERE id = $1",
            [callbackTokenId],
          )).toMatchObject({ rows: [{ consumed_at: null }] });
          return;
        }

        const service = createOAuthService({ repository: attackedRepository });
        const owner = unwrap(await service.signInFromProfile(profile({
          subject: "inherited-find-unlink-owner",
          email: "inherited-find-unlink-owner@example.com",
        })));
        const other = unwrap(await service.signInFromProfile(profile({
          subject: "inherited-find-unlink-other",
          email: "inherited-find-unlink-other@example.com",
        })));
        const ownerIdentity = (await base.identities.listByUserId(owner.user.id))[0];
        const otherIdentity = (await base.identities.listByUserId(other.user.id))[0];
        if (ownerIdentity === undefined || otherIdentity === undefined) throw new Error("unlink identities were not persisted");
        injectedIdentity = otherIdentity;
        projectedList = [
          installInheritedFind(ownerIdentity, uuidSchema.parse("00000000-0000-4000-8000-000000000102")),
          { ...ownerIdentity, id: uuidSchema.parse("00000000-0000-4000-8000-000000000103") },
        ];
        sessionCreateCalls = 0;
        deleteByIdCalls = 0;
        const before = await databaseMutationSnapshot();

        const result = await service.unlinkIdentity({ session: owner.session }, otherIdentity.id);

        expect(result).toMatchObject({
          data: null,
          error: {
            name: "AuthError",
            code: "not_found",
            status: 404,
            message: "Identity not found",
          },
        });
        expect(sessionCreateCalls).toBe(0);
        expect(deleteByIdCalls).toBe(0);
        expect(await databaseMutationSnapshot()).toEqual(before);
        expect(await base.identities.findByProviderSubject(
          otherIdentity.provider,
          otherIdentity.provider_subject,
        )).not.toBeNull();
      } finally {
        Array.prototype.find = originalFind;
      }
    },
  );

  it("assigns configured default roles to OAuth-created users and rolls back missing-role creation", async () => {
    const role = await requireRepository().roles.create({
      key: roleKeySchema.parse("oauth_member"),
      name: "OAuth Member",
      rank: 2,
    });
    const service = createOAuthService({ defaultRoleKeys: [role.key] });
    const created = unwrap(await service.signInFromProfile(profile({
      subject: "oauth-default-role-subject",
      email: "oauth-default-role@example.com",
    })));
    const assignments = await disposable?.pool.query<{ role_id: string }>(
      "SELECT role_id::text FROM auth.user_roles WHERE user_id = $1",
      [created.user.id],
    );
    expect(assignments?.rows).toEqual([{ role_id: role.id }]);

    const missingEmail = "oauth-missing-role@example.com";
    const missingSubject = "oauth-missing-role-subject";
    const missingRoleService = createOAuthService({ defaultRoleKeys: ["missing_oauth_role"] });
    await expect(missingRoleService.signInFromProfile(profile({
      subject: missingSubject,
      email: missingEmail,
    }))).rejects.toBeInstanceOf(AuthConfigurationError);
    expect((await disposable?.pool.query(
      "SELECT id FROM auth.users WHERE email_normalized = $1",
      [missingEmail],
    ))?.rows).toHaveLength(0);
    expect((await disposable?.pool.query(
      "SELECT id FROM auth.identities WHERE provider_subject = $1",
      [missingSubject],
    ))?.rows).toHaveLength(0);
  });

  it("requires at least 32 decoded bytes for OAuth HMAC and encryption keys", () => {
    const { sessions } = createServices();
    const base = {
      repository: requireRepository(),
      sessions,
      providers: [deterministicProvider()],
      allowedRedirects: [CALLBACK],
      clock: () => now,
    } as const;
    for (const [label, key] of [
      ["one byte", Uint8Array.of(1)],
      ["31 bytes", new Uint8Array(31)],
      ["one decoded byte", "YQ"],
      ["whitespace", "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8 "],
      ["noncanonical trailing bits", "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh9"],
    ] as const) {
      expect(() => new OAuthService({ ...base, tokenHashKey: key, encryptionKey: ENCRYPTION_KEY }), label).toThrow(AuthConfigurationError);
      expect(() => new OAuthService({ ...base, tokenHashKey: TOKEN_HASH_KEY, encryptionKey: key }), label).toThrow(AuthConfigurationError);
    }
    expect(() => new OAuthService({
      ...base,
      tokenHashKey: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
      encryptionKey: "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8",
    })).not.toThrow();
  });
});
