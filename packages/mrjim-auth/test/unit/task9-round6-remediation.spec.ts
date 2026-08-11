import { createHmac, generateKeyPairSync } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import type { AuthRepository, KeyProvider, Mailer } from "../../src/shared/contracts.js";
import { AuthApiError, AuthConfigurationError } from "../../src/shared/errors.js";
import { authFailure, authSuccess } from "../../src/shared/result.js";
import { sanitizeIdentityData, sanitizeRedactedMetadata, uuidSchema } from "../../src/shared/types.js";
import { createAuthServer } from "../../src/server/create-auth-server.js";
import { EmailService } from "../../src/server/email.js";
import { importEs256Key } from "../../src/server/jwks.js";
import { OAuthService } from "../../src/server/oauth.js";
import { OidcOAuthProvider, OAuthProviderError, type OAuthProvider } from "../../src/server/oauth-providers.js";
import { OneTimeTokenService } from "../../src/server/one-time-tokens.js";
import { PasswordService } from "../../src/server/passwords.js";
import { SessionService } from "../../src/server/sessions.js";
import { TokenService } from "../../src/server/tokens.js";
import { UserService } from "../../src/server/users.js";
import { authorizeRoute, callbackRoute, exchangeRoute, providersRoute } from "../../src/server/routes/oauth.js";
import { permissionsRoute } from "../../src/server/routes/permissions.js";

const NOW = new Date("2026-08-11T05:00:00.000Z");
const CALLBACK = "https://project.example.com/auth/callback";
const TOKEN_HASH_KEY = Uint8Array.from({ length: 32 }, (_, index) => index + 1);
const ENCRYPTION_KEY = Uint8Array.from({ length: 32 }, (_, index) => index + 41);
const USER_ID = uuidSchema.parse("00000000-0000-4000-8000-000000000901");

const noop = async (..._args: unknown[]): Promise<undefined> => undefined;

function repositoryFixture(overrides: Record<string, unknown> = {}): AuthRepository {
  const repository = {
    transaction: async (callback: (value: AuthRepository) => unknown) => callback(repository as unknown as AuthRepository),
    users: {
      findById: noop, findByIdForUpdate: noop, findByNormalizedEmail: noop,
      findByNormalizedEmailForUpdate: noop, create: noop, createIfAvailable: noop,
      update: noop, softDelete: noop,
    },
    identities: {
      findByProviderSubject: noop, listByUserId: noop, create: noop,
      createIfAvailable: noop, deleteById: noop,
    },
    passwordCredentials: { findByUserId: noop, upsert: noop, deleteByUserId: noop },
    sessions: {
      create: noop, findByIdForUpdate: noop, findRefreshForUpdate: noop,
      rotate: noop, revokeSession: noop, revokeFamily: noop, revokeUserSessions: noop,
    },
    oneTimeTokens: { issue: noop, consume: noop, consumeBound: noop, recordFailure: noop },
    oauthStates: { create: noop, consume: noop },
    authorization: {
      effectivePermissions: noop, assignRole: noop, unassignRole: noop,
      setRolePermissions: noop, setRoleInheritance: noop,
    },
    roles: { list: noop, findById: noop, create: noop, update: noop, delete: noop },
    permissions: { list: noop, findById: noop, create: noop, update: noop, delete: noop },
    operations: { appendAudit: noop, findApiKeyByHash: noop },
    ...overrides,
  } as unknown as AuthRepository;
  return repository;
}

function keyProvider(): KeyProvider {
  const pair = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return {
    getActiveKeyId: () => "active",
    getSigningKey: () => pair.privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    getVerificationKeys: () => new Map([
      ["active", pair.publicKey.export({ type: "spki", format: "pem" }).toString()],
    ]),
  };
}

function tokenService(provider: KeyProvider = keyProvider()): TokenService {
  return new TokenService({
    issuer: "https://project.example.com/auth/v1",
    audience: "project",
    keyProvider: provider,
    tokenHashKey: TOKEN_HASH_KEY,
    clock: () => NOW,
  });
}

function emailService(): EmailService {
  return new EmailService({ allowedRedirects: [CALLBACK], defaultRedirect: CALLBACK });
}

function oneTimeTokenService(
  repository: AuthRepository = repositoryFixture(),
  mailer: Mailer = { send: async () => undefined },
): OneTimeTokenService {
  return new OneTimeTokenService({
    repository,
    mailer,
    email: emailService(),
    tokenHashKey: TOKEN_HASH_KEY,
    clock: () => NOW,
  });
}

function oauthProvider(overrides: Partial<OAuthProvider> = {}): OAuthProvider {
  return {
    name: "google",
    clientId: "google-client",
    scopes: ["openid", "email", "profile"],
    capabilities: { authorization_code: true, pkce: true, identity_linking: true },
    authorizationUrl: () => "https://provider.example/authorize",
    exchange: async () => ({
      provider: "google",
      subject: "provider-subject",
      issuer: "https://provider.example",
      email: null,
      emailVerified: false,
      claims: sanitizeIdentityData({ sub: "provider-subject" }),
    }),
    ...overrides,
  };
}

function sessionService(): SessionService {
  return new SessionService({ repository: repositoryFixture(), tokens: tokenService(), clock: () => NOW });
}

function oauthService(): OAuthService {
  return new OAuthService({
    repository: repositoryFixture(),
    sessions: sessionService(),
    providers: [oauthProvider()],
    tokenHashKey: TOKEN_HASH_KEY,
    encryptionKey: ENCRYPTION_KEY,
    allowedRedirects: [CALLBACK],
    defaultRedirect: CALLBACK,
    clock: () => NOW,
  });
}

function validCreateAuthServerOptions(): Parameters<typeof createAuthServer>[0] {
  return {
    environment: "test",
    baseUrl: "https://project.example.com/auth/v1",
    siteUrl: "https://project.example.com",
    database: repositoryFixture(),
    signingKeys: {
      issuer: "https://project.example.com/auth/v1",
      audience: "project",
      activeKeyId: "active",
      keys: { active: TOKEN_HASH_KEY },
    },
    secrets: {
      tokenHashKey: TOKEN_HASH_KEY,
      encryptionKey: ENCRYPTION_KEY,
    },
    email: { send: async () => undefined },
    redirects: { allowed: [CALLBACK] },
    accessTokenTtlSeconds: 900,
    refreshTokenTtlSeconds: 86_400,
  };
}

function capturedOutcome(operation: () => unknown): { readonly value?: unknown; readonly error?: unknown } {
  try {
    return { value: operation() };
  } catch (error) {
    return { error };
  }
}

function expectNoRawFailure(outcome: { readonly value?: unknown; readonly error?: unknown }, sentinel: string): void {
  expect(String(outcome.error ?? "")).not.toContain(sentinel);
  expect(outcome.error).toBeUndefined();
}

afterEach(() => {
  Reflect.deleteProperty(Object.prototype, "then");
});

describe("Task 9 round 6 shared intrinsic regressions", () => {
  it("keeps every public service constructor stable under post-import trim and safe-integer pollution", () => {
    const operations: readonly [string, () => unknown, "trim" | "safeInteger"][] = [
      ["EmailService", () => emailService(), "trim"],
      ["TokenService", () => tokenService(), "trim"],
      ["OidcOAuthProvider", () => new OidcOAuthProvider({
        name: "oidc",
        clientId: "client",
        clientSecret: "secret",
        issuer: "https://issuer.example",
      }), "trim"],
      ["OAuthService", () => oauthService(), "trim"],
      ["PasswordService", () => new PasswordService(), "safeInteger"],
      ["SessionService", () => sessionService(), "safeInteger"],
      ["UserService", () => new UserService({
        repository: repositoryFixture(),
        passwords: new PasswordService(),
        email: emailService(),
        mailer: { send: async () => undefined },
        oneTimeTokens: oneTimeTokenService(),
        clock: () => NOW,
      }), "safeInteger"],
      ["createAuthServer", () => createAuthServer(validCreateAuthServerOptions()), "trim"],
    ];

    for (const [label, operation, pollution] of operations) {
      const target = pollution === "trim" ? String.prototype : Number;
      const key = pollution === "trim" ? "trim" : "isSafeInteger";
      const original = Object.getOwnPropertyDescriptor(target, key);
      let outcome: { readonly value?: unknown; readonly error?: unknown };
      try {
        Object.defineProperty(target, key, {
          configurable: true,
          enumerable: original?.enumerable ?? false,
          writable: true,
          value: () => { throw new Error(`round6-${label}-sentinel`); },
        });
        outcome = capturedOutcome(operation);
      } finally {
        if (original === undefined) Reflect.deleteProperty(target, key);
        else Object.defineProperty(target, key, original);
      }
      expectNoRawFailure(outcome, `round6-${label}-sentinel`);
      expect(outcome.value, label).toBeDefined();
    }
  });

  it("keeps error validation and metadata/identity sanitization independent of mutable collection methods", () => {
    const originalSetHas = Set.prototype.has;
    const originalSome = Array.prototype.some;
    const originalEntries = Object.entries;
    let error: unknown;
    let metadata: unknown;
    let identity: unknown;
    try {
      Set.prototype.has = (() => { throw new Error("round6-set-sentinel"); }) as typeof Set.prototype.has;
      Array.prototype.some = (() => { throw new Error("round6-some-sentinel"); }) as typeof Array.prototype.some;
      Object.entries = (() => { throw new Error("round6-entries-sentinel"); }) as typeof Object.entries;
      error = capturedOutcome(() => new AuthApiError("invalid_request", 400, "invalid")).error;
      metadata = capturedOutcome(() => sanitizeRedactedMetadata({ nested: ["safe"] })).error;
      identity = capturedOutcome(() => sanitizeIdentityData({ sub: "subject" })).error;
    } finally {
      Set.prototype.has = originalSetHas;
      Array.prototype.some = originalSome;
      Object.entries = originalEntries;
    }
    expect(error).toBeUndefined();
    expect(metadata).toBeUndefined();
    expect(identity).toBeUndefined();
  });
});

describe("Task 9 round 6 one-time-token and configuration regressions", () => {
  it("uses the real HMAC digest for OTP hashes even when Uint8Array.from is poisoned", async () => {
    let issuedHash: Uint8Array | undefined;
    let issuedToken = "";
    const consumed = {
      user_id: null,
      purpose: "email_otp" as const,
      target: "otp@example.com",
      redirect: CALLBACK,
      expires_at: new Date(NOW.getTime() + 60_000),
      metadata: {},
    };
    const repository = repositoryFixture({
      oneTimeTokens: {
        issue: async (input: { readonly token_hash: Uint8Array }) => { issuedHash = input.token_hash; },
        consumeBound: async (candidate: Uint8Array) => {
          if (issuedHash === undefined || candidate.byteLength !== issuedHash.byteLength) return null;
          for (let index = 0; index < candidate.byteLength; index += 1) {
            if (candidate[index] !== issuedHash[index]) return null;
          }
          return consumed;
        },
        consume: noop,
        recordFailure: noop,
      },
    });
    const mailer: Mailer = {
      send: async (message) => { issuedToken = message.variables.token ?? ""; },
    };
    const service = oneTimeTokenService(repository, mailer);
    const originalFrom = Uint8Array.from;
    let issued: Awaited<ReturnType<OneTimeTokenService["issue"]>>;
    try {
      Uint8Array.from = (() => new Uint8Array(32)) as typeof Uint8Array.from;
      issued = await service.issue({
        purpose: "email_otp",
        target: "otp@example.com",
        to: "otp@example.com",
        redirectTo: CALLBACK,
      });
    } finally {
      Uint8Array.from = originalFrom;
    }
    expect(issued.error).toBeNull();
    expect(issuedHash).toBeDefined();
    expect(issuedToken).not.toBe("");
    const arbitrary = await service.verify({
      purpose: "email_otp",
      target: "otp@example.com",
      token: "attacker-controlled-token",
      redirectTo: CALLBACK,
    });
    expect(arbitrary.error?.code).toBe("otp_invalid");
    expect(arbitrary.data).toBeNull();
    const expected = createHmac("sha256", TOKEN_HASH_KEY).update(issuedToken, "utf8").digest();
    expect(Array.from(issuedHash ?? [])).toEqual(Array.from(expected));
  });

  it("does not dispatch one-time-token purposes through a mutable Set.has", async () => {
    const service = oneTimeTokenService(repositoryFixture({
      oneTimeTokens: {
        issue: noop,
        consume: noop,
        consumeBound: async () => null,
        recordFailure: noop,
      },
    }));
    const originalHas = Set.prototype.has;
    let result: unknown;
    try {
      Set.prototype.has = (() => { throw new Error("round6-purpose-set-sentinel"); }) as typeof Set.prototype.has;
      result = await service.verify({
        purpose: "email_otp",
        target: "otp@example.com",
        token: "bad",
        redirectTo: CALLBACK,
      });
    } catch (error) {
      result = error;
    } finally {
      Set.prototype.has = originalHas;
    }
    expect(result).not.toBeInstanceOf(Error);
    expect((result as { readonly error?: { readonly code?: string } }).error?.code).toBe("otp_invalid");
  });

  it("normalizes a valid base path without ambient String.replace", () => {
    const original = Object.getOwnPropertyDescriptor(String.prototype, "replace");
    let outcome: { readonly value?: unknown; readonly error?: unknown };
    try {
      Object.defineProperty(String.prototype, "replace", {
        configurable: true,
        enumerable: original?.enumerable ?? false,
        writable: true,
        value: () => { throw new Error("round6-replace-sentinel"); },
      });
      outcome = capturedOutcome(() => createAuthServer(validCreateAuthServerOptions()));
    } finally {
      if (original === undefined) Reflect.deleteProperty(String.prototype, "replace");
      else Object.defineProperty(String.prototype, "replace", original);
    }
    expectNoRawFailure(outcome, "round6-replace-sentinel");
    expect(outcome.value).toBeDefined();
  });
});

describe("Task 9 round 6 provider error redaction", () => {
  it("does not expose verification key ids, provider material, or causes", async () => {
    const keyId = "provider-key-id-secret-sentinel";
    const service = tokenService({
      getActiveKeyId: () => keyId,
      getSigningKey: () => "not-a-key",
      getVerificationKeys: () => new Map([[keyId, "not-a-key"]]),
    });
    let thrown: unknown;
    try {
      await service.jwks();
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(AuthConfigurationError);
    expect(String(thrown)).not.toContain(keyId);
    expect(JSON.stringify(thrown)).not.toContain(keyId);
    expect((thrown as { readonly cause?: unknown }).cause).toBeUndefined();

    let malformed: unknown;
    try {
      await importEs256Key({ kty: "EC", crv: "P-256", x: "malformed", y: "malformed" }, keyId, "verification");
    } catch (error) {
      malformed = error;
    }
    expect(malformed).toBeInstanceOf(AuthConfigurationError);
    expect(String(malformed)).not.toContain(keyId);
    expect(String(malformed)).not.toContain("DataError");
    expect((malformed as { readonly cause?: unknown }).cause).toBeUndefined();
  });

  it("does not wrap OIDC provider failures with a public cause chain", async () => {
    class FailingProvider extends OidcOAuthProvider {
      protected override async configuration(): Promise<never> {
        return {} as never;
      }
    }
    const provider = new FailingProvider({
      name: "oidc",
      clientId: "client",
      clientSecret: "secret",
      issuer: "https://issuer.example",
    });
    let thrown: unknown;
    try {
      await provider.exchange({
        code: "provider-code-sentinel",
        state: "provider-state-sentinel",
        expectedState: "provider-state-sentinel",
        redirectUri: CALLBACK,
        codeVerifier: "a".repeat(43),
        nonce: "provider-nonce-sentinel",
      });
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(OAuthProviderError);
    expect(String(thrown)).not.toContain("provider-code-sentinel");
    expect((thrown as { readonly cause?: unknown }).cause).toBeUndefined();
  });

  it("redacts discovery failures before provider protocol work begins", async () => {
    class RejectingConfigurationProvider extends OidcOAuthProvider {
      protected override async configuration(): Promise<never> {
        throw new Error("round6-discovery-sentinel");
      }
    }
    const provider = new RejectingConfigurationProvider({
      name: "oidc",
      clientId: "client",
      clientSecret: "secret",
      issuer: "https://issuer.example",
    });
    const calls = [
      () => provider.authorizationUrl({
        clientId: "client",
        redirectUri: CALLBACK,
        state: "state",
        nonce: "nonce",
        scopes: ["openid"],
        codeChallenge: "challenge",
        codeChallengeMethod: "S256" as const,
      }),
      () => provider.exchange({
        code: "provider-code",
        state: "provider-state",
        expectedState: "provider-state",
        redirectUri: CALLBACK,
        codeVerifier: "a".repeat(43),
        nonce: "nonce",
      }),
    ];
    for (const call of calls) {
      let failure: unknown;
      try {
        await call();
      } catch (error) {
        failure = error;
      }
      expect(failure).toBeInstanceOf(OAuthProviderError);
      expect(String(failure)).not.toContain("round6-discovery-sentinel");
      expect((failure as { readonly cause?: unknown }).cause).toBeUndefined();
    }
  });
});

describe("Task 9 round 6 OAuth and permission route result boundaries", () => {
  it("shields OAuth and permission responses from inherited then assimilation", async () => {
    const service = {
      listProviders: () => [{
        name: "google",
        scopes: ["openid"],
        capabilities: { authorization_code: true, pkce: true, identity_linking: true },
      }],
      authorize: () => Promise.resolve(authSuccess({
        provider: "google",
        url: "https://provider.example/authorize",
        redirect: CALLBACK,
        expiresAt: NOW.toISOString(),
      })),
      callback: () => Promise.resolve(authSuccess({
        code: "internal-code",
        redirect: CALLBACK,
        url: `${CALLBACK}?code=internal-code`,
        expiresAt: NOW.toISOString(),
      })),
      exchangeCode: () => Promise.resolve(authSuccess({ user: {}, identity: {}, session: {} })),
      listIdentities: () => Promise.resolve(authSuccess([])),
      unlinkIdentity: () => Promise.resolve(authSuccess(null)),
    };
    const permissionService = {
      getPermissions: () => permissionResult,
      authorize: () => true,
    };
    const permissionResult = Promise.resolve(["invoice.read"]);
    let thenCalls = 0;
    const descriptor = {
      configurable: true,
      enumerable: false,
      writable: true,
      value: () => {
        thenCalls += 1;
        throw new Error("round6-response-then-sentinel");
      },
    };
    let results: readonly Response[] = [];
    try {
      Object.defineProperty(Object.prototype, "then", descriptor);
      results = [
        providersRoute(service as never),
        await authorizeRoute(service as never, new Request(`${CALLBACK}?provider=google&code_challenge=client-challenge`)),
        await callbackRoute(service as never, "google", new Request(`${CALLBACK}?code=provider-code&state=provider-state`)),
        await exchangeRoute(service as never, new Request("https://project.example.com/exchange", {
          method: "POST",
          body: JSON.stringify({ code: "internal-code", code_verifier: "a".repeat(43) }),
          headers: { "content-type": "application/json" },
        })),
        await permissionsRoute(permissionService as never, new Request("https://project.example.com/user/permissions"), { user_id: USER_ID }),
      ];
    } finally {
      Reflect.deleteProperty(Object.prototype, "then");
    }
    expect(results.map((response) => response.status)).toEqual([200, 200, 303, 200, 200]);
    expect(thenCalls).toBe(0);
  });

  it("maps callback failures and rejects provider-controlled redirect/result data", async () => {
    const throwing = {
      listProviders: () => [],
      authorize: () => Promise.resolve(authFailure(new AuthApiError("oauth_provider_error", 502, "provider failure"))),
      callback: () => { throw new Error("round6-callback-provider-sentinel"); },
      exchangeCode: () => Promise.resolve(authSuccess({
        user: { access_token: "round6-verifier-sentinel" },
        identity: { provider_code: "round6-provider-code-sentinel" },
        session: { refresh_token: "round6-token-sentinel" },
      })),
      listIdentities: () => Promise.resolve(authSuccess([])),
      unlinkIdentity: () => Promise.resolve(authSuccess(null)),
    };
    const callbackResponse = await callbackRoute(throwing as never, "google", new Request(`${CALLBACK}?code=provider-code&state=provider-state`));
    const callbackBody = await callbackResponse.text();
    expect(callbackResponse.status).toBe(500);
    expect(callbackBody).not.toContain("round6-callback-provider-sentinel");

    const redirecting = {
      ...throwing,
      callback: () => Promise.resolve(authSuccess({
        code: "internal-code",
        redirect: CALLBACK,
        url: "https://attacker.example/redirect?code=round6-provider-code-sentinel",
        expiresAt: NOW.toISOString(),
      })),
    };
    const redirectResponse = await callbackRoute(redirecting as never, "google", new Request(`${CALLBACK}?code=provider-code&state=provider-state`));
    expect(redirectResponse.status).not.toBe(303);
    expect(redirectResponse.headers.get("location") ?? "").not.toContain("round6-provider-code-sentinel");

    const exchangeResponse = await exchangeRoute(throwing as never, new Request("https://project.example.com/exchange", {
      method: "POST",
      body: JSON.stringify({ code: "internal-code", code_verifier: "a".repeat(43) }),
      headers: { "content-type": "application/json" },
    }));
    const exchangeBody = await exchangeResponse.text();
    expect(exchangeResponse.status).toBe(500);
    expect(exchangeBody).not.toContain("round6-verifier-sentinel");
    expect(exchangeBody).not.toContain("round6-provider-code-sentinel");
    expect(exchangeBody).not.toContain("round6-token-sentinel");
  });
});

describe("Task 9 round 7 provider discovery boundary", () => {
  it("does not expose provider fields outside the documented discovery allowlist", async () => {
    let clientSecretReads = 0;
    const provider = {
      name: "google",
      scopes: ["openid"],
      capabilities: { authorization_code: true, pkce: true, identity_linking: true },
      token: {
        value: "provider-token-sentinel",
        nested: { verifier: "provider-verifier-sentinel", code: "provider-code-sentinel" },
        payload: "provider-payload-sentinel",
      },
    };
    Object.defineProperty(provider, "clientSecret", {
      configurable: true,
      enumerable: true,
      get: () => {
        clientSecretReads += 1;
        throw new Error("provider-secret-getter-sentinel");
      },
    });
    const service = {
      listProviders: () => [provider],
      authorize: () => authSuccess(null),
      callback: () => authSuccess(null),
      exchangeCode: () => authSuccess(null),
      listIdentities: () => authSuccess([]),
      unlinkIdentity: () => authSuccess(null),
    };

    const response = providersRoute(service as never);
    const responseBody = await response.text();
    expect(response.status).toBe(200);
    expect(responseBody).not.toContain("provider-secret-sentinel");
    expect(responseBody).not.toContain("provider-token-sentinel");
    expect(responseBody).not.toContain("provider-verifier-sentinel");
    expect(responseBody).not.toContain("provider-code-sentinel");
    expect(responseBody).not.toContain("provider-payload-sentinel");
    expect(responseBody).not.toContain("provider-secret-getter-sentinel");
    expect(clientSecretReads).toBe(0);
    expect(responseBody).toContain('"name":"google"');
    expect(responseBody).toContain('"scopes":["openid"]');
    expect(responseBody).toContain('"capabilities":{"authorization_code":true,"pkce":true,"identity_linking":true}');
  });

  it("fails closed when an allowed provider scope string exceeds its bound", async () => {
    const service = {
      listProviders: () => [{
        name: "google",
        scopes: ["s".repeat(129)],
        capabilities: { authorization_code: true, pkce: true, identity_linking: true },
      }],
      authorize: () => authSuccess(null),
      callback: () => authSuccess(null),
      exchangeCode: () => authSuccess(null),
      listIdentities: () => authSuccess([]),
      unlinkIdentity: () => authSuccess(null),
    };

    const response = providersRoute(service as never);
    const responseBody = await response.json() as { readonly data?: unknown; readonly error?: { readonly code?: string } };
    expect(response.status).toBe(500);
    expect(responseBody.data).toBeNull();
    expect(responseBody.error?.code).toBe("internal_error");
  });
});
