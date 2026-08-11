import { createHmac, generateKeyPairSync } from "node:crypto";
import {
  CompactSign,
  SignJWT,
  decodeJwt,
  decodeProtectedHeader,
  exportJWK,
  importPKCS8,
  importSPKI,
  jwtVerify,
} from "jose";
import { describe, expect, it } from "vitest";
import type { KeyProvider } from "../../src/shared/contracts.js";
import type { User, UUID } from "../../src/shared/types.js";
import { TokenService } from "../../src/server/tokens.js";
import { uuidSchema } from "../../src/shared/types.js";
import type { SessionRecord } from "../../src/shared/contracts.js";
import { AuthConfigurationError } from "../../src/shared/errors.js";

const ISSUER = "https://project.example.com/auth/v1";
const AUDIENCE = "project";
const NOW = new Date("2026-08-11T04:00:00.000Z");
const TOKEN_HASH_KEY = Uint8Array.from({ length: 32 }, (_, index) => index + 1);

type GeneratedKey = {
  readonly privateKey: string;
  readonly publicKey: string;
};

function generateEs256Key(): GeneratedKey {
  const pair = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return {
    privateKey: pair.privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    publicKey: pair.publicKey.export({ type: "spki", format: "pem" }).toString(),
  };
}

function makeProvider(keys: ReadonlyMap<string, GeneratedKey>, activeKeyId = "active") {
  let active = activeKeyId;
  const provider: KeyProvider & { setActiveKeyId(keyId: string): void } = {
    getActiveKeyId: () => active,
    getSigningKey: (keyId) => keys.get(keyId)?.privateKey ?? "",
    getVerificationKeys: () =>
      new Map([...keys].map(([keyId, key]) => [keyId, key.publicKey])),
    setActiveKeyId: (keyId) => {
      active = keyId;
    },
  };
  return provider;
}

function makeUser(): User {
  return {
    id: uuidSchema.parse("00000000-0000-4000-8000-000000000101"),
    email: "user@example.com",
    phone: null,
    email_confirmed_at: "2026-08-11T00:00:00.000Z",
    phone_confirmed_at: null,
    confirmed_at: "2026-08-11T00:00:00.000Z",
    last_sign_in_at: null,
    banned_until: null,
    user_metadata: { displayName: "User" },
    app_metadata: { provider: "email" },
    created_at: "2026-08-11T00:00:00.000Z",
    updated_at: "2026-08-11T00:00:00.000Z",
    deleted_at: null,
  };
}

function makeSession(): SessionRecord {
  return {
    id: uuidSchema.parse("00000000-0000-4000-8000-000000000102"),
    user_id: uuidSchema.parse("00000000-0000-4000-8000-000000000101"),
    aal: 2,
    ip_address: "127.0.0.1",
    user_agent: "tokens-test",
    created_at: NOW,
    refreshed_at: NOW,
    expires_at: new Date("2026-09-10T04:00:00.000Z"),
    revoked_at: null,
  };
}

function makeService(
  provider: KeyProvider,
  overrides: Partial<ConstructorParameters<typeof TokenService>[0]> = {},
): TokenService {
  return new TokenService({
    issuer: ISSUER,
    audience: AUDIENCE,
    keyProvider: provider,
    tokenHashKey: TOKEN_HASH_KEY,
    accessTokenTtlSeconds: 900,
    clock: () => NOW,
    ...overrides,
  });
}

describe("TokenService", () => {
  it("issues ES256 access tokens with the required claims and protected kid", async () => {
    const key = generateEs256Key();
    const provider = makeProvider(new Map([["active", key]]));
    const service = makeService(provider);

    const jwt = await service.issueAccessToken(makeUser(), makeSession());
    const header = decodeProtectedHeader(jwt);
    expect(header).toMatchObject({ alg: "ES256", kid: "active", typ: "JWT" });

    const verified = await jwtVerify(jwt, await importSPKI(key.publicKey, "ES256"), {
      algorithms: ["ES256"],
      issuer: ISSUER,
      audience: AUDIENCE,
      currentDate: NOW,
    });
    expect(verified.payload).toMatchObject({
      iss: ISSUER,
      aud: AUDIENCE,
      sub: "00000000-0000-4000-8000-000000000101",
      sid: "00000000-0000-4000-8000-000000000102",
      aal: 2,
      iat: Math.floor(NOW.getTime() / 1000),
      exp: Math.floor(NOW.getTime() / 1000) + 900,
    });

    const result = await service.verifyAccessToken(jwt);
    expect(result.error).toBeNull();
    expect(result.data).toMatchObject({
      iss: ISSUER,
      aud: AUDIENCE,
      sub: "00000000-0000-4000-8000-000000000101",
      sid: "00000000-0000-4000-8000-000000000102",
      aal: 2,
    });
  });

  it("selects rotated verification keys and publishes public JWKS without private material", async () => {
    const active = generateEs256Key();
    const rotated = generateEs256Key();
    const provider = makeProvider(
      new Map([
        ["active", active],
        ["rotated", rotated],
      ]),
    );
    const service = makeService(provider);

    const oldToken = await service.issueAccessToken(makeUser(), makeSession());
    provider.setActiveKeyId("rotated");
    const newToken = await service.issueAccessToken(makeUser(), makeSession());

    expect(decodeProtectedHeader(oldToken).kid).toBe("active");
    expect(decodeProtectedHeader(newToken).kid).toBe("rotated");
    expect((await service.verifyAccessToken(oldToken)).error).toBeNull();
    expect((await service.verifyAccessToken(newToken)).error).toBeNull();

    const jwks = await service.jwks();
    expect(jwks.keys).toHaveLength(2);
    expect(jwks.keys.map((key) => key.kid).sort()).toEqual(["active", "rotated"]);
    for (const publicKey of jwks.keys) {
      expect(publicKey).toMatchObject({ alg: "ES256", crv: "P-256", kty: "EC", use: "sig" });
      expect(publicKey).not.toHaveProperty("d");
    }
  });

  it("derives public JWKS safely when verification material is a private JWK", async () => {
    const key = generateEs256Key();
    const privateJwk = await exportJWK(
      await importPKCS8(key.privateKey, "ES256", { extractable: true }),
    );
    const provider: KeyProvider = {
      getActiveKeyId: () => "active",
      getSigningKey: () => key.privateKey,
      getVerificationKeys: () => new Map([["active", privateJwk]]),
    };

    const jwks = await makeService(provider).jwks();
    expect(jwks.keys).toHaveLength(1);
    expect(jwks.keys[0]).toMatchObject({
      kid: "active",
      alg: "ES256",
      crv: "P-256",
      kty: "EC",
      use: "sig",
    });
    for (const privateField of ["d", "p", "q", "dp", "dq", "qi", "key_ops"]) {
      expect(jwks.keys[0]).not.toHaveProperty(privateField);
    }
  });

  it("captures provider maps and redacts hostile provider-returned values", async () => {
    const key = generateEs256Key();
    const service = makeService(makeProvider(new Map([["active", key]])));
    const originalEntries = Map.prototype.entries;
    let mapThrown: unknown;
    try {
      Map.prototype.entries = (() => { throw new Error("provider-map-entries-sentinel"); }) as typeof Map.prototype.entries;
      await service.jwks();
    } catch (error) {
      mapThrown = error;
    } finally {
      Map.prototype.entries = originalEntries;
    }
    expect(mapThrown).toBeUndefined();

    const privateJwk = await exportJWK(await importPKCS8(key.privateKey, "ES256", { extractable: true }));
    Object.defineProperty(privateJwk, "kty", {
      configurable: true,
      enumerable: true,
      get: () => { throw new Error("provider-jwk-sentinel"); },
    });
    const hostileJwkProvider: KeyProvider = {
      getActiveKeyId: () => "active",
      getSigningKey: () => key.privateKey,
      getVerificationKeys: () => new Map([["active", privateJwk]]),
    };
    await expect(makeService(hostileJwkProvider).jwks()).rejects.toSatisfy((error: unknown) =>
      error instanceof AuthConfigurationError && !String(error).includes("provider-jwk-sentinel"));

    const rejectingThenable = { then: (_resolve: unknown, reject: (error: Error) => void) => reject(new Error("provider-thenable-sentinel")) };
    const hostileActiveProvider: KeyProvider = {
      getActiveKeyId: () => rejectingThenable as never,
      getSigningKey: () => key.privateKey,
      getVerificationKeys: () => new Map([["active", key.publicKey]]),
    };
    await expect(makeService(hostileActiveProvider).issueAccessToken(makeUser(), makeSession())).rejects.toSatisfy((error: unknown) =>
      error instanceof AuthConfigurationError && !String(error).includes("provider-thenable-sentinel"));

    const hostileSigningProvider: KeyProvider = {
      getActiveKeyId: () => "active",
      getSigningKey: () => rejectingThenable as never,
      getVerificationKeys: () => new Map([["active", key.publicKey]]),
    };
    await expect(makeService(hostileSigningProvider).issueAccessToken(makeUser(), makeSession())).rejects.toSatisfy((error: unknown) =>
      error instanceof AuthConfigurationError && !String(error).includes("provider-thenable-sentinel"));
  });

  it("rejects mismatched, expired, revoked, and malformed session records before signing", async () => {
    const key = generateEs256Key();
    const service = makeService(makeProvider(new Map([["active", key]])));
    const user = makeUser();
    const session = makeSession();
    const otherUserId = uuidSchema.parse("00000000-0000-4000-8000-000000000103");
    const invalidSessions: readonly SessionRecord[] = [
      { ...session, user_id: otherUserId },
      { ...session, expires_at: new Date(NOW.getTime() - 1) },
      { ...session, created_at: new Date("invalid") },
      { ...session, refreshed_at: new Date("invalid") },
      { ...session, expires_at: new Date("invalid") },
      { ...session, revoked_at: NOW },
    ];

    for (const invalidSession of invalidSessions) {
      await expect(service.issueAccessToken(user, invalidSession)).rejects.toBeInstanceOf(
        AuthConfigurationError,
      );
    }
  });

  it("caps access-token expiry at the owning session expiry", async () => {
    const key = generateEs256Key();
    const service = makeService(makeProvider(new Map([["active", key]])));
    const sessionExpiry = new Date(NOW.getTime() + 45_000);

    const jwt = await service.issueAccessToken(makeUser(), {
      ...makeSession(),
      expires_at: sessionExpiry,
    });
    const claims = decodeJwt(jwt);
    expect(claims.exp).toBe(Math.floor(sessionExpiry.getTime() / 1000));
    expect(claims.exp).toBeLessThanOrEqual(Math.floor(sessionExpiry.getTime() / 1000));
  });

  it("hashes opaque tokens with HMAC-SHA-256 and returns exactly one digest", () => {
    const key = generateEs256Key();
    const service = makeService(makeProvider(new Map([["active", key]])));
    const raw = "opaque-refresh-token-value";

    const actual = service.hashOpaqueToken(raw);
    const expected = createHmac("sha256", TOKEN_HASH_KEY).update(raw, "utf8").digest();
    expect(actual.byteLength).toBe(32);
    expect(Buffer.from(actual)).toEqual(expected);
    expect(service.hashOpaqueToken(raw)).toEqual(actual);
    expect(service.hashOpaqueToken(`${raw}-different`)).not.toEqual(actual);
  });

  it("rejects wrong issuer, audience, algorithm, kid, key, and expiry as stable invalid tokens", async () => {
    const key = generateEs256Key();
    const otherKey = generateEs256Key();
    const provider = makeProvider(new Map([["active", key]]));
    const service = makeService(provider);
    const user = makeUser();
    const session = makeSession();
    const claims = {
      sub: user.id as UUID,
      sid: session.id as UUID,
      aal: session.aal,
      iat: Math.floor(NOW.getTime() / 1000),
      exp: Math.floor(NOW.getTime() / 1000) + 900,
    };

    const wrongIssuer = await new SignJWT(claims)
      .setProtectedHeader({ alg: "ES256", kid: "active", typ: "JWT" })
      .setIssuer("https://attacker.example.com")
      .setAudience(AUDIENCE)
      .sign(await importKeyForTest(key.privateKey, "private"));
    const wrongAudience = await new SignJWT(claims)
      .setProtectedHeader({ alg: "ES256", kid: "active", typ: "JWT" })
      .setIssuer(ISSUER)
      .setAudience("other-project")
      .sign(await importKeyForTest(key.privateKey, "private"));
    const wrongKid = await new SignJWT({ ...claims, iss: ISSUER, aud: AUDIENCE })
      .setProtectedHeader({ alg: "ES256", kid: "unknown", typ: "JWT" })
      .sign(await importKeyForTest(key.privateKey, "private"));
    const wrongKey = await new SignJWT({ ...claims, iss: ISSUER, aud: AUDIENCE })
      .setProtectedHeader({ alg: "ES256", kid: "active", typ: "JWT" })
      .sign(await importKeyForTest(otherKey.privateKey, "private"));
    const expired = await new SignJWT({ ...claims, iss: ISSUER, aud: AUDIENCE, exp: 1 })
      .setProtectedHeader({ alg: "ES256", kid: "active", typ: "JWT" })
      .sign(await importKeyForTest(key.privateKey, "private"));
    const wrongAlgorithm = await new SignJWT({ ...claims, iss: ISSUER, aud: AUDIENCE })
      .setProtectedHeader({ alg: "HS256", kid: "active", typ: "JWT" })
      .sign(new TextEncoder().encode("not-an-ec-key"));
    const missingKid = await new CompactSign(
      new TextEncoder().encode(JSON.stringify({ ...claims, iss: ISSUER, aud: AUDIENCE })),
    )
      .setProtectedHeader({ alg: "ES256", typ: "JWT" })
      .sign(await importKeyForTest(key.privateKey, "private"));

    for (const token of [
      wrongIssuer,
      wrongAudience,
      wrongKid,
      wrongKey,
      expired,
      wrongAlgorithm,
      missingKid,
    ]) {
      const result = await service.verifyAccessToken(token);
      expect(result.data).toBeNull();
      expect(result.error).toMatchObject({ name: "AuthError", code: "invalid_token", status: 401 });
    }
  });

  it("captures key-provider and clock boundaries without invoking hostile values", async () => {
    const thenableCases: readonly [string, (provider: KeyProvider, calls: { value: number }) => void][] = [
      ["own data thenable", (provider, calls) => Object.defineProperty(provider, "then", {
        configurable: true,
        value: () => { calls.value += 1; },
      })],
      ["own accessor then", (provider, calls) => Object.defineProperty(provider, "then", {
        configurable: true,
        get: () => { calls.value += 1; throw new Error("key-provider-then-sentinel"); },
      })],
      ["inherited data thenable", (provider, calls) => {
        const prototype = Object.create(Object.getPrototypeOf(provider));
        Object.defineProperty(prototype, "then", { configurable: true, value: () => { calls.value += 1; } });
        Object.setPrototypeOf(provider, prototype);
      }],
      ["inherited accessor then", (provider, calls) => {
        const prototype = Object.create(Object.getPrototypeOf(provider));
        Object.defineProperty(prototype, "then", {
          configurable: true,
          get: () => { calls.value += 1; throw new Error("inherited-key-provider-then-sentinel"); },
        });
        Object.setPrototypeOf(provider, prototype);
      }],
      ["poisoned prototype", (provider, calls) => {
        const prototype = Object.create(Object.getPrototypeOf(provider), {
          then: {
            configurable: true,
            get: () => { calls.value += 1; throw new Error("poisoned-key-provider-then-sentinel"); },
          },
        });
        Object.setPrototypeOf(provider, prototype);
      }],
    ];

    for (const [label, install] of thenableCases) {
      const provider = makeProvider(new Map([["active", generateEs256Key()]]));
      const calls = { value: 0 };
      install(provider, calls);
      let thrown: unknown;
      try {
        makeService(provider);
      } catch (error) {
        thrown = error;
      }
      expect(thrown, label).toBeInstanceOf(AuthConfigurationError);
      expect(String(thrown), label).not.toContain("sentinel");
      expect(calls.value, label).toBe(0);
    }

    const callableThenable = Object.assign(() => undefined, {
      getActiveKeyId: () => "active",
      getSigningKey: () => "",
      getVerificationKeys: () => new Map(),
    }) as unknown as KeyProvider;
    let callableThenCalls = 0;
    Object.defineProperty(callableThenable, "then", {
      configurable: true,
      value: () => { callableThenCalls += 1; },
    });
    expect(() => makeService(callableThenable)).toThrow(AuthConfigurationError);
    expect(callableThenCalls).toBe(0);

    const accessorProvider = makeProvider(new Map([["active", generateEs256Key()]]));
    let methodGetterCalls = 0;
    Object.defineProperty(accessorProvider, "getActiveKeyId", {
      configurable: true,
      get: () => { methodGetterCalls += 1; throw new Error("key-provider-method-sentinel"); },
    });
    let methodThrown: unknown;
    try {
      makeService(accessorProvider);
    } catch (error) {
      methodThrown = error;
    }
    expect(methodThrown).toBeInstanceOf(AuthConfigurationError);
    expect(String(methodThrown)).not.toContain("key-provider-method-sentinel");
    expect(methodGetterCalls).toBe(0);

    const clockAccessorOptions = {
      issuer: ISSUER,
      audience: AUDIENCE,
      keyProvider: makeProvider(new Map([["active", generateEs256Key()]])),
      tokenHashKey: TOKEN_HASH_KEY,
      accessTokenTtlSeconds: 900,
    } as any;
    let clockGetterCalls = 0;
    Object.defineProperty(clockAccessorOptions, "clock", {
      configurable: true,
      get: () => { clockGetterCalls += 1; throw new Error("clock-sentinel"); },
    });
    let clockThrown: unknown;
    try {
      new TokenService(clockAccessorOptions);
    } catch (error) {
      clockThrown = error;
    }
    expect(clockThrown).toBeInstanceOf(AuthConfigurationError);
    expect(String(clockThrown)).not.toContain("clock-sentinel");
    expect(clockGetterCalls).toBe(0);

    const thenableClock = (() => NOW) as (() => Date) & { then?: () => void };
    let clockThenCalls = 0;
    Object.defineProperty(thenableClock, "then", {
      configurable: true,
      value: () => { clockThenCalls += 1; },
    });
    expect(() => makeService(makeProvider(new Map([["active", generateEs256Key()]])), { clock: thenableClock })).toThrow(AuthConfigurationError);
    expect(clockThenCalls).toBe(0);

    const key = generateEs256Key();
    let oldCalls = 0;
    let newCalls = 0;
    const receiverProvider = {
      keys: new Map([["active", key]]),
      getActiveKeyId() { return "active"; },
      getSigningKey(this: { keys: ReadonlyMap<string, GeneratedKey> }, keyId: string) {
        return this.keys.get(keyId)?.privateKey ?? "";
      },
      getVerificationKeys(this: { keys: ReadonlyMap<string, GeneratedKey> }) {
        oldCalls += 1;
        return new Map([...this.keys].map(([keyId, value]) => [keyId, value.publicKey]));
      },
    } as KeyProvider & { keys: ReadonlyMap<string, GeneratedKey>; getVerificationKeys: () => ReadonlyMap<string, string> };
    const receiverService = makeService(receiverProvider);
    receiverProvider.getVerificationKeys = () => {
      newCalls += 1;
      return new Map();
    };
    const jwks = await receiverService.jwks();
    expect(jwks.keys).toHaveLength(1);
    expect(oldCalls).toBe(1);
    expect(newCalls).toBe(0);
  });

  it("requires dense own audience entries and isolates the captured collection", () => {
    const sparse = new Array<string>(1);
    expect(() => makeService(makeProvider(new Map([["active", generateEs256Key()]])), { audience: sparse })).toThrow(AuthConfigurationError);

    const inherited = new Array<string>(1);
    const inheritedPrototype = Object.create(Array.prototype) as Record<string, unknown>;
    Object.defineProperty(inheritedPrototype, "0", { configurable: true, value: "inherited-audience" });
    Object.setPrototypeOf(inherited, inheritedPrototype);
    expect(() => makeService(makeProvider(new Map([["active", generateEs256Key()]])), { audience: inherited })).toThrow(AuthConfigurationError);

    const oversized = Array.from({ length: 129 }, (_, index) => `audience-${index}`);
    expect(() => makeService(makeProvider(new Map([["active", generateEs256Key()]])), { audience: oversized })).toThrow(AuthConfigurationError);

    const originalSome = Array.prototype.some;
    try {
      Array.prototype.some = (() => { throw new Error("audience some sentinel"); }) as typeof Array.prototype.some;
      expect(() => makeService(makeProvider(new Map([["active", generateEs256Key()]])), { audience: ["project"] })).not.toThrow();
    } finally {
      Array.prototype.some = originalSome;
    }
  });
});

async function importKeyForTest(value: string, kind: "private") {
  const { importPKCS8 } = await import("jose");
  return importPKCS8(value, "ES256");
}
