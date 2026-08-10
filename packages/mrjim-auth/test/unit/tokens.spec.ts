import { createHmac, generateKeyPairSync } from "node:crypto";
import {
  CompactSign,
  SignJWT,
  decodeProtectedHeader,
  importSPKI,
  jwtVerify,
} from "jose";
import { describe, expect, it } from "vitest";
import type { KeyProvider } from "../../src/shared/contracts.js";
import type { User, UUID } from "../../src/shared/types.js";
import { TokenService } from "../../src/server/tokens.js";
import { uuidSchema } from "../../src/shared/types.js";
import type { SessionRecord } from "../../src/shared/contracts.js";

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
});

async function importKeyForTest(value: string, kind: "private") {
  const { importPKCS8 } = await import("jose");
  return importPKCS8(value, "ES256");
}
