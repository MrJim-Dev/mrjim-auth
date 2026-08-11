import { createHmac } from "node:crypto";
import {
  SignJWT,
  decodeProtectedHeader,
  jwtVerify,
  type JWTPayload,
} from "jose";
import { authFailure, type AuthResult } from "../shared/result.js";
import {
  AuthApiError,
  AuthConfigurationError,
} from "../shared/errors.js";
import type {
  KeyProvider,
  SessionRecord,
} from "../shared/contracts.js";
import { uuidSchema, type User } from "../shared/types.js";
import {
  ES256_ALGORITHM,
  buildPublicJwks,
  importEs256Key,
  type PublicEs256Jwk,
} from "./jwks.js";
import {
  assertBoundaryObject,
  captureBoundaryBytes,
  captureBoundaryClock,
  captureBoundaryKeyProvider,
  captureBoundaryMapEntries,
  invokeBoundaryResult,
  captureBoundaryStringArray,
  optionalBoundaryOption,
  requiredBoundaryOption,
} from "./callback-boundary.js";
import {
  safeNumberIsFinite,
  safeNumberIsInteger,
  safeNumberIsSafeInteger,
  safeStringTrim,
} from "../shared/safe-intrinsics.js";

/** The verified claims required from every Task 5 access token. */
export interface AccessTokenClaims extends JWTPayload {
  readonly iss: string;
  readonly aud: string | string[];
  readonly sub: string;
  readonly sid: string;
  readonly aal: number;
  readonly iat: number;
  readonly exp: number;
}

/** Configuration for the server-only token service. */
export interface TokenServiceOptions {
  /** The public issuer placed in and required from access tokens. */
  readonly issuer: string;
  /** The intended project audience placed in and required from access tokens. */
  readonly audience: string | string[];
  /** Project-owned active/verification key selection and rotation boundary. */
  readonly keyProvider: KeyProvider;
  /** Project-owned HMAC key used for opaque-token digests. */
  readonly tokenHashKey: string | Uint8Array;
  /** Access-token lifetime in seconds. Defaults to 15 minutes. */
  readonly accessTokenTtlSeconds?: number;
  /** Injectable clock for deterministic tests and project operation control. */
  readonly clock?: () => Date;
}

const DEFAULT_ACCESS_TOKEN_TTL_SECONDS = 900;
const tokenNumberIsFinite = safeNumberIsFinite;
const tokenNumberIsInteger = safeNumberIsInteger;
const tokenNumberIsSafeInteger = safeNumberIsSafeInteger;
const tokenUint8ArrayFrom = Uint8Array.from.bind(Uint8Array) as (value: ArrayLike<number> | Iterable<number>) => Uint8Array;
const tokenTextEncoder = TextEncoder;

function invalidToken(): AuthResult<never> {
  return authFailure(new AuthApiError("invalid_token", 401, "Invalid access token"));
}

function validClock(clock: () => Date): Date {
  const now = clock();
  if (!(now instanceof Date) || !tokenNumberIsFinite(now.getTime())) {
    throw new AuthConfigurationError("token clock must return a valid Date");
  }
  return now;
}

function validString(value: string, label: string): string {
  if (typeof value !== "string" || safeStringTrim(value) === null || safeStringTrim(value) === "") {
    throw new AuthConfigurationError(`${label} must be non-empty`);
  }
  return value;
}

function validUuid(value: unknown, label: string): string {
  const parsed = uuidSchema.safeParse(value);
  if (!parsed.success) {
    throw new AuthConfigurationError(`${label} must be a valid UUID`);
  }
  return parsed.data;
}

function validDate(value: unknown, label: string): number {
  if (!(value instanceof Date) || !tokenNumberIsFinite(value.getTime())) {
    throw new AuthConfigurationError(`${label} must be a valid Date`);
  }
  return value.getTime();
}

function validClaims(payload: JWTPayload): payload is AccessTokenClaims {
  const audience = payload.aud;
  let audienceValid = false;
  if (typeof audience === "string") {
    audienceValid = safeStringTrim(audience) !== null && safeStringTrim(audience) !== "";
  } else {
    try {
      captureBoundaryStringArray(audience, "access-token audience", 1, 128);
      audienceValid = true;
    } catch {
      audienceValid = false;
    }
  }
  return (
    typeof payload.iss === "string" &&
    safeStringTrim(payload.iss) !== null && safeStringTrim(payload.iss) !== "" &&
    audienceValid &&
    typeof payload.sub === "string" &&
    safeStringTrim(payload.sub) !== null && safeStringTrim(payload.sub) !== "" &&
    typeof payload.sid === "string" &&
    safeStringTrim(payload.sid) !== null && safeStringTrim(payload.sid) !== "" &&
    typeof payload.aal === "number" &&
    tokenNumberIsInteger(payload.aal) &&
    payload.aal >= 1 &&
    payload.aal <= 3 &&
    typeof payload.iat === "number" &&
    tokenNumberIsSafeInteger(payload.iat) &&
    typeof payload.exp === "number" &&
    tokenNumberIsSafeInteger(payload.exp) &&
    payload.exp > payload.iat
  );
}

/**
 * Server-only ES256 JWT and opaque-token primitive.
 *
 * Verification selects a key only after reading the protected `kid`, allows
 * only ES256, and lets jose enforce the issuer, audience, required claims, and
 * expiry checks. The provider is queried for every operation so key rotation
 * can publish old verification keys while selecting a new active signer.
 */
export class TokenService {
  readonly issuer: string;
  readonly audience: string | string[];
  readonly accessTokenTtlSeconds: number;

  private readonly keyProvider: KeyProvider;
  private readonly tokenHashKey: Uint8Array;
  private readonly clock: () => Date;

  constructor(options: TokenServiceOptions) {
    if (options === null || typeof options !== "object") {
      throw new AuthConfigurationError("token options are incomplete");
    }
    const source = options as unknown as object;
    assertBoundaryObject(source, "token options");

    // Snapshot every callback-bearing option before ordinary validation can
    // touch a hostile accessor or a mutable provider object.
    const issuerValue = requiredBoundaryOption(source, "issuer", "token issuer");
    const audienceValue = requiredBoundaryOption(source, "audience", "token audience");
    const keyProviderValue = requiredBoundaryOption(source, "keyProvider", "token key provider");
    const tokenHashKeyValue = requiredBoundaryOption(source, "tokenHashKey", "token hash key");
    const accessTokenTtlValue = optionalBoundaryOption(source, "accessTokenTtlSeconds", "access token TTL");
    const clockValue = optionalBoundaryOption(source, "clock", "token clock");
    const keyProvider = captureBoundaryKeyProvider(keyProviderValue);
    const clock = captureBoundaryClock(clockValue, "token clock", () => new Date());

    this.issuer = validString(issuerValue as string, "token issuer");
    const audience = typeof audienceValue === "string"
      ? audienceValue
      : captureBoundaryStringArray(audienceValue, "token audience", 1, 128);
    if (typeof audience === "string" && (safeStringTrim(audience) === null || safeStringTrim(audience) === "")) {
      throw new AuthConfigurationError("token audience must be non-empty");
    }
    this.audience = typeof audience === "string" ? audience : audience as string[];

    const hashKey =
      typeof tokenHashKeyValue === "string"
        ? new tokenTextEncoder().encode(tokenHashKeyValue)
        : captureBoundaryBytes(tokenHashKeyValue, "token hash key", 1);
    if (hashKey.byteLength === 0) {
      throw new AuthConfigurationError("token hash key must be non-empty");
    }
    this.tokenHashKey = hashKey;

    const accessTokenTtlSeconds = (accessTokenTtlValue as number | undefined) ?? DEFAULT_ACCESS_TOKEN_TTL_SECONDS;
    if (
      !tokenNumberIsSafeInteger(accessTokenTtlSeconds) ||
      accessTokenTtlSeconds < 300 ||
      accessTokenTtlSeconds > 3_600
    ) {
      throw new AuthConfigurationError("access token TTL must be between 300 and 3600 seconds");
    }
    this.accessTokenTtlSeconds = accessTokenTtlSeconds;
    this.keyProvider = keyProvider;
    this.clock = clock;
    validClock(this.clock);
  }

  /** Issues an ES256 JWT with a protected key id and the required claims. */
  async issueAccessToken(user: User, session: SessionRecord): Promise<string> {
    const userId = validUuid(user.id, "access-token subject");
    const sessionId = validUuid(session.id, "access-token session id");
    const sessionUserId = validUuid(session.user_id, "access-token session owner");
    if (sessionUserId !== userId) {
      throw new AuthConfigurationError("access-token session owner does not match the user");
    }
    if (user.deleted_at !== null || session.revoked_at !== null) {
      throw new AuthConfigurationError("cannot issue an access token for an inactive subject");
    }
    if (!tokenNumberIsInteger(session.aal) || session.aal < 1 || session.aal > 3) {
      throw new AuthConfigurationError("access-token AAL must be an integer from 1 to 3");
    }

    const createdAt = validDate(session.created_at, "access-token session creation time");
    const refreshedAt = validDate(session.refreshed_at, "access-token session refresh time");
    const sessionExpiresAt = validDate(session.expires_at, "access-token session expiry");
    if (createdAt > refreshedAt || refreshedAt > sessionExpiresAt) {
      throw new AuthConfigurationError("access-token session timestamps are inconsistent");
    }

    const keyId = validString(await invokeBoundaryResult<string>(
      this.keyProvider.getActiveKeyId,
      this.keyProvider,
      [],
      "active signing key provider",
    ), "active signing key id");
    const material = await invokeBoundaryResult<Parameters<typeof importEs256Key>[0]>(
      this.keyProvider.getSigningKey,
      this.keyProvider,
      [keyId],
      "signing key provider",
    );
    const signingKey = await importEs256Key(material, keyId, "signing");
    const now = validClock(this.clock).getTime();
    if (createdAt > now || refreshedAt > now || sessionExpiresAt <= now) {
      throw new AuthConfigurationError("cannot issue an access token outside the session lifetime");
    }
    const issuedAt = Math.floor(now / 1000);
    const expiresAt = Math.min(
      issuedAt + this.accessTokenTtlSeconds,
      Math.floor(sessionExpiresAt / 1000),
    );
    if (expiresAt <= issuedAt) {
      throw new AuthConfigurationError("session expiry is too close to issue an access token");
    }

    return new SignJWT({
      sub: userId,
      sid: sessionId,
      aal: session.aal,
    })
      .setProtectedHeader({ alg: ES256_ALGORITHM, kid: keyId, typ: "JWT" })
      .setIssuer(this.issuer)
      .setAudience(this.audience)
      .setIssuedAt(issuedAt)
      .setExpirationTime(expiresAt)
      .sign(signingKey);
  }

  /**
   * Verifies one access token and returns a stable public auth failure for all
   * malformed, expired, wrong-key, wrong-kid, wrong-algorithm, issuer, or
   * audience inputs.
   */
  async verifyAccessToken(jwt: string): Promise<AuthResult<AccessTokenClaims>> {
    try {
      if (typeof jwt !== "string" || safeStringTrim(jwt) === null || safeStringTrim(jwt) === "") return invalidToken();
      const protectedHeader = decodeProtectedHeader(jwt);
      if (
        protectedHeader.alg !== ES256_ALGORITHM ||
        typeof protectedHeader.kid !== "string" ||
        safeStringTrim(protectedHeader.kid) === null || safeStringTrim(protectedHeader.kid) === ""
      ) {
        return invalidToken();
      }

      const verificationKeys = await invokeBoundaryResult<ReadonlyMap<string, Parameters<typeof importEs256Key>[0]>>(
        this.keyProvider.getVerificationKeys,
        this.keyProvider,
        [],
        "verification key provider",
      );
      const entries = captureBoundaryMapEntries(verificationKeys, "verification key provider", 100_000);
      let material: Parameters<typeof importEs256Key>[0] | undefined;
      for (let index = 0; index < entries.length; index += 1) {
        const entry = entries[index];
        if (entry !== undefined && entry[0] === protectedHeader.kid) {
          material = entry[1] as Parameters<typeof importEs256Key>[0];
          break;
        }
      }
      if (material === undefined) return invalidToken();
      const verificationKey = await importEs256Key(
        material,
        protectedHeader.kid,
        "verification",
      );
      const verified = await jwtVerify<AccessTokenClaims>(jwt, verificationKey, {
        algorithms: [ES256_ALGORITHM],
        issuer: this.issuer,
        audience: this.audience,
        requiredClaims: ["iss", "aud", "sub", "sid", "aal", "iat", "exp"],
        currentDate: validClock(this.clock),
      });
      if (!validClaims(verified.payload)) return invalidToken();
      return { data: verified.payload, error: null };
    } catch (error) {
      if (error instanceof AuthConfigurationError) throw error;
      return invalidToken();
    }
  }

  /** Returns the HMAC-SHA-256 digest persisted for an opaque token. */
  hashOpaqueToken(token: string): Uint8Array {
    if (typeof token !== "string") {
      throw new TypeError("opaque token must be a string");
    }
    return tokenUint8ArrayFrom(
      createHmac("sha256", this.tokenHashKey).update(token, "utf8").digest(),
    );
  }

  /** Returns the public verification keys for `/.well-known/jwks.json`. */
  async jwks(): Promise<{ readonly keys: readonly PublicEs256Jwk[] }> {
    const jwks = await buildPublicJwks(this.keyProvider);
    return { keys: jwks.keys as readonly PublicEs256Jwk[] };
  }
}
