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
import type { User } from "../shared/types.js";
import {
  ES256_ALGORITHM,
  buildPublicJwks,
  importEs256Key,
  type PublicEs256Jwk,
} from "./jwks.js";

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

function invalidToken(): AuthResult<never> {
  return authFailure(new AuthApiError("invalid_token", 401, "Invalid access token"));
}

function validClock(clock: () => Date): Date {
  const now = clock();
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) {
    throw new AuthConfigurationError("token clock must return a valid Date");
  }
  return now;
}

function validString(value: string, label: string): string {
  if (typeof value !== "string" || value.trim() === "") {
    throw new AuthConfigurationError(`${label} must be non-empty`);
  }
  return value;
}

function validClaims(payload: JWTPayload): payload is AccessTokenClaims {
  const audience = payload.aud;
  return (
    typeof payload.iss === "string" &&
    payload.iss.trim() !== "" &&
    (typeof audience === "string" ||
      (Array.isArray(audience) &&
        audience.length > 0 &&
        audience.every((value) => typeof value === "string" && value.trim() !== ""))) &&
    typeof payload.sub === "string" &&
    payload.sub.trim() !== "" &&
    typeof payload.sid === "string" &&
    payload.sid.trim() !== "" &&
    typeof payload.aal === "number" &&
    Number.isInteger(payload.aal) &&
    payload.aal >= 1 &&
    payload.aal <= 3 &&
    typeof payload.iat === "number" &&
    Number.isSafeInteger(payload.iat) &&
    typeof payload.exp === "number" &&
    Number.isSafeInteger(payload.exp) &&
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
    this.issuer = validString(options.issuer, "token issuer");
    if (
      (typeof options.audience !== "string" && !Array.isArray(options.audience)) ||
      (typeof options.audience === "string" && options.audience.trim() === "") ||
      (Array.isArray(options.audience) && options.audience.length === 0) ||
      (Array.isArray(options.audience) &&
        options.audience.some((value) => typeof value !== "string" || value.trim() === ""))
    ) {
      throw new AuthConfigurationError("token audience must be non-empty");
    }
    this.audience = Array.isArray(options.audience)
      ? [...options.audience]
      : options.audience;
    if (
      options.keyProvider === null ||
      typeof options.keyProvider !== "object" ||
      typeof options.keyProvider.getActiveKeyId !== "function" ||
      typeof options.keyProvider.getSigningKey !== "function" ||
      typeof options.keyProvider.getVerificationKeys !== "function"
    ) {
      throw new AuthConfigurationError("token key provider is incomplete");
    }
    this.keyProvider = options.keyProvider;

    const hashKey =
      typeof options.tokenHashKey === "string"
        ? new TextEncoder().encode(options.tokenHashKey)
        : Uint8Array.from(options.tokenHashKey);
    if (hashKey.byteLength === 0) {
      throw new AuthConfigurationError("token hash key must be non-empty");
    }
    this.tokenHashKey = hashKey;

    const accessTokenTtlSeconds = options.accessTokenTtlSeconds ?? DEFAULT_ACCESS_TOKEN_TTL_SECONDS;
    if (
      !Number.isSafeInteger(accessTokenTtlSeconds) ||
      accessTokenTtlSeconds < 300 ||
      accessTokenTtlSeconds > 3_600
    ) {
      throw new AuthConfigurationError("access token TTL must be between 300 and 3600 seconds");
    }
    this.accessTokenTtlSeconds = accessTokenTtlSeconds;
    this.clock = options.clock ?? (() => new Date());
    validClock(this.clock);
  }

  /** Issues an ES256 JWT with a protected key id and the required claims. */
  async issueAccessToken(user: User, session: SessionRecord): Promise<string> {
    if (user.deleted_at !== null || session.revoked_at !== null) {
      throw new AuthConfigurationError("cannot issue an access token for an inactive subject");
    }
    const userId = validString(user.id, "access-token subject");
    const sessionId = validString(session.id, "access-token session id");
    if (!Number.isInteger(session.aal) || session.aal < 1 || session.aal > 3) {
      throw new AuthConfigurationError("access-token AAL must be an integer from 1 to 3");
    }

    const keyId = validString(await this.keyProvider.getActiveKeyId(), "active signing key id");
    const material = await this.keyProvider.getSigningKey(keyId);
    const signingKey = await importEs256Key(material, keyId, "signing");
    const issuedAt = Math.floor(validClock(this.clock).getTime() / 1000);
    const expiresAt = issuedAt + this.accessTokenTtlSeconds;

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
      if (typeof jwt !== "string" || jwt.trim() === "") return invalidToken();
      const protectedHeader = decodeProtectedHeader(jwt);
      if (
        protectedHeader.alg !== ES256_ALGORITHM ||
        typeof protectedHeader.kid !== "string" ||
        protectedHeader.kid.trim() === ""
      ) {
        return invalidToken();
      }

      const verificationKeys = await this.keyProvider.getVerificationKeys();
      const material = verificationKeys.get(protectedHeader.kid);
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
    return Uint8Array.from(
      createHmac("sha256", this.tokenHashKey).update(token, "utf8").digest(),
    );
  }

  /** Returns the public verification keys for `/.well-known/jwks.json`. */
  async jwks(): Promise<{ readonly keys: readonly PublicEs256Jwk[] }> {
    const jwks = await buildPublicJwks(this.keyProvider);
    return { keys: jwks.keys as readonly PublicEs256Jwk[] };
  }
}
