import {
  exportJWK,
  importJWK,
  importPKCS8,
  importSPKI,
  type CryptoKey,
  type JWK,
  type JSONWebKeySet,
} from "jose";
import { AuthConfigurationError } from "../shared/errors.js";
import type { KeyMaterial, KeyProvider } from "../shared/contracts.js";

/** The only signing algorithm accepted by the Task 5 token boundary. */
export const ES256_ALGORITHM = "ES256" as const;

/** The normalized key type consumed by jose for ES256 operations. */
export type Es256Key = CryptoKey | Uint8Array;

/** A public ES256 JWK exposed by the project's JWKS endpoint. */
export type PublicEs256Jwk = JWK & {
  readonly kid: string;
  readonly alg: typeof ES256_ALGORITHM;
  readonly use: "sig";
  readonly kty: "EC";
  readonly crv: "P-256";
  readonly x: string;
  readonly y: string;
};

type ValidEs256Jwk = JWK & {
  readonly kty: "EC";
  readonly crv: "P-256";
  readonly x: string;
  readonly y: string;
};

function materialText(material: string | Uint8Array): string {
  return typeof material === "string"
    ? material
    : new TextDecoder().decode(material);
}

function materialJwk(material: KeyMaterial): JWK | null {
  if (typeof material === "object" && !(material instanceof Uint8Array)) {
    return { ...material } as JWK;
  }

  if (typeof material !== "string" && !(material instanceof Uint8Array)) {
    return null;
  }

  const text = materialText(material).trim();
  if (!text.startsWith("{")) return null;
  try {
    const parsed: unknown = JSON.parse(text);
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return null;
    return parsed as JWK;
  } catch {
    return null;
  }
}

function assertEs256Jwk(jwk: JWK, keyId: string): asserts jwk is ValidEs256Jwk {
  if (
    jwk.kty !== "EC" ||
    jwk.crv !== "P-256" ||
    typeof jwk.x !== "string" ||
    typeof jwk.y !== "string" ||
    (jwk.alg !== undefined && jwk.alg !== ES256_ALGORITHM) ||
    (jwk.use !== undefined && jwk.use !== "sig")
  ) {
    throw new AuthConfigurationError(
      `key '${keyId}' must be an EC P-256 key for ES256`,
    );
  }
}

function publicJwkMaterial(jwk: JWK, keyId: string): ValidEs256Jwk {
  assertEs256Jwk(jwk, keyId);
  return {
    kty: "EC",
    crv: "P-256",
    x: jwk.x,
    y: jwk.y,
    alg: ES256_ALGORITHM,
    use: "sig",
  };
}

async function exportJwk(key: Es256Key, keyId: string): Promise<JWK> {
  try {
    return await exportJWK(key);
  } catch (error) {
    throw new AuthConfigurationError(`key '${keyId}' cannot be exported as a public JWK`, {
      cause: error,
    });
  }
}

/**
 * Imports project-owned PEM/JWK material as an ES256 key.
 *
 * Raw symmetric material, RSA keys, other curves, and ambiguous strings are
 * rejected instead of being interpreted as a different JWT algorithm.
 */
export async function importEs256Key(
  material: KeyMaterial,
  keyId: string,
  purpose: "signing" | "verification" | "jwks",
): Promise<Es256Key> {
  if (typeof keyId !== "string" || keyId.trim() === "") {
    throw new AuthConfigurationError("ES256 key identifiers must be non-empty");
  }

  const jwk = materialJwk(material);
  if (jwk !== null) {
    assertEs256Jwk(jwk, keyId);
    if (purpose === "signing" && typeof jwk.d !== "string") {
      throw new AuthConfigurationError(`signing key '${keyId}' must contain private material`);
    }
    try {
      return await importJWK(jwk, ES256_ALGORITHM);
    } catch (error) {
      throw new AuthConfigurationError(`key '${keyId}' is not a valid ES256 JWK`, {
        cause: error,
      });
    }
  }

  if (typeof material !== "string" && !(material instanceof Uint8Array)) {
    throw new AuthConfigurationError(`key '${keyId}' uses unsupported key material`);
  }

  const pem = materialText(material).trim();
  try {
    if (pem.includes("PRIVATE KEY")) {
      return await importPKCS8(pem, ES256_ALGORITHM, {
        extractable: purpose === "jwks",
      });
    }
    if (pem.includes("PUBLIC KEY")) {
      return await importSPKI(pem, ES256_ALGORITHM, { extractable: true });
    }
  } catch (error) {
    throw new AuthConfigurationError(`key '${keyId}' is not a valid ES256 PEM key`, {
      cause: error,
    });
  }

  throw new AuthConfigurationError(
    `key '${keyId}' must be an ES256 PKCS#8/SPKI PEM or JWK object`,
  );
}

/** Converts one configured verification key to a public, non-sensitive JWK. */
export async function publicEs256Jwk(
  material: KeyMaterial,
  keyId: string,
): Promise<PublicEs256Jwk> {
  const configuredJwk = materialJwk(material);
  let jwk: JWK;
  if (configuredJwk !== null) {
    // A private JWK may be supplied as the verification source. Derive a
    // public JWK before importing/exporting so non-extractable private keys
    // never reach the JWKS exporter.
    const key = await importEs256Key(
      publicJwkMaterial(configuredJwk, keyId),
      keyId,
      "jwks",
    );
    jwk = await exportJwk(key, keyId);
  } else {
    const key = await importEs256Key(material, keyId, "jwks");
    jwk = await exportJwk(key, keyId);
  }

  assertEs256Jwk(jwk, keyId);
  const publicJwk: Record<string, unknown> = { ...jwk };
  for (const privateParameter of ["d", "p", "q", "dp", "dq", "qi", "key_ops", "ext"]) {
    delete publicJwk[privateParameter];
  }
  return {
    ...publicJwk,
    kid: keyId,
    alg: ES256_ALGORITHM,
    use: "sig",
    kty: "EC",
    crv: "P-256",
    x: jwk.x,
    y: jwk.y,
  } as PublicEs256Jwk;
}

/** Builds the public JWKS from every currently published verification key. */
export async function buildPublicJwks(provider: KeyProvider): Promise<JSONWebKeySet> {
  const verificationKeys = await provider.getVerificationKeys();
  if (
    verificationKeys === null ||
    typeof verificationKeys !== "object" ||
    typeof verificationKeys.get !== "function" ||
    typeof verificationKeys.entries !== "function"
  ) {
    throw new AuthConfigurationError("verification key provider must return a key map");
  }

  const entries = [...verificationKeys.entries()];
  if (entries.some(([keyId]) => typeof keyId !== "string" || keyId.trim() === "")) {
    throw new AuthConfigurationError("verification key identifiers must be non-empty strings");
  }
  entries.sort(([left], [right]) => left.localeCompare(right));
  if (entries.length === 0) {
    throw new AuthConfigurationError("at least one ES256 verification key is required");
  }

  const keys = await Promise.all(
    entries.map(([keyId, material]) => publicEs256Jwk(material, keyId)),
  );
  return { keys };
}
