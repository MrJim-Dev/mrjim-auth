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
import {
  boundaryIsArray,
  boundaryIsUint8Array,
  captureBoundaryKeyMaterial,
  captureBoundaryMapEntries,
  captureBoundaryMethodGroup,
  defineBoundaryArrayValue,
  invokeBoundaryResult,
  sortBoundaryArray,
} from "./callback-boundary.js";
import { safeStringTrim } from "../shared/safe-intrinsics.js";

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

const jwksTextDecoder = TextDecoder;
const jwksJsonParse = JSON.parse;
const jwksStringIncludes = String.prototype.includes;
const jwksStringTrim = String.prototype.trim;
const jwksStringStartsWith = String.prototype.startsWith;
const jwksReflectApply = Reflect.apply;

function materialText(material: string | Uint8Array): string {
  return typeof material === "string"
    ? material
    : new jwksTextDecoder().decode(material);
}

function materialJwk(material: KeyMaterial): JWK | null {
  const snapshot = captureBoundaryKeyMaterial(material, "ES256 key material");
  if (typeof snapshot === "object" && snapshot !== null && !boundaryIsUint8Array(snapshot, "ES256 key material")) {
    return snapshot as JWK;
  }

  if (typeof snapshot !== "string" && !boundaryIsUint8Array(snapshot, "ES256 key material")) {
    return null;
  }

  const text = jwksReflectApply(jwksStringTrim, materialText(snapshot as string | Uint8Array), []) as string;
  if (!jwksReflectApply(jwksStringStartsWith, text, ["{"])) return null;
  try {
    const parsed: unknown = jwksReflectApply(jwksJsonParse, undefined, [text]);
    if (typeof parsed !== "object" || parsed === null || boundaryIsArray(parsed, "ES256 JWK")) return null;
    return captureBoundaryKeyMaterial(parsed, "ES256 JWK") as JWK;
  } catch {
    return null;
  }
}

function assertEs256Jwk(jwk: JWK, _keyId: string): asserts jwk is ValidEs256Jwk {
  if (
    jwk.kty !== "EC" ||
    jwk.crv !== "P-256" ||
    typeof jwk.x !== "string" ||
    typeof jwk.y !== "string" ||
    (jwk.alg !== undefined && jwk.alg !== ES256_ALGORITHM) ||
    (jwk.use !== undefined && jwk.use !== "sig")
  ) {
    throw new AuthConfigurationError("ES256 key material is invalid");
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

async function exportJwk(key: Es256Key, _keyId: string): Promise<JWK> {
  try {
    return await exportJWK(key);
  } catch {
    throw new AuthConfigurationError("ES256 public key export failed");
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
  if (typeof keyId !== "string" || safeStringTrim(keyId) === null || safeStringTrim(keyId) === "") {
    throw new AuthConfigurationError("ES256 key identifier is invalid");
  }

  const safeMaterial = captureBoundaryKeyMaterial(material, "ES256 key material");
  const jwk = materialJwk(safeMaterial);
  if (jwk !== null) {
    assertEs256Jwk(jwk, keyId);
    if (purpose === "signing" && typeof jwk.d !== "string") {
      throw new AuthConfigurationError("ES256 signing key material is invalid");
    }
    try {
      return await importJWK(
        purpose === "verification" ? publicJwkMaterial(jwk, keyId) : jwk,
        ES256_ALGORITHM,
      );
    } catch {
      throw new AuthConfigurationError("ES256 JWK import failed");
    }
  }

  if (typeof safeMaterial !== "string" && !boundaryIsUint8Array(safeMaterial, "ES256 key material")) {
    throw new AuthConfigurationError("ES256 key material is invalid");
  }

  const pem = jwksReflectApply(jwksStringTrim, materialText(safeMaterial as string | Uint8Array), []) as string;
  try {
    if (jwksReflectApply(jwksStringIncludes, pem, ["PRIVATE KEY"])) {
      return await importPKCS8(pem, ES256_ALGORITHM, {
        extractable: purpose === "jwks",
      });
    }
    if (jwksReflectApply(jwksStringIncludes, pem, ["PUBLIC KEY"])) {
      return await importSPKI(pem, ES256_ALGORITHM, { extractable: true });
    }
  } catch {
    throw new AuthConfigurationError("ES256 PEM import failed");
  }

  throw new AuthConfigurationError("ES256 key material is invalid");
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

  jwk = captureBoundaryKeyMaterial(jwk, "exported ES256 key material") as JWK;
  assertEs256Jwk(jwk, keyId);
  return {
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
  const capturedProvider = captureBoundaryMethodGroup(
    provider,
    "verification key provider",
    ["getVerificationKeys"],
  ) as unknown as KeyProvider;
  const verificationKeys = await invokeBoundaryResult<ReadonlyMap<string, KeyMaterial>>(
    capturedProvider.getVerificationKeys,
    capturedProvider,
    [],
    "verification key provider",
  );
  const rawEntries = captureBoundaryMapEntries(verificationKeys, "verification key provider", 100_000);
  const entries: Array<readonly [string, KeyMaterial]> = [];
  for (let index = 0; index < rawEntries.length; index += 1) {
    const entry = rawEntries[index];
    if (entry === undefined || typeof entry[0] !== "string" || safeStringTrim(entry[0]) === null || safeStringTrim(entry[0]) === "") {
      throw new AuthConfigurationError("verification key identifiers are invalid");
    }
    defineBoundaryArrayValue(entries, index, [entry[0], captureBoundaryKeyMaterial(entry[1], "verification key material")], "verification key entries");
  }
  sortBoundaryArray(entries, (left, right) => left[0] < right[0] ? -1 : left[0] > right[0] ? 1 : 0, "verification key entries");
  if (entries.length === 0) {
    throw new AuthConfigurationError("at least one ES256 verification key is required");
  }

  const keys: PublicEs256Jwk[] = [];
  for (let index = 0; index < entries.length; index += 1) {
    const entry = entries[index];
    if (entry === undefined) throw new AuthConfigurationError("verification key entries are malformed");
    defineBoundaryArrayValue(keys, index, await publicEs256Jwk(entry[1], entry[0]), "public JWKS keys");
  }
  return { keys };
}
