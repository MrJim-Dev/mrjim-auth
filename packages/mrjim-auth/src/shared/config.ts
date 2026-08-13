import { z } from "zod";
import type {
  AuthRepository,
  KeyMaterial,
  Mailer,
  RateLimiter,
} from "./contracts.js";
import { roleKeySchema } from "./types.js";
import type {
  DebugLogger,
  LockFunction,
  SupportedStorage,
} from "./types.js";
import {
  safeStringIncludes,
  safeStringPadEnd,
  safeStringReplace,
  safeStringTrim,
} from "./safe-intrinsics.js";

// Configuration validation is also a construction boundary. Capture the
// intrinsics used by its predicates before caller-controlled values can be
// inspected so polluted collection prototypes cannot change validation or
// leak their failures.
const configArrayIsArray = Array.isArray;
const configObjectKeys = Object.keys;
const configObjectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const configObjectGetPrototypeOf = Object.getPrototypeOf;
const configSetConstructor = Set;
const configSetHas = Set.prototype.has;
const configSetAdd = Set.prototype.add;
const configReflectApply = Reflect.apply;
const configUint8Array = Uint8Array;

function configByteLength(value: unknown): number | null {
  try {
    if (!(value instanceof configUint8Array)) return null;
    return typeof value.byteLength === "number" ? value.byteLength : null;
  } catch {
    return null;
  }
}

/**
 * Runtime mode used to decide whether cleartext local URLs are acceptable.
 *
 * @compatibility Project-specific configuration extension.
 */
export type AuthEnvironment = "development" | "test" | "production";

const safeTrimmedStringSchema = z.string().transform((value) => safeStringTrim(value) ?? "");
const nonEmptyStringSchema = safeTrimmedStringSchema.pipe(z.string().min(1));

function parseUrlSafely(value: string): URL | null {
  try {
    return new URL(value);
  } catch {
    return null;
  }
}

const httpHttpsUrlSchema = z
  .custom<string>((value) => {
    if (typeof value !== "string") return false;
    const trimmed = safeStringTrim(value);
    if (trimmed === null || trimmed === "") return false;
    const parsed = parseUrlSafely(trimmed);
    return parsed !== null && (parsed.protocol === "http:" || parsed.protocol === "https:");
  }, "Invalid URL")
  .transform((value) => safeStringTrim(value) ?? "");

/**
 * Validates the client base URL in every runtime environment.
 *
 * @compatibility Supabase-inspired client initialization URL boundary.
 */
export const clientBaseUrlSchema = httpHttpsUrlSchema;

const storageSchema = z.custom<SupportedStorage>(
  (value) => {
    if (typeof value !== "object" || value === null) {
      return false;
    }
    const candidate = value as Record<string, unknown>;
    return (
      typeof candidate.getItem === "function" &&
      typeof candidate.setItem === "function" &&
      typeof candidate.removeItem === "function"
    );
  },
  "storage must implement getItem, setItem, and removeItem",
);

const lockSchema = z.custom<LockFunction>(
  (value) => typeof value === "function",
  "lock must be a function",
);

const debugSchema = z.union([
  z.boolean(),
  z.custom<DebugLogger>((value) => typeof value === "function", "debug must be a boolean or function"),
]);

const fetchSchema = z.custom<typeof fetch>(
  (value) => typeof value === "function",
  "fetch must be a function",
);

/**
 * Validates browser/SSR client options.
 *
 * Only PKCE is supported in v1. The schema contains no server credentials or
 * Node-only dependencies and can be used from a browser-reachable module.
 *
 * @compatibility Supabase-inspired client options with PKCE-only behavior.
 *
 * @example
 * ```ts
 * const options = clientOptionsSchema.parse({
 *   auth: { flowType: "pkce", persistSession: true },
 * });
 * ```
 */
export const clientOptionsSchema = z.object({
  auth: z
    .object({
      autoRefreshToken: z.boolean().optional(),
      persistSession: z.boolean().optional(),
      detectSessionInUrl: z.boolean().optional(),
      flowType: z.literal("pkce").optional(),
      storage: storageSchema.optional(),
      storageKey: nonEmptyStringSchema.optional(),
      lock: lockSchema.optional(),
      debug: debugSchema.optional(),
      skipAutoInitialize: z.boolean().optional(),
    })
    .optional(),
  global: z
    .object({
      fetch: fetchSchema.optional(),
      headers: z.record(z.string(), z.string()).optional(),
    })
    .optional(),
  storage: z
    .object({
      url: z.string().url().optional(),
    })
    .optional(),
});

/**
 * The inferred, browser-safe client options type.
 *
 * @compatibility Supabase-inspired options; only documented v1 fields are
 * accepted.
 */
export type ClientOptions = z.infer<typeof clientOptionsSchema>;

const keyMaterialSchema = z.custom<KeyMaterial>(
  (value) => {
    if (typeof value === "string") {
      return (safeStringTrim(value) ?? "").length > 0;
    }
    const byteLength = configByteLength(value);
    if (byteLength !== null) return byteLength > 0;
    if (typeof value !== "object" || value === null) return false;
    try {
      return configObjectKeys(value).length > 0;
    } catch {
      return false;
    }
  },
  "key material must be non-empty",
);

const opaqueSecretSchema = z.custom<string | Uint8Array>(
  (value) => {
    const byteLength = configByteLength(value);
    return (typeof value === "string" && (safeStringTrim(value) ?? "").length > 0) || (byteLength !== null && byteLength > 0);
  },
  "opaque secret material must be non-empty",
);

function decodedBase64urlLength(value: string): number | null {
  const trimmed = safeStringTrim(value);
  if (trimmed === null || value !== trimmed) return null;
  const encoded = value;
  if (encoded === "" || !/^[A-Za-z0-9_-]+$/.test(encoded) || encoded.length % 4 === 1) return null;
  try {
    const first = safeStringReplace(encoded, /-/g, "+");
    const standard = first === null ? null : safeStringReplace(first, /_/g, "/");
    if (standard === null) return null;
    const padded = safeStringPadEnd(standard, Math.ceil(standard.length / 4) * 4, "=");
    if (padded === null) return null;
    const decoded = atob(padded);
    const encodedCanonical = btoa(decoded);
    const firstCanonical = safeStringReplace(encodedCanonical, /\+/g, "-");
    const secondCanonical = firstCanonical === null ? null : safeStringReplace(firstCanonical, /\//g, "_");
    const canonical = secondCanonical === null ? null : safeStringReplace(secondCanonical, /=/g, "");
    if (canonical === null) return null;
    return canonical === encoded ? decoded.length : null;
  } catch {
    return null;
  }
}

/** Unpadded base64url strings decode to at least 32 random bytes; byte arrays are measured directly. */
const secretKeyMaterialSchema = z.custom<string | Uint8Array>(
  (value) => {
    const byteLength = configByteLength(value);
    return byteLength !== null
      ? byteLength >= 32
      : typeof value === "string" && (decodedBase64urlLength(value) ?? 0) >= 32;
  },
  "secret key material must contain at least 32 decoded bytes (unpadded base64url or Uint8Array)",
);

const keyMapSchema = z
  .record(nonEmptyStringSchema, keyMaterialSchema)
  .superRefine((keys, context) => {
    if (configObjectKeys(keys).length === 0) {
      context.addIssue({
        code: "custom",
        message: "at least one signing key is required",
      });
    }
  });

const requiredRepositoryMethods = {
  root: ["transaction"],
  users: ["findById", "findByIdForUpdate", "findByNormalizedEmail", "findByNormalizedEmailForUpdate", "create", "createIfAvailable", "update", "softDelete"],
  identities: ["findByProviderSubject", "listByUserId", "create", "createIfAvailable", "deleteById"],
  passwordCredentials: ["findByUserId", "upsert", "deleteByUserId"],
  sessions: [
    "create",
    "findByIdForUpdate",
    "findRefreshForUpdate",
    "rotate",
    "revokeSession",
    "revokeFamily",
    "revokeUserSessions",
  ],
  oneTimeTokens: ["issue", "consume", "consumeBound", "recordFailure"],
  oauthStates: ["create", "consume"],
  authorization: [
    "effectivePermissions",
    "assignRole",
    "unassignRole",
    "setRolePermissions",
    "setRoleInheritance",
  ],
  roles: ["list", "findById", "create", "update", "delete"],
  permissions: ["list", "findById", "create", "update", "delete"],
  operations: ["appendAudit", "findApiKeyByHash"],
} as const;

function isObjectRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null) return false;
  try {
    return !configArrayIsArray(value);
  } catch {
    return false;
  }
}

type DataPropertySnapshot =
  | { readonly valid: true; readonly present: false }
  | { readonly valid: true; readonly present: true; readonly value: unknown }
  | { readonly valid: false; readonly present: boolean };

function dataPropertySnapshot(value: object, key: PropertyKey): DataPropertySnapshot {
  let current: object | null = value;
  const seen = new configSetConstructor<object>();
  for (let depth = 0; current !== null && depth < 32; depth += 1) {
    try {
      if (configReflectApply(configSetHas, seen, [current])) return { valid: false, present: true };
      configReflectApply(configSetAdd, seen, [current]);
    } catch {
      return { valid: false, present: true };
    }
    let descriptor: PropertyDescriptor | undefined;
    try {
      descriptor = configObjectGetOwnPropertyDescriptor(current, key);
    } catch {
      return { valid: false, present: false };
    }
    if (descriptor !== undefined) {
      if (!("value" in descriptor)) return { valid: false, present: true };
      return { valid: true, present: true, value: descriptor.value };
    }
    try {
      current = configObjectGetPrototypeOf(current);
    } catch {
      return { valid: false, present: false };
    }
  }
  return current === null ? { valid: true, present: false } : { valid: false, present: true };
}

function hasMethods(value: unknown, methods: readonly string[]): boolean {
  if (!isObjectRecord(value)) return false;
  for (let index = 0; index < methods.length; index += 1) {
    const method = methods[index];
    if (method === undefined) return false;
    const property = dataPropertySnapshot(value, method);
    if (!property.valid || !property.present || typeof property.value !== "function") return false;
  }
  return true;
}

/**
 * Returns whether an adapter implements every Task 2 repository boundary.
 *
 * @internal This is a pre-export validation boundary for later server and
 * PostgreSQL tasks.
 */
export function isAuthRepository(value: unknown): value is AuthRepository {
  if (!isObjectRecord(value) || !hasMethods(value, requiredRepositoryMethods.root)) {
    return false;
  }

  const members = configObjectKeys(requiredRepositoryMethods) as Array<keyof typeof requiredRepositoryMethods>;
  for (let index = 0; index < members.length; index += 1) {
    const member = members[index];
    if (member === undefined || member === "root") continue;
    const property = dataPropertySnapshot(value, member);
    if (!property.valid || !property.present || !hasMethods(property.value, requiredRepositoryMethods[member])) {
      return false;
    }
  }
  return true;
}

/**
 * Runtime validation for the complete transaction-neutral repository
 * aggregate. It rejects `{}` and malformed member methods before server start.
 *
 * @internal The schema is not exported from the package root until a later
 * server/PostgreSQL export task.
 */
export const authRepositorySchema = z.custom<AuthRepository>(
  isAuthRepository,
  "database must implement every required auth repository boundary",
);

const mailerSchema = z.custom<Mailer>(
  (value) => hasMethods(value, ["send"]),
  "email must implement send",
);

const rateLimiterSchema = z.custom<RateLimiter>(
  (value) => hasMethods(value, ["consume"]),
  "rateLimiter must implement consume",
);

const oauthClientSchema = z.object({
  clientId: nonEmptyStringSchema,
  clientSecret: opaqueSecretSchema,
});

const oidcClientSchema = oauthClientSchema.extend({
  issuer: httpHttpsUrlSchema.superRefine((value, context) => {
    const parsed = parseUrlSafely(value);
    if (parsed !== null && parsed.protocol !== "https:") {
      context.addIssue({ code: "custom", message: "OIDC issuer must use HTTPS" });
    }
  }),
  scopes: z.array(nonEmptyStringSchema).min(1).optional(),
});

const authorizationSchema = z.object({
  defaultRoleKeys: z.array(roleKeySchema).optional(),
  allowWildcards: z.boolean().optional(),
  protectedRoleKeys: z.array(roleKeySchema).optional(),
});

const redirectSchema = httpHttpsUrlSchema.superRefine((value, context) => {
  if (safeStringIncludes(value, "*")) {
    context.addIssue({ code: "custom", message: "redirects must be exact URLs" });
  }

  const parsed = parseUrlSafely(value);
  if (parsed?.hash !== undefined && parsed.hash !== "") {
    context.addIssue({ code: "custom", message: "redirects may not include fragments" });
  }
});

/**
 * Validates the server composition/configuration contract.
 *
 * Production requires HTTPS for the public base URL, site URL, and every
 * redirect. The schema also requires a non-empty active signing-key set,
 * token-hash key, encryption key, issuer, and audience. Parsing failures are
 * configuration failures and should be allowed to throw synchronously.
 *
 * @compatibility Project-owned server composition contract shaped by the
 * Supabase-inspired client/server split.
 */
export const authServerOptionsSchema = z
  .object({
    environment: z.enum(["development", "test", "production"]).default("production"),
    baseUrl: httpHttpsUrlSchema,
    siteUrl: httpHttpsUrlSchema,
    database: authRepositorySchema,
    signingKeys: z.object({
      issuer: nonEmptyStringSchema,
      audience: nonEmptyStringSchema,
      activeKeyId: nonEmptyStringSchema,
      keys: keyMapSchema,
    }),
    secrets: z.object({
      tokenHashKey: secretKeyMaterialSchema,
      encryptionKey: secretKeyMaterialSchema,
    }),
    email: mailerSchema,
    rateLimiter: rateLimiterSchema.optional(),
    oauth: z
      .object({
        google: oauthClientSchema.optional(),
        oidc: oidcClientSchema.optional(),
      })
      .optional(),
    redirects: z.object({
      allowed: z.array(redirectSchema).min(1),
    }),
    authorization: authorizationSchema.optional(),
    accessTokenTtlSeconds: z.number().int().min(300).max(3_600).default(900),
    refreshTokenTtlSeconds: z
      .number()
      .int()
      .min(3_600)
      .max(90 * 24 * 60 * 60)
      .default(30 * 24 * 60 * 60),
  })
  .superRefine((options, context) => {
    if (options.signingKeys.keys[options.signingKeys.activeKeyId] === undefined) {
      context.addIssue({
        code: "custom",
        path: ["signingKeys", "activeKeyId"],
        message: "activeKeyId must identify configured signing key material",
      });
    }

    if (options.environment !== "production") {
      return;
    }

    const productionUrls: Array<{ path: PropertyKey[]; value: string }> = [
      { path: ["baseUrl"], value: options.baseUrl },
      { path: ["siteUrl"], value: options.siteUrl },
    ];
    for (let index = 0; index < options.redirects.allowed.length; index += 1) {
      const value = options.redirects.allowed[index];
      if (value !== undefined) {
        productionUrls[productionUrls.length] = {
          path: ["redirects", "allowed", index],
          value,
        };
      }
    }

    for (let index = 0; index < productionUrls.length; index += 1) {
      const entry = productionUrls[index];
      if (entry === undefined) continue;
      const parsed = parseUrlSafely(entry.value);
      if (parsed !== null && parsed.protocol !== "https:") {
        context.addIssue({
          code: "custom",
          path: entry.path,
          message: "production URLs must use HTTPS",
        });
      }
    }
  });

/**
 * The inferred server configuration type consumed by later tasks.
 *
 * @compatibility Project-specific server contract; database, mail, key,
 * redirect, and authorization adapters remain project-owned.
 */
export type AuthServerOptions = z.infer<typeof authServerOptionsSchema>;

/** Alias retained for callers that prefer the shorter server-config name. */
export const serverOptionsSchema = authServerOptionsSchema;

/** Alias for code that calls client options a client configuration. */
export const clientConfigSchema = clientOptionsSchema;

/** Alias for code that calls server options a server configuration. */
export const serverConfigSchema = authServerOptionsSchema;
