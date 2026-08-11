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

/**
 * Runtime mode used to decide whether cleartext local URLs are acceptable.
 *
 * @compatibility Project-specific configuration extension.
 */
export type AuthEnvironment = "development" | "test" | "production";

const nonEmptyStringSchema = z.string().trim().min(1);

function parseUrlSafely(value: string): URL | null {
  try {
    return new URL(value);
  } catch {
    return null;
  }
}

const httpHttpsUrlSchema = z.string().trim().url().superRefine((value, context) => {
  const parsed = parseUrlSafely(value);
  if (parsed === null) {
    return;
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    context.addIssue({
      code: "custom",
      message: "URL scheme must be http or https",
    });
  }
});

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
      return value.trim().length > 0;
    }
    if (value instanceof Uint8Array) {
      return value.byteLength > 0;
    }
    return (
      typeof value === "object" &&
      value !== null &&
      Object.keys(value).length > 0
    );
  },
  "key material must be non-empty",
);

const opaqueSecretSchema = z.custom<string | Uint8Array>(
  (value) =>
    (typeof value === "string" && value.trim().length > 0) ||
    (value instanceof Uint8Array && value.byteLength > 0),
  "opaque secret material must be non-empty",
);

function decodedBase64urlLength(value: string): number | null {
  if (value !== value.trim()) return null;
  const encoded = value;
  if (encoded === "" || !/^[A-Za-z0-9_-]+$/.test(encoded) || encoded.length % 4 === 1) return null;
  try {
    const standard = encoded.replace(/-/g, "+").replace(/_/g, "/");
    const decoded = atob(standard.padEnd(Math.ceil(standard.length / 4) * 4, "="));
    const canonical = btoa(decoded).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
    return canonical === encoded ? decoded.length : null;
  } catch {
    return null;
  }
}

/** Unpadded base64url strings decode to at least 32 random bytes; byte arrays are measured directly. */
const secretKeyMaterialSchema = z.custom<string | Uint8Array>(
  (value) => value instanceof Uint8Array
    ? value.byteLength >= 32
    : typeof value === "string" && (decodedBase64urlLength(value) ?? 0) >= 32,
  "secret key material must contain at least 32 decoded bytes (unpadded base64url or Uint8Array)",
);

const keyMapSchema = z
  .record(nonEmptyStringSchema, keyMaterialSchema)
  .superRefine((keys, context) => {
    if (Object.keys(keys).length === 0) {
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
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

type DataPropertySnapshot =
  | { readonly valid: true; readonly present: false }
  | { readonly valid: true; readonly present: true; readonly value: unknown }
  | { readonly valid: false; readonly present: boolean };

function dataPropertySnapshot(value: object, key: PropertyKey): DataPropertySnapshot {
  let current: object | null = value;
  const seen = new Set<object>();
  for (let depth = 0; current !== null && depth < 32; depth += 1) {
    if (seen.has(current)) return { valid: false, present: true };
    seen.add(current);
    let descriptor: PropertyDescriptor | undefined;
    try {
      descriptor = Object.getOwnPropertyDescriptor(current, key);
    } catch {
      return { valid: false, present: false };
    }
    if (descriptor !== undefined) {
      if (!("value" in descriptor)) return { valid: false, present: true };
      return { valid: true, present: true, value: descriptor.value };
    }
    try {
      current = Object.getPrototypeOf(current);
    } catch {
      return { valid: false, present: false };
    }
  }
  return current === null ? { valid: true, present: false } : { valid: false, present: true };
}

function hasMethods(value: unknown, methods: readonly string[]): boolean {
  return isObjectRecord(value) && methods.every((method) => {
    const property = dataPropertySnapshot(value, method);
    return property.valid && property.present && typeof property.value === "function";
  });
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

  return (Object.entries(requiredRepositoryMethods) as readonly [string, readonly string[]][])
    .filter(([member]) => member !== "root")
    .every(([member, methods]) => {
      const property = dataPropertySnapshot(value, member);
      return property.valid && property.present && hasMethods(property.value, methods);
    });
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
  if (value.includes("*")) {
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
      ...options.redirects.allowed.map((value, index) => ({
        path: ["redirects", "allowed", index],
        value,
      })),
    ];

    for (const { path, value } of productionUrls) {
      const parsed = parseUrlSafely(value);
      if (parsed !== null && parsed.protocol !== "https:") {
        context.addIssue({
          code: "custom",
          path,
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
