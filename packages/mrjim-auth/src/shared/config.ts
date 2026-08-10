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

const secretMaterialSchema = z.custom<string | Uint8Array>(
  (value) =>
    (typeof value === "string" && value.trim().length > 0) ||
    (value instanceof Uint8Array && value.byteLength > 0),
  "secret key material must be non-empty",
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
  users: ["findById", "findByNormalizedEmail", "create", "update", "softDelete"],
  identities: ["findByProviderSubject", "listByUserId", "create", "deleteById"],
  passwordCredentials: ["findByUserId", "upsert", "deleteByUserId"],
  sessions: [
    "create",
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

function hasMethods(value: unknown, methods: readonly string[]): boolean {
  return (
    isObjectRecord(value) &&
    methods.every((method) => typeof value[method] === "function")
  );
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
    .every(([member, methods]) => hasMethods(value[member], methods));
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
  (value) =>
    typeof value === "object" &&
    value !== null &&
    typeof (value as { send?: unknown }).send === "function",
  "email must implement send",
);

const rateLimiterSchema = z.custom<RateLimiter>(
  (value) =>
    typeof value === "object" &&
    value !== null &&
    typeof (value as { consume?: unknown }).consume === "function",
  "rateLimiter must implement consume",
);

const oauthClientSchema = z.object({
  clientId: nonEmptyStringSchema,
  clientSecret: secretMaterialSchema,
});

const oidcClientSchema = oauthClientSchema.extend({
  issuer: httpHttpsUrlSchema,
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
      tokenHashKey: secretMaterialSchema,
      encryptionKey: secretMaterialSchema,
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
