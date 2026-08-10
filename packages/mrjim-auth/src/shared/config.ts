import { z } from "zod";
import type {
  AuthRepository,
  KeyMaterial,
  Mailer,
  RateLimiter,
} from "./contracts.js";
import type {
  DebugLogger,
  LockFunction,
  SupportedStorage,
} from "./types.js";

/** Runtime mode used to decide whether cleartext local URLs are acceptable. */
export type AuthEnvironment = "development" | "test" | "production";

const nonEmptyStringSchema = z.string().trim().min(1);
const absoluteUrlSchema = z.string().trim().url();

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

/** The inferred, browser-safe client options type. */
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

const repositorySchema = z.custom<AuthRepository>(
  (value) => typeof value === "object" && value !== null,
  "database must be a project-owned auth repository",
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
  issuer: absoluteUrlSchema,
  scopes: z.array(nonEmptyStringSchema).min(1).optional(),
});

const authorizationSchema = z.object({
  defaultRoleKeys: z.array(nonEmptyStringSchema).optional(),
  allowWildcards: z.boolean().optional(),
  protectedRoleKeys: z.array(nonEmptyStringSchema).optional(),
});

const redirectSchema = absoluteUrlSchema.superRefine((value, context) => {
  if (value.includes("*")) {
    context.addIssue({ code: "custom", message: "redirects must be exact URLs" });
  }

  try {
    if (new URL(value).hash !== "") {
      context.addIssue({ code: "custom", message: "redirects may not include fragments" });
    }
  } catch {
    // The URL validator above reports malformed URLs.
  }
});

/**
 * Validates the server composition/configuration contract.
 *
 * Production requires HTTPS for the public base URL, site URL, and every
 * redirect. The schema also requires a non-empty active signing-key set,
 * token-hash key, encryption key, issuer, and audience. Parsing failures are
 * configuration failures and should be allowed to throw synchronously.
 */
export const authServerOptionsSchema = z
  .object({
    environment: z.enum(["development", "test", "production"]).default("production"),
    baseUrl: absoluteUrlSchema,
    siteUrl: absoluteUrlSchema,
    database: repositorySchema,
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
      if (new URL(value).protocol !== "https:") {
        context.addIssue({
          code: "custom",
          path,
          message: "production URLs must use HTTPS",
        });
      }
    }
  });

/** The inferred server configuration type consumed by later tasks. */
export type AuthServerOptions = z.infer<typeof authServerOptionsSchema>;

/** Alias retained for callers that prefer the shorter server-config name. */
export const serverOptionsSchema = authServerOptionsSchema;

/** Alias for code that calls client options a client configuration. */
export const clientConfigSchema = clientOptionsSchema;

/** Alias for code that calls server options a server configuration. */
export const serverConfigSchema = authServerOptionsSchema;
