import { z } from "zod";

/** A JSON primitive suitable for redacted metadata and safe claims. */
export type JsonPrimitive = string | number | boolean | null;

/** A JSON-compatible value suitable for user or application metadata. */
export type JsonValue =
  | JsonPrimitive
  | readonly JsonValue[]
  | { readonly [key: string]: JsonValue };

/** A JSON object used for application metadata. */
export type JsonObject = { readonly [key: string]: JsonValue };

declare const uuidBrand: unique symbol;

/**
 * A UUID that has passed the shared runtime validator.
 *
 * @compatibility Project-owned canonical identifier; the string wire format is
 * compatible with PostgreSQL UUID values.
 */
export type UUID = string & { readonly [uuidBrand]: "UUID" };

/** Validates and brands a UUID for use by shared contracts. */
export const uuidSchema = z.string().uuid().transform((value) => value as UUID);

declare const lowercaseKeyBrand: unique symbol;

/** A lowercase authorization key that has passed a shared runtime validator. */
export type LowercaseKey = string & {
  readonly [lowercaseKeyBrand]: "LowercaseKey";
};

/** Validates and brands any non-empty lowercase authorization key. */
export const lowercaseKeySchema = z
  .string()
  .min(1)
  .regex(/^[a-z0-9_.*-]+$/, "authorization keys must use lowercase characters")
  .refine((value) => value === value.toLowerCase(), "authorization keys must be lowercase")
  .transform((value) => value as LowercaseKey);

declare const scopeIdentifierBrand: unique symbol;

/** A parsed, project-defined authorization scope identifier. */
export type ScopeIdentifier = string & {
  readonly [scopeIdentifierBrand]: "ScopeIdentifier";
};

/** Validates and brands a non-empty project-defined scope identifier. */
export const scopeIdentifierSchema = z
  .string()
  .trim()
  .min(1, "scope identifiers must not be empty")
  .transform((value) => value as ScopeIdentifier);

/** Validates a simple lowercase role key. */
export const roleKeySchema = z
  .string()
  .min(1)
  .regex(/^[a-z][a-z0-9_-]*$/, "role keys must be lowercase identifiers")
  .transform((value) => value as LowercaseKey);

const permissionResourceSchema = z
  .union([
    z
      .string()
      .min(1)
      .regex(/^[a-z][a-z0-9_-]*$/, "permission resources must be lowercase identifiers"),
    z.literal("*"),
  ])
  .transform((value) => value as LowercaseKey);

const permissionActionSchema = z
  .union([
    z
      .string()
      .min(1)
      .regex(/^[a-z][a-z0-9_-]*$/, "permission actions must be lowercase identifiers"),
    z.literal("*"),
  ])
  .transform((value) => value as LowercaseKey);

/** Validates `resource.action`, `resource.*`, or `*.*` permission keys. */
export const permissionKeySchema = z
  .string()
  .regex(/^[a-z][a-z0-9_-]*\.(?:[a-z][a-z0-9_-]*|\*)$|^\*\.\*$/, "invalid permission key")
  .transform((value) => value as LowercaseKey);

const sensitiveKeySegments = new Set([
  "access",
  "authorization",
  "bearer",
  "client",
  "code",
  "cookie",
  "credential",
  "hash",
  "jwt",
  "key",
  "oauth",
  "otp",
  "passcode",
  "password",
  "pem",
  "pkce",
  "private",
  "refresh",
  "secret",
  "session",
  "sig",
  "signature",
  "state",
  "token",
  "verifier",
]);

const credentialBearingLinkPrefixes = new Set([
  "auth",
  "confirmation",
  "invite",
  "magic",
  "raw",
  "recovery",
  "reset",
  "verification",
  "verify",
]);

function keySegments(key: string): readonly string[] {
  return key
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1_$2")
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .replace(/[^a-zA-Z0-9]+/g, "_")
    .toLowerCase()
    .split("_")
    .filter(Boolean);
}

/** Returns true for credential-bearing key names, including style variants. */
export function isSensitiveKeyName(key: string): boolean {
  const segments = keySegments(key);
  const normalizedKey = key.replace(/[^a-zA-Z0-9]/g, "").toLowerCase();
  const isExplicitSessionIdentifier =
    normalizedKey === "sessionid";
  return (
    !isExplicitSessionIdentifier &&
    (normalizedKey === "session" ||
      segments.some((segment) => sensitiveKeySegments.has(segment)) ||
      (segments.includes("one") && segments.includes("time")) ||
      (segments.includes("raw") && segments.includes("link")) ||
      (segments.includes("link") &&
        segments.some((segment) => credentialBearingLinkPrefixes.has(segment))))
  );
}

function parseUrlSafely(value: string): URL | null {
  try {
    return new URL(value);
  } catch {
    return null;
  }
}

function isRawCredentialString(value: string): boolean {
  return (
    value.includes("-----BEGIN ") ||
    /^Bearer\s+\S+/i.test(value) ||
    /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(value)
  );
}

function hasCredentialBearingUrl(value: string): boolean {
  const parsed = parseUrlSafely(value);
  if (parsed === null) {
    return false;
  }

  const entries = [...parsed.searchParams.entries()];
  const hash = parsed.hash.startsWith("#") ? parsed.hash.slice(1) : parsed.hash;
  if (hash !== "") {
    const hashParams = new URLSearchParams(hash);
    if (hash.includes("=") || hash.includes("&")) {
      entries.push(...hashParams.entries());
    } else {
      entries.push([hash, ""]);
    }
  }

  return entries.some(
    ([key, nestedValue]) => isSensitiveKeyName(key) || isRawCredentialString(nestedValue),
  );
}

function isSensitiveString(value: string): boolean {
  return isRawCredentialString(value) || hasCredentialBearingUrl(value);
}

const nonEmptyIdentityStringSchema = z.string().trim().min(1);
const safeIdentityUrlSchema = z.string().trim().url().superRefine((value, context) => {
  const parsed = parseUrlSafely(value);
  if (parsed === null) {
    return;
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    context.addIssue({
      code: "custom",
      message: "identity URLs must use http or https",
    });
  }
  if (hasCredentialBearingUrl(value)) {
    context.addIssue({
      code: "custom",
      message: "identity URLs must not contain credential-bearing query or fragment data",
    });
  }
});

const publicIdentityDataShape = {
  sub: nonEmptyIdentityStringSchema.optional(),
  email: nonEmptyIdentityStringSchema.optional(),
  email_verified: z.boolean().optional(),
  name: nonEmptyIdentityStringSchema.optional(),
  given_name: nonEmptyIdentityStringSchema.optional(),
  family_name: nonEmptyIdentityStringSchema.optional(),
  picture: safeIdentityUrlSchema.optional(),
  avatar_url: safeIdentityUrlSchema.optional(),
  locale: nonEmptyIdentityStringSchema.optional(),
  hd: nonEmptyIdentityStringSchema.optional(),
  preferred_username: nonEmptyIdentityStringSchema.optional(),
} as const;

const publicIdentityDataObjectSchema = z
  .object(publicIdentityDataShape)
  .strict()
  .superRefine((value, context) => {
    if (containsForbiddenValue(value)) {
      context.addIssue({
        code: "custom",
        message: "identity data must not contain detectable credential material",
      });
    }
  });

declare const safeIdentityDataBrand: unique symbol;

/** A runtime-validated, branded set of public identity claims. */
export type SafeIdentityData = z.infer<typeof publicIdentityDataObjectSchema> & {
  readonly [safeIdentityDataBrand]: "SafeIdentityData";
};

/**
 * Runtime allowlist for public provider identity claims.
 *
 * Nested objects, arrays, unknown claims, and credential-bearing keys are not
 * public identity data. Raw provider claims must be sanitized before creating
 * an `Identity` value.
 */
export const safeIdentityDataSchema = publicIdentityDataObjectSchema.transform(
  (value) => value as SafeIdentityData,
);

/** Compatibility alias for the public identity-data schema. */
export const publicIdentityDataSchema = safeIdentityDataSchema;

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function containsForbiddenValue(value: unknown, seen = new Set<object>()): boolean {
  if (typeof value === "string") {
    return isSensitiveString(value);
  }
  if (typeof value !== "object" || value === null) {
    return false;
  }
  if (seen.has(value)) {
    return true;
  }
  seen.add(value);

  if (Array.isArray(value)) {
    return value.some((item) => containsForbiddenValue(item, seen));
  }
  if (!isPlainRecord(value)) {
    return true;
  }
  return Object.entries(value).some(
    ([key, nested]) => isSensitiveKeyName(key) || containsForbiddenValue(nested, seen),
  );
}

/**
 * Removes credential-bearing values from raw provider claims and returns only
 * the public scalar allowlist.
 *
 * @param input - Raw provider claims kept in memory by a server/provider
 * adapter. The value is never returned from this function unchanged.
 * @returns Public identity claims safe for `Identity.identity_data`.
 *
 * @example
 * ```ts
 * const identity_data = sanitizeIdentityData({
 *   sub: "provider-subject",
 *   name: "User",
 *   accessToken: "never-public",
 * });
 * // { sub: "provider-subject", name: "User" }
 * ```
 *
 * @since 0.1.0
 */
export function sanitizeIdentityData(input: unknown): SafeIdentityData {
  if (!isPlainRecord(input)) {
    return safeIdentityDataSchema.parse({});
  }

  const output: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(input)) {
    if (
      !(key in publicIdentityDataShape) ||
      isSensitiveKeyName(key) ||
      !(
        typeof value === "string" ||
        typeof value === "boolean" ||
        value === undefined
      ) ||
      containsForbiddenValue(value) ||
      ((key === "picture" || key === "avatar_url") &&
        !safeIdentityUrlSchema.safeParse(value).success) ||
      (typeof value === "string" && value.trim() === "")
    ) {
      continue;
    }
    output[key] = value;
  }

  return safeIdentityDataSchema.parse(output);
}

declare const redactedMetadataBrand: unique symbol;

/**
 * JSON metadata that has passed recursive redaction checks.
 *
 * Use `sanitizeRedactedMetadata` to create this branded value. Raw token,
 * hash, password, OAuth-code, provider-secret, and private-key fields are not
 * valid at any nesting level.
 */
export type RedactedMetadata = JsonObject & {
  readonly [redactedMetadataBrand]: "RedactedMetadata";
};

function isJsonPrimitive(value: unknown): value is JsonPrimitive {
  return (
    value === null ||
    typeof value === "string" ||
    typeof value === "number" ||
    typeof value === "boolean"
  );
}

function sanitizeMetadataValue(
  value: unknown,
  seen = new Set<object>(),
): JsonValue | undefined {
  if (isJsonPrimitive(value)) {
    return typeof value === "string" && isSensitiveString(value) ? undefined : value;
  }
  if (typeof value !== "object" || value === null || seen.has(value)) {
    return undefined;
  }
  seen.add(value);

  if (Array.isArray(value)) {
    const items = value
      .map((item) => sanitizeMetadataValue(item, seen))
      .filter((item): item is JsonValue => item !== undefined);
    return items;
  }
  if (!isPlainRecord(value)) {
    return undefined;
  }

  const output: Record<string, JsonValue> = {};
  for (const [key, nested] of Object.entries(value)) {
    if (isSensitiveKeyName(key)) {
      continue;
    }
    const sanitized = sanitizeMetadataValue(nested, seen);
    if (sanitized !== undefined) {
      output[key] = sanitized;
    }
  }
  if (Object.keys(value).length > 0 && Object.keys(output).length === 0) {
    return undefined;
  }
  return output;
}

/** Returns whether metadata is JSON and contains no recursively forbidden values. */
export function isRedactedMetadata(value: unknown): value is RedactedMetadata {
  if (!isPlainRecord(value)) {
    return false;
  }
  return !containsForbiddenValue(value) && sanitizeMetadataValue(value) !== undefined;
}

/**
 * Runtime validator for metadata written to one-time-token/audit boundaries.
 *
 * @compatibility Project-specific redaction boundary used by later server
 * operations; it is not a general-purpose public metadata schema.
 */
export const redactedMetadataSchema = z.custom<RedactedMetadata>(
  isRedactedMetadata,
  "metadata must be recursively redacted",
);

/**
 * Recursively removes sensitive metadata keys and values.
 *
 * @param input - Arbitrary JSON-like metadata from an internal operation.
 * @returns A branded metadata object safe for public contract boundaries.
 *
 * @example
 * ```ts
 * const metadata = sanitizeRedactedMetadata({
 *   attempt: 1,
 *   nested: { providerSecret: "removed", result: "accepted" },
 * });
 * ```
 *
 * @since 0.1.0
 */
export function sanitizeRedactedMetadata(input: unknown): RedactedMetadata {
  const sanitized = sanitizeMetadataValue(input);
  if (!isPlainRecord(sanitized)) {
    return {} as RedactedMetadata;
  }
  return sanitized as RedactedMetadata;
}

/** An ISO-8601 timestamp returned by the public API. */
export type IsoTimestamp = string;

/**
 * A user record containing identity-safe fields only.
 *
 * @compatibility Supabase-inspired. Credential hashes, bearer tokens, and
 * provider secrets are intentionally not part of this type.
 */
export interface User {
  /** The project's UUID for the user. */
  id: UUID;
  /** The normalized or display email, when present. */
  email: string | null;
  /** The user's phone number, when present. */
  phone: string | null;
  /** When email ownership was confirmed. */
  email_confirmed_at: IsoTimestamp | null;
  /** When phone ownership was confirmed. */
  phone_confirmed_at: IsoTimestamp | null;
  /** The first confirmation timestamp, when any login target was confirmed. */
  confirmed_at: IsoTimestamp | null;
  /** The last successful sign-in timestamp. */
  last_sign_in_at: IsoTimestamp | null;
  /** The account ban expiry, when the account is temporarily banned. */
  banned_until: IsoTimestamp | null;
  /** User-controlled profile metadata. */
  user_metadata: JsonObject;
  /** Project-controlled metadata used for non-authoritative hints. */
  app_metadata: JsonObject;
  /** When the user record was created. */
  created_at: IsoTimestamp;
  /** When the user record was last changed. */
  updated_at: IsoTimestamp;
  /** When the user was soft-deleted, if applicable. */
  deleted_at: IsoTimestamp | null;
}

/**
 * A linked login identity with provider-safe profile data.
 *
 * @compatibility Supabase-inspired. Provider access tokens, refresh tokens,
 * client credentials, raw claims, and other provider secrets are intentionally
 * excluded; use `sanitizeIdentityData` before constructing this value.
 */
export interface Identity {
  /** The project's UUID for the linked identity. */
  id: UUID;
  /** The owning user's UUID. */
  user_id: UUID;
  /** The configured provider key, such as `google`. */
  provider: string;
  /** The stable subject issued by the provider. */
  provider_subject: string;
  /** The provider email when the provider supplied one. */
  email: string | null;
  /** Redacted, scalar provider claims suitable for the client. */
  identity_data: SafeIdentityData;
  /** When the identity was linked. */
  created_at: IsoTimestamp;
  /** When the identity record was last changed. */
  updated_at: IsoTimestamp;
}

/**
 * An access/refresh session returned by auth operations.
 *
 * @compatibility Supabase-inspired response shape. Refresh tokens are opaque
 * values and are never persisted by the shared contract itself.
 */
export interface Session {
  /** The short-lived bearer access token. */
  access_token: string;
  /** The opaque rotating refresh token. */
  refresh_token: string;
  /** The token type used in the Authorization header. */
  token_type: "bearer";
  /** Access-token lifetime in seconds from issuance. */
  expires_in: number;
  /** Access-token expiry as a Unix timestamp in seconds. */
  expires_at: number;
  /** The identity-safe user associated with the session. */
  user: User;
}

/**
 * A data-driven role with a lowercase stable key.
 *
 * @compatibility Project-specific RBAC contract; permissions are data-driven,
 * not inferred from rank.
 */
export interface Role {
  /** The role UUID. */
  id: UUID;
  /** A unique lowercase role key, for example `member`. */
  key: LowercaseKey;
  /** The human-readable role name. */
  name: string;
  /** Optional role description. */
  description: string | null;
  /** Administrative ordering value; it does not grant permissions. */
  rank: number;
  /** Whether the role is protected by project policy. */
  is_system: boolean;
  /** When the role was created. */
  created_at: IsoTimestamp;
  /** When the role was last changed. */
  updated_at: IsoTimestamp;
}

/**
 * A data-driven permission with a lowercase `resource.action` key.
 *
 * @compatibility Project-specific RBAC contract. Supported wildcards are
 * `resource.*` and `*.*`; there are no explicit denies in v1.
 */
export interface Permission {
  /** The permission UUID. */
  id: UUID;
  /** A unique lowercase key, for example `invoice.read`. */
  key: LowercaseKey;
  /** The lowercase resource portion of the key. */
  resource: LowercaseKey;
  /** The lowercase action portion of the key. */
  action: LowercaseKey;
  /** Optional permission description. */
  description: string | null;
  /** When the permission was created. */
  created_at: IsoTimestamp;
  /** When the permission was last changed. */
  updated_at: IsoTimestamp;
}

/** Runtime validation for public role records. */
export const roleSchema = z.object({
  id: uuidSchema,
  key: roleKeySchema,
  name: z.string().trim().min(1),
  description: z.string().nullable(),
  rank: z.number().int().nonnegative(),
  is_system: z.boolean(),
  created_at: z.string().min(1),
  updated_at: z.string().min(1),
});

/** Runtime validation for public permission records and wildcard relationships. */
export const permissionSchema = z
  .object({
    id: uuidSchema,
    key: permissionKeySchema,
    resource: permissionResourceSchema,
    action: permissionActionSchema,
    description: z.string().nullable(),
    created_at: z.string().min(1),
    updated_at: z.string().min(1),
  })
  .superRefine((permission, context) => {
    if (permission.key !== `${permission.resource}.${permission.action}`) {
      context.addIssue({
        code: "custom",
        path: ["key"],
        message: "permission key must equal resource.action",
      });
    }
    if (permission.resource === ("*" as LowercaseKey) && permission.action !== ("*" as LowercaseKey)) {
      context.addIssue({
        code: "custom",
        path: ["key"],
        message: "only *.* is supported for a wildcard resource",
      });
    }
  });

/**
 * Lifecycle events emitted by the client auth namespace.
 *
 * @compatibility Supabase-inspired event names.
 */
export type AuthChangeEvent =
  | "INITIAL_SESSION"
  | "SIGNED_IN"
  | "SIGNED_OUT"
  | "TOKEN_REFRESHED"
  | "USER_UPDATED"
  | "PASSWORD_RECOVERY";

/** A callback used to serialize refresh-token work across browser contexts. */
export type LockFunction = <T>(
  name: string,
  acquireTimeout: number,
  callback: () => Promise<T>,
) => Promise<T>;

/** A client debug callback. Debug output must not include secrets or tokens. */
export type DebugLogger = (message: string, context?: unknown) => void;

/**
 * Minimal synchronous/asynchronous storage contract used by browser and SSR
 * clients.
 *
 * @compatibility Supabase-inspired storage adapter shape.
 */
export interface SupportedStorage {
  /** Reads a stored value or returns null when the key is absent. */
  getItem(key: string): string | null | Promise<string | null>;
  /** Stores a value under a key. */
  setItem(key: string, value: string): void | Promise<void>;
  /** Removes a stored key. */
  removeItem(key: string): void | Promise<void>;
}

/** A scope used by server-side authorization checks and role assignments. */
export interface AuthorizationScope {
  /** The project-defined scope kind. */
  type: string;
  /** The parsed project-defined scope identifier, for example `org_123`. */
  id: ScopeIdentifier;
}

/** The browser/SSR options accepted by the shared client contract. */
export type { ClientOptions } from "./config.js";

/** The server composition options accepted by the shared contract. */
export type { AuthServerOptions } from "./config.js";
