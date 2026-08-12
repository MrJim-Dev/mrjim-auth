import { z } from "zod";
import {
  safeArrayIsArray,
  safeDefineData,
  safeDefineArrayValue,
  safeGetPrototypeOf,
  safeOwnDataEntries,
  safeOwnDataProperty,
  safeObjectPrototype,
  safeSetAddValue,
  safeSetHasValue,
  safeStringIncludes,
  safeStringReplace,
  safeStringSlice,
  safeStringSplit,
  safeStringStartsWith,
  safeStringToLowerCase,
  safeStringTrim,
  safeCreateRecord,
} from "./safe-intrinsics.js";

const typesURL = URL;
const typesURLSearchParams = URLSearchParams;
const typesReflectApply = Reflect.apply;
const typesObjectGetPrototypeOf = Object.getPrototypeOf;
const typesObjectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const typesObjectHasOwnProperty = Object.prototype.hasOwnProperty;
const typesSearchParamsEntries = URLSearchParams.prototype.entries;
const typesSearchParamsIteratorNext = (() => {
  const iterator = typesReflectApply(typesSearchParamsEntries, new typesURLSearchParams(), []) as object;
  const prototype = typesObjectGetPrototypeOf(iterator);
  if (prototype === null) throw new Error("URLSearchParams iterator is unavailable");
  const descriptor = typesObjectGetOwnPropertyDescriptor(prototype, "next");
  if (descriptor === undefined || !typesReflectApply(typesObjectHasOwnProperty, descriptor, ["value"]) || typeof descriptor.value !== "function") {
    throw new Error("URLSearchParams iterator is unavailable");
  }
  return descriptor.value as Function;
})();
const typesSetConstructor = Set;

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
  .refine((value) => value === (safeStringToLowerCase(value) ?? ""), "authorization keys must be lowercase")
  .transform((value) => value as LowercaseKey);

declare const scopeIdentifierBrand: unique symbol;

/** A parsed, project-defined authorization scope identifier. */
export type ScopeIdentifier = string & {
  readonly [scopeIdentifierBrand]: "ScopeIdentifier";
};

/** Validates and brands a non-empty project-defined scope identifier. */
const typesSafeTrimmedStringSchema = z.string().transform((value) => safeStringTrim(value) ?? "");

export const scopeIdentifierSchema = typesSafeTrimmedStringSchema
  .pipe(z.string().min(1, "scope identifiers must not be empty"))
  .transform((value) => value as ScopeIdentifier);

/** Validates a simple lowercase role key. */
export const roleKeySchema = z
  .string()
  .min(1)
  .regex(/^[a-z][a-z0-9_-]*$/, "role keys must be lowercase identifiers")
  .transform((value) => value as LowercaseKey);

/** Validates the only OAuth state flow modes accepted by the repository. */
export const oauthFlowSchema = z.enum(["sign_in", "link_identity"]);

const permissionResourceSchema = z
  .union([
    z
      .string()
      .min(1)
      .regex(/^[a-z][a-z0-9_-]*(?:\.[a-z][a-z0-9_-]*)*$/, "permission resources must be lowercase namespaces"),
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
  .regex(/^[a-z][a-z0-9_-]*(?:\.[a-z][a-z0-9_-]*)*\.(?:[a-z][a-z0-9_-]*|\*)$|^\*\.\*$/, "invalid permission key")
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
  const first = safeStringReplace(key, /([A-Z]+)([A-Z][a-z])/g, "$1_$2");
  const second = first === null ? null : safeStringReplace(first, /([a-z0-9])([A-Z])/g, "$1_$2");
  const third = second === null ? null : safeStringReplace(second, /[^a-zA-Z0-9]+/g, "_");
  const lowered = third === null ? null : safeStringToLowerCase(third);
  const pieces = lowered === null ? null : safeStringSplit(lowered, "_");
  if (pieces === null) return [];
  const result: string[] = [];
  for (let index = 0; index < pieces.length; index += 1) {
    const segment = pieces[index];
    if (segment !== undefined && segment !== "") safeDefineArrayValue(result, result.length, segment);
  }
  return result;
}

/** Returns true for credential-bearing key names, including style variants. */
export function isSensitiveKeyName(key: string): boolean {
  const segments = keySegments(key);
  const replaced = safeStringReplace(key, /[^a-zA-Z0-9]/g, "");
  const normalizedKey = replaced === null ? "" : safeStringToLowerCase(replaced) ?? "";
  const isExplicitSessionIdentifier =
    normalizedKey === "sessionid";
  let sensitiveSegment = false;
  let one = false;
  let time = false;
  let raw = false;
  let link = false;
  let linkPrefix = false;
  for (let index = 0; index < segments.length; index += 1) {
    const segment = segments[index];
    if (segment === undefined) continue;
    if (safeSetHasValue(sensitiveKeySegments, segment)) sensitiveSegment = true;
    if (segment === "one") one = true;
    if (segment === "time") time = true;
    if (segment === "raw") raw = true;
    if (segment === "link") link = true;
    if (safeSetHasValue(credentialBearingLinkPrefixes, segment)) linkPrefix = true;
  }
  return (
    !isExplicitSessionIdentifier &&
    (normalizedKey === "session" ||
      sensitiveSegment ||
      (one && time) ||
      (raw && link) ||
      (link && linkPrefix))
  );
}

function parseUrlSafely(value: string): URL | null {
  try {
    return new typesURL(value);
  } catch {
    return null;
  }
}

function isRawCredentialString(value: string): boolean {
  return (
    safeStringIncludes(value, "-----BEGIN ") ||
    /^Bearer\s+\S+/i.test(value) ||
    /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(value)
  );
}

function hasCredentialBearingUrl(value: string): boolean {
  const parsed = parseUrlSafely(value);
  if (parsed === null) {
    return false;
  }

  const entries: [string, string][] = [];
  const appendParams = (params: URLSearchParams): boolean => {
    let iterator: object;
    try {
      iterator = typesReflectApply(typesSearchParamsEntries, params, []) as object;
      for (;;) {
        const step = typesReflectApply(typesSearchParamsIteratorNext, iterator, []) as unknown;
        if (step === null || typeof step !== "object") return false;
        const done = safeOwnDataProperty(step, "done");
        const value = safeOwnDataProperty(step, "value");
        if (!done.valid || !done.present || typeof done.value !== "boolean" || !value.valid || !value.present) return false;
        if (done.value) return true;
        if (!safeArrayIsArray(value.value)) return false;
        const tuple = value.value as unknown[];
        if (tuple.length !== 2) return false;
        const key = safeOwnDataProperty(tuple, "0");
        const nestedValue = safeOwnDataProperty(tuple, "1");
        if (!key.valid || !key.present || typeof key.value !== "string" || !nestedValue.valid || !nestedValue.present || typeof nestedValue.value !== "string") return false;
        if (!safeDefineArrayValue(entries, entries.length, [key.value, nestedValue.value])) return false;
      }
    } catch {
      return false;
    }
  };
  if (!appendParams(parsed.searchParams)) return false;
  const hash = safeStringStartsWith(parsed.hash, "#")
    ? safeStringSlice(parsed.hash, 1) ?? ""
    : parsed.hash;
  if (hash !== "") {
    const hashParams = new typesURLSearchParams(hash);
    if (safeStringIncludes(hash, "=") || safeStringIncludes(hash, "&")) {
      if (!appendParams(hashParams)) return false;
    } else {
      if (!safeDefineArrayValue(entries, entries.length, [hash, ""])) return false;
    }
  }

  for (let index = 0; index < entries.length; index += 1) {
    const entry = entries[index];
    if (entry !== undefined && (isSensitiveKeyName(entry[0]) || isRawCredentialString(entry[1]))) return true;
  }
  return false;
}

function isSensitiveString(value: string): boolean {
  return isRawCredentialString(value) || hasCredentialBearingUrl(value);
}

const nonEmptyIdentityStringSchema = typesSafeTrimmedStringSchema.pipe(z.string().min(1));
const safeIdentityUrlSchema = z
  .custom<string>((value) => {
    if (typeof value !== "string") return false;
    const trimmed = safeStringTrim(value);
    if (trimmed === null || trimmed === "") return false;
    const parsed = parseUrlSafely(trimmed);
    return parsed !== null
      && (parsed.protocol === "http:" || parsed.protocol === "https:")
      && !hasCredentialBearingUrl(trimmed);
  }, "identity URL is invalid")
  .transform((value) => safeStringTrim(value) ?? "");

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
  if (typeof value !== "object" || value === null || safeArrayIsArray(value)) {
    return false;
  }
  const prototype = safeGetPrototypeOf(value);
  return prototype === safeObjectPrototype || prototype === null;
}

function isPublicIdentityKey(key: string): boolean {
  switch (key) {
    case "sub":
    case "email":
    case "email_verified":
    case "name":
    case "given_name":
    case "family_name":
    case "picture":
    case "avatar_url":
    case "locale":
    case "hd":
    case "preferred_username":
      return true;
    default:
      return false;
  }
}

function safeIdentityUrl(value: string): string | null {
  const trimmed = safeStringTrim(value);
  if (trimmed === null || trimmed === "") return null;
  const parsed = parseUrlSafely(trimmed);
  if (parsed === null || (parsed.protocol !== "http:" && parsed.protocol !== "https:")) return null;
  return hasCredentialBearingUrl(trimmed) ? null : trimmed;
}

function containsForbiddenValue(value: unknown, seen = new typesSetConstructor<object>()): boolean {
  if (typeof value === "string") {
    return isSensitiveString(value);
  }
  if (typeof value !== "object" || value === null) {
    return false;
  }
  if (safeSetHasValue(seen, value)) {
    return true;
  }
  if (!safeSetAddValue(seen, value)) return true;

  if (safeArrayIsArray(value)) {
    const entries = safeOwnDataEntries(value);
    if (entries === null) return true;
    for (let index = 0; index < entries.length; index += 1) {
      const entry = entries[index];
      if (entry !== undefined && entry[0] !== "length" && containsForbiddenValue(entry[1], seen)) return true;
    }
    return false;
  }
  if (!isPlainRecord(value)) {
    return true;
  }
  const entries = safeOwnDataEntries(value);
  if (entries === null) return true;
  for (let index = 0; index < entries.length; index += 1) {
    const entry = entries[index];
    if (entry !== undefined && (isSensitiveKeyName(entry[0]) || containsForbiddenValue(entry[1], seen))) return true;
  }
  return false;
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
    return safeCreateRecord() as SafeIdentityData;
  }

  const output = safeCreateRecord();
  const entries = safeOwnDataEntries(input);
  if (entries === null) return safeCreateRecord() as SafeIdentityData;
  for (let index = 0; index < entries.length; index += 1) {
    const entry = entries[index];
    if (entry === undefined) continue;
    const key = entry[0];
    const value = entry[1];
    if (
      !isPublicIdentityKey(key) ||
      isSensitiveKeyName(key) ||
      !(typeof value === "string" || typeof value === "boolean" || value === undefined) ||
      containsForbiddenValue(value) ||
      (typeof value === "string" && (safeStringTrim(value) ?? "") === "")
    ) {
      continue;
    }
    if (typeof value === "string") {
      const trimmed = key === "picture" || key === "avatar_url"
        ? safeIdentityUrl(value)
        : safeStringTrim(value);
      if (trimmed === null || trimmed === "") continue;
      if (!safeDefineData(output, key, trimmed)) continue;
    } else if (!safeDefineData(output, key, value)) continue;
  }

  return output as SafeIdentityData;
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
  seen = new typesSetConstructor<object>(),
): JsonValue | undefined {
  if (isJsonPrimitive(value)) {
    return typeof value === "string" && isSensitiveString(value) ? undefined : value;
  }
  if (typeof value !== "object" || value === null || safeSetHasValue(seen, value)) {
    return undefined;
  }
  if (!safeSetAddValue(seen, value)) return undefined;

  if (safeArrayIsArray(value)) {
    const entries = safeOwnDataEntries(value);
    if (entries === null) return undefined;
    const items: JsonValue[] = [];
    for (let index = 0; index < entries.length; index += 1) {
      const entry = entries[index];
      if (entry === undefined || entry[0] === "length") continue;
      const item = sanitizeMetadataValue(entry[1], seen);
      if (item !== undefined) safeDefineArrayValue(items, items.length, item);
    }
    return items;
  }
  if (!isPlainRecord(value)) {
    return undefined;
  }

  const output = safeCreateRecord() as Record<string, JsonValue>;
  const entries = safeOwnDataEntries(value);
  if (entries === null) return undefined;
  let inputCount = 0;
  let outputCount = 0;
  for (let index = 0; index < entries.length; index += 1) {
    const entry = entries[index];
    if (entry === undefined) continue;
    inputCount += 1;
    const key = entry[0];
    const nested = entry[1];
    if (isSensitiveKeyName(key)) {
      continue;
    }
    const sanitized = sanitizeMetadataValue(nested, seen);
    if (sanitized !== undefined) {
      if (safeDefineData(output, key, sanitized)) outputCount += 1;
    }
  }
  if (inputCount > 0 && outputCount === 0) {
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
  name: typesSafeTrimmedStringSchema.pipe(z.string().min(1)),
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
