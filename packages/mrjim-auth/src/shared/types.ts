/** A JSON-compatible value suitable for user or application metadata. */
export type JsonValue =
  | string
  | number
  | boolean
  | null
  | readonly JsonValue[]
  | { readonly [key: string]: JsonValue };

/** A JSON object used for metadata that is safe to expose to the caller. */
export type JsonObject = { readonly [key: string]: JsonValue };

/** A project UUID represented at the public TypeScript boundary. */
export type UUID = string;

/** A lowercase key validated by the server/database contract. */
export type LowercaseKey = Lowercase<string>;

/**
 * Provider claims after credential-bearing fields have been removed.
 *
 * The reserved fields are rejected at the type boundary so an identity cannot
 * accidentally be modeled with provider tokens or client credentials.
 */
export type SafeIdentityData = JsonObject & {
  readonly access_token?: never;
  readonly refresh_token?: never;
  readonly id_token?: never;
  readonly client_id?: never;
  readonly client_secret?: never;
};

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
 * client credentials, and other provider secrets must never be returned here.
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
  /** Redacted, provider-safe claims suitable for the client. */
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

/** A data-driven role with a lowercase stable key. */
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

/** A data-driven permission with a lowercase `resource.action` key. */
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

/** Lifecycle events emitted by the client auth namespace. */
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
  /** The project-defined scope identifier. */
  id: string;
}

/** The browser/SSR options accepted by the shared client contract. */
export type { ClientOptions } from "./config.js";

/** The server composition options accepted by the shared contract. */
export type { AuthServerOptions } from "./config.js";
