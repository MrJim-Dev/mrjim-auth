import { createAuthClient } from "./client/auth-client.js";
import type { MrJimAuthClient } from "./client/auth-client.js";
import type { ClientOptions } from "./shared/types.js";
import { createStorageClient } from "./storage/client.js";
import { safeArrayIsArray, safeStringReplace } from "./shared/safe-intrinsics.js";

function ownData(value: unknown, key: string): unknown {
  if (value === null || typeof value !== "object" || safeArrayIsArray(value)) return undefined;
  return Object.getOwnPropertyDescriptor(value, key)?.value;
}

function storageUrl(authUrl: string, options: ClientOptions | undefined): string {
  const storage = ownData(options, "storage");
  const configured = ownData(storage, "url");
  if (configured !== undefined) return configured as string;
  const parsed = new URL(authUrl);
  parsed.pathname = safeStringReplace(parsed.pathname, /\/auth\/v1\/?$/u, "/storage/v1") ?? parsed.pathname;
  return parsed.href;
}

function configuredFetch(options: ClientOptions | undefined): typeof fetch | undefined {
  const global = ownData(options, "global");
  return ownData(global, "fetch") as typeof fetch | undefined;
}

/**
 * Creates a browser-safe or isomorphic authentication client for a
 * project-owned mrjim-auth HTTP endpoint.
 *
 * @param authUrl - Absolute URL of the project's `/auth/v1` endpoint.
 * @param publishableKey - Optional project publishable key sent as `apikey`.
 * @param options - Session, PKCE, storage, lock, debug, fetch, and header options.
 * @returns An immutable client with an immutable `auth` namespace.
 *
 * @remarks
 * Expected HTTP and authentication failures resolve as `{ data, error }`.
 * Malformed configuration or method input throws synchronously. Browser
 * authorization data is advisory; backend authorization remains authoritative.
 *
 * @example
 * ```ts
 * import { createClient } from "mrjim-auth";
 *
 * const client = createClient(
 *   "https://project.example.com/auth/v1",
 *   "publishable-key",
 * );
 *
 * const { data, error } = await client.auth.signInWithPassword({
 *   email: "user@example.com",
 *   password: "correct horse battery staple",
 * });
 * ```
 *
 * @since 0.1.0
 */
export function createClient(
  authUrl: string,
  publishableKey?: string,
  options?: ClientOptions,
): MrJimAuthClient {
  const authClient = createAuthClient(authUrl, publishableKey, options);
  const storage = createStorageClient(storageUrl(authUrl, options), publishableKey, {
    fetch: configuredFetch(options),
    accessToken: async () => {
      const result = await authClient.auth.getSession();
      return result.error === null ? result.data.session?.access_token ?? null : null;
    },
  });
  return Object.freeze({ auth: authClient.auth, storage });
}

export type {
  AuthMethodOptions,
  AuthNamespace,
  ClientAuthOptions,
  ClientGlobalOptions,
  EmailOtpType,
  MrJimAuthClient,
  NullableSessionData,
  OAuthData,
  OAuthInput,
  OAuthOptions,
  OtpSignInInput,
  PasswordSignInInput,
  PermissionScope,
  RecoveryOptions,
  ResetPasswordInput,
  ResendInput,
  ResendType,
  SessionData,
  SignOutScope,
  SignUpInput,
  UpdateUserAttributes,
  VerifyOtpInput,
} from "./client/auth-client.js";
export type {
  SignedUploadData,
  SignedUploadOptions,
  SignedUrlData,
  StorageBucketClient,
  StorageClient,
  StorageResult,
} from "./storage/client.js";
export type { AuthStateCallback, AuthSubscription } from "./client/events.js";
export type { AuthError } from "./shared/errors.js";
export type { AuthResult } from "./shared/result.js";
export type {
  AuthChangeEvent,
  ClientOptions,
  Identity,
  JsonObject,
  JsonValue,
  LockFunction,
  Session,
  SupportedStorage,
  User,
} from "./shared/types.js";
