import {
  AuthApiError,
  AuthConfigurationError,
  AuthProgrammingError,
  type AuthError,
} from "../shared/errors.js";
import { authFailure, authSuccess, type AuthResult } from "../shared/result.js";
import type {
  AuthChangeEvent,
  DebugLogger,
  Identity,
  JsonObject,
  Session,
  SupportedStorage,
  UpdatePasswordInput,
  User,
  LockFunction,
} from "../shared/types.js";
import { createEventBus, type AuthStateCallback, type AuthSubscription, type EventBus } from "./events.js";
import { initializeAuthClient, readAuthUrl } from "./initialize.js";
import { createLockController, isLockBoundaryError, type LockController } from "./lock.js";
import { createStorageController, type PkceTransaction, type StorageController } from "./storage.js";
import { createTransport, type Transport } from "./transport.js";
import {
  assertConfigurationObject,
  assertObject,
  captureMethod,
  createNullRecord,
  freeze,
  hasOwnData,
  invoke,
  isObjectLike,
  objectKeys,
  ownData,
  snapshotJson,
  trimString,
} from "./boundary.js";
import { generatePkcePair } from "./pkce.js";
import { safeArrayIsArray, safeDefineData, safeStringSlice, safeStringTrim } from "../shared/safe-intrinsics.js";
import type { StorageClient } from "../storage/client.js";

const clientGlobal = globalThis as unknown as Record<string, unknown>;
const clientPromiseResolve = Promise.resolve.bind(Promise);
const clientPromiseThen = Promise.prototype.then;
const clientSetTimeout = setTimeout;
const clientClearTimeout = clearTimeout;
const clientDateNow = Date.now;
const clientArrayPush = Array.prototype.push;
const clientObjectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const clientObjectGetPrototypeOf = Object.getPrototypeOf;
const clientObjectHasOwnProperty = Object.prototype.hasOwnProperty;
const clientObjectFreeze = Object.freeze;
const clientReflectApply = Reflect.apply;
const clientURL = URL;
const clientMathFloor = Math.floor;
const clientMathMax = Math.max;
const clientMathMin = Math.min;
const clientNumberIsSafeInteger = Number.isSafeInteger;
const clientTextEncoder = TextEncoder;
const clientEncoder = new clientTextEncoder();
const clientEncode = captureMethod(clientTextEncoder.prototype, "encode", "TextEncoder.encode", "configuration").method;
const clientUint8Array = Uint8Array;

const DEFAULT_STORAGE_KEY = "default";
const MAX_STORAGE_KEY = 128;
const MAX_EMAIL = 320;
const MAX_PASSWORD = 1024;
const MAX_RECOVERY_TOKEN = 128;
const MAX_PROVIDER = 128;
const AUTO_REFRESH_SKEW_MS = 30_000;
const MIN_RETRY_MS = 1_000;

export type EmailOtpType = "emailOtp" | "magicLink" | "email_otp" | "magic_link" | "signup";
export type ResendType = "signup" | "recovery";
export type SignOutScope = "local" | "global" | "others";

/** Signup redirect and user-metadata options. */
export interface AuthMethodOptions {
  /** Exact allowlisted callback URL. */
  readonly redirectTo?: string;
  /** Project-defined user metadata. */
  readonly data?: JsonObject;
}

/** Email/password signup input. */
export interface SignUpInput {
  /** Email address to normalize and register. */
  readonly email: string;
  /** Project-policy password. */
  readonly password: string;
  /** Optional redirect and initial user metadata. */
  readonly options?: AuthMethodOptions;
}

/** Email/password sign-in input. */
export interface PasswordSignInInput {
  /** Registered account email. */
  readonly email: string;
  /** Account password. */
  readonly password: string;
}

/** Magic-link or email-OTP issuance input. */
export interface OtpSignInInput {
  /** Target email for the magic link or OTP. */
  readonly email: string;
  /** Issuance type and exact redirect. */
  readonly options?: {
    readonly type?: EmailOtpType;
    readonly redirectTo?: string;
  };
}

/** Magic-link or email-OTP verification input. */
export interface VerifyOtpInput {
  /** Email bound to the proof. */
  readonly email: string;
  /** One-time proof delivered by the project mailer. */
  readonly token: string;
  /** Verification mode used when the proof was issued. */
  readonly type: EmailOtpType;
  /** Optional exact redirect binding. */
  readonly options?: { readonly redirectTo?: string };
}

/** OAuth/OIDC redirect behavior. */
export interface OAuthOptions {
  /** Exact callback URL allowed by project configuration. */
  readonly redirectTo?: string;
  /** Return the URL without assigning browser location. */
  readonly skipBrowserRedirect?: boolean;
}

/** OAuth/OIDC provider input. */
export interface OAuthInput {
  /** Configured provider key such as `google`. */
  readonly provider: string;
  /** Redirect behavior for this PKCE transaction. */
  readonly options?: OAuthOptions;
}

/** Password-recovery redirect behavior. */
export interface RecoveryOptions {
  /** Exact redirect bound to the one-time recovery proof. */
  readonly redirectTo?: string;
}

/** Purpose-bound recovery proof used to replace a forgotten password. */
export interface ResetPasswordInput {
  /** Account email addressed by the recovery message. */
  readonly email: string;
  /** One-time recovery token delivered by the project mailer. */
  readonly token: string;
  /** Replacement password accepted under project password policy. */
  readonly password: string;
  /** Optional exact redirect binding used when the token was issued. */
  readonly options?: RecoveryOptions;
}

/** Signup/recovery message resend input. */
export interface ResendInput {
  /** Proof purpose to resend. */
  readonly type: ResendType;
  /** Account email addressed by the message. */
  readonly email: string;
  /** Optional exact redirect binding. */
  readonly options?: RecoveryOptions;
}

/** Self-service user fields supported by the v1 HTTP contract. */
export interface UpdateUserAttributes {
  /** New email requiring project proof policy. */
  readonly email?: string;
  /** Replacement user-owned metadata. */
  readonly data?: JsonObject;
  /** Exact redirect for email-change proof. */
  readonly redirectTo?: string;
}

export type { UpdatePasswordInput } from "../shared/types.js";

/** Optional project-defined authorization scope. */
export interface PermissionScope {
  /** Scope kind such as `organization`. */
  readonly type: string;
  /** Project-defined scope identifier. */
  readonly id: string;
}

export interface OAuthData {
  /** The configured provider key. */
  readonly provider: string;
  /** The provider authorization URL for the current PKCE transaction. */
  readonly url: string;
}

export interface SessionData {
  /** The authoritative user returned with the session. */
  readonly user: User;
  /** The validated access/refresh session. */
  readonly session: Session;
}

export interface NullableSessionData {
  /** The user when the operation resolved an account immediately. */
  readonly user: User | null;
  /** The session when the operation authenticated immediately. */
  readonly session: Session | null;
}

/** Supabase-inspired authentication operations for one project endpoint. */
export interface AuthNamespace {
  /** Creates an email/password account under project policy. */
  readonly signUp: (input: SignUpInput) => Promise<AuthResult<NullableSessionData>>;
  /** Authenticates with an email and password. */
  readonly signInWithPassword: (input: PasswordSignInInput) => Promise<AuthResult<SessionData>>;
  /** Requests a magic link or email OTP. */
  readonly signInWithOtp: (input: OtpSignInInput) => Promise<AuthResult<NullableSessionData>>;
  /** Verifies an email OTP or magic-link token. */
  readonly verifyOtp: (input: VerifyOtpInput) => Promise<AuthResult<NullableSessionData>>;
  /** Starts an OAuth/OIDC PKCE sign-in transaction. */
  readonly signInWithOAuth: (input: OAuthInput) => Promise<AuthResult<OAuthData>>;
  /** Exchanges a callback code using the stored PKCE verifier. */
  readonly exchangeCodeForSession: (code: string) => Promise<AuthResult<SessionData>>;
  /** Requests a non-enumerating password-recovery email. */
  readonly resetPasswordForEmail: (email: string, options?: RecoveryOptions) => Promise<AuthResult<{ readonly sent: true }>>;
  /** Consumes a one-time recovery proof and replaces the forgotten password. */
  readonly resetPassword: (input: ResetPasswordInput) => Promise<AuthResult<{ readonly user: User }>>;
  /** Resends a signup or recovery message. */
  readonly resend: (input: ResendInput) => Promise<AuthResult<{ readonly sent: true }>>;
  /** Reads the locally persisted session without server validation. */
  readonly getSession: () => Promise<AuthResult<{ readonly session: Session | null }>>;
  /** Retrieves the authoritative current user from the auth server. */
  readonly getUser: (jwt?: string) => Promise<AuthResult<{ readonly user: User }>>;
  /** Validates or refreshes and then persists a supplied session. */
  readonly setSession: (session: Session) => Promise<AuthResult<SessionData>>;
  /** Rotates a refresh token under the configured cross-context lock. */
  readonly refreshSession: (session?: Session) => Promise<AuthResult<SessionData>>;
  /** Updates email or user metadata; use updatePassword for passwords; phone remains unsupported. */
  readonly updateUser: (attributes: UpdateUserAttributes) => Promise<AuthResult<{ readonly user: User }>>;
  /** Changes the authenticated user's password after current-password proof. */
  readonly updatePassword: (input: UpdatePasswordInput) => Promise<AuthResult<{ readonly user: User }>>;
  /** Returns linked identities with provider secrets removed. */
  readonly getUserIdentities: () => Promise<AuthResult<{ readonly identities: readonly Identity[] }>>;
  /** Starts an authenticated OAuth/OIDC identity-link transaction. */
  readonly linkIdentity: (input: OAuthInput) => Promise<AuthResult<OAuthData>>;
  /** Unlinks an identity under server-enforced login-method policy. */
  readonly unlinkIdentity: (identity: Pick<Identity, "id"> | Identity) => Promise<AuthResult<null>>;
  /** Browser permission data is an interface hint; backend authorization remains authoritative. */
  readonly getPermissions: (options?: { readonly scope?: PermissionScope }) => Promise<AuthResult<{ readonly permissions: readonly string[] }>>;
  /** Revokes sessions using `local`, `global`, or `others` scope. */
  readonly signOut: (options?: { readonly scope?: SignOutScope }) => Promise<AuthResult<null>>;
  /** Subscribes to ordered local auth lifecycle events. */
  readonly onAuthStateChange: (callback: AuthStateCallback) => AuthSubscription;
  /** Starts expiry-aware refresh scheduling. */
  readonly startAutoRefresh: () => void;
  /** Stops refresh scheduling without signing out. */
  readonly stopAutoRefresh: () => void;
  /** Idempotently releases timers, channels, listeners, and subscriptions. */
  readonly dispose: () => void;
}

/** Immutable browser-safe client returned by {@link createClient}. */
export interface MrJimAuthClient {
  /** Project-scoped authentication operations. */
  readonly auth: AuthNamespace;
  /** Project-scoped object storage operations. */
  readonly storage: StorageClient;
}

/** Internal auth-only client composed by the public project client. */
export type MrJimAuthOnlyClient = Pick<MrJimAuthClient, "auth">;

/** Fully validated client auth options after defaulting. */
export interface ClientAuthOptions {
  /** Whether expiry-aware refresh scheduling is active. */
  readonly autoRefreshToken: boolean;
  /** Whether sessions use the configured/default persistent storage. */
  readonly persistSession: boolean;
  /** Whether browser callback credentials are detected and cleaned. */
  readonly detectSessionInUrl: boolean;
  /** v1 always uses authorization-code PKCE for OAuth. */
  readonly flowType: "pkce";
  /** Optional synchronous/asynchronous storage adapter. */
  readonly storage?: SupportedStorage | undefined;
  /** Namespace shared by session, PKCE, events, and locks. */
  readonly storageKey: string;
  /** Optional project lock implementation. */
  readonly lock?: LockFunction | undefined;
  /** Optional redacted diagnostic logger. */
  readonly debug?: boolean | DebugLogger | undefined;
  /** Prevents automatic initial storage/URL processing. */
  readonly skipAutoInitialize: boolean;
}

/** Fully validated client transport options after defaulting. */
export interface ClientGlobalOptions {
  /** Injected fetch implementation. */
  readonly fetch: typeof fetch;
  /** Validated global request headers. */
  readonly headers: readonly (readonly [string, string])[];
}

/** Internal immutable client option snapshot. */
export interface SnapshotClientOptions {
  readonly auth: ClientAuthOptions;
  readonly global: ClientGlobalOptions;
}

function internalError(): AuthApiError {
  return new AuthApiError("internal_error", 500, "Internal authentication error");
}

function expectedError(code: "unauthorized" | "session_expired" | "invalid_request", status: number, message: string): AuthApiError {
  return new AuthApiError(code, status, message);
}

function safeDebug(debug: DebugLogger | undefined, message: string, context: Record<string, unknown>): void {
  if (debug === undefined) return;
  try {
    debug(message, context);
  } catch {
    // Debug is deliberately non-authoritative.
  }
}

function isBrowserRuntime(): boolean {
  try {
    return typeof clientGlobal.window === "object" && typeof clientGlobal.document === "object";
  } catch {
    return false;
  }
}

function optionValue(value: object, key: string, label: string): unknown {
  const property = ownData(value, key);
  if (!property.ok) throw new AuthConfigurationError(`${label} is malformed`);
  return property.present ? property.value : undefined;
}

function optionRecord(value: unknown, label: string): object | undefined {
  if (value === undefined) return undefined;
  assertConfigurationObject(value, label);
  if (hasThenPropertySafe(value)) throw new AuthConfigurationError(`${label} is malformed`);
  return value;
}

function hasThenPropertySafe(value: object): boolean {
  let current: object | null | undefined = value;
  for (let depth = 0; current !== null && current !== undefined && depth < 16; depth += 1) {
    try {
      const descriptor = clientObjectGetOwnPropertyDescriptor(current, "then");
      if (descriptor !== undefined) return true;
      current = clientObjectGetPrototypeOf(current);
    } catch {
      return true;
    }
  }
  return current !== null;
}

function snapshotHeaders(value: unknown): readonly (readonly [string, string])[] {
  if (value === undefined) return [];
  assertConfigurationObject(value, "global.headers");
  const keys = objectKeys(value);
  if (keys.length > 128) throw new AuthConfigurationError("global.headers is oversized");
  const headers: Array<readonly [string, string]> = [];
  for (let index = 0; index < keys.length; index += 1) {
    const key = keys[index];
    if (key === undefined) throw new AuthConfigurationError("global.headers is malformed");
    const header = optionValue(value, key, "global.headers");
    if (typeof header !== "string" || header.length > 4096 || /[\r\n]/u.test(key) || /[\r\n]/u.test(header)) throw new AuthConfigurationError("global.headers is malformed");
    clientArrayPush.call(headers, Object.freeze([key, header]));
  }
  return clientObjectFreeze(headers);
}

function snapshotClientOptions(options: unknown): SnapshotClientOptions {
  const browser = isBrowserRuntime();
  const root = optionRecord(options, "client options");
  const authRecord = optionRecord(root === undefined ? undefined : optionValue(root, "auth", "client.auth"), "client.auth");
  const globalRecord = optionRecord(root === undefined ? undefined : optionValue(root, "global", "client.global"), "client.global");
  const auth = {
    autoRefreshToken: ((authRecord === undefined ? undefined : optionValue(authRecord, "autoRefreshToken", "auth.autoRefreshToken")) ?? browser) as boolean,
    persistSession: ((authRecord === undefined ? undefined : optionValue(authRecord, "persistSession", "auth.persistSession")) ?? browser) as boolean,
    detectSessionInUrl: ((authRecord === undefined ? undefined : optionValue(authRecord, "detectSessionInUrl", "auth.detectSessionInUrl")) ?? browser) as boolean,
    flowType: ((authRecord === undefined ? undefined : optionValue(authRecord, "flowType", "auth.flowType")) ?? "pkce") as "pkce",
    storage: authRecord === undefined ? undefined : optionValue(authRecord, "storage", "auth.storage") as SupportedStorage | undefined,
    storageKey: ((authRecord === undefined ? undefined : optionValue(authRecord, "storageKey", "auth.storageKey")) ?? DEFAULT_STORAGE_KEY) as string,
    lock: authRecord === undefined ? undefined : optionValue(authRecord, "lock", "auth.lock") as LockFunction | undefined,
    debug: authRecord === undefined ? undefined : optionValue(authRecord, "debug", "auth.debug") as boolean | DebugLogger | undefined,
    skipAutoInitialize: ((authRecord === undefined ? undefined : optionValue(authRecord, "skipAutoInitialize", "auth.skipAutoInitialize")) ?? false) as boolean,
  };
  if (typeof auth.autoRefreshToken !== "boolean" || typeof auth.persistSession !== "boolean" || typeof auth.detectSessionInUrl !== "boolean" || auth.flowType !== "pkce" || typeof auth.skipAutoInitialize !== "boolean") throw new AuthConfigurationError("auth options are malformed");
  if (typeof auth.storageKey !== "string" || auth.storageKey.length < 1 || auth.storageKey.length > MAX_STORAGE_KEY || safeStringTrim(auth.storageKey) !== auth.storageKey || !/^[A-Za-z0-9._-]+$/u.test(auth.storageKey)) throw new AuthConfigurationError("auth.storageKey is malformed");
  if (auth.lock !== undefined && typeof auth.lock !== "function") throw new AuthConfigurationError("auth.lock is malformed");
  if (auth.debug !== undefined && typeof auth.debug !== "boolean" && typeof auth.debug !== "function") throw new AuthConfigurationError("auth.debug is malformed");
  const fetchProperty = globalRecord === undefined ? undefined : ownData(globalRecord, "fetch");
  if (fetchProperty !== undefined && !fetchProperty.ok) throw new AuthConfigurationError("global.fetch is malformed");
  const globalFetch = fetchProperty?.present ? fetchProperty.value : clientGlobal.fetch;
  if (typeof globalFetch !== "function") throw new AuthConfigurationError("global.fetch is malformed");
  return {
    auth: Object.freeze(auth),
    global: Object.freeze({ fetch: globalFetch as typeof fetch, headers: snapshotHeaders(globalRecord === undefined ? undefined : optionValue(globalRecord, "headers", "global.headers")) }),
  };
}

function requiredString(value: object, key: string, label: string, maximum: number): string {
  const property = ownData(value, key);
  if (!property.ok || !property.present) throw new AuthProgrammingError(`${label} is required`);
  return trimString(property.value, label, maximum);
}

function passwordValue(value: object, key: string, label: string): string {
  const password = requiredString(value, key, label, MAX_PASSWORD);
  let encoded: unknown;
  try {
    encoded = invoke<unknown>(clientEncode, clientEncoder, [password]);
  } catch {
    throw new AuthProgrammingError(`${label} is malformed`);
  }
  if (password.length < 8 || !(encoded instanceof clientUint8Array) || encoded.byteLength > MAX_PASSWORD) {
    throw new AuthProgrammingError(`${label} is malformed`);
  }
  return password;
}

function recoveryPassword(value: object): string {
  return passwordValue(value, "password", "password");
}

function optionalString(value: object, key: string, label: string, maximum: number): string | undefined {
  const property = ownData(value, key);
  if (!property.ok) throw new AuthProgrammingError(`${label} is malformed`);
  return property.present ? trimString(property.value, label, maximum) : undefined;
}

function optionalObject(value: object, key: string, label: string): object | undefined {
  const property = ownData(value, key);
  if (!property.ok) throw new AuthProgrammingError(`${label} is malformed`);
  if (!property.present) return undefined;
  assertObject(property.value, label);
  return property.value;
}

function validateInput(value: unknown, label: string): object {
  assertObject(value, label);
  if (hasThenPropertySafe(value)) throw new AuthProgrammingError(`${label} is malformed`);
  return value;
}

function redirectFrom(value: object | undefined): string | undefined {
  return value === undefined ? undefined : optionalString(value, "redirectTo", "redirectTo", 2048);
}

function wireOtpType(value: unknown): "magic_link" | "email_otp" | "signup" {
  if (value === undefined || value === "emailOtp" || value === "email_otp") return "email_otp";
  if (value === "magicLink" || value === "magic_link") return "magic_link";
  if (value === "signup") return "signup";
  throw new AuthProgrammingError("OTP type is malformed");
}

function sessionResult(session: Session): AuthResult<SessionData> {
  return authSuccess({ user: session.user, session });
}

function nullableSessionResult(user: User | null, session: Session | null): AuthResult<NullableSessionData> {
  return authSuccess({ user, session });
}

function copyJsonObject(value: unknown, label: string): JsonObject {
  const snapshot = snapshotJson(value, label);
  if (snapshot === null || typeof snapshot !== "object" || safeArrayIsArray(snapshot)) throw new AuthProgrammingError(`${label} is malformed`);
  return snapshot as JsonObject;
}

function copyUser(value: unknown): User {
  if (value === null || typeof value !== "object" || safeArrayIsArray(value)) throw new AuthProgrammingError("user response is malformed");
  const fields = ["id", "email", "phone", "email_confirmed_at", "phone_confirmed_at", "confirmed_at", "last_sign_in_at", "banned_until", "created_at", "updated_at", "deleted_at", "user_metadata", "app_metadata"];
  for (let index = 0; index < fields.length; index += 1) if (!hasOwnData(value, fields[index]!)) throw new AuthProgrammingError("user response is malformed");
  const id = ownData(value, "id");
  const email = ownData(value, "email");
  const phone = ownData(value, "phone");
  const emailConfirmed = ownData(value, "email_confirmed_at");
  const phoneConfirmed = ownData(value, "phone_confirmed_at");
  const confirmed = ownData(value, "confirmed_at");
  const lastSignIn = ownData(value, "last_sign_in_at");
  const banned = ownData(value, "banned_until");
  const created = ownData(value, "created_at");
  const updated = ownData(value, "updated_at");
  const deleted = ownData(value, "deleted_at");
  const requiredUserFields = [id, email, phone, emailConfirmed, phoneConfirmed, confirmed, lastSignIn, banned, created, updated, deleted];
  for (let index = 0; index < requiredUserFields.length; index += 1) {
    const item = requiredUserFields[index];
    if (item === undefined || !item.ok || !item.present) throw new AuthProgrammingError("user response is malformed");
  }
  if (typeof id.value !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(id.value)) throw new AuthProgrammingError("user response is malformed");
  const nullableUserStrings = [email, phone, emailConfirmed, phoneConfirmed, confirmed, lastSignIn, banned, deleted];
  for (let index = 0; index < nullableUserStrings.length; index += 1) {
    const item = nullableUserStrings[index];
    if (item === undefined || (item.value !== null && (typeof item.value !== "string" || item.value.length > 320))) throw new AuthProgrammingError("user response is malformed");
  }
  if (typeof created.value !== "string" || created.value.length < 1 || created.value.length > 128 || typeof updated.value !== "string" || updated.value.length < 1 || updated.value.length > 128) throw new AuthProgrammingError("user response is malformed");
  return freeze({
    id: id.value as User["id"],
    email: email.value as string | null,
    phone: phone.value as string | null,
    email_confirmed_at: emailConfirmed.value as string | null,
    phone_confirmed_at: phoneConfirmed.value as string | null,
    confirmed_at: confirmed.value as string | null,
    last_sign_in_at: lastSignIn.value as string | null,
    banned_until: banned.value as string | null,
    user_metadata: copyJsonObject(ownData(value, "user_metadata").value, "user metadata"),
    app_metadata: copyJsonObject(ownData(value, "app_metadata").value, "app metadata"),
    created_at: created.value as string,
    updated_at: updated.value as string,
    deleted_at: deleted.value as string | null,
  }) as User;
}

function copySession(value: unknown): Session {
  if (value === null || typeof value !== "object" || safeArrayIsArray(value)) throw new AuthProgrammingError("session response is malformed");
  const access = ownData(value, "access_token");
  const refresh = ownData(value, "refresh_token");
  const type = ownData(value, "token_type");
  const expiresIn = ownData(value, "expires_in");
  const expiresAt = ownData(value, "expires_at");
  const userValue = ownData(value, "user");
  const requiredSessionFields = [access, refresh, type, expiresIn, expiresAt, userValue];
  for (let index = 0; index < requiredSessionFields.length; index += 1) {
    const item = requiredSessionFields[index];
    if (item === undefined || !item.ok || !item.present) throw new AuthProgrammingError("session response is malformed");
  }
  if (typeof access.value !== "string" || typeof refresh.value !== "string" || access.value.length === 0 || refresh.value.length === 0 || access.value.length > 8192 || refresh.value.length > 8192 || type.value !== "bearer" || typeof expiresIn.value !== "number" || !clientNumberIsSafeInteger(expiresIn.value) || expiresIn.value <= 0 || typeof expiresAt.value !== "number" || !clientNumberIsSafeInteger(expiresAt.value) || expiresAt.value <= 0) throw new AuthProgrammingError("session response is malformed");
  const copiedUser = copyUser(userValue.value);
  return freeze({ access_token: access.value, refresh_token: refresh.value, token_type: "bearer", expires_in: expiresIn.value, expires_at: expiresAt.value, user: copiedUser });
}

function copyNullableAuthData(value: unknown): NullableSessionData {
  if (value === null || typeof value !== "object" || safeArrayIsArray(value)) throw new AuthProgrammingError("auth response is malformed");
  const user = ownData(value, "user");
  const session = ownData(value, "session");
  if (!user.ok || !user.present || !session.ok || !session.present) throw new AuthProgrammingError("auth response is malformed");
  return freeze({ user: user.value === null ? null : copyUser(user.value), session: session.value === null ? null : copySession(session.value) });
}

function copySessionResponse(value: unknown): Session {
  return copySession(value);
}

function copyUserResponse(value: unknown): User {
  if (value === null || typeof value !== "object" || safeArrayIsArray(value)) throw new AuthProgrammingError("user response is malformed");
  const user = ownData(value, "user");
  if (!user.ok || !user.present) throw new AuthProgrammingError("user response is malformed");
  return copyUser(user.value);
}

function copySent(value: unknown): { readonly sent: true } {
  if (value === null || typeof value !== "object" || safeArrayIsArray(value)) throw new AuthProgrammingError("sent response is malformed");
  const sent = ownData(value, "sent");
  if (!sent.ok || !sent.present || sent.value !== true) throw new AuthProgrammingError("sent response is malformed");
  return freeze({ sent: true });
}

function copyAuthorize(value: unknown): OAuthData & { readonly redirect: string; readonly expiresAt: string } {
  if (value === null || typeof value !== "object" || safeArrayIsArray(value)) throw new AuthProgrammingError("OAuth response is malformed");
  const provider = ownData(value, "provider");
  const url = ownData(value, "url");
  const redirect = ownData(value, "redirect");
  const expiresAt = ownData(value, "expires_at");
  const requiredAuthorizeFields = [provider, url, redirect, expiresAt];
  for (let index = 0; index < requiredAuthorizeFields.length; index += 1) {
    const item = requiredAuthorizeFields[index];
    if (item === undefined || !item.ok || !item.present) throw new AuthProgrammingError("OAuth response is malformed");
  }
  if (typeof provider.value !== "string" || provider.value.length < 1 || provider.value.length > MAX_PROVIDER || typeof url.value !== "string" || url.value.length < 1 || url.value.length > 4096 || typeof redirect.value !== "string" || redirect.value.length < 1 || redirect.value.length > 2048 || typeof expiresAt.value !== "string" || expiresAt.value.length < 1 || expiresAt.value.length > 128) throw new AuthProgrammingError("OAuth response is malformed");
  let parsed: URL;
  try { parsed = new clientURL(url.value); } catch { throw new AuthProgrammingError("OAuth response is malformed"); }
  if ((parsed.protocol !== "https:" && parsed.protocol !== "http:") || parsed.username !== "" || parsed.password !== "") throw new AuthProgrammingError("OAuth response is malformed");
  return freeze({ provider: provider.value, url: url.value, redirect: redirect.value, expiresAt: expiresAt.value });
}

function isPublicIdentityKey(key: string): boolean {
  return key === "sub"
    || key === "email"
    || key === "email_verified"
    || key === "name"
    || key === "given_name"
    || key === "family_name"
    || key === "picture"
    || key === "avatar_url"
    || key === "locale"
    || key === "hd"
    || key === "preferred_username";
}

function copyIdentityData(value: unknown): Identity["identity_data"] {
  const snapshot = snapshotJson(value, "identity data");
  if (snapshot === null || typeof snapshot !== "object" || safeArrayIsArray(snapshot)) throw new AuthProgrammingError("identity data is malformed");
  const keys = objectKeys(snapshot);
  const output = createNullRecord();
  for (let index = 0; index < keys.length; index += 1) {
    const key = keys[index];
    if (key === undefined || !isPublicIdentityKey(key)) throw new AuthProgrammingError("identity data is malformed");
    const property = ownData(snapshot, key);
    if (!property.ok || !property.present) throw new AuthProgrammingError("identity data is malformed");
    if (key === "email_verified") {
      if (typeof property.value !== "boolean" || !safeDefineData(output, key, property.value)) throw new AuthProgrammingError("identity data is malformed");
      continue;
    }
    if (typeof property.value !== "string" || property.value.length < 1 || property.value.length > 4096 || safeStringTrim(property.value) !== property.value || /^Bearer\s|-----BEGIN |^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/iu.test(property.value)) throw new AuthProgrammingError("identity data is malformed");
    if (key === "picture" || key === "avatar_url") {
      let parsed: URL;
      try {
        parsed = new clientURL(property.value);
      } catch {
        throw new AuthProgrammingError("identity data is malformed");
      }
      if ((parsed.protocol !== "http:" && parsed.protocol !== "https:") || parsed.username !== "" || parsed.password !== "" || /(?:token|secret|code|key|signature|credential|password)=/iu.test(`${parsed.search}&${parsed.hash}`)) throw new AuthProgrammingError("identity data is malformed");
    }
    if (!safeDefineData(output, key, property.value)) throw new AuthProgrammingError("identity data is malformed");
  }
  return freeze(output) as Identity["identity_data"];
}

function copyIdentity(value: unknown): Identity {
  if (value === null || typeof value !== "object" || safeArrayIsArray(value)) throw new AuthProgrammingError("identity response is malformed");
  const id = ownData(value, "id");
  const userId = ownData(value, "user_id");
  const provider = ownData(value, "provider");
  const subject = ownData(value, "provider_subject");
  const email = ownData(value, "email");
  const identityData = ownData(value, "identity_data");
  const created = ownData(value, "created_at");
  const updated = ownData(value, "updated_at");
  const requiredIdentityFields = [id, userId, provider, subject, email, identityData, created, updated];
  for (let index = 0; index < requiredIdentityFields.length; index += 1) {
    const item = requiredIdentityFields[index];
    if (item === undefined || !item.ok || !item.present) throw new AuthProgrammingError("identity response is malformed");
  }
  if (typeof id.value !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(id.value) || typeof userId.value !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(userId.value) || typeof provider.value !== "string" || provider.value.length < 1 || provider.value.length > 128 || typeof subject.value !== "string" || subject.value.length < 1 || subject.value.length > 2048 || (email.value !== null && (typeof email.value !== "string" || email.value.length > MAX_EMAIL)) || typeof created.value !== "string" || created.value.length < 1 || created.value.length > 128 || typeof updated.value !== "string" || updated.value.length < 1 || updated.value.length > 128) throw new AuthProgrammingError("identity response is malformed");
  const data = copyIdentityData(identityData.value);
  return freeze({ id: id.value as Identity["id"], user_id: userId.value as Identity["user_id"], provider: provider.value, provider_subject: subject.value, email: email.value as string | null, identity_data: data, created_at: created.value, updated_at: updated.value });
}

function copyIdentities(value: unknown): readonly Identity[] {
  if (value === null || typeof value !== "object" || safeArrayIsArray(value)) throw new AuthProgrammingError("identity response is malformed");
  const identities = ownData(value, "identities");
  if (!identities.ok || !identities.present || !safeArrayIsArray(identities.value)) throw new AuthProgrammingError("identity response is malformed");
  const identityValues = identities.value as unknown[];
  if (identityValues.length > 10_000) throw new AuthProgrammingError("identity response is malformed");
  const output: Identity[] = [];
  for (let index = 0; index < identityValues.length; index += 1) clientArrayPush.call(output, copyIdentity(identityValues[index]));
  return freeze(output);
}

function copyPermissions(value: unknown): readonly string[] {
  if (value === null || typeof value !== "object" || safeArrayIsArray(value)) throw new AuthProgrammingError("permission response is malformed");
  const permissions = ownData(value, "permissions");
  if (!permissions.ok || !permissions.present || !safeArrayIsArray(permissions.value)) throw new AuthProgrammingError("permission response is malformed");
  const permissionValues = permissions.value as unknown[];
  if (permissionValues.length > 100_000) throw new AuthProgrammingError("permission response is malformed");
  const output: string[] = [];
  for (let index = 0; index < permissionValues.length; index += 1) {
    const item = permissionValues[index];
    if (typeof item !== "string" || item.length === 0 || item.length > 256) throw new AuthProgrammingError("permission response is malformed");
    clientArrayPush.call(output, item);
  }
  return freeze(output);
}

function copyExchange(value: unknown): { readonly user: User; readonly session: Session } {
  if (value === null || typeof value !== "object" || safeArrayIsArray(value)) throw new AuthProgrammingError("exchange response is malformed");
  const user = ownData(value, "user");
  const session = ownData(value, "session");
  const identity = ownData(value, "identity");
  if (!user.ok || !user.present || !session.ok || !session.present || !identity.ok || !identity.present) throw new AuthProgrammingError("exchange response is malformed");
  return freeze({ user: copyUser(user.value), session: copySession(session.value) });
}

function wireOptions(value: object | undefined): { readonly redirect_to?: string; readonly data?: JsonObject } | undefined {
  if (value === undefined) return undefined;
  const redirect = redirectFrom(value);
  const dataValue = optionalObject(value, "data", "options.data");
  return {
    ...(redirect === undefined ? {} : { redirect_to: redirect }),
    ...(dataValue === undefined ? {} : { data: copyJsonObject(dataValue, "options.data") }),
  };
}

function currentUnixSeconds(): number {
  return clientMathFloor(clientDateNow() / 1000);
}

export function createAuthClient(baseUrl: string, publishableKey: string | undefined, options: unknown): MrJimAuthOnlyClient {
  const snapshot = snapshotClientOptions(options);
  const debug = typeof snapshot.auth.debug === "function" ? snapshot.auth.debug : undefined;
  const transport: Transport = createTransport({ baseUrl, publishableKey, fetch: snapshot.global.fetch, headers: snapshot.global.headers, debug });
  const storage: StorageController = createStorageController({ storageKey: snapshot.auth.storageKey, storage: snapshot.auth.storage, persistSession: snapshot.auth.persistSession });
  const lock: LockController = createLockController({ storageKey: snapshot.auth.storageKey, lock: snapshot.auth.lock });
  let disposed = false;
  let currentSession: Session | null = null;
  let refreshTimer: ReturnType<typeof setTimeout> | undefined;
  let visibilityRemove: (() => void) | undefined;
  let documentVisible = true;
  let autoRefreshRunning = snapshot.auth.autoRefreshToken;
  let lastRevision = 0;
  let lastEventRevision = -1;
  let lastEvent: AuthChangeEvent | undefined;
  let refreshPromise: Promise<AuthResult<SessionData>> | undefined;
  let remoteQueue = clientPromiseResolve();
  let initialization: Promise<void>;

  const resultCall = async <T>(operation: () => Promise<AuthResult<unknown>>, parse: (value: unknown) => T): Promise<AuthResult<T>> => {
    try {
      const result = await operation();
      if (result.error !== null) return authFailure(result.error);
      try {
        return authSuccess(parse(result.data));
      } catch {
        return authFailure(internalError());
      }
    } catch {
      return authFailure(internalError());
    }
  };

  const contain = async <T>(operation: () => Promise<AuthResult<T>>): Promise<AuthResult<T>> => {
    try {
      return await operation();
    } catch {
      return authFailure(internalError());
    }
  };

  const readLatest = async (): Promise<Session | null> => {
    try {
      const value = await storage.readSession();
      currentSession = value === null ? null : copySession(value);
      lastRevision = await storage.readRevision();
      return currentSession;
    } catch {
      currentSession = null;
      return null;
    }
  };

  const dispatch = (event: AuthChangeEvent, sessionValue: Session | null, revision: number, publish = true): void => {
    if (disposed) return;
    if (event !== "INITIAL_SESSION" && revision > 0 && revision === lastEventRevision && event === lastEvent) return;
    if (event !== "INITIAL_SESSION" && revision > 0) {
      lastEventRevision = revision;
      lastEvent = event;
    }
    eventBus.dispatch(event, sessionValue === null ? null : copySession(sessionValue));
    if (publish) eventBus.publish(event, revision);
  };

  const commit = async (sessionValue: Session, event: AuthChangeEvent | undefined): Promise<boolean> => {
    if (disposed) return false;
    const safeSession = copySession(sessionValue);
    try {
      const revision = await storage.writeSession(safeSession);
      currentSession = safeSession;
      lastRevision = revision;
      scheduleRefresh();
      if (event !== undefined) dispatch(event, safeSession, revision);
      return true;
    } catch {
      return false;
    }
  };

  const clearSession = async (emit: boolean): Promise<boolean> => {
    if (disposed) return false;
    const hadSession = currentSession !== null;
    try {
      const revision = await storage.clearSession();
      if (disposed) return false;
      currentSession = null;
      lastRevision = revision;
      stopTimer();
      if (emit && hadSession) dispatch("SIGNED_OUT", null, revision);
      return true;
    } catch {
      currentSession = null;
      stopTimer();
      return false;
    }
  };

  const onRemote = (event: AuthChangeEvent, revision: number): void => {
    if (disposed) return;
    const synchronize = async (): Promise<void> => {
      if (disposed || (revision !== 0 && revision <= lastRevision)) return;
      const previousRevision = lastRevision;
      const sessionValue = await readLatest();
      if (disposed || lastRevision <= previousRevision) return;
      const effectiveEvent = sessionValue === null ? "SIGNED_OUT" : event === "SIGNED_OUT" ? "SIGNED_IN" : event;
      dispatch(effectiveEvent, sessionValue, lastRevision, false);
      scheduleRefresh();
    };
    remoteQueue = clientReflectApply(clientPromiseThen, remoteQueue, [synchronize, synchronize]) as Promise<void>;
  };

  const eventBus: EventBus = createEventBus({ channelName: `mrjim-auth:${snapshot.auth.storageKey}:events`, storageKey: storage.sessionKey, debug, onRemote });

  const stopTimer = (): void => {
    if (refreshTimer !== undefined) {
      clientClearTimeout(refreshTimer);
      refreshTimer = undefined;
    }
  };

  const scheduleRefresh = (minimumDelay = 50): void => {
    stopTimer();
    if (disposed || !autoRefreshRunning || !documentVisible || currentSession === null) return;
    const delay = clientMathMax(minimumDelay, currentSession.expires_at * 1000 - clientDateNow() - AUTO_REFRESH_SKEW_MS);
    refreshTimer = clientSetTimeout(() => {
      refreshTimer = undefined;
      if (disposed || !autoRefreshRunning) return;
      void (async () => {
        try {
          const result = await refreshSessionInternal(undefined, true);
          scheduleRefresh(result.error === null ? 50 : MIN_RETRY_MS);
        } catch {
          scheduleRefresh(MIN_RETRY_MS);
        }
      })();
    }, clientMathMin(delay, 2_147_000_000));
  };

  const refreshSessionInternal = async (supplied: Session | undefined, emit: boolean): Promise<AuthResult<SessionData>> => {
    const requested = supplied === undefined ? currentSession : copySession(supplied);
    try {
      return await lock.run(async () => {
        const latest = await readLatest();
        const candidate = latest ?? requested;
        if (candidate === null) return authFailure(expectedError("session_expired", 401, "Session is missing"));
        if (requested !== null && latest !== null && latest.refresh_token !== requested.refresh_token) {
          if (emit) dispatch("TOKEN_REFRESHED", latest, lastRevision, false);
          scheduleRefresh();
          return sessionResult(latest);
        }
        const result = await transport.request({ method: "POST", path: "/token", query: [["grant_type", "refresh_token"]], body: { refresh_token: candidate.refresh_token }, operation: "refreshSession" });
        if (result.error !== null) {
          if (result.error.code === "invalid_token" || result.error.code === "token_expired" || result.error.code === "refresh_token_reused" || result.error.code === "session_expired") await clearSession(emit);
          return authFailure(result.error);
        }
        let rotated: Session;
        try { rotated = copySessionResponse(result.data); } catch { return authFailure(internalError()); }
        if (!await commit(rotated, emit ? "TOKEN_REFRESHED" : undefined)) return authFailure(internalError());
        return sessionResult(rotated);
      });
    } catch (error) {
      if (isLockBoundaryError(error)) return authFailure(internalError());
      return authFailure(internalError());
    }
  };

  const ensureReady = async (): Promise<void> => {
    await initialization;
  };

  const exchangeTransaction = async (code: string, transaction: PkceTransaction, event: AuthChangeEvent | undefined): Promise<AuthResult<SessionData>> => {
    try {
      return await lock.run(async () => {
        const consumed = await storage.consumePkce(transaction.id);
        if (consumed === null || consumed.expiresAt <= clientDateNow()) return authFailure(expectedError("invalid_request", 400, "OAuth transaction is invalid"));
        const result = await resultCall(
          () => transport.request({ method: "POST", path: "/exchange", body: { code, code_verifier: consumed.codeVerifier, redirect_to: consumed.redirectTo }, operation: "exchangeCodeForSession" }),
          copyExchange,
        );
        if (result.error !== null) return result;
        if (result.data.session.user.id !== result.data.user.id) return authFailure(internalError());
        if (!await commit(result.data.session, event)) return authFailure(internalError());
        return sessionResult(result.data.session);
      });
    } catch {
      return authFailure(internalError());
    }
  };

  const rawExchange = async (code: string, transaction: PkceTransaction): Promise<{ readonly session: Session; readonly event?: AuthChangeEvent }> => {
    const result = await exchangeTransaction(code, transaction, undefined);
    if (result.error !== null || result.data === null) throw result.error ?? internalError();
    return { session: result.data.session, event: "SIGNED_IN" };
  };

  initialization = snapshot.auth.skipAutoInitialize
    ? clientPromiseResolve()
    : (async () => {
      try {
        const result = await initializeAuthClient({ storage, detectSessionInUrl: snapshot.auth.detectSessionInUrl, debug, exchange: rawExchange });
        if (disposed) return;
        currentSession = result.session === null ? null : copySession(result.session);
        try {
          lastRevision = await storage.readRevision();
        } catch {
          lastRevision = 0;
        }
        dispatch("INITIAL_SESSION", currentSession, lastRevision, false);
        if (result.postEvent !== undefined) dispatch(result.postEvent.event, result.postEvent.session, lastRevision, false);
        scheduleRefresh();
      } catch {
        if (!disposed) dispatch("INITIAL_SESSION", null, lastRevision, false);
      }
    })();

  if (isBrowserRuntime()) {
    try {
      const documentValue = clientGlobal.document;
      if (documentValue !== null && typeof documentValue === "object") {
        const add = captureMethod(documentValue, "addEventListener", "document.addEventListener", "configuration");
        const remove = captureMethod(documentValue, "removeEventListener", "document.removeEventListener", "configuration");
        let current: object | null | undefined = documentValue;
        let visibilityGetter: Function | undefined;
        let visibilityData: string | undefined;
        for (let depth = 0; current !== null && current !== undefined && depth < 16; depth += 1) {
          const descriptor = clientObjectGetOwnPropertyDescriptor(current, "visibilityState");
          if (descriptor !== undefined) {
            if (typeof descriptor.get === "function") visibilityGetter = descriptor.get;
            else if (clientReflectApply(clientObjectHasOwnProperty, descriptor, ["value"]) && typeof descriptor.value === "string") visibilityData = descriptor.value;
            break;
          }
          current = clientObjectGetPrototypeOf(current);
        }
        const readVisibilityState = (): string | undefined => {
          let state = visibilityData;
          try {
            if (visibilityGetter !== undefined) state = clientReflectApply(visibilityGetter, documentValue, []) as string;
          } catch {
            state = undefined;
          }
          return state;
        };
        documentVisible = readVisibilityState() !== "hidden";
        const visibilityListener = (): void => {
          documentVisible = readVisibilityState() !== "hidden";
          if (!documentVisible) {
            stopTimer();
            return;
          }
          void (async () => {
            try {
              await readLatest();
              scheduleRefresh();
            } catch {
              // Visibility changes cannot surface adapter failures.
            }
          })();
        };
        invoke(add.method, add.receiver, ["visibilitychange", visibilityListener]);
        visibilityRemove = () => {
          try {
            invoke(remove.method, remove.receiver, ["visibilitychange", visibilityListener]);
          } catch {
            // Disposal is idempotent and fail-closed.
          }
        };
      }
    } catch {
      safeDebug(debug, "visibility listener unavailable", { source: "visibility" });
    }
  }

  const signUp = (input: SignUpInput): Promise<AuthResult<NullableSessionData>> => {
    const value = validateInput(input, "signUp input");
    const email = requiredString(value, "email", "email", MAX_EMAIL);
    const password = requiredString(value, "password", "password", MAX_PASSWORD);
    const optionsValue = optionalObject(value, "options", "signUp options");
    return contain(async () => {
      await ensureReady();
      const result = await resultCall(() => transport.request({ method: "POST", path: "/signup", body: { email, password, ...(wireOptions(optionsValue) === undefined ? {} : { options: wireOptions(optionsValue) }) }, operation: "signUp" }), copyNullableAuthData);
      if (result.error === null && result.data.session !== null) {
        if (!await commit(result.data.session, "SIGNED_IN")) return authFailure(internalError());
        return nullableSessionResult(result.data.user, result.data.session);
      }
      if (result.error === null && result.data.user !== null) return nullableSessionResult(result.data.user, null);
      return result;
    });
  };

  const signInWithPassword = (input: PasswordSignInInput): Promise<AuthResult<SessionData>> => {
    const value = validateInput(input, "signInWithPassword input");
    const email = requiredString(value, "email", "email", MAX_EMAIL);
    const password = requiredString(value, "password", "password", MAX_PASSWORD);
    return contain(async () => {
      await ensureReady();
      const result = await resultCall(() => transport.request({ method: "POST", path: "/token", query: [["grant_type", "password"]], body: { email, password }, operation: "signInWithPassword" }), copySessionResponse);
      if (result.error !== null) return result;
      if (!await commit(result.data, "SIGNED_IN")) return authFailure(internalError());
      return sessionResult(result.data);
    });
  };

  const signInWithOtp = (input: OtpSignInInput): Promise<AuthResult<NullableSessionData>> => {
    const value = validateInput(input, "signInWithOtp input");
    const email = requiredString(value, "email", "email", MAX_EMAIL);
    const optionsValue = optionalObject(value, "options", "OTP options");
    const type = optionsValue === undefined ? undefined : (() => { const item = ownData(optionsValue, "type"); if (!item.ok || !item.present) return undefined; return wireOtpType(item.value); })();
    const redirect = redirectFrom(optionsValue);
    return contain(async () => {
      await ensureReady();
      const wire = { email, ...(type === undefined && redirect === undefined ? {} : { options: { ...(type === undefined ? {} : { type }), ...(redirect === undefined ? {} : { redirect_to: redirect }) } }) };
      const result = await resultCall(() => transport.request({ method: "POST", path: "/otp", body: wire, operation: "signInWithOtp" }), copyNullableAuthData);
      if (result.error === null && result.data.session !== null) {
        if (!await commit(result.data.session, "SIGNED_IN")) return authFailure(internalError());
      }
      return result;
    });
  };

  const verifyOtp = (input: VerifyOtpInput): Promise<AuthResult<NullableSessionData>> => {
    const value = validateInput(input, "verifyOtp input");
    const email = requiredString(value, "email", "email", MAX_EMAIL);
    const token = requiredString(value, "token", "token", 512);
    const typeValue = ownData(value, "type");
    if (!typeValue.ok || !typeValue.present) throw new AuthProgrammingError("OTP type is required");
    const type = wireOtpType(typeValue.value);
    const optionsValue = optionalObject(value, "options", "verification options");
    const redirect = redirectFrom(optionsValue);
    return contain(async () => {
      await ensureReady();
      const body = { email, token, type, ...(redirect === undefined ? {} : { redirect_to: redirect }) };
      const result = await resultCall(() => transport.request({ method: "POST", path: "/verify", body, operation: "verifyOtp" }), copyNullableAuthData);
      if (result.error === null && result.data.session !== null) {
        if (!await commit(result.data.session, "SIGNED_IN")) return authFailure(internalError());
      }
      return result;
    });
  };

  const startOAuth = (input: OAuthInput, flow: PkceTransaction["flow"]): Promise<AuthResult<OAuthData>> => {
    const value = validateInput(input, "OAuth input");
    const provider = requiredString(value, "provider", "provider", MAX_PROVIDER);
    const optionsValue = optionalObject(value, "options", "OAuth options");
    const redirect = redirectFrom(optionsValue);
    const skip = optionsValue === undefined ? false : (() => { const item = ownData(optionsValue, "skipBrowserRedirect"); if (!item.ok || !item.present) return false; if (typeof item.value !== "boolean") throw new AuthProgrammingError("skipBrowserRedirect is malformed"); return item.value; })();
    return contain(async () => {
      await ensureReady();
      if (flow === "link_identity") {
        const existing = await readLatest();
        if (existing === null) return authFailure(expectedError("unauthorized", 401, "Authenticated session is required"));
      }
      const pair = await generatePkcePair();
      const exactRedirect = redirect ?? readAuthUrl()?.cleanedHref ?? `${transport.baseUrl}/callback`;
      const transactionId = safeStringSlice(pair.codeChallenge, 0, 24);
      if (transactionId === null) return authFailure(internalError());
      const transaction: PkceTransaction = freeze({ id: transactionId, provider, flow, codeVerifier: pair.codeVerifier, codeChallenge: pair.codeChallenge, redirectTo: exactRedirect, createdAt: clientDateNow(), expiresAt: clientDateNow() + 10 * 60_000 });
      await lock.run(() => storage.writePkce(transaction));
      const bearer = flow === "link_identity" ? currentSession?.access_token : undefined;
      const query: Array<readonly [string, string]> = [["provider", provider], ["code_challenge", pair.codeChallenge], ["code_challenge_method", "S256"], ["flow", flow], ["redirect_to", exactRedirect]];
      const result = await resultCall(() => transport.request({ method: "GET", path: "/authorize", query, bearer, operation: flow === "link_identity" ? "linkIdentity" : "signInWithOAuth" }), (data) => {
        const authorize = copyAuthorize(data);
        if (authorize.provider !== provider || authorize.redirect !== exactRedirect) throw new AuthProgrammingError("OAuth response is malformed");
        return { provider: authorize.provider, url: authorize.url };
      });
      if (result.error !== null) {
        await lock.run(() => storage.consumePkce(transaction.id));
        return result;
      }
      if (!skip) {
        try {
          const location = clientGlobal.location;
          if (location !== null && typeof location === "object") {
            const assign = captureMethod(location, "assign", "location.assign");
            invoke(assign.method, assign.receiver, [result.data.url]);
          }
        } catch {
          safeDebug(debug, "browser redirect unavailable", { operation: flow === "link_identity" ? "linkIdentity" : "signInWithOAuth" });
        }
      }
      return result;
    });
  };

  const signInWithOAuth = (input: OAuthInput): Promise<AuthResult<OAuthData>> => startOAuth(input, "sign_in");
  const linkIdentity = (input: OAuthInput): Promise<AuthResult<OAuthData>> => startOAuth(input, "link_identity");

  const exchangeCodeForSession = (code: string): Promise<AuthResult<SessionData>> => {
    const safeCode = trimString(code, "exchange code", 512);
    return contain(async () => {
      await ensureReady();
      const transaction = await storage.findPkce();
      if (transaction === null || transaction.expiresAt <= clientDateNow()) return authFailure(expectedError("invalid_request", 400, "OAuth transaction is invalid"));
      return exchangeTransaction(safeCode, transaction, "SIGNED_IN");
    });
  };

  const resetPasswordForEmail = (emailInput: string, optionsValue?: RecoveryOptions): Promise<AuthResult<{ readonly sent: true }>> => {
    const email = trimString(emailInput, "email", MAX_EMAIL);
    const optionsObject = optionsValue === undefined ? undefined : validateInput(optionsValue, "recovery options");
    const redirect = redirectFrom(optionsObject);
    return contain(async () => {
      await ensureReady();
      return resultCall(() => transport.request({ method: "POST", path: "/recover", body: { email, ...(redirect === undefined ? {} : { redirect_to: redirect }) }, operation: "resetPasswordForEmail" }), copySent);
    });
  };

  const resetPassword = (input: ResetPasswordInput): Promise<AuthResult<{ readonly user: User }>> => {
    const value = validateInput(input, "resetPassword input");
    const email = requiredString(value, "email", "email", MAX_EMAIL);
    const token = requiredString(value, "token", "recovery token", MAX_RECOVERY_TOKEN);
    const password = recoveryPassword(value);
    const optionsValue = optionalObject(value, "options", "recovery options");
    const redirect = redirectFrom(optionsValue);
    return contain(async () => {
      await ensureReady();
      const result = await resultCall(
        () => transport.request({ method: "POST", path: "/recover/verify", body: { email, token, password, ...(redirect === undefined ? {} : { redirect_to: redirect }) }, operation: "resetPassword" }),
        (response) => ({ user: copyUserResponse(response) }),
      );
      if (result.error === null) {
        await clearSession(false);
        dispatch("PASSWORD_RECOVERY", null, 0, false);
      }
      return result;
    });
  };

  const resend = (input: ResendInput): Promise<AuthResult<{ readonly sent: true }>> => {
    const value = validateInput(input, "resend input");
    const type = requiredString(value, "type", "resend type", 32);
    if (type !== "signup" && type !== "recovery") throw new AuthProgrammingError("resend type is malformed");
    const email = requiredString(value, "email", "email", MAX_EMAIL);
    const optionsValue = optionalObject(value, "options", "resend options");
    const redirect = redirectFrom(optionsValue);
    return contain(async () => {
      await ensureReady();
      return resultCall(() => transport.request({ method: "POST", path: "/resend", body: { type, email, ...(redirect === undefined ? {} : { options: { redirect_to: redirect } }) }, operation: "resend" }), copySent);
    });
  };

  const getSession = (): Promise<AuthResult<{ readonly session: Session | null }>> => contain(async () => {
    await ensureReady();
    const sessionValue = await readLatest();
    return authSuccess({ session: sessionValue === null ? null : copySession(sessionValue) });
  });

  const getUser = (jwt?: string): Promise<AuthResult<{ readonly user: User }>> => {
    const explicit = jwt === undefined ? undefined : trimString(jwt, "access token", 8192);
    return contain(async () => {
      await ensureReady();
      const sessionValue = explicit === undefined ? await readLatest() : currentSession;
      const bearer = explicit ?? sessionValue?.access_token;
      if (bearer === undefined) return authFailure(expectedError("unauthorized", 401, "Authenticated session is required"));
      return resultCall(
        () => transport.request({ method: "GET", path: "/user", bearer, operation: "getUser" }),
        (value) => ({ user: copyUserResponse(value) }),
      );
    });
  };

  const setSession = (value: Session): Promise<AuthResult<SessionData>> => {
    const supplied = copySession(value);
    return contain(async () => {
      await ensureReady();
      if (supplied.expires_at <= currentUnixSeconds()) return refreshSessionInternal(supplied, true);
      const result = await resultCall(
        () => transport.request({ method: "GET", path: "/user", bearer: supplied.access_token, operation: "setSession" }),
        (response) => ({ user: copyUserResponse(response) }),
      );
      if (result.error !== null) return result;
      const validated = freeze({ ...supplied, user: result.data.user });
      if (!await commit(validated, "SIGNED_IN")) return authFailure(internalError());
      return sessionResult(validated);
    });
  };

  const refreshSession = (value?: Session): Promise<AuthResult<SessionData>> => {
    const supplied = value === undefined ? undefined : copySession(value);
    if (refreshPromise !== undefined) return refreshPromise;
    refreshPromise = (async () => {
      try {
        await ensureReady();
        return await refreshSessionInternal(supplied, true);
      } finally {
        refreshPromise = undefined;
      }
    })();
    return refreshPromise;
  };

  const updateUser = (attributes: UpdateUserAttributes): Promise<AuthResult<{ readonly user: User }>> => {
    const value = validateInput(attributes, "updateUser attributes");
    const email = optionalString(value, "email", "email", MAX_EMAIL);
    const dataValue = optionalObject(value, "data", "user metadata");
    const redirect = redirectFrom(value);
    const unsupportedPassword = ownData(value, "password");
    const unsupportedPhone = ownData(value, "phone");
    if ((unsupportedPassword.ok && unsupportedPassword.present) || (unsupportedPhone.ok && unsupportedPhone.present)) throw new AuthProgrammingError("password and phone updates are not supported by the current HTTP contract");
    return contain(async () => {
      await ensureReady();
      const sessionValue = await readLatest();
      if (sessionValue === null) return authFailure(expectedError("unauthorized", 401, "Authenticated session is required"));
      const body = { ...(email === undefined ? {} : { email }), ...(dataValue === undefined ? {} : { user_metadata: copyJsonObject(dataValue, "user metadata") }), ...(redirect === undefined ? {} : { redirect_to: redirect }) };
      const result = await resultCall(
        () => transport.request({ method: "PUT", path: "/user", body, bearer: sessionValue.access_token, operation: "updateUser" }),
        (response) => ({ user: copyUserResponse(response) }),
      );
      if (result.error !== null) return result;
      const next = freeze({ ...sessionValue, user: result.data.user });
      if (!await commit(next, "USER_UPDATED")) return authFailure(internalError());
      return authSuccess({ user: result.data.user });
    });
  };

  const updatePassword = (input: UpdatePasswordInput): Promise<AuthResult<{ readonly user: User }>> => {
    const value = validateInput(input, "updatePassword input");
    const currentPassword = passwordValue(value, "currentPassword", "current password");
    const password = recoveryPassword(value);
    const revokeOtherSessionsValue = optionValue(value, "revokeOtherSessions", "revokeOtherSessions");
    if (revokeOtherSessionsValue !== undefined && typeof revokeOtherSessionsValue !== "boolean") {
      throw new AuthProgrammingError("revokeOtherSessions is malformed");
    }
    return contain(async () => {
      await ensureReady();
      const sessionValue = await readLatest();
      if (sessionValue === null) return authFailure(expectedError("unauthorized", 401, "Authenticated session is required"));
      const body = {
        current_password: currentPassword,
        password,
        ...(revokeOtherSessionsValue === undefined ? {} : { revoke_other_sessions: revokeOtherSessionsValue }),
      };
      const result = await resultCall(
        () => transport.request({ method: "PUT", path: "/user/password", body, bearer: sessionValue.access_token, operation: "updatePassword" }),
        (response) => ({ user: copyUserResponse(response) }),
      );
      if (result.error !== null) return result;
      const next = freeze({ ...sessionValue, user: result.data.user });
      if (!await commit(next, "USER_UPDATED")) return authFailure(internalError());
      return authSuccess({ user: result.data.user });
    });
  };

  const getUserIdentities = (): Promise<AuthResult<{ readonly identities: readonly Identity[] }>> => contain(async () => {
    await ensureReady();
    const sessionValue = await readLatest();
    if (sessionValue === null) return authFailure(expectedError("unauthorized", 401, "Authenticated session is required"));
    return resultCall(() => transport.request({ method: "GET", path: "/user/identities", bearer: sessionValue.access_token, operation: "getUserIdentities" }), (value) => ({ identities: copyIdentities(value) }));
  });

  const unlinkIdentity = (identityValue: Pick<Identity, "id"> | Identity): Promise<AuthResult<null>> => {
    const value = validateInput(identityValue, "identity");
    const id = requiredString(value, "id", "identity id", 128);
    return contain(async () => {
      await ensureReady();
      const sessionValue = await readLatest();
      if (sessionValue === null) return authFailure(expectedError("unauthorized", 401, "Authenticated session is required"));
      return resultCall(() => transport.request({ method: "DELETE", path: `/user/identities/${encodeURIComponent(id)}`, bearer: sessionValue.access_token, operation: "unlinkIdentity" }), (data) => { if (data !== null) throw new AuthProgrammingError("unlink response is malformed"); return null; });
    });
  };

  const getPermissions = (optionsValue?: { readonly scope?: PermissionScope }): Promise<AuthResult<{ readonly permissions: readonly string[] }>> => {
    const optionsObject = optionsValue === undefined ? undefined : validateInput(optionsValue, "permission options");
    const scopeValue = optionsObject === undefined ? undefined : optionalObject(optionsObject, "scope", "permission scope");
    const scopeType = scopeValue === undefined ? undefined : requiredString(scopeValue, "type", "scope type", 64);
    const scopeId = scopeValue === undefined ? undefined : requiredString(scopeValue, "id", "scope id", 256);
    return contain(async () => {
      await ensureReady();
      const sessionValue = await readLatest();
      if (sessionValue === null) return authFailure(expectedError("unauthorized", 401, "Authenticated session is required"));
      const query: Array<readonly [string, string]> = [];
      if (scopeType !== undefined && scopeId !== undefined) {
        clientArrayPush.call(query, ["scope_type", scopeType]);
        clientArrayPush.call(query, ["scope_id", scopeId]);
      }
      return resultCall(() => transport.request({ method: "GET", path: "/user/permissions", query, bearer: sessionValue.access_token, operation: "getPermissions" }), (value) => ({ permissions: copyPermissions(value) }));
    });
  };

  const signOut = (optionsValue?: { readonly scope?: SignOutScope }): Promise<AuthResult<null>> => {
    const optionsObject = optionsValue === undefined ? undefined : validateInput(optionsValue, "signOut options");
    const scopeValue = optionsObject === undefined ? "local" : optionValue(optionsObject, "scope", "signOut scope") ?? "local";
    if (scopeValue !== "local" && scopeValue !== "global" && scopeValue !== "others") throw new AuthProgrammingError("signOut scope is malformed");
    const scope = scopeValue as SignOutScope;
    return contain(async () => {
      await ensureReady();
      const sessionValue = await readLatest();
      if (sessionValue === null) return authSuccess(null);
      const result = await resultCall(() => transport.request({ method: "POST", path: "/logout", body: { scope }, bearer: sessionValue.access_token, operation: "signOut" }), (value) => { if (value !== null) throw new AuthProgrammingError("logout response is malformed"); return null; });
      if (scope !== "others") {
        const cleared = await clearSession(true);
        if (!cleared && result.error === null) return authFailure(internalError());
      }
      return result;
    });
  };

  const onAuthStateChange = (callback: AuthStateCallback): AuthSubscription => {
    if (typeof callback !== "function") throw new AuthProgrammingError("auth state callback must be a function");
    return eventBus.subscribe(callback);
  };

  const startAutoRefresh = (): void => {
    if (disposed) return;
    autoRefreshRunning = true;
    scheduleRefresh();
  };

  const stopAutoRefresh = (): void => {
    autoRefreshRunning = false;
    stopTimer();
  };

  const dispose = (): void => {
    if (disposed) return;
    disposed = true;
    autoRefreshRunning = false;
    stopTimer();
    visibilityRemove?.();
    visibilityRemove = undefined;
    transport.dispose();
    eventBus.dispose();
  };

  const auth: AuthNamespace = freeze({
    signUp,
    signInWithPassword,
    signInWithOtp,
    verifyOtp,
    signInWithOAuth,
    exchangeCodeForSession,
    resetPasswordForEmail,
    resetPassword,
    resend,
    getSession,
    getUser,
    setSession,
    refreshSession,
    updateUser,
    updatePassword,
    getUserIdentities,
    linkIdentity,
    unlinkIdentity,
    getPermissions,
    signOut,
    onAuthStateChange,
    startAutoRefresh,
    stopAutoRefresh,
    dispose,
  });
  return freeze({ auth });
}
