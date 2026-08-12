import { createHmac, randomUUID, timingSafeEqual } from "node:crypto";
import { z } from "zod";
import {
  AuthApiError,
  AuthConfigurationError,
  isPublicAuthErrorCode,
  type PublicAuthErrorCode,
} from "../shared/errors.js";
import type { AuthRepository, Mailer, RateLimiter } from "../shared/contracts.js";
import type { AuthServerOptions } from "../shared/config.js";
import { uuidSchema, type Session, type User } from "../shared/types.js";
import { createAuthorizationRequestContext, type AuthorizationRequestContext, type AuthorizationRequirement, type AuthorizationSubject } from "./authorization.js";
import type { AuthenticatedSession } from "./sessions.js";
import type { AccessTokenClaims } from "./tokens.js";
import { handlePublicRoute } from "./routes/public.js";
import { handleUserRoute } from "./routes/user.js";
import { handleAdminRoute } from "./routes/admin.js";
import {
  boundaryDataProperty,
  boundaryHasThen,
  boundaryIsArray,
  assertBoundaryObject,
  boundaryOwnDataProperty,
  captureBoundaryBytes,
  captureBoundaryMethodGroup,
  captureBoundaryRepository,
  captureBoundaryStringArray,
  requiredBoundaryOption,
} from "./callback-boundary.js";
import {
  routeContracts,
  refreshTokenRequestSchema,
  signupRequestSchema,
  userSchema,
  type AuthServerServices,
  type RouteAuthContext,
  type RouteContext,
  type RouteContract,
  type RouteOutput,
} from "./routes/contracts.js";

const nativeRequest = Request;
const nativeResponse = Response;
const nativeHeaders = Headers;
const nativeURL = URL;
const nativeURLSearchParams = URLSearchParams;
const nativeUint8Array = Uint8Array;
const nativeUint8ArrayFrom = nativeUint8Array.from.bind(nativeUint8Array);
const nativeTextDecoder = TextDecoder;
const nativePromise = Promise;
const nativePromisePrototype = Promise.prototype;
const nativePromiseThen = Promise.prototype.then;
const nativeString = String;
const nativeObjectPrototype = Object.prototype;
const nativeArrayIsArray = Array.isArray;
const nativeArrayPush = Array.prototype.push;
const nativeSet = Set;
const nativeSetHas = Set.prototype.has;
const nativeSetAdd = Set.prototype.add;
const nativeSetDelete = Set.prototype.delete;
const authNumberIsFinite = Number.isFinite;
const authNumberIsInteger = Number.isInteger;
const authNumberIsSafeInteger = Number.isSafeInteger;
const objectDefineProperty = Object.defineProperty;
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const objectGetOwnPropertyNames = Object.getOwnPropertyNames;
const objectGetOwnPropertySymbols = Object.getOwnPropertySymbols;
const objectGetPrototypeOf = Object.getPrototypeOf;
const objectCreate = Object.create;
const objectFreeze = Object.freeze;
const reflectApply = Reflect.apply;
const jsonParse = JSON.parse;
const jsonStringify = JSON.stringify;
const headersGet = captureMethod(nativeHeaders.prototype, "get");
const headersSet = captureMethod(nativeHeaders.prototype, "set");
const requestMethodGetter = captureGetter(nativeRequest.prototype, "method");
const requestUrlGetter = captureGetter(nativeRequest.prototype, "url");
const requestHeadersGetter = captureGetter(nativeRequest.prototype, "headers");
const requestBodyGetter = captureGetter(nativeRequest.prototype, "body");
const urlSearchParamsGetter = captureGetter(nativeURL.prototype, "searchParams");
const searchParamsGet = captureMethod(nativeURLSearchParams.prototype, "get");
const searchParamsGetAll = captureMethod(nativeURLSearchParams.prototype, "getAll");
const searchParamsKeys = captureMethod(nativeURLSearchParams.prototype, "keys");
const searchParamsIteratorNext = captureIteratorNext();
const readableStreamGetReader = captureMethod(ReadableStream.prototype, "getReader");
const readableReaderRead = captureMethod(ReadableStreamDefaultReader.prototype, "read");
const readableReaderCancel = captureMethod(ReadableStreamDefaultReader.prototype, "cancel");
const readableReaderReleaseLock = captureMethod(ReadableStreamDefaultReader.prototype, "releaseLock");
const typedArrayPrototype = objectGetPrototypeOf(nativeUint8Array.prototype);
const typedArrayLengthGetter = (() => {
  const descriptor = objectGetOwnPropertyDescriptor(typedArrayPrototype, "length");
  if (descriptor === undefined || typeof descriptor.get !== "function") {
    throw new AuthConfigurationError("required typed-array length getter is unavailable");
  }
  return descriptor.get;
})();
const typedArraySet = captureMethod(typedArrayPrototype, "set");
const dateGetTime = Function.prototype.call.bind(Date.prototype.getTime) as (value: Date) => number;
const apiKeyRecordSchema = z.object({
  id: z.string().uuid(),
  prefix: z.string().min(1).max(128),
  kind: z.enum(["publishable", "secret"]),
  scopes: z.array(z.string()),
  expires_at: z.union([z.instanceof(Date), z.null()]),
  revoked_at: z.union([z.instanceof(Date), z.null()]),
}).strict();
const accessClaimsSchema = z.object({
  iss: z.string().min(1),
  aud: z.union([z.string().min(1), z.array(z.string().min(1)).min(1)]),
  sub: z.string().uuid(),
  sid: z.string().uuid(),
  aal: z.number().int().min(1).max(3),
  iat: z.number().int().nonnegative(),
  exp: z.number().int().positive(),
}).strict();

const MAX_BODY_BYTES = 64 * 1024;
const MAX_SNAPSHOT_DEPTH = 32;
const MAX_SNAPSHOT_KEYS = 100_000;
const ALLOWED_REQUEST_HEADERS = ["apikey", "authorization", "content-type", "x-request-id"] as const;
const SAFE_CACHE_CONTROL = "public, max-age=300, must-revalidate";
const FETCH_SITE_VALUES = ["cross-site", "same-origin", "same-site", "none"] as const;
const FETCH_MODE_VALUES = ["cors", "navigate", "no-cors", "same-origin", "websocket"] as const;
const FETCH_DEST_VALUES = ["audio", "audioworklet", "document", "embed", "empty", "font", "frame", "iframe", "image", "manifest", "object", "paintworklet", "report", "script", "serviceworker", "sharedworker", "style", "track", "video", "worker", "xslt"] as const;
const FETCH_USER_VALUES = ["?0", "?1"] as const;

type DataProperty =
  | { readonly valid: true; readonly present: false }
  | { readonly valid: true; readonly present: true; readonly value: unknown }
  | { readonly valid: false; readonly present: boolean };

type RequestMeta = {
  readonly request: Request;
  readonly method: string;
  readonly url: URL;
  readonly headers: Headers;
  readonly requestId: string;
  readonly apiKey: HeaderValue;
  readonly authorization: HeaderValue;
  readonly contentLength: HeaderValue;
  readonly contentType: HeaderValue;
  readonly contentEncoding: HeaderValue;
  readonly accessControlRequestMethod: HeaderValue;
  readonly accessControlRequestHeaders: HeaderValue;
  readonly origin: string | null;
  readonly browserMarked: boolean;
};

type HeaderValue =
  | { readonly state: "absent" }
  | { readonly state: "valid"; readonly value: string }
  | { readonly state: "invalid" };

type FetchMetadataState = "absent" | "present" | "invalid";

type SafeResult =
  | { readonly ok: true; readonly data: unknown }
  | { readonly ok: false; readonly code: PublicAuthErrorCode; readonly status: number };

class RequestBoundaryError extends Error {
  readonly status: number;
  readonly code: PublicAuthErrorCode;

  constructor(code: PublicAuthErrorCode, status: number) {
    super(code);
    this.name = "RequestBoundaryError";
    this.code = code;
    this.status = status;
  }
}

function captureGetter(target: object, key: PropertyKey): Function {
  const descriptor = objectGetOwnPropertyDescriptor(target, key);
  if (descriptor === undefined || typeof descriptor.get !== "function") {
    throw new AuthConfigurationError(`required Web API getter is unavailable: ${nativeString(key)}`);
  }
  return descriptor.get;
}

function captureMethod(target: object, key: PropertyKey): Function {
  const descriptor = objectGetOwnPropertyDescriptor(target, key);
  if (descriptor === undefined || typeof descriptor.value !== "function") {
    throw new AuthConfigurationError(`required Web API method is unavailable: ${nativeString(key)}`);
  }
  return descriptor.value;
}

function captureIteratorNext(): Function {
  const iterator = reflectApply(searchParamsKeys, new nativeURLSearchParams(), []) as Iterator<string>;
  const prototype = objectGetPrototypeOf(iterator);
  if (prototype === null) throw new AuthConfigurationError("URLSearchParams iterator is unavailable");
  const descriptor = objectGetOwnPropertyDescriptor(prototype, "next");
  if (descriptor === undefined || typeof descriptor.value !== "function") {
    throw new AuthConfigurationError("URLSearchParams iterator is unavailable");
  }
  return descriptor.value;
}

function invoke<T>(method: Function, receiver: unknown, args: readonly unknown[]): T {
  return reflectApply(method, receiver, args as unknown[]) as T;
}

function containsExact(values: readonly string[], candidate: string): boolean {
  for (let index = 0; index < values.length; index += 1) {
    if (values[index] === candidate) return true;
  }
  return false;
}

function appendInternal<T>(values: T[], value: T): void {
  invoke(nativeArrayPush, values, [value]);
}

function setHasInternal<T>(set: Set<T>, value: T): boolean {
  return invoke<boolean>(nativeSetHas, set, [value]);
}

function setAddInternal<T>(set: Set<T>, value: T): void {
  invoke(nativeSetAdd, set, [value]);
}

function setDeleteInternal<T>(set: Set<T>, value: T): boolean {
  return invoke<boolean>(nativeSetDelete, set, [value]);
}

function readHeaderValue(headers: object, name: string): HeaderValue {
  let value: unknown;
  try {
    value = invoke<unknown>(headersGet, headers, [name]);
  } catch {
    return { state: "invalid" };
  }
  if (value === null) return { state: "absent" };
  if (
    typeof value !== "string"
    || value.length === 0
    || runtimeStringIncludes(value, ",")
    || runtimeStringIncludes(value, "\r")
    || runtimeStringIncludes(value, "\n")
  ) return { state: "invalid" };
  return { state: "valid", value };
}

function readListHeaderValue(headers: object, name: string): HeaderValue {
  let value: unknown;
  try {
    value = invoke<unknown>(headersGet, headers, [name]);
  } catch {
    return { state: "invalid" };
  }
  if (value === null) return { state: "absent" };
  if (typeof value !== "string" || value.length === 0 || runtimeStringIncludes(value, "\r") || runtimeStringIncludes(value, "\n")) {
    return { state: "invalid" };
  }
  return { state: "valid", value };
}

function ownDataProperty(value: object, key: PropertyKey): DataProperty {
  try {
    const descriptor = objectGetOwnPropertyDescriptor(value, key);
    if (descriptor === undefined) return { valid: true, present: false };
    if (!("value" in descriptor)) return { valid: false, present: true };
    return { valid: true, present: true, value: descriptor.value };
  } catch {
    return { valid: false, present: false };
  }
}

const USER_SERVICE_METHODS = ["signUp", "signIn", "signInWithOtp", "verifyOtp", "resetPasswordForEmail", "resetPassword", "resend", "updateUser"] as const;
const SESSION_SERVICE_METHODS = ["refresh", "authorizeSession", "signOut"] as const;
const TOKEN_SERVICE_METHODS = ["verifyAccessToken", "jwks"] as const;
const AUTHORIZATION_SERVICE_METHODS = ["getPermissions", "authorize"] as const;
const OAUTH_SERVICE_METHODS = ["listProviders", "authorize", "callback", "exchangeCode", "listIdentities", "unlinkIdentity"] as const;
const ADMIN_SERVICE_METHODS = ["listUsers", "getUserById", "findUser", "createUser", "updateUserById", "deleteUser", "inviteUserByEmail", "listRoles", "createRole", "updateRole", "deleteRole", "setRolePermissions", "setRoleInheritance", "assignRole", "unassignRole", "listPermissions", "createPermission", "updatePermission", "deletePermission", "listAudit"] as const;
const AUTH_SERVER_SERVICE_MEMBERS = ["users", "sessions", "tokens", "authorization", "oauth", "admin"] as const;

function capturedService(
  member: typeof AUTH_SERVER_SERVICE_MEMBERS[number],
  value: unknown,
): unknown {
  if (member === "users") return captureBoundaryMethodGroup(value, "user", USER_SERVICE_METHODS);
  if (member === "sessions") return captureBoundaryMethodGroup(value, "session", SESSION_SERVICE_METHODS, ["revokeRefreshToken"]);
  if (member === "tokens") return captureBoundaryMethodGroup(value, "token", TOKEN_SERVICE_METHODS);
  if (member === "authorization") return captureBoundaryMethodGroup(value, "authorization", AUTHORIZATION_SERVICE_METHODS);
  if (member === "admin") return captureBoundaryMethodGroup(value, "admin", ADMIN_SERVICE_METHODS);
  return captureBoundaryMethodGroup(value, "OAuth", OAUTH_SERVICE_METHODS);
}

/** Captures a partial service composition before schema/default access. */
export function captureAuthServerServiceOverrides(value: unknown): Partial<AuthServerServices> {
  assertBoundaryObject(value, "auth server service composition");
  const source = value as object;
  const facade = objectCreate(null) as Record<string, unknown>;
  for (let index = 0; index < AUTH_SERVER_SERVICE_MEMBERS.length; index += 1) {
    const member = AUTH_SERVER_SERVICE_MEMBERS[index];
    if (member === undefined) throw new AuthConfigurationError("auth server service composition is incomplete");
    const property = boundaryOwnDataProperty(source, member);
    if (!property.valid) throw new AuthConfigurationError(`auth server ${member} must be a data property`);
    if (!property.present || ((member === "oauth" || member === "admin") && property.value === undefined)) continue;
    objectDefineProperty(facade, member, {
      configurable: false,
      enumerable: true,
      writable: false,
      value: capturedService(member, property.value),
    });
  }
  return objectFreeze(facade) as Partial<AuthServerServices>;
}

/** Captures all service callbacks without mutating the caller's composition. */
export function captureAuthServerServices(value: AuthServerServices): AuthServerServices {
  const captured = captureAuthServerServiceOverrides(value) as Record<string, unknown>;
  const requiredMembers = ["users", "sessions", "tokens", "authorization"] as const;
  for (let index = 0; index < requiredMembers.length; index += 1) {
    const member = requiredMembers[index];
    if (member === undefined) throw new AuthConfigurationError("auth server service composition is incomplete");
    const property = boundaryOwnDataProperty(captured, member);
    if (!property.valid || !property.present) throw new AuthConfigurationError(`auth server ${member} is unavailable`);
  }
  return captured as unknown as AuthServerServices;
}

/** Captures the configured mail-delivery callback before schema inspection. */
export function captureAuthServerMailer(value: Mailer): Mailer {
  return captureBoundaryMethodGroup(value, "email", ["send"]) as unknown as Mailer;
}

/** Captures the configured rate-limit callback before schema inspection. */
export function captureAuthServerRateLimiter(value: RateLimiter): RateLimiter {
  return captureBoundaryMethodGroup(value, "rateLimiter", ["consume"]) as unknown as RateLimiter;
}

/** Captures every repository callback used by the server and default services. */
export function captureAuthServerRepository(value: AuthRepository): AuthRepository {
  return captureBoundaryRepository(value);
}

function isAsciiAlphaNumeric(value: string | undefined): boolean {
  if (value === undefined) return false;
  return (value >= "a" && value <= "z") || (value >= "A" && value <= "Z") || (value >= "0" && value <= "9");
}

function validRequestId(value: unknown): value is string {
  if (typeof value !== "string" || value.length < 1 || value.length > 128 || !isAsciiAlphaNumeric(value[0])) return false;
  for (let index = 1; index < value.length; index += 1) {
    const character = value[index];
    if (character === undefined || (!isAsciiAlphaNumeric(character) && character !== "_" && character !== "-")) return false;
  }
  return true;
}

function readFetchMetadata(headers: object): FetchMetadataState {
  const fields: readonly [string, readonly string[]][] = [
    ["sec-fetch-site", FETCH_SITE_VALUES],
    ["sec-fetch-mode", FETCH_MODE_VALUES],
    ["sec-fetch-dest", FETCH_DEST_VALUES],
    ["sec-fetch-user", FETCH_USER_VALUES],
  ];
  let present = false;
  for (let index = 0; index < fields.length; index += 1) {
    const field = fields[index];
    if (field === undefined) return "invalid";
    const [name, allowed] = field;
    const header = readHeaderValue(headers, name);
    if (header.state === "invalid") return "invalid";
    if (header.state === "absent") continue;
    present = true;
    if (runtimeStringTrim(header.value) !== header.value || !containsExact(allowed, header.value)) return "invalid";
  }
  return present ? "present" : "absent";
}

function nativePromiseValue(value: unknown): Promise<unknown> {
  if (
    value === null ||
    (typeof value !== "object" && typeof value !== "function") ||
    objectGetPrototypeOf(value) !== nativePromisePrototype ||
    objectGetOwnPropertyDescriptor(value, "then") !== undefined
  ) {
    throw new RequestBoundaryError("internal_error", 500);
  }
  const outcome = new nativePromise((resolve) => {
    let settled = false;
    const finish = (ok: boolean, result: unknown) => {
      if (settled) return;
      settled = true;
      resolve({ ok, result });
    };
    try {
      invoke(nativePromiseThen, value, [
        (result: unknown) => finish(true, result),
        (_reason: unknown) => finish(false, undefined),
      ]);
    } catch {
      finish(false, undefined);
    }
  });
  return new nativePromise((resolve, reject) => {
    invoke(nativePromiseThen, outcome, [
      (value: unknown) => {
        if (value === null || typeof value !== "object") {
          reject(new RequestBoundaryError("internal_error", 500));
          return;
        }
        const result = value as { readonly ok?: unknown; readonly result?: unknown };
        if (result.ok !== true || hasThenValue(result.result)) {
          reject(new RequestBoundaryError("internal_error", 500));
          return;
        }
        resolve(result.result);
      },
      () => reject(new RequestBoundaryError("internal_error", 500)),
    ]);
  });
}

function drainNativePromise(value: unknown): void {
  try {
    if (
      value === null ||
      (typeof value !== "object" && typeof value !== "function") ||
      objectGetPrototypeOf(value) !== nativePromisePrototype ||
      objectGetOwnPropertyDescriptor(value, "then") !== undefined
    ) return;
    invoke(nativePromiseThen, value, [() => undefined, () => undefined]);
  } catch {
    // Cancellation is best effort and must not change the stable request result.
  }
}

function cancelReader(reader: unknown): void {
  try {
    drainNativePromise(invoke(readableReaderCancel, reader, []));
  } catch {
    // Cancellation is best effort and must not change the stable request result.
  }
}

function hasThenValue(value: unknown): boolean {
  return value !== null && (typeof value === "object" || typeof value === "function") && hasThenProperty(value);
}

function hasThenProperty(value: unknown): boolean {
  return value !== null && (typeof value === "object" || typeof value === "function")
    ? boundaryHasThen(value as object)
    : false;
}

async function invokeUntrusted<T>(operation: () => unknown): Promise<T> {
  let value: unknown;
  try {
    value = operation();
  } catch (error) {
    throw error;
  }
  if (hasThenValue(value)) return await nativePromiseValue(value) as T;
  return value as T;
}

function snapshotValue(value: unknown, depth = 0, seen = new nativeSet<object>()): unknown {
  if (depth > MAX_SNAPSHOT_DEPTH) throw new RequestBoundaryError("internal_error", 500);
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!authNumberIsFinite(value)) throw new RequestBoundaryError("internal_error", 500);
    return value;
  }
  if (typeof value !== "object") throw new RequestBoundaryError("internal_error", 500);
  if (setHasInternal(seen, value)) throw new RequestBoundaryError("internal_error", 500);
  setAddInternal(seen, value);
  try {
    if (nativeArrayIsArray(value)) {
      if (hasThenProperty(value)) throw new RequestBoundaryError("internal_error", 500);
      const length = ownDataProperty(value, "length");
      if (!length.valid || !length.present || typeof length.value !== "number" || !authNumberIsSafeInteger(length.value) || length.value < 0 || length.value > MAX_SNAPSHOT_KEYS) {
        throw new RequestBoundaryError("internal_error", 500);
      }
      const names = objectGetOwnPropertyNames(value);
      for (const name of names) {
        if (name === "length") continue;
        if (!/^\d+$/.test(name) || Number(name) >= length.value) throw new RequestBoundaryError("internal_error", 500);
      }
      const output: unknown[] = [];
      for (let index = 0; index < length.value; index += 1) {
        const item = ownDataProperty(value, `${index}`);
        if (!item.valid || !item.present) throw new RequestBoundaryError("internal_error", 500);
        appendInternal(output, snapshotValue(item.value, depth + 1, seen));
      }
      return output;
    }
    if (objectGetPrototypeOf(value) !== nativeObjectPrototype && objectGetPrototypeOf(value) !== null) {
      throw new RequestBoundaryError("internal_error", 500);
    }
    if (hasThenProperty(value) || objectGetOwnPropertySymbols(value).length !== 0) {
      throw new RequestBoundaryError("internal_error", 500);
    }
    const names = objectGetOwnPropertyNames(value);
    if (names.length > MAX_SNAPSHOT_KEYS) throw new RequestBoundaryError("internal_error", 500);
    const output = objectCreate(null) as Record<string, unknown>;
    for (const name of names) {
      const property = ownDataProperty(value, name);
      if (!property.valid || !property.present) throw new RequestBoundaryError("internal_error", 500);
      objectDefineProperty(output, name, {
        configurable: false,
        enumerable: true,
        value: snapshotValue(property.value, depth + 1, seen),
        writable: false,
      });
    }
    return output;
  } finally {
    setDeleteInternal(seen, value);
  }
}

function statusForCode(code: PublicAuthErrorCode): number {
  switch (code) {
    case "invalid_credentials":
    case "unauthorized":
    case "invalid_token":
    case "token_expired":
    case "refresh_token_reused":
    case "session_expired":
    case "otp_invalid":
    case "otp_expired":
    case "otp_attempts_exceeded":
    case "oauth_state_invalid":
      return 401;
    case "forbidden":
    case "insufficient_permission":
    case "identity_already_linked":
      return code === "identity_already_linked" ? 409 : 403;
    case "not_found":
      return 404;
    case "conflict":
      return 409;
    case "rate_limit_exceeded":
      return 429;
    case "oauth_provider_error":
      return 502;
    case "internal_error":
      return 500;
    default:
      return 400;
  }
}

function messageForCode(code: PublicAuthErrorCode): string {
  switch (code) {
    case "invalid_credentials": return "Invalid login credentials";
    case "unauthorized": return "Authenticated session is required";
    case "invalid_token": return "Invalid token";
    case "token_expired": return "Token has expired";
    case "refresh_token_reused": return "Refresh token reuse detected";
    case "session_expired": return "Session has expired";
    case "otp_invalid": return "Invalid one-time code";
    case "otp_expired": return "One-time code has expired";
    case "otp_attempts_exceeded": return "One-time code attempts exceeded";
    case "forbidden": return "Forbidden";
    case "insufficient_permission": return "Insufficient permission";
    case "not_found": return "Not found";
    case "conflict": return "Conflict";
    case "rate_limit_exceeded": return "Too many authentication attempts";
    case "redirect_not_allowed": return "Redirect URL is not allowed";
    case "oauth_state_invalid": return "Invalid OAuth state";
    case "oauth_provider_error": return "OAuth provider authentication failed";
    case "identity_already_linked": return "This login identity is already linked";
    case "identity_unlink_not_allowed": return "A final usable login method cannot be removed";
    case "invalid_request": return "Invalid authentication request";
    case "internal_error": return "Internal authentication error";
  }
}

function safeError(value: unknown, fallbackCode: PublicAuthErrorCode = "internal_error"): { readonly code: PublicAuthErrorCode; readonly status: number } {
  if (value === null || (typeof value !== "object" && typeof value !== "function")) {
    return { code: fallbackCode, status: statusForCode(fallbackCode) };
  }
  const codeProperty = ownDataProperty(value, "code");
  const statusProperty = ownDataProperty(value, "status");
  const code = codeProperty.valid && codeProperty.present && isPublicAuthErrorCode(codeProperty.value)
    ? codeProperty.value
    : fallbackCode;
  const expectedStatus = statusForCode(code);
  const status = statusProperty.valid && statusProperty.present && typeof statusProperty.value === "number" && authNumberIsSafeInteger(statusProperty.value)
    && (statusProperty.value === expectedStatus || (code === "invalid_request" && (statusProperty.value === 405 || statusProperty.value === 413)) || (code === "oauth_provider_error" && statusProperty.value === 502))
    ? statusProperty.value
    : expectedStatus;
  return { code, status };
}

function snapshotResult(value: unknown): SafeResult {
  if (value === null || (typeof value !== "object" && typeof value !== "function") || hasThenProperty(value)) {
    return { ok: false, code: "internal_error", status: 500 };
  }
  const dataProperty = ownDataProperty(value, "data");
  const errorProperty = ownDataProperty(value, "error");
  if (!dataProperty.valid || !errorProperty.valid || !errorProperty.present) {
    return { ok: false, code: "internal_error", status: 500 };
  }
  if (errorProperty.value === null && dataProperty.present) {
    try {
      return { ok: true, data: snapshotValue(dataProperty.value) };
    } catch {
      return { ok: false, code: "internal_error", status: 500 };
    }
  }
  const error = safeError(errorProperty.value);
  return { ok: false, ...error };
}

function safeAuthorizationSubject(value: unknown, requestId: string): AuthorizationSubject | null {
  try {
    const snapshot = snapshotValue(value);
    if (snapshot === null || typeof snapshot !== "object") return null;
    const userId = ownDataProperty(snapshot, "user_id");
    const returnedRequestId = ownDataProperty(snapshot, "request_id");
    if (!userId.valid || !userId.present || !uuidSchema.safeParse(userId.value).success) return null;
    if (returnedRequestId.present && (!returnedRequestId.valid || typeof returnedRequestId.value !== "string" || !validRequestId(returnedRequestId.value))) return null;
    return objectFreeze({ user_id: userId.value as AuthorizationSubject["user_id"], request_id: requestId });
  } catch {
    return null;
  }
}

function copyBytes(value: unknown): Uint8Array | null {
  if (!(value instanceof nativeUint8Array)) return null;
  let length: unknown;
  try { length = invoke(typedArrayLengthGetter, value, []); } catch { return null; }
  if (typeof length !== "number" || !authNumberIsSafeInteger(length) || length !== 32) return null;
  const output = new nativeUint8Array(length);
  for (let index = 0; index < length; index += 1) {
    const item = ownDataProperty(value, `${index}`);
    if (!item.valid || !item.present || typeof item.value !== "number" || !authNumberIsInteger(item.value) || item.value < 0 || item.value > 255) return null;
    output[index] = item.value;
  }
  return output;
}

function safeDate(value: unknown): Date | null {
  if (!(value instanceof Date)) return null;
  try {
    const time = dateGetTime(value);
    return authNumberIsFinite(time) ? new Date(time) : null;
  } catch {
    return null;
  }
}

function safeStringArray(value: unknown): readonly string[] | null {
  if (!nativeArrayIsArray(value) || hasThenProperty(value)) return null;
  const lengthProperty = ownDataProperty(value, "length");
  if (!lengthProperty.valid || !lengthProperty.present || typeof lengthProperty.value !== "number" || !authNumberIsSafeInteger(lengthProperty.value) || lengthProperty.value < 0 || lengthProperty.value > MAX_SNAPSHOT_KEYS) return null;
  for (const name of objectGetOwnPropertyNames(value)) {
    if (name === "length") continue;
    if (!/^\d+$/u.test(name) || Number(name) >= lengthProperty.value) return null;
  }
  const output: string[] = [];
  for (let index = 0; index < lengthProperty.value; index += 1) {
    const item = ownDataProperty(value, `${index}`);
    if (!item.valid || !item.present || typeof item.value !== "string" || item.value.length > 256) return null;
    appendInternal(output, item.value);
  }
  return objectFreeze(output);
}

function safeApiKey(value: unknown, expectedHash: Uint8Array, now: Date): RouteAuthContext["key"] | null {
  if (value === null || (typeof value !== "object" && typeof value !== "function") || hasThenProperty(value)) return null;
  const allowedNames = ["id", "prefix", "kind", "scopes", "expires_at", "revoked_at", "key_hash"] as const;
  try {
    const names = objectGetOwnPropertyNames(value);
    if (objectGetOwnPropertySymbols(value).length !== 0) return null;
    for (let index = 0; index < names.length; index += 1) {
      const name = names[index];
      if (name === undefined || !containsExact(allowedNames, name)) return null;
    }
  } catch {
    return null;
  }
  const snapshot: Record<string, unknown> = objectCreate(null) as Record<string, unknown>;
  for (let nameIndex = 0; nameIndex < allowedNames.length; nameIndex += 1) {
    const name = allowedNames[nameIndex];
    if (name === undefined) return null;
    const property = ownDataProperty(value, name);
    if (!property.valid || !property.present) return null;
    objectDefineProperty(snapshot, name, { configurable: true, enumerable: true, writable: true, value: property.value });
  }
  const keyHash = copyBytes(snapshot.key_hash);
  if (keyHash === null || keyHash.byteLength !== expectedHash.byteLength || !timingSafeEqual(Buffer.from(keyHash), Buffer.from(expectedHash))) return null;
  const scopes = safeStringArray(snapshot.scopes);
  if (scopes === null) return null;
  const parsed = apiKeyRecordSchema.safeParse({
    id: snapshot.id,
    prefix: snapshot.prefix,
    kind: snapshot.kind,
    scopes,
    expires_at: snapshot.expires_at,
    revoked_at: snapshot.revoked_at,
  });
  if (!parsed.success) return null;
  const expiresAt = safeDate(parsed.data.expires_at);
  const revokedAt = safeDate(parsed.data.revoked_at);
  if ((parsed.data.revoked_at !== null && revokedAt === null) || (parsed.data.expires_at !== null && expiresAt === null)) return null;
  if (revokedAt !== null || (expiresAt !== null && dateGetTime(expiresAt) <= dateGetTime(now))) return null;
  return objectFreeze({ id: parsed.data.id, kind: parsed.data.kind, scopes: objectFreeze([...parsed.data.scopes]) });
}

function isValidBearer(value: string): boolean {
  return /^Bearer [A-Za-z0-9._~-]+$/u.test(value);
}

function audienceMatches(value: string | readonly string[], expected: string | readonly string[]): boolean {
  const actual = typeof value === "string" ? [value] : value;
  const configured = typeof expected === "string" ? [expected] : expected;
  if (actual.length !== configured.length) return false;
  for (let index = 0; index < actual.length; index += 1) {
    const candidate = actual[index];
    if (candidate === undefined || !containsExact(configured, candidate)) return false;
  }
  return true;
}

function readQueryKeys(params: URLSearchParams): string[] | null {
  const iterator = invoke<Iterator<string>>(searchParamsKeys, params, []);
  const keys: string[] = [];
  for (;;) {
    const step = invoke<unknown>(searchParamsIteratorNext, iterator, []);
    if (step === null || typeof step !== "object") return null;
    const done = ownDataProperty(step, "done");
    const value = ownDataProperty(step, "value");
    if (!done.valid || !done.present || typeof done.value !== "boolean" || !value.valid || !value.present) return null;
    if (done.value) return keys;
    if (typeof value.value !== "string") return null;
    appendInternal(keys, value.value);
    if (keys.length > 128) return null;
  }
}

function decodeSegment(value: string): string | null {
  try {
    const decoded = decodeURIComponent(value);
    if (decoded === "" || runtimeStringIncludes(decoded, "/") || runtimeStringIncludes(decoded, "\\") || runtimeStringIncludes(decoded, "\u0000")) return null;
    return decoded;
  } catch {
    return null;
  }
}

function exactPath(path: string, basePath: string): { readonly path: string; readonly callbackProvider?: string; readonly params?: Readonly<Record<string, string>> } | null {
  if (!runtimeStringStartsWith(path, `${basePath}/`)) return null;
  const relative = runtimeStringSlice(path, basePath.length);
  if (relative === "/callback" || relative === "/callback/") return null;
  if (runtimeStringStartsWith(relative, "/callback/")) {
    const providerPart = runtimeStringSlice(relative, "/callback/".length);
    if (runtimeStringIncludes(providerPart, "/")) return null;
    const provider = decodeSegment(providerPart);
    return provider === null ? null : { path: "/callback/{provider}", callbackProvider: provider };
  }
  if (runtimeStringStartsWith(relative, "/user/identities/")) {
    const identityPart = runtimeStringSlice(relative, "/user/identities/".length);
    if (runtimeStringIncludes(identityPart, "/")) return null;
    const identityId = decodeSegment(identityPart);
    if (identityId === null || !uuidSchema.safeParse(identityId).success) return null;
    return { path: "/user/identities/{id}", callbackProvider: identityId };
  }
  if (runtimeStringStartsWith(relative, "/admin/")) {
    const parts = runtimeStringSplit(runtimeStringSlice(relative, 1), "/");
    const decodedUuid = (index: number): string | null => {
      const value = parts[index];
      if (value === undefined) return null;
      const decoded = decodeSegment(value);
      return decoded !== null && uuidSchema.safeParse(decoded).success ? decoded : null;
    };
    if (parts.length === 3 && parts[0] === "admin" && parts[1] === "users" && parts[2] !== "find" && parts[2] !== "invite") {
      const id = decodedUuid(2); if (id === null) return null;
      return { path: "/admin/users/{id}", params: objectFreeze({ id }) };
    }
    if (parts.length === 5 && parts[0] === "admin" && parts[1] === "users" && parts[3] === "roles") {
      const id = decodedUuid(2); const roleId = decodedUuid(4); if (id === null || roleId === null) return null;
      return { path: "/admin/users/{id}/roles/{roleId}", params: objectFreeze({ id, roleId }) };
    }
    if (parts.length === 3 && parts[0] === "admin" && parts[1] === "roles") {
      const id = decodedUuid(2); if (id === null) return null;
      return { path: "/admin/roles/{id}", params: objectFreeze({ id }) };
    }
    if (parts.length === 4 && parts[0] === "admin" && parts[1] === "roles" && (parts[3] === "permissions" || parts[3] === "inheritance")) {
      const id = decodedUuid(2); if (id === null) return null;
      return { path: `/admin/roles/{id}/${parts[3]}`, params: objectFreeze({ id }) };
    }
    if (parts.length === 3 && parts[0] === "admin" && parts[1] === "permissions") {
      const id = decodedUuid(2); if (id === null) return null;
      return { path: "/admin/permissions/{id}", params: objectFreeze({ id }) };
    }
  }
  if (runtimeStringEndsWith(relative, "/")) return null;
  return { path: relative };
}

function routeContract(path: string, method?: string): RouteContract | undefined {
  for (let index = 0; index < routeContracts.length; index += 1) {
    const candidate = routeContracts[index];
    if (candidate !== undefined && candidate.path === path && (method === undefined || candidate.method === method)) return candidate;
  }
  return undefined;
}

function isJsonContentType(value: string | null): boolean {
  if (value === null) return false;
  const normalized = runtimeStringToLowerCase(runtimeStringTrim(value));
  return normalized === "application/json" || normalized === "application/json; charset=utf-8";
}

const runtimeStringTrim = Function.prototype.call.bind(String.prototype.trim) as (value: string) => string;
const runtimeStringIncludes = Function.prototype.call.bind(String.prototype.includes) as (value: string, search: string) => boolean;
const runtimeStringToLowerCase = Function.prototype.call.bind(String.prototype.toLowerCase) as (value: string) => string;
const runtimeStringSplit = Function.prototype.call.bind(String.prototype.split) as (value: string, separator: string) => string[];
const runtimeStringStartsWith = Function.prototype.call.bind(String.prototype.startsWith) as (value: string, search: string) => boolean;
const runtimeStringSlice = Function.prototype.call.bind(String.prototype.slice) as (value: string, start: number, end?: number) => string;
const runtimeStringEndsWith = Function.prototype.call.bind(String.prototype.endsWith) as (value: string, search: string) => boolean;

function captureRuntimeOrigin(value: unknown, label: string): string {
  if (value !== null && typeof value === "object") assertBoundaryObject(value, label);
  if (typeof value !== "string" || runtimeStringTrim(value) !== value) {
    throw new AuthConfigurationError(`${label} must be a canonical HTTP(S) origin`);
  }
  let parsed: URL;
  try {
    parsed = new nativeURL(value);
  } catch {
    throw new AuthConfigurationError(`${label} must be a canonical HTTP(S) origin`);
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") throw new AuthConfigurationError(`${label} must be a canonical HTTP(S) origin`);
  if (parsed.origin !== value || parsed.pathname !== "/" || parsed.search !== "" || parsed.hash !== "" || parsed.username !== "" || parsed.password !== "") {
    throw new AuthConfigurationError(`${label} must be a canonical HTTP(S) origin`);
  }
  return value;
}

function captureRuntimePath(value: unknown, label: string): string {
  if (value !== null && typeof value === "object") assertBoundaryObject(value, label);
  if (typeof value !== "string" || runtimeStringTrim(value) !== value || value.length < 2 || value[0] !== "/" || value[value.length - 1] === "/") {
    throw new AuthConfigurationError(`${label} must be a canonical absolute path`);
  }
  let parsed: URL;
  try {
    parsed = new nativeURL(`https://runtime.invalid${value}`);
  } catch {
    throw new AuthConfigurationError(`${label} must be a canonical absolute path`);
  }
  if (parsed.pathname !== value || parsed.search !== "" || parsed.hash !== "") {
    throw new AuthConfigurationError(`${label} must be a canonical absolute path`);
  }
  return value;
}

/** Internal construction inputs for the framework-neutral handler. */
export interface AuthServerRuntimeOptions {
  readonly config: AuthServerOptions;
  readonly repository: AuthRepository;
  readonly services: AuthServerServices;
  readonly apiKeyHashKey: Uint8Array;
  readonly baseOrigin: string;
  readonly basePath: string;
  readonly allowedOrigins: readonly string[];
  readonly allowedRedirects: readonly string[];
}

/** Safe current-user subject returned by `authorize`. */
export type AuthSubject = AuthorizationSubject;

/** Framework-neutral Web Request/Response authentication server. */
export class AuthServer {
  private readonly tokenIssuer: string;
  private readonly tokenAudience: string | string[];
  private readonly repository: AuthRepository;
  private readonly services: AuthServerServices;
  private readonly apiKeyHashKey: Uint8Array;
  private readonly baseOrigin: string;
  private readonly basePath: string;
  private readonly allowedOrigins: readonly string[];
  private readonly allowedRedirects: readonly string[];

  constructor(options: AuthServerRuntimeOptions) {
    if (options === null || typeof options !== "object") throw new AuthConfigurationError("auth server runtime options are incomplete");
    const source = options as unknown as object;
    assertBoundaryObject(source, "auth server runtime options");
    const config = requiredBoundaryOption(source, "config", "auth server config");
    const repository = requiredBoundaryOption(source, "repository", "auth server repository");
    const services = requiredBoundaryOption(source, "services", "auth server services");
    const apiKeyHashKey = requiredBoundaryOption(source, "apiKeyHashKey", "API-key hash key");
    const baseOrigin = requiredBoundaryOption(source, "baseOrigin", "auth server base origin");
    const basePath = requiredBoundaryOption(source, "basePath", "auth server base path");
    const allowedOrigins = requiredBoundaryOption(source, "allowedOrigins", "auth server allowed origins");
    const allowedRedirects = requiredBoundaryOption(source, "allowedRedirects", "auth server allowed redirects");
    const capturedApiKeyHashKey = captureBoundaryBytes(apiKeyHashKey, "API-key hash key", 32);
    if (config === null || typeof config !== "object") throw new AuthConfigurationError("auth server config is incomplete");
    const configSource = config as object;
    assertBoundaryObject(configSource, "auth server config");
    const signingKeysProperty = boundaryOwnDataProperty(configSource, "signingKeys");
    if (!signingKeysProperty.valid || !signingKeysProperty.present || signingKeysProperty.value === null || typeof signingKeysProperty.value !== "object") {
      throw new AuthConfigurationError("auth server signing keys are incomplete");
    }
    const signingKeys = signingKeysProperty.value as object;
    assertBoundaryObject(signingKeys, "auth server signing keys");
    const issuerProperty = boundaryOwnDataProperty(signingKeys, "issuer");
    const audienceProperty = boundaryOwnDataProperty(signingKeys, "audience");
    if (!issuerProperty.valid || !issuerProperty.present || typeof issuerProperty.value !== "string" || !audienceProperty.valid || !audienceProperty.present) {
      throw new AuthConfigurationError("auth server signing keys are incomplete");
    }
    const audienceValue = audienceProperty.value;
    const audienceIsArray = typeof audienceValue === "string"
      ? false
      : boundaryIsArray(audienceValue, "auth server token audience");
    if (typeof audienceValue !== "string" && !audienceIsArray) throw new AuthConfigurationError("auth server signing keys are incomplete");
    this.tokenIssuer = issuerProperty.value;
    this.tokenAudience = audienceIsArray
      ? captureBoundaryStringArray(audienceValue, "auth server token audience", 1, 128) as string[]
      : audienceValue as string;
    this.repository = captureAuthServerRepository(repository as AuthRepository);
    this.services = captureAuthServerServices(services as AuthServerServices);
    this.apiKeyHashKey = capturedApiKeyHashKey;
    this.baseOrigin = captureRuntimeOrigin(baseOrigin, "auth server base origin");
    this.basePath = captureRuntimePath(basePath, "auth server base path");
    this.allowedOrigins = captureBoundaryStringArray(allowedOrigins, "auth server allowed origins", 1, 128);
    this.allowedRedirects = captureBoundaryStringArray(allowedRedirects, "auth server allowed redirects", 1, 100_000);
  }

  /** Handles one framework-neutral Web Request without hidden network work. */
  async handle(request: Request): Promise<Response> {
    let meta: RequestMeta | null = null;
    try {
      meta = this.snapshotRequest(request);
      if (meta === null) return this.errorResponse(null, "invalid_request", 400);
      const originCheck = this.checkOrigin(meta);
      if (originCheck !== null) return this.errorResponse(meta, originCheck.code, originCheck.status);
      const routed = exactPath(meta.url.pathname, this.basePath);
      if (meta.method === "OPTIONS") return this.preflight(meta, routed);
      if (routed === null) return this.errorResponse(meta, "not_found", 404);
      const contract = routeContract(routed.path, meta.method);
      if (contract === undefined) {
        if (routeContract(routed.path) !== undefined) return this.errorResponse(meta, "invalid_request", 405);
        return this.errorResponse(meta, "not_found", 404);
      }
      const query = this.queryFor(meta.url, contract);
      const body = await this.parseRequestBody(meta, contract, query);
      const auth = await this.authenticate(meta, contract, query);
      const context: RouteContext = {
        request: meta.request,
        requestId: meta.requestId,
        query,
        body,
        ...(routed.params === undefined ? {} : { params: routed.params }),
        ...(auth === undefined ? {} : { auth }),
        services: this.services,
        invoke: <T>(operation: () => unknown) => invokeUntrusted<T>(operation),
      };
      let output: RouteOutput | null;
      if (runtimeStringStartsWith(routed.path, "/admin")) {
        output = await handleAdminRoute(routed.path, context);
      } else if (runtimeStringStartsWith(routed.path, "/user") || routed.path === "/logout") {
        output = await handleUserRoute(
          routed.path === "/user/identities/{id}" ? `/user/identities/${routed.callbackProvider}` : routed.path,
          context,
        );
      } else if (routed.path === "/callback/{provider}" && routed.callbackProvider !== undefined) {
        output = await handlePublicRoute(`/callback/${routed.callbackProvider}`, context);
      } else {
        output = await handlePublicRoute(routed.path, context);
      }
      if (output === null) return this.errorResponse(meta, "not_found", 404);
      return this.outputResponse(meta, output);
    } catch (error) {
      const safe = safeError(error);
      return this.errorResponse(meta, safe.code, safe.status);
    }
  }

  /** Authenticates a request and enforces a fresh request-local permission context. */
  async authorize(request: Request, requirement: AuthorizationRequirement): Promise<AuthSubject> {
    let meta: RequestMeta | null = null;
    try {
      meta = this.snapshotRequest(request);
      if (meta === null) throw new AuthApiError("invalid_request", 400, "Invalid request");
      const originCheck = this.checkOrigin(meta);
      if (originCheck !== null) throw new AuthApiError(originCheck.code, originCheck.status, messageForCode(originCheck.code));
      const auth = await this.authenticate(meta, undefined, new nativeURLSearchParams(), true);
      if (auth === undefined || auth.authorizationSubject === undefined) throw new AuthApiError("unauthorized", 401, "Authenticated session is required");
      const context = auth.authorizationContext ?? createAuthorizationRequestContext(auth.authorizationSubject);
      if (context === null) throw new AuthApiError("unauthorized", 401, "Authenticated session is required");
      const raw = await invokeUntrusted(() => this.services.authorization.authorize(auth.authorizationSubject!, requirement, context));
      const direct = safeAuthorizationSubject(raw, meta.requestId);
      if (direct !== null) return direct;
      const result = snapshotResult(raw);
      if (!result.ok) throw new AuthApiError(result.code, result.status, messageForCode(result.code), meta.requestId);
      const wrapped = safeAuthorizationSubject(result.data, meta.requestId);
      if (wrapped === null) throw new AuthApiError("insufficient_permission", 403, "Insufficient permission", meta.requestId);
      return wrapped;
    } catch (error) {
      const safe = safeError(error, "unauthorized");
      const status = safe.status === 403 || safe.code === "insufficient_permission" ? 403 : safe.status === 400 ? 400 : 401;
      throw new AuthApiError(status === 403 ? "insufficient_permission" : status === 400 ? "invalid_request" : "unauthorized", status, messageForCode(status === 403 ? "insufficient_permission" : status === 400 ? "invalid_request" : "unauthorized"), meta?.requestId);
    }
  }

  private snapshotRequest(request: Request): RequestMeta | null {
    if (request === null || (typeof request !== "object" && typeof request !== "function")) return null;
    try {
      const method = invoke<unknown>(requestMethodGetter, request, []);
      const urlValue = invoke<unknown>(requestUrlGetter, request, []);
      const headers = invoke<unknown>(requestHeadersGetter, request, []);
      if (typeof method !== "string" || typeof urlValue !== "string" || headers === null || (typeof headers !== "object" && typeof headers !== "function")) return null;
      const url = new nativeURL(urlValue);
      if (url.hash !== "") return null;
      const requestIdHeader = readHeaderValue(headers, "x-request-id");
      const originHeader = readHeaderValue(headers, "origin");
      const apiKey = readHeaderValue(headers, "apikey");
      const authorization = readHeaderValue(headers, "authorization");
      const contentLength = readHeaderValue(headers, "content-length");
      const contentType = readHeaderValue(headers, "content-type");
      const contentEncoding = readHeaderValue(headers, "content-encoding");
      const accessControlRequestMethod = readHeaderValue(headers, "access-control-request-method");
      const accessControlRequestHeaders = readListHeaderValue(headers, "access-control-request-headers");
      const strictHeaders: readonly HeaderValue[] = [
        requestIdHeader,
        originHeader,
        apiKey,
        authorization,
        contentLength,
        contentType,
        contentEncoding,
        accessControlRequestMethod,
      ];
      for (let headerIndex = 0; headerIndex < strictHeaders.length; headerIndex += 1) {
        const header = strictHeaders[headerIndex];
        if (header !== undefined && header.state === "invalid") throw new RequestBoundaryError("invalid_request", 400);
      }
      if (accessControlRequestHeaders.state === "invalid") {
        throw new RequestBoundaryError("invalid_request", 400);
      }
      if (contentEncoding.state === "valid" && contentEncoding.value !== "identity") {
        throw new RequestBoundaryError("invalid_request", 400);
      }
      if (requestIdHeader.state === "valid" && !validRequestId(requestIdHeader.value)) {
        throw new RequestBoundaryError("invalid_request", 400);
      }
      if (contentLength.state === "valid") {
        if (!/^\d+$/u.test(contentLength.value)) throw new RequestBoundaryError("invalid_request", 400);
        const declaredLength = Number(contentLength.value);
        if (!authNumberIsSafeInteger(declaredLength)) throw new RequestBoundaryError("invalid_request", 400);
        if (declaredLength > MAX_BODY_BYTES) throw new RequestBoundaryError("invalid_request", 413);
      }
      if (authorization.state === "valid" && !isValidBearer(authorization.value)) {
        throw new RequestBoundaryError("invalid_request", 400);
      }
      const browserMarked = readFetchMetadata(headers);
      if (browserMarked === "invalid") throw new RequestBoundaryError("forbidden", 403);
      const rawRequestId = requestIdHeader.state === "valid" ? requestIdHeader.value : null;
      const rawOrigin = originHeader.state === "valid" ? originHeader.value : null;
      const requestId = validRequestId(rawRequestId) ? rawRequestId : randomUUID();
      return {
        request,
        method,
        url,
        headers: headers as Headers,
        requestId,
        apiKey,
        authorization,
        contentLength,
        contentType,
        contentEncoding,
        accessControlRequestMethod,
        accessControlRequestHeaders,
        origin: rawOrigin,
        browserMarked: browserMarked === "present",
      };
    } catch (error) {
      if (error instanceof RequestBoundaryError) throw error;
      return null;
    }
  }

  private checkOrigin(meta: RequestMeta): { readonly code: "forbidden" | "not_found"; readonly status: 403 | 404 } | null {
    if (meta.url.origin !== this.baseOrigin) return { code: "not_found", status: 404 };
    if (meta.origin === null) return null;
    if (!containsExact(this.allowedOrigins, meta.origin)) return { code: "forbidden", status: 403 };
    return null;
  }

  private preflight(meta: RequestMeta, routed: { readonly path: string } | null): Response {
    if (meta.origin === null || routed === null || routeContract(routed.path) === undefined) return this.errorResponse(meta, "invalid_request", 400);
    const requestedMethod = meta.accessControlRequestMethod.state === "valid"
      ? meta.accessControlRequestMethod.value
      : null;
    const requestedHeaders = meta.accessControlRequestHeaders.state === "valid"
      ? meta.accessControlRequestHeaders.value
      : null;
    if (requestedMethod === null || !containsExact(["GET", "POST", "PUT", "DELETE"], requestedMethod)) return this.errorResponse(meta, "invalid_request", 400);
    if (routeContract(routed.path, requestedMethod) === undefined) return this.errorResponse(meta, "invalid_request", 405);
    if (requestedHeaders !== null) {
      const rawHeaders = runtimeStringSplit(requestedHeaders, ",");
      for (let headerIndex = 0; headerIndex < rawHeaders.length; headerIndex += 1) {
        const rawHeader = rawHeaders[headerIndex];
        if (rawHeader === undefined) return this.errorResponse(meta, "invalid_request", 400);
        const header = runtimeStringToLowerCase(runtimeStringTrim(rawHeader));
        if (header === "" || !/^[!#$%&'*+.^_`|~0-9a-z-]+$/u.test(header)) {
          return this.errorResponse(meta, "invalid_request", 400);
        }
        if (!containsExact(ALLOWED_REQUEST_HEADERS, header)) return this.errorResponse(meta, "forbidden", 403);
      }
    }
    const response = this.emptyResponse(meta, 204);
    invoke(headersSet, response.headers, ["access-control-allow-methods", "GET, POST, PUT, PATCH, DELETE"]);
    invoke(headersSet, response.headers, ["access-control-allow-headers", "apikey, authorization, content-type, x-request-id"]);
    invoke(headersSet, response.headers, ["access-control-max-age", "300"]);
    return response;
  }

  private queryFor(url: URL, contract: RouteContract): URLSearchParams {
    const params = invoke<URLSearchParams>(urlSearchParamsGetter, url, []);
    const keys = readQueryKeys(params);
    if (keys === null) throw new RequestBoundaryError("invalid_request", 400);
    const allowed: string[] = [];
    const query = contract.query ?? [];
    for (let index = 0; index < query.length; index += 1) {
      const parameter = query[index];
      if (parameter === undefined) throw new RequestBoundaryError("invalid_request", 400);
      appendInternal(allowed, parameter.name);
    }
    for (const key of keys) {
      if (!containsExact(allowed, key)) throw new RequestBoundaryError("invalid_request", 400);
      const values = invoke<string[]>(searchParamsGetAll, params, [key]);
      if (!nativeArrayIsArray(values) || values.length !== 1) throw new RequestBoundaryError("invalid_request", 400);
    }
    for (let index = 0; index < query.length; index += 1) {
      const parameter = query[index];
      if (parameter === undefined) throw new RequestBoundaryError("invalid_request", 400);
      const values = invoke<string[]>(searchParamsGetAll, params, [parameter.name]);
      if (parameter.required && (!nativeArrayIsArray(values) || values.length !== 1 || values[0] === "")) throw new RequestBoundaryError("invalid_request", 400);
    }
    return params;
  }

  private async parseRequestBody(meta: RequestMeta, contract: RouteContract, query: URLSearchParams): Promise<unknown> {
    if (contract.body === undefined) return undefined;
    const contentLength = meta.contentLength.state === "valid" ? meta.contentLength.value : null;
    if (contentLength !== null) {
      if (!/^\d+$/u.test(contentLength)) throw new RequestBoundaryError("invalid_request", 400);
      const length = Number(contentLength);
      if (!authNumberIsSafeInteger(length) || length > MAX_BODY_BYTES) throw new RequestBoundaryError("invalid_request", 413);
    }
    const contentType = meta.contentType.state === "valid" ? meta.contentType.value : null;
    if (!isJsonContentType(contentType)) {
      if (contract.path === "/logout" && contentType === null) {
        let requestBody: unknown;
        try { requestBody = invoke(requestBodyGetter, meta.request, []); } catch { throw new RequestBoundaryError("invalid_request", 400); }
        if (requestBody === null) return {};
      }
      throw new RequestBoundaryError("invalid_request", 400);
    }
    const bytes = await this.readBody(meta, contentLength === null ? undefined : Number(contentLength));
    if (bytes.byteLength === 0) {
      if (contract.path === "/logout") return {};
      throw new RequestBoundaryError("invalid_request", 400);
    }
    let parsedJson: unknown;
    try {
      const text = new nativeTextDecoder("utf-8", { fatal: true }).decode(bytes);
      parsedJson = jsonParse(text);
    } catch {
      throw new RequestBoundaryError("invalid_request", 400);
    }
    let schema = contract.body;
    if (contract.path === "/token") {
      const grantType = invoke<string | null>(searchParamsGet, query, ["grant_type"]);
      schema = grantType === "refresh_token"
        ? refreshTokenRequestSchema
        : grantType === "password"
          ? signupRequestSchema.pick({ email: true, password: true }).strict()
          : schema;
    }
    let safeInput: unknown;
    try {
      safeInput = snapshotValue(parsedJson);
    } catch {
      throw new RequestBoundaryError("invalid_request", 400);
    }
    const result = schema.safeParse(safeInput);
    if (!result.success) throw new RequestBoundaryError("invalid_request", 400);
    return snapshotValue(result.data);
  }

  private async readBody(meta: RequestMeta, declaredLength: number | undefined): Promise<Uint8Array> {
    let stream: unknown;
    try {
      stream = invoke<unknown>(requestBodyGetter, meta.request, []);
    } catch {
      throw new RequestBoundaryError("invalid_request", 400);
    }
    if (stream === null || typeof stream !== "object") throw new RequestBoundaryError("invalid_request", 400);
    let reader: unknown;
    try {
      reader = invoke<unknown>(readableStreamGetReader, stream, []);
    } catch {
      throw new RequestBoundaryError("invalid_request", 400);
    }
    const chunks: Uint8Array[] = [];
    let total = 0;
    let cancellationRequested = false;
    const cancel = () => {
      if (cancellationRequested) return;
      cancellationRequested = true;
      cancelReader(reader);
    };
    try {
      for (;;) {
        const raw = invoke<unknown>(readableReaderRead, reader, []);
        const result = await nativePromiseValue(raw);
        if (result === null || typeof result !== "object") throw new RequestBoundaryError("invalid_request", 400);
        const doneProperty = ownDataProperty(result, "done");
        const valueProperty = ownDataProperty(result, "value");
        if (!doneProperty.valid || !doneProperty.present || typeof doneProperty.value !== "boolean" || !valueProperty.valid || !valueProperty.present) throw new RequestBoundaryError("invalid_request", 400);
        if (doneProperty.value) {
          if (declaredLength !== undefined && total !== declaredLength) throw new RequestBoundaryError("invalid_request", 400);
          break;
        }
        const chunk = copyChunk(valueProperty.value);
        if (chunk === null) throw new RequestBoundaryError("invalid_request", 400);
        total += chunk.byteLength;
        if (total > MAX_BODY_BYTES || (declaredLength !== undefined && total > declaredLength)) throw new RequestBoundaryError("invalid_request", 413);
        appendInternal(chunks, chunk);
      }
    } catch (error) {
      cancel();
      if (error instanceof RequestBoundaryError && error.code !== "internal_error") throw error;
      throw new RequestBoundaryError("invalid_request", 400);
    } finally {
      try { invoke(readableReaderReleaseLock, reader, []); } catch { /* best effort */ }
    }
    const output = new nativeUint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      invoke(typedArraySet, output, [chunk, offset]);
      offset += chunk.byteLength;
    }
    return output;
  }

  private async authenticate(
    meta: RequestMeta,
    contract: RouteContract | undefined,
    query: URLSearchParams,
    forceBearer = false,
  ): Promise<RouteAuthContext | undefined> {
    if (contract?.security === "signed") return undefined;
    const now = new Date();
    if (meta.apiKey.state !== "valid") {
      throw new AuthApiError("unauthorized", 401, "API key is required", meta.requestId);
    }
    const rawApiKey = meta.apiKey.value;
    if (runtimeStringTrim(rawApiKey) !== rawApiKey || rawApiKey.length < 8 || rawApiKey.length > 512) {
      throw new AuthApiError("unauthorized", 401, "API key is required", meta.requestId);
    }
    const expectedHash = nativeUint8ArrayFrom(createHmac("sha256", this.apiKeyHashKey).update(`apikey\0${rawApiKey}`, "utf8").digest());
    const record = await invokeUntrusted<unknown>(() => this.repository.operations.findApiKeyByHash(expectedHash, { now }));
    const key = safeApiKey(record, expectedHash, now);
    if (key === null) throw new AuthApiError("unauthorized", 401, "Invalid API key", meta.requestId);
    if (key.kind === "secret" && (meta.origin !== null || meta.browserMarked)) throw new AuthApiError("forbidden", 403, "Secret API keys are not accepted from browser origins", meta.requestId);
    try {
      const lastUse = this.repository.admin?.touchApiKeyLastUsed(key.id as never, now);
      if (lastUse !== undefined) drainNativePromise(lastUse);
    } catch {
      // Last-use timestamps are operational hints and never authentication authority.
    }

    let bearer: string | null = null;
    if (meta.authorization.state === "valid") {
      if (!isValidBearer(meta.authorization.value)) throw new AuthApiError("invalid_request", 400, "Invalid bearer authorization", meta.requestId);
      bearer = runtimeStringSlice(meta.authorization.value, "Bearer ".length);
    }
    const requiresBearer = forceBearer || contract?.security === "user" || (contract?.security === "admin" && key.kind !== "secret") || (contract?.path === "/authorize" && invoke<string | null>(searchParamsGet, query, ["flow"]) === "link_identity");
    if (requiresBearer && bearer === null) throw new AuthApiError("unauthorized", 401, "Authenticated session is required", meta.requestId);
    if (!requiresBearer && bearer !== null && contract?.security !== "admin" && contract?.path !== "/logout" && contract?.path !== "/authorize") throw new AuthApiError("invalid_request", 400, "Conflicting credentials", meta.requestId);
    if (bearer === null) return { key };
    const authenticated = await this.authenticateBearer(bearer, meta.requestId);
    return {
      key,
      subject: { session: authenticated.session },
      authorizationSubject: objectFreeze({ user_id: authenticated.user_id, request_id: meta.requestId }),
      session: authenticated,
      ...(() => {
        const authorizationContext = createAuthorizationRequestContext({ user_id: authenticated.user_id, request_id: meta.requestId });
        return authorizationContext === null ? {} : { authorizationContext };
      })(),
    };
  }

  private async authenticateBearer(bearer: string, requestId: string): Promise<AuthenticatedSession> {
    const rawVerification = await invokeUntrusted(() => this.services.tokens.verifyAccessToken(bearer));
    const verification = snapshotResult(rawVerification);
    if (!verification.ok) throw new AuthApiError("unauthorized", 401, "Invalid access token", requestId);
    const claimsParsed = accessClaimsSchema.safeParse(verification.data);
    const nowSeconds = Math.floor(Date.now() / 1000);
    if (
      !claimsParsed.success ||
      claimsParsed.data.exp <= claimsParsed.data.iat ||
      claimsParsed.data.iat > nowSeconds ||
      claimsParsed.data.exp <= nowSeconds ||
      claimsParsed.data.iss !== this.tokenIssuer ||
      !audienceMatches(claimsParsed.data.aud, this.tokenAudience) ||
      !uuidSchema.safeParse(claimsParsed.data.sid).success
    ) throw new AuthApiError("unauthorized", 401, "Invalid access token", requestId);
    const userRaw = await invokeUntrusted(() => this.repository.users.findById(uuidSchema.parse(claimsParsed.data.sub)));
    let safeUser: User;
    try {
      const value = snapshotValue(userRaw);
      const parsed = userSchema.safeParse(value);
      if (!parsed.success) throw new Error("invalid user");
      safeUser = parsed.data as User;
    } catch {
      throw new AuthApiError("unauthorized", 401, "Invalid access token", requestId);
    }
    const session: Session = {
      access_token: bearer,
      refresh_token: "access-token-placeholder",
      token_type: "bearer",
      expires_in: claimsParsed.data.exp - claimsParsed.data.iat,
      expires_at: claimsParsed.data.exp,
      user: safeUser,
    };
    const rawSession = await invokeUntrusted(() => this.services.sessions.authorizeSession(session));
    const authorized = snapshotResult(rawSession);
    if (!authorized.ok) throw new AuthApiError("unauthorized", 401, "Authenticated session is required", requestId);
    try {
      const safe = snapshotValue(authorized.data);
      if (safe === null || typeof safe !== "object") throw new Error("invalid session");
      const value = safe as Record<string, unknown>;
      if (value.user_id !== claimsParsed.data.sub || value.session_id !== claimsParsed.data.sid) throw new Error("wrong session");
      return {
        session,
        session_id: claimsParsed.data.sid as AuthenticatedSession["session_id"],
        user_id: claimsParsed.data.sub as AuthenticatedSession["user_id"],
        user: safeUser,
      };
    } catch {
      throw new AuthApiError("unauthorized", 401, "Authenticated session is required", requestId);
    }
  }

  private outputResponse(meta: RequestMeta, output: RouteOutput): Response {
    if (output.kind === "redirect") {
      if (!this.safeRedirectTarget(output.location)) return this.errorResponse(meta, "oauth_state_invalid", 401);
      return this.redirectResponse(meta, output.location);
    }
    if (output.kind === "callback") {
      const result = snapshotResult(output.result);
      if (!result.ok) return this.errorResponse(meta, result.code, result.status);
      if (result.data === null || typeof result.data !== "object") return this.errorResponse(meta, "internal_error", 500);
      const data = result.data as Record<string, unknown>;
      if (typeof data.url !== "string" || !this.safeRedirectTarget(data.url)) return this.errorResponse(meta, "oauth_state_invalid", 401);
      return this.redirectResponse(meta, data.url);
    }
    const result = snapshotResult(output.result);
    if (!result.ok) return this.errorResponse(meta, result.code, result.status);
    let mapped: unknown;
    try {
      mapped = snapshotValue(output.mapData(result.data));
      const parsed = output.schema.safeParse(mapped);
      if (!parsed.success) return this.errorResponse(meta, "internal_error", 500);
      const payload = objectCreate(null) as Record<string, unknown>;
      objectDefineProperty(payload, "data", { configurable: false, enumerable: true, value: parsed.data, writable: false });
      objectDefineProperty(payload, "error", { configurable: false, enumerable: true, value: null, writable: false });
      return this.jsonResponse(meta, payload, output.status ?? 200, output.cache ?? "no-store");
    } catch {
      return this.errorResponse(meta, "internal_error", 500);
    }
  }

  private safeRedirectTarget(value: string): boolean {
    try {
      const target = new nativeURL(value);
      if (target.hash !== "") return false;
      for (let index = 0; index < this.allowedRedirects.length; index += 1) {
        const allowed = this.allowedRedirects[index];
        if (allowed === undefined) return false;
        const base = new nativeURL(allowed);
        if (target.origin === base.origin && target.pathname === base.pathname) return true;
      }
      return false;
    } catch {
      return false;
    }
  }

  private jsonResponse(meta: RequestMeta | null, value: object, status: number, cache: "no-store" | "public"): Response {
    const headers = new nativeHeaders();
    invoke(headersSet, headers, ["content-type", "application/json; charset=utf-8"]);
    invoke(headersSet, headers, ["cache-control", cache === "public" ? SAFE_CACHE_CONTROL : "no-store"]);
    return this.finalizeResponse(meta, new nativeResponse(invoke(jsonStringify, undefined, [value]), { status, headers }));
  }

  private errorResponse(meta: RequestMeta | null, code: PublicAuthErrorCode, status: number): Response {
    const requestId = meta?.requestId ?? randomUUID();
    const payload = objectCreate(null) as Record<string, unknown>;
    const error = objectCreate(null) as Record<string, unknown>;
    objectDefineProperty(error, "code", { configurable: false, enumerable: true, value: code, writable: false });
    objectDefineProperty(error, "message", { configurable: false, enumerable: true, value: messageForCode(code), writable: false });
    objectDefineProperty(error, "request_id", { configurable: false, enumerable: true, value: requestId, writable: false });
    objectDefineProperty(payload, "error", { configurable: false, enumerable: true, value: error, writable: false });
    const response = this.jsonResponse(meta, payload, status, "no-store");
    if (status === 429) invoke(headersSet, response.headers, ["retry-after", "1"]);
    return response;
  }

  private emptyResponse(meta: RequestMeta, status: number): Response {
    const headers = new nativeHeaders();
    invoke(headersSet, headers, ["cache-control", "no-store"]);
    return this.finalizeResponse(meta, new nativeResponse(null, { status, headers }));
  }

  private redirectResponse(meta: RequestMeta, location: string): Response {
    const headers = new nativeHeaders();
    invoke(headersSet, headers, ["location", location]);
    invoke(headersSet, headers, ["cache-control", "no-store"]);
    return this.finalizeResponse(meta, new nativeResponse(null, { status: 303, headers }));
  }

  private finalizeResponse(meta: RequestMeta | null, response: Response): Response {
    const headers = response.headers;
    if (meta !== null) {
      invoke(headersSet, headers, ["x-request-id", meta.requestId]);
      invoke(headersSet, headers, ["vary", "Origin"]);
      if (meta.origin !== null && containsExact(this.allowedOrigins, meta.origin)) {
        invoke(headersSet, headers, ["access-control-allow-origin", meta.origin]);
        invoke(headersSet, headers, ["access-control-allow-credentials", "true"]);
        invoke(headersSet, headers, ["access-control-expose-headers", "x-request-id"]);
      }
    }
    try {
      objectDefineProperty(response, "then", {
        configurable: false,
        enumerable: false,
        value: undefined,
        writable: false,
      });
    } catch {
      throw new AuthConfigurationError("Response then shield is unavailable");
    }
    return response;
  }
}

function copyChunk(value: unknown): Uint8Array | null {
  if (!(value instanceof nativeUint8Array)) return null;
  let length: unknown;
  try { length = invoke(typedArrayLengthGetter, value, []); } catch { return null; }
  if (typeof length !== "number" || !authNumberIsSafeInteger(length) || length < 0) return null;
  if (length > MAX_BODY_BYTES) return new nativeUint8Array(MAX_BODY_BYTES + 1);
  const output = new nativeUint8Array(length);
  for (let index = 0; index < length; index += 1) {
    const item = ownDataProperty(value, `${index}`);
    if (!item.valid || !item.present || typeof item.value !== "number" || !authNumberIsInteger(item.value) || item.value < 0 || item.value > 255) return null;
    output[index] = item.value;
  }
  return output;
}
