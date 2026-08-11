import { createHmac, randomUUID, timingSafeEqual } from "node:crypto";
import { z } from "zod";
import {
  AuthApiError,
  AuthConfigurationError,
  isPublicAuthErrorCode,
  type PublicAuthErrorCode,
} from "../shared/errors.js";
import type { AuthRepository } from "../shared/contracts.js";
import type { AuthServerOptions } from "../shared/config.js";
import { uuidSchema, type Session, type User } from "../shared/types.js";
import { createAuthorizationRequestContext, type AuthorizationRequestContext, type AuthorizationRequirement, type AuthorizationSubject } from "./authorization.js";
import type { AuthenticatedSession } from "./sessions.js";
import type { AccessTokenClaims } from "./tokens.js";
import { handlePublicRoute } from "./routes/public.js";
import { handleUserRoute } from "./routes/user.js";
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
const nativeTextDecoder = TextDecoder;
const nativePromise = Promise;
const nativePromisePrototype = Promise.prototype;
const nativePromiseThen = Promise.prototype.then;
const nativeObjectPrototype = Object.prototype;
const nativeArrayIsArray = Array.isArray;
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
const readableReaderReleaseLock = captureMethod(ReadableStreamDefaultReader.prototype, "releaseLock");
const typedArrayPrototype = objectGetPrototypeOf(nativeUint8Array.prototype);
const typedArrayLengthGetter = (() => {
  const descriptor = objectGetOwnPropertyDescriptor(typedArrayPrototype, "length");
  if (descriptor === undefined || typeof descriptor.get !== "function") {
    throw new AuthConfigurationError("required typed-array length getter is unavailable");
  }
  return descriptor.get;
})();
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
const ALLOWED_REQUEST_HEADERS = new Set(["apikey", "authorization", "content-type", "x-request-id"]);
const SAFE_CACHE_CONTROL = "public, max-age=300, must-revalidate";

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
  readonly origin: string | null;
};

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
    throw new AuthConfigurationError(`required Web API getter is unavailable: ${String(key)}`);
  }
  return descriptor.get;
}

function captureMethod(target: object, key: PropertyKey): Function {
  const descriptor = objectGetOwnPropertyDescriptor(target, key);
  if (descriptor === undefined || typeof descriptor.value !== "function") {
    throw new AuthConfigurationError(`required Web API method is unavailable: ${String(key)}`);
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

function hasThenProperty(value: object): boolean {
  let current: object | null = value;
  for (let depth = 0; current !== null && depth < 8; depth += 1) {
    try {
      if (objectGetOwnPropertyDescriptor(current, "then") !== undefined) return true;
      current = objectGetPrototypeOf(current);
    } catch {
      return true;
    }
  }
  return current !== null;
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

function validHeaderValue(value: string | null): string | null {
  if (value === null) return null;
  if (value.includes(",") || value.includes("\r") || value.includes("\n")) return null;
  return value;
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

function hasThenValue(value: unknown): boolean {
  return value !== null && (typeof value === "object" || typeof value === "function") && hasThenProperty(value);
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

function snapshotValue(value: unknown, depth = 0, seen = new Set<object>()): unknown {
  if (depth > MAX_SNAPSHOT_DEPTH) throw new RequestBoundaryError("internal_error", 500);
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new RequestBoundaryError("internal_error", 500);
    return value;
  }
  if (typeof value !== "object") throw new RequestBoundaryError("internal_error", 500);
  if (seen.has(value)) throw new RequestBoundaryError("internal_error", 500);
  seen.add(value);
  try {
    if (nativeArrayIsArray(value)) {
      if (hasThenProperty(value)) throw new RequestBoundaryError("internal_error", 500);
      const length = ownDataProperty(value, "length");
      if (!length.valid || !length.present || typeof length.value !== "number" || !Number.isSafeInteger(length.value) || length.value < 0 || length.value > MAX_SNAPSHOT_KEYS) {
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
        output.push(snapshotValue(item.value, depth + 1, seen));
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
    seen.delete(value);
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
  const status = statusProperty.valid && statusProperty.present && typeof statusProperty.value === "number" && Number.isSafeInteger(statusProperty.value)
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
  if (typeof length !== "number" || !Number.isSafeInteger(length) || length !== 32) return null;
  const output = new nativeUint8Array(length);
  for (let index = 0; index < length; index += 1) {
    const item = ownDataProperty(value, `${index}`);
    if (!item.valid || !item.present || typeof item.value !== "number" || !Number.isInteger(item.value) || item.value < 0 || item.value > 255) return null;
    output[index] = item.value;
  }
  return output;
}

function safeDate(value: unknown): Date | null {
  if (!(value instanceof Date)) return null;
  try {
    const time = dateGetTime(value);
    return Number.isFinite(time) ? new Date(time) : null;
  } catch {
    return null;
  }
}

function safeStringArray(value: unknown): readonly string[] | null {
  if (!nativeArrayIsArray(value) || hasThenProperty(value)) return null;
  const lengthProperty = ownDataProperty(value, "length");
  if (!lengthProperty.valid || !lengthProperty.present || typeof lengthProperty.value !== "number" || !Number.isSafeInteger(lengthProperty.value) || lengthProperty.value < 0 || lengthProperty.value > MAX_SNAPSHOT_KEYS) return null;
  for (const name of objectGetOwnPropertyNames(value)) {
    if (name === "length") continue;
    if (!/^\d+$/u.test(name) || Number(name) >= lengthProperty.value) return null;
  }
  const output: string[] = [];
  for (let index = 0; index < lengthProperty.value; index += 1) {
    const item = ownDataProperty(value, `${index}`);
    if (!item.valid || !item.present || typeof item.value !== "string" || item.value.length > 256) return null;
    output.push(item.value);
  }
  return objectFreeze(output);
}

function safeApiKey(value: unknown, expectedHash: Uint8Array, now: Date): RouteAuthContext["key"] | null {
  if (value === null || (typeof value !== "object" && typeof value !== "function") || hasThenProperty(value)) return null;
  const allowedNames = new Set(["id", "prefix", "kind", "scopes", "expires_at", "revoked_at", "key_hash"]);
  try {
    if (objectGetOwnPropertySymbols(value).length !== 0 || objectGetOwnPropertyNames(value).some((name) => !allowedNames.has(name))) return null;
  } catch {
    return null;
  }
  const snapshot: Record<string, unknown> = objectCreate(null) as Record<string, unknown>;
  for (const name of ["id", "prefix", "kind", "scopes", "expires_at", "revoked_at", "key_hash"]) {
    const property = ownDataProperty(value, name);
    if (!property.valid || !property.present) return null;
    snapshot[name] = property.value;
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
  return actual.length === configured.length && actual.every((candidate) => configured.includes(candidate));
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
    keys.push(value.value);
    if (keys.length > 128) return null;
  }
}

function decodeSegment(value: string): string | null {
  try {
    const decoded = decodeURIComponent(value);
    if (decoded === "" || decoded.includes("/") || decoded.includes("\\") || decoded.includes("\u0000")) return null;
    return decoded;
  } catch {
    return null;
  }
}

function exactPath(path: string, basePath: string): { readonly path: string; readonly callbackProvider?: string } | null {
  if (!path.startsWith(`${basePath}/`)) return null;
  const relative = path.slice(basePath.length);
  if (relative === "/callback" || relative === "/callback/") return null;
  if (relative.startsWith("/callback/")) {
    const providerPart = relative.slice("/callback/".length);
    if (providerPart.includes("/")) return null;
    const provider = decodeSegment(providerPart);
    return provider === null ? null : { path: "/callback/{provider}", callbackProvider: provider };
  }
  if (relative.startsWith("/user/identities/")) {
    const identityPart = relative.slice("/user/identities/".length);
    if (identityPart.includes("/")) return null;
    const identityId = decodeSegment(identityPart);
    if (identityId === null || !uuidSchema.safeParse(identityId).success) return null;
    return { path: "/user/identities/{id}", callbackProvider: identityId };
  }
  if (relative.endsWith("/")) return null;
  return { path: relative };
}

function routeContract(path: string, method?: string): RouteContract | undefined {
  return routeContracts.find((candidate) => candidate.path === path && (method === undefined || candidate.method === method));
}

function isJsonContentType(value: string | null): boolean {
  if (value === null) return false;
  const normalized = value.trim().toLowerCase();
  return normalized === "application/json" || normalized === "application/json; charset=utf-8";
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
  private readonly config: AuthServerOptions;
  private readonly repository: AuthRepository;
  private readonly services: AuthServerServices;
  private readonly apiKeyHashKey: Uint8Array;
  private readonly baseOrigin: string;
  private readonly basePath: string;
  private readonly allowedOrigins: readonly string[];
  private readonly allowedRedirects: readonly string[];

  constructor(options: AuthServerRuntimeOptions) {
    this.config = options.config;
    this.repository = options.repository;
    this.services = options.services;
    this.apiKeyHashKey = nativeUint8Array.from(options.apiKeyHashKey);
    this.baseOrigin = options.baseOrigin;
    this.basePath = options.basePath;
    this.allowedOrigins = objectFreeze([...options.allowedOrigins]);
    this.allowedRedirects = objectFreeze([...options.allowedRedirects]);
    if (this.apiKeyHashKey.byteLength < 32) throw new AuthConfigurationError("API-key hash key must contain at least 32 bytes");
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
        ...(auth === undefined ? {} : { auth }),
        services: this.services,
        invoke: <T>(operation: () => unknown) => invokeUntrusted<T>(operation),
      };
      let output: RouteOutput | null;
      if (routed.path.startsWith("/user") || routed.path === "/logout") {
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
      const rawRequestId = validHeaderValue(invoke<string | null>(headersGet, headers, ["x-request-id"]));
      const rawOrigin = validHeaderValue(invoke<string | null>(headersGet, headers, ["origin"]));
      const requestId = validRequestId(rawRequestId) ? rawRequestId : randomUUID();
      return { request, method, url, headers: headers as Headers, requestId, origin: rawOrigin };
    } catch {
      return null;
    }
  }

  private checkOrigin(meta: RequestMeta): { readonly code: "forbidden" | "not_found"; readonly status: 403 | 404 } | null {
    if (meta.url.origin !== this.baseOrigin) return { code: "not_found", status: 404 };
    if (meta.origin === null) return null;
    if (!this.allowedOrigins.includes(meta.origin)) return { code: "forbidden", status: 403 };
    return null;
  }

  private preflight(meta: RequestMeta, routed: { readonly path: string } | null): Response {
    if (meta.origin === null || routed === null || routeContract(routed.path) === undefined) return this.errorResponse(meta, "invalid_request", 400);
    const requestedMethod = validHeaderValue(invoke<string | null>(headersGet, meta.headers, ["access-control-request-method"]));
    const requestedHeaders = validHeaderValue(invoke<string | null>(headersGet, meta.headers, ["access-control-request-headers"]));
    if (requestedMethod === null || !["GET", "POST", "PUT", "DELETE"].includes(requestedMethod)) return this.errorResponse(meta, "invalid_request", 400);
    if (routeContract(routed.path, requestedMethod) === undefined) return this.errorResponse(meta, "invalid_request", 405);
    if (requestedHeaders !== null) {
      for (const header of requestedHeaders.split(",").map((item) => item.trim().toLowerCase())) {
        if (header === "" || !ALLOWED_REQUEST_HEADERS.has(header)) return this.errorResponse(meta, "forbidden", 403);
      }
    }
    const response = this.emptyResponse(meta, 204);
    invoke(headersSet, response.headers, ["access-control-allow-methods", "GET, POST, PUT, DELETE"]);
    invoke(headersSet, response.headers, ["access-control-allow-headers", "apikey, authorization, content-type, x-request-id"]);
    invoke(headersSet, response.headers, ["access-control-max-age", "300"]);
    return response;
  }

  private queryFor(url: URL, contract: RouteContract): URLSearchParams {
    const params = invoke<URLSearchParams>(urlSearchParamsGetter, url, []);
    const keys = readQueryKeys(params);
    if (keys === null) throw new RequestBoundaryError("invalid_request", 400);
    const allowed = new Set((contract.query ?? []).map(({ name }) => name));
    for (const key of keys) {
      if (!allowed.has(key)) throw new RequestBoundaryError("invalid_request", 400);
      const values = invoke<string[]>(searchParamsGetAll, params, [key]);
      if (!nativeArrayIsArray(values) || values.length !== 1) throw new RequestBoundaryError("invalid_request", 400);
    }
    for (const parameter of contract.query ?? []) {
      const values = invoke<string[]>(searchParamsGetAll, params, [parameter.name]);
      if (parameter.required && (!nativeArrayIsArray(values) || values.length !== 1 || values[0] === "")) throw new RequestBoundaryError("invalid_request", 400);
    }
    return params;
  }

  private async parseRequestBody(meta: RequestMeta, contract: RouteContract, query: URLSearchParams): Promise<unknown> {
    if (contract.body === undefined) return undefined;
    const contentLength = validHeaderValue(invoke<string | null>(headersGet, meta.headers, ["content-length"]));
    if (contentLength !== null) {
      if (!/^\d+$/u.test(contentLength)) throw new RequestBoundaryError("invalid_request", 400);
      const length = Number(contentLength);
      if (!Number.isSafeInteger(length) || length > MAX_BODY_BYTES) throw new RequestBoundaryError("invalid_request", 413);
    }
    const contentType = validHeaderValue(invoke<string | null>(headersGet, meta.headers, ["content-type"]));
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
    try {
      for (;;) {
        const raw = invoke<unknown>(readableReaderRead, reader, []);
        const result = await nativePromiseValue(raw);
        if (result === null || typeof result !== "object") throw new RequestBoundaryError("invalid_request", 400);
        const doneProperty = ownDataProperty(result, "done");
        const valueProperty = ownDataProperty(result, "value");
        if (!doneProperty.valid || !doneProperty.present || typeof doneProperty.value !== "boolean" || !valueProperty.valid || !valueProperty.present) throw new RequestBoundaryError("invalid_request", 400);
        if (doneProperty.value) break;
        const chunk = copyChunk(valueProperty.value);
        if (chunk === null) throw new RequestBoundaryError("invalid_request", 400);
        total += chunk.byteLength;
        if (total > MAX_BODY_BYTES || (declaredLength !== undefined && total > declaredLength)) throw new RequestBoundaryError("invalid_request", 413);
        chunks.push(chunk);
      }
    } catch (error) {
      if (error instanceof RequestBoundaryError && error.code !== "internal_error") throw error;
      throw new RequestBoundaryError("invalid_request", 400);
    } finally {
      try { invoke(readableReaderReleaseLock, reader, []); } catch { /* best effort */ }
    }
    if (declaredLength !== undefined && total !== declaredLength) throw new RequestBoundaryError("invalid_request", 400);
    const output = new nativeUint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      output.set(chunk, offset);
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
    const rawApiKey = validHeaderValue(invoke<string | null>(headersGet, meta.headers, ["apikey"]));
    if (rawApiKey === null || rawApiKey.trim() !== rawApiKey || rawApiKey.length < 8 || rawApiKey.length > 512) {
      throw new AuthApiError("unauthorized", 401, "API key is required", meta.requestId);
    }
    const expectedHash = Uint8Array.from(createHmac("sha256", this.apiKeyHashKey).update(`apikey\0${rawApiKey}`, "utf8").digest());
    const record = await invokeUntrusted<unknown>(() => this.repository.operations.findApiKeyByHash(expectedHash, { now }));
    const key = safeApiKey(record, expectedHash, now);
    if (key === null) throw new AuthApiError("unauthorized", 401, "Invalid API key", meta.requestId);
    if (key.kind === "secret" && meta.origin !== null) throw new AuthApiError("forbidden", 403, "Secret API keys are not accepted from browser origins", meta.requestId);

    const authorization = validHeaderValue(invoke<string | null>(headersGet, meta.headers, ["authorization"]));
    let bearer: string | null = null;
    if (authorization !== null) {
      if (!isValidBearer(authorization)) throw new AuthApiError("unauthorized", 401, "Invalid bearer authorization", meta.requestId);
      bearer = authorization.slice("Bearer ".length);
    }
    const requiresBearer = forceBearer || contract?.security === "user" || (contract?.path === "/authorize" && invoke<string | null>(searchParamsGet, query, ["flow"]) === "link_identity");
    if (requiresBearer && bearer === null) throw new AuthApiError("unauthorized", 401, "Authenticated session is required", meta.requestId);
    if (!requiresBearer && bearer !== null && contract?.path !== "/logout" && contract?.path !== "/authorize") throw new AuthApiError("invalid_request", 400, "Conflicting credentials", meta.requestId);
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
      claimsParsed.data.iss !== this.config.signingKeys.issuer ||
      !audienceMatches(claimsParsed.data.aud, this.config.signingKeys.audience) ||
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
      return this.allowedRedirects.some((allowed) => {
        const base = new nativeURL(allowed);
        return target.origin === base.origin && target.pathname === base.pathname;
      });
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
    return this.jsonResponse(meta, payload, status, "no-store");
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
      if (meta.origin !== null && this.allowedOrigins.includes(meta.origin)) {
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
  if (typeof length !== "number" || !Number.isSafeInteger(length) || length < 0) return null;
  if (length > MAX_BODY_BYTES) return new nativeUint8Array(MAX_BODY_BYTES + 1);
  const output = new nativeUint8Array(length);
  for (let index = 0; index < length; index += 1) {
    const item = ownDataProperty(value, `${index}`);
    if (!item.valid || !item.present || typeof item.value !== "number" || !Number.isInteger(item.value) || item.value < 0 || item.value > 255) return null;
    output[index] = item.value;
  }
  return output;
}
