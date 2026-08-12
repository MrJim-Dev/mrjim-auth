import {
  AuthApiError,
  AuthConfigurationError,
  type AuthError,
  isPublicAuthErrorCode,
} from "../shared/errors.js";
import { authFailure, authSuccess, type AuthResult } from "../shared/result.js";
import { safeArrayIsArray, safeDefineData, safeStringEndsWith, safeStringIncludes, safeStringSlice, safeStringStartsWith, safeStringToLowerCase, safeStringTrim } from "../shared/safe-intrinsics.js";
import {
  awaitSafe,
  captureMethod,
  createNullRecord,
  hasOwnData,
  invoke,
  isObjectLike,
  ownData,
  parseJson,
  snapshotJson,
  stringifyJson,
  trimString,
  MAX_CLIENT_BODY_BYTES,
  MAX_CLIENT_STRING,
  type BoundaryResult,
} from "./boundary.js";

const transportURL = URL;
const transportURLSearchParams = URLSearchParams;
const transportResponse = Response;
const transportObjectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const transportObjectGetPrototypeOf = Object.getPrototypeOf;
const transportObjectPrototype = Object.prototype;
const transportObjectHasOwnProperty = Object.prototype.hasOwnProperty;
const transportReflectApply = Reflect.apply;
const transportNumberIsSafeInteger = Number.isSafeInteger;
const transportArrayPush = Array.prototype.push;
const transportObjectFreeze = Object.freeze;
const transportResponseStatusGetter = (() => {
  const descriptor = transportObjectGetOwnPropertyDescriptor(transportResponse.prototype, "status");
  if (descriptor === undefined || typeof descriptor.get !== "function") throw new AuthConfigurationError("Response.status is unavailable");
  return descriptor.get;
})();
const transportResponseBodyGetter = (() => {
  const descriptor = transportObjectGetOwnPropertyDescriptor(transportResponse.prototype, "body");
  if (descriptor === undefined || typeof descriptor.get !== "function") throw new AuthConfigurationError("Response.body is unavailable");
  return descriptor.get;
})();
const transportResponseText = captureMethod(transportResponse.prototype, "text", "Response.text", "configuration");
const transportAbortController = AbortController;
const transportAbort = captureMethod(transportAbortController.prototype, "abort", "AbortController.abort", "configuration").method;
const transportAbortSignalGetter = (() => {
  const descriptor = transportObjectGetOwnPropertyDescriptor(transportAbortController.prototype, "signal");
  if (descriptor === undefined || typeof descriptor.get !== "function") throw new AuthConfigurationError("AbortController.signal is unavailable");
  return descriptor.get;
})();
const transportTextEncoder = TextEncoder;
const transportTextDecoder = TextDecoder;
const transportEncoder = new transportTextEncoder();
const transportDecoder = new transportTextDecoder("utf-8", { fatal: true });
const transportEncode = captureMethod(transportTextEncoder.prototype, "encode", "TextEncoder.encode", "configuration").method;
const transportDecode = captureMethod(transportTextDecoder.prototype, "decode", "TextDecoder.decode", "configuration").method;
const transportUint8Array = Uint8Array;
const transportUint8ArraySet = Uint8Array.prototype.set;
const transportSet = Set;
const transportSetAdd = Set.prototype.add;
const transportSetDelete = Set.prototype.delete;
const transportSetForEach = Set.prototype.forEach;

const MAX_BASE_URL = 2048;
const MAX_API_KEY = 512;
const MAX_HEADER_COUNT = 128;
const MAX_HEADER_VALUE = 4096;

export type TransportMethod = "GET" | "POST" | "PUT" | "DELETE";

export interface TransportRequest {
  readonly method: TransportMethod;
  readonly path: string;
  readonly query?: readonly (readonly [string, string])[];
  readonly body?: unknown;
  readonly bearer?: string | undefined;
  readonly signal?: AbortSignal | undefined;
  readonly operation?: string;
}

export interface TransportOptions {
  readonly baseUrl: string;
  readonly publishableKey?: string | undefined;
  readonly fetch: typeof fetch;
  readonly headers?: readonly (readonly [string, string])[] | undefined;
  readonly debug?: boolean | ((message: string, context?: unknown) => void) | undefined;
}

export interface Transport {
  readonly baseUrl: string;
  readonly request: (request: TransportRequest) => Promise<AuthResult<unknown>>;
  readonly dispose: () => void;
}

function internalError(): AuthApiError {
  return new AuthApiError("internal_error", 500, "Internal authentication error");
}

function safeError(code: "invalid_request" | "internal_error", message: string): AuthApiError {
  return new AuthApiError(code, code === "invalid_request" ? 400 : 500, message);
}

function validRequestId(value: unknown): value is string {
  if (typeof value !== "string" || value.length < 1 || value.length > 128) return false;
  for (let index = 0; index < value.length; index += 1) {
    const character = value[index];
    if (character === undefined) return false;
    const alphaNumeric = (character >= "a" && character <= "z")
      || (character >= "A" && character <= "Z")
      || (character >= "0" && character <= "9");
    if (!alphaNumeric && character !== "_" && character !== "-") return false;
  }
  return true;
}

function responseStatus(response: object): number | null {
  try {
    const own = transportObjectGetOwnPropertyDescriptor(response, "status");
    if (own !== undefined && !transportReflectApply(transportObjectHasOwnProperty, own, ["value"])) return null;
    if (own !== undefined) return typeof own.value === "number" ? own.value : null;
    if (transportObjectGetPrototypeOf(response) === transportResponse.prototype) {
      return transportReflectApply(transportResponseStatusGetter, response, []) as number;
    }
    const value = ownData(response, "status");
    return value.ok && value.present && typeof value.value === "number" ? value.value : null;
  } catch {
    return null;
  }
}

function responseBodyMethod(response: object): Function | null {
  try {
    if (transportObjectGetPrototypeOf(response) === transportResponse.prototype) return transportResponseText.method;
    return captureMethod(response, "text", "response.text").method;
  } catch {
    return null;
  }
}

function responseBodyStream(response: object): object | null {
  try {
    if (transportObjectGetPrototypeOf(response) !== transportResponse.prototype) return null;
    const value = transportReflectApply(transportResponseBodyGetter, response, []);
    return isObjectLike(value) ? value : null;
  } catch {
    return null;
  }
}

function utf8Length(value: string): number | null {
  try {
    const encoded = invoke<unknown>(transportEncode, transportEncoder, [value]);
    return encoded instanceof transportUint8Array ? encoded.byteLength : null;
  } catch {
    return null;
  }
}

async function boundedResponseText(response: object): Promise<string | null> {
  const stream = responseBodyStream(response);
  if (stream !== null) {
    try {
      const getReader = captureMethod(stream, "getReader", "response.body.getReader");
      const reader = invoke<unknown>(getReader.method, getReader.receiver, []);
      if (!isObjectLike(reader)) return null;
      const read = captureMethod(reader, "read", "response reader.read");
      const cancel = captureMethod(reader, "cancel", "response reader.cancel");
      const release = captureMethod(reader, "releaseLock", "response reader.releaseLock");
      const chunks: Uint8Array[] = [];
      let total = 0;
      while (true) {
        const item = await awaitSafe(invoke<unknown>(read.method, read.receiver, []), "response stream");
        if (!isObjectLike(item)) return null;
        const done = ownData(item, "done");
        const value = ownData(item, "value");
        if (!done.ok || !done.present || typeof done.value !== "boolean" || !value.ok) return null;
        if (done.value) break;
        if (!value.present || !(value.value instanceof transportUint8Array)) return null;
        total += value.value.byteLength;
        if (total > MAX_CLIENT_BODY_BYTES) {
          try { await awaitSafe(invoke<unknown>(cancel.method, cancel.receiver, []), "response stream cancel"); } catch { /* Oversized response already fails closed. */ }
          return null;
        }
        transportArrayPush.call(chunks, value.value);
      }
      const bytes = new transportUint8Array(total);
      let offset = 0;
      for (let index = 0; index < chunks.length; index += 1) {
        const chunk = chunks[index];
        if (chunk === undefined) return null;
        transportReflectApply(transportUint8ArraySet, bytes, [chunk, offset]);
        offset += chunk.byteLength;
      }
      const decoded = invoke<unknown>(transportDecode, transportDecoder, [bytes]);
      try { invoke(release.method, release.receiver, []); } catch { /* Full consumption already released resources. */ }
      return typeof decoded === "string" ? decoded : null;
    } catch {
      return null;
    }
  }
  const method = responseBodyMethod(response);
  if (method === null) return null;
  const bodyValue = invoke<unknown>(method, response, []);
  const text = await awaitSafe(bodyValue as string | Promise<string>, "response body");
  if (typeof text !== "string") return null;
  const length = utf8Length(text);
  return length !== null && length <= MAX_CLIENT_BODY_BYTES ? text : null;
}

function snapshotEnvelope(value: unknown): BoundaryResult<Record<string, unknown>> {
  if (value === null || typeof value !== "object") return { ok: false };
  const snapshot = snapshotJson(value, "authentication response");
  if (snapshot === null || typeof snapshot !== "object" || safeArrayIsArray(snapshot)) return { ok: false };
  return { ok: true, value: snapshot as Record<string, unknown> };
}

function parseError(status: number, body: unknown): AuthError {
  const envelope = snapshotEnvelope(body);
  if (!envelope.ok) return internalError();
  const error = ownData(envelope.value, "error");
  if (!error.ok || !error.present || error.value === null || typeof error.value !== "object" || safeArrayIsArray(error.value)) return internalError();
  const code = ownData(error.value, "code");
  const message = ownData(error.value, "message");
  const requestId = ownData(error.value, "request_id");
  if (!code.ok || !code.present || !isPublicAuthErrorCode(code.value) || !message.ok || !message.present || typeof message.value !== "string" || message.value.length < 1 || message.value.length > 2048) return internalError();
  if (requestId.present && (!requestId.ok || typeof requestId.value !== "string" || !validRequestId(requestId.value))) return internalError();
  const loweredMessage = safeStringToLowerCase(message.value) ?? "";
  const safeMessage = safeStringIncludes(loweredMessage, "bearer") || safeStringIncludes(loweredMessage, "token") || safeStringIncludes(loweredMessage, "secret") || safeStringIncludes(loweredMessage, "authorization code") || safeStringIncludes(loweredMessage, "authorization_code") || safeStringIncludes(loweredMessage, "auth code") || safeStringIncludes(loweredMessage, "code=") || safeStringIncludes(loweredMessage, "code:") || safeStringIncludes(loweredMessage, "state=") || safeStringIncludes(loweredMessage, "verifier") || safeStringIncludes(loweredMessage, "credential") || safeStringIncludes(loweredMessage, "password")
    ? "Authentication request failed"
    : message.value;
  return new AuthApiError(code.value, status, safeMessage, requestId.ok && requestId.present ? requestId.value as string : undefined);
}

function parseSuccess(status: number, body: unknown): AuthResult<unknown> {
  const envelope = snapshotEnvelope(body);
  if (!envelope.ok) return authFailure(internalError());
  const data = ownData(envelope.value, "data");
  const error = ownData(envelope.value, "error");
  if (!data.ok || !data.present || !error.ok || !error.present || error.value !== null) return authFailure(internalError());
  return authSuccess(data.value);
}

function normalizeBaseUrl(value: unknown): string {
  if (typeof value !== "string" || value.length === 0 || value.length > MAX_BASE_URL || safeStringTrim(value) !== value) {
    throw new AuthConfigurationError("auth URL is malformed");
  }
  if (/(?:^|\/)\.{1,2}(?:\/|$)/u.test(value) || /%2f|%2e/iu.test(value)) {
    throw new AuthConfigurationError("auth URL path normalization is ambiguous");
  }
  let parsed: URL;
  try {
    parsed = new transportURL(value);
  } catch {
    throw new AuthConfigurationError("auth URL is malformed");
  }
  if ((parsed.protocol !== "http:" && parsed.protocol !== "https:") || parsed.username !== "" || parsed.password !== "" || parsed.search !== "" || parsed.hash !== "") {
    throw new AuthConfigurationError("auth URL must be an absolute HTTP(S) URL without credentials or query parameters");
  }
  if (safeStringIncludes(parsed.pathname, "//") || /(?:^|\/)\.{1,2}(?:\/|$)/u.test(parsed.pathname) || /%2f|%2e/iu.test(parsed.pathname)) {
    throw new AuthConfigurationError("auth URL path normalization is ambiguous");
  }
  let pathname = parsed.pathname;
  while (pathname.length > 1 && safeStringEndsWith(pathname, "/")) pathname = safeStringSlice(pathname, 0, pathname.length - 1) ?? pathname;
  parsed.pathname = pathname;
  return pathname === "/" ? parsed.origin : parsed.href;
}

function validateApiKey(value: unknown): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string" || value.length === 0 || value.length > MAX_API_KEY || safeStringTrim(value) !== value || /[\u0000-\u001f\u007f]/u.test(value)) throw new AuthConfigurationError("publishable key is malformed");
  return value;
}

function validateHeaders(headers: readonly (readonly [string, string])[] | undefined): readonly (readonly [string, string])[] {
  if (headers === undefined) return [];
  if (headers.length > MAX_HEADER_COUNT) throw new AuthConfigurationError("global headers are oversized");
  const output: Array<readonly [string, string]> = [];
  const seen = createNullRecord();
  for (let index = 0; index < headers.length; index += 1) {
    const entry = headers[index];
    if (entry === undefined || entry.length !== 2 || typeof entry[0] !== "string" || typeof entry[1] !== "string" || entry[0].length === 0 || entry[0].length > 128 || entry[1].length > MAX_HEADER_VALUE || !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/u.test(entry[0]) || /[\u0000-\u001f\u007f]/u.test(entry[1])) throw new AuthConfigurationError("global headers are malformed");
    const normalized = safeStringToLowerCase(entry[0]);
    if (normalized === null || transportReflectApply(transportObjectHasOwnProperty, seen, [normalized]) || !safeDefineData(seen, normalized, true)) throw new AuthConfigurationError("global headers are malformed");
    transportArrayPush.call(output, transportObjectFreeze([normalized, entry[1]]));
  }
  return transportObjectFreeze(output);
}

function safeDebug(debug: TransportOptions["debug"], message: string, context: Record<string, unknown>): void {
  if (typeof debug !== "function") return;
  try {
    debug(message, { operation: context.operation, method: context.method, path: context.path, status: context.status });
  } catch {
    // Debug hooks are observational and cannot change the auth result.
  }
}

function makeUrl(baseUrl: string, path: string, query: readonly (readonly [string, string])[] | undefined): string {
  if (typeof path !== "string" || !safeStringStartsWith(path, "/") || safeStringIncludes(path, "?") || safeStringIncludes(path, "#") || path.length > 256) throw new AuthConfigurationError("authentication path is malformed");
  let url: URL;
  try {
    url = new transportURL(`${baseUrl}${path}`);
  } catch {
    throw new AuthConfigurationError("authentication path is malformed");
  }
  if (query !== undefined) {
    if (query.length > 16) throw new AuthConfigurationError("authentication query is oversized");
    const params = new transportURLSearchParams();
    for (let index = 0; index < query.length; index += 1) {
      const pair = query[index];
      if (pair === undefined || pair.length !== 2 || typeof pair[0] !== "string" || typeof pair[1] !== "string" || pair[0].length === 0 || pair[0].length > 128 || pair[1].length > MAX_CLIENT_STRING) throw new AuthConfigurationError("authentication query is malformed");
      params.append(pair[0], pair[1]);
    }
    url.search = params.toString();
  }
  return url.href;
}

export function createTransport(options: TransportOptions): Transport {
  const baseUrl = normalizeBaseUrl(options.baseUrl);
  const publishableKey = validateApiKey(options.publishableKey);
  if (typeof options.fetch !== "function") throw new AuthConfigurationError("fetch must be a function");
  const headers = validateHeaders(options.headers);
  const fetchReceiver = options.fetch;
  const activeControllers = new transportSet<AbortController>();
  let disposed = false;

  const request = async (input: TransportRequest): Promise<AuthResult<unknown>> => {
    if (disposed) return authFailure(internalError());
    const operation = input.operation ?? input.path;
    let url: string;
    try {
      url = makeUrl(baseUrl, input.path, input.query);
    } catch (error) {
      if (error instanceof AuthConfigurationError) throw error;
      return authFailure(internalError());
    }
    const requestHeaders = createNullRecord() as Record<string, string>;
    const controller = new transportAbortController();
    const signal = transportReflectApply(transportAbortSignalGetter, controller, []) as AbortSignal;
    transportReflectApply(transportSetAdd, activeControllers, [controller]);
    try {
      for (let index = 0; index < headers.length; index += 1) {
        const entry = headers[index];
        if (entry === undefined) continue;
        if (entry[0] === "apikey" || entry[0] === "authorization" || entry[0] === "content-type") continue;
        if (!safeDefineData(requestHeaders, entry[0], entry[1])) return authFailure(internalError());
      }
      if (publishableKey !== undefined && !safeDefineData(requestHeaders, "apikey", publishableKey)) return authFailure(internalError());
      if (input.bearer !== undefined) {
        const bearer = trimString(input.bearer, "bearer token", 8192);
        if (/[\u0000-\u001f\u007f]/u.test(bearer)) return authFailure(internalError());
        if (!safeDefineData(requestHeaders, "authorization", `Bearer ${bearer}`)) return authFailure(internalError());
      }
      let body: string | undefined;
      if (input.body !== undefined) {
        body = stringifyJson(input.body, "authentication request body");
        const bodyLength = utf8Length(body);
        if (bodyLength === null || bodyLength > MAX_CLIENT_BODY_BYTES) return authFailure(internalError());
        if (!safeDefineData(requestHeaders, "content-type", "application/json")) return authFailure(internalError());
      }
      const result = invoke<unknown>(fetchReceiver, undefined, [url, {
        method: input.method,
        headers: requestHeaders,
        ...(body === undefined ? {} : { body }),
        signal,
      }]);
      const response = await awaitSafe(result, "fetch");
      if (disposed) return authFailure(internalError());
      if (!isObjectLike(response)) return authFailure(internalError());
      const status = responseStatus(response);
      if (status === null || !transportNumberIsSafeInteger(status) || status < 100 || status > 599) return authFailure(internalError());
      const text = await boundedResponseText(response);
      if (disposed) return authFailure(internalError());
      if (text === null) return authFailure(internalError());
      let parsed: unknown;
      try {
        parsed = parseJson(text, "authentication response");
      } catch {
        return authFailure(internalError());
      }
      safeDebug(options.debug, "authentication request completed", { operation, method: input.method, path: input.path, status });
      if (status < 200 || status >= 300) return authFailure(parseError(status, parsed));
      return parseSuccess(status, parsed);
    } catch (error) {
      if (error instanceof AuthConfigurationError) throw error;
      safeDebug(options.debug, "authentication request failed", { operation, method: input.method, path: input.path, status: 0 });
      return authFailure(internalError());
    } finally {
      transportReflectApply(transportSetDelete, activeControllers, [controller]);
    }
  };

  const dispose = (): void => {
    if (disposed) return;
    disposed = true;
    transportReflectApply(transportSetForEach, activeControllers, [(controller: AbortController) => {
      try { invoke(transportAbort, controller, []); } catch { /* Disposal is fail-closed and idempotent. */ }
    }]);
  };

  return transportObjectFreeze({ baseUrl, request, dispose });
}

export { normalizeBaseUrl };
