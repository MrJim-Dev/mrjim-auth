import { AuthApiError } from "../../shared/errors.js";
import { authFailure, authSuccess, type AuthResult } from "../../shared/result.js";
import {
  type AuthorizationScope,
  type ScopeIdentifier,
} from "../../shared/types.js";
import {
  AuthorizationService,
  createAuthorizationRequestContext,
  type AuthorizationSubject,
} from "../authorization.js";

const objectDefineProperty = Object.defineProperty;
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const objectGetPrototypeOf = Object.getPrototypeOf;
const objectCreate = Object.create;
const objectSetPrototypeOf = Object.setPrototypeOf;
const objectHasOwnProperty = Object.prototype.hasOwnProperty;
const reflectApply = Reflect.apply;
const arrayIsArray = Array.isArray;
const numberIsSafeInteger = Number.isSafeInteger;
const nativeHeaders = Headers;
const nativeRequest = Request;
const nativeURL = URL;
const nativeURLSearchParams = URLSearchParams;
const nativeResponse = Response;
const jsonStringify = JSON.stringify;
const MAX_RESPONSE_PERMISSION_KEYS = 100_000;
const requestHeadersGetter = captureGetter(nativeRequest.prototype, "headers", "Request.headers");
const requestMethodGetter = captureGetter(nativeRequest.prototype, "method", "Request.method");
const requestUrlGetter = captureGetter(nativeRequest.prototype, "url", "Request.url");
const urlSearchParamsGetter = captureGetter(nativeURL.prototype, "searchParams", "URL.searchParams");
const headersGet = captureMethod(nativeHeaders.prototype, "get", "Headers.get");
const searchParamsGet = captureMethod(nativeURLSearchParams.prototype, "get", "URLSearchParams.get");
const searchParamsGetAll = captureMethod(nativeURLSearchParams.prototype, "getAll", "URLSearchParams.getAll");
const searchParamsKeys = captureMethod(nativeURLSearchParams.prototype, "keys", "URLSearchParams.keys");
const stringTrim = String.prototype.trim;
const searchParamsIteratorNext = (() => {
  const iterator = reflectApply(searchParamsKeys, new nativeURLSearchParams(), []) as Iterator<string>;
  const prototype = objectGetPrototypeOf(iterator) as { readonly next?: unknown } | null;
  if (prototype === null || typeof prototype.next !== "function") {
    throw new Error("URLSearchParams iterator next is unavailable");
  }
  return prototype.next;
})();

function captureGetter(target: object, key: PropertyKey, label: string): Function {
  const descriptor = objectGetOwnPropertyDescriptor(target, key);
  if (descriptor === undefined || typeof descriptor.get !== "function") {
    throw new Error(`${label} getter is unavailable`);
  }
  return descriptor.get;
}

function captureMethod(target: object, key: PropertyKey, label: string): Function {
  const descriptor = objectGetOwnPropertyDescriptor(target, key);
  if (
    descriptor === undefined ||
    !reflectApply(objectHasOwnProperty, descriptor, ["value"]) ||
    typeof descriptor.value !== "function"
  ) {
    throw new Error(`${label} method is unavailable`);
  }
  return descriptor.value;
}

type DataProperty =
  | { readonly valid: true; readonly present: false }
  | { readonly valid: true; readonly present: true; readonly value: unknown }
  | { readonly valid: false; readonly present: boolean };

function ownDataProperty(value: object, key: PropertyKey): DataProperty {
  try {
    const descriptor = objectGetOwnPropertyDescriptor(value, key);
    if (descriptor === undefined) return { valid: true, present: false };
    if (!reflectApply(objectHasOwnProperty, descriptor, ["value"])) {
      return { valid: false, present: true };
    }
    return { valid: true, present: true, value: descriptor.value };
  } catch {
    return { valid: false, present: false };
  }
}

function invoke<T>(method: Function, receiver: unknown, args: readonly unknown[]): T {
  return reflectApply(method, receiver, args as unknown[]) as T;
}

function newNullPrototypeArray<T>(): T[] {
  const values: T[] = [];
  invoke<object>(objectSetPrototypeOf, undefined, [values, null]);
  return values;
}

function containsNul(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    if (value[index] === "\u0000") return true;
  }
  return false;
}

function isAsciiAlphaNumeric(value: string | undefined): boolean {
  if (value === undefined) return false;
  return (
    (value >= "a" && value <= "z") ||
    (value >= "A" && value <= "Z") ||
    (value >= "0" && value <= "9")
  );
}

function isRequestId(value: unknown): value is string {
  if (typeof value !== "string" || value.length < 1 || value.length > 128) return false;
  if (!isAsciiAlphaNumeric(value[0])) return false;
  for (let index = 1; index < value.length; index += 1) {
    const character = value[index];
    if (character === undefined) return false;
    if (!isAsciiAlphaNumeric(character) && character !== "_" && character !== "-") return false;
  }
  return true;
}

function isScopeType(value: unknown): value is string {
  if (typeof value !== "string" || value.length < 1 || value.length > 64) return false;
  const first = value[0];
  if (first === undefined || first < "a" || first > "z") return false;
  for (let index = 1; index < value.length; index += 1) {
    const character = value[index];
    if (
      character === undefined ||
      !(
        (character >= "a" && character <= "z") ||
        (character >= "0" && character <= "9") ||
        character === "_" ||
        character === "-"
      )
    ) {
      return false;
    }
  }
  return true;
}

type RouteRequestSnapshot = {
  readonly method: string;
  readonly url: string | undefined;
  readonly requestId: string | undefined;
};

function snapshotRequest(request: unknown): RouteRequestSnapshot | null {
  if (request === null || (typeof request !== "object" && typeof request !== "function")) return null;
  try {
    const method = invoke<unknown>(requestMethodGetter, request, []);
    if (typeof method !== "string") return null;
    const headers = invoke<unknown>(requestHeadersGetter, request, []);
    if (headers === null || (typeof headers !== "object" && typeof headers !== "function")) return null;
    const rawRequestId = invoke<unknown>(headersGet, headers, ["x-request-id"]);
    if (rawRequestId !== null && typeof rawRequestId !== "string") return null;
    const requestId = isRequestId(rawRequestId) ? rawRequestId : undefined;
    if (method !== "GET") return { method, url: undefined, requestId };
    const url = invoke<unknown>(requestUrlGetter, request, []);
    if (typeof url !== "string") return null;
    return { method, url, requestId };
  } catch {
    return null;
  }
}

function snapshotStrings(value: unknown): string[] | null {
  if (!arrayIsArray(value)) return null;
  const lengthProperty = ownDataProperty(value, "length");
  if (
    !lengthProperty.valid ||
    !lengthProperty.present ||
    typeof lengthProperty.value !== "number" ||
    !numberIsSafeInteger(lengthProperty.value) ||
    lengthProperty.value < 0 ||
    lengthProperty.value > 2
  ) {
    return null;
  }
  const snapshot: string[] = [];
  for (let index = 0; index < lengthProperty.value; index += 1) {
    const item = ownDataProperty(value, `${index}`);
    if (!item.valid || !item.present || typeof item.value !== "string") return null;
    objectDefineProperty(snapshot, `${index}`, {
      configurable: true,
      enumerable: true,
      value: item.value,
      writable: true,
    });
  }
  return snapshot;
}

function hasOnlyAllowedScopeKeys(params: unknown): boolean {
  try {
    if (params === null || (typeof params !== "object" && typeof params !== "function")) return false;
    const iterator = invoke<Iterator<string>>(searchParamsKeys, params, []);
    for (;;) {
      const step: unknown = invoke<unknown>(searchParamsIteratorNext, iterator, []);
      if (step === null || typeof step !== "object") return false;
      const done = ownDataProperty(step, "done");
      const value = ownDataProperty(step, "value");
      if (
        !done.valid || !done.present || typeof done.value !== "boolean" ||
        !value.valid || !value.present
      ) return false;
      if (done.value === true) return true;
      if (typeof value.value !== "string") return false;
      if (value.value !== "scope_type" && value.value !== "scope_id") return false;
    }
  } catch {
    return false;
  }
}

function defineSafeProperty(target: object, key: PropertyKey, value: unknown): void {
  objectDefineProperty(target, key, {
    configurable: false,
    enumerable: true,
    value,
    writable: false,
  });
}

function safeStatus(value: unknown, fallback: number): number {
  return typeof value === "number" && numberIsSafeInteger(value) && value >= 100 && value <= 599
    ? value
    : fallback;
}

function snapshotResponsePermissions(value: unknown): string[] {
  const snapshot = newNullPrototypeArray<string>();
  if (!arrayIsArray(value)) return snapshot;

  const lengthProperty = ownDataProperty(value, "length");
  if (
    !lengthProperty.valid ||
    !lengthProperty.present ||
    typeof lengthProperty.value !== "number" ||
    !numberIsSafeInteger(lengthProperty.value) ||
    lengthProperty.value < 0 ||
    lengthProperty.value > MAX_RESPONSE_PERMISSION_KEYS
  ) {
    return snapshot;
  }
  for (let index = 0; index < lengthProperty.value; index += 1) {
    const item = ownDataProperty(value, `${index}`);
    if (!item.valid || !item.present || typeof item.value !== "string") {
      return newNullPrototypeArray<string>();
    }
    defineSafeProperty(snapshot, `${index}`, item.value);
  }
  return snapshot;
}

function snapshotSuccessData(value: unknown): object {
  const data = objectCreate(null) as Record<string, unknown>;
  if (value !== null && (typeof value === "object" || typeof value === "function")) {
    const permissions = ownDataProperty(value, "permissions");
    if (permissions.valid && permissions.present) {
      defineSafeProperty(data, "permissions", snapshotResponsePermissions(permissions.value));
      return data;
    }
  }
  defineSafeProperty(data, "permissions", snapshotResponsePermissions(undefined));
  return data;
}

function safeResponseCode(value: unknown): string {
  if (
    value === "invalid_request" ||
    value === "unauthorized" ||
    value === "forbidden" ||
    value === "insufficient_permission"
  ) {
    return value;
  }
  return "invalid_request";
}

function snapshotError(error: unknown, fallbackStatus: number): object {
  const output = objectCreate(null) as Record<string, unknown>;
  const name = "AuthError";
  let message = "Authentication request failed";
  let status = fallbackStatus;
  let code = "invalid_request";
  let requestId: string | undefined;

  if (error !== null && (typeof error === "object" || typeof error === "function")) {
    const messageProperty = ownDataProperty(error, "message");
    const statusProperty = ownDataProperty(error, "status");
    const codeProperty = ownDataProperty(error, "code");
    const requestIdProperty = ownDataProperty(error, "request_id");
    if (messageProperty.valid && messageProperty.present && typeof messageProperty.value === "string") {
      message = messageProperty.value;
    }
    if (statusProperty.valid && statusProperty.present) {
      status = safeStatus(statusProperty.value, fallbackStatus);
    }
    if (codeProperty.valid && codeProperty.present) {
      code = safeResponseCode(codeProperty.value);
    }
    if (
      requestIdProperty.valid &&
      requestIdProperty.present &&
      isRequestId(requestIdProperty.value)
    ) {
      requestId = requestIdProperty.value;
    }
  }

  defineSafeProperty(output, "name", name);
  defineSafeProperty(output, "message", message);
  defineSafeProperty(output, "status", status);
  defineSafeProperty(output, "code", code);
  if (requestId !== undefined) defineSafeProperty(output, "request_id", requestId);
  return output;
}

function snapshotResult<T>(result: AuthResult<T>): { readonly body: object; readonly status: number } {
  const body = objectCreate(null) as Record<string, unknown>;
  const dataProperty = ownDataProperty(result as unknown as object, "data");
  const errorProperty = ownDataProperty(result as unknown as object, "error");
  if (!dataProperty.valid || !errorProperty.valid || !errorProperty.present) {
    defineSafeProperty(body, "data", null);
    defineSafeProperty(body, "error", snapshotError(undefined, 500));
    return { body, status: 500 };
  }

  if (errorProperty.value === null) {
    defineSafeProperty(body, "data", snapshotSuccessData(dataProperty.present ? dataProperty.value : undefined));
    defineSafeProperty(body, "error", null);
    return { body, status: 200 };
  }

  const errorObject = errorProperty.value;
  const statusProperty =
    errorObject !== null && (typeof errorObject === "object" || typeof errorObject === "function")
      ? ownDataProperty(errorObject, "status")
      : { valid: false, present: false } as const;
  const status = statusProperty.valid && statusProperty.present
    ? safeStatus(statusProperty.value, 500)
    : 500;
  defineSafeProperty(body, "data", null);
  defineSafeProperty(body, "error", snapshotError(errorObject, status));
  return { body, status };
}

function json(value: object, status = 200): Response {
  const serialized = invoke<string>(jsonStringify, undefined, [value]);
  const headers = objectCreate(null) as Record<string, string>;
  defineSafeProperty(headers, "content-type", "application/json; charset=utf-8");
  defineSafeProperty(headers, "cache-control", "no-store");
  return new nativeResponse(serialized, {
    status,
    headers,
  });
}

function resultResponse<T>(result: AuthResult<T>): Response {
  const snapshot = snapshotResult(result);
  return json(snapshot.body, snapshot.status);
}

function invalidRequest(requestIdValue?: string): Response {
  return resultResponse(authFailure(new AuthApiError(
    "invalid_request",
    400,
    "Invalid permissions request",
    requestIdValue,
  )));
}

function methodNotAllowed(requestIdValue?: string): Response {
  return resultResponse(authFailure(new AuthApiError(
    "invalid_request",
    405,
    "Method is not allowed",
    requestIdValue,
  )));
}

function parseScope(urlValue: string): AuthorizationScope | undefined | null {
  try {
    const url = new nativeURL(urlValue);
    const params = invoke<unknown>(urlSearchParamsGetter, url, []);
    if (!hasOnlyAllowedScopeKeys(params)) return null;
    const types = snapshotStrings(invoke<unknown>(searchParamsGetAll, params, ["scope_type"]));
    const ids = snapshotStrings(invoke<unknown>(searchParamsGetAll, params, ["scope_id"]));
    if (types === null || ids === null) return null;
    if (types.length > 1 || ids.length > 1) return null;
    const type = invoke<unknown>(searchParamsGet, params, ["scope_type"]);
    const id = invoke<unknown>(searchParamsGet, params, ["scope_id"]);
    if ((type !== null && typeof type !== "string") || (id !== null && typeof id !== "string")) return null;
    if (type === null && id === null) return undefined;
    if (type === null || id === null) return null;
    if (containsNul(type) || containsNul(id)) return null;

    const trimmedType = invoke<string>(stringTrim, type, []);
    const trimmedId = invoke<string>(stringTrim, id, []);
    if (
      trimmedType !== type ||
      trimmedId !== id ||
      trimmedId.length === 0 ||
      !isScopeType(trimmedType)
    ) {
      return null;
    }
    return { type: trimmedType, id: trimmedId as ScopeIdentifier };
  } catch {
    return null;
  }
}

/** Serves the authenticated user's safe effective permission-key endpoint. */
export async function permissionsRoute(
  service: AuthorizationService,
  request: Request,
  subject?: AuthorizationSubject,
): Promise<Response> {
  const requestSnapshot = snapshotRequest(request);
  if (requestSnapshot === null) return invalidRequest();
  if (requestSnapshot.method !== "GET") return methodNotAllowed(requestSnapshot.requestId);
  if (requestSnapshot.url === undefined) return invalidRequest(requestSnapshot.requestId);
  const scope = parseScope(requestSnapshot.url);
  if (scope === null) return invalidRequest(requestSnapshot.requestId);
  const context = subject === undefined ? null : createAuthorizationRequestContext(subject);
  if (context === null) {
    return resultResponse(authFailure(new AuthApiError(
      "unauthorized",
      401,
      "Authenticated session is required",
      requestSnapshot.requestId,
    )));
  }
  const permissions = await service.getPermissions(context.subject.user_id, scope, context);
  const safePermissions = newNullPrototypeArray<string>();
  for (let index = 0; index < permissions.length; index += 1) {
    objectDefineProperty(safePermissions, `${index}`, {
      configurable: true,
      enumerable: true,
      value: permissions[index],
      writable: true,
    });
  }
  return resultResponse(authSuccess({ permissions: safePermissions }));
}

/** Creates the framework-neutral user-permission route handler. */
export function createPermissionRoutes(service: AuthorizationService): {
  readonly permissions: (
    request: Request,
    subject?: AuthorizationSubject,
  ) => Promise<Response>;
} {
  return {
    permissions: (request, subject) => permissionsRoute(service, request, subject),
  };
}
