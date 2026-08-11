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
const reflectApply = Reflect.apply;
const regexpTest = RegExp.prototype.test;
const searchParamsGet = URLSearchParams.prototype.get;
const searchParamsGetAll = URLSearchParams.prototype.getAll;
const searchParamsKeys = URLSearchParams.prototype.keys;
const stringTrim = String.prototype.trim;

const requestIdPattern = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;
const scopeTypePattern = /^[a-z][a-z0-9_-]*$/;

function invoke<T>(method: Function, receiver: unknown, args: readonly unknown[]): T {
  return reflectApply(method, receiver, args as unknown[]) as T;
}

function requestId(request: Request): string | undefined {
  try {
    const value = request.headers.get("x-request-id");
    return value !== null && invoke<boolean>(regexpTest, requestIdPattern, [value]) ? value : undefined;
  } catch {
    return undefined;
  }
}

function json(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}

function resultResponse<T>(result: AuthResult<T>): Response {
  return json(result, result.error === null ? 200 : result.error.status);
}

function invalidRequest(request: Request): Response {
  return resultResponse(authFailure(new AuthApiError(
    "invalid_request",
    400,
    "Invalid permissions request",
    requestId(request),
  )));
}

function methodNotAllowed(request: Request): Response {
  return resultResponse(authFailure(new AuthApiError(
    "invalid_request",
    405,
    "Method is not allowed",
    requestId(request),
  )));
}

function parseScope(request: Request): AuthorizationScope | undefined | null {
  try {
    const url = new URL(request.url);
    const params = url.searchParams;
    const keys = invoke<IterableIterator<string>>(searchParamsKeys, params, []);
    for (const key of keys) {
      if (key !== "scope_type" && key !== "scope_id") return null;
    }
    const types = invoke<readonly string[]>(searchParamsGetAll, params, ["scope_type"]);
    const ids = invoke<readonly string[]>(searchParamsGetAll, params, ["scope_id"]);
    if (types.length > 1 || ids.length > 1) return null;
    const type = invoke<string | null>(searchParamsGet, params, ["scope_type"]);
    const id = invoke<string | null>(searchParamsGet, params, ["scope_id"]);
    if (type === null && id === null) return undefined;
    if (type === null || id === null) return null;
    if (type.includes("\u0000") || id.includes("\u0000")) return null;

    const trimmedType = invoke<string>(stringTrim, type, []);
    const trimmedId = invoke<string>(stringTrim, id, []);
    if (
      trimmedType !== type ||
      trimmedId !== id ||
      trimmedType.length === 0 ||
      trimmedType.length > 64 ||
      trimmedId.length === 0 ||
      !invoke<boolean>(regexpTest, scopeTypePattern, [trimmedType])
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
  if (request.method !== "GET") return methodNotAllowed(request);
  const scope = parseScope(request);
  if (scope === null) return invalidRequest(request);
  const context = subject === undefined ? null : createAuthorizationRequestContext(subject);
  if (context === null) {
    return resultResponse(authFailure(new AuthApiError(
      "unauthorized",
      401,
      "Authenticated session is required",
      requestId(request),
    )));
  }
  const permissions = await service.getPermissions(context.subject.user_id, scope, context);
  const safePermissions: string[] = [];
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
