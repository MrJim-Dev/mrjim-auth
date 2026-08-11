import { z } from "zod";
import { AuthApiError } from "../../shared/errors.js";
import { authFailure, authSuccess, type AuthResult } from "../../shared/result.js";
import {
  scopeIdentifierSchema,
  type AuthorizationScope,
} from "../../shared/types.js";
import {
  AuthorizationService,
  subjectUserId,
  type AuthorizationSubject,
} from "../authorization.js";

const scopeTypeSchema = z
  .string()
  .trim()
  .min(1)
  .max(64)
  .regex(/^[a-z][a-z0-9_-]*$/)
  .refine((value) => value === value.toLowerCase());

const allowedQueryKeys = new Set(["scope_type", "scope_id"]);

function requestId(request: Request): string | undefined {
  const value = request.headers.get("x-request-id");
  return value !== null && /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(value) ? value : undefined;
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
  const url = new URL(request.url);
  for (const key of url.searchParams.keys()) {
    if (!allowedQueryKeys.has(key)) return null;
  }
  for (const key of allowedQueryKeys) {
    if (url.searchParams.getAll(key).length > 1) return null;
  }
  const type = url.searchParams.get("scope_type");
  const id = url.searchParams.get("scope_id");
  if (type === null && id === null) return undefined;
  if (type === null || id === null) return null;
  const parsedType = scopeTypeSchema.safeParse(type);
  const parsedId = scopeIdentifierSchema.safeParse(id);
  if (!parsedType.success || !parsedId.success || parsedType.data !== type || parsedId.data !== id) {
    return null;
  }
  return { type: parsedType.data, id: parsedId.data };
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
  if (subject === undefined || subjectUserId(subject) === null) {
    return resultResponse(authFailure(new AuthApiError(
      "unauthorized",
      401,
      "Authenticated session is required",
      requestId(request),
    )));
  }
  const permissions = await service.getPermissions(subjectUserId(subject)!, scope);
  return resultResponse(authSuccess({ permissions: [...permissions] }));
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
