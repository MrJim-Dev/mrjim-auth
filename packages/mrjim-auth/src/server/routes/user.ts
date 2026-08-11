import { AuthApiError } from "../../shared/errors.js";
import { authSuccess } from "../../shared/result.js";
import { normalizeAndValidateEmail } from "../email.js";
import type { ZodType } from "zod";
import type { RouteContext, RouteOutput } from "./contracts.js";
import {
  identitiesDataSchema,
  nullDataSchema,
  permissionsDataSchema,
  updateUserRequestSchema,
  userDataSchema,
} from "./contracts.js";
import {
  safeStringIncludes,
  safeStringSlice,
  safeStringStartsWith,
  safeStringTrim,
} from "../../shared/safe-intrinsics.js";

function service(
  result: unknown,
  mapData: (data: unknown) => unknown,
  schema: ZodType,
): RouteOutput {
  return { kind: "service", result, mapData, schema };
}

function mapUser(data: unknown): unknown {
  return data;
}

function mapIdentities(data: unknown): unknown {
  return { identities: data };
}

function mapPermissions(data: unknown): unknown {
  return { permissions: data };
}

function serviceContext(context: RouteContext) {
  return { request_id: context.requestId };
}

function requireAuth(context: RouteContext) {
  if (context.auth?.subject === undefined || context.auth.session === undefined || context.auth.authorizationSubject === undefined) {
    throw new AuthApiError("unauthorized", 401, "Authenticated session is required");
  }
  return context.auth;
}

function validScopeType(value: string): boolean {
  if (value.length < 1 || value.length > 64) return false;
  const first = value[0];
  if (first === undefined || first < "a" || first > "z") return false;
  for (let index = 1; index < value.length; index += 1) {
    const character = value[index];
    if (character === undefined || !(
      (character >= "a" && character <= "z") ||
      (character >= "0" && character <= "9") ||
      character === "_" || character === "-"
    )) return false;
  }
  return true;
}

/** Handles all authenticated current-user routes. */
export async function handleUserRoute(
  path: string,
  context: RouteContext,
): Promise<RouteOutput | null> {
  if (path === "/logout" && context.request.method === "POST") {
    const value = context.body as { readonly scope?: "local" | "global" | "others"; readonly refresh_token?: string };
    if (value.refresh_token !== undefined) {
      if (context.auth?.subject !== undefined) throw new AuthApiError("invalid_request", 400, "Conflicting credentials");
      if (context.services.sessions.revokeRefreshToken === undefined) {
        throw new AuthApiError("invalid_request", 400, "Refresh-token logout is unavailable");
      }
      const result = await context.invoke(() => context.services.sessions.revokeRefreshToken!(value.refresh_token!, value.scope ?? "local"));
      return service(result, (data) => data, nullDataSchema);
    }
  }

  const auth = requireAuth(context);

  if (path === "/user" && context.request.method === "GET") {
    return service(authSuccess({ user: auth.session?.user }), mapUser, userDataSchema);
  }

  if (path === "/user" && context.request.method === "PUT") {
    const value = context.body as typeof updateUserRequestSchema._output;
    const patch = {
      ...(value.email === undefined ? {} : { email: normalizeAndValidateEmail(value.email).normalized }),
      ...(value.user_metadata === undefined ? {} : { user_metadata: value.user_metadata }),
      ...(value.redirect_to === undefined ? {} : { redirectTo: value.redirect_to }),
    };
    const result = await context.invoke(() => context.services.users.updateUser(
      auth.subject!,
      patch,
      serviceContext(context),
    ));
    return service(result, mapUser, userDataSchema);
  }

  if (path === "/user/identities" && context.request.method === "GET") {
    const oauth = context.services.oauth;
    if (oauth === undefined) return service(authSuccess([]), mapIdentities, identitiesDataSchema);
    const result = await context.invoke(() => oauth.listIdentities(auth.subject!));
    return service(result, mapIdentities, identitiesDataSchema);
  }

  if (safeStringStartsWith(path, "/user/identities/") && context.request.method === "DELETE") {
    const identityId = safeStringSlice(path, "/user/identities/".length) ?? "";
    const oauth = context.services.oauth;
    if (oauth === undefined) throw new AuthApiError("not_found", 404, "Identity not found");
    const result = await context.invoke(() => oauth.unlinkIdentity(auth.subject!, identityId));
    return service(result, (data) => data, nullDataSchema);
  }

  if (path === "/user/permissions" && context.request.method === "GET") {
    const scopeType = context.query.get("scope_type");
    const scopeId = context.query.get("scope_id");
    if ((scopeType === null) !== (scopeId === null)) {
      throw new AuthApiError("invalid_request", 400, "Scope type and scope id must be provided together");
    }
    if (
      scopeType !== null &&
      (!validScopeType(scopeType) || scopeId === null || scopeId.length === 0 || safeStringTrim(scopeId) !== scopeId || safeStringIncludes(scopeId, "\u0000"))
    ) {
      throw new AuthApiError("invalid_request", 400, "Invalid permission scope");
    }
    const scope = scopeType === null && scopeId === null
      ? undefined
      : { type: scopeType ?? "", id: scopeId ?? "" };
    const permissions = await context.invoke(() => context.services.authorization.getPermissions(
      auth.authorizationSubject!.user_id,
      scope,
      undefined,
    ));
    return service(authSuccess(permissions), mapPermissions, permissionsDataSchema);
  }

  if (path === "/logout" && context.request.method === "POST") {
    const value = context.body as { readonly scope?: "local" | "global" | "others"; readonly refresh_token?: string };
    if (value.refresh_token !== undefined) {
      throw new AuthApiError("invalid_request", 400, "Conflicting credentials");
    }
    const result = await context.invoke(() => context.services.sessions.signOut(auth.subject!.session, value.scope ?? "local"));
    return service(result, (data) => data, nullDataSchema);
  }

  return null;
}
