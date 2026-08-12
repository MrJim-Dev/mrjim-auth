import { AuthApiError } from "../../shared/errors.js";
import type { CreatePermissionInput, CreateRoleInput, CreateUserInput, UpdatePermissionInput, UpdateRoleInput, UpdateUserInput } from "../../shared/contracts.js";
import {
  lowercaseKeySchema,
  permissionKeySchema,
  roleKeySchema,
  scopeIdentifierSchema,
  type AuthorizationScope,
} from "../../shared/types.js";
import type { AdminPrincipal } from "../admin-service.js";
import type { RouteContext, RouteOutput } from "./contracts.js";
import {
  adminAuditDataSchema,
  adminInheritedRoleIdsRequestSchema,
  adminInviteRequestSchema,
  adminPermissionCreateRequestSchema,
  adminPermissionDataSchema,
  adminPermissionIdsRequestSchema,
  adminPermissionUpdateRequestSchema,
  adminPermissionsDataSchema,
  adminRoleCreateRequestSchema,
  adminRoleDataSchema,
  adminRoleUpdateRequestSchema,
  adminRolesDataSchema,
  adminUserCreateRequestSchema,
  adminUserDataSchema,
  adminUserUpdateRequestSchema,
  adminUsersDataSchema,
  nullDataSchema,
} from "./contracts.js";
import { z, type ZodType } from "zod";

const inviteDataSchema = z.object({ invited: z.unknown() }).strict();

function service(result: unknown, schema: ZodType): RouteOutput {
  return { kind: "service", result, mapData: (data) => data, schema };
}

function principal(context: RouteContext): AdminPrincipal {
  const auth = context.auth;
  if (auth === undefined) throw new AuthApiError("unauthorized", 401, "Administration authentication is required");
  if (auth.key.kind === "secret") return { kind: "secret", keyId: auth.key.id as never, scopes: auth.key.scopes };
  if (auth.session === undefined) throw new AuthApiError("unauthorized", 401, "Authenticated session is required");
  return { kind: "user", userId: auth.session.user_id, sessionId: auth.session.session_id };
}

function required(context: RouteContext) {
  const service = context.services.admin;
  if (service === undefined) throw new AuthApiError("not_found", 404, "Administration is not configured");
  return service;
}

function param(context: RouteContext, key: string): string {
  const value = context.params?.[key];
  if (value === undefined) throw new AuthApiError("invalid_request", 400, "Invalid administration path");
  return value;
}

function pagination(context: RouteContext): { page?: number; perPage?: number } {
  const page = context.query.get("page");
  const perPage = context.query.get("per_page");
  const result: { page?: number; perPage?: number } = {};
  if (page !== null) result.page = Number(page);
  if (perPage !== null) result.perPage = Number(perPage);
  return result;
}

function parsedDate(value: string | null): Date | null { return value === null ? null : new Date(value); }

function userInput(value: typeof adminUserUpdateRequestSchema._output): CreateUserInput & UpdateUserInput {
  const output: CreateUserInput & UpdateUserInput = {};
  if (value.email !== undefined) output.email = value.email;
  if (value.phone !== undefined) output.phone = value.phone;
  if (value.email_confirmed_at !== undefined) output.email_confirmed_at = parsedDate(value.email_confirmed_at);
  if (value.phone_confirmed_at !== undefined) output.phone_confirmed_at = parsedDate(value.phone_confirmed_at);
  if (value.confirmed_at !== undefined) output.confirmed_at = parsedDate(value.confirmed_at);
  if (value.last_sign_in_at !== undefined) output.last_sign_in_at = parsedDate(value.last_sign_in_at);
  if (value.banned_until !== undefined) output.banned_until = parsedDate(value.banned_until);
  if (value.user_metadata !== undefined) output.user_metadata = value.user_metadata;
  if (value.app_metadata !== undefined) output.app_metadata = value.app_metadata;
  return output;
}

function scope(context: RouteContext): AuthorizationScope | null {
  const type = context.query.get("scope_type");
  const id = context.query.get("scope_id");
  if (type === null && id === null) return null;
  if (type === null || id === null || !/^[a-z][a-z0-9_-]{0,63}$/u.test(type)) throw new AuthApiError("invalid_request", 400, "Invalid role scope");
  const parsed = scopeIdentifierSchema.safeParse(id);
  if (!parsed.success) throw new AuthApiError("invalid_request", 400, "Invalid role scope");
  return { type, id: parsed.data };
}

/** Dispatches exact Task 12 administration routes to the trusted service. */
export async function handleAdminRoute(path: string, context: RouteContext): Promise<RouteOutput | null> {
  const admin = required(context);
  const actor = principal(context);
  const method = context.request.method;
  if (path === "/admin/users" && method === "GET") return service(await context.invoke(() => admin.listUsers(pagination(context), actor)), adminUsersDataSchema);
  if (path === "/admin/users" && method === "POST") return service(await context.invoke(() => admin.createUser(userInput(context.body as typeof adminUserCreateRequestSchema._output), actor)), adminUserDataSchema);
  if (path === "/admin/users/find" && method === "GET") return service(await context.invoke(() => admin.findUser({ email: context.query.get("email") ?? "" }, actor)), adminUserDataSchema);
  if (path === "/admin/users/invite" && method === "POST") {
    const value = context.body as typeof adminInviteRequestSchema._output;
    return service(await context.invoke(() => admin.inviteUserByEmail(value.email, value.options, actor)), inviteDataSchema);
  }
  if (path === "/admin/users/{id}" && method === "GET") return service(await context.invoke(() => admin.getUserById(param(context, "id"), actor)), adminUserDataSchema);
  if (path === "/admin/users/{id}" && method === "PATCH") return service(await context.invoke(() => admin.updateUserById(param(context, "id"), userInput(context.body as typeof adminUserUpdateRequestSchema._output), actor)), adminUserDataSchema);
  if (path === "/admin/users/{id}" && method === "DELETE") {
    const soft = context.query.get("soft");
    if (soft !== null && soft !== "true") throw new AuthApiError("invalid_request", 400, "Only soft deletion is supported");
    return service(await context.invoke(() => admin.deleteUser(param(context, "id"), { soft: true }, actor)), adminUserDataSchema);
  }
  if (path === "/admin/users/{id}/roles/{roleId}" && method === "PUT") return service(await context.invoke(() => admin.assignRole(param(context, "id"), param(context, "roleId"), scope(context), actor)), nullDataSchema);
  if (path === "/admin/users/{id}/roles/{roleId}" && method === "DELETE") return service(await context.invoke(() => admin.unassignRole(param(context, "id"), param(context, "roleId"), scope(context), actor)), nullDataSchema);
  if (path === "/admin/roles" && method === "GET") return service(await context.invoke(() => admin.listRoles(actor)), adminRolesDataSchema);
  if (path === "/admin/roles" && method === "POST") {
    const value = context.body as typeof adminRoleCreateRequestSchema._output;
    const key = roleKeySchema.safeParse(value.key); if (!key.success) throw new AuthApiError("invalid_request", 400, "Invalid role");
    const input: CreateRoleInput = { key: key.data, name: value.name, rank: value.rank, ...(value.description === undefined ? {} : { description: value.description }), ...(value.is_system === undefined ? {} : { is_system: value.is_system }) };
    return service(await context.invoke(() => admin.createRole(input, actor)), adminRoleDataSchema);
  }
  if (path === "/admin/roles/{id}" && method === "PATCH") {
    const value = context.body as typeof adminRoleUpdateRequestSchema._output;
    const parsed = value.key === undefined ? undefined : roleKeySchema.safeParse(value.key); if (parsed !== undefined && !parsed.success) throw new AuthApiError("invalid_request", 400, "Invalid role");
    const patch: UpdateRoleInput = {};
    if (parsed?.success) patch.key = parsed.data;
    if (value.name !== undefined) patch.name = value.name;
    if (value.description !== undefined) patch.description = value.description;
    if (value.rank !== undefined) patch.rank = value.rank;
    if (value.is_system !== undefined) patch.is_system = value.is_system;
    return service(await context.invoke(() => admin.updateRole(param(context, "id"), patch, actor)), adminRoleDataSchema);
  }
  if (path === "/admin/roles/{id}" && method === "DELETE") return service(await context.invoke(() => admin.deleteRole(param(context, "id"), actor)), nullDataSchema);
  if (path === "/admin/roles/{id}/permissions" && method === "PUT") {
    const value = context.body as typeof adminPermissionIdsRequestSchema._output;
    return service(await context.invoke(() => admin.setRolePermissions(param(context, "id"), value.permission_ids, actor)), nullDataSchema);
  }
  if (path === "/admin/roles/{id}/inheritance" && method === "PUT") {
    const value = context.body as typeof adminInheritedRoleIdsRequestSchema._output;
    return service(await context.invoke(() => admin.setRoleInheritance(param(context, "id"), value.inherited_role_ids, actor)), nullDataSchema);
  }
  if (path === "/admin/permissions" && method === "GET") return service(await context.invoke(() => admin.listPermissions(actor)), adminPermissionsDataSchema);
  if (path === "/admin/permissions" && method === "POST") {
    const value = context.body as typeof adminPermissionCreateRequestSchema._output;
    const key = permissionKeySchema.safeParse(value.key); const resource = lowercaseKeySchema.safeParse(value.resource); const action = lowercaseKeySchema.safeParse(value.action);
    if (!key.success || !resource.success || !action.success) throw new AuthApiError("invalid_request", 400, "Invalid permission");
    const input: CreatePermissionInput = { key: key.data, resource: resource.data, action: action.data, ...(value.description === undefined ? {} : { description: value.description }) };
    return service(await context.invoke(() => admin.createPermission(input, actor)), adminPermissionDataSchema);
  }
  if (path === "/admin/permissions/{id}" && method === "PATCH") {
    const value = context.body as typeof adminPermissionUpdateRequestSchema._output;
    const key = value.key === undefined ? undefined : permissionKeySchema.safeParse(value.key);
    const resource = value.resource === undefined ? undefined : lowercaseKeySchema.safeParse(value.resource);
    const action = value.action === undefined ? undefined : lowercaseKeySchema.safeParse(value.action);
    if (key?.success === false || resource?.success === false || action?.success === false) throw new AuthApiError("invalid_request", 400, "Invalid permission");
    const patch: UpdatePermissionInput = {};
    if (key?.success) patch.key = key.data;
    if (resource?.success) patch.resource = resource.data;
    if (action?.success) patch.action = action.data;
    if (value.description !== undefined) patch.description = value.description;
    return service(await context.invoke(() => admin.updatePermission(param(context, "id"), patch, actor)), adminPermissionDataSchema);
  }
  if (path === "/admin/permissions/{id}" && method === "DELETE") return service(await context.invoke(() => admin.deletePermission(param(context, "id"), actor)), nullDataSchema);
  if (path === "/admin/audit" && method === "GET") return service(await context.invoke(() => admin.listAudit(pagination(context), actor)), adminAuditDataSchema);
  return null;
}
