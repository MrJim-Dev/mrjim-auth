import type {
  AuthRepository,
  CreatePermissionInput,
  CreateRoleInput,
  CreateUserInput,
  UpdatePermissionInput,
  UpdateRoleInput,
  UpdateUserInput,
  RateLimiter,
} from "../shared/contracts.js";
import { AuthApiError, AuthConfigurationError } from "../shared/errors.js";
import { authFailure, authSuccess, type AuthResult } from "../shared/result.js";
import {
  permissionKeySchema,
  roleKeySchema,
  sanitizeRedactedMetadata,
  uuidSchema,
  type AuthorizationScope,
  type Permission,
  type Role,
  type UUID,
} from "../shared/types.js";
import { ADMIN_MUTATION_RATE_LIMIT_POLICY } from "./rate-limit.js";

export type AdminPermission =
  | "auth.users.manage"
  | "auth.roles.manage"
  | "auth.permissions.manage"
  | "auth.audit.read";

export type AdminPrincipal =
  | { readonly kind: "trusted" }
  | { readonly kind: "secret"; readonly keyId: UUID; readonly scopes: readonly string[] }
  | { readonly kind: "user"; readonly userId: UUID; readonly sessionId?: UUID };

export interface AdminServiceOptions {
  readonly repository: AuthRepository;
  readonly clock?: () => Date;
  readonly invite?: (email: string, options?: Readonly<Record<string, unknown>>) => Promise<unknown>;
  readonly rateLimiter?: RateLimiter;
}

export interface AdminPageOptions { readonly page?: number; readonly perPage?: number }

const PERMISSIONS = new Set<AdminPermission>([
  "auth.users.manage", "auth.roles.manage", "auth.permissions.manage", "auth.audit.read",
]);

function failure(code: "invalid_request" | "insufficient_permission" | "not_found" | "forbidden" | "conflict" | "internal_error", status: number, message: string): AuthResult<never> {
  return authFailure(new AuthApiError(code, status, message));
}

function page(input: AdminPageOptions = {}): { page: number; perPage: number } | null {
  const page = input.page ?? 1;
  const perPage = input.perPage ?? 50;
  return Number.isSafeInteger(page) && page >= 1 && page <= 100 && Number.isSafeInteger(perPage) && perPage >= 1 && perPage <= 100
    ? { page, perPage }
    : null;
}

function hasPermission(permissions: readonly Permission[], required: AdminPermission): boolean {
  for (const permission of permissions) {
    if (permission.key === required || permission.key === "auth.*" || permission.key === "*.*") return true;
  }
  return false;
}

function keyAuthorized(principal: AdminPrincipal, required: AdminPermission): boolean {
  if (principal.kind === "trusted") return true;
  if (principal.kind !== "secret") return false;
  return principal.scopes.includes(required) || principal.scopes.includes("auth.*") || principal.scopes.includes("*.*");
}

function principalActor(principal: AdminPrincipal): { actor_user_id?: UUID; actor_key_id?: UUID; actor_session_id?: UUID } {
  if (principal.kind === "user") return { actor_user_id: principal.userId, ...(principal.sessionId === undefined ? {} : { actor_session_id: principal.sessionId }) };
  if (principal.kind === "secret") return { actor_key_id: principal.keyId };
  return {};
}

function safeUuid(value: string): UUID | null {
  const parsed = uuidSchema.safeParse(value);
  return parsed.success ? parsed.data : null;
}

function internalFailure(): AuthResult<never> {
  return failure("internal_error", 500, "The administration operation could not be completed");
}

function knownMutationFailure(error: unknown): AuthResult<never> | null {
  const code = typeof error === "object" && error !== null && "code" in error ? String(error.code) : "";
  if (code === "not_found") return failure("not_found", 404, "Resource not found");
  if (code === "protected_role" || code === "role_rank_violation") return failure("forbidden", 403, "Role policy denied the operation");
  return null;
}

/** Trusted, transaction-oriented implementation behind the Node-only admin client. */
export class AdminService {
  readonly #repository: AuthRepository;
  readonly #clock: () => Date;
  readonly #invite?: AdminServiceOptions["invite"];
  readonly #rateLimiter: RateLimiter | undefined;

  constructor(options: AdminServiceOptions) {
    if (options.repository.admin === undefined) throw new AuthConfigurationError("AdminService requires repository.admin");
    this.#repository = options.repository;
    this.#clock = options.clock ?? (() => new Date());
    this.#invite = options.invite;
    this.#rateLimiter = options.rateLimiter;
  }

  async #authorize(repository: AuthRepository, principal: AdminPrincipal, required: AdminPermission): Promise<AuthResult<null>> {
    if (!PERMISSIONS.has(required)) return failure("insufficient_permission", 403, "Insufficient permission");
    if (keyAuthorized(principal, required)) return authSuccess(null);
    if (principal.kind !== "user") return failure("insufficient_permission", 403, "Insufficient permission");
    await repository.admin!.assignedRolesForUpdate(principal.userId, this.#clock());
    const permissions = await repository.authorization.effectivePermissions(principal.userId, undefined, { now: this.#clock() });
    return hasPermission(permissions, required)
      ? authSuccess(null)
      : failure("insufficient_permission", 403, "Insufficient permission");
  }

  async #read<T>(principal: AdminPrincipal, required: AdminPermission, operation: (repository: AuthRepository) => Promise<T>): Promise<AuthResult<T>> {
    try {
      return await this.#repository.transaction(async (repository) => {
        const authorization = await this.#authorize(repository, principal, required);
        if (authorization.error) return authorization;
        return authSuccess(await operation(repository));
      });
    } catch (error) {
      const code = typeof error === "object" && error !== null && "code" in error ? String(error.code) : "";
      return code === "not_found" ? failure("not_found", 404, "Resource not found") : internalFailure();
    }
  }

  async #mutate<T>(principal: AdminPrincipal, required: AdminPermission, audit: { action: string; targetType: string; targetId?: UUID | null; metadata?: unknown }, operation: (repository: AuthRepository, now: Date) => Promise<T>): Promise<AuthResult<T>> {
    try {
      return await this.#repository.transaction(async (repository) => {
        const now = this.#clock();
        const appendOutcome = async (outcome: "success" | "failure", metadata: unknown) => repository.operations.appendAudit({
          ...principalActor(principal), action: audit.action, target_type: audit.targetType,
          target_id: audit.targetId ?? null, metadata: sanitizeRedactedMetadata(metadata), outcome, occurred_at: now,
        }, { now });
        const authorization = await this.#authorize(repository, principal, required);
        if (authorization.error) {
          await appendOutcome("failure", { event: "admin_permission_denied", required });
          return authorization as AuthResult<T>;
        }
        if (this.#rateLimiter !== undefined) {
          const limiterKey = principal.kind === "user" ? `user:${principal.userId}` : principal.kind === "secret" ? `key:${principal.keyId}` : "trusted";
          const decision = await this.#rateLimiter.consume(limiterKey, ADMIN_MUTATION_RATE_LIMIT_POLICY);
          if (!decision.allowed) {
            await appendOutcome("failure", { event: "admin_rate_limited" });
            return authFailure(new AuthApiError("rate_limit_exceeded", 429, "Too many administration requests")) as AuthResult<T>;
          }
        }
        let data: T;
        try {
          data = await operation(repository, now);
        } catch (error) {
          const known = knownMutationFailure(error);
          if (known === null) throw error;
          await appendOutcome("failure", { event: "admin_policy_denied" });
          return known as AuthResult<T>;
        }
        await appendOutcome("success", audit.metadata ?? {});
        return authSuccess(data);
      });
    } catch (error) {
      const code = typeof error === "object" && error !== null && "code" in error ? String(error.code) : "";
      if (code === "duplicate" || code === "23505") return failure("conflict", 409, "Resource already exists");
      return internalFailure();
    }
  }

  async #assertRank(repository: AuthRepository, principal: AdminPrincipal, roles: readonly Role[], lockedActorRoles?: readonly Role[]): Promise<AuthResult<null>> {
    if (principal.kind !== "user") return authSuccess(null);
    const actorRoles = lockedActorRoles ?? await repository.admin!.assignedRolesForUpdate(principal.userId, this.#clock());
    let actorRank = -1;
    for (const role of actorRoles) actorRank = Math.max(actorRank, role.rank);
    for (const role of roles) {
      if (actorRank <= role.rank) return failure("forbidden", 403, "Role rank denied the operation");
    }
    return authSuccess(null);
  }

  async listUsers(options: AdminPageOptions, principal: AdminPrincipal) {
    const paging = page(options); if (!paging) return failure("invalid_request", 400, "Invalid pagination");
    return this.#read(principal, "auth.users.manage", async (repository) => {
      const result = await repository.admin!.listUsers(paging);
      return { users: result.users, total: result.total, page: paging.page, per_page: paging.perPage };
    });
  }

  async getUserById(id: string, principal: AdminPrincipal) {
    const userId = safeUuid(id); if (!userId) return failure("invalid_request", 400, "Invalid user id");
    return this.#read(principal, "auth.users.manage", async (repository) => {
      const user = await repository.users.findById(userId);
      if (!user) throw Object.assign(new Error("not found"), { code: "not_found" });
      return { user };
    });
  }

  async findUser(input: { readonly email: string }, principal: AdminPrincipal) {
    if (typeof input.email !== "string" || input.email.trim().length === 0 || input.email.length > 320) return failure("invalid_request", 400, "Invalid email");
    return this.#read(principal, "auth.users.manage", async (repository) => ({ user: await repository.users.findByNormalizedEmail(input.email) }));
  }

  async createUser(input: CreateUserInput, principal: AdminPrincipal) {
    return this.#mutate(principal, "auth.users.manage", { action: "admin.user.created", targetType: "user", metadata: { event: "admin_user_created" } }, async (repository, now) => ({ user: await repository.users.create(input, { now }) }));
  }

  async updateUserById(id: string, patch: UpdateUserInput, principal: AdminPrincipal) {
    const userId = safeUuid(id); if (!userId) return failure("invalid_request", 400, "Invalid user id");
    return this.#mutate(principal, "auth.users.manage", { action: "admin.user.updated", targetType: "user", targetId: userId, metadata: { event: "admin_user_updated" } }, async (repository, now) => ({ user: await repository.users.update(userId, patch, { now }) }));
  }

  async deleteUser(id: string, options: { readonly soft?: boolean }, principal: AdminPrincipal) {
    const userId = safeUuid(id); if (!userId || options.soft === false) return failure("invalid_request", 400, "Only soft user deletion is supported");
    if (principal.kind === "user" && principal.userId === userId) return failure("forbidden", 403, "Administrators cannot delete their own account");
    return this.#mutate(principal, "auth.users.manage", { action: "admin.user.deleted", targetType: "user", targetId: userId, metadata: { event: "admin_user_soft_deleted" } }, async (repository, now) => {
      const user = await repository.users.findByIdForUpdate(userId, { now });
      if (!user) throw Object.assign(new Error("not found"), { code: "not_found" });
      await repository.users.softDelete(userId, now, { now });
      await repository.sessions.revokeUserSessions(userId, undefined, { now });
      return { user };
    });
  }

  async inviteUserByEmail(email: string, options: Readonly<Record<string, unknown>> | undefined, principal: AdminPrincipal) {
    if (!this.#invite) return failure("invalid_request", 400, "Invitation delivery is not configured");
    return this.#mutate(principal, "auth.users.manage", { action: "admin.user.invited", targetType: "user", metadata: { event: "admin_user_invited" } }, async () => ({ invited: await this.#invite!(email, options) }));
  }

  async listRoles(principal: AdminPrincipal) { return this.#read(principal, "auth.roles.manage", async (repository) => ({ roles: await repository.roles.list() })); }
  async createRole(input: CreateRoleInput, principal: AdminPrincipal) {
    const key = roleKeySchema.safeParse(input.key); if (!key.success || !Number.isSafeInteger(input.rank) || input.rank < 0) return failure("invalid_request", 400, "Invalid role");
    if (input.is_system === true && principal.kind !== "trusted") return failure("forbidden", 403, "Role policy denied the operation");
    return this.#mutate(principal, "auth.roles.manage", { action: "admin.role.created", targetType: "role", metadata: { event: "admin_role_created", role: key.data } }, async (repository, now) => {
      if (principal.kind === "user") {
        const actorRoles = await repository.admin!.assignedRolesForUpdate(principal.userId, now);
        if (!actorRoles.some((role) => role.rank > input.rank) || input.is_system === true) throw Object.assign(new Error("rank"), { code: "role_rank_violation" });
      }
      return { role: await repository.roles.create({ ...input, key: key.data }, { now }) };
    });
  }

  async updateRole(id: string, patch: UpdateRoleInput, principal: AdminPrincipal) {
    const roleId = safeUuid(id); if (!roleId) return failure("invalid_request", 400, "Invalid role id");
    return this.#roleMutation("admin.role.updated", roleId, principal, async (repository, now, role) => {
      if (patch.rank !== undefined && principal.kind === "user") {
        const rank = await this.#assertRank(repository, principal, [{ ...role, rank: patch.rank }]); if (rank.error) throw Object.assign(new Error("rank"), { code: "role_rank_violation" });
      }
      return { role: await repository.roles.update(roleId, patch, { now }) };
    });
  }

  async deleteRole(id: string, principal: AdminPrincipal) {
    const roleId = safeUuid(id); if (!roleId) return failure("invalid_request", 400, "Invalid role id");
    return this.#roleMutation("admin.role.deleted", roleId, principal, async (repository) => { await repository.roles.delete(roleId); return null; });
  }

  async #roleMutation<T>(action: string, roleId: UUID, principal: AdminPrincipal, operation: (repository: AuthRepository, now: Date, role: Role) => Promise<T>) {
    return this.#mutate(principal, "auth.roles.manage", { action, targetType: "role", targetId: roleId, metadata: { event: action.replaceAll(".", "_") } }, async (repository, now) => {
      const actorRoles = principal.kind === "user"
        ? await repository.admin!.assignedRolesForUpdate(principal.userId, now)
        : undefined;
      const [role] = await repository.admin!.rolesForUpdate([roleId]);
      if (!role) throw Object.assign(new Error("not found"), { code: "not_found" });
      const rank = await this.#assertRank(repository, principal, [role], actorRoles);
      if (rank.error) throw Object.assign(new Error("rank"), { code: "role_rank_violation" });
      return operation(repository, now, role);
    });
  }

  async setRolePermissions(id: string, permissionIds: readonly string[], principal: AdminPrincipal) {
    const roleId = safeUuid(id); const ids = permissionIds.map(safeUuid); if (!roleId || ids.some((value) => value === null)) return failure("invalid_request", 400, "Invalid identifiers");
    return this.#roleMutation("admin.role.permissions_set", roleId, principal, async (repository) => { await repository.authorization.setRolePermissions(roleId, ids as UUID[]); return null; });
  }

  async setRoleInheritance(id: string, inheritedRoleIds: readonly string[], principal: AdminPrincipal) {
    const roleId = safeUuid(id); const ids = inheritedRoleIds.map(safeUuid); if (!roleId || ids.some((value) => value === null)) return failure("invalid_request", 400, "Invalid identifiers");
    return this.#mutate(principal, "auth.roles.manage", { action: "admin.role.inheritance_set", targetType: "role", targetId: roleId, metadata: { event: "admin_role_inheritance_set" } }, async (repository) => {
      const actorRoles = principal.kind === "user"
        ? await repository.admin!.assignedRolesForUpdate(principal.userId, this.#clock())
        : undefined;
      const roles = await repository.admin!.rolesForUpdate([roleId, ...(ids as UUID[])]);
      const rank = await this.#assertRank(repository, principal, roles, actorRoles); if (rank.error) throw Object.assign(new Error("rank"), { code: "role_rank_violation" });
      await repository.authorization.setRoleInheritance(roleId, ids as UUID[]); return null;
    });
  }

  async assignRole(userIdValue: string, roleIdValue: string, scope: AuthorizationScope | null, principal: AdminPrincipal) {
    const userId = safeUuid(userIdValue); const roleId = safeUuid(roleIdValue); if (!userId || !roleId) return failure("invalid_request", 400, "Invalid identifiers");
    return this.#roleMutation("admin.role.assigned", roleId, principal, async (repository, now) => { await repository.authorization.assignRole({ user_id: userId, role_id: roleId, scope, assigned_by: principal.kind === "user" ? principal.userId : null }, { now }); return null; });
  }

  async unassignRole(userIdValue: string, roleIdValue: string, scope: AuthorizationScope | null, principal: AdminPrincipal) {
    const userId = safeUuid(userIdValue); const roleId = safeUuid(roleIdValue); if (!userId || !roleId) return failure("invalid_request", 400, "Invalid identifiers");
    return this.#roleMutation("admin.role.unassigned", roleId, principal, async (repository, now, role) => {
      if (role.is_system && await repository.admin!.countActiveRoleAssignments(roleId, now) <= 1) throw Object.assign(new Error("protected"), { code: "protected_role" });
      await repository.authorization.unassignRole(userId, roleId, scope, { now }); return null;
    });
  }

  async listPermissions(principal: AdminPrincipal) { return this.#read(principal, "auth.permissions.manage", async (repository) => ({ permissions: await repository.permissions.list() })); }
  async createPermission(input: CreatePermissionInput, principal: AdminPrincipal) {
    const parsed = permissionKeySchema.safeParse(input.key); if (!parsed.success || `${input.resource}.${input.action}` !== parsed.data) return failure("invalid_request", 400, "Invalid permission");
    return this.#mutate(principal, "auth.permissions.manage", { action: "admin.permission.created", targetType: "permission", metadata: { event: "admin_permission_created", permission: parsed.data } }, async (repository, now) => ({ permission: await repository.permissions.create({ ...input, key: parsed.data }, { now }) }));
  }
  async updatePermission(id: string, patch: UpdatePermissionInput, principal: AdminPrincipal) {
    const permissionId = safeUuid(id); if (!permissionId) return failure("invalid_request", 400, "Invalid permission id");
    return this.#mutate(principal, "auth.permissions.manage", { action: "admin.permission.updated", targetType: "permission", targetId: permissionId, metadata: { event: "admin_permission_updated" } }, async (repository, now) => ({ permission: await repository.permissions.update(permissionId, patch, { now }) }));
  }
  async deletePermission(id: string, principal: AdminPrincipal) {
    const permissionId = safeUuid(id); if (!permissionId) return failure("invalid_request", 400, "Invalid permission id");
    return this.#mutate(principal, "auth.permissions.manage", { action: "admin.permission.deleted", targetType: "permission", targetId: permissionId, metadata: { event: "admin_permission_deleted" } }, async (repository) => { await repository.permissions.delete(permissionId); return null; });
  }
  async listAudit(options: AdminPageOptions, principal: AdminPrincipal) {
    const paging = page(options); if (!paging) return failure("invalid_request", 400, "Invalid pagination");
    return this.#read(principal, "auth.audit.read", async (repository) => {
      const result = await repository.admin!.listAudit(paging);
      return { events: result.events, total: result.total, page: paging.page, per_page: paging.perPage };
    });
  }
}
