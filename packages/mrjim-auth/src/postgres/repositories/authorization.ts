import type {
  AuthorizationRepository,
  PermissionRepository,
  RoleRepository,
  RoleAssignmentInput,
} from "../../shared/contracts.js";
import type { InsertObject, Selectable, UpdateObject } from "kysely";
import { PostgresRepositoryError } from "./errors.js";
import { authDb, operationNow, withTransaction } from "./context.js";
import {
  PERMISSION_COLUMNS,
  ROLE_COLUMNS,
  type Database,
  type RepositoryContext,
  type RolesTable,
} from "./schema.js";
import { mapPermission, mapRole } from "./mapping.js";
import type { AuthorizationScope, Permission, Role, UUID } from "../../shared/types.js";

function normalizedScope(scope: AuthorizationScope | null | undefined): {
  readonly scope_type: string | null;
  readonly scope_id: string | null;
} {
  if (scope === undefined || scope === null) return { scope_type: null, scope_id: null };
  return { scope_type: scope.type.trim().toLowerCase(), scope_id: scope.id.trim() };
}

async function lockRole(context: RepositoryContext, roleId: UUID): Promise<Selectable<RolesTable>> {
  const row = await authDb(context)
    .selectFrom("roles")
    .select(ROLE_COLUMNS)
    .where("id", "=", roleId)
    .forUpdate()
    .executeTakeFirst();
  if (row === undefined) {
    throw new PostgresRepositoryError("not_found", `role ${roleId} was not found`);
  }
  return row;
}

async function lockAllRoles(context: RepositoryContext, requiredRoleIds: readonly UUID[]): Promise<void> {
  const rows = await authDb(context)
    .selectFrom("roles")
    .select(["id"])
    .orderBy("id", "asc")
    .forUpdate()
    .execute();
  const available = new Set(rows.map((row) => row.id));
  for (const roleId of requiredRoleIds) {
    if (!available.has(roleId)) {
      throw new PostgresRepositoryError("not_found", `role ${roleId} was not found`);
    }
  }
}

async function ensurePermissionsExist(
  context: RepositoryContext,
  permissionIds: readonly UUID[],
): Promise<void> {
  if (permissionIds.length === 0) return;
  const rows = await authDb(context)
    .selectFrom("permissions")
    .select(["id"])
    .where("id", "in", permissionIds)
    .execute();
  if (rows.length !== new Set(permissionIds).size) {
    throw new PostgresRepositoryError("not_found", "one or more permissions were not found");
  }
}

async function inheritedRoleIds(
  context: RepositoryContext,
  initialRoleIds: readonly UUID[],
): Promise<readonly UUID[]> {
  const all = new Set(initialRoleIds);
  let frontier: UUID[] = [...new Set(initialRoleIds)];
  while (frontier.length > 0) {
    const edges = await authDb(context)
      .selectFrom("role_inheritance")
      .select(["role_id", "inherits_role_id"])
      .where("role_id", "in", frontier)
      .execute();
    const next: UUID[] = [];
    for (const edge of edges) {
      if (!all.has(edge.inherits_role_id)) {
        all.add(edge.inherits_role_id);
        next.push(edge.inherits_role_id);
      }
    }
    frontier = next;
  }
  return [...all];
}

function createAuthorizationRepository(context: RepositoryContext): AuthorizationRepository {
  return {
    async effectivePermissions(userId, requestedScope, options) {
      const user = await authDb(context)
        .selectFrom("users")
        .select(["id"])
        .where("id", "=", userId)
        .where("deleted_at", "is", null)
        .executeTakeFirst();
      if (user === undefined) return [];

      const now = operationNow(options);
      const scope = normalizedScope(requestedScope);
      const assignments = await authDb(context)
        .selectFrom("user_roles")
        .select(["role_id"])
        .where("user_id", "=", userId)
        .where((expression) =>
          expression.or([
            expression("expires_at", "is", null),
            expression("expires_at", ">", now),
          ]),
        )
        .where((expression) =>
          scope.scope_type === null
            ? expression("scope_type", "is", null)
            : expression.or([
                expression("scope_type", "is", null),
                expression.and([
                  expression("scope_type", "=", scope.scope_type),
                  expression("scope_id", "=", scope.scope_id),
                ]),
              ]),
        )
        .execute();
      const directRoleIds = assignments.map((assignment) => assignment.role_id);
      if (directRoleIds.length === 0) return [];
      const roleIds = await inheritedRoleIds(context, directRoleIds);
      const permissionRows = await authDb(context)
        .selectFrom("permissions")
        .select(PERMISSION_COLUMNS)
        .where(
          "id",
          "in",
          authDb(context)
            .selectFrom("role_permissions")
            .select("permission_id")
            .where("role_id", "in", roleIds),
        )
        .orderBy("key", "asc")
        .execute();
      const unique = new Map<string, Permission>();
      for (const permission of permissionRows) {
        const mapped = mapPermission(permission);
        unique.set(mapped.id, mapped);
      }
      return [...unique.values()].sort((left, right) => left.key.localeCompare(right.key));
    },

    async assignRole(input: RoleAssignmentInput, options) {
      await withTransaction(context, async (transaction) => {
        await lockRole(transaction, input.role_id);
        const normalized = normalizedScope(input.scope);
        const values: InsertObject<Database, "user_roles"> = {
          user_id: input.user_id,
          role_id: input.role_id,
          scope_type: normalized.scope_type,
          scope_id: normalized.scope_id,
          assigned_by: input.assigned_by ?? null,
          assigned_at: operationNow(options),
          expires_at: input.expires_at ?? null,
        };
        await authDb(transaction).insertInto("user_roles").values(values).execute();
      });
    },

    async unassignRole(userId, roleId, requestedScope, options) {
      await withTransaction(context, async (transaction) => {
        await lockRole(transaction, roleId);
        const normalized = normalizedScope(requestedScope);
        let query = authDb(transaction)
          .deleteFrom("user_roles")
          .where("user_id", "=", userId)
          .where("role_id", "=", roleId);
        if (normalized.scope_type === null) {
          query = query.where("scope_type", "is", null);
        } else {
          query = query
            .where("scope_type", "=", normalized.scope_type)
            .where("scope_id", "=", normalized.scope_id);
        }
        await query.execute();
      });
    },

    async setRolePermissions(roleId, permissionIds, options) {
      await withTransaction(context, async (transaction) => {
        await lockRole(transaction, roleId);
        const uniquePermissionIds = [...new Set(permissionIds)];
        await ensurePermissionsExist(transaction, uniquePermissionIds);
        await authDb(transaction).deleteFrom("role_permissions").where("role_id", "=", roleId).execute();
        if (uniquePermissionIds.length > 0) {
          await authDb(transaction)
            .insertInto("role_permissions")
            .values(uniquePermissionIds.map((permission_id) => ({ role_id: roleId, permission_id })))
            .execute();
        }
      });
    },

    async setRoleInheritance(roleId, inheritedRoleIdsInput, options) {
      await withTransaction(context, async (transaction) => {
        const uniqueRoleIds = [...new Set([roleId, ...inheritedRoleIdsInput])];
        await lockAllRoles(transaction, uniqueRoleIds);
        const inheritedRoleIds = [...new Set(inheritedRoleIdsInput)];
        await authDb(transaction).deleteFrom("role_inheritance").where("role_id", "=", roleId).execute();
        if (inheritedRoleIds.length > 0) {
          await authDb(transaction)
            .insertInto("role_inheritance")
            .values(
              inheritedRoleIds.map((inherits_role_id) => ({
                role_id: roleId,
                inherits_role_id,
              })),
            )
            .execute();
        }
      });
    },
  } satisfies AuthorizationRepository;
}

function createRoleRepository(context: RepositoryContext): RoleRepository {
  return {
    async list() {
      const rows = await authDb(context)
        .selectFrom("roles")
        .select(ROLE_COLUMNS)
        .orderBy("key", "asc")
        .execute();
      return rows.map(mapRole);
    },

    async findById(id) {
      const row = await authDb(context)
        .selectFrom("roles")
        .select(ROLE_COLUMNS)
        .where("id", "=", id)
        .executeTakeFirst();
      return row === undefined ? null : mapRole(row);
    },

    async create(input, options) {
      const now = operationNow(options);
      const values: InsertObject<Database, "roles"> = {
        key: input.key,
        name: input.name,
        description: input.description ?? null,
        rank: input.rank,
        is_system: input.is_system ?? false,
        created_at: now,
        updated_at: now,
      };
      const row = await authDb(context)
        .insertInto("roles")
        .values(values)
        .returning(ROLE_COLUMNS)
        .executeTakeFirstOrThrow();
      return mapRole(row);
    },

    async update(id, patch, options) {
      return withTransaction(context, async (transaction) => {
        await lockRole(transaction, id);
        const values: UpdateObject<Database, "roles"> = { updated_at: operationNow(options) };
        if (patch.key !== undefined) values.key = patch.key;
        if (patch.name !== undefined) values.name = patch.name;
        if (patch.description !== undefined) values.description = patch.description;
        if (patch.rank !== undefined) values.rank = patch.rank;
        if (patch.is_system !== undefined) values.is_system = patch.is_system;
        const row = await authDb(transaction)
          .updateTable("roles")
          .set(values)
          .where("id", "=", id)
          .returning(ROLE_COLUMNS)
          .executeTakeFirst();
        if (row === undefined) throw new PostgresRepositoryError("not_found", `role ${id} was not found`);
        return mapRole(row);
      });
    },

    async delete(id) {
      await withTransaction(context, async (transaction) => {
        const role = await lockRole(transaction, id);
        if (role.is_system) {
          throw new PostgresRepositoryError("protected_role", `system role ${id} cannot be deleted`);
        }
        await authDb(transaction).deleteFrom("roles").where("id", "=", id).execute();
      });
    },
  } satisfies RoleRepository;
}

function createPermissionRepository(context: RepositoryContext): PermissionRepository {
  return {
    async list() {
      const rows = await authDb(context)
        .selectFrom("permissions")
        .select(PERMISSION_COLUMNS)
        .orderBy("key", "asc")
        .execute();
      return rows.map(mapPermission);
    },

    async findById(id) {
      const row = await authDb(context)
        .selectFrom("permissions")
        .select(PERMISSION_COLUMNS)
        .where("id", "=", id)
        .executeTakeFirst();
      return row === undefined ? null : mapPermission(row);
    },

    async create(input, options) {
      const now = operationNow(options);
      const values: InsertObject<Database, "permissions"> = {
        key: input.key,
        resource: input.resource,
        action: input.action,
        description: input.description ?? null,
        created_at: now,
        updated_at: now,
      };
      const row = await authDb(context)
        .insertInto("permissions")
        .values(values)
        .returning(PERMISSION_COLUMNS)
        .executeTakeFirstOrThrow();
      return mapPermission(row);
    },

    async update(id, patch, options) {
      const values: UpdateObject<Database, "permissions"> = { updated_at: operationNow(options) };
      if (patch.key !== undefined) values.key = patch.key;
      if (patch.resource !== undefined) values.resource = patch.resource;
      if (patch.action !== undefined) values.action = patch.action;
      if (patch.description !== undefined) values.description = patch.description;
      const row = await authDb(context)
        .updateTable("permissions")
        .set(values)
        .where("id", "=", id)
        .returning(PERMISSION_COLUMNS)
        .executeTakeFirst();
      if (row === undefined) throw new PostgresRepositoryError("not_found", `permission ${id} was not found`);
      return mapPermission(row);
    },

    async delete(id) {
      await authDb(context).deleteFrom("permissions").where("id", "=", id).execute();
    },
  } satisfies PermissionRepository;
}

/** Build authorization, role, and permission repository members. */
export function createAuthorizationRepositories(context: RepositoryContext): {
  readonly authorization: AuthorizationRepository;
  readonly roles: RoleRepository;
  readonly permissions: PermissionRepository;
} {
  return {
    authorization: createAuthorizationRepository(context),
    roles: createRoleRepository(context),
    permissions: createPermissionRepository(context),
  };
}
