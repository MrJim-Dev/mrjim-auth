import type {
  AuthorizationRepository,
  PermissionRepository,
  RoleRepository,
  RoleAssignmentInput,
} from "../../shared/contracts.js";
import type { InsertObject, Selectable, UpdateObject } from "kysely";
import { sql } from "kysely";
import { PostgresRepositoryError } from "./errors.js";
import { authDb, operationNow, withTransaction } from "./context.js";
import {
  PERMISSION_COLUMNS,
  ROLE_COLUMNS,
  type Database,
  type PermissionsTable,
  type RepositoryContext,
  type RolesTable,
} from "./schema.js";
import { mapPermission, mapRole } from "./mapping.js";
import type { AuthorizationScope, Permission, UUID } from "../../shared/types.js";

/** Stable lock order for role/permission mutations: roles ascending, then permissions ascending. */
export const AUTHORIZATION_LOCK_ORDER = "roles ascending by id -> permissions ascending by id";

function normalizedScope(scope: AuthorizationScope | null | undefined): {
  readonly scope_type: string | null;
  readonly scope_id: string | null;
} {
  if (scope === undefined || scope === null) return { scope_type: null, scope_id: null };
  return { scope_type: scope.type.trim().toLowerCase(), scope_id: scope.id.trim() };
}

async function lockRoles(
  context: RepositoryContext,
  requiredRoleIds: readonly UUID[],
): Promise<void> {
  const roleIds = [...new Set(requiredRoleIds)].sort((left, right) => left.localeCompare(right));
  if (roleIds.length === 0) return;
  const rows = await authDb(context)
    .selectFrom("roles")
    .select(["id"])
    .where("id", "in", roleIds)
    .orderBy("id", "asc")
    .forUpdate()
    .execute();
  if (rows.length !== roleIds.length) {
    throw new PostgresRepositoryError("not_found", "one or more roles were not found");
  }
}

async function lockPermissions(
  context: RepositoryContext,
  requiredPermissionIds: readonly UUID[],
): Promise<void> {
  const permissionIds = [...new Set(requiredPermissionIds)].sort((left, right) => left.localeCompare(right));
  if (permissionIds.length === 0) return;
  const rows = await authDb(context)
    .selectFrom("permissions")
    .select(["id"])
    .where("id", "in", permissionIds)
    .orderBy("id", "asc")
    .forUpdate()
    .execute();
  if (rows.length !== permissionIds.length) {
    throw new PostgresRepositoryError("not_found", "one or more permissions were not found");
  }
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

async function existingPermissionIdsForRole(
  context: RepositoryContext,
  roleId: UUID,
): Promise<readonly UUID[]> {
  const rows = await authDb(context)
    .selectFrom("role_permissions")
    .select(["permission_id"])
    .where("role_id", "=", roleId)
    .execute();
  return rows.map((row) => row.permission_id);
}

function createAuthorizationRepository(context: RepositoryContext): AuthorizationRepository {
  return {
    async effectivePermissions(userId, requestedScope, options) {
      const now = operationNow(options);
      const scope = normalizedScope(requestedScope);
      type PermissionRow = Pick<Selectable<PermissionsTable>,
        "id" | "key" | "resource" | "action" | "description" | "created_at" | "updated_at">;
      const query = sql<PermissionRow>`
        WITH RECURSIVE direct_roles AS (
          SELECT ur.role_id
            FROM auth.user_roles AS ur
            JOIN auth.users AS u ON u.id = ur.user_id
           WHERE ur.user_id = ${userId}
             AND u.deleted_at IS NULL
             AND (ur.expires_at IS NULL OR ur.expires_at > ${now})
             AND (
               (ur.scope_type IS NULL AND ur.scope_id IS NULL)
               OR (
                 ur.scope_type = ${scope.scope_type}
                 AND ur.scope_id = ${scope.scope_id}
               )
             )
        ), effective_roles(role_id) AS (
          SELECT role_id FROM direct_roles
          UNION
          SELECT inheritance.inherits_role_id
            FROM auth.role_inheritance AS inheritance
            JOIN effective_roles AS role_state
              ON role_state.role_id = inheritance.role_id
        )
        SELECT DISTINCT
               permission.id,
               permission.key,
               permission.resource,
               permission.action,
               permission.description,
               permission.created_at,
               permission.updated_at
          FROM effective_roles
          JOIN auth.role_permissions AS role_permission
            ON role_permission.role_id = effective_roles.role_id
          JOIN auth.permissions AS permission
            ON permission.id = role_permission.permission_id
         ORDER BY permission.key ASC
      `;
      const permissionRows = (await query.execute(context.db)).rows;
      const unique = new Map<string, Permission>();
      for (const permission of permissionRows) {
        const mapped = mapPermission(permission);
        unique.set(mapped.id, mapped);
      }
      return [...unique.values()];
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

    async unassignRole(userId, roleId, requestedScope) {
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

    async setRolePermissions(roleId, permissionIds) {
      await withTransaction(context, async (transaction) => {
        await lockRoles(transaction, [roleId]);
        const currentPermissionIds = await existingPermissionIdsForRole(transaction, roleId);
        const nextPermissionIds = [...new Set(permissionIds)].sort((left, right) => left.localeCompare(right));
        await lockPermissions(transaction, [...currentPermissionIds, ...nextPermissionIds]);
        await authDb(transaction).deleteFrom("role_permissions").where("role_id", "=", roleId).execute();
        if (nextPermissionIds.length > 0) {
          await authDb(transaction)
            .insertInto("role_permissions")
            .values(nextPermissionIds.map((permission_id) => ({ role_id: roleId, permission_id })))
            .execute();
        }
      });
    },

    async setRoleInheritance(roleId, inheritedRoleIdsInput) {
      await withTransaction(context, async (transaction) => {
        const inheritedRoleIds = [...new Set(inheritedRoleIdsInput)]
          .sort((left, right) => left.localeCompare(right));
        await lockRoles(transaction, [roleId, ...inheritedRoleIds]);
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
        const role = await lockRole(transaction, id);
        if (patch.is_system !== undefined && patch.is_system !== role.is_system) {
          throw new PostgresRepositoryError(
            "protected_role",
            `system-role status for ${id} is immutable after creation`,
          );
        }
        const values: UpdateObject<Database, "roles"> = { updated_at: operationNow(options) };
        if (patch.key !== undefined) values.key = patch.key;
        if (patch.name !== undefined) values.name = patch.name;
        if (patch.description !== undefined) values.description = patch.description;
        if (patch.rank !== undefined) values.rank = patch.rank;
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
      await withTransaction(context, async (transaction) => {
        const permission = await authDb(transaction)
          .selectFrom("permissions")
          .select(["id"])
          .where("id", "=", id)
          .executeTakeFirst();
        if (permission === undefined) return;
        const roles = await authDb(transaction)
          .selectFrom("role_permissions")
          .select(["role_id"])
          .where("permission_id", "=", id)
          .orderBy("role_id", "asc")
          .execute();
        await lockRoles(transaction, roles.map((role) => role.role_id));
        await lockPermissions(transaction, [id]);
        await authDb(transaction).deleteFrom("permissions").where("id", "=", id).execute();
      });
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
