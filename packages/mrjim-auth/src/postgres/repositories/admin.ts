import { sql, type InsertObject, type Selectable } from "kysely";
import type {
  AdminRepository,
  ApiKeyAdminRecord,
  AuditEventRecord,
} from "../../shared/contracts.js";
import { redactedMetadataSchema, type Role, type UUID } from "../../shared/types.js";
import { assertDigest, authDb } from "./context.js";
import { requireTransaction } from "./errors.js";
import { mapRole, mapUser } from "./mapping.js";
import {
  ROLE_COLUMNS,
  USER_COLUMNS,
  type ApiKeysTable,
  type AuditLogTable,
  type Database,
  type RepositoryContext,
} from "./schema.js";

const API_KEY_ADMIN_COLUMNS = [
  "id", "name", "prefix", "kind", "scopes", "last_used_at", "expires_at", "revoked_at", "created_at",
] as const;
const AUDIT_ADMIN_COLUMNS = [
  "id", "actor_user_id", "actor_key_id", "actor_session_id", "action", "target_type", "target_id",
  "ip_address", "user_agent", "metadata", "outcome", "occurred_at",
] as const;

function mapAdminApiKey(row: Pick<Selectable<ApiKeysTable>, (typeof API_KEY_ADMIN_COLUMNS)[number]>): ApiKeyAdminRecord {
  return {
    id: row.id, name: row.name, prefix: row.prefix, kind: row.kind, scopes: [...row.scopes],
    last_used_at: row.last_used_at, expires_at: row.expires_at, revoked_at: row.revoked_at, created_at: row.created_at,
  };
}

function mapAudit(row: Pick<Selectable<AuditLogTable>, (typeof AUDIT_ADMIN_COLUMNS)[number]>): AuditEventRecord {
  return {
    id: row.id, actor_user_id: row.actor_user_id, actor_key_id: row.actor_key_id,
    actor_session_id: row.actor_session_id, action: row.action, target_type: row.target_type,
    target_id: row.target_id, ip_address: row.ip_address, user_agent: row.user_agent,
    metadata: redactedMetadataSchema.parse(row.metadata), outcome: row.outcome, occurred_at: row.occurred_at,
  };
}

function offset(page: number, perPage: number): number {
  return (page - 1) * perPage;
}

function countValue(value: string | number | bigint | undefined): number {
  const count = Number(value ?? 0);
  if (!Number.isSafeInteger(count) || count < 0) throw new Error("invalid PostgreSQL count");
  return count;
}

async function currentRoleIds(context: RepositoryContext, userId: UUID, now: Date, lock = false): Promise<UUID[]> {
  let query = authDb(context)
    .selectFrom("user_roles")
    .select("role_id")
    .where("user_id", "=", userId)
    .where((expression) => expression.or([expression("expires_at", "is", null), expression("expires_at", ">", now)]))
    .orderBy("role_id", "asc");
  if (lock) query = query.forUpdate();
  const rows = await query.execute();
  return rows.map((row) => row.role_id);
}

function sameIds(left: readonly UUID[], right: readonly UUID[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

/** Build the trusted administration repository on the current transaction context. */
export function createAdminRepository(context: RepositoryContext): AdminRepository {
  return {
    async listUsers(input) {
      const [rows, count] = await Promise.all([
        authDb(context).selectFrom("users").select(USER_COLUMNS).where("deleted_at", "is", null)
          .orderBy("created_at", "desc").orderBy("id", "desc")
          .limit(input.perPage).offset(offset(input.page, input.perPage)).execute(),
        authDb(context).selectFrom("users").select(sql<string>`count(*)`.as("count")).where("deleted_at", "is", null).executeTakeFirstOrThrow(),
      ]);
      return { users: rows.map(mapUser), total: countValue(count.count) };
    },

    async createApiKey(input) {
      const values: InsertObject<Database, "api_keys"> = {
        name: input.name, prefix: input.prefix, key_hash: assertDigest(input.key_hash, "API key hash"),
        kind: input.kind, scopes: [...input.scopes], last_used_at: null, expires_at: input.expires_at,
        revoked_at: null, created_at: input.created_at,
      };
      const row = await authDb(context).insertInto("api_keys").values(values).returning(API_KEY_ADMIN_COLUMNS).executeTakeFirstOrThrow();
      return mapAdminApiKey(row);
    },

    async listApiKeys(input) {
      const [rows, count] = await Promise.all([
        authDb(context).selectFrom("api_keys").select(API_KEY_ADMIN_COLUMNS)
          .orderBy("created_at", "desc").orderBy("id", "desc")
          .limit(input.perPage).offset(offset(input.page, input.perPage)).execute(),
        authDb(context).selectFrom("api_keys").select(sql<string>`count(*)`.as("count")).executeTakeFirstOrThrow(),
      ]);
      return { apiKeys: rows.map(mapAdminApiKey), total: countValue(count.count) };
    },

    async revokeApiKey(id, revokedAt) {
      const result = await authDb(context).updateTable("api_keys").set({ revoked_at: revokedAt })
        .where("id", "=", id).where("revoked_at", "is", null).executeTakeFirst();
      return countValue(result.numUpdatedRows) === 1;
    },

    async touchApiKeyLastUsed(id, usedAt) {
      await authDb(context).updateTable("api_keys").set({ last_used_at: usedAt })
        .where("id", "=", id).where("revoked_at", "is", null).execute();
    },

    async listAudit(input) {
      const [rows, count] = await Promise.all([
        authDb(context).selectFrom("audit_log").select(AUDIT_ADMIN_COLUMNS)
          .orderBy("occurred_at", "desc").orderBy("id", "desc")
          .limit(input.perPage).offset(offset(input.page, input.perPage)).execute(),
        authDb(context).selectFrom("audit_log").select(sql<string>`count(*)`.as("count")).executeTakeFirstOrThrow(),
      ]);
      return { events: rows.map(mapAudit), total: countValue(count.count) };
    },

    async assignedRolesForUpdate(userId, now) {
      requireTransaction(context.inTransaction);
      let roleIds = await currentRoleIds(context, userId, now, true);
      const locked = new Set<UUID>();
      for (let attempt = 0; attempt < 8; attempt += 1) {
        const additions = roleIds.filter((id) => !locked.has(id));
        if (additions.length > 0) {
          const rows = await authDb(context).selectFrom("roles").select("id").where("id", "in", additions)
            .orderBy("id", "asc").forUpdate().execute();
          for (const row of rows) locked.add(row.id);
        }
        const current = await currentRoleIds(context, userId, now, true);
        if (sameIds(roleIds, current)) {
          if (current.length === 0) return [];
          const rows = await authDb(context).selectFrom("roles").select(ROLE_COLUMNS).where("id", "in", current).orderBy("id", "asc").execute();
          return rows.map(mapRole) as readonly Role[];
        }
        roleIds = current;
      }
      throw new Error("role assignments changed too frequently");
    },

    async rolesForUpdate(roleIdsInput) {
      requireTransaction(context.inTransaction);
      const roleIds = [...new Set(roleIdsInput)].sort((left, right) => left.localeCompare(right));
      if (roleIds.length === 0) return [];
      const rows = await authDb(context).selectFrom("roles").select(ROLE_COLUMNS).where("id", "in", roleIds)
        .orderBy("id", "asc").forUpdate().execute();
      if (rows.length !== roleIds.length) throw Object.assign(new Error("role not found"), { code: "not_found" });
      return rows.map(mapRole);
    },

    async countActiveRoleAssignments(roleId, now) {
      requireTransaction(context.inTransaction);
      const row = await authDb(context).selectFrom("user_roles").select(sql<string>`count(*)`.as("count"))
        .where("role_id", "=", roleId)
        .where((expression) => expression.or([expression("expires_at", "is", null), expression("expires_at", ">", now)]))
        .executeTakeFirstOrThrow();
      return countValue(row.count);
    },
  };
}
