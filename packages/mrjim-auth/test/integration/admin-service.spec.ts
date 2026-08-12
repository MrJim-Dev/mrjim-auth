import { describe, expect, it } from "vitest";
import type { AuthRepository } from "../../src/shared/contracts.js";
import { lowercaseKeySchema, permissionKeySchema, roleKeySchema, uuidSchema } from "../../src/shared/types.js";
import { AdminService } from "../../src/server/admin-service.js";

const USER_ID = uuidSchema.parse("11111111-1111-4111-8111-111111111111");
const ROLE_ID = uuidSchema.parse("22222222-2222-4222-8222-222222222222");
const ACTOR_ID = uuidSchema.parse("33333333-3333-4333-8333-333333333333");
const NOW = new Date("2026-08-12T00:00:00.000Z");

function repository(overrides: Partial<AuthRepository> = {}): AuthRepository {
  const events: unknown[] = [];
  const base = {
    async transaction<T>(callback: (repository: AuthRepository) => Promise<T>) { return callback(base as AuthRepository); },
    users: {
      findById: async () => null, findByIdForUpdate: async () => null,
      findByNormalizedEmail: async () => null, findByNormalizedEmailForUpdate: async () => null,
      create: async () => { throw new Error("unused"); }, createIfAvailable: async () => null,
      update: async () => { throw new Error("unused"); }, softDelete: async () => undefined,
    },
    sessions: { revokeUserSessions: async () => undefined },
    authorization: {
      effectivePermissions: async () => [], assignRole: async () => undefined,
      unassignRole: async () => undefined, setRolePermissions: async () => undefined,
      setRoleInheritance: async () => undefined,
    },
    roles: {
      list: async () => [], findById: async () => null,
      create: async () => { throw new Error("unused"); }, update: async () => { throw new Error("unused"); },
      delete: async () => undefined,
    },
    permissions: {
      list: async () => [], findById: async () => null,
      create: async () => { throw new Error("unused"); }, update: async () => { throw new Error("unused"); },
      delete: async () => undefined,
    },
    operations: { appendAudit: async (input: unknown) => { events.push(input); }, findApiKeyByHash: async () => null },
    admin: {
      listUsers: async () => ({ users: [], total: 0 }), createApiKey: async () => { throw new Error("unused"); },
      listApiKeys: async () => ({ apiKeys: [], total: 0 }), revokeApiKey: async () => false,
      touchApiKeyLastUsed: async () => undefined, listAudit: async () => ({ events: [], total: 0 }),
      assignedRolesForUpdate: async () => [], countActiveRoleAssignments: async () => 0,
      rolesForUpdate: async () => [],
    },
    identities: {}, passwordCredentials: {}, oneTimeTokens: {}, oauthStates: {},
    __events: events,
    ...overrides,
  } as unknown as AuthRepository & { __events: unknown[] };
  return base;
}

describe("transactional administration service", () => {
  it("denies delegated user administration unless the dynamic permission is effective", async () => {
    let transactions = 0;
    const base = repository();
    base.transaction = async (callback) => { transactions += 1; return callback(base); };
    const service = new AdminService({ repository: base, clock: () => NOW });
    const result = await service.listUsers({ page: 1, perPage: 50 }, { kind: "user", userId: ACTOR_ID });
    expect(result).toMatchObject({ data: null, error: { code: "insufficient_permission", status: 403 } });
    expect(transactions).toBe(1);
  });

  it("soft-deletes a user, revokes every session, and appends the audit in one transaction", async () => {
    const trace: string[] = [];
    const user = {
      id: USER_ID, email: "member@example.test", phone: null, email_confirmed_at: null,
      phone_confirmed_at: null, confirmed_at: null, last_sign_in_at: null, banned_until: null,
      user_metadata: {}, app_metadata: {}, created_at: NOW.toISOString(), updated_at: NOW.toISOString(), deleted_at: null,
    };
    const base = repository();
    base.users.findByIdForUpdate = async () => user;
    base.users.softDelete = async () => { trace.push("delete"); };
    base.sessions.revokeUserSessions = async () => { trace.push("revoke"); };
    base.operations.appendAudit = async () => { trace.push("audit"); };
    base.transaction = async (callback) => { trace.push("begin"); const value = await callback(base); trace.push("commit"); return value; };
    const service = new AdminService({ repository: base, clock: () => NOW });
    const result = await service.deleteUser(USER_ID, { soft: true }, { kind: "secret", keyId: ACTOR_ID, scopes: ["auth.users.manage"] });
    expect(result.error).toBeNull();
    expect(trace).toEqual(["begin", "delete", "revoke", "audit", "commit"]);
  });

  it("enforces actor rank and the final protected-role assignment under the same role lock", async () => {
    const targetRole = { id: ROLE_ID, key: roleKeySchema.parse("owner"), name: "Owner", description: null, rank: 100, is_system: true, created_at: NOW.toISOString(), updated_at: NOW.toISOString() };
    const actorRole = { ...targetRole, id: ACTOR_ID, key: roleKeySchema.parse("admin"), name: "Admin", rank: 50, is_system: false };
    const permission = { id: USER_ID, key: permissionKeySchema.parse("auth.roles.manage"), resource: lowercaseKeySchema.parse("auth.roles"), action: lowercaseKeySchema.parse("manage"), description: null, created_at: NOW.toISOString(), updated_at: NOW.toISOString() };
    const base = repository();
    base.authorization.effectivePermissions = async () => [permission];
    base.roles.findById = async () => targetRole;
    base.admin!.rolesForUpdate = async () => [targetRole];
    base.admin!.assignedRolesForUpdate = async () => [actorRole];
    base.admin!.countActiveRoleAssignments = async () => 1;
    const service = new AdminService({ repository: base, clock: () => NOW });
    await expect(service.assignRole(USER_ID, ROLE_ID, null, { kind: "user", userId: ACTOR_ID })).resolves.toMatchObject({ error: { code: "forbidden" } });
    await expect(service.unassignRole(USER_ID, ROLE_ID, null, { kind: "secret", keyId: ACTOR_ID, scopes: ["auth.roles.manage"] })).resolves.toMatchObject({ error: { code: "forbidden" } });
  });
});
