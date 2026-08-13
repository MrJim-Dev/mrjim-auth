import { describe, expect, it } from "vitest";
import type { AuthRepository } from "../../src/shared/contracts.js";
import { AdminService } from "../../src/server/admin-service.js";
import { uuidSchema, type User, type UUID } from "../../src/shared/types.js";

const TARGET_ID = uuidSchema.parse("11111111-1111-4111-8111-111111111111");
const OTHER_ID = uuidSchema.parse("22222222-2222-4222-8222-222222222222");
const ACTOR_KEY_ID = uuidSchema.parse("33333333-3333-4333-8333-333333333333");
const ACTOR_USER_ID = uuidSchema.parse("44444444-4444-4444-8444-444444444444");
const NOW = new Date("2026-08-13T00:00:00.000Z");

type ImportInput = {
  readonly id: string;
  readonly email?: string | null;
  readonly phone?: string | null;
  readonly email_confirmed_at?: Date | null;
  readonly phone_confirmed_at?: Date | null;
  readonly confirmed_at?: Date | null;
  readonly last_sign_in_at?: Date | null;
  readonly banned_until?: Date | null;
  readonly user_metadata?: Record<string, unknown>;
  readonly app_metadata?: Record<string, unknown>;
};

type ImportService = {
  importUser(input: unknown, principal: unknown): Promise<unknown>;
};

function makeUser(
  id: UUID,
  email: string | null,
  userMetadata: Record<string, unknown> = {},
  appMetadata: Record<string, unknown> = {},
): User {
  return {
    id,
    email,
    phone: null,
    email_confirmed_at: null,
    phone_confirmed_at: null,
    confirmed_at: null,
    last_sign_in_at: null,
    banned_until: null,
    user_metadata: userMetadata as User["user_metadata"],
    app_metadata: appMetadata as User["app_metadata"],
    created_at: NOW.toISOString(),
    updated_at: NOW.toISOString(),
    deleted_at: null,
  };
}

function fixture(initialUser: User | null = null): {
  readonly repository: AuthRepository;
  readonly calls: ImportInput[];
  readonly events: Record<string, unknown>[];
  current(): User | null;
} {
  let currentUser = initialUser;
  const calls: ImportInput[] = [];
  const events: Record<string, unknown>[] = [];
  const normalized = (value: string | null | undefined): string | null => {
    if (value === undefined || value === null) return null;
    const trimmed = value.trim();
    return trimmed === "" ? null : trimmed.toLowerCase();
  };
  const base = {
    async transaction<T>(callback: (repository: AuthRepository) => Promise<T>): Promise<T> {
      return callback(base as unknown as AuthRepository);
    },
    users: {
      findById: async (id: UUID) => currentUser?.id === id ? currentUser : null,
      findByIdForUpdate: async (id: UUID) => currentUser?.id === id ? currentUser : null,
      findByNormalizedEmail: async (email: string) => normalized(currentUser?.email) === normalized(email) ? currentUser : null,
      findByNormalizedEmailForUpdate: async (email: string) => normalized(currentUser?.email) === normalized(email) ? currentUser : null,
      create: async () => { throw new Error("unused"); },
      createIfAvailable: async () => null,
      createWithId: async (input: ImportInput) => {
        calls.push(input);
        if (currentUser?.id === input.id) throw Object.assign(new Error("duplicate UUID"), { code: "user_id_exists" });
        if (normalized(currentUser?.email) !== null && normalized(currentUser?.email) === normalized(input.email)) {
          throw Object.assign(new Error("duplicate email"), { code: "email_exists" });
        }
        const id = uuidSchema.parse(input.id);
        currentUser = makeUser(
          id,
          input.email === undefined || input.email === null ? null : input.email.trim(),
          (input.user_metadata ?? {}) as Record<string, unknown>,
          (input.app_metadata ?? {}) as Record<string, unknown>,
        );
        return currentUser;
      },
      update: async () => { throw new Error("unused"); },
      softDelete: async () => undefined,
    },
    sessions: { revokeUserSessions: async () => undefined },
    authorization: {
      effectivePermissions: async () => [],
      assignRole: async () => undefined,
      unassignRole: async () => undefined,
      setRolePermissions: async () => undefined,
      setRoleInheritance: async () => undefined,
    },
    roles: {
      list: async () => [],
      findById: async () => null,
      create: async () => { throw new Error("unused"); },
      update: async () => { throw new Error("unused"); },
      delete: async () => undefined,
    },
    permissions: {
      list: async () => [],
      findById: async () => null,
      create: async () => { throw new Error("unused"); },
      update: async () => { throw new Error("unused"); },
      delete: async () => undefined,
    },
    operations: {
      appendAudit: async (input: Record<string, unknown>) => { events.push(input); },
      findApiKeyByHash: async () => null,
    },
    admin: {
      listUsers: async () => ({ users: [], total: 0 }),
      createApiKey: async () => { throw new Error("unused"); },
      listApiKeys: async () => ({ apiKeys: [], total: 0 }),
      revokeApiKey: async () => false,
      touchApiKeyLastUsed: async () => undefined,
      listAudit: async () => ({ events: [], total: 0 }),
      assignedRolesForUpdate: async () => [],
      rolesForUpdate: async () => [],
      countActiveRoleAssignments: async () => 0,
    },
    identities: {},
    passwordCredentials: {},
    oneTimeTokens: {},
    oauthStates: {},
  };
  return {
    repository: base as unknown as AuthRepository,
    calls,
    events,
    current: () => currentUser,
  };
}

function importUser(service: AdminService, input: ImportInput, principal: unknown): Promise<unknown> {
  return (service as unknown as ImportService).importUser(input, principal);
}

function secret(scopes: readonly string[]) {
  return { kind: "secret", keyId: ACTOR_KEY_ID, scopes } as const;
}

describe("stable UUID user import", () => {
  it("imports a supplied UUID and bounded profile metadata through the admin service", async () => {
    const value = fixture();
    const service = new AdminService({ repository: value.repository, clock: () => NOW });

    const result = await importUser(service, {
      id: TARGET_ID,
      email: "member@example.test",
      user_metadata: { display_name: "Member" },
    }, secret(["auth.users.import"]));

    expect(result).toMatchObject({
      data: { user: { id: TARGET_ID, email: "member@example.test", user_metadata: { display_name: "Member" } } },
      error: null,
    });
    expect(value.calls).toHaveLength(1);
    expect(value.calls[0]?.id).toBe(TARGET_ID);
  });

  it("rejects an invalid UUID before touching the repository", async () => {
    const value = fixture();
    const service = new AdminService({ repository: value.repository, clock: () => NOW });

    const result = await importUser(service, { id: "not-a-uuid", email: "member@example.test" }, secret(["auth.users.import"]));

    expect(result).toMatchObject({ data: null, error: { code: "invalid_request", status: 400 } });
    expect(value.calls).toHaveLength(0);
  });

  it("rejects an interactive administrator even when that user can manage users", async () => {
    const value = fixture();
    const service = new AdminService({ repository: value.repository, clock: () => NOW });

    const result = await importUser(service, { id: TARGET_ID, email: "member@example.test" }, {
      kind: "user",
      userId: ACTOR_USER_ID,
      sessionId: ACTOR_KEY_ID,
    });

    expect(result).toMatchObject({ data: null, error: { code: "forbidden", status: 403 } });
    expect(value.calls).toHaveLength(0);
  });

  it("requires the exact import scope and does not accept ordinary user-management scope", async () => {
    const value = fixture();
    const service = new AdminService({ repository: value.repository, clock: () => NOW });

    const result = await importUser(service, { id: TARGET_ID, email: "member@example.test" }, secret(["auth.users.manage"]));

    expect(result).toMatchObject({ data: null, error: { code: "insufficient_permission", status: 403 } });
    expect(value.calls).toHaveLength(0);
  });

  it("does not widen the import permission through wildcard scopes", async () => {
    const value = fixture();
    const service = new AdminService({ repository: value.repository, clock: () => NOW });

    const result = await importUser(service, { id: TARGET_ID, email: "member@example.test" }, secret(["auth.*"]));

    expect(result).toMatchObject({ data: null, error: { code: "insufficient_permission", status: 403 } });
    expect(value.calls).toHaveLength(0);
  });

  it("makes an equivalent same-record retry idempotent without creating or overwriting", async () => {
    const value = fixture();
    const service = new AdminService({ repository: value.repository, clock: () => NOW });
    const input = { id: TARGET_ID, email: "member@example.test", user_metadata: { display_name: "Member" } };

    const first = await importUser(service, input, secret(["auth.users.import"]));
    const second = await importUser(service, input, secret(["auth.users.import"]));

    expect(first).toMatchObject({ error: null });
    expect(second).toEqual(first);
    expect(value.calls).toHaveLength(1);
  });

  it("fails on a conflicting existing UUID and never overwrites it", async () => {
    const value = fixture();
    const service = new AdminService({ repository: value.repository, clock: () => NOW });
    const principal = secret(["auth.users.import"]);

    await importUser(service, { id: TARGET_ID, email: "original@example.test" }, principal);
    const result = await importUser(service, { id: TARGET_ID, email: "different@example.test" }, principal);

    expect(result).toMatchObject({ data: null, error: { code: "conflict", status: 409 } });
    expect(value.current()).toMatchObject({ id: TARGET_ID, email: "original@example.test" });
    expect(value.calls).toHaveLength(1);
  });

  it("fails on a duplicate email owned by another UUID", async () => {
    const value = fixture();
    const service = new AdminService({ repository: value.repository, clock: () => NOW });
    const principal = secret(["auth.users.import"]);

    await importUser(service, { id: TARGET_ID, email: "shared@example.test" }, principal);
    const result = await importUser(service, { id: OTHER_ID, email: "SHARED@example.test" }, principal);

    expect(result).toMatchObject({ data: null, error: { code: "conflict", status: 409 } });
    expect(value.current()).toMatchObject({ id: TARGET_ID, email: "shared@example.test" });
    expect(value.calls).toHaveLength(1);
  });

  it("emits a correlated successful import audit event", async () => {
    const value = fixture();
    const service = new AdminService({ repository: value.repository, clock: () => NOW });

    await importUser(service, { id: TARGET_ID, email: "member@example.test" }, secret(["auth.users.import"]));

    expect(value.events).toEqual(expect.arrayContaining([
      expect.objectContaining({
        actor_key_id: ACTOR_KEY_ID,
        action: "admin.user.imported",
        target_type: "user",
        target_id: TARGET_ID,
        outcome: "success",
        metadata: expect.objectContaining({ event: "admin_user_imported" }),
      }),
    ]));
  });
});
