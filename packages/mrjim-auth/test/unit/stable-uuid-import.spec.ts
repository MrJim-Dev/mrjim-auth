import { describe, expect, it } from "vitest";
import type { AuthRepository, ImportUserInput, RateLimiter } from "../../src/shared/contracts.js";
import { AdminService, type AdminPrincipal } from "../../src/server/admin-service.js";
import { uuidSchema, type User, type UUID } from "../../src/shared/types.js";

const TARGET_ID = uuidSchema.parse("11111111-1111-4111-8111-111111111111");
const OTHER_ID = uuidSchema.parse("22222222-2222-4222-8222-222222222222");
const ACTOR_KEY_ID = uuidSchema.parse("33333333-3333-4333-8333-333333333333");
const ACTOR_USER_ID = uuidSchema.parse("44444444-4444-4444-8444-444444444444");
const NOW = new Date("2026-08-13T00:00:00.000Z");

function makeUser(
  email: string | null,
  input: ImportUserInput,
): User {
  const emailConfirmedAt = input.email_confirmed_at !== undefined
    ? input.email_confirmed_at
    : input.confirmed_at !== undefined && email !== null ? input.confirmed_at : null;
  const phone = input.phone === undefined || input.phone === null || input.phone.trim() === "" ? null : input.phone.trim();
  const phoneConfirmedAt = input.phone_confirmed_at !== undefined
    ? input.phone_confirmed_at
    : input.confirmed_at !== undefined && email === null && phone !== null ? input.confirmed_at : null;
  const confirmations = [emailConfirmedAt, phoneConfirmedAt].filter((value): value is Date => value instanceof Date).sort((left, right) => left.getTime() - right.getTime());
  return {
    id: input.id,
    email,
    phone,
    email_confirmed_at: emailConfirmedAt?.toISOString() ?? null,
    phone_confirmed_at: phoneConfirmedAt?.toISOString() ?? null,
    confirmed_at: confirmations[0]?.toISOString() ?? null,
    last_sign_in_at: input.last_sign_in_at?.toISOString() ?? null,
    banned_until: input.banned_until?.toISOString() ?? null,
    user_metadata: input.user_metadata ?? {},
    app_metadata: input.app_metadata ?? {},
    created_at: NOW.toISOString(),
    updated_at: NOW.toISOString(),
    deleted_at: null,
  };
}

function fixture(initialUser: User | null = null): {
  readonly repository: AuthRepository;
  readonly calls: ImportUserInput[];
  readonly phoneLocks: string[];
  readonly events: Record<string, unknown>[];
  current(): User | null;
} {
  let currentUser = initialUser;
  const calls: ImportUserInput[] = [];
  const phoneLocks: string[] = [];
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
      findByNormalizedPhoneForUpdate: async (phone: string) => {
        phoneLocks.push(phone);
        return normalized(currentUser?.phone) === normalized(phone) ? currentUser : null;
      },
      create: async () => { throw new Error("unused"); },
      createIfAvailable: async () => null,
      createWithId: async (input: ImportUserInput) => {
        calls.push(input);
        if (currentUser?.id === input.id) throw Object.assign(new Error("duplicate UUID"), { code: "user_id_exists" });
        if (normalized(currentUser?.email) !== null && normalized(currentUser?.email) === normalized(input.email)) {
          throw Object.assign(new Error("duplicate email"), { code: "email_exists" });
        }
        if (normalized(currentUser?.phone) !== null && normalized(currentUser?.phone) === normalized(input.phone)) {
          throw Object.assign(new Error("duplicate phone"), { code: "phone_exists" });
        }
        const email = input.email === undefined || input.email === null || input.email.trim() === "" ? null : input.email.trim();
        currentUser = makeUser(email, input);
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
    phoneLocks,
    events,
    current: () => currentUser,
  };
}

function importUser(service: AdminService, input: ImportUserInput, principal: AdminPrincipal) {
  return service.importUser(input, principal);
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

  it("rejects reserved credential keys and credential-bearing values at every metadata depth", async () => {
    const value = fixture();
    const service = new AdminService({ repository: value.repository, clock: () => NOW });

    const result = await importUser(service, {
      id: TARGET_ID,
      user_metadata: {
        profile: {
          password: "password-material",
          password_hash: "hash-material",
          nested: {
            refresh_token: "refresh-material",
            access_token: "access-material",
            session: "session-material",
            oauth_client_secret: "secret-material",
            private_key: "-----BEGIN PRIVATE KEY-----secret",
            url: "https://example.test/callback?access_token=secret",
          },
        },
        values: ["Bearer access-token", "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.signature"],
      },
    }, secret(["auth.users.import"]));

    expect(result).toMatchObject({ data: null, error: { code: "invalid_request", status: 400 } });
    expect(value.calls).toHaveLength(0);
    expect(value.events).toEqual(expect.arrayContaining([
      expect.objectContaining({ actor_key_id: ACTOR_KEY_ID, action: "admin.user.imported", outcome: "failure", metadata: { event: "admin_import_invalid_request" } }),
    ]));
  });

  it("rejects an invalid UUID before touching the repository", async () => {
    const value = fixture();
    const service = new AdminService({ repository: value.repository, clock: () => NOW });

    const result = await importUser(service, { id: "not-a-uuid" as UUID, email: "member@example.test" }, secret(["auth.users.import"]));

    expect(result).toMatchObject({ data: null, error: { code: "invalid_request", status: 400 } });
    expect(value.calls).toHaveLength(0);
    expect(value.events).toEqual(expect.arrayContaining([
      expect.objectContaining({ actor_key_id: ACTOR_KEY_ID, action: "admin.user.imported", outcome: "failure", metadata: { event: "admin_import_invalid_request" } }),
    ]));
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

  it("rejects a trusted principal even though it is not interactive", async () => {
    const value = fixture();
    const service = new AdminService({ repository: value.repository, clock: () => NOW });

    const result = await importUser(service, { id: TARGET_ID, email: "member@example.test" }, { kind: "trusted" });

    expect(result).toMatchObject({ data: null, error: { code: "forbidden", status: 403 } });
    expect(value.calls).toHaveLength(0);
  });

  it("does not change a safe authorization error when failure-audit persistence fails", async () => {
    const value = fixture();
    (value.repository.operations as unknown as { appendAudit: () => Promise<void> }).appendAudit = async () => {
      throw new Error("audit database unavailable");
    };
    const service = new AdminService({ repository: value.repository, clock: () => NOW });

    const result = await importUser(service, { id: TARGET_ID, email: "member@example.test" }, secret(["auth.users.manage"]));

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

  it("locks and rejects a duplicate phone owned by another UUID", async () => {
    const value = fixture();
    const service = new AdminService({ repository: value.repository, clock: () => NOW });
    const principal = secret(["auth.users.import"]);

    await importUser(service, { id: TARGET_ID, phone: "+639171234567" }, principal);
    const result = await importUser(service, { id: OTHER_ID, phone: " +639171234567 " }, principal);

    expect(result).toMatchObject({ data: null, error: { code: "conflict", status: 409 } });
    expect(value.phoneLocks).toEqual(["+639171234567", "+639171234567"]);
    expect(value.current()).toMatchObject({ id: TARGET_ID, phone: "+639171234567" });
    expect(value.calls).toHaveLength(1);
  });

  it("treats phone and persisted auth timestamps as equivalent on retry", async () => {
    const value = fixture();
    const service = new AdminService({ repository: value.repository, clock: () => NOW });
    const principal = secret(["auth.users.import"]);
    const input: ImportUserInput = {
      id: TARGET_ID,
      phone: " +639171234567 ",
      phone_confirmed_at: new Date("2026-08-12T00:00:00.000Z"),
      last_sign_in_at: new Date("2026-08-12T01:00:00.000Z"),
      banned_until: new Date("2026-08-20T00:00:00.000Z"),
      app_metadata: { source: "courtera" },
    };

    const first = await importUser(service, input, principal);
    const second = await importUser(service, input, principal);

    expect(first).toMatchObject({ error: null, data: { user: { phone: "+639171234567", phone_confirmed_at: "2026-08-12T00:00:00.000Z", last_sign_in_at: "2026-08-12T01:00:00.000Z", banned_until: "2026-08-20T00:00:00.000Z" } } });
    expect(second).toEqual(first);
    expect(value.calls).toHaveLength(1);
  });

  it("returns an internal error but still attempts a fresh failure audit for unexpected operation errors", async () => {
    const value = fixture();
    (value.repository.users as unknown as { createWithId: () => Promise<never> }).createWithId = async () => {
      throw new Error("unexpected database failure");
    };
    const service = new AdminService({ repository: value.repository, clock: () => NOW });

    const result = await importUser(service, { id: TARGET_ID, email: "member@example.test" }, secret(["auth.users.import"]));

    expect(result).toMatchObject({ data: null, error: { code: "internal_error", status: 500 } });
    expect(value.events).toEqual(expect.arrayContaining([
      expect.objectContaining({ actor_key_id: ACTOR_KEY_ID, action: "admin.user.imported", target_id: TARGET_ID, outcome: "failure", metadata: { event: "admin_import_failed" } }),
    ]));
  });

  it("returns 409 and audits through a fresh transaction after a mapped race aborts the first transaction", async () => {
    const value = fixture();
    let transactionCount = 0;
    let firstTransactionAborted = false;
    const repository = value.repository as unknown as {
      transaction(callback: (repository: AuthRepository) => Promise<unknown>): Promise<unknown>;
      users: { createWithId(input: ImportUserInput): Promise<never> };
      operations: { appendAudit(input: Record<string, unknown>): Promise<void> };
    };
    repository.transaction = async (callback) => {
      transactionCount += 1;
      const result = await callback(value.repository);
      if (transactionCount === 1 && firstTransactionAborted) throw Object.assign(new Error("current transaction is aborted"), { code: "25P02" });
      return result;
    };
    repository.users.createWithId = async () => {
      firstTransactionAborted = true;
      throw Object.assign(new Error("email race"), { code: "email_exists" });
    };
    repository.operations.appendAudit = async (input) => {
      if (transactionCount === 1 && firstTransactionAborted) throw Object.assign(new Error("current transaction is aborted"), { code: "25P02" });
      value.events.push(input);
    };
    const service = new AdminService({ repository: value.repository, clock: () => NOW });

    const result = await importUser(service, { id: TARGET_ID, email: "member@example.test" }, secret(["auth.users.import"]));

    expect(result).toMatchObject({ data: null, error: { code: "conflict", status: 409 } });
    expect(transactionCount).toBe(2);
    expect(value.events).toEqual(expect.arrayContaining([
      expect.objectContaining({ actor_key_id: ACTOR_KEY_ID, action: "admin.user.imported", outcome: "failure", metadata: { event: "admin_policy_denied" } }),
    ]));
  });

  it("audits rate limiting without invoking the import repository operation", async () => {
    const value = fixture();
    const rateLimiter: RateLimiter = { consume: async () => ({ allowed: false, remaining: 0, retryAfterSeconds: 1 }) };
    const service = new AdminService({ repository: value.repository, clock: () => NOW, rateLimiter });

    const result = await importUser(service, { id: TARGET_ID, email: "member@example.test" }, secret(["auth.users.import"]));

    expect(result).toMatchObject({ data: null, error: { code: "rate_limit_exceeded", status: 429 } });
    expect(value.calls).toHaveLength(0);
    expect(value.events).toEqual(expect.arrayContaining([
      expect.objectContaining({ actor_key_id: ACTOR_KEY_ID, action: "admin.user.imported", outcome: "failure", metadata: { event: "admin_rate_limited" } }),
    ]));
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
