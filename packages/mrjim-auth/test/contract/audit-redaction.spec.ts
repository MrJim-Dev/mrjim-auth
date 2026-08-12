import { createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";
import { ApiKeyService, type ApiKeyStore } from "../../src/server/api-keys.js";
import { AuditService, type AuditStore } from "../../src/server/audit.js";

const HASH_KEY = Uint8Array.from({ length: 32 }, (_, index) => index + 1);
const NOW = new Date("2026-08-12T00:00:00.000Z");

describe("API-key and audit redaction contracts", () => {
  it("returns a generated key once while persisting only its HMAC digest and bounded display data", async () => {
    const creates: unknown[] = [];
    const store: ApiKeyStore = {
      async create(input) {
        creates.push(input);
        return {
          id: "11111111-1111-4111-8111-111111111111",
          name: input.name,
          prefix: input.prefix,
          kind: input.kind,
          scopes: input.scopes,
          last_used_at: null,
          expires_at: input.expires_at,
          revoked_at: null,
          created_at: NOW,
        };
      },
      async list() { return { apiKeys: [], total: 0 }; },
      async revoke() { return true; },
      async touchLastUsed() {},
    };
    const service = new ApiKeyService({ store, hashKey: HASH_KEY, clock: () => NOW });
    const result = await service.generate({ kind: "secret", name: "deploy", scopes: ["auth.users.manage"] });

    expect(result.error).toBeNull();
    const raw = result.data!.key;
    expect(raw).toMatch(/^sk_[A-Za-z0-9_-]{43}$/);
    expect(result.data!.apiKey).not.toHaveProperty("key_hash");
    expect(result.data!.apiKey).not.toHaveProperty("key");
    expect(creates).toHaveLength(1);
    const persisted = creates[0] as { key_hash: Uint8Array; prefix: string; name: string };
    expect(persisted.name).toBe("deploy");
    expect(persisted.prefix).toBe(raw.slice(0, 11));
    expect(Buffer.from(persisted.key_hash)).toEqual(createHmac("sha256", HASH_KEY).update(`apikey\0${raw}`).digest());
    expect(JSON.stringify(persisted)).not.toContain(raw);
  });

  it("normalizes scopes and rejects secret-bearing names, scopes, and expiry without calling the store", async () => {
    let creates = 0;
    const store = {
      async create() { creates += 1; throw new Error("must not run"); },
      async list() { return { apiKeys: [], total: 0 }; },
      async revoke() { return false; },
      async touchLastUsed() {},
    } satisfies ApiKeyStore;
    const service = new ApiKeyService({ store, hashKey: HASH_KEY, clock: () => NOW });

    await expect(service.generate({ kind: "secret", name: "sk_topsecretvalue", scopes: [] })).resolves.toMatchObject({ error: { code: "invalid_request" } });
    await expect(service.generate({ kind: "secret", name: "deploy", scopes: ["Bearer hidden"] })).resolves.toMatchObject({ error: { code: "invalid_request" } });
    await expect(service.generate({ kind: "secret", name: "deploy", scopes: [], expiresAt: NOW })).resolves.toMatchObject({ error: { code: "invalid_request" } });
    expect(creates).toBe(0);
  });

  it("projects audit rows through an explicit allowlist and rejects secret metadata before persistence", async () => {
    const appends: unknown[] = [];
    const store: AuditStore = {
      async append(input) { appends.push(input); },
      async list() {
        return {
          events: [{
            id: "22222222-2222-4222-8222-222222222222",
            actor_user_id: null,
            actor_key_id: null,
            actor_session_id: null,
            action: "admin.user.updated",
            target_type: "user",
            target_id: "11111111-1111-4111-8111-111111111111",
            ip_address: null,
            user_agent: null,
            metadata: { event: "admin_user_updated" },
            outcome: "success",
            occurred_at: NOW,
            password_hash: "$argon2id$secret",
            raw_token: "secret-token",
          }],
          total: 1,
        };
      },
    };
    const service = new AuditService({ store });
    const rejected = await service.append({
      action: "admin.user.updated",
      target_type: "user",
      metadata: { password: "do-not-store" } as never,
      outcome: "failure",
    });
    expect(rejected.error?.code).toBe("invalid_request");
    expect(appends).toHaveLength(0);

    const listed = await service.list({ page: 1, perPage: 25 });
    expect(listed.error).toBeNull();
    expect(listed.data!.events[0]).toEqual({
      id: "22222222-2222-4222-8222-222222222222",
      actor_user_id: null,
      actor_key_id: null,
      actor_session_id: null,
      action: "admin.user.updated",
      target_type: "user",
      target_id: "11111111-1111-4111-8111-111111111111",
      ip_address: null,
      user_agent: null,
      metadata: { event: "admin_user_updated" },
      outcome: "success",
      occurred_at: NOW.toISOString(),
    });
    expect(JSON.stringify(listed)).not.toContain("argon2");
    expect(JSON.stringify(listed)).not.toContain("secret-token");
  });
});
