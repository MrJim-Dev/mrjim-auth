import { describe, expect, it } from "vitest";
import { createAdminClient } from "../../src/server/admin.js";
import * as routeContractModule from "../../src/server/routes/contracts.js";

type SchemaLike = { safeParse(value: unknown): { readonly success: boolean } };

function importSchema(): SchemaLike | undefined {
  return (routeContractModule as unknown as Record<string, unknown>).adminUserImportRequestSchema as SchemaLike | undefined;
}

describe("stable UUID import HTTP contract", () => {
  it("declares a distinct import-only admin route and request schema", () => {
    const route = routeContractModule.routeContracts.find((candidate) => candidate.path === "/admin/users/import" && candidate.method === "POST");
    expect(route).toMatchObject({ operationId: "adminImportUser", security: "admin" });
    expect(importSchema()).toBeDefined();
  });

  it("bounds import fields and rejects credential material", () => {
    const schema = importSchema();
    const valid = {
      id: "11111111-1111-4111-8111-111111111111",
      email: "member@example.test",
      user_metadata: { display_name: "Member" },
      app_metadata: { source: "courtera" },
    };
    expect(schema?.safeParse(valid).success).toBe(true);
    expect(schema?.safeParse({ ...valid, id: "not-a-uuid" }).success).toBe(false);
    expect(schema?.safeParse({ ...valid, password_hash: "must-not-be-accepted" }).success).toBe(false);
    expect(schema?.safeParse({ ...valid, user_metadata: { oversized: "x".repeat(4097) } }).success).toBe(false);
  });

  it("keeps ordinary admin create and public signup unable to receive an ID", () => {
    expect(routeContractModule.adminUserCreateRequestSchema.safeParse({
      id: "11111111-1111-4111-8111-111111111111",
      email: "member@example.test",
    }).success).toBe(false);
    expect(routeContractModule.signupRequestSchema.safeParse({
      id: "11111111-1111-4111-8111-111111111111",
      email: "member@example.test",
      password: "correct horse battery staple",
    }).success).toBe(false);
  });

  it("exposes import only as a distinct Node admin-client operation", () => {
    const client = createAdminClient("https://project.example.test/auth/v1", "sk_admin_test_key", {
      global: { fetch: async () => new Response(JSON.stringify({ data: null, error: null }), { status: 200 }) },
    });
    expect(typeof (client.auth.admin as unknown as Record<string, unknown>).importUser).toBe("function");
  });
});
