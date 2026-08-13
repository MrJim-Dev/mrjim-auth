import { describe, expect, it } from "vitest";
import { createAdminClient } from "../../src/server/admin.js";

const AUTH_URL = "https://project.example.test/auth/v1";
const SECRET_KEY = "sk_admin_test_key";

function success(data: unknown): Response {
  return new Response(JSON.stringify({ data, error: null }), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

describe("server-only admin client contract", () => {
  it("exposes the Supabase-shaped immutable admin namespace only from the Node server boundary", () => {
    const client = createAdminClient(AUTH_URL, SECRET_KEY, { global: { fetch: async () => success(null) } });
    expect(Object.isFrozen(client)).toBe(true);
    expect(Object.isFrozen(client.auth)).toBe(true);
    expect(Object.isFrozen(client.auth.admin)).toBe(true);
    expect(Object.keys(client.auth.admin).sort()).toEqual([
      "assignRole",
      "createPermission",
      "createRole",
      "createUser",
      "deletePermission",
      "deleteRole",
      "deleteUser",
      "findUser",
      "getUserById",
      "importUser",
      "inviteUserByEmail",
      "listAudit",
      "listPermissions",
      "listRoles",
      "listUsers",
      "setRoleInheritance",
      "setRolePermissions",
      "unassignRole",
      "updatePermission",
      "updateRole",
      "updateUserById",
    ].sort());
  });

  it("maps pagination and fixed secret-key headers without accepting browser-origin configuration", async () => {
    let seen: Request | undefined;
    const client = createAdminClient(AUTH_URL, SECRET_KEY, {
      global: {
        fetch: async (input, init) => {
          seen = new Request(input, init);
          return success({ users: [], total: 0, page: 2, per_page: 25 });
        },
      },
    });
    await expect(client.auth.admin.listUsers({ page: 2, perPage: 25 })).resolves.toEqual({
      data: { users: [], total: 0, page: 2, per_page: 25 },
      error: null,
    });
    expect(seen!.url).toBe(`${AUTH_URL}/admin/users?page=2&per_page=25`);
    expect(seen!.headers.get("apikey")).toBe(SECRET_KEY);
    expect(seen!.headers.get("authorization")).toBeNull();
    expect(seen!.headers.get("origin")).toBeNull();

    expect(() => createAdminClient(AUTH_URL, SECRET_KEY, {
      global: { fetch: async () => success(null), headers: { origin: "https://browser.example" } },
    })).toThrow(/browser|origin/i);
  });

  it("uses the strict server endpoint/body shapes for find, invite, and scoped role assignment", async () => {
    const requests: Request[] = [];
    const client = createAdminClient(AUTH_URL, SECRET_KEY, {
      global: { fetch: async (input, init) => { requests.push(new Request(input, init)); return success(null); } },
    });
    await client.auth.admin.findUser({ email: "user@example.test" });
    await client.auth.admin.inviteUserByEmail("user@example.test", { redirect_to: "https://project.example.test/welcome" });
    await client.auth.admin.assignRole("11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222", { type: "organization", id: "org_1" });
    expect(requests[0]!.url).toBe(`${AUTH_URL}/admin/users/find?email=user%40example.test`);
    expect(await requests[1]!.json()).toEqual({ email: "user@example.test", options: { redirect_to: "https://project.example.test/welcome" } });
    expect(requests[2]!.url).toBe(`${AUTH_URL}/admin/users/11111111-1111-4111-8111-111111111111/roles/22222222-2222-4222-8222-222222222222?scope_type=organization&scope_id=org_1`);
  });

  it("maps stable HTTP errors without leaking response bodies or the secret key", async () => {
    const client = createAdminClient(AUTH_URL, SECRET_KEY, {
      global: {
        fetch: async () => new Response(JSON.stringify({
          error: { code: "insufficient_permission", message: `denied ${SECRET_KEY}`, request_id: "admin-request" },
        }), { status: 403, headers: { "content-type": "application/json" } }),
      },
    });
    const result = await client.auth.admin.listRoles();
    expect(result.error).toMatchObject({ code: "insufficient_permission", status: 403, request_id: "admin-request" });
    expect(result.error?.message).not.toContain(SECRET_KEY);
  });
});
