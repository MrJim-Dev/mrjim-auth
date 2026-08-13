import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import ts from "typescript";
import { describe, expect, it } from "vitest";
import { createClient, type AuthStateCallback, type Identity, type Session, type SupportedStorage, type User } from "../../src/index.js";
import { createAdminClient, type AdminNamespace } from "../../src/server/admin.js";

const packageRoot = resolve(import.meta.dirname, "../..");
const workspaceRoot = resolve(packageRoot, "../..");
const baseUrl = "https://project.example.com/auth/v1";
const publishableKey = "publishable-key";
const secretKey = "secret-key";
const userId = "11111111-1111-4111-8111-111111111111" as User["id"];
const identityId = "22222222-2222-4222-8222-222222222222" as Identity["id"];
const now = "2026-08-12T00:00:00.000Z";
const redirectTo = "https://project.example.com/auth/callback";

const clientMethodNames = [
  "signUp",
  "signInWithPassword",
  "signInWithOtp",
  "verifyOtp",
  "signInWithOAuth",
  "exchangeCodeForSession",
  "resetPasswordForEmail",
  "resetPassword",
  "resend",
  "getSession",
  "getUser",
  "setSession",
  "refreshSession",
  "updateUser",
  "getUserIdentities",
  "linkIdentity",
  "unlinkIdentity",
  "getPermissions",
  "signOut",
  "onAuthStateChange",
  "startAutoRefresh",
  "stopAutoRefresh",
  "dispose",
] as const;

const adminMethodNames = [
  "listUsers",
  "getUserById",
  "findUser",
  "createUser",
  "importUser",
  "updateUserById",
  "deleteUser",
  "inviteUserByEmail",
  "listRoles",
  "createRole",
  "updateRole",
  "deleteRole",
  "setRolePermissions",
  "setRoleInheritance",
  "assignRole",
  "unassignRole",
  "listPermissions",
  "createPermission",
  "updatePermission",
  "deletePermission",
  "listAudit",
] as const;

const user: User = {
  id: userId,
  email: "user@example.com",
  phone: null,
  email_confirmed_at: now,
  phone_confirmed_at: null,
  confirmed_at: now,
  last_sign_in_at: now,
  banned_until: null,
  user_metadata: { display_name: "User" },
  app_metadata: {},
  created_at: now,
  updated_at: now,
  deleted_at: null,
};

const identity: Identity = {
  id: identityId,
  user_id: userId,
  provider: "google",
  provider_subject: "google-subject",
  email: user.email,
  identity_data: { sub: "google-subject", email: "user@example.com" } as Identity["identity_data"],
  created_at: now,
  updated_at: now,
};

function makeSession(): Session {
  return {
    access_token: "access-token",
    refresh_token: "refresh-token",
    token_type: "bearer",
    expires_in: 3600,
    expires_at: Math.floor(Date.now() / 1000) + 3600,
    user,
  };
}

function jsonResponse(data: unknown): Response {
  return new Response(JSON.stringify({ data, error: null }), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

function userResponse(): Response {
  return jsonResponse({ user });
}

function sessionResponse(): Response {
  return jsonResponse(makeSession());
}

function createStorage(): SupportedStorage {
  const values = new Map<string, string>();
  return {
    getItem: (key) => values.get(key) ?? null,
    setItem: (key, value) => { values.set(key, value); },
    removeItem: (key) => { values.delete(key); },
  };
}

function createAuthFetch(): typeof fetch {
  return async (input, init) => {
    const request = new Request(input, init);
    const url = new URL(request.url);
    if (url.pathname.startsWith("/auth/v1/user/identities/")) return jsonResponse(null);
    switch (url.pathname) {
      case "/auth/v1/signup":
      case "/auth/v1/otp":
        return jsonResponse({ user: null, session: null });
      case "/auth/v1/token":
        return sessionResponse();
      case "/auth/v1/verify":
        return jsonResponse({ user, session: makeSession() });
      case "/auth/v1/authorize":
        return jsonResponse({ provider: "google", url: "https://accounts.example/authorize", redirect: redirectTo, expires_at: now });
      case "/auth/v1/exchange":
        return jsonResponse({ user, session: makeSession(), identity });
      case "/auth/v1/recover":
      case "/auth/v1/resend":
        return jsonResponse({ sent: true });
      case "/auth/v1/recover/verify":
        return jsonResponse({ user });
      case "/auth/v1/user":
        return userResponse();
      case "/auth/v1/user/identities":
        return request.method === "DELETE" ? jsonResponse(null) : jsonResponse({ identities: [identity] });
      case "/auth/v1/user/permissions":
        return jsonResponse({ permissions: ["invoice.read"] });
      case "/auth/v1/logout":
        return jsonResponse(null);
      default:
        throw new Error(`unexpected public auth route: ${url.pathname}`);
    }
  };
}

function createAdminFetch(): typeof fetch {
  return async (input, init) => {
    const request = new Request(input, init);
    expect(request.headers.get("apikey")).toBe(secretKey);
    expect(request.headers.get("authorization")).toBeNull();
    return jsonResponse(null);
  };
}

function compileSupabaseFixture(): readonly string[] {
  const source = `
    import { createClient, type AuthChangeEvent, type ClientOptions, type Identity, type Session, type User } from "mrjim-auth";
    import { createAdminClient, type AdminNamespace } from "mrjim-auth/server";

    const storage = new Map<string, string>();
    const options: ClientOptions = {
      auth: {
        autoRefreshToken: false,
        persistSession: true,
        detectSessionInUrl: false,
        flowType: "pkce",
        storage: {
          getItem: (key) => storage.get(key) ?? null,
          setItem: (key, value) => { storage.set(key, value); },
          removeItem: (key) => { storage.delete(key); },
        },
        storageKey: "fixture",
        lock: async (_name, _timeout, callback) => callback(),
        debug: false,
        skipAutoInitialize: true,
      },
      global: { fetch },
    };
    const client = createClient("https://project.example.com/auth/v1", "publishable-key", options);
    const auth = client.auth;
    const callback: (event: AuthChangeEvent, session: Session | null) => void = (_event, _session) => {};
    const subscription = auth.onAuthStateChange(callback);
    const userInput: User = {
      id: "11111111-1111-4111-8111-111111111111" as User["id"],
      email: "user@example.com", phone: null, email_confirmed_at: null, phone_confirmed_at: null,
      confirmed_at: null, last_sign_in_at: null, banned_until: null, user_metadata: {}, app_metadata: {},
      created_at: "2026-08-12T00:00:00.000Z", updated_at: "2026-08-12T00:00:00.000Z", deleted_at: null,
    };
    const session: Session = {
      access_token: "access-token", refresh_token: "refresh-token", token_type: "bearer", expires_in: 900,
      expires_at: Math.floor(Date.now() / 1000) + 900, user: userInput,
    };
    void auth.signUp({ email: "user@example.com", password: "correct horse battery staple", options: { redirectTo: "https://project.example.com/auth/callback", data: { source: "fixture" } } });
    void auth.signInWithPassword({ email: "user@example.com", password: "correct horse battery staple" });
    void auth.signInWithOtp({ email: "user@example.com", options: { type: "emailOtp", redirectTo: "https://project.example.com/auth/callback" } });
    void auth.verifyOtp({ email: "user@example.com", token: "123456", type: "emailOtp", options: { redirectTo: "https://project.example.com/auth/callback" } });
    void auth.signInWithOAuth({ provider: "google", options: { redirectTo: "https://project.example.com/auth/callback", skipBrowserRedirect: true } });
    void auth.exchangeCodeForSession("callback-code");
    void auth.resetPasswordForEmail("user@example.com", { redirectTo: "https://project.example.com/auth/callback" });
    void auth.resetPassword({ email: "user@example.com", token: "recovery-token", password: "new correct horse battery staple" });
    void auth.resend({ type: "recovery", email: "user@example.com" });
    void auth.getSession();
    void auth.getUser();
    void auth.setSession(session);
    void auth.refreshSession(session);
    void auth.updateUser({ email: "new@example.com", data: { display_name: "New" }, redirectTo: "https://project.example.com/auth/callback" });
    void auth.getUserIdentities();
    void auth.linkIdentity({ provider: "google", options: { skipBrowserRedirect: true } });
    void auth.unlinkIdentity({ id: "22222222-2222-4222-8222-222222222222" as Identity["id"] });
    void auth.getPermissions({ scope: { type: "organization", id: "org_123" } });
    void auth.signOut({ scope: "local" });
    auth.startAutoRefresh();
    auth.stopAutoRefresh();
    subscription.unsubscribe();
    auth.dispose();

    const admin = createAdminClient("https://project.example.com/auth/v1", "secret-key");
    const namespace: AdminNamespace = admin.auth.admin;
    void namespace.listUsers({ page: 1, perPage: 25 });
    void namespace.getUserById("11111111-1111-4111-8111-111111111111");
    void namespace.findUser({ email: "user@example.com" });
    void namespace.createUser({ email: "user@example.com", password: "correct horse battery staple" });
    void namespace.updateUserById("11111111-1111-4111-8111-111111111111", { user_metadata: { display_name: "Updated" } });
    void namespace.deleteUser("11111111-1111-4111-8111-111111111111");
    void namespace.inviteUserByEmail("user@example.com", { redirect_to: "https://project.example.com/auth/callback" });
    void namespace.listRoles();
    void namespace.createRole({ key: "member", name: "Member", rank: 1 });
    void namespace.updateRole("role-1", { name: "Updated member" });
    void namespace.deleteRole("role-1");
    void namespace.setRolePermissions("role-1", ["permission-1"]);
    void namespace.setRoleInheritance("role-1", ["role-2"]);
    void namespace.assignRole("11111111-1111-4111-8111-111111111111", "role-1", { type: "organization", id: "org_123" });
    void namespace.unassignRole("11111111-1111-4111-8111-111111111111", "role-1", null);
    void namespace.listPermissions();
    void namespace.createPermission({ key: "invoice.read", resource: "invoice", action: "read" });
    void namespace.updatePermission("permission-1", { description: "Read invoices" });
    void namespace.deletePermission("permission-1");
    void namespace.listAudit({ page: 1, perPage: 25 });
  `;
  const directory = mkdtempSync(resolve(tmpdir(), "mrjim-auth-surface-"));
  try {
    const fixture = resolve(directory, "supabase-surface.ts");
    writeFileSync(fixture, source);
    const program = ts.createProgram([fixture], {
      baseUrl: workspaceRoot,
      paths: {
        "mrjim-auth": ["packages/mrjim-auth/dist/index.d.ts"],
        "mrjim-auth/server": ["packages/mrjim-auth/dist/server/index.d.ts"],
      },
      ignoreDeprecations: "6.0",
      module: ts.ModuleKind.ESNext,
      moduleResolution: ts.ModuleResolutionKind.Bundler,
      noEmit: true,
      skipLibCheck: true,
      strict: true,
      target: ts.ScriptTarget.ES2022,
      types: ["node"],
    });
    return ts.getPreEmitDiagnostics(program).map((diagnostic) => {
      const message = ts.flattenDiagnosticMessageText(diagnostic.messageText, "\n");
      if (diagnostic.file === undefined || diagnostic.start === undefined) return message;
      const position = diagnostic.file.getLineAndCharacterOfPosition(diagnostic.start);
      return `${diagnostic.file.fileName}:${position.line + 1}:${position.character + 1} ${message}`;
    });
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

describe("Supabase-shaped public surface", () => {
  it("compiles the complete client and admin surface against current declarations", () => {
    expect(compileSupabaseFixture()).toEqual([]);
  });

  it("invokes every supported client method, lifecycle event, and admin method", async () => {
    const client = createClient(baseUrl, publishableKey, {
      auth: {
        autoRefreshToken: false,
        persistSession: false,
        detectSessionInUrl: false,
        skipAutoInitialize: true,
        storage: createStorage(),
      },
      global: { fetch: createAuthFetch() },
    });
    const events: string[] = [];
    const callback: AuthStateCallback = (event) => events.push(event);
    const subscription = client.auth.onAuthStateChange(callback);
    expect(Object.keys(client.auth).sort()).toEqual([...clientMethodNames].sort());

    const session = makeSession();
    const clientCalls: ReadonlyArray<readonly [string, () => Promise<unknown>]> = [
      ["signUp", () => client.auth.signUp({ email: user.email!, password: "correct horse battery staple", options: { redirectTo } })],
      ["signInWithPassword", () => client.auth.signInWithPassword({ email: user.email!, password: "correct horse battery staple" })],
      ["signInWithOtp", () => client.auth.signInWithOtp({ email: user.email!, options: { type: "emailOtp", redirectTo } })],
      ["verifyOtp", () => client.auth.verifyOtp({ email: user.email!, token: "123456", type: "emailOtp", options: { redirectTo } })],
      ["signInWithOAuth", () => client.auth.signInWithOAuth({ provider: "google", options: { redirectTo, skipBrowserRedirect: true } })],
      ["exchangeCodeForSession", () => client.auth.exchangeCodeForSession("callback-code")],
      ["resetPasswordForEmail", () => client.auth.resetPasswordForEmail(user.email!, { redirectTo })],
      ["resetPassword", () => client.auth.resetPassword({ email: user.email!, token: "recovery-token", password: "new correct horse battery staple" })],
      ["resend", () => client.auth.resend({ type: "recovery", email: user.email!, options: { redirectTo } })],
      ["getSession", () => client.auth.getSession()],
      ["getUser", () => client.auth.getUser("explicit-access-token")],
      ["setSession", () => client.auth.setSession(session)],
      ["refreshSession", () => client.auth.refreshSession(session)],
      ["updateUser", () => client.auth.updateUser({ email: "new@example.com", data: { display_name: "Updated" } })],
      ["getUserIdentities", () => client.auth.getUserIdentities()],
      ["linkIdentity", () => client.auth.linkIdentity({ provider: "google", options: { redirectTo, skipBrowserRedirect: true } })],
      ["unlinkIdentity", () => client.auth.unlinkIdentity({ id: identityId })],
      ["getPermissions", () => client.auth.getPermissions({ scope: { type: "organization", id: "org_123" } })],
      ["signOut", () => client.auth.signOut({ scope: "local" })],
    ];
    expect(clientCalls.map(([name]) => name)).toEqual(clientMethodNames.slice(0, 19));
    for (const [name, call] of clientCalls) {
      const result = await call();
      expect(result, `${name} must return an auth result`).toHaveProperty("error", null);
    }
    client.auth.startAutoRefresh();
    client.auth.stopAutoRefresh();
    subscription.unsubscribe();
    client.auth.dispose();
    expect(events).toEqual(expect.arrayContaining(["SIGNED_IN", "USER_UPDATED", "PASSWORD_RECOVERY", "SIGNED_OUT"]));

    const admin = createAdminClient(baseUrl, secretKey, { global: { fetch: createAdminFetch() } });
    const namespace = admin.auth.admin;
    expect(Object.keys(namespace).sort()).toEqual([...adminMethodNames].sort());
    const adminCalls: ReadonlyArray<readonly [string, () => Promise<unknown>]> = [
      ["listUsers", () => namespace.listUsers({ page: 1, perPage: 25 })],
      ["getUserById", () => namespace.getUserById(userId)],
      ["findUser", () => namespace.findUser({ email: user.email! })],
      ["createUser", () => namespace.createUser({ email: user.email!, password: "correct horse battery staple" })],
      ["importUser", () => namespace.importUser({ id: userId, email: user.email!, user_metadata: { display_name: "Imported" } })],
      ["updateUserById", () => namespace.updateUserById(userId, { user_metadata: { display_name: "Updated" } })],
      ["deleteUser", () => namespace.deleteUser(userId)],
      ["inviteUserByEmail", () => namespace.inviteUserByEmail(user.email!, { redirect_to: redirectTo })],
      ["listRoles", () => namespace.listRoles()],
      ["createRole", () => namespace.createRole({ key: "member", name: "Member", rank: 1 })],
      ["updateRole", () => namespace.updateRole("role-1", { name: "Updated member" })],
      ["deleteRole", () => namespace.deleteRole("role-1")],
      ["setRolePermissions", () => namespace.setRolePermissions("role-1", ["permission-1"])],
      ["setRoleInheritance", () => namespace.setRoleInheritance("role-1", ["role-2"])],
      ["assignRole", () => namespace.assignRole(userId, "role-1", { type: "organization", id: "org_123" })],
      ["unassignRole", () => namespace.unassignRole(userId, "role-1", null)],
      ["listPermissions", () => namespace.listPermissions()],
      ["createPermission", () => namespace.createPermission({ key: "invoice.read", resource: "invoice", action: "read" })],
      ["updatePermission", () => namespace.updatePermission("permission-1", { description: "Read invoices" })],
      ["deletePermission", () => namespace.deletePermission("permission-1")],
      ["listAudit", () => namespace.listAudit({ page: 1, perPage: 25 })],
    ];
    expect(adminCalls.map(([name]) => name)).toEqual(adminMethodNames);
    for (const [name, call] of adminCalls) {
      const result = await call();
      expect(result, `${name} must return an admin auth result`).toHaveProperty("error", null);
    }
  });
});
