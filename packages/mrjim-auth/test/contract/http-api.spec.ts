import { createHmac, generateKeyPairSync } from "node:crypto";
import { beforeAll, describe, expect, it } from "vitest";
import { AuthConfigurationError } from "../../src/shared/errors.js";
import { AuthServer } from "../../src/server/auth-server.js";
import { createAdminClient } from "../../src/server/admin.js";

const BASE_URL = "https://project.example.com/auth/v1";
const SITE_URL = "https://project.example.com";
const CALLBACK = "https://project.example.com/auth/callback";
const TOKEN_HASH_KEY = Uint8Array.from({ length: 32 }, (_, index) => index + 1);
const PUBLISHABLE_KEY = "pk_test_task9_contract";
const SECRET_KEY = "sk_test_task9_contract";
const ACCESS_TOKEN = "access-token-task9";
const REFRESH_TOKEN = "refresh-token-task9";
const USER_ID = "00000000-0000-4000-8000-000000000901";
const SESSION_ID = "00000000-0000-4000-8000-000000000902";
const IDENTITY_ID = "00000000-0000-4000-8000-000000000903";

type ServerModule = {
  readonly createAuthServer: (options: unknown) => {
    handle(request: Request): Promise<Response>;
    authorize(request: Request, requirement: unknown): Promise<unknown>;
  };
  readonly generateOpenApiDocument: () => Record<string, unknown>;
};

let serverModule: ServerModule;

function generatedSigningKey(): string {
  const pair = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return pair.privateKey.export({ type: "pkcs8", format: "pem" }).toString();
}

function apiKeyHash(value: string): Uint8Array {
  return Uint8Array.from(
    createHmac("sha256", TOKEN_HASH_KEY).update(`apikey\0${value}`, "utf8").digest(),
  );
}

function user() {
  return {
    id: USER_ID,
    email: "User@Example.com",
    phone: null,
    email_confirmed_at: "2026-08-11T00:00:00.000Z",
    phone_confirmed_at: null,
    confirmed_at: "2026-08-11T00:00:00.000Z",
    last_sign_in_at: null,
    banned_until: null,
    user_metadata: { display_name: "User" },
    app_metadata: {},
    created_at: "2026-08-11T00:00:00.000Z",
    updated_at: "2026-08-11T00:00:00.000Z",
    deleted_at: null,
  };
}

function session() {
  return {
    access_token: ACCESS_TOKEN,
    refresh_token: REFRESH_TOKEN,
    token_type: "bearer",
    expires_in: 900,
    expires_at: 1_800_000_900,
    user: user(),
  };
}

function accessClaims(overrides: Record<string, unknown> = {}) {
  return {
    sub: USER_ID,
    sid: SESSION_ID,
    aal: 1,
    iat: 1_700_000_000,
    exp: 1_800_000_900,
    iss: BASE_URL,
    aud: "project",
    ...overrides,
  };
}

function identity() {
  return {
    id: IDENTITY_ID,
    user_id: USER_ID,
    provider: "google",
    provider_subject: "provider-subject",
    email: "user@example.com",
    identity_data: { sub: "provider-subject", email: "user@example.com", email_verified: true },
    created_at: "2026-08-11T00:00:00.000Z",
    updated_at: "2026-08-11T00:00:00.000Z",
  };
}

function success<T>(data: T) {
  return { data, error: null };
}

function apiKeyRecord(value: string, kind: "publishable" | "secret" = "publishable") {
  return {
    id: "00000000-0000-4000-8000-000000000904",
    prefix: value.slice(0, 8),
    kind,
    scopes: [],
    key_hash: apiKeyHash(value),
    expires_at: null,
    revoked_at: null,
  };
}

function makeOptions(calls: Array<{ readonly name: string; readonly input: unknown }>) {
  const records = new Map<string, ReturnType<typeof apiKeyRecord>>([
    [PUBLISHABLE_KEY, apiKeyRecord(PUBLISHABLE_KEY)],
    [SECRET_KEY, apiKeyRecord(SECRET_KEY, "secret")],
  ]);
  const repository = {
    transaction: async (callback: (value: unknown) => Promise<unknown>) => callback(repository),
    users: {
      findById: async () => user(), findByIdForUpdate: async () => user(),
      findByNormalizedEmail: async () => user(), findByNormalizedEmailForUpdate: async () => user(),
      create: async () => user(), createIfAvailable: async () => user(), update: async () => user(), softDelete: async () => undefined,
    },
    identities: {
      findByProviderSubject: async () => identity(), listByUserId: async () => [identity()],
      create: async () => identity(), createIfAvailable: async () => identity(), deleteById: async () => undefined,
    },
    passwordCredentials: { findByUserId: async () => null, upsert: async () => undefined, deleteByUserId: async () => undefined },
    sessions: {
      create: async () => ({ session: {}, refreshToken: {} }), findByIdForUpdate: async () => null,
      findRefreshForUpdate: async () => null, rotate: async () => ({}), revokeSession: async () => undefined,
      revokeFamily: async () => undefined, revokeUserSessions: async () => undefined,
    },
    oneTimeTokens: { issue: async () => undefined, consume: async () => null, consumeBound: async () => null, recordFailure: async () => null },
    oauthStates: { create: async () => undefined, consume: async () => null },
    authorization: {
      effectivePermissions: async () => [], assignRole: async () => undefined, unassignRole: async () => undefined,
      setRolePermissions: async () => undefined, setRoleInheritance: async () => undefined,
    },
    roles: { list: async () => [], findById: async () => null, create: async () => ({}), update: async () => ({}), delete: async () => undefined },
    permissions: { list: async () => [], findById: async () => null, create: async () => ({}), update: async () => ({}), delete: async () => undefined },
    operations: {
      appendAudit: async () => undefined,
      findApiKeyByHash: async (hash: Uint8Array) => {
        for (const [raw, record] of records) {
          if (raw === PUBLISHABLE_KEY && Buffer.from(hash).equals(Buffer.from(record.key_hash))) return record;
          if (raw === SECRET_KEY && Buffer.from(hash).equals(Buffer.from(record.key_hash))) return record;
        }
        return null;
      },
    },
  };

  const users = {
    signUp: async (input: unknown) => { calls.push({ name: "signUp", input }); return success({ user: user(), session: null }); },
    signIn: async (input: unknown) => { calls.push({ name: "signIn", input }); return success({ user: user(), session: session() }); },
    signInWithOtp: async (input: unknown) => { calls.push({ name: "signInWithOtp", input }); return success({ user: null, session: null }); },
    verifyOtp: async (input: unknown) => { calls.push({ name: "verifyOtp", input }); return success({ user: user(), session: session() }); },
    resetPasswordForEmail: async (input: unknown) => { calls.push({ name: "resetPasswordForEmail", input }); return success({ sent: true }); },
    resetPassword: async (input: unknown) => { calls.push({ name: "resetPassword", input }); return success({ user: user() }); },
    resend: async (input: unknown) => { calls.push({ name: "resend", input }); return success({ sent: true }); },
    updateUser: async (_subject: unknown, input: unknown) => { calls.push({ name: "updateUser", input }); return success({ user: user() }); },
  };
  const sessions = {
    refresh: async (input: unknown) => { calls.push({ name: "refresh", input }); return success(session()); },
    authorizeSession: async (_input: unknown) => success({ session: session(), session_id: SESSION_ID, user_id: USER_ID, user: user() }),
    signOut: async (_subject: unknown, input: unknown) => { calls.push({ name: "signOut", input }); return success(null); },
    revokeRefreshToken: async (input: unknown) => { calls.push({ name: "revokeRefreshToken", input }); return success(null); },
  };
  const oauth = {
    listProviders: () => [{ name: "google", scopes: ["openid", "email"], capabilities: { authorization_code: true, pkce: true, identity_linking: true } }],
    authorize: async (input: unknown) => { calls.push({ name: "authorize", input }); return success({ provider: "google", url: "https://accounts.example/authorize", redirect: CALLBACK, state: "state", codeVerifier: "verifier", expiresAt: "2026-08-11T00:10:00.000Z" }); },
    callback: async (input: unknown) => { calls.push({ name: "callback", input }); return success({ code: "callback-code", redirect: CALLBACK, url: `${CALLBACK}?code=callback-code`, expiresAt: "2026-08-11T00:01:00.000Z" }); },
    exchangeCode: async (input: unknown) => { calls.push({ name: "exchangeCode", input }); return success({ user: user(), identity: identity(), session: session() }); },
    listIdentities: async (_subject: unknown) => success([identity()]),
    unlinkIdentity: async (_subject: unknown, input: unknown) => { calls.push({ name: "unlinkIdentity", input }); return success(null); },
  };
  const authorization = {
    getPermissions: async (_userId: unknown, _scope: unknown, _context: unknown) => ["invoice.read"],
    authorize: async (subject: unknown) => subject,
  };
  const tokens = {
    verifyAccessToken: async (value: string) => value === ACCESS_TOKEN
      ? success({ sub: USER_ID, sid: SESSION_ID, aal: 1, iat: 1_700_000_000, exp: 1_800_000_900, iss: `${BASE_URL}`, aud: "project" })
      : { data: null, error: { name: "AuthError", code: "invalid_token", status: 401, message: "Invalid access token" } },
    jwks: async () => ({ keys: [{ kid: "test", alg: "ES256", use: "sig", kty: "EC", crv: "P-256", x: "x", y: "y" }] }),
  };

  return {
    baseUrl: BASE_URL,
    siteUrl: SITE_URL,
    database: repository,
    signingKeys: { issuer: BASE_URL, audience: "project", activeKeyId: "test", keys: { test: generatedSigningKey() } },
    secrets: { tokenHashKey: TOKEN_HASH_KEY, encryptionKey: Uint8Array.from({ length: 32 }, (_, index) => index + 33) },
    email: { send: async () => undefined },
    redirects: { allowed: [CALLBACK] },
    authorization: { defaultRoleKeys: [], allowWildcards: true },
    environment: "test",
    services: { users, sessions, oauth, authorization, tokens },
  };
}

function request(path: string, init: RequestInit = {}): Request {
  const headers = new Headers(init.headers);
  if (!headers.has("apikey")) headers.set("apikey", PUBLISHABLE_KEY);
  return new Request(`${BASE_URL}${path}`, { ...init, headers });
}

async function body(response: Response): Promise<Record<string, any>> {
  return await response.json() as Record<string, any>;
}

describe("Task 9 framework-neutral HTTP contract", () => {
  beforeAll(async () => {
    serverModule = await import("../../src/server/index.js") as unknown as ServerModule;
    expect(serverModule.createAuthServer).toBeTypeOf("function");
    expect(serverModule.generateOpenApiDocument).toBeTypeOf("function");
  });

  it("dispatches Task 12 admin routes for non-browser secrets and delegated bearer sessions", async () => {
    const calls: Array<{ readonly name: string; readonly input: unknown }> = [];
    const options = makeOptions(calls) as any;
    const result = (data: unknown) => success(data);
    const unused = async () => result(null);
    options.services.admin = {
      listUsers: async (input: unknown, principal: unknown) => { calls.push({ name: "admin.listUsers", input: { input, principal } }); return result({ users: [], total: 0, page: 2, per_page: 25 }); },
      getUserById: async (input: unknown, principal: unknown) => { calls.push({ name: "admin.getUserById", input: { input, principal } }); return result({ user: user() }); },
      findUser: unused, createUser: unused, updateUserById: unused, deleteUser: unused, inviteUserByEmail: unused,
      listRoles: unused, createRole: unused, updateRole: unused, deleteRole: unused, setRolePermissions: unused,
      setRoleInheritance: unused, assignRole: unused, unassignRole: unused, listPermissions: unused,
      createPermission: unused, updatePermission: unused, deletePermission: unused, listAudit: unused,
    };
    const auth = serverModule.createAuthServer(options);

    const secret = await auth.handle(request("/admin/users?page=2&per_page=25", { headers: { apikey: SECRET_KEY } }));
    expect(secret.status).toBe(200);
    expect(await body(secret)).toMatchObject({ data: { users: [], page: 2, per_page: 25 }, error: null });
    expect(calls.at(-1)).toMatchObject({ name: "admin.listUsers", input: { principal: { kind: "secret" } } });
    const client = createAdminClient(BASE_URL, SECRET_KEY, { global: { fetch: (input, init) => auth.handle(new Request(input, init)) } });
    await expect(client.auth.admin.listUsers({ page: 2, perPage: 25 })).resolves.toMatchObject({ data: { users: [], page: 2, per_page: 25 }, error: null });

    const delegated = await auth.handle(request(`/admin/users/${USER_ID}`, { headers: { apikey: PUBLISHABLE_KEY, authorization: `Bearer ${ACCESS_TOKEN}` } }));
    expect(delegated.status).toBe(200);
    expect(calls.at(-1)).toMatchObject({ name: "admin.getUserById", input: { input: USER_ID, principal: { kind: "user", userId: USER_ID, sessionId: SESSION_ID } } });

    const missingBearer = await auth.handle(request("/admin/users", { headers: { apikey: PUBLISHABLE_KEY } }));
    expect(missingBearer.status).toBe(401);
    const browserSecret = await auth.handle(request("/admin/users", { headers: { apikey: SECRET_KEY, origin: SITE_URL } }));
    expect(browserSecret.status).toBe(403);
  });

  it("dispatches signup and normalizes email before the user service", async () => {
    const calls: Array<{ readonly name: string; readonly input: unknown }> = [];
    const auth = serverModule.createAuthServer(makeOptions(calls));
    const response = await auth.handle(request("/signup", {
      method: "POST",
      headers: { "content-type": "application/json", "x-request-id": "task9-signup" },
      body: JSON.stringify({ email: " User@Example.com ", password: "correct horse battery staple", options: { redirect_to: CALLBACK } }),
    }));
    const value = await body(response);
    expect(response.status).toBe(200);
    expect(value).toMatchObject({ data: { user: { id: USER_ID }, session: null }, error: null });
    expect(calls[0]).toMatchObject({ name: "signUp", input: { email: "user@example.com" } });
    expect(response.headers.get("content-type")).toBe("application/json; charset=utf-8");
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("x-request-id")).toBe("task9-signup");
  });

  it("dispatches both token grant types and rejects duplicate grant parameters", async () => {
    const calls: Array<{ readonly name: string; readonly input: unknown }> = [];
    const auth = serverModule.createAuthServer(makeOptions(calls));
    const password = await auth.handle(request("/token?grant_type=password", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: "USER@example.com", password: "correct horse battery staple" }),
    }));
    expect(password.status).toBe(200);
    expect(calls.at(-1)?.name).toBe("signIn");
    const refresh = await auth.handle(request("/token?grant_type=refresh_token", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ refresh_token: REFRESH_TOKEN }),
    }));
    expect(refresh.status).toBe(200);
    expect(calls.at(-1)?.name).toBe("refresh");
    const duplicate = await auth.handle(request("/token?grant_type=password&grant_type=refresh_token", {
      method: "POST", headers: { "content-type": "application/json" }, body: "{}",
    }));
    expect(duplicate.status).toBe(400);
    expect((await body(duplicate)).error.code).toBe("invalid_request");
  });

  it("covers OTP, verification, recovery issue/consume, and resend route contracts", async () => {
    const calls: Array<{ readonly name: string; readonly input: unknown }> = [];
    const auth = serverModule.createAuthServer(makeOptions(calls));
    const cases: readonly [string, unknown, string][] = [
      ["/otp", { email: "USER@example.com", options: { type: "email_otp", redirect_to: CALLBACK } }, "signInWithOtp"],
      ["/verify", { email: "USER@example.com", token: "123456", type: "email_otp", redirect_to: CALLBACK }, "verifyOtp"],
      ["/recover", { email: "USER@example.com", redirect_to: CALLBACK }, "resetPasswordForEmail"],
      ["/recover/verify", { email: "USER@example.com", token: "recovery-token", password: "new correct horse battery staple", redirect_to: CALLBACK }, "resetPassword"],
      ["/resend", { type: "signup", email: "USER@example.com", options: { redirect_to: CALLBACK } }, "resend"],
    ];
    for (const [path, value, name] of cases) {
      const response = await auth.handle(request(path, {
        method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(value),
      }));
      expect(response.status, path).toBe(200);
      expect(calls.at(-1)?.name, path).toBe(name);
    }
    expect(calls.find(({ name }) => name === "resetPassword")?.input).toMatchObject({
      email: "user@example.com",
      token: "recovery-token",
      password: "new correct horse battery staple",
      redirectTo: CALLBACK,
    });
  });

  it("rejects recovery passwords above the UTF-8 byte policy before service dispatch", async () => {
    const calls: Array<{ readonly name: string; readonly input: unknown }> = [];
    const auth = serverModule.createAuthServer(makeOptions(calls));
    const password = "😀".repeat(300);
    expect(new TextEncoder().encode(password).byteLength).toBe(1_200);
    const response = await auth.handle(request("/recover/verify", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: "user@example.com", token: "recovery-token", password }),
    }));
    expect(response.status).toBe(400);
    expect((await body(response)).error.code).toBe("invalid_request");
    expect(calls.some(({ name }) => name === "resetPassword")).toBe(false);
  });

  it("covers providers, OAuth authorize/callback/exchange, and JWKS", async () => {
    const calls: Array<{ readonly name: string; readonly input: unknown }> = [];
    const auth = serverModule.createAuthServer(makeOptions(calls));
    expect((await body(await auth.handle(request("/providers")))).data.providers).toHaveLength(1);
    const authorizeBody = await body(await auth.handle(request("/authorize?provider=google&code_challenge=client-challenge")));
    expect(authorizeBody.data).toMatchObject({ provider: "google", redirect: CALLBACK });
    expect(authorizeBody.data).not.toHaveProperty("state");
    expect(authorizeBody.data).not.toHaveProperty("code_verifier");
    const callback = await auth.handle(request("/callback/google?code=provider-code&state=state"));
    expect(callback.status).toBe(303);
    expect(callback.headers.get("location")).toContain("code=callback-code");
    const exchange = await auth.handle(request("/exchange", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ code: "callback-code", code_verifier: "verifier", redirect_to: CALLBACK }),
    }));
    expect(exchange.status).toBe(200);
    expect((await body(exchange)).data.session.access_token).toBe(ACCESS_TOKEN);
    const jwks = await auth.handle(request("/.well-known/jwks.json"));
    expect(jwks.status).toBe(200);
    expect((await body(jwks)).data.keys[0]).not.toHaveProperty("d");
  });

  it("projects AuthServer provider discovery without reading extra fields", async () => {
    const options = makeOptions([]);
    let clientSecretReads = 0;
    const provider = {
      name: "google",
      scopes: ["openid"],
      capabilities: { authorization_code: true, pkce: true, identity_linking: true },
      token: { value: "auth-server-provider-token-sentinel", verifier: "auth-server-provider-verifier-sentinel" },
    };
    Object.defineProperty(provider, "clientSecret", {
      configurable: true,
      enumerable: true,
      get() {
        clientSecretReads += 1;
        throw new Error("auth-server-provider-secret-sentinel");
      },
    });
    const oauth = options.services.oauth;
    if (oauth === undefined) throw new Error("OAuth service fixture is unavailable");
    options.services.oauth = { ...oauth, listProviders: () => [provider] };
    const auth = serverModule.createAuthServer(options);
    const response = await auth.handle(request("/providers"));
    const value = await body(response);
    expect(response.status).toBe(200);
    expect(clientSecretReads).toBe(0);
    expect(value.data.providers).toEqual([{
      name: "google",
      scopes: ["openid"],
      capabilities: { authorization_code: true, pkce: true, identity_linking: true },
    }]);
    expect(JSON.stringify(value)).not.toContain("auth-server-provider-token-sentinel");
    expect(JSON.stringify(value)).not.toContain("auth-server-provider-verifier-sentinel");
    expect(JSON.stringify(value)).not.toContain("auth-server-provider-secret-sentinel");
  });

  it("does not expose provider state or server PKCE material on the authorize wire contract", async () => {
    const calls: Array<{ readonly name: string; readonly input: unknown }> = [];
    const options = makeOptions(calls) as any;
    options.services.oauth.authorize = async (input: unknown) => {
      calls.push({ name: "authorize", input });
      return success({
        provider: "google",
        url: "https://accounts.example/authorize?client_id=public-client",
        redirect: CALLBACK,
        state: "provider-state-sentinel",
        codeVerifier: "server-verifier-sentinel",
        expiresAt: "2026-08-11T00:10:00.000Z",
      });
    };
    const auth = serverModule.createAuthServer(options);
    const authorizeResponse = await auth.handle(request("/authorize?provider=google&code_challenge=client-challenge-sentinel&code_challenge_method=S256"));
    expect(authorizeResponse.status).toBe(200);
    const authorizeBody = await body(authorizeResponse);
    expect(authorizeBody.data).not.toHaveProperty("state");
    expect(authorizeBody.data).not.toHaveProperty("code_verifier");
    expect(JSON.stringify(authorizeBody)).not.toContain("provider-state-sentinel");
    expect(JSON.stringify(authorizeBody)).not.toContain("server-verifier-sentinel");
    expect((calls.at(-1)?.input as Record<string, unknown>)).toMatchObject({ codeChallenge: "client-challenge-sentinel" });

    const callback = await auth.handle(request("/callback/google?code=provider-code-sentinel&state=provider-state-sentinel"));
    expect(callback.status).toBe(303);
    const location = callback.headers.get("location") ?? "";
    expect(location).not.toContain("provider-code-sentinel");
    expect(location).not.toContain("provider-state-sentinel");
    expect(location).not.toContain("server-verifier-sentinel");
  });

  it("requires a strict API key and bearer session for current-user routes", async () => {
    const auth = serverModule.createAuthServer(makeOptions([]));
    const missingKey = await auth.handle(new Request(`${BASE_URL}/user`));
    expect(missingKey.status).toBe(401);
    expect((await body(missingKey)).error).toMatchObject({ code: "unauthorized", request_id: expect.any(String) });
    const invalidBearer = await auth.handle(request("/user", { headers: { authorization: "Bearer one two" } }));
    expect(invalidBearer.status).toBe(400);
    const userResponse = await auth.handle(request("/user", { headers: { authorization: `Bearer ${ACCESS_TOKEN}` } }));
    expect(userResponse.status).toBe(200);
    expect((await body(userResponse)).data.user.id).toBe(USER_ID);
    const permissions = await auth.handle(request("/user/permissions", { headers: { authorization: `Bearer ${ACCESS_TOKEN}` } }));
    expect(permissions.status).toBe(200);
    expect((await body(permissions)).data.permissions).toEqual(["invoice.read"]);
  });

  it("covers update, identities, unlink, and logout dispatch", async () => {
    const calls: Array<{ readonly name: string; readonly input: unknown }> = [];
    const auth = serverModule.createAuthServer(makeOptions(calls));
    const bearer = { authorization: `Bearer ${ACCESS_TOKEN}` };
    const update = await auth.handle(request("/user", {
      method: "PUT", headers: { ...bearer, "content-type": "application/json" },
      body: JSON.stringify({ user_metadata: { display_name: "Updated" } }),
    }));
    expect(update.status).toBe(200);
    expect(calls.at(-1)?.name).toBe("updateUser");
    expect((await body(await auth.handle(request("/user/identities", { headers: bearer })))).data.identities).toHaveLength(1);
    expect((await auth.handle(request(`/user/identities/${IDENTITY_ID}`, { method: "DELETE", headers: bearer }))).status).toBe(200);
    expect(calls.at(-1)?.name).toBe("unlinkIdentity");
    expect((await auth.handle(request("/logout", { method: "POST", headers: { ...bearer, "content-type": "application/json" }, body: JSON.stringify({ scope: "local" }) }))).status).toBe(200);
    expect(calls.at(-1)?.name).toBe("signOut");
    expect((await auth.handle(request("/logout", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ refresh_token: REFRESH_TOKEN }) }))).status).toBe(200);
    expect(calls.at(-1)?.name).toBe("revokeRefreshToken");
  });

  it("rejects unknown fields, missing JSON content type, malformed JSON, and body overflow", async () => {
    const auth = serverModule.createAuthServer(makeOptions([]));
    const unknown = await auth.handle(request("/signup", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: "user@example.com", password: "correct horse battery staple", extra: true }),
    }));
    expect(unknown.status).toBe(400);
    const missingType = await auth.handle(request("/signup", { method: "POST", body: "{}" }));
    expect(missingType.status).toBe(400);
    const malformed = await auth.handle(request("/signup", { method: "POST", headers: { "content-type": "application/json" }, body: "{" }));
    expect(malformed.status).toBe(400);
    const exactPasswordLength = 64 * 1024 - JSON.stringify({ email: "user@example.com", password: "" }).length;
    const exactPayload = JSON.stringify({ email: "user@example.com", password: "x".repeat(exactPasswordLength) });
    expect(new TextEncoder().encode(exactPayload).byteLength).toBe(64 * 1024);
    const exact = await auth.handle(request("/signup", {
      method: "POST", headers: { "content-type": "application/json" },
      body: exactPayload,
    }));
    expect(exact.status).toBe(400);
    const overflow = await auth.handle(request("/signup", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: "user@example.com", password: "x".repeat(exactPasswordLength + 1) }),
    }));
    expect(overflow.status).toBe(413);
  });

  it("rejects misleading lengths, streamed overflow, and body read failures", async () => {
    const auth = serverModule.createAuthServer(makeOptions([]));
    const misleadingLength = await auth.handle(request("/signup", {
      method: "POST",
      headers: { "content-type": "application/json", "content-length": "1" },
      body: JSON.stringify({ email: "user@example.com", password: "correct horse battery staple" }),
    }));
    expect(misleadingLength.status).toBe(413);

    const overflowStream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array(64 * 1024 + 1));
        controller.close();
      },
    });
    const streamedOverflow = await auth.handle(new Request(`${BASE_URL}/signup`, {
      method: "POST",
      headers: { apikey: PUBLISHABLE_KEY, "content-type": "application/json" },
      body: overflowStream,
      duplex: "half",
    } as RequestInit));
    expect(streamedOverflow.status).toBe(413);

    const failingStream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.error(new Error("body read failure"));
      },
    });
    const bodyFailure = await auth.handle(new Request(`${BASE_URL}/signup`, {
      method: "POST",
      headers: { apikey: PUBLISHABLE_KEY, "content-type": "application/json" },
      body: failingStream,
      duplex: "half",
    } as RequestInit));
    expect(bodyFailure.status).toBe(400);
  });

  it("cancels failed body readers without changing stable errors", async () => {
    const auth = serverModule.createAuthServer(makeOptions([]));
    const cancellation = { overflow: 0, invalid: 0, failure: 0 };
    const overflowStream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array(64 * 1024 + 1));
      },
      cancel() {
        cancellation.overflow += 1;
        return Promise.reject(new Error("overflow cancellation rejected"));
      },
    });
    const overflow = await auth.handle(new Request(`${BASE_URL}/signup`, {
      method: "POST",
      headers: { apikey: PUBLISHABLE_KEY, "content-type": "application/json" },
      body: overflowStream,
      duplex: "half",
    } as RequestInit));
    expect(overflow.status).toBe(413);
    expect(cancellation.overflow).toBe(1);

    const invalidChunkStream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue("not-a-byte-chunk" as unknown as Uint8Array);
      },
      cancel() {
        cancellation.invalid += 1;
        return Promise.reject(new Error("invalid cancellation rejected"));
      },
    });
    const invalidChunk = await auth.handle(new Request(`${BASE_URL}/signup`, {
      method: "POST",
      headers: { apikey: PUBLISHABLE_KEY, "content-type": "application/json" },
      body: invalidChunkStream,
      duplex: "half",
    } as RequestInit));
    expect(invalidChunk.status).toBe(400);
    expect(cancellation.invalid).toBe(1);

    const readFailureStream = new ReadableStream<Uint8Array>({
      pull(controller) {
        controller.error(new Error("reader failed"));
      },
      cancel() {
        cancellation.failure += 1;
        return Promise.reject(new Error("failure cancellation rejected"));
      },
    });
    const readFailure = await auth.handle(new Request(`${BASE_URL}/signup`, {
      method: "POST",
      headers: { apikey: PUBLISHABLE_KEY, "content-type": "application/json" },
      body: readFailureStream,
      duplex: "half",
    } as RequestInit));
    expect(readFailure.status).toBe(400);
    expect(cancellation.failure).toBeLessThanOrEqual(1);
  });

  it("rejects unsupported or ambiguous Content-Encoding before reading the body", async () => {
    const calls: Array<{ readonly name: string; readonly input: unknown }> = [];
    const auth = serverModule.createAuthServer(makeOptions(calls));
    const signup = JSON.stringify({ email: "user@example.com", password: "correct horse battery staple" });
    const encodings = ["gzip", "br", "deflate", "GZIP", "gzip, identity", "identity, gzip", "identity,identity", "", "identity;foo"];
    for (const encoding of encodings) {
      let pulls = 0;
      const stream = new ReadableStream<Uint8Array>({
        pull(controller) {
          pulls += 1;
          controller.enqueue(new TextEncoder().encode(signup));
          controller.close();
        },
      });
      const encodedRequest = new Request(`${BASE_URL}/signup`, {
        method: "POST",
        headers: { apikey: PUBLISHABLE_KEY, "content-type": "application/json", "content-encoding": encoding },
        body: stream,
        duplex: "half",
      } as RequestInit);
      await new Promise<void>((resolve) => { setTimeout(resolve, 0); });
      const pullsBeforeHandle = pulls;
      const response = await auth.handle(encodedRequest);
      expect(response.status, JSON.stringify({ encoding })).toBe(400);
      expect(pulls, JSON.stringify({ encoding })).toBe(pullsBeforeHandle);
    }
    expect(calls).toHaveLength(0);

    const identity = await auth.handle(request("/signup", {
      method: "POST",
      headers: { "content-type": "application/json", "content-encoding": "identity" },
      body: signup,
    }));
    expect(identity.status).toBe(200);
    expect(calls).toHaveLength(1);
  });

  it("validates Content-Encoding before every bodyless dispatch and preflight", async () => {
    const calls: Array<{ readonly name: string; readonly input: unknown }> = [];
    const auth = serverModule.createAuthServer(makeOptions(calls));
    const routes: readonly [string, RequestInit][] = [
      ["/providers", {}],
      ["/.well-known/jwks.json", {}],
      ["/authorize?provider=google", {}],
      ["/callback/google?code=provider-code&state=provider-state", {}],
      ["/user", { headers: { authorization: `Bearer ${ACCESS_TOKEN}` } }],
      ["/user/identities", { headers: { authorization: `Bearer ${ACCESS_TOKEN}` } }],
      ["/logout", { method: "POST", headers: { "content-type": "application/json" }, body: "{}" }],
    ];
    for (const encoding of ["gzip", "br", "deflate", "identity, gzip", "gzip, identity", "identity,identity", ""]) {
      for (const [path, init] of routes) {
        const response = await auth.handle(request(path, {
          ...init,
          headers: { ...(init.headers ?? {}), "content-encoding": encoding },
        }));
        expect(response.status, `${path} ${encoding}`).toBe(400);
      }
      const preflight = await auth.handle(request("/signup", {
        method: "OPTIONS",
        headers: {
          origin: SITE_URL,
          "access-control-request-method": "POST",
          "access-control-request-headers": "apikey, content-type",
          "content-encoding": encoding,
        },
      }));
      expect(preflight.status, `OPTIONS ${encoding}`).toBe(400);
    }
    expect(calls).toHaveLength(0);
  });

  it("rejects ambiguous strict headers, parses preflight lists, and classifies Fetch Metadata failures as forbidden", async () => {
    const cases: readonly [string, RequestInit, number][] = [
      ["/providers", { headers: { authorization: "Bearer one, Bearer two" } }, 400],
      ["/signup", {
        method: "POST",
        headers: { "content-type": "application/json", "content-length": "1, 1000" },
        body: JSON.stringify({ email: "user@example.com", password: "correct horse battery staple" }),
      }, 400],
      ["/signup", {
        method: "POST",
        headers: { "content-type": "application/json", authorization: "Bearer one, Bearer two" },
        body: JSON.stringify({ email: "user@example.com", password: "correct horse battery staple" }),
      }, 400],
      ["/providers", { headers: { apikey: `${PUBLISHABLE_KEY}, ${PUBLISHABLE_KEY}` } }, 400],
      ["/providers", { headers: { origin: `${SITE_URL}, https://attacker.example` } }, 400],
      ["/signup", {
        method: "POST",
        headers: { "content-type": "application/json, application/json" },
        body: JSON.stringify({ email: "user@example.com", password: "correct horse battery staple" }),
      }, 400],
    ];
    for (const [path, init, status] of cases) {
      const calls: Array<{ readonly name: string; readonly input: unknown }> = [];
      const auth = serverModule.createAuthServer(makeOptions(calls));
      const response = await auth.handle(request(path, init));
      expect(response.status, path).toBe(status);
      expect(calls, path).toHaveLength(0);
    }

    const fetchCases: readonly Record<string, string>[] = [
      { "sec-fetch-site": "cross-site, same-origin" },
      { "sec-fetch-site": "not-a-fetch-site" },
      { "sec-fetch-mode": "cors, navigate" },
      { "sec-fetch-dest": "" },
      { "sec-fetch-user": "?1, ?0" },
    ];
    for (const headers of fetchCases) {
      const calls: Array<{ readonly name: string; readonly input: unknown }> = [];
      const auth = serverModule.createAuthServer(makeOptions(calls));
      const response = await auth.handle(request("/providers", { headers: { apikey: SECRET_KEY, ...headers } }));
      expect(response.status, JSON.stringify(headers)).toBe(403);
      expect(calls).toHaveLength(0);
    }

    const preflightCalls: Array<{ readonly name: string; readonly input: unknown }> = [];
    const preflightAuth = serverModule.createAuthServer(makeOptions(preflightCalls));
    const legal = await preflightAuth.handle(request("/signup", {
      method: "OPTIONS",
      headers: {
        origin: SITE_URL,
        "access-control-request-method": "POST",
        "access-control-request-headers": "apikey, authorization, content-type, x-request-id",
      },
    }));
    expect(legal.status).toBe(204);
    const disallowed = await preflightAuth.handle(request("/signup", {
      method: "OPTIONS",
      headers: {
        origin: SITE_URL,
        "access-control-request-method": "POST",
        "access-control-request-headers": "apikey, x-evil, authorization",
      },
    }));
    expect(disallowed.status).toBe(403);
    expect(preflightCalls).toHaveLength(0);
  });

  it("applies CORS, preflight, method, path, and origin rules without authorizing preflight", async () => {
    const auth = serverModule.createAuthServer(makeOptions([]));
    const preflight = await auth.handle(request("/user", {
      method: "OPTIONS",
      headers: { origin: SITE_URL, "access-control-request-method": "GET", "access-control-request-headers": "apikey, authorization" },
    }));
    expect(preflight.status).toBe(204);
    expect(preflight.headers.get("access-control-allow-origin")).toBe(SITE_URL);
    expect(preflight.headers.get("vary")).toContain("Origin");
    const actual = await auth.handle(request("/user", { headers: { origin: SITE_URL, authorization: `Bearer ${ACCESS_TOKEN}` } }));
    expect(actual.status).toBe(200);
    const disallowed = await auth.handle(request("/user", { headers: { origin: "https://attacker.example", authorization: `Bearer ${ACCESS_TOKEN}` } }));
    expect(disallowed.status).toBe(403);
    const trailing = await auth.handle(request("/providers/"));
    expect(trailing.status).toBe(404);
    const wrongOrigin = await auth.handle(new Request(`https://other.example.com${"/auth/v1/providers"}`, { headers: { apikey: PUBLISHABLE_KEY } }));
    expect(wrongOrigin.status).toBe(404);
    const mismatch = await auth.handle(request("/providers", { method: "POST" }));
    expect(mismatch.status).toBe(405);
  });

  it("does not let polluted array membership intrinsics authorize or reflect an attacker origin", async () => {
    const auth = serverModule.createAuthServer(makeOptions([]));
    const originalIncludes = Array.prototype.includes;
    const originalSome = Array.prototype.some;
    try {
      const allowedOrigins = (auth as any).allowedOrigins;
      const allowedRedirects = (auth as any).allowedRedirects;
      Array.prototype.includes = function (this: unknown[], ...args: unknown[]) {
        if (this === allowedOrigins) throw new Error("cors-includes-sentinel");
        return originalIncludes.apply(this, args as [unknown]);
      } as typeof Array.prototype.includes;
      Array.prototype.some = function (this: unknown[], ...args: unknown[]) {
        if (this === allowedRedirects) throw new Error("cors-some-sentinel");
        return originalSome.apply(this, args as [(value: unknown) => unknown]);
      } as typeof Array.prototype.some;
      const actual = await auth.handle(request("/providers", {
        headers: { origin: "https://attacker.example", apikey: PUBLISHABLE_KEY },
      }));
      const preflight = await auth.handle(request("/providers", {
        method: "OPTIONS",
        headers: {
          origin: "https://attacker.example",
          "access-control-request-method": "GET",
          "access-control-request-headers": "apikey",
        },
      }));
      expect(actual.status).toBe(403);
      expect(actual.headers.get("access-control-allow-origin")).toBeNull();
      expect(preflight.status).toBe(403);
      expect(preflight.headers.get("access-control-allow-origin")).toBeNull();
    } finally {
      Array.prototype.includes = originalIncludes;
      Array.prototype.some = originalSome;
    }
  });

  it("uses a captured byte-array conversion for API-key hashing", async () => {
    const auth = serverModule.createAuthServer(makeOptions([]));
    const descriptor = Object.getOwnPropertyDescriptor(Uint8Array, "from");
    const originalFrom = Uint8Array.from;
    expect(originalFrom).toBeTypeOf("function");
    try {
      Object.defineProperty(Uint8Array, "from", {
        configurable: descriptor?.configurable ?? true,
        enumerable: descriptor?.enumerable ?? false,
        writable: true,
        value: (...args: unknown[]) => {
          if ((new Error().stack ?? "").includes("auth-server.ts")) {
            throw new Error("api-key-uint8array-from-sentinel");
          }
          return Reflect.apply(originalFrom, Uint8Array, args);
        },
      });
      const response = await auth.handle(request("/providers"));
      expect(response.status).toBe(200);
      expect(JSON.stringify(await body(response))).not.toContain("api-key-uint8array-from-sentinel");
    } finally {
      if (descriptor === undefined) Reflect.deleteProperty(Uint8Array, "from");
      else Object.defineProperty(Uint8Array, "from", descriptor);
    }
  });

  it("redacts service failures and rejects browser secret keys", async () => {
    const auth = serverModule.createAuthServer(makeOptions([]));
    const secretBrowser = await auth.handle(request("/providers", { headers: { apikey: SECRET_KEY, origin: SITE_URL } }));
    expect(secretBrowser.status).toBe(403);
    const invalid = await auth.handle(new Request(`${BASE_URL}/providers`, { headers: { apikey: "pk_invalid" } }));
    expect(invalid.status).toBe(401);

    const failureOptions = makeOptions([]) as any;
    failureOptions.services.users.signUp = () => ({ data: null, error: { code: "internal_error", status: 500, message: "adapter secret raw-value" } });
    const failure = await serverModule.createAuthServer(failureOptions).handle(request("/signup", {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ email: "user@example.com", password: "correct horse battery staple" }),
    }));
    const failureBody = await body(failure);
    expect(failure.status).toBe(500);
    expect(JSON.stringify(failureBody)).not.toContain("adapter secret raw-value");
    expect(failureBody.error).toMatchObject({ code: "internal_error", message: "Internal authentication error" });

    let thenCalls = 0;
    const thenableOptions = makeOptions([]) as any;
    const thenable = Object.create(null);
    Object.defineProperty(thenable, "then", { configurable: false, enumerable: true, get: () => { thenCalls += 1; throw new Error("then getter executed"); } });
    thenableOptions.services.users.signUp = () => thenable;
    const thenableResponse = await serverModule.createAuthServer(thenableOptions).handle(request("/signup", {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ email: "user@example.com", password: "correct horse battery staple" }),
    }));
    expect(thenableResponse.status).toBe(500);
    expect(thenCalls).toBe(0);
  });

  it("keeps an authenticated provider response stable when Set.delete is poisoned", async () => {
    const auth = serverModule.createAuthServer(makeOptions([]));
    const originalDelete = Set.prototype.delete;
    try {
      Set.prototype.delete = (() => { throw new Error("round7-set-delete-sentinel"); }) as typeof Set.prototype.delete;
      const response = await auth.handle(request("/providers"));
      const responseBody = await body(response);
      expect(response.status).toBe(200);
      expect(JSON.stringify(responseBody)).not.toContain("round7-set-delete-sentinel");
      expect(responseBody.data.providers).toEqual([{
        name: "google",
        scopes: ["openid", "email"],
        capabilities: { authorization_code: true, pkce: true, identity_linking: true },
      }]);
    } finally {
      Set.prototype.delete = originalDelete;
    }
  });

  it("keeps invalid OIDC requests on the stable redacted error envelope when Object.setPrototypeOf is poisoned", async () => {
    const auth = serverModule.createAuthServer(makeOptions([]));
    const descriptor = Object.getOwnPropertyDescriptor(Object, "setPrototypeOf");
    if (descriptor === undefined) throw new Error("Object.setPrototypeOf is unavailable");
    let setterCalls = 0;
    Object.defineProperty(Object, "setPrototypeOf", {
      configurable: descriptor.configurable ?? true,
      enumerable: descriptor.enumerable ?? false,
      writable: true,
      value: (..._args: unknown[]) => {
        setterCalls += 1;
        throw new Error("round8-http-setPrototypeOf-sentinel");
      },
    });
    let response: Response;
    try {
      response = await auth.handle(request("/authorize?provider=google&code_challenge=client-challenge&code_challenge_method=plain", {
        headers: { "x-request-id": "round8-http-request" },
      }));
    } finally {
      Object.defineProperty(Object, "setPrototypeOf", descriptor);
    }
    const responseBody = await body(response);
    expect(setterCalls).toBe(0);
    expect(response.status).toBe(400);
    expect(responseBody.error).toEqual({
      code: "invalid_request",
      message: "Invalid authentication request",
      request_id: "round8-http-request",
    });
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(JSON.stringify(responseBody)).not.toContain("round8-http-setPrototypeOf-sentinel");
  });

  it("captures every service and repository callback at construction", async () => {
    const calls: Array<{ readonly name: string; readonly input: unknown }> = [];
    const options = makeOptions(calls) as any;
    const originalSignUp = options.services.users.signUp;
    let signUpReceiver: unknown;
    options.services.users.signUp = function (this: unknown, ...args: unknown[]) {
      signUpReceiver = this;
      return Reflect.apply(originalSignUp, this, args);
    };
    const originalLookup = options.database.operations.findApiKeyByHash;
    let lookupReceiver: unknown;
    options.database.operations.findApiKeyByHash = function (this: unknown, ...args: unknown[]) {
      lookupReceiver = this;
      return Reflect.apply(originalLookup, this, args);
    };

    const auth = serverModule.createAuthServer(options);
    const serviceMethods: Record<string, readonly string[]> = {
      users: ["signUp", "signIn", "signInWithOtp", "verifyOtp", "resetPasswordForEmail", "resetPassword", "resend", "updateUser"],
      sessions: ["refresh", "authorizeSession", "signOut", "revokeRefreshToken"],
      tokens: ["verifyAccessToken", "jwks"],
      authorization: ["getPermissions", "authorize"],
      oauth: ["listProviders", "authorize", "callback", "exchangeCode", "listIdentities", "unlinkIdentity"],
    };
    for (const [serviceName, methods] of Object.entries(serviceMethods)) {
      const service = options.services[serviceName];
      if (service === undefined) continue;
      for (const method of methods) {
        if (typeof service[method] === "function") service[method] = () => { throw new Error(`swapped ${serviceName}.${method}`); };
      }
    }
    for (const member of Object.keys(options.database)) {
      const value = options.database[member];
      if (value === null || typeof value !== "object") continue;
      for (const method of Object.keys(value)) {
        if (typeof value[method] === "function") value[method] = () => { throw new Error(`swapped database.${member}.${method}`); };
      }
    }

    const jsonRequest = (path: string, value: unknown) => request(path, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(value),
    });
    const responses: Array<[string, Promise<Response>, number]> = [
      ["signup", auth.handle(jsonRequest("/signup", { email: "user@example.com", password: "correct horse battery staple" })), 200],
      ["password", auth.handle(jsonRequest("/token?grant_type=password", { email: "user@example.com", password: "correct horse battery staple" })), 200],
      ["refresh", auth.handle(jsonRequest("/token?grant_type=refresh_token", { refresh_token: REFRESH_TOKEN })), 200],
      ["otp", auth.handle(jsonRequest("/otp", { email: "user@example.com" })), 200],
      ["verify", auth.handle(jsonRequest("/verify", { email: "user@example.com", token: "123456", type: "email_otp" })), 200],
      ["recover", auth.handle(jsonRequest("/recover", { email: "user@example.com" })), 200],
      ["resetPassword", auth.handle(jsonRequest("/recover/verify", { email: "user@example.com", token: "recovery-token", password: "new correct horse battery staple" })), 200],
      ["resend", auth.handle(jsonRequest("/resend", { type: "signup", email: "user@example.com" })), 200],
      ["providers", auth.handle(request("/providers")), 200],
      ["authorize", auth.handle(request("/authorize?provider=google&code_challenge=client-challenge&redirect_to=https%3A%2F%2Fproject.example.com%2Fauth%2Fcallback")), 200],
      ["callback", auth.handle(request("/callback/google?code=provider-code&state=state")), 303],
      ["exchange", auth.handle(jsonRequest("/exchange", { code: "callback-code", code_verifier: "verifier" })), 200],
      ["getUser", auth.handle(request("/user", { headers: { authorization: `Bearer ${ACCESS_TOKEN}` } })), 200],
      ["updateUser", auth.handle(request("/user", { method: "PUT", headers: { authorization: `Bearer ${ACCESS_TOKEN}`, "content-type": "application/json" }, body: JSON.stringify({ user_metadata: { display_name: "Updated" } }) })), 200],
      ["identities", auth.handle(request("/user/identities", { headers: { authorization: `Bearer ${ACCESS_TOKEN}` } })), 200],
      ["unlinkIdentity", auth.handle(request(`/user/identities/${IDENTITY_ID}`, { method: "DELETE", headers: { authorization: `Bearer ${ACCESS_TOKEN}` } })), 200],
      ["permissions", auth.handle(request("/user/permissions", { headers: { authorization: `Bearer ${ACCESS_TOKEN}` } })), 200],
      ["signOut", auth.handle(request("/logout", { method: "POST", headers: { authorization: `Bearer ${ACCESS_TOKEN}`, "content-type": "application/json" }, body: "{}" })), 200],
      ["revokeRefreshToken", auth.handle(jsonRequest("/logout", { refresh_token: REFRESH_TOKEN })), 200],
      ["jwks", auth.handle(request("/.well-known/jwks.json")), 200],
    ];
    for (const [name, responsePromise, status] of responses) {
      const response = await responsePromise;
      expect(response.status, name).toBe(status);
    }
    const subject = await auth.authorize(request("/not-a-route", { headers: { authorization: `Bearer ${ACCESS_TOKEN}` } }), { all: ["invoice.read"] });
    expect(subject).toMatchObject({ user_id: USER_ID });
    expect(signUpReceiver).toBe(options.services.users);
    expect(lookupReceiver).toBe(options.database.operations);
    expect(calls.map(({ name }) => name)).toEqual(expect.arrayContaining(["signUp", "signIn", "signInWithOtp", "verifyOtp", "resetPasswordForEmail", "resetPassword", "resend", "refresh", "updateUser", "signOut", "revokeRefreshToken", "authorize", "callback", "exchangeCode", "unlinkIdentity"]));
  });

  it("rejects accessor and thenable service values without invoking them", () => {
    const accessorOptions = makeOptions([]) as any;
    let getterCalls = 0;
    Object.defineProperty(accessorOptions.services.users, "signUp", {
      configurable: true,
      enumerable: true,
      get: () => { getterCalls += 1; throw new Error("service getter executed"); },
    });
    expect(() => serverModule.createAuthServer(accessorOptions)).toThrow();
    expect(getterCalls).toBe(0);

    const thenableOptions = makeOptions([]) as any;
    let thenGetterCalls = 0;
    Object.defineProperty(thenableOptions.services.users, "then", {
      configurable: true,
      enumerable: true,
      get: () => { thenGetterCalls += 1; throw new Error("then getter executed"); },
    });
    expect(() => serverModule.createAuthServer(thenableOptions)).toThrow();
    expect(thenGetterCalls).toBe(0);

    const callbackThenableOptions = makeOptions([]) as any;
    let callbackThenCalls = 0;
    Object.defineProperty(callbackThenableOptions.services.users.signUp, "then", {
      configurable: true,
      value: () => { callbackThenCalls += 1; },
    });
    expect(() => serverModule.createAuthServer(callbackThenableOptions)).toThrow(AuthConfigurationError);
    expect(callbackThenCalls).toBe(0);
  });

  it("rejects top-level and service-composition thenables before schema access", () => {
    const ownTopLevel = makeOptions([]) as any;
    Object.defineProperty(ownTopLevel, "then", {
      configurable: true,
      value: () => { throw new Error("top-level then sentinel"); },
    });
    expect(() => serverModule.createAuthServer(ownTopLevel)).toThrow(AuthConfigurationError);

    const accessorTopLevel = makeOptions([]) as any;
    let topLevelGetterCalls = 0;
    Object.defineProperty(accessorTopLevel, "then", {
      configurable: true,
      get: () => {
        topLevelGetterCalls += 1;
        throw new Error("top-level then getter sentinel");
      },
    });
    let accessorThrown: unknown;
    try {
      serverModule.createAuthServer(accessorTopLevel);
    } catch (error) {
      accessorThrown = error;
    }
    expect(accessorThrown).toBeInstanceOf(AuthConfigurationError);
    expect(String(accessorThrown)).not.toContain("getter sentinel");
    expect(topLevelGetterCalls).toBe(0);

    const ownServices = makeOptions([]) as any;
    Object.defineProperty(ownServices.services, "then", {
      configurable: true,
      value: () => { throw new Error("services then sentinel"); },
    });
    expect(() => serverModule.createAuthServer(ownServices)).toThrow(AuthConfigurationError);

    const accessorServices = makeOptions([]) as any;
    let servicesGetterCalls = 0;
    Object.defineProperty(accessorServices.services, "then", {
      configurable: true,
      get: () => {
        servicesGetterCalls += 1;
        throw new Error("services then getter sentinel");
      },
    });
    let servicesThrown: unknown;
    try {
      serverModule.createAuthServer(accessorServices);
    } catch (error) {
      servicesThrown = error;
    }
    expect(servicesThrown).toBeInstanceOf(AuthConfigurationError);
    expect(String(servicesThrown)).not.toContain("services then getter sentinel");
    expect(servicesGetterCalls).toBe(0);

    const originalThen = Object.getOwnPropertyDescriptor(Object.prototype, "then");
    try {
      Object.defineProperty(Object.prototype, "then", {
        configurable: true,
        value: () => { throw new Error("Object.prototype then sentinel"); },
      });
      expect(() => serverModule.createAuthServer(makeOptions([]))).toThrow(AuthConfigurationError);
      const inheritedServices = makeOptions([]) as any;
      Object.setPrototypeOf(inheritedServices.services, Object.prototype);
      expect(() => serverModule.createAuthServer(inheritedServices)).toThrow(AuthConfigurationError);
    } finally {
      if (originalThen === undefined) Reflect.deleteProperty(Object.prototype, "then");
      else Object.defineProperty(Object.prototype, "then", originalThen);
    }
  });

  it("validates AuthServer runtime origin and path before assignment", () => {
    const options = makeOptions([]) as any;
    const runtime = (overrides: Record<string, unknown> = {}) => ({
      config: options,
      repository: options.database,
      services: options.services,
      apiKeyHashKey: TOKEN_HASH_KEY,
      baseOrigin: "https://project.example.com",
      basePath: "/auth/v1",
      allowedOrigins: ["https://project.example.com"],
      allowedRedirects: [CALLBACK],
      ...overrides,
    });

    for (const value of [{}, 42, "not an origin", "https://project.example.com/"]) {
      expect(() => new AuthServer(runtime({ baseOrigin: value }) as never)).toThrow(AuthConfigurationError);
    }
    for (const value of [{}, 42, "auth/v1", "/auth/v1/"]) {
      expect(() => new AuthServer(runtime({ basePath: value }) as never)).toThrow(AuthConfigurationError);
    }

    const revoked = Proxy.revocable({}, {});
    revoked.revoke();
    expect(() => new AuthServer(runtime({ baseOrigin: revoked.proxy }) as never)).toThrow(AuthConfigurationError);

    const thenable = Object.create(null);
    Object.defineProperty(thenable, "then", { configurable: true, value: () => undefined });
    expect(() => new AuthServer(runtime({ baseOrigin: thenable }) as never)).toThrow(AuthConfigurationError);

    expect(() => new AuthServer(runtime() as never)).not.toThrow();
  });

  it("redacts hostile factory collections and survives polluted intrinsics", () => {
    const revokedRedirects = Proxy.revocable([CALLBACK], {});
    revokedRedirects.revoke();
    const revokedOptions = makeOptions([]) as any;
    revokedOptions.redirects.allowed = revokedRedirects.proxy;
    let revokedThrown: unknown;
    try {
      serverModule.createAuthServer(revokedOptions);
    } catch (error) {
      revokedThrown = error;
    }
    expect(revokedThrown).toBeInstanceOf(AuthConfigurationError);
    expect(String(revokedThrown)).not.toContain("TypeError");

    const ownKeysOptions = makeOptions([]) as any;
    ownKeysOptions.redirects.allowed = new Proxy([CALLBACK], {
      ownKeys: () => { throw new Error("factory ownKeys sentinel"); },
    });
    let ownKeysThrown: unknown;
    try {
      serverModule.createAuthServer(ownKeysOptions);
    } catch (error) {
      ownKeysThrown = error;
    }
    expect(ownKeysThrown).toBeInstanceOf(AuthConfigurationError);
    expect(String(ownKeysThrown)).not.toContain("factory ownKeys sentinel");

    const originalSome = Array.prototype.some;
    const originalPush = Array.prototype.push;
    const originalEntries = Object.entries;
    try {
      Array.prototype.some = (() => { throw new Error("factory some sentinel"); }) as typeof Array.prototype.some;
      expect(() => serverModule.createAuthServer(makeOptions([]))).not.toThrow();
      Array.prototype.some = originalSome;
      Array.prototype.push = (() => { throw new Error("factory push sentinel"); }) as typeof Array.prototype.push;
      expect(() => serverModule.createAuthServer(makeOptions([]))).not.toThrow();
      Array.prototype.push = originalPush;
      Object.entries = (() => { throw new Error("factory entries sentinel"); }) as typeof Object.entries;
      expect(() => serverModule.createAuthServer(makeOptions([]))).not.toThrow();
    } finally {
      Array.prototype.some = originalSome;
      Array.prototype.push = originalPush;
      Object.entries = originalEntries;
    }
  });

  it("uses captured typed-array and nested collection intrinsics during server construction", () => {
    const cases: readonly [string, (operation: () => void) => void, (options: any) => void][] = [
      ["Uint8Array", (operation) => {
        const descriptor = Object.getOwnPropertyDescriptor(globalThis, "Uint8Array");
        try {
          Object.defineProperty(globalThis, "Uint8Array", {
            configurable: true,
            enumerable: descriptor?.enumerable ?? false,
            writable: true,
            value: {},
          });
          operation();
        } finally {
          if (descriptor === undefined) Reflect.deleteProperty(globalThis, "Uint8Array");
          else Object.defineProperty(globalThis, "Uint8Array", descriptor);
        }
      }, (options) => {
        options.signingKeys.keys.test = new TextEncoder().encode(options.signingKeys.keys.test);
      }],
      ["Array index setter", (operation) => {
        const descriptor = Object.getOwnPropertyDescriptor(Array.prototype, "0");
        try {
          Object.defineProperty(Array.prototype, "0", {
            configurable: true,
            set: () => { throw new Error("server-array-index-sentinel"); },
          });
          operation();
        } finally {
          if (descriptor === undefined) Reflect.deleteProperty(Array.prototype, "0");
          else Object.defineProperty(Array.prototype, "0", descriptor);
        }
      }, (options) => {
        options.signingKeys.audience = ["project"];
      }],
      ["Number safe integer", (operation) => {
        const descriptor = Object.getOwnPropertyDescriptor(Number, "isSafeInteger");
        try {
          Object.defineProperty(Number, "isSafeInteger", {
            configurable: true,
            enumerable: false,
            writable: true,
            value: () => { throw new Error("server-number-sentinel"); },
          });
          operation();
        } finally {
          if (descriptor === undefined) Reflect.deleteProperty(Number, "isSafeInteger");
          else Object.defineProperty(Number, "isSafeInteger", descriptor);
        }
      }, (options) => {
        options.signingKeys.audience = ["project"];
      }],
      ["String conversion", (operation) => {
        const descriptor = Object.getOwnPropertyDescriptor(globalThis, "String");
        try {
          Object.defineProperty(globalThis, "String", {
            configurable: true,
            enumerable: descriptor?.enumerable ?? false,
            writable: true,
            value: () => { throw new Error("server-string-sentinel"); },
          });
          operation();
        } finally {
          if (descriptor === undefined) Reflect.deleteProperty(globalThis, "String");
          else Object.defineProperty(globalThis, "String", descriptor);
        }
      }, (options) => {
        options.signingKeys.audience = ["project"];
      }],
    ];
    for (const [label, install, prepare] of cases) {
      const options = makeOptions([]) as any;
      prepare(options);
      let thrown: unknown;
      try {
        install(() => serverModule.createAuthServer(options));
      } catch (error) {
        thrown = error;
      }
      if (label === "Uint8Array") {
        expect(thrown, label).toBeUndefined();
      } else {
        expect(thrown, label).toBeInstanceOf(AuthConfigurationError);
        expect(String(thrown), label).not.toMatch(/sentinel/i);
      }
    }
  });

  it("captures configured repository, mailer, and limiter callbacks before schema inspection", () => {
    const targets: readonly [string, (options: any, getter: () => unknown) => void][] = [
      ["repository", (options, getter) => Object.defineProperty(options.database.users, "findById", { configurable: true, enumerable: true, get: getter })],
      ["mailer", (options, getter) => Object.defineProperty(options.email, "send", { configurable: true, enumerable: true, get: getter })],
      ["rateLimiter", (options, getter) => {
        options.rateLimiter = {};
        Object.defineProperty(options.rateLimiter, "consume", { configurable: true, enumerable: true, get: getter });
      }],
    ];
    for (const [label, install] of targets) {
      const options = makeOptions([]) as any;
      let getterCalls = 0;
      install(options, () => {
        getterCalls += 1;
        throw new Error(`${label}-sentinel`);
      });
      let thrown: unknown;
      try {
        serverModule.createAuthServer(options);
      } catch (error) {
        thrown = error;
      }
      expect(getterCalls, label).toBe(0);
      expect(String(thrown), label).not.toContain(`${label}-sentinel`);
    }
  });

  it("snapshots nested security configuration before schema inspection", () => {
    const targets: readonly [string, (options: any, getter: () => unknown) => void][] = [
      ["signingKeys aggregate", (options, getter) => {
        Object.defineProperty(options.signingKeys, "activeKeyId", { configurable: true, enumerable: true, get: getter });
      }],
      ["inherited signingKeys field", (options, getter) => {
        const prototype = Object.create(Object.getPrototypeOf(options.signingKeys));
        Object.defineProperty(prototype, "activeKeyId", { configurable: true, get: getter });
        delete options.signingKeys.activeKeyId;
        Object.setPrototypeOf(options.signingKeys, prototype);
      }],
      ["signing key map", (options, getter) => {
        Object.defineProperty(options.signingKeys.keys, "test", { configurable: true, enumerable: true, get: getter });
      }],
      ["signing key material record", (options, getter) => {
        const material = { d: "key-material" };
        Object.defineProperty(material, "x", { configurable: true, enumerable: true, get: getter });
        options.signingKeys.keys.test = material;
      }],
      ["signing key map thenable", (options, getter) => {
        Object.defineProperty(options.signingKeys.keys, "then", { configurable: true, enumerable: true, get: getter });
      }],
      ["secrets tokenHashKey", (options, getter) => {
        Object.defineProperty(options.secrets, "tokenHashKey", { configurable: true, enumerable: true, get: getter });
      }],
      ["secrets aggregate thenable", (options, getter) => {
        Object.defineProperty(options.secrets, "then", { configurable: true, enumerable: true, get: getter });
      }],
      ["redirect array entry", (options, getter) => {
        Object.defineProperty(options.redirects.allowed, "0", { configurable: true, enumerable: true, get: getter });
      }],
      ["authorization array entry", (options, getter) => {
        options.authorization.defaultRoleKeys = ["role.user"];
        Object.defineProperty(options.authorization.defaultRoleKeys, "0", { configurable: true, enumerable: true, get: getter });
      }],
      ["OAuth client secret", (options, getter) => {
        options.oauth = { google: { clientId: "google-client", clientSecret: "secret" } };
        Object.defineProperty(options.oauth.google, "clientSecret", { configurable: true, enumerable: true, get: getter });
      }],
    ];
    for (const [label, install] of targets) {
      const options = makeOptions([]) as any;
      let getterCalls = 0;
      install(options, () => {
        getterCalls += 1;
        throw new Error(`${label}-sentinel`);
      });
      let thrown: unknown;
      try {
        serverModule.createAuthServer(options);
      } catch (error) {
        thrown = error;
      }
      expect(thrown, label).toBeInstanceOf(Error);
      expect(getterCalls, label).toBe(0);
      expect(String(thrown), label).not.toContain("sentinel");
    }

    const options = makeOptions([]) as any;
    const auth = serverModule.createAuthServer(options);
    options.signingKeys.activeKeyId = "mutated";
    options.signingKeys.keys.test = generatedSigningKey();
    return auth.handle(request("/.well-known/jwks.json")).then(async (response) => {
      expect(response.status).toBe(200);
      expect((await body(response)).data.keys[0].kid).toBe("test");
    });
  });

  it("rejects expired and revoked API keys before dispatch", async () => {
    const expiredOptions = makeOptions([]) as any;
    expiredOptions.database.operations.findApiKeyByHash = async () => ({
      ...apiKeyRecord(PUBLISHABLE_KEY),
      expires_at: new Date(0),
    });
    const expired = await serverModule.createAuthServer(expiredOptions).handle(request("/providers"));
    expect(expired.status).toBe(401);

    const revokedOptions = makeOptions([]) as any;
    revokedOptions.database.operations.findApiKeyByHash = async () => ({
      ...apiKeyRecord(PUBLISHABLE_KEY),
      revoked_at: new Date(),
    });
    const revoked = await serverModule.createAuthServer(revokedOptions).handle(request("/providers"));
    expect(revoked.status).toBe(401);
  });

  it("rejects browser-marked secret keys without Origin and preserves server use", async () => {
    const calls: Array<{ readonly name: string; readonly input: unknown }> = [];
    const auth = serverModule.createAuthServer(makeOptions(calls));
    const signup = JSON.stringify({ email: "user@example.com", password: "correct horse battery staple" });
    const browserSignals = [
      { "sec-fetch-site": "cross-site", "sec-fetch-mode": "cors", "sec-fetch-dest": "empty" },
      { "sec-fetch-site": "same-origin" },
      { "sec-fetch-site": "same-site" },
      { "sec-fetch-mode": "navigate", "sec-fetch-dest": "document", "sec-fetch-user": "?1" },
      { "sec-fetch-site": "none", "sec-fetch-mode": "navigate", "sec-fetch-dest": "document" },
    ];
    for (const headers of browserSignals) {
      const response = await auth.handle(request("/signup", {
        method: "POST",
        headers: { apikey: SECRET_KEY, "content-type": "application/json", ...headers },
        body: signup,
      }));
      expect(response.status, JSON.stringify(headers)).toBe(403);
    }
    expect(calls).toHaveLength(0);

    const serverResponse = await auth.handle(request("/signup", {
      method: "POST",
      headers: { apikey: SECRET_KEY, "content-type": "application/json" },
      body: signup,
    }));
    expect(serverResponse.status).toBe(200);
    expect(calls).toHaveLength(1);

    const duplicate = await auth.handle(request("/signup", {
      method: "POST",
      headers: { apikey: SECRET_KEY, "content-type": "application/json", "sec-fetch-site": "cross-site, same-origin" },
      body: signup,
    }));
    expect(duplicate.status).toBe(403);
    expect(calls).toHaveLength(1);

    const malformed = await auth.handle(request("/signup", {
      method: "POST",
      headers: { apikey: SECRET_KEY, "content-type": "application/json", "sec-fetch-site": "not-a-fetch-site" },
      body: signup,
    }));
    expect(malformed.status).toBe(403);
    expect(calls).toHaveLength(1);

    const hostileRequest = Object.create(null) as Request;
    let metadataGetterCalls = 0;
    Object.defineProperty(hostileRequest, "headers", {
      get: () => { metadataGetterCalls += 1; throw new Error("headers getter executed"); },
    });
    const hostileResponse = await auth.handle(hostileRequest);
    expect(hostileResponse.status).toBe(400);
    expect(metadataGetterCalls).toBe(0);
  });

  it("fails closed for expired, revoked, and wrong-session access tokens", async () => {
    const expiredOptions = makeOptions([]) as any;
    expiredOptions.services.tokens.verifyAccessToken = async () => success(accessClaims({ exp: 1_700_000_001 }));
    const expired = await serverModule.createAuthServer(expiredOptions).handle(request("/user", {
      headers: { authorization: `Bearer ${ACCESS_TOKEN}` },
    }));
    expect(expired.status).toBe(401);

    const revokedOptions = makeOptions([]) as any;
    revokedOptions.services.sessions.authorizeSession = async () => ({
      data: null,
      error: { code: "unauthorized", status: 401, message: "revoked session" },
    });
    const revoked = await serverModule.createAuthServer(revokedOptions).handle(request("/user", {
      headers: { authorization: `Bearer ${ACCESS_TOKEN}` },
    }));
    expect(revoked.status).toBe(401);

    const wrongSessionOptions = makeOptions([]) as any;
    wrongSessionOptions.services.sessions.authorizeSession = async () => success({
      session: session(),
      session_id: "00000000-0000-4000-8000-000000000999",
      user_id: USER_ID,
      user: user(),
    });
    const wrongSession = await serverModule.createAuthServer(wrongSessionOptions).handle(request("/user", {
      headers: { authorization: `Bearer ${ACCESS_TOKEN}` },
    }));
    expect(wrongSession.status).toBe(401);
  });

  it("rejects malformed adapter records and shields response settlement", async () => {
    const accessorOptions = makeOptions([]) as any;
    const malformed = success({ user: user(), session: null });
    let dataReads = 0;
    Object.defineProperty(malformed, "data", {
      configurable: false,
      enumerable: true,
      get: () => { dataReads += 1; throw new Error("adapter getter executed"); },
    });
    accessorOptions.services.users.signUp = () => malformed;
    const accessorResponse = await serverModule.createAuthServer(accessorOptions).handle(request("/signup", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: "user@example.com", password: "correct horse battery staple" }),
    }));
    expect(accessorResponse.status).toBe(500);
    expect(dataReads).toBe(0);

    const pollutedOptions = makeOptions([]) as any;
    const pollutedProvider = Object.create({ name: "google" });
    Object.defineProperties(pollutedProvider, {
      scopes: { configurable: true, enumerable: true, value: [], writable: false },
      capabilities: { configurable: true, enumerable: true, value: { authorization_code: true, pkce: true, identity_linking: true }, writable: false },
    });
    pollutedOptions.services.oauth.listProviders = () => [pollutedProvider];
    const pollutedResponse = await serverModule.createAuthServer(pollutedOptions).handle(request("/providers"));
    expect(pollutedResponse.status).toBe(500);

    const response = await serverModule.createAuthServer(makeOptions([])).handle(request("/providers"));
    const descriptor = Object.getOwnPropertyDescriptor(response, "then");
    expect(descriptor).toMatchObject({ configurable: false, enumerable: false, writable: false, value: undefined });
  });

  it("authorizes with a fresh immutable request-local subject", async () => {
    const contexts: unknown[] = [];
    const options = makeOptions([]) as any;
    options.services.authorization.authorize = async (_subject: unknown, _requirement: unknown, context: unknown) => {
      contexts.push(context);
      return success({ user_id: USER_ID });
    };
    const auth = serverModule.createAuthServer(options);
    const subject = await auth.authorize(request("/not-a-route", { headers: { authorization: `Bearer ${ACCESS_TOKEN}`, "x-request-id": "task9-authorize" } }), { all: ["invoice.read"] });
    expect(subject).toEqual({ user_id: USER_ID, request_id: "task9-authorize" });
    expect(Object.isFrozen(subject)).toBe(true);
    const second = await auth.authorize(request("/not-a-route", { headers: { authorization: `Bearer ${ACCESS_TOKEN}`, "x-request-id": "task9-second" } }), { all: ["invoice.read"] });
    expect(second).toEqual({ user_id: USER_ID, request_id: "task9-second" });
    expect(contexts).toHaveLength(2);
    expect(contexts[0]).not.toBe(contexts[1]);
    expect((contexts[0] as any).subject.request_id).toBe("task9-authorize");
    expect((contexts[1] as any).subject.request_id).toBe("task9-second");
    await expect(auth.authorize(new Request(`${BASE_URL}/not-a-route`), { all: ["invoice.read"] })).rejects.toMatchObject({ code: "unauthorized", status: 401 });
  });

  it("generates deterministic OpenAPI with route parity and all security schemes", () => {
    const first = serverModule.generateOpenApiDocument();
    const second = serverModule.generateOpenApiDocument();
    expect(JSON.stringify(first)).toBe(JSON.stringify(second));
    const paths = first.paths as Record<string, unknown>;
    expect(Object.keys(paths)).toEqual(expect.arrayContaining([
      "/signup", "/token", "/otp", "/verify", "/recover", "/recover/verify", "/resend", "/providers", "/authorize",
      "/callback/{provider}", "/exchange", "/user", "/user/identities", "/user/identities/{id}",
      "/user/permissions", "/logout", "/.well-known/jwks.json",
    ]));
    const schemes = (first.components as Record<string, any>).securitySchemes;
    expect(schemes).toMatchObject({ publishableKey: expect.anything(), secretKey: expect.anything(), bearerAuth: expect.anything() });
  });
});
