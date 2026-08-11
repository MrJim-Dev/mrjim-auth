import { createHmac, generateKeyPairSync } from "node:crypto";
import { beforeAll, describe, expect, it } from "vitest";

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
          if (Buffer.from(hash).equals(Buffer.from(apiKeyHash(raw)))) return record;
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

  it("covers OTP, verification, recovery, and resend route contracts", async () => {
    const calls: Array<{ readonly name: string; readonly input: unknown }> = [];
    const auth = serverModule.createAuthServer(makeOptions(calls));
    const cases: readonly [string, unknown, string][] = [
      ["/otp", { email: "USER@example.com", options: { type: "email_otp", redirect_to: CALLBACK } }, "signInWithOtp"],
      ["/verify", { email: "USER@example.com", token: "123456", type: "email_otp", redirect_to: CALLBACK }, "verifyOtp"],
      ["/recover", { email: "USER@example.com", redirect_to: CALLBACK }, "resetPasswordForEmail"],
      ["/resend", { type: "signup", email: "USER@example.com", options: { redirect_to: CALLBACK } }, "resend"],
    ];
    for (const [path, value, name] of cases) {
      const response = await auth.handle(request(path, {
        method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(value),
      }));
      expect(response.status, path).toBe(200);
      expect(calls.at(-1)?.name, path).toBe(name);
    }
  });

  it("covers providers, OAuth authorize/callback/exchange, and JWKS", async () => {
    const calls: Array<{ readonly name: string; readonly input: unknown }> = [];
    const auth = serverModule.createAuthServer(makeOptions(calls));
    expect((await body(await auth.handle(request("/providers")))).data.providers).toHaveLength(1);
    expect((await body(await auth.handle(request("/authorize?provider=google")))).data).toMatchObject({ provider: "google", code_verifier: "verifier" });
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

  it("requires a strict API key and bearer session for current-user routes", async () => {
    const auth = serverModule.createAuthServer(makeOptions([]));
    const missingKey = await auth.handle(new Request(`${BASE_URL}/user`));
    expect(missingKey.status).toBe(401);
    expect((await body(missingKey)).error).toMatchObject({ code: "unauthorized", request_id: expect.any(String) });
    const invalidBearer = await auth.handle(request("/user", { headers: { authorization: "Bearer one two" } }));
    expect(invalidBearer.status).toBe(401);
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
      users: ["signUp", "signIn", "signInWithOtp", "verifyOtp", "resetPasswordForEmail", "resend", "updateUser"],
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
      ["resend", auth.handle(jsonRequest("/resend", { type: "signup", email: "user@example.com" })), 200],
      ["providers", auth.handle(request("/providers")), 200],
      ["authorize", auth.handle(request("/authorize?provider=google&redirect_to=https%3A%2F%2Fproject.example.com%2Fauth%2Fcallback")), 200],
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
    expect(calls.map(({ name }) => name)).toEqual(expect.arrayContaining(["signUp", "signIn", "signInWithOtp", "verifyOtp", "resetPasswordForEmail", "resend", "refresh", "updateUser", "signOut", "revokeRefreshToken", "authorize", "callback", "exchangeCode", "unlinkIdentity"]));
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
    expect(duplicate.status).toBe(400);
    expect(calls).toHaveLength(1);

    const malformed = await auth.handle(request("/signup", {
      method: "POST",
      headers: { apikey: SECRET_KEY, "content-type": "application/json", "sec-fetch-site": "not-a-fetch-site" },
      body: signup,
    }));
    expect(malformed.status).toBe(400);
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
      "/signup", "/token", "/otp", "/verify", "/recover", "/resend", "/providers", "/authorize",
      "/callback/{provider}", "/exchange", "/user", "/user/identities", "/user/identities/{id}",
      "/user/permissions", "/logout", "/.well-known/jwks.json",
    ]));
    const schemes = (first.components as Record<string, any>).securitySchemes;
    expect(schemes).toMatchObject({ publishableKey: expect.anything(), secretKey: expect.anything(), bearerAuth: expect.anything() });
  });
});
