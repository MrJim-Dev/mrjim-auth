import { describe, expect, it, vi } from "vitest";
import { createClient, type PasswordSignInInput, type SignUpInput } from "../../src/index.js";
import {
  AuthApiError,
  AuthConfigurationError,
  AuthProgrammingError,
} from "../../src/shared/errors.js";
import type { Identity, Session, SupportedStorage, User } from "../../src/shared/types.js";

const BASE_URL = "https://project.example.com/auth/v1";
const API_KEY = "publishable-key";
const ACCESS_TOKEN = "access-token-sentinel";
const REFRESH_TOKEN = "refresh-token-sentinel";
const USER_ID = "11111111-1111-4111-8111-111111111111";
const IDENTITY_ID = "22222222-2222-4222-8222-222222222222";
const REDIRECT = "https://project.example.com/auth/callback";

const user: User = {
  id: USER_ID as User["id"],
  email: "user@example.com",
  phone: null,
  email_confirmed_at: "2026-08-12T00:00:00.000Z",
  phone_confirmed_at: null,
  confirmed_at: "2026-08-12T00:00:00.000Z",
  last_sign_in_at: "2026-08-12T00:00:00.000Z",
  banned_until: null,
  user_metadata: { display_name: "User" },
  app_metadata: {},
  created_at: "2026-08-12T00:00:00.000Z",
  updated_at: "2026-08-12T00:00:00.000Z",
  deleted_at: null,
};

function session(overrides: Partial<Session> = {}): Session {
  return {
    access_token: ACCESS_TOKEN,
    refresh_token: REFRESH_TOKEN,
    token_type: "bearer",
    expires_in: 900,
    expires_at: Math.floor(Date.now() / 1000) + 900,
    user,
    ...overrides,
  };
}

const identity = {
  id: IDENTITY_ID,
  user_id: USER_ID,
  provider: "google",
  provider_subject: "google-subject",
  email: "user@example.com",
  identity_data: { sub: "google-subject", email: "user@example.com" },
  created_at: "2026-08-12T00:00:00.000Z",
  updated_at: "2026-08-12T00:00:00.000Z",
} as Identity;

function success(data: unknown): Response {
  return new Response(JSON.stringify({ data, error: null }), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

function failure(
  status: number,
  error: { code: string; message: string; request_id?: string },
): Response {
  return new Response(JSON.stringify({ error }), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function createStorage(): SupportedStorage & { readonly values: Map<string, string> } {
  const values = new Map<string, string>();
  return {
    values,
    getItem: (key) => values.get(key) ?? null,
    setItem: (key, value) => {
      values.set(key, value);
    },
    removeItem: (key) => {
      values.delete(key);
    },
  };
}

function createFetch(responses: readonly Response[] | (() => Response | Promise<Response>)) {
  const calls: Array<{ readonly input: RequestInfo | URL; readonly init?: RequestInit }> = [];
  let index = 0;
  const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    calls.push(init === undefined ? { input } : { input, init });
    if (typeof responses === "function") return await responses();
    const response = responses[index];
    index += 1;
    if (response === undefined) throw new Error("test response queue exhausted");
    return response;
  });
  return { fetcher, calls };
}

function createTestClient(
  fetcher: typeof fetch,
  options: Record<string, unknown> = {},
) {
  return createClient(BASE_URL, API_KEY, {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
      detectSessionInUrl: false,
      skipAutoInitialize: true,
      ...(options.auth as Record<string, unknown> | undefined),
    },
    global: { fetch: fetcher, ...(options.global as Record<string, unknown> | undefined) },
  });
}

function requestDetails(call: { readonly input: RequestInfo | URL; readonly init?: RequestInit }) {
  const request = new Request(call.input, call.init);
  return {
    url: request.url,
    method: request.method,
    headers: Object.fromEntries(request.headers.entries()),
    body: request.body === null ? null : undefined,
    request,
  };
}

async function requestJson(request: Request): Promise<unknown> {
  return await request.clone().json();
}

async function establishSession(
  fetcher: typeof fetch,
  clientOptions: Record<string, unknown> = {},
) {
  const client = createTestClient(fetcher, clientOptions);
  const result = await client.auth.setSession(session());
  expect(result.error).toBeNull();
  return client;
}

describe("browser-safe public auth client", () => {
  it("exposes an immutable auth namespace with the complete Task 10 method shape", () => {
    const { fetcher } = createFetch([success({ user: null, session: null })]);
    const client = createTestClient(fetcher);

    expect(Object.keys(client)).toEqual(["auth"]);
    expect(Object.isFrozen(client)).toBe(true);
    expect(Object.isFrozen(client.auth)).toBe(true);
    expect(Object.keys(client.auth).sort()).toEqual([
      "dispose",
      "exchangeCodeForSession",
      "getPermissions",
      "getSession",
      "getUser",
      "getUserIdentities",
      "linkIdentity",
      "onAuthStateChange",
      "refreshSession",
      "resend",
      "resetPassword",
      "resetPasswordForEmail",
      "setSession",
      "signInWithOAuth",
      "signInWithOtp",
      "signInWithPassword",
      "signOut",
      "signUp",
      "startAutoRefresh",
      "stopAutoRefresh",
      "unlinkIdentity",
      "updateUser",
      "verifyOtp",
    ].sort());
  });

  it("validates and canonicalizes the base URL synchronously", () => {
    const { fetcher } = createFetch([]);
    expect(() => createClient("https://user:password@example.com/auth/v1", API_KEY, { global: { fetch: fetcher } })).toThrow(AuthConfigurationError);
    expect(() => createClient("https://example.com/auth/v1?token=secret", API_KEY, { global: { fetch: fetcher } })).toThrow(AuthConfigurationError);
    expect(() => createClient("https://example.com/auth//v1", API_KEY, { global: { fetch: fetcher } })).toThrow(AuthConfigurationError);
    expect(() => createClient("https://example.com/auth/../v1", API_KEY, { global: { fetch: fetcher } })).toThrow(AuthConfigurationError);
    expect(() => createClient("https://example.com/auth/%2e%2e/v1", API_KEY, { global: { fetch: fetcher } })).toThrow(AuthConfigurationError);
    expect(() => createClient("ftp://example.com/auth/v1", API_KEY, { global: { fetch: fetcher } })).toThrow(AuthConfigurationError);
    expect(() => createClient("https://example.com/auth/v1", { toString: () => API_KEY } as unknown as string, { global: { fetch: fetcher } })).toThrow(AuthConfigurationError);
  });

  it("maps signup to the approved wire contract and preserves nested result shape", async () => {
    const { fetcher, calls } = createFetch([success({ user, session: null })]);
    const client = createTestClient(fetcher);
    const result = await client.auth.signUp({
      email: "user@example.com",
      password: "correct horse battery staple",
      options: { redirectTo: REDIRECT, data: { display_name: "User" } },
    });

    expect(result).toEqual({ data: { user, session: null }, error: null });
    const request = requestDetails(calls[0]!);
    expect(request.url).toBe(`${BASE_URL}/signup`);
    expect(request.method).toBe("POST");
    expect(request.headers).toMatchObject({ apikey: API_KEY, "content-type": "application/json" });
    expect(await requestJson(request.request)).toEqual({
      email: "user@example.com",
      password: "correct horse battery staple",
      options: { redirect_to: REDIRECT, data: { display_name: "User" } },
    });
    expect(request.headers.authorization).toBeUndefined();
  });

  it("maps password sign-in to the password token grant without bearer authorization", async () => {
    const { fetcher, calls } = createFetch([success(session())]);
    const client = createTestClient(fetcher);
    const result = await client.auth.signInWithPassword({ email: "user@example.com", password: "correct horse battery staple" });

    expect(result).toEqual({ data: { user, session: session() }, error: null });
    const request = requestDetails(calls[0]!);
    expect(request.url).toBe(`${BASE_URL}/token?grant_type=password`);
    expect(request.method).toBe("POST");
    expect(await requestJson(request.request)).toEqual({ email: "user@example.com", password: "correct horse battery staple" });
    expect(request.headers.authorization).toBeUndefined();
  });

  it("maps OTP sign-in and verification options to snake_case wire fields", async () => {
    const otp = createFetch([success({ user: null, session: null }), success({ user, session: session() })]);
    const client = createTestClient(otp.fetcher);
    await expect(client.auth.signInWithOtp({ email: "user@example.com", options: { type: "emailOtp", redirectTo: REDIRECT } })).resolves.toEqual({ data: { user: null, session: null }, error: null });
    await expect(client.auth.verifyOtp({ email: "user@example.com", token: "123456", type: "emailOtp", options: { redirectTo: REDIRECT } })).resolves.toEqual({ data: { user, session: session() }, error: null });
    const otpRequest = requestDetails(otp.calls[0]!);
    expect(otpRequest.url).toBe(`${BASE_URL}/otp`);
    expect(await requestJson(otpRequest.request)).toEqual({ email: "user@example.com", options: { type: "email_otp", redirect_to: REDIRECT } });
    const verifyRequest = requestDetails(otp.calls[1]!);
    expect(verifyRequest.url).toBe(`${BASE_URL}/verify`);
    expect(await requestJson(verifyRequest.request)).toEqual({ email: "user@example.com", token: "123456", type: "email_otp", redirect_to: REDIRECT });
  });

  it("maps recovery and resend calls without reflecting secrets in the URL", async () => {
    const updatedUser = { ...user, updated_at: "2026-08-12T00:01:00.000Z" };
    const { fetcher, calls } = createFetch([success({ sent: true }), success({ user: updatedUser }), success({ sent: true })]);
    const client = createTestClient(fetcher);
    const events: string[] = [];
    client.auth.onAuthStateChange((event) => events.push(event));
    await expect(client.auth.resetPasswordForEmail("user@example.com", { redirectTo: REDIRECT })).resolves.toEqual({ data: { sent: true }, error: null });
    await expect((client.auth as unknown as { resetPassword(input: unknown): Promise<unknown> }).resetPassword({
      email: "user@example.com",
      token: "recovery-token-sentinel",
      password: "new correct horse battery staple",
      options: { redirectTo: REDIRECT },
    })).resolves.toEqual({ data: { user: updatedUser }, error: null });
    await expect(client.auth.resend({ type: "recovery", email: "user@example.com", options: { redirectTo: REDIRECT } })).resolves.toEqual({ data: { sent: true }, error: null });
    expect(requestDetails(calls[0]!).url).toBe(`${BASE_URL}/recover`);
    expect(await requestJson(requestDetails(calls[0]!).request)).toEqual({ email: "user@example.com", redirect_to: REDIRECT });
    expect(requestDetails(calls[1]!).url).toBe(`${BASE_URL}/recover/verify`);
    expect(await requestJson(requestDetails(calls[1]!).request)).toEqual({ email: "user@example.com", token: "recovery-token-sentinel", password: "new correct horse battery staple", redirect_to: REDIRECT });
    expect(requestDetails(calls[2]!).url).toBe(`${BASE_URL}/resend`);
    expect(await requestJson(requestDetails(calls[2]!).request)).toEqual({ type: "recovery", email: "user@example.com", options: { redirect_to: REDIRECT } });
    expect(requestDetails(calls[0]!).url).not.toContain("user@example.com");
    expect(requestDetails(calls[1]!).url).not.toContain("recovery-token-sentinel");
    expect(events).toEqual(["PASSWORD_RECOVERY"]);
  });

  it("rejects recovery proofs and replacement passwords outside service bounds before fetch", () => {
    const { fetcher, calls } = createFetch([]);
    const client = createTestClient(fetcher);
    expect(() => client.auth.resetPassword({ email: "user@example.com", token: "recovery-token", password: "short" })).toThrow(AuthProgrammingError);
    expect(() => client.auth.resetPassword({ email: "user@example.com", token: "x".repeat(129), password: "valid password" })).toThrow(AuthProgrammingError);
    expect(() => client.auth.resetPassword({ email: "user@example.com", token: "recovery-token", password: "😀".repeat(300) })).toThrow(AuthProgrammingError);
    expect(calls).toHaveLength(0);
  });

  it("refreshes a persisted session when automatic initialization is skipped", async () => {
    const storage = createStorage();
    storage.values.set("mrjim-auth:default", JSON.stringify({ version: 1, revision: 1, session: session() }));
    const rotated = session({ access_token: "rotated-access", refresh_token: "rotated-refresh" });
    const { fetcher, calls } = createFetch([success(rotated)]);
    const client = createTestClient(fetcher, { auth: { persistSession: true, storage, skipAutoInitialize: true } });
    await expect(client.auth.refreshSession()).resolves.toEqual({ data: { user, session: rotated }, error: null });
    expect(requestDetails(calls[0]!).url).toBe(`${BASE_URL}/token?grant_type=refresh_token`);
  });

  it("reads getSession locally while getUser always validates through the server", async () => {
    const storage = createStorage();
    const { fetcher, calls } = createFetch([success({ user }), success({ user })]);
    const client = createTestClient(fetcher, { auth: { persistSession: true, storage } });
    const setResult = await client.auth.setSession(session());
    expect(setResult.error).toBeNull();
    calls.length = 0;
    const local = await client.auth.getSession();
    expect(local).toEqual({ data: { session: session() }, error: null });
    expect(calls).toHaveLength(0);
    const remote = await client.auth.getUser();
    expect(remote).toEqual({ data: { user }, error: null });
    const request = requestDetails(calls[0]!);
    expect(request.url).toBe(`${BASE_URL}/user`);
    expect(request.method).toBe("GET");
    expect(request.headers.authorization).toBe(`Bearer ${ACCESS_TOKEN}`);
  });

  it("sets a valid session through the user endpoint and refreshes an expired pair", async () => {
    const future = session({ expires_at: Math.floor(Date.now() / 1000) + 900 });
    const valid = createFetch([success({ user })]);
    const validClient = createTestClient(valid.fetcher);
    await expect(validClient.auth.setSession(future)).resolves.toEqual({ data: { user, session: future }, error: null });
    expect(requestDetails(valid.calls[0]!).url).toBe(`${BASE_URL}/user`);

    const expired = session({ expires_at: Math.floor(Date.now() / 1000) - 1 });
    const rotated = session({ access_token: "rotated-access", refresh_token: "rotated-refresh" });
    const refresh = createFetch([success(rotated)]);
    const refreshClient = createTestClient(refresh.fetcher);
    await expect(refreshClient.auth.setSession(expired)).resolves.toEqual({ data: { user, session: rotated }, error: null });
    expect(requestDetails(refresh.calls[0]!).url).toBe(`${BASE_URL}/token?grant_type=refresh_token`);
    expect(await requestJson(requestDetails(refresh.calls[0]!).request)).toEqual({ refresh_token: REFRESH_TOKEN });
  });

  it("refreshes the latest stored session and preserves only the winning validated session", async () => {
    const storage = createStorage();
    const rotated = session({ access_token: "rotated-access", refresh_token: "rotated-refresh" });
    const { fetcher, calls } = createFetch([success({ user }), success(rotated)]);
    const client = createTestClient(fetcher, { auth: { persistSession: true, storage } });
    await client.auth.setSession(session());
    calls.length = 0;
    await expect(client.auth.refreshSession()).resolves.toEqual({ data: { user, session: rotated }, error: null });
    expect(requestDetails(calls[0]!).url).toBe(`${BASE_URL}/token?grant_type=refresh_token`);
    const persisted = JSON.stringify([...storage.values.values()]);
    expect(persisted).toContain("rotated-access");
    expect(persisted).not.toContain(ACCESS_TOKEN);
    expect((await client.auth.getSession()).data?.session?.refresh_token).toBe("rotated-refresh");
  });

  it("updates the stored user without changing session credentials", async () => {
    const storage = createStorage();
    const changed = { ...user, user_metadata: { display_name: "Changed" } };
    const { fetcher, calls } = createFetch([success({ user }), success({ user: changed })]);
    const client = await establishSession(fetcher, { auth: { persistSession: true, storage } });
    calls.length = 0;
    await expect(client.auth.updateUser({ data: { display_name: "Changed" }, email: "new@example.com" })).resolves.toEqual({ data: { user: changed }, error: null });
    const request = requestDetails(calls[0]!);
    expect(request.url).toBe(`${BASE_URL}/user`);
    expect(request.method).toBe("PUT");
    expect(await requestJson(request.request)).toEqual({ email: "new@example.com", user_metadata: { display_name: "Changed" } });
    expect((await client.auth.getSession()).data?.session?.refresh_token).toBe(REFRESH_TOKEN);
  });

  it("maps OAuth start and code exchange while retaining client-only PKCE material", async () => {
    const exchangeSession = session({ access_token: "exchange-access", refresh_token: "exchange-refresh" });
    const { fetcher, calls } = createFetch([
      success({ provider: "google", url: "https://accounts.example/authorize", redirect: REDIRECT, expires_at: "2026-08-12T00:10:00.000Z" }),
      success({ user, identity, session: exchangeSession }),
    ]);
    const storage = createStorage();
    const client = createTestClient(fetcher, { auth: { persistSession: true, storage } });
    const oauth = await client.auth.signInWithOAuth({ provider: "google", options: { redirectTo: REDIRECT, skipBrowserRedirect: true } });
    expect(oauth).toMatchObject({ data: { provider: "google", url: "https://accounts.example/authorize" }, error: null });
    const authorizeRequest = requestDetails(calls[0]!);
    const authorizeUrl = new URL(authorizeRequest.url);
    expect(authorizeUrl.pathname).toBe("/auth/v1/authorize");
    expect(authorizeUrl.searchParams.get("provider")).toBe("google");
    expect(authorizeUrl.searchParams.get("code_challenge_method")).toBe("S256");
    expect(authorizeUrl.searchParams.get("redirect_to")).toBe(REDIRECT);
    expect(authorizeUrl.searchParams.get("flow")).toBe("sign_in");
    expect(authorizeUrl.searchParams.get("code_challenge")).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(authorizeRequest.headers.authorization).toBeUndefined();
    const stored = [...storage.values.values()].join("\n");
    expect(stored).toContain("codeVerifier");
    expect(stored).not.toContain("accounts.example");
    expect(stored).not.toContain("provider-state");
    calls.shift();
    await expect(client.auth.exchangeCodeForSession("internal-code")).resolves.toEqual({ data: { user, session: exchangeSession }, error: null });
    const exchangeRequest = requestDetails(calls[0]!);
    expect(exchangeRequest.url).toBe(`${BASE_URL}/exchange`);
    expect(await requestJson(exchangeRequest.request)).toMatchObject({ code: "internal-code", redirect_to: REDIRECT });
    const exchangeBody = await requestJson(exchangeRequest.request) as Record<string, unknown>;
    expect(exchangeBody.code_verifier).toMatch(/^[A-Za-z0-9._~-]{43,128}$/);
    expect(JSON.stringify(exchangeBody)).not.toContain(ACCESS_TOKEN);
  });

  it("requires a current bearer session for identity, permissions, and linking operations", async () => {
    const storage = createStorage();
    const { fetcher, calls } = createFetch([
      success({ user }),
      success({ identities: [identity] }),
      success({ permissions: ["invoice.read"] }),
      success(null),
      success({ provider: "google", url: "https://accounts.example/authorize", redirect: REDIRECT, expires_at: "2026-08-12T00:10:00.000Z" }),
    ]);
    const client = await establishSession(fetcher, { auth: { persistSession: true, storage } });
    calls.length = 0;
    await expect(client.auth.getUserIdentities()).resolves.toEqual({ data: { identities: [identity] }, error: null });
    await expect(client.auth.getPermissions({ scope: { type: "organization", id: "org_123" } })).resolves.toEqual({ data: { permissions: ["invoice.read"] }, error: null });
    await expect(client.auth.unlinkIdentity(identity)).resolves.toEqual({ data: null, error: null });
    await expect(client.auth.linkIdentity({ provider: "google", options: { redirectTo: REDIRECT, skipBrowserRedirect: true } })).resolves.toMatchObject({ data: { provider: "google" }, error: null });
    const identityRequest = requestDetails(calls[0]!);
    expect(identityRequest.url).toBe(`${BASE_URL}/user/identities`);
    expect(identityRequest.headers.authorization).toBe(`Bearer ${ACCESS_TOKEN}`);
    const permissionRequest = requestDetails(calls[1]!);
    expect(permissionRequest.url).toBe(`${BASE_URL}/user/permissions?scope_type=organization&scope_id=org_123`);
    const unlinkRequest = requestDetails(calls[2]!);
    expect(unlinkRequest.url).toBe(`${BASE_URL}/user/identities/${IDENTITY_ID}`);
    const linkUrl = new URL(requestDetails(calls[3]!).url);
    expect(linkUrl.searchParams.get("flow")).toBe("link_identity");
    expect(requestDetails(calls[3]!).headers.authorization).toBe(`Bearer ${ACCESS_TOKEN}`);
  });

  it("signs out according to scope and emits one local event", async () => {
    const storage = createStorage();
    const { fetcher, calls } = createFetch([success({ user }), success(null)]);
    const client = await establishSession(fetcher, { auth: { persistSession: true, storage } });
    const events: string[] = [];
    client.auth.onAuthStateChange((event) => events.push(event));
    calls.length = 0;
    await expect(client.auth.signOut({ scope: "local" })).resolves.toEqual({ data: null, error: null });
    expect(requestDetails(calls[0]!).url).toBe(`${BASE_URL}/logout`);
    expect(await requestJson(requestDetails(calls[0]!).request)).toEqual({ scope: "local" });
    expect(events).toEqual(["SIGNED_OUT"]);
    expect((await client.auth.getSession()).data?.session).toBeNull();
  });

  it("normalizes malformed, network, and hostile responses into redacted internal errors", async () => {
    const malformed = createFetch([success({ session: { access_token: "leaked" } })]);
    const malformedClient = createTestClient(malformed.fetcher);
    const malformedResult = await malformedClient.auth.signInWithPassword({ email: "user@example.com", password: "correct horse battery staple" });
    expect(malformedResult.data).toBeNull();
    expect(malformedResult.error).toMatchObject({ code: "internal_error", status: 500 });
    expect(JSON.stringify(malformedResult)).not.toContain("leaked");

    const network = createFetch(async () => { throw new Error("network-sentinel access-token-sentinel"); });
    const networkClient = createTestClient(network.fetcher);
    const networkResult = await networkClient.auth.getUser("explicit-access-token");
    expect(networkResult.data).toBeNull();
    expect(networkResult.error).toMatchObject({ code: "internal_error", message: "Internal authentication error" });
    expect(JSON.stringify(networkResult)).not.toContain("network-sentinel");

    const api = createFetch([failure(401, { code: "invalid_credentials", message: "Invalid login credentials", request_id: "request-123" })]);
    const apiClient = createTestClient(api.fetcher);
    const apiResult = await apiClient.auth.signInWithPassword({ email: "user@example.com", password: "correct horse battery staple" });
    expect(apiResult.data).toBeNull();
    expect(apiResult.error).toBeInstanceOf(AuthApiError);
    expect(apiResult.error).toMatchObject({ code: "invalid_credentials", status: 401, request_id: "request-123" });

    const uppercaseSecret = createFetch([failure(401, { code: "invalid_credentials", message: "TOKEN UPPERCASE-SECRET" })]);
    const uppercaseClient = createTestClient(uppercaseSecret.fetcher);
    const uppercaseResult = await uppercaseClient.auth.signInWithPassword({ email: "user@example.com", password: "correct horse battery staple" });
    expect(uppercaseResult.error).toMatchObject({ code: "invalid_credentials", message: "Authentication request failed" });
    expect(JSON.stringify(uppercaseResult)).not.toContain("UPPERCASE-SECRET");

    const codeSecret = createFetch([failure(400, { code: "oauth_provider_error", message: "authorization code=provider-code-sentinel" })]);
    const codeClient = createTestClient(codeSecret.fetcher);
    const codeResult = await codeClient.auth.signInWithPassword({ email: "user@example.com", password: "correct horse battery staple" });
    expect(codeResult.error).toMatchObject({ message: "Authentication request failed" });
    expect(JSON.stringify(codeResult)).not.toContain("provider-code-sentinel");
  });

  it("rejects bearer control characters before fetch and enforces response limits in UTF-8 bytes", async () => {
    const headerCapture = createFetch([success({ user })]);
    const headerClient = createTestClient(headerCapture.fetcher);
    const headerResult = await headerClient.auth.getUser("access-token\r\nX-Injected: yes");
    expect(headerResult.error).toMatchObject({ code: "internal_error" });
    expect(headerCapture.calls).toHaveLength(0);

    const padding = Array.from({ length: 70 }, () => "😀".repeat(4_000));
    const oversizedText = JSON.stringify({ data: { ...session(), padding }, error: null });
    expect(new TextEncoder().encode(oversizedText).byteLength).toBeGreaterThan(1024 * 1024);
    expect(oversizedText.length).toBeLessThan(1024 * 1024);
    const oversizedFetch = (async () => Object.freeze({ status: 200, text: async () => oversizedText }) as unknown as Response) as typeof fetch;
    const oversizedClient = createTestClient(oversizedFetch);
    const oversizedResult = await oversizedClient.auth.signInWithPassword({ email: "user@example.com", password: "correct horse battery staple" });
    expect(oversizedResult.data).toBeNull();
    expect(oversizedResult.error).toMatchObject({ code: "internal_error" });
  });

  it("aborts in-flight fetch work when disposed", async () => {
    let capturedSignal: AbortSignal | undefined;
    const fetcher = ((_input: RequestInfo | URL, init?: RequestInit) => {
      capturedSignal = init?.signal ?? undefined;
      return new Promise<Response>((_resolve, reject) => {
        capturedSignal?.addEventListener("abort", () => reject(new DOMException("Aborted", "AbortError")), { once: true });
      });
    }) as typeof fetch;
    const client = createTestClient(fetcher);
    const pending = client.auth.getUser("explicit-access-token");
    await Promise.resolve();
    await Promise.resolve();
    client.auth.dispose();
    expect(capturedSignal?.aborted).toBe(true);
    if (capturedSignal?.aborted === true) await expect(pending).resolves.toMatchObject({ data: null, error: { code: "internal_error" } });
  });

  it.each([
    ["successful", success(session({ access_token: "late-access", refresh_token: "late-refresh" }))],
    ["terminal-error", failure(401, { code: "invalid_token", message: "Refresh token is invalid" })],
  ])("does not mutate persisted sessions after disposal when injected fetch ignores abort (%s)", async (_case, lateResponse) => {
    const storage = createStorage();
    storage.values.set("mrjim-auth:default", JSON.stringify({ version: 1, revision: 1, session: session() }));
    let resolveFetch: ((response: Response) => void) | undefined;
    const fetcher = vi.fn((_input: RequestInfo | URL, _init?: RequestInit) => new Promise<Response>((resolve) => {
      resolveFetch = resolve;
    })) as unknown as typeof fetch;
    const client = createTestClient(fetcher, { auth: { persistSession: true, storage } });
    const before = [...storage.values.entries()];

    const pending = client.auth.refreshSession();
    await vi.waitFor(() => expect(fetcher).toHaveBeenCalledTimes(1));
    client.auth.dispose();
    resolveFetch?.(lateResponse);
    await pending;

    expect([...storage.values.entries()]).toEqual(before);
  });

  it("rejects provider-secret identity fields instead of returning a hostile server snapshot", async () => {
    const storage = createStorage();
    const hostileIdentity = { ...identity, identity_data: { sub: "google-subject", access_token: "provider-secret-sentinel" } };
    const { fetcher } = createFetch([success({ user }), success({ identities: [hostileIdentity] })]);
    const client = await establishSession(fetcher, { auth: { persistSession: true, storage } });
    const result = await client.auth.getUserIdentities();
    expect(result.data).toBeNull();
    expect(result.error).toMatchObject({ code: "internal_error", status: 500 });
    expect(JSON.stringify(result)).not.toContain("provider-secret-sentinel");
  });

  it("rejects oversized user fields and credential-bearing OAuth URLs at the response boundary", async () => {
    const oversizedUser = { ...user, created_at: "x".repeat(129) };
    const oversized = createFetch([success({ ...session(), user: oversizedUser })]);
    const oversizedClient = createTestClient(oversized.fetcher);
    const oversizedResult = await oversizedClient.auth.signInWithPassword({ email: "user@example.com", password: "correct horse battery staple" });
    expect(oversizedResult.data).toBeNull();
    expect(oversizedResult.error).toMatchObject({ code: "internal_error", status: 500 });

    const credentialUrl = createFetch([
      success({ provider: "google", url: "https://user:password@accounts.example/authorize", redirect: REDIRECT, expires_at: "2026-08-12T00:10:00.000Z" }),
    ]);
    const oauthClient = createTestClient(credentialUrl.fetcher);
    const oauthResult = await oauthClient.auth.signInWithOAuth({ provider: "google", options: { redirectTo: REDIRECT, skipBrowserRedirect: true } });
    expect(oauthResult.data).toBeNull();
    expect(oauthResult.error).toMatchObject({ code: "internal_error", status: 500 });
  });

  it("fails closed on accessor inputs, revoked proxies, and hostile thenables", async () => {
    const { fetcher } = createFetch([]);
    expect(() => createClient(BASE_URL, API_KEY, { global: Object.defineProperty({}, "fetch", { get: () => fetcher }) })).toThrow(AuthConfigurationError);
    const client = createTestClient(fetcher);
    expect(() => client.auth.signInWithPassword(Object.defineProperty({ password: "password" }, "email", { get: () => "user@example.com" }) as PasswordSignInInput)).toThrow(AuthProgrammingError);
    const { proxy, revoke } = Proxy.revocable({}, {});
    revoke();
    expect(() => client.auth.signUp(proxy as SignUpInput)).toThrow(AuthProgrammingError);

    const thenable = Object.defineProperty({}, "then", { get: () => { throw new Error("thenable-secret-sentinel"); } });
    const hostileFetch = (() => thenable) as unknown as typeof fetch;
    const hostileClient = createTestClient(hostileFetch);
    const result = await hostileClient.auth.getUser("explicit-access-token");
    expect(result.error).toMatchObject({ code: "internal_error", message: "Internal authentication error" });
    expect(JSON.stringify(result)).not.toContain("thenable-secret-sentinel");
  });

  it("contains callback and debug failures without awaiting or leaking secrets", async () => {
    const { fetcher } = createFetch([success({ user, session: session() })]);
    const debug = vi.fn(() => { throw new Error("debug-sentinel"); });
    const client = createTestClient(fetcher, { auth: { debug } });
    const callback = vi.fn(() => { throw new Error("callback-sentinel"); });
    const subscription = client.auth.onAuthStateChange(callback);
    await client.auth.signUp({ email: "user@example.com", password: "correct horse battery staple" });
    expect(callback).toHaveBeenCalled();
    subscription.unsubscribe();
    subscription.unsubscribe();
    expect(JSON.stringify(debug.mock.calls)).not.toContain("access-token-sentinel");
    expect(JSON.stringify(debug.mock.calls)).not.toContain("callback-sentinel");
  });

  it("rejects malformed adapters synchronously and exposes idempotent lifecycle controls", () => {
    const { fetcher } = createFetch([]);
    expect(() => createClient(BASE_URL, API_KEY, { global: { fetch: undefined as unknown as typeof fetch } })).toThrow(AuthConfigurationError);
    expect(() => createClient(BASE_URL, API_KEY, { auth: { storage: { getItem: 1, setItem() {}, removeItem() {} } as unknown as SupportedStorage }, global: { fetch: fetcher } })).toThrow(AuthConfigurationError);
    expect(() => createClient(BASE_URL, API_KEY, { auth: { lock: 1 as never }, global: { fetch: fetcher } })).toThrow(AuthConfigurationError);
    const client = createTestClient(fetcher);
    expect(() => client.auth.startAutoRefresh()).not.toThrow();
    expect(() => client.auth.stopAutoRefresh()).not.toThrow();
    expect(() => client.auth.dispose()).not.toThrow();
    expect(() => client.auth.dispose()).not.toThrow();
    expect(() => client.auth.getSession()).not.toThrow();
    expect(() => { throw new AuthProgrammingError("sentinel"); }).toThrow(AuthProgrammingError);
  });

  it("keeps public client boundaries stable after common prototype methods are polluted", async () => {
    const originalArrayEvery = Array.prototype.every;
    const originalArrayPush = Array.prototype.push;
    const originalArraySlice = Array.prototype.slice;
    const originalStringEndsWith = String.prototype.endsWith;
    const originalStringIncludes = String.prototype.includes;
    const originalStringSlice = String.prototype.slice;
    const originalStringStartsWith = String.prototype.startsWith;
    const originalStringTrim = String.prototype.trim;
    const responseBody = JSON.stringify({ data: session(), error: null });
    const response = Object.freeze({
      status: 200,
      headers: Object.freeze({ get: () => null }),
      text: async () => responseBody,
    }) as unknown as Response;
    let result: Awaited<ReturnType<ReturnType<typeof createTestClient>["auth"]["signInWithPassword"]>> | undefined;
    let requestUrl: string | undefined;
    try {
      Array.prototype.every = (() => { throw new Error("array-every-sentinel"); }) as unknown as typeof Array.prototype.every;
      Array.prototype.push = (() => { throw new Error("array-push-sentinel"); }) as typeof Array.prototype.push;
      Array.prototype.slice = (() => { throw new Error("array-slice-sentinel"); }) as typeof Array.prototype.slice;
      String.prototype.endsWith = (() => { throw new Error("string-ends-with-sentinel"); }) as typeof String.prototype.endsWith;
      String.prototype.includes = (() => { throw new Error("string-includes-sentinel"); }) as typeof String.prototype.includes;
      String.prototype.slice = (() => { throw new Error("string-slice-sentinel"); }) as typeof String.prototype.slice;
      String.prototype.startsWith = (() => { throw new Error("string-starts-with-sentinel"); }) as typeof String.prototype.startsWith;
      String.prototype.trim = (() => { throw new Error("string-trim-sentinel"); }) as typeof String.prototype.trim;
      const fetcher = (async (input: RequestInfo | URL) => {
        requestUrl = String(input);
        return response;
      }) as typeof fetch;
      const client = createTestClient(fetcher);
      result = await client.auth.signInWithPassword({ email: "user@example.com", password: "correct horse battery staple" });
      client.auth.dispose();
    } finally {
      Array.prototype.every = originalArrayEvery;
      Array.prototype.push = originalArrayPush;
      Array.prototype.slice = originalArraySlice;
      String.prototype.endsWith = originalStringEndsWith;
      String.prototype.includes = originalStringIncludes;
      String.prototype.slice = originalStringSlice;
      String.prototype.startsWith = originalStringStartsWith;
      String.prototype.trim = originalStringTrim;
    }
    expect(requestUrl).toBe(`${BASE_URL}/token?grant_type=password`);
    expect(result).toEqual({ data: { user, session: session() }, error: null });
    expect(JSON.stringify(result)).not.toContain("array-push-sentinel");
    expect(JSON.stringify(result)).not.toContain("string-trim-sentinel");
  });
});
