import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { test, expect } from "@playwright/test";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const distRoot = resolve(packageRoot, "dist");
const USER_ID = "11111111-1111-4111-8111-111111111111";
const ACCESS_TOKEN = "browser-access-token";
const REFRESH_TOKEN = "browser-refresh-token";
const ROTATED_ACCESS_TOKEN = "browser-rotated-access-token";
const ROTATED_REFRESH_TOKEN = "browser-rotated-refresh-token";

let refreshRequestCount = 0;
const exchangeRequestBodies: unknown[] = [];
const authorizeRedirects: string[] = [];

function browserUser() {
  return {
    id: USER_ID,
    email: "user@example.com",
    phone: null,
    email_confirmed_at: "2026-08-12T00:00:00.000Z",
    phone_confirmed_at: null,
    confirmed_at: "2026-08-12T00:00:00.000Z",
    last_sign_in_at: "2026-08-12T00:00:00.000Z",
    banned_until: null,
    user_metadata: {},
    app_metadata: {},
    created_at: "2026-08-12T00:00:00.000Z",
    updated_at: "2026-08-12T00:00:00.000Z",
    deleted_at: null,
  };
}

function browserSession(accessToken = ACCESS_TOKEN, refreshToken = REFRESH_TOKEN, expiresAt = Math.floor(Date.now() / 1000) + 900) {
  return {
    access_token: accessToken,
    refresh_token: refreshToken,
    token_type: "bearer",
    expires_in: 900,
    expires_at: expiresAt,
    user: browserUser(),
  };
}

function json(response: ServerResponse, data: unknown, status = 200): void {
  response.writeHead(status, { "content-type": "application/json; charset=utf-8" });
  response.end(JSON.stringify(status >= 200 && status < 300 ? { data, error: null } : { error: data }));
}

async function requestJson(request: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  for await (const chunk of request) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  return JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
}

async function startStaticServer(): Promise<{ readonly server: Server; readonly origin: string }> {
  const server = createServer(async (request, response) => {
    const parsed = new URL(request.url ?? "/", "http://127.0.0.1");
    const pathname = parsed.pathname;
    if (pathname === "/" || pathname === "/callback") {
      response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      response.end("<!doctype html><html><body><div id='app'></div></body></html>");
      return;
    }
    if (pathname.startsWith("/dist/")) {
      try {
        const file = await readFile(resolve(distRoot, pathname.slice("/dist/".length)));
        response.writeHead(200, { "content-type": pathname.endsWith(".js") ? "text/javascript; charset=utf-8" : "application/octet-stream" });
        response.end(file);
      } catch {
        response.writeHead(404);
        response.end();
      }
      return;
    }
    if (pathname === "/auth/v1/user") {
      json(response, { user: browserUser() });
      return;
    }
    if (pathname === "/auth/v1/token" && parsed.searchParams.get("grant_type") === "refresh_token") {
      refreshRequestCount += 1;
      await new Promise((resolvePromise) => setTimeout(resolvePromise, 100));
      json(response, browserSession(ROTATED_ACCESS_TOKEN, ROTATED_REFRESH_TOKEN));
      return;
    }
    if (pathname === "/auth/v1/authorize") {
      const redirect = parsed.searchParams.get("redirect_to") ?? "";
      authorizeRedirects.push(redirect);
      json(response, {
        provider: parsed.searchParams.get("provider") ?? "google",
        url: "https://accounts.example/authorize",
        redirect,
        expires_at: "2026-08-12T00:10:00.000Z",
      });
      return;
    }
    if (pathname === "/auth/v1/exchange") {
      exchangeRequestBodies.push(await requestJson(request));
      json(response, {
        user: browserUser(),
        identity: {
          id: "22222222-2222-4222-8222-222222222222",
          user_id: USER_ID,
          provider: "google",
          provider_subject: "google-subject",
          email: "user@example.com",
          identity_data: { sub: "google-subject", email: "user@example.com" },
          created_at: "2026-08-12T00:00:00.000Z",
          updated_at: "2026-08-12T00:00:00.000Z",
        },
        session: browserSession(ROTATED_ACCESS_TOKEN, ROTATED_REFRESH_TOKEN),
      });
      return;
    }
    if (pathname === "/auth/v1/recover/verify") {
      await requestJson(request);
      json(response, { user: browserUser() });
      return;
    }
    if (pathname === "/auth/v1/logout") {
      json(response, null);
      return;
    }
    response.writeHead(404);
    response.end();
  });
  await new Promise<void>((resolvePromise, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolvePromise());
  });
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("browser test server did not bind");
  return { server, origin: `http://127.0.0.1:${address.port}` };
}

test.describe("real local browser auth lifecycle", () => {
  let server: Server;
  let origin: string;

  test.beforeAll(async () => {
    const started = await startStaticServer();
    server = started.server;
    origin = started.origin;
  });

  test.afterAll(async () => {
    await new Promise<void>((resolvePromise) => server.close(() => resolvePromise()));
  });

  test("delivers INITIAL_SESSION first and once, removes malformed state, and persists a validated session", async ({ page }) => {
    await page.goto(`${origin}/`);
    const result = await page.evaluate(async ({ pageOrigin, initialSession }) => {
      const { createClient } = await import(`${pageOrigin}/dist/index.js`);
      const key = "browser-lifecycle-initial";
      const storageName = `mrjim-auth:${key}`;
      localStorage.setItem(storageName, "{malformed");
      const firstEvents: string[] = [];
      const first = createClient(`${pageOrigin}/auth/v1`, "browser-key", { auth: { storageKey: key, autoRefreshToken: false, detectSessionInUrl: false } });
      first.auth.onAuthStateChange((event: string) => firstEvents.push(event));
      await new Promise((resolvePromise) => setTimeout(resolvePromise, 25));
      const malformedRemoved = localStorage.getItem(storageName) === null;
      const setResult = await first.auth.setSession(initialSession);
      const persisted = localStorage.getItem(storageName);
      first.auth.dispose();

      const secondEvents: string[] = [];
      const second = createClient(`${pageOrigin}/auth/v1`, "browser-key", { auth: { storageKey: key, autoRefreshToken: false, detectSessionInUrl: false } });
      second.auth.onAuthStateChange((event: string) => secondEvents.push(event));
      const restored = await second.auth.getSession();
      second.auth.dispose();
      return {
        firstEvents,
        secondEvents,
        malformedRemoved,
        persistedSession: persisted?.includes(initialSession.refresh_token) === true,
        restoredRefreshToken: restored.data?.session?.refresh_token,
        setError: setResult.error?.code ?? null,
      };
    }, { pageOrigin: origin, initialSession: browserSession() });

    expect(result).toEqual({
      firstEvents: ["INITIAL_SESSION", "SIGNED_IN"],
      secondEvents: ["INITIAL_SESSION"],
      malformedRemoved: true,
      persistedSession: true,
      restoredRefreshToken: REFRESH_TOKEN,
      setError: null,
    });
  });

  test("refreshes before expiry once across two tabs and converges on the winning rotation", async ({ browser }) => {
    refreshRequestCount = 0;
    const context = await browser.newContext();
    const first = await context.newPage();
    const second = await context.newPage();
    await first.goto(`${origin}/`);
    await second.goto(`${origin}/`);
    const key = "browser-lifecycle-refresh";
    const expiring = browserSession(ACCESS_TOKEN, REFRESH_TOKEN, Math.floor(Date.now() / 1000) + 20);
    await first.evaluate(({ storageKey, initialSession }) => {
      localStorage.setItem(`mrjim-auth:${storageKey}`, JSON.stringify({ version: 1, revision: 1, session: initialSession }));
    }, { storageKey: key, initialSession: expiring });

    const runTab = async (page: typeof first) => page.evaluate(async ({ pageOrigin, storageKey, winner }) => {
      const { createClient } = await import(`${pageOrigin}/dist/index.js`);
      const events: string[] = [];
      const client = createClient(`${pageOrigin}/auth/v1`, "browser-key", { auth: { storageKey, detectSessionInUrl: false } });
      client.auth.onAuthStateChange((event: string) => events.push(event));
      let refreshToken: string | undefined;
      const deadline = Date.now() + 4_000;
      while (Date.now() < deadline) {
        refreshToken = (await client.auth.getSession()).data?.session?.refresh_token;
        if (refreshToken === winner) break;
        await new Promise((resolvePromise) => setTimeout(resolvePromise, 25));
      }
      const eventDeadline = Date.now() + 500;
      while (Date.now() < eventDeadline && !events.includes("TOKEN_REFRESHED")) {
        await new Promise((resolvePromise) => setTimeout(resolvePromise, 10));
      }
      client.auth.dispose();
      return { events, refreshToken };
    }, { pageOrigin: origin, storageKey: key, winner: ROTATED_REFRESH_TOKEN });

    const [firstResult, secondResult] = await Promise.all([runTab(first), runTab(second)]);
    expect(refreshRequestCount).toBe(1);
    expect(firstResult.refreshToken).toBe(ROTATED_REFRESH_TOKEN);
    expect(secondResult.refreshToken).toBe(ROTATED_REFRESH_TOKEN);
    expect(firstResult.events[0]).toBe("INITIAL_SESSION");
    expect(secondResult.events[0]).toBe("INITIAL_SESSION");
    expect([...firstResult.events, ...secondResult.events].filter((event) => event === "TOKEN_REFRESHED")).toHaveLength(2);
    await context.close();
  });

  test("consumes a matching OAuth PKCE URL, cleans credentials before events, and preserves unrelated URL data", async ({ page }) => {
    exchangeRequestBodies.length = 0;
    const cleanRedirect = `${origin}/callback?keep=1#fragment`;
    await page.goto(`${origin}/`);
    const started = await page.evaluate(async ({ pageOrigin, redirectTo }) => {
      const { createClient } = await import(`${pageOrigin}/dist/index.js`);
      const client = createClient(`${pageOrigin}/auth/v1`, "browser-key", { auth: { storageKey: "browser-lifecycle-url", autoRefreshToken: false, detectSessionInUrl: false } });
      const result = await client.auth.signInWithOAuth({ provider: "google", options: { redirectTo, skipBrowserRedirect: true } });
      client.auth.dispose();
      return result.error?.code ?? null;
    }, { pageOrigin: origin, redirectTo: cleanRedirect });
    expect(started).toBeNull();

    await page.goto(`${origin}/callback?keep=1&code=internal-code#fragment`);
    const result = await page.evaluate(async ({ pageOrigin }) => {
      const { createClient } = await import(`${pageOrigin}/dist/index.js`);
      const observations: Array<{ readonly event: string; readonly href: string }> = [];
      const client = createClient(`${pageOrigin}/auth/v1`, "browser-key", { auth: { storageKey: "browser-lifecycle-url", autoRefreshToken: false } });
      client.auth.onAuthStateChange((event: string) => observations.push({ event, href: location.href }));
      const session = await client.auth.getSession();
      client.auth.dispose();
      return { observations, href: location.href, refreshToken: session.data?.session?.refresh_token };
    }, { pageOrigin: origin });

    expect(result.observations.map(({ event }) => event)).toEqual(["INITIAL_SESSION", "SIGNED_IN"]);
    expect(result.observations.every(({ href }) => href === cleanRedirect)).toBe(true);
    expect(result.href).toBe(cleanRedirect);
    expect(result.refreshToken).toBe(ROTATED_REFRESH_TOKEN);
    expect(exchangeRequestBodies).toHaveLength(1);
    expect(exchangeRequestBodies[0]).toMatchObject({ code: "internal-code", redirect_to: cleanRedirect, code_verifier: expect.stringMatching(/^[A-Za-z0-9._~-]{43,128}$/) });
    expect(JSON.stringify(exchangeRequestBodies)).not.toContain(ACCESS_TOKEN);
  });

  test("rejects duplicated callback codes and falls back when primary history cleanup is unavailable", async ({ page }) => {
    exchangeRequestBodies.length = 0;
    const key = "browser-lifecycle-url-fail-closed";
    const cleanRedirect = `${origin}/callback?keep=2`;
    await page.goto(`${origin}/`);
    await page.evaluate(async ({ pageOrigin, storageKey, redirectTo }) => {
      const { createClient } = await import(`${pageOrigin}/dist/index.js`);
      const client = createClient(`${pageOrigin}/auth/v1`, "browser-key", { auth: { storageKey, autoRefreshToken: false, detectSessionInUrl: false } });
      await client.auth.signInWithOAuth({ provider: "google", options: { redirectTo, skipBrowserRedirect: true } });
      client.auth.dispose();
    }, { pageOrigin: origin, storageKey: key, redirectTo: cleanRedirect });

    const duplicateUrl = `${origin}/callback?keep=2&code=first&code=second`;
    await page.goto(duplicateUrl);
    const duplicate = await page.evaluate(async ({ pageOrigin, storageKey }) => {
      const { createClient } = await import(`${pageOrigin}/dist/index.js`);
      const events: string[] = [];
      const client = createClient(`${pageOrigin}/auth/v1`, "browser-key", { auth: { storageKey, autoRefreshToken: false } });
      client.auth.onAuthStateChange((event: string) => events.push(event));
      const session = await client.auth.getSession();
      const pkcePresent = localStorage.getItem(`mrjim-auth:${storageKey}:pkce`)?.includes("codeVerifier") === true;
      client.auth.dispose();
      return { events, href: location.href, refreshToken: session.data?.session?.refresh_token ?? null, pkcePresent };
    }, { pageOrigin: origin, storageKey: key });
    expect(duplicate).toEqual({ events: ["INITIAL_SESSION"], href: cleanRedirect, refreshToken: null, pkcePresent: true });
    expect(exchangeRequestBodies).toHaveLength(0);

    await page.addInitScript(() => {
      Object.defineProperty(history, "replaceState", { configurable: true, value: () => { throw new Error("history unavailable"); } });
    });
    const unavailableUrl = `${origin}/callback?keep=2&code=single`;
    await page.goto(unavailableUrl);
    const unavailable = await page.evaluate(async ({ pageOrigin, storageKey }) => {
      const { createClient } = await import(`${pageOrigin}/dist/index.js`);
      const events: string[] = [];
      const client = createClient(`${pageOrigin}/auth/v1`, "browser-key", { auth: { storageKey, autoRefreshToken: false } });
      client.auth.onAuthStateChange((event: string) => events.push(event));
      const session = await client.auth.getSession();
      const pkcePresent = localStorage.getItem(`mrjim-auth:${storageKey}:pkce`)?.includes("codeVerifier") === true;
      client.auth.dispose();
      return { events, href: location.href, refreshToken: session.data?.session?.refresh_token ?? null, pkcePresent };
    }, { pageOrigin: origin, storageKey: key });
    expect(unavailable).toEqual({ events: ["INITIAL_SESSION", "SIGNED_IN"], href: cleanRedirect, refreshToken: ROTATED_REFRESH_TOKEN, pkcePresent: false });
    expect(exchangeRequestBodies).toHaveLength(1);
  });

  test("cleans error-only callbacks and never reuses callback credentials as an OAuth redirect", async ({ page }) => {
    const errorUrl = `${origin}/callback?keep=3&error_description=authorization%20code%3Dprovider-secret#fragment`;
    const cleanErrorUrl = `${origin}/callback?keep=3#fragment`;
    await page.goto(errorUrl);
    const cleaned = await page.evaluate(async ({ pageOrigin }) => {
      const { createClient } = await import(`${pageOrigin}/dist/index.js`);
      const observations: Array<{ readonly event: string; readonly href: string }> = [];
      const client = createClient(`${pageOrigin}/auth/v1`, "browser-key", { auth: { storageKey: "browser-error-cleanup", autoRefreshToken: false } });
      client.auth.onAuthStateChange((event: string) => observations.push({ event, href: location.href }));
      await client.auth.getSession();
      client.auth.dispose();
      return { observations, href: location.href };
    }, { pageOrigin: origin });
    expect(cleaned.href).toBe(cleanErrorUrl);
    expect(cleaned.observations).toEqual([{ event: "INITIAL_SESSION", href: cleanErrorUrl }]);

    authorizeRedirects.length = 0;
    await page.goto(`${origin}/callback?keep=4&code=callback-code-sentinel&state=state-sentinel#fragment`);
    const oauthError = await page.evaluate(async ({ pageOrigin }) => {
      const { createClient } = await import(`${pageOrigin}/dist/index.js`);
      const client = createClient(`${pageOrigin}/auth/v1`, "browser-key", { auth: { storageKey: "browser-safe-default-redirect", autoRefreshToken: false, detectSessionInUrl: false, skipAutoInitialize: true } });
      const result = await client.auth.signInWithOAuth({ provider: "google", options: { skipBrowserRedirect: true } });
      client.auth.dispose();
      return result.error?.code ?? null;
    }, { pageOrigin: origin });
    expect(oauthError).toBeNull();
    expect(authorizeRedirects).toEqual([`${origin}/callback?keep=4#fragment`]);
    expect(authorizeRedirects[0]).not.toContain("callback-code-sentinel");
    expect(authorizeRedirects[0]).not.toContain("state-sentinel");
  });

  test("consumes one PKCE transaction atomically across two tabs", async ({ browser }) => {
    exchangeRequestBodies.length = 0;
    const context = await browser.newContext();
    const first = await context.newPage();
    const second = await context.newPage();
    await first.goto(`${origin}/`);
    await second.goto(`${origin}/`);
    const key = "browser-atomic-pkce";
    const redirectTo = `${origin}/callback?atomic=1`;
    await first.evaluate(async ({ pageOrigin, storageKey, redirect }) => {
      const { createClient } = await import(`${pageOrigin}/dist/index.js`);
      const client = createClient(`${pageOrigin}/auth/v1`, "browser-key", { auth: { storageKey, autoRefreshToken: false, detectSessionInUrl: false, skipAutoInitialize: true } });
      await client.auth.signInWithOAuth({ provider: "google", options: { redirectTo: redirect, skipBrowserRedirect: true } });
      client.auth.dispose();
    }, { pageOrigin: origin, storageKey: key, redirect: redirectTo });

    const exchange = (page: typeof first) => page.evaluate(async ({ pageOrigin, storageKey }) => {
      const { createClient } = await import(`${pageOrigin}/dist/index.js`);
      const client = createClient(`${pageOrigin}/auth/v1`, "browser-key", { auth: { storageKey, autoRefreshToken: false, detectSessionInUrl: false, skipAutoInitialize: true } });
      const result = await client.auth.exchangeCodeForSession("one-time-code");
      client.auth.dispose();
      return result.error?.code ?? null;
    }, { pageOrigin: origin, storageKey: key });
    const results = await Promise.all([exchange(first), exchange(second)]);
    expect(results.filter((value) => value === null)).toHaveLength(1);
    expect(results.filter((value) => value === "invalid_request")).toHaveLength(1);
    expect(exchangeRequestBodies).toHaveLength(1);
    await context.close();
  });

  test("completes a purpose-bound password recovery through the public client", async ({ page }) => {
    await page.goto(`${origin}/`);
    const result = await page.evaluate(async ({ pageOrigin }) => {
      const { createClient } = await import(`${pageOrigin}/dist/index.js`);
      const events: string[] = [];
      const client = createClient(`${pageOrigin}/auth/v1`, "browser-key", { auth: { storageKey: "browser-password-recovery", autoRefreshToken: false, detectSessionInUrl: false, skipAutoInitialize: true } });
      client.auth.onAuthStateChange((event: string) => events.push(event));
      const completed = await client.auth.resetPassword({ email: "user@example.com", token: "recovery-token", password: "new correct horse battery staple", options: { redirectTo: `${pageOrigin}/callback` } });
      client.auth.dispose();
      return { error: completed.error?.code ?? null, email: completed.data?.user.email ?? null, events };
    }, { pageOrigin: origin });
    expect(result).toEqual({ error: null, email: "user@example.com", events: ["PASSWORD_RECOVERY"] });
  });

  test("propagates SIGNED_OUT across tabs with metadata-only channel messages", async ({ browser }) => {
    const context = await browser.newContext();
    const first = await context.newPage();
    const second = await context.newPage();
    await first.goto(`${origin}/`);
    await second.goto(`${origin}/`);
    const key = "browser-lifecycle-signout";
    await first.evaluate(({ storageKey, initialSession }) => {
      localStorage.setItem(`mrjim-auth:${storageKey}`, JSON.stringify({ version: 1, revision: 1, session: initialSession }));
    }, { storageKey: key, initialSession: browserSession() });

    await Promise.all([first, second].map((page) => page.evaluate(async ({ pageOrigin, storageKey }) => {
      const { createClient } = await import(`${pageOrigin}/dist/index.js`);
      const events: string[] = [];
      const messages: unknown[] = [];
      const observer = new BroadcastChannel(`mrjim-auth:${storageKey}:events`);
      observer.addEventListener("message", (event) => messages.push(event.data));
      const client = createClient(`${pageOrigin}/auth/v1`, "browser-key", { auth: { storageKey, autoRefreshToken: false, detectSessionInUrl: false } });
      client.auth.onAuthStateChange((event: string) => events.push(event));
      await client.auth.getSession();
      (globalThis as unknown as { __authTest?: unknown }).__authTest = { client, events, messages, observer };
    }, { pageOrigin: origin, storageKey: key })));

    await first.evaluate(async () => {
      const state = (globalThis as unknown as { __authTest: { client: { auth: { signOut(input: unknown): Promise<unknown> } } } }).__authTest;
      await state.client.auth.signOut({ scope: "local" });
    });
    const remote = await second.evaluate(async () => {
      const state = (globalThis as unknown as { __authTest: { client: { auth: { getSession(): Promise<{ data: { session: unknown } | null }> } }; events: string[]; messages: unknown[] } }).__authTest;
      const deadline = Date.now() + 2_000;
      while (Date.now() < deadline && !state.events.includes("SIGNED_OUT")) await new Promise((resolvePromise) => setTimeout(resolvePromise, 20));
      return { events: state.events, messages: state.messages, session: (await state.client.auth.getSession()).data?.session ?? null };
    });

    expect(remote.events).toContain("SIGNED_OUT");
    expect(remote.session).toBeNull();
    expect(remote.messages).toContainEqual({ version: 1, revision: 2, event: "SIGNED_OUT" });
    expect(JSON.stringify(remote.messages)).not.toContain(ACCESS_TOKEN);
    expect(JSON.stringify(remote.messages)).not.toContain(REFRESH_TOKEN);
    await Promise.all([first, second].map((page) => page.evaluate(() => {
      const state = (globalThis as unknown as { __authTest: { client: { auth: { dispose(): void } }; observer: BroadcastChannel } }).__authTest;
      state.client.auth.dispose();
      state.observer.close();
    })));
    await context.close();
  });

  test("pauses auto-refresh while hidden and resumes it when the document becomes visible", async ({ page }) => {
    refreshRequestCount = 0;
    await page.goto(`${origin}/`);
    const result = await page.evaluate(async ({ pageOrigin, initialSession, winner }) => {
      let visibility = "hidden";
      Object.defineProperty(document, "visibilityState", { configurable: true, get: () => visibility });
      const { createClient } = await import(`${pageOrigin}/dist/index.js`);
      const key = "browser-lifecycle-visibility";
      localStorage.setItem(`mrjim-auth:${key}`, JSON.stringify({ version: 1, revision: 1, session: initialSession }));
      const client = createClient(`${pageOrigin}/auth/v1`, "browser-key", { auth: { storageKey: key, detectSessionInUrl: false } });
      await client.auth.getSession();
      document.dispatchEvent(new Event("visibilitychange"));
      await new Promise((resolvePromise) => setTimeout(resolvePromise, 200));
      const whileHidden = (await client.auth.getSession()).data?.session?.refresh_token;
      visibility = "visible";
      document.dispatchEvent(new Event("visibilitychange"));
      let afterVisible: string | undefined;
      const deadline = Date.now() + 3_000;
      while (Date.now() < deadline) {
        afterVisible = (await client.auth.getSession()).data?.session?.refresh_token;
        if (afterVisible === winner) break;
        await new Promise((resolvePromise) => setTimeout(resolvePromise, 25));
      }
      client.auth.dispose();
      delete (document as unknown as { visibilityState?: string }).visibilityState;
      return { whileHidden, afterVisible };
    }, {
      pageOrigin: origin,
      initialSession: browserSession(ACCESS_TOKEN, REFRESH_TOKEN, Math.floor(Date.now() / 1000) + 20),
      winner: ROTATED_REFRESH_TOKEN,
    });
    expect(result).toEqual({ whileHidden: REFRESH_TOKEN, afterVisible: ROTATED_REFRESH_TOKEN });
    expect(refreshRequestCount).toBe(1);
  });

  test("falls back to storage events when BroadcastChannel is unavailable", async ({ browser }) => {
    const context = await browser.newContext();
    await context.addInitScript(() => {
      Object.defineProperty(globalThis, "BroadcastChannel", { configurable: true, writable: true, value: undefined });
    });
    const first = await context.newPage();
    const second = await context.newPage();
    await first.goto(`${origin}/`);
    await second.goto(`${origin}/`);
    const key = "browser-lifecycle-storage-fallback";
    await first.evaluate(({ storageKey, initialSession }) => {
      localStorage.setItem(`mrjim-auth:${storageKey}`, JSON.stringify({ version: 1, revision: 1, session: initialSession }));
    }, { storageKey: key, initialSession: browserSession() });

    await Promise.all([first, second].map((page) => page.evaluate(async ({ pageOrigin, storageKey }) => {
      const { createClient } = await import(`${pageOrigin}/dist/index.js`);
      const events: string[] = [];
      const client = createClient(`${pageOrigin}/auth/v1`, "browser-key", { auth: { storageKey, autoRefreshToken: false, detectSessionInUrl: false } });
      client.auth.onAuthStateChange((event: string) => events.push(event));
      await client.auth.getSession();
      (globalThis as unknown as { __storageFallback?: unknown }).__storageFallback = { client, events };
    }, { pageOrigin: origin, storageKey: key })));

    await first.evaluate(async () => {
      const state = (globalThis as unknown as { __storageFallback: { client: { auth: { refreshSession(): Promise<unknown> } } } }).__storageFallback;
      await state.client.auth.refreshSession();
    });
    const refreshed = await second.evaluate(async () => {
      const state = (globalThis as unknown as { __storageFallback: { events: string[] } }).__storageFallback;
      const deadline = Date.now() + 2_000;
      while (Date.now() < deadline && !state.events.includes("TOKEN_REFRESHED")) await new Promise((resolvePromise) => setTimeout(resolvePromise, 20));
      return state.events;
    });
    expect(refreshed).toContain("TOKEN_REFRESHED");
    expect(refreshed.filter((event) => event === "SIGNED_IN")).toHaveLength(0);

    await first.evaluate(async () => {
      const state = (globalThis as unknown as { __storageFallback: { client: { auth: { signOut(input: unknown): Promise<unknown> } } } }).__storageFallback;
      await state.client.auth.signOut({ scope: "local" });
    });
    const remote = await second.evaluate(async () => {
      const state = (globalThis as unknown as { __storageFallback: { client: { auth: { getSession(): Promise<{ data: { session: unknown } | null }> } }; events: string[] } }).__storageFallback;
      const deadline = Date.now() + 2_000;
      while (Date.now() < deadline && !state.events.includes("SIGNED_OUT")) await new Promise((resolvePromise) => setTimeout(resolvePromise, 20));
      return { events: state.events, session: (await state.client.auth.getSession()).data?.session ?? null };
    });
    expect(remote.events).toContain("SIGNED_OUT");
    expect(remote.session).toBeNull();
    await Promise.all([first, second].map((page) => page.evaluate(() => {
      const state = (globalThis as unknown as { __storageFallback: { client: { auth: { dispose(): void } } } }).__storageFallback;
      state.client.auth.dispose();
    })));
    await context.close();
  });

  test("supports unsubscribe and idempotent dispose in the browser bundle", async ({ page }) => {
    await page.goto(`${origin}/`);
    const result = await page.evaluate(async ({ pageOrigin }) => {
      const { createClient } = await import(`${pageOrigin}/dist/index.js`);
      const client = createClient(`${pageOrigin}/auth/v1`, "browser-key", { auth: { autoRefreshToken: false, detectSessionInUrl: false, skipAutoInitialize: true } });
      let count = 0;
      const subscription = client.auth.onAuthStateChange(() => { count += 1; });
      subscription.unsubscribe();
      subscription.unsubscribe();
      client.auth.dispose();
      client.auth.dispose();
      return { count, frozen: Object.isFrozen(client) && Object.isFrozen(client.auth) };
    }, { pageOrigin: origin });
    expect(result).toEqual({ count: 0, frozen: true });
  });
});
