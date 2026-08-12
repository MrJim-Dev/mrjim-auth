import { describe, expect, it } from "vitest";
import { createClient } from "../../src/index.js";
import { createBrowserClient } from "../../src/adapters/nextjs-browser.js";
import { createServerClient } from "../../src/adapters/nextjs-server.js";
import type { Cookie, CookieToSet } from "../../src/server/cookies.js";

const AUTH_URL = "https://project.example.test/auth/v1";
const KEY = "publishable-key";

function createCookieJar(initial: readonly Cookie[] = []): {
  readonly cookies: Cookie[];
  readonly writes: CookieToSet[];
  readonly adapter: { getAll(): Cookie[]; setAll(values: CookieToSet[]): void };
} {
  const cookies = [...initial];
  const writes: CookieToSet[] = [];
  return {
    cookies,
    writes,
    adapter: {
      getAll() {
        return cookies.map((cookie) => ({ ...cookie }));
      },
      setAll(values) {
        writes.push(...values.map((value) => ({ ...value, options: { ...value.options } })));
        for (const value of values) {
          const index = cookies.findIndex((cookie) => cookie.name === value.name);
          const cookie = { name: value.name, value: value.value };
          if (index === -1) cookies.push(cookie);
          else cookies[index] = cookie;
        }
      },
    },
  };
}

function session(overrides: Record<string, unknown> = {}) {
  return {
    access_token: "access-token",
    refresh_token: "refresh-token",
    token_type: "bearer",
    expires_in: 900,
    expires_at: Math.floor(Date.now() / 1000) + 900,
    user: {
      id: "11111111-1111-4111-8111-111111111111",
      email: "user@example.test",
      phone: null,
      email_confirmed_at: null,
      phone_confirmed_at: null,
      confirmed_at: null,
      last_sign_in_at: null,
      banned_until: null,
      user_metadata: {},
      app_metadata: {},
      created_at: "2026-08-12T00:00:00.000Z",
      updated_at: "2026-08-12T00:00:00.000Z",
      deleted_at: null,
    },
    ...overrides,
  };
}

function response(data: unknown): Response {
  return new Response(JSON.stringify({ data, error: null }), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

describe("Next.js browser and SSR adapter contracts", () => {
  it("returns one immutable browser client per module realm and storage key", () => {
    const fetch = async () => response({ user: null, session: null });
    const first = createBrowserClient(AUTH_URL, KEY, { global: { fetch }, auth: { storageKey: "browser-contract" } });
    const second = createBrowserClient(AUTH_URL, KEY, { global: { fetch }, auth: { storageKey: "browser-contract" } });

    expect(first).toBe(second);
    expect(Object.isFrozen(first)).toBe(true);
    expect(Object.isFrozen(first.auth)).toBe(true);
  });

  it("fails closed when a storage key is rebound to conflicting URL, key, or options", () => {
    const fetch = async () => response({ user: null, session: null });
    createBrowserClient(AUTH_URL, KEY, { global: { fetch }, auth: { storageKey: "conflict-contract", persistSession: false } });

    expect(() => createBrowserClient("https://other.example.test/auth/v1", KEY, { global: { fetch }, auth: { storageKey: "conflict-contract", persistSession: false } })).toThrow(/storage key/i);
    expect(() => createBrowserClient(AUTH_URL, "other-key", { global: { fetch }, auth: { storageKey: "conflict-contract", persistSession: false } })).toThrow(/storage key/i);
    expect(() => createBrowserClient(AUTH_URL, KEY, { global: { fetch }, auth: { storageKey: "conflict-contract", persistSession: true } })).toThrow(/storage key/i);
  });

  it("exposes only browser-safe client behavior from the browser helper", () => {
    const fetch = async () => response({ user: null, session: null });
    const client = createBrowserClient(AUTH_URL, KEY, { global: { fetch }, auth: { storageKey: "export-contract" } });
    expect(Object.keys(client)).toEqual(["auth"]);
    expect(client).not.toHaveProperty("admin");
    expect(client).not.toHaveProperty("database");
    expect(client).not.toHaveProperty("server");
  });

  it("creates fresh request-local server clients and reads cookies without writing", async () => {
    const first = createCookieJar();
    const second = createCookieJar();
    const fetch = async () => response({ user: null, session: null });
    const firstClient = createServerClient(AUTH_URL, KEY, { cookies: first.adapter, headers: { "x-request-id": "one" }, global: { fetch } });
    const secondClient = createServerClient(AUTH_URL, KEY, { cookies: second.adapter, headers: { "x-request-id": "two" }, global: { fetch } });

    expect(firstClient).not.toBe(secondClient);
    await expect(firstClient.auth.getSession()).resolves.toEqual({ data: { session: null }, error: null });
    await expect(secondClient.auth.getSession()).resolves.toEqual({ data: { session: null }, error: null });
    expect(first.cookies).toEqual([]);
    expect(second.cookies).toEqual([]);
  });

  it("persists a rotated session with secure bounded cookie attributes and removes stale chunks", async () => {
    const jar = createCookieJar([
      { name: "mrjim-auth.0", value: "stale" },
      { name: "mrjim-auth.1", value: "stale" },
      { name: "unrelated", value: "keep" },
    ]);
    const fetch = async (input: RequestInfo | URL) => {
      expect(new Request(input).url).toContain("/token?grant_type=refresh_token");
      return response(session({ access_token: "rotated-access", refresh_token: "rotated-refresh" }));
    };
    const client = createServerClient(AUTH_URL, KEY, {
      cookies: jar.adapter,
      headers: { authorization: "caller-controlled", "x-request-id": "rotate-contract" },
      secure: true,
      global: { fetch },
    });
    const result = await client.auth.refreshSession(session({ access_token: "old-access", refresh_token: "old-refresh" }));

    expect(result.error).toBeNull();
    expect(jar.cookies.some((cookie) => cookie.name === "unrelated")).toBe(true);
    expect(jar.cookies.some((cookie) => cookie.value.includes("rotated-refresh"))).toBe(false);
    expect(jar.cookies.filter((cookie) => cookie.name.startsWith("mrjim-auth.")).every((cookie) => cookie.value.length > 0)).toBe(true);
    const persisted = jar.writes.find((cookie) => cookie.value.length > 0);
    expect(persisted?.options).toMatchObject({ httpOnly: true, sameSite: "lax", path: "/", secure: true });
  });

  it("signs out by clearing every auth cookie chunk and fails closed on unavailable required writes", async () => {
    const jar = createCookieJar([
      { name: "mrjim-auth.0", value: "chunk-a" },
      { name: "mrjim-auth.1", value: "chunk-b" },
    ]);
    const fetch = async () => response(null);
    const client = createServerClient(AUTH_URL, KEY, { cookies: jar.adapter, global: { fetch } });
    await expect(client.auth.signOut()).resolves.toEqual({ data: null, error: null });
    expect(jar.cookies.filter((cookie) => cookie.name.startsWith("mrjim-auth.")).every((cookie) => cookie.value === "")).toBe(true);

    const failing = {
      getAll: () => [{ name: "mrjim-auth.0", value: "chunk-a" }],
      setAll: () => { throw new Error("cookie write secret"); },
    };
    const failingClient = createServerClient(AUTH_URL, KEY, { cookies: failing, global: { fetch } });
    const failure = await failingClient.auth.signOut();
    expect(failure.error?.code).toBe("internal_error");
    expect(JSON.stringify(failure)).not.toContain("cookie write secret");
  });

  it("keeps profile/session data out of JavaScript-readable cookie values", async () => {
    const jar = createCookieJar();
    const fetch = async () => response(session());
    const client = createServerClient(AUTH_URL, KEY, { cookies: jar.adapter, secure: true, global: { fetch } });
    await client.auth.setSession(session());

    const serialized = jar.cookies.map((cookie) => cookie.value).join("");
    expect(serialized).not.toContain("user@example.test");
    expect(serialized).not.toContain("access-token");
    expect(serialized).not.toContain("service");
  });

  it("does not let request headers replace SDK security headers", async () => {
    const jar = createCookieJar();
    let seen: Headers | undefined;
    const fetch = async (_input: RequestInfo | URL, init?: RequestInit) => {
      seen = new Headers(init?.headers);
      return response({ user: null, session: null });
    };
    const client = createServerClient(AUTH_URL, KEY, {
      cookies: jar.adapter,
      headers: { apikey: "caller-key", authorization: "caller-token", "content-type": "text/plain" },
      global: { fetch },
    });
    await client.auth.getSession();

    expect(seen?.get("content-type")).not.toBe("text/plain");
  });

  it("does not import or expose the Node server boundary through browser construction", () => {
    expect(createClient).toBeTypeOf("function");
    expect(createBrowserClient).toBeTypeOf("function");
    expect(createServerClient).toBeTypeOf("function");
  });
});
