import { describe, expect, it } from "vitest";
import { Buffer } from "node:buffer";
import { createClient } from "../../src/index.js";
import { createBrowserClient } from "../../src/adapters/nextjs-browser.js";
import { createServerClient } from "../../src/adapters/nextjs-server.js";
import { createCookieStorage, type Cookie, type CookieToSet } from "../../src/server/cookies.js";
import type { Session, User } from "../../src/shared/types.js";

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

function session(overrides: Partial<Session> = {}): Session {
  return {
    access_token: "access-token",
    refresh_token: "refresh-token",
    token_type: "bearer" as const,
    expires_in: 900,
    expires_at: Math.floor(Date.now() / 1000) + 900,
    user: {
      id: "11111111-1111-4111-8111-111111111111" as User["id"],
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
    expect(() => createBrowserClient(AUTH_URL, KEY, { global: { fetch }, auth: { storageKey: "conflict-contract", persistSession: false }, storage: { url: "https://other.example.test/storage/v1" } })).toThrow(/storage key/i);
  });

  it("exposes only browser-safe client behavior from the browser helper", () => {
    const fetch = async () => response({ user: null, session: null });
    const client = createBrowserClient(AUTH_URL, KEY, { global: { fetch }, auth: { storageKey: "export-contract" } });
    expect(Object.keys(client)).toEqual(["auth", "storage"]);
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

  it("uses the runtime fetch when the server adapter configures headers without a fetch override", async () => {
    const jar = createCookieJar();
    const client = createServerClient(AUTH_URL, KEY, {
      cookies: jar.adapter,
      headers: { "x-request-id": "runtime-fetch-contract" },
    });

    await expect(client.auth.getSession()).resolves.toEqual({ data: { session: null }, error: null });
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
    expect(jar.cookies.some((cookie) => cookie.name === "mrjim-auth.0" && cookie.value.length > 0)).toBe(true);
    expect(jar.writes.some((cookie) => cookie.name === "mrjim-auth.1" && cookie.value === "" && cookie.options.maxAge === 0)).toBe(true);
    const persisted = jar.writes.find((cookie) => cookie.value.length > 0);
    expect(persisted?.options).toMatchObject({ httpOnly: true, sameSite: "lax", path: "/", secure: true });
  });

  it("supports asynchronous cookie adapters and defaults to Secure for an HTTPS auth URL", async () => {
    const jar = createCookieJar();
    const asyncAdapter = {
      async getAll() { return jar.adapter.getAll(); },
      async setAll(values: readonly CookieToSet[]) { jar.adapter.setAll([...values]); },
    };
    const fetch = async () => response(session());
    const client = createServerClient(AUTH_URL, KEY, { cookies: asyncAdapter, global: { fetch } });

    await expect(client.auth.setSession(session())).resolves.toMatchObject({ error: null });
    expect(jar.writes.filter((cookie) => cookie.value.length > 0).every((cookie) => cookie.options.secure)).toBe(true);
  });

  it("does not permit an HTTPS auth client to disable Secure cookies", async () => {
    const jar = createCookieJar();
    const client = createServerClient(AUTH_URL, KEY, {
      cookies: jar.adapter,
      secure: false,
      global: { fetch: async () => response(session()) },
    });

    await expect(client.auth.setSession(session())).resolves.toMatchObject({ error: null });
    expect(jar.writes.filter((cookie) => cookie.value.length > 0).every((cookie) => cookie.options.secure)).toBe(true);
  });

  it("allows read-only cookie access but fails closed when a session mutation requires a write", async () => {
    const fetch = async () => response(session());
    const client = createServerClient(AUTH_URL, KEY, { cookies: { getAll: async () => [] }, global: { fetch } });

    await expect(client.auth.getSession()).resolves.toEqual({ data: { session: null }, error: null });
    const result = await client.auth.setSession(session());
    expect(result.error?.code).toBe("internal_error");
  });

  it("rejects accessor, malformed, oversized, and over-limit cookie results without disclosure", async () => {
    let getterCalls = 0;
    const accessorCookie = Object.create(null) as Record<string, unknown>;
    Object.defineProperty(accessorCookie, "name", {
      enumerable: true,
      get() { getterCalls += 1; throw new Error("cookie accessor secret"); },
    });
    Object.defineProperty(accessorCookie, "value", { enumerable: true, value: "QQ" });
    const cases: ReadonlyArray<readonly Cookie[]> = [
      [accessorCookie as unknown as Cookie],
      [{ name: "mrjim-auth.1", value: "QQ" }],
      [{ name: "mrjim-auth.0", value: "A".repeat(4_097) }],
      Array.from({ length: 129 }, (_, index) => ({ name: `mrjim-auth.${index}`, value: "QQ" })),
    ];

    for (const cookies of cases) {
      const writes: CookieToSet[] = [];
      const client = createServerClient(AUTH_URL, KEY, {
        cookies: { getAll: async () => cookies, setAll: async (values) => { writes.push(...values); } },
        global: { fetch: async () => response({ user: null, session: null }) },
      });
      const result = await client.auth.getSession();
      expect(result).toEqual({ data: { session: null }, error: null });
      expect(JSON.stringify(result)).not.toContain("cookie accessor secret");
      expect(writes.every((cookie) => cookie.value === "" && cookie.options.maxAge === 0)).toBe(true);
    }
    expect(getterCalls).toBe(0);
  });

  it("rejects hostile adapter thenables and unsafe cookie metadata without invoking accessors", async () => {
    let thenReads = 0;
    const thenable = Object.create(null) as Record<string, unknown>;
    Object.defineProperty(thenable, "then", {
      get() { thenReads += 1; throw new Error("cookie then secret"); },
    });
    const readClient = createServerClient(AUTH_URL, KEY, {
      cookies: { getAll: () => thenable as unknown as Promise<readonly Cookie[]> },
      global: { fetch: async () => response(session()) },
    });
    await expect(readClient.auth.getSession()).resolves.toEqual({ data: { session: null }, error: null });

    const writeClient = createServerClient(AUTH_URL, KEY, {
      cookies: { getAll: () => [], setAll: () => thenable as unknown as Promise<void> },
      global: { fetch: async () => response(session()) },
    });
    expect((await writeClient.auth.setSession(session())).error?.code).toBe("internal_error");
    expect(thenReads).toBe(0);

    expect(() => createServerClient(AUTH_URL, KEY, {
      cookies: createCookieJar().adapter,
      cookiePath: "/; injected=true",
      global: { fetch: async () => response(session()) },
    })).toThrow(/cookie path/i);
    expect(() => createServerClient(AUTH_URL, KEY, {
      cookies: createCookieJar().adapter,
      cookieName: "x".repeat(126),
      global: { fetch: async () => response(session()) },
    })).toThrow(/cookie name/i);
  });

  it("rejects oversized storage input before allocating an encoded copy", async () => {
    const storage = createCookieStorage({ adapter: createCookieJar().adapter, storageKey: "default", secure: true });
    const original = Buffer.from;
    let calls = 0;
    try {
      Buffer.from = ((value: string, encoding: BufferEncoding) => {
        calls += 1;
        return original(value, encoding);
      }) as typeof Buffer.from;
      await expect(storage.setItem("mrjim-auth:default", "x".repeat(400_000))).rejects.toThrow(/oversized/i);
    } finally {
      Buffer.from = original;
    }
    expect(calls).toBe(0);
  });

  it("expires non-canonical stale chunk suffixes during the next write", async () => {
    const jar = createCookieJar([{ name: "mrjim-auth.01", value: "stale" }]);
    const storage = createCookieStorage({ adapter: jar.adapter, storageKey: "default", secure: true });

    await expect(storage.setItem("mrjim-auth:default", "x".repeat(4_000))).resolves.toBeUndefined();
    expect(jar.writes.some((cookie) => cookie.name === "mrjim-auth.01" && cookie.value === "" && cookie.options.maxAge === 0)).toBe(true);
  });

  it("isolates parallel request-local clients and their cookie state", async () => {
    const first = createCookieJar();
    const second = createCookieJar();
    const firstSession = session({ access_token: "first-access", refresh_token: "first-refresh" });
    const secondSession = session({ access_token: "second-access", refresh_token: "second-refresh" });
    const firstClient = createServerClient(AUTH_URL, KEY, { cookies: first.adapter, global: { fetch: async () => response(firstSession) } });
    const secondClient = createServerClient(AUTH_URL, KEY, { cookies: second.adapter, global: { fetch: async () => response(secondSession) } });

    await Promise.all([firstClient.auth.setSession(firstSession), secondClient.auth.setSession(secondSession)]);
    const [firstResult, secondResult] = await Promise.all([firstClient.auth.getSession(), secondClient.auth.getSession()]);

    expect(firstResult.data?.session?.access_token).toBe("first-access");
    expect(secondResult.data?.session?.access_token).toBe("second-access");
    expect(first.cookies.map((cookie) => cookie.value).join("")).not.toBe(second.cookies.map((cookie) => cookie.value).join(""));
  });

  it("signs out by clearing every auth cookie chunk and fails closed on unavailable required writes", async () => {
    const jar = createCookieJar();
    const fetch = async (input: RequestInfo | URL) => new Request(input).url.endsWith("/user") ? response(session()) : response(null);
    const client = createServerClient(AUTH_URL, KEY, { cookies: jar.adapter, global: { fetch } });
    await expect(client.auth.setSession(session())).resolves.toMatchObject({ error: null });
    expect(jar.cookies.some((cookie) => cookie.name.startsWith("mrjim-auth.") && cookie.value.length > 0)).toBe(true);
    await expect(client.auth.signOut()).resolves.toEqual({ data: null, error: null });
    expect(jar.cookies.filter((cookie) => cookie.name.startsWith("mrjim-auth.")).every((cookie) => cookie.value === "")).toBe(true);

    const seed = createCookieJar();
    const seedClient = createServerClient(AUTH_URL, KEY, { cookies: seed.adapter, global: { fetch } });
    await expect(seedClient.auth.setSession(session())).resolves.toMatchObject({ error: null });
    const failing = {
      getAll: () => seed.cookies,
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
    await client.auth.resetPasswordForEmail("user@example.test");

    expect(seen?.get("apikey")).toBe(KEY);
    expect(seen?.get("authorization")).not.toBe("caller-token");
    expect(seen?.get("content-type")).not.toBe("text/plain");
  });

  it("does not import or expose the Node server boundary through browser construction", () => {
    expect(createClient).toBeTypeOf("function");
    expect(createBrowserClient).toBeTypeOf("function");
    expect(createServerClient).toBeTypeOf("function");
  });
});
