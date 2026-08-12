import { cookies, headers } from "next/headers";
import { createServerClient, type CookieToSet } from "mrjim-auth/nextjs/server";
import type { AuthError, User } from "mrjim-auth";

function requiredEnv(name: string, value: string | undefined): string {
  if (value === undefined || value.trim() === "") throw new Error(`${name} is required`);
  return value.trim();
}

function requiredUrl(name: string, value: string | undefined): string {
  const raw = requiredEnv(name, value);
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new Error(`${name} must be an absolute HTTP(S) URL`);
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error(`${name} must be an absolute HTTP(S) URL`);
  }
  return parsed.href.endsWith("/") ? parsed.href.slice(0, -1) : parsed.href;
}

export function authUrl(): string {
  return requiredUrl("MRJIM_AUTH_URL", process.env.MRJIM_AUTH_URL);
}

export function publishableKey(): string {
  return requiredEnv("MRJIM_AUTH_PUBLISHABLE_KEY", process.env.MRJIM_AUTH_PUBLISHABLE_KEY);
}

export function siteUrl(): string {
  return requiredUrl(
    "MRJIM_SITE_URL",
    process.env.MRJIM_SITE_URL ?? process.env.NEXT_PUBLIC_SITE_URL,
  );
}

export function sitePath(pathname: string): string {
  if (!/^\/[A-Za-z0-9._~!$&'()*+,;=:@%/?-]*$/u.test(pathname)) {
    throw new Error("site path is malformed");
  }
  return new URL(pathname, `${siteUrl()}/`).href;
}

/** Creates a fresh request-local cookie-backed client for a Route Handler or Server Component. */
export async function createRequestAuthClient() {
  const cookieStore = await cookies();
  const requestHeaders = await headers();

  return createServerClient(authUrl(), publishableKey(), {
    cookies: {
      getAll: () => cookieStore.getAll(),
      setAll: (values: readonly CookieToSet[]) => {
        for (const { name, value, options } of values) {
          cookieStore.set(name, value, options);
        }
      },
    },
    headers: {
      "x-request-id": requestHeaders.get("x-request-id") ?? crypto.randomUUID(),
    },
    auth: { storageKey: "nextjs-app-router" },
  });
}

export interface ServerAuthState {
  readonly client: Awaited<ReturnType<typeof createRequestAuthClient>>;
  readonly user: User | null;
  readonly permissions: readonly string[];
  readonly error: AuthError | null;
}

/**
 * Reads the user through the auth server's validated `/user` boundary.
 * Cookie `getSession()` is deliberately not used as authorization proof.
 */
export async function getServerAuthState(): Promise<ServerAuthState> {
  const client = await createRequestAuthClient();
  const userResult = await client.auth.getUser();
  if (userResult.error !== null || userResult.data === null) {
    return {
      client,
      user: null,
      permissions: [],
      error: userResult.error,
    };
  }

  const permissionsResult = await client.auth.getPermissions();
  return {
    client,
    user: userResult.data.user,
    permissions: permissionsResult.error === null ? permissionsResult.data.permissions : [],
    error: permissionsResult.error,
  };
}
