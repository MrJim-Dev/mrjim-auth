import { createClient, type ClientOptions, type MrJimAuthClient } from "../index.js";
import { createCookieStorage, type CookieAdapter, type Cookie, type CookieOptions, type CookieToSet } from "../server/cookies.js";

export interface ServerClientOptions {
  readonly cookies: CookieAdapter;
  readonly headers?: Readonly<Record<string, string>>;
  readonly secure?: boolean;
  readonly cookieName?: string;
  readonly cookiePath?: string;
  readonly auth?: Omit<NonNullable<ClientOptions["auth"]>, "storage" | "persistSession" | "detectSessionInUrl" | "autoRefreshToken">;
  readonly global?: ClientOptions["global"];
}

function safeHeaders(...sources: Array<Readonly<Record<string, string>> | undefined>): Record<string, string> {
  const output: Record<string, string> = Object.create(null) as Record<string, string>;
  for (const source of sources) {
    if (source === undefined || source === null || typeof source !== "object" || Array.isArray(source)) continue;
    for (const key of Object.keys(source)) {
      const descriptor = Object.getOwnPropertyDescriptor(source, key);
      if (descriptor === undefined || !("value" in descriptor) || typeof descriptor.value !== "string") throw new TypeError("Server client headers are malformed");
      output[key] = descriptor.value;
    }
  }
  return output;
}

/** Creates one request-local, cookie-backed user auth client. */
export function createServerClient(
  authUrl: string,
  publishableKey: string,
  options: ServerClientOptions,
): MrJimAuthClient {
  if (options === null || typeof options !== "object" || Array.isArray(options)) throw new TypeError("Server client options are malformed");
  let parsed: URL;
  try { parsed = new URL(authUrl); } catch { throw new TypeError("Server auth URL is malformed"); }
  const storageKey = options.auth?.storageKey ?? "default";
  const secure = options.secure ?? parsed.protocol === "https:";
  const storage = createCookieStorage({
    adapter: options.cookies,
    storageKey,
    secure,
    ...(options.cookieName === undefined ? {} : { cookieName: options.cookieName }),
    ...(options.cookiePath === undefined ? {} : { path: options.cookiePath }),
  });
  const headers = safeHeaders(options.global?.headers, options.headers);
  return createClient(authUrl, publishableKey, {
    auth: {
      ...options.auth,
      storageKey,
      storage,
      persistSession: true,
      detectSessionInUrl: false,
      autoRefreshToken: false,
    },
    global: {
      ...(options.global?.fetch === undefined ? {} : { fetch: options.global.fetch }),
      headers,
    },
  });
}

export type { Cookie, CookieAdapter, CookieOptions, CookieToSet };
