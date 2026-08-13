import { createClient, type ClientOptions, type MrJimAuthClient } from "../index.js";

interface BrowserBinding {
  readonly authUrl: string;
  readonly key: string | undefined;
  readonly signature: string;
  readonly fetch: unknown;
  readonly storage: unknown;
  readonly lock: unknown;
  readonly debug: unknown;
  readonly client: MrJimAuthClient;
}

const browserClients = new Map<string, BrowserBinding>();

function optionSignature(options: ClientOptions | undefined): string {
  const auth = options?.auth;
  const headers = options?.global?.headers ?? {};
  const headerEntries = Object.keys(headers).sort().map((key) => [key.toLowerCase(), headers[key]]);
  return JSON.stringify({
    autoRefreshToken: auth?.autoRefreshToken,
    persistSession: auth?.persistSession,
    detectSessionInUrl: auth?.detectSessionInUrl,
    flowType: auth?.flowType,
    skipAutoInitialize: auth?.skipAutoInitialize,
    storageUrl: options?.storage?.url,
    headers: headerEntries,
  });
}

/** Returns one browser auth client per module realm and storage key. */
export function createBrowserClient(
  authUrl: string,
  publishableKey?: string,
  options?: ClientOptions,
): MrJimAuthClient {
  const storageKey = options?.auth?.storageKey ?? "default";
  if (typeof storageKey !== "string" || !/^[A-Za-z0-9._-]{1,128}$/u.test(storageKey)) throw new TypeError("Browser client storage key is malformed");
  let canonicalUrl: string;
  try {
    const parsed = new URL(authUrl);
    canonicalUrl = parsed.href.endsWith("/") ? parsed.href.slice(0, -1) : parsed.href;
  } catch {
    throw new TypeError("Browser auth URL is malformed");
  }
  const signature = optionSignature(options);
  const existing = browserClients.get(storageKey);
  if (existing !== undefined) {
    if (existing.authUrl !== canonicalUrl || existing.key !== publishableKey || existing.signature !== signature
      || existing.fetch !== options?.global?.fetch || existing.storage !== options?.auth?.storage
      || existing.lock !== options?.auth?.lock || existing.debug !== options?.auth?.debug) {
      throw new TypeError("Browser auth storage key is already bound to conflicting configuration");
    }
    return existing.client;
  }
  const client = createClient(authUrl, publishableKey, options);
  browserClients.set(storageKey, Object.freeze({
    authUrl: canonicalUrl,
    key: publishableKey,
    signature,
    fetch: options?.global?.fetch,
    storage: options?.auth?.storage,
    lock: options?.auth?.lock,
    debug: options?.auth?.debug,
    client,
  }));
  return client;
}
