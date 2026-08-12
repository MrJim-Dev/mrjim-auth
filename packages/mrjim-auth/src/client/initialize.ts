import type { AuthChangeEvent, Session } from "../shared/types.js";
import { safeStringIncludes, safeStringSlice, safeStringStartsWith } from "../shared/safe-intrinsics.js";
import { captureMethod, invoke, ownData, snapshotJson, type BoundaryResult } from "./boundary.js";
import type { PkceTransaction, StorageController } from "./storage.js";

const initializeGlobal = globalThis as unknown as Record<string, unknown>;
const initializeURL = URL;
const initializeURLSearchParams = URLSearchParams;
const initializeObjectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const initializeObjectGetPrototypeOf = Object.getPrototypeOf;
const initializeObjectHasOwnProperty = Object.prototype.hasOwnProperty;
const initializeReflectApply = Reflect.apply;
const initializeString = String;
const initializeAuthParamNames = [
  "code",
  "state",
  "error",
  "error_code",
  "error_description",
  "access_token",
  "refresh_token",
  "expires_in",
  "expires_at",
  "token_type",
  "type",
] as const;
const initializeParamsDelete = captureMethod(initializeURLSearchParams.prototype, "delete", "URLSearchParams.delete", "configuration");
const initializeParamsGet = captureMethod(initializeURLSearchParams.prototype, "get", "URLSearchParams.get", "configuration");
const initializeParamsGetAll = captureMethod(initializeURLSearchParams.prototype, "getAll", "URLSearchParams.getAll", "configuration");
const initializeParamsToString = captureMethod(initializeURLSearchParams.prototype, "toString", "URLSearchParams.toString", "configuration");
const initializeLocationHref = (() => {
  try {
    const location = initializeGlobal.location;
    if (location === null || typeof location !== "object") return null;
    let current: object | null = location;
    for (let depth = 0; current !== null && depth < 16; depth += 1) {
      const descriptor = initializeObjectGetOwnPropertyDescriptor(current, "href");
      if (descriptor !== undefined) {
        if (typeof descriptor.get === "function") return { receiver: location, getter: descriptor.get };
        if (initializeReflectApply(initializeObjectHasOwnProperty, descriptor, ["value"]) && typeof descriptor.value === "string") {
          return { receiver: location, getter: () => descriptor.value };
        }
        return null;
      }
      current = initializeObjectGetPrototypeOf(current) as object | null;
    }
    return null;
  } catch {
    return null;
  }
})();
const initializeHistoryWriters = (() => {
  try {
    const history = initializeGlobal.history;
    if (history === null || typeof history !== "object") return null;
    let replace: ReturnType<typeof captureMethod> | null = null;
    let push: ReturnType<typeof captureMethod> | null = null;
    try { replace = captureMethod(history, "replaceState", "history.replaceState"); } catch { replace = null; }
    try { push = captureMethod(history, "pushState", "history.pushState"); } catch { push = null; }
    return replace === null && push === null ? null : { replace, push };
  } catch {
    return null;
  }
})();

export interface UrlSnapshot {
  readonly href: string;
  readonly cleanedHref: string;
  readonly code: string | null;
  readonly recovery: boolean;
  readonly hasAuthMarker: boolean;
}

export interface InitializationResult {
  readonly session: Session | null;
  readonly postEvent?: { readonly event: AuthChangeEvent; readonly session: Session };
}

export interface InitializeOptions {
  readonly storage: StorageController;
  readonly detectSessionInUrl: boolean;
  readonly debug?: ((message: string, context?: unknown) => void) | undefined;
  readonly exchange: (code: string, transaction: PkceTransaction) => Promise<{ readonly session: Session; readonly event?: AuthChangeEvent }>;
}

function safeDebug(debug: InitializeOptions["debug"], message: string, context: Record<string, unknown>): void {
  if (debug === undefined) return;
  try {
    debug(message, context);
  } catch {
    // Debug is observational only.
  }
}

function currentHref(): string | null {
  try {
    if (initializeLocationHref === null) return null;
    const href = initializeReflectApply(initializeLocationHref.getter, initializeLocationHref.receiver, []);
    return typeof href === "string" ? href : null;
  } catch {
    return null;
  }
}

function getParam(params: URLSearchParams, key: string): string | null {
  try {
    return initializeReflectApply(initializeParamsGet.method, params, [key]) as string | null;
  } catch {
    return null;
  }
}

function getSingleParam(params: URLSearchParams, key: string): { readonly valid: boolean; readonly value: string | null } {
  try {
    const values = initializeReflectApply(initializeParamsGetAll.method, params, [key]) as string[];
    if (values.length > 1) return { valid: false, value: null };
    const value = values[0];
    return { valid: true, value: value === undefined ? null : value };
  } catch {
    return { valid: false, value: null };
  }
}

function removeAuthParams(params: URLSearchParams): void {
  for (let index = 0; index < initializeAuthParamNames.length; index += 1) {
    const name = initializeAuthParamNames[index];
    try {
      initializeReflectApply(initializeParamsDelete.method, params, [name]);
    } catch {
      // A malformed URL object is ignored by the caller.
    }
  }
}

function removeAuthFromUrl(rawHref: string): UrlSnapshot | null {
  let parsed: URL;
  try {
    parsed = new initializeURL(rawHref);
  } catch {
    return null;
  }
  const searchParams = parsed.searchParams;
  const queryCode = getSingleParam(searchParams, "code");
  const queryType = getSingleParam(searchParams, "type");
  if (!queryCode.valid || !queryType.valid) return null;
  const code = queryCode.value;
  const error = getParam(searchParams, "error") ?? getParam(searchParams, "error_code");
  const type = queryType.value;
  const hashText = safeStringStartsWith(parsed.hash, "#") ? safeStringSlice(parsed.hash, 1) ?? "" : parsed.hash;
  let hashParams: URLSearchParams | null = null;
  let hashCode: string | null = null;
  let hashError: string | null = null;
  let hashType: string | null = null;
  if (safeStringIncludes(hashText, "=") || safeStringIncludes(hashText, "&")) {
    try {
      hashParams = new initializeURLSearchParams(hashText);
      const singleHashCode = getSingleParam(hashParams, "code");
      const singleHashType = getSingleParam(hashParams, "type");
      if (!singleHashCode.valid || !singleHashType.valid) return null;
      hashCode = singleHashCode.value;
      hashError = getParam(hashParams, "error") ?? getParam(hashParams, "error_code");
      hashType = singleHashType.value;
      removeAuthParams(hashParams);
    } catch {
      hashParams = null;
    }
  }
  if (code !== null && hashCode !== null) return null;
  removeAuthParams(searchParams);
  if (hashParams !== null) {
    const remainingHash = initializeReflectApply(initializeParamsToString.method, hashParams, []) as string;
    parsed.hash = remainingHash === "" ? "" : `#${remainingHash}`;
  }
  const cleanedHref = parsed.href;
  return {
    href: rawHref,
    cleanedHref,
    code: code ?? hashCode,
    recovery: type === "recovery" || hashType === "recovery",
    hasAuthMarker: code !== null || hashCode !== null || error !== null || hashError !== null,
  };
}

function replaceHistory(cleanedHref: string, debug: InitializeOptions["debug"]): boolean {
  if (initializeHistoryWriters === null) return false;
  const writers = [initializeHistoryWriters.replace, initializeHistoryWriters.push];
  for (let index = 0; index < writers.length; index += 1) {
    const writer = writers[index];
    if (writer === null || writer === undefined) continue;
    try {
      invoke(writer.method, writer.receiver, [null, "", cleanedHref]);
      if (currentHref() === cleanedHref) return true;
    } catch {
      // Try the next same-document history writer.
    }
  }
  safeDebug(debug, "auth URL cleanup unavailable", { source: "history" });
  return false;
}

export function readAuthUrl(): UrlSnapshot | null {
  const href = currentHref();
  return href === null ? null : removeAuthFromUrl(href);
}

export async function initializeAuthClient(options: InitializeOptions): Promise<InitializationResult> {
  let url: UrlSnapshot | null = null;
  let postEvent: InitializationResult["postEvent"];
  try {
    url = options.detectSessionInUrl ? readAuthUrl() : null;
    if (url?.hasAuthMarker === true && url.code !== null) {
      const transaction = await options.storage.findPkce({ redirectTo: url.cleanedHref });
      if (transaction !== null) {
        if (!replaceHistory(url.cleanedHref, options.debug)) throw new Error("auth URL cleanup failed");
        const consumed = await options.storage.consumePkce(transaction.id);
        if (consumed !== null && consumed.codeVerifier === transaction.codeVerifier) {
          try {
            const exchanged = await options.exchange(url.code, consumed);
            postEvent = { event: url.recovery ? "PASSWORD_RECOVERY" : exchanged.event ?? "SIGNED_IN", session: exchanged.session };
          } catch {
            safeDebug(options.debug, "auth URL exchange failed", { source: "url" });
          }
        }
      }
    }
  } catch {
    safeDebug(options.debug, "auth URL initialization failed", { source: "url" });
  }
  let session: Session | null = null;
  try {
    session = await options.storage.readSession();
  } catch {
    session = null;
  }
  return postEvent === undefined ? { session } : { session, postEvent };
}
