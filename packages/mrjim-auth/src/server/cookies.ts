import { Buffer } from "node:buffer";
import type { SupportedStorage } from "../shared/types.js";

export interface Cookie { readonly name: string; readonly value: string; }
export interface CookieOptions {
  readonly httpOnly: true;
  readonly secure: boolean;
  readonly sameSite: "lax";
  readonly path: string;
  readonly maxAge?: number;
}
export interface CookieToSet extends Cookie { readonly options: CookieOptions; }
export interface CookieAdapter {
  getAll(): readonly Cookie[] | Promise<readonly Cookie[]>;
  setAll?(cookies: readonly CookieToSet[]): void | Promise<void>;
}
export interface CookieStorageOptions {
  readonly adapter: CookieAdapter;
  readonly storageKey: string;
  readonly cookieName?: string;
  readonly secure: boolean;
  readonly path?: string;
}

const reflectApply = Reflect.apply;
const getDescriptor = Object.getOwnPropertyDescriptor;
const getPrototype = Object.getPrototypeOf;
const arraySort = Array.prototype.sort;
const promisePrototype = Promise.prototype;
const jsonParse = JSON.parse;
const CHUNK_SIZE = 3_000;
const MAX_CHUNKS = 128;
const MAX_COOKIE_VALUE = 4_096;
const MAX_ENCODED = CHUNK_SIZE * MAX_CHUNKS;
const invalidRecord = "__invalid_mrjim_auth_cookie_record__";

class CookieBoundaryError extends Error { readonly name = "CookieBoundaryError"; }

function captureMethod(value: object, key: PropertyKey, required: boolean): Function | null {
  let current: object | null = value;
  for (let depth = 0; current !== null && depth < 16; depth += 1) {
    const descriptor = getDescriptor(current, key);
    if (descriptor !== undefined) {
      if (!("value" in descriptor) || typeof descriptor.value !== "function") throw new CookieBoundaryError("Cookie adapter is malformed");
      return descriptor.value;
    }
    current = getPrototype(current) as object | null;
  }
  if (required) throw new CookieBoundaryError("Cookie adapter is malformed");
  return null;
}

function validName(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= 128 && /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/u.test(value);
}

function baseName(options: CookieStorageOptions, key: string): string {
  const root = options.cookieName ?? (options.storageKey === "default" ? "mrjim-auth" : `mrjim-auth-${options.storageKey}`);
  if (!validName(root)) throw new CookieBoundaryError("Cookie name is malformed");
  const sessionKey = `mrjim-auth:${options.storageKey}`;
  if (key === sessionKey) {
    if (!validName(`${root}.127`)) throw new CookieBoundaryError("Cookie name is malformed");
    return root;
  }
  if (key === `${sessionKey}:pkce`) {
    const pkce = `${root}-pkce`;
    if (!validName(`${pkce}.127`)) throw new CookieBoundaryError("Cookie name is malformed");
    return pkce;
  }
  throw new CookieBoundaryError("Cookie storage key is malformed");
}

function snapshotCookies(value: unknown): readonly Cookie[] {
  if (!Array.isArray(value) || value.length > 256) throw new CookieBoundaryError("Cookie adapter result is malformed");
  const output: Cookie[] = [];
  const names = new Set<string>();
  for (const item of value) {
    if (item === null || typeof item !== "object") throw new CookieBoundaryError("Cookie adapter result is malformed");
    const name = getDescriptor(item, "name");
    const content = getDescriptor(item, "value");
    if (name === undefined || !("value" in name) || !validName(name.value)
      || content === undefined || !("value" in content) || typeof content.value !== "string"
      || content.value.length > MAX_COOKIE_VALUE || names.has(name.value)) throw new CookieBoundaryError("Cookie adapter result is malformed");
    names.add(name.value);
    output.push(Object.freeze({ name: name.value, value: content.value }));
  }
  return Object.freeze(output);
}

function attributes(options: CookieStorageOptions, clear = false): CookieOptions {
  const path = options.path ?? "/";
  if (typeof path !== "string" || !path.startsWith("/") || path.length > 1_024 || /[\x00-\x20;,\x7f]/u.test(path)) throw new CookieBoundaryError("Cookie path is malformed");
  return Object.freeze({ httpOnly: true, secure: options.secure, sameSite: "lax", path, ...(clear ? { maxAge: 0 } : {}) });
}

function isClearedSessionRecord(value: string): boolean {
  try {
    const parsed = reflectApply(jsonParse, JSON, [value]) as unknown;
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return false;
    const version = getDescriptor(parsed, "version");
    const revision = getDescriptor(parsed, "revision");
    const session = getDescriptor(parsed, "session");
    return version !== undefined && "value" in version && version.value === 1
      && revision !== undefined && "value" in revision && Number.isSafeInteger(revision.value) && (revision.value as number) >= 0
      && session !== undefined && "value" in session && session.value === null;
  } catch {
    return false;
  }
}

export function createCookieStorage(options: CookieStorageOptions): SupportedStorage {
  if (options.adapter === null || typeof options.adapter !== "object") throw new CookieBoundaryError("Cookie adapter is malformed");
  if (typeof options.storageKey !== "string" || !/^[A-Za-z0-9._-]{1,128}$/u.test(options.storageKey)) throw new CookieBoundaryError("Storage key is malformed");
  baseName(options, `mrjim-auth:${options.storageKey}`);
  baseName(options, `mrjim-auth:${options.storageKey}:pkce`);
  attributes(options);
  const getAll = captureMethod(options.adapter, "getAll", true)!;
  const setAll = captureMethod(options.adapter, "setAll", false);
  const read = async (): Promise<readonly Cookie[]> => {
    try {
      const result = reflectApply(getAll, options.adapter, []);
      if (Array.isArray(result)) return snapshotCookies(result);
      if (result === null || (typeof result !== "object" && typeof result !== "function") || getPrototype(result) !== promisePrototype) throw new CookieBoundaryError("Cookie adapter result is malformed");
      return snapshotCookies(await (result as Promise<unknown>));
    }
    catch { throw new CookieBoundaryError("Cookie read failed"); }
  };
  const write = async (values: readonly CookieToSet[]): Promise<void> => {
    if (setAll === null) throw new CookieBoundaryError("Cookie storage is read-only");
    try {
      const result = reflectApply(setAll, options.adapter, [values]);
      if (result !== undefined) {
        if (result === null || (typeof result !== "object" && typeof result !== "function") || getPrototype(result) !== promisePrototype) throw new CookieBoundaryError("Cookie adapter result is malformed");
        await (result as Promise<unknown>);
      }
    }
    catch { throw new CookieBoundaryError("Cookie write failed"); }
  };
  const clear = async (base: string): Promise<void> => {
    const existing = (await read()).filter((cookie) => cookie.name.startsWith(`${base}.`));
    const targets: readonly Cookie[] = existing.length === 0 ? [{ name: `${base}.0`, value: "" }] : existing;
    await write(Object.freeze(targets.map((cookie) => Object.freeze({ name: cookie.name, value: "", options: attributes(options, true) }))));
  };
  return Object.freeze({
    async getItem(key: string): Promise<string | null> {
      const base = baseName(options, key);
      const prefix = `${base}.`;
      const chunks: Array<{ index: number; value: string }> = [];
      for (const cookie of await read()) {
        if (!cookie.name.startsWith(prefix)) continue;
        const suffix = cookie.name.slice(prefix.length);
        if (!/^(0|[1-9][0-9]{0,2})$/u.test(suffix)) return invalidRecord;
        const index = Number(suffix);
        if (!Number.isSafeInteger(index) || index >= MAX_CHUNKS) return invalidRecord;
        chunks.push({ index, value: cookie.value });
      }
      if (chunks.length === 0) return null;
      reflectApply(arraySort, chunks, [(a: { index: number }, b: { index: number }) => a.index - b.index]);
      for (let index = 0; index < chunks.length; index += 1) if (chunks[index]?.index !== index) return invalidRecord;
      const encoded = chunks.map((chunk) => chunk.value).join("");
      if (encoded.length === 0 || encoded.length > MAX_ENCODED || !/^[A-Za-z0-9_-]+$/u.test(encoded)) return invalidRecord;
      try {
        const bytes = Buffer.from(encoded, "base64url");
        if (bytes.toString("base64url") !== encoded) return invalidRecord;
        return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
      } catch { return invalidRecord; }
    },
    async setItem(key: string, value: string): Promise<void> {
      if (typeof value !== "string") throw new CookieBoundaryError("Cookie value is malformed");
      const base = baseName(options, key);
      if (key === `mrjim-auth:${options.storageKey}` && isClearedSessionRecord(value)) {
        await clear(base);
        return;
      }
      const encoded = Buffer.from(value, "utf8").toString("base64url");
      if (encoded.length === 0 || encoded.length > MAX_ENCODED) throw new CookieBoundaryError("Cookie value is oversized");
      const chunks: string[] = [];
      for (let offset = 0; offset < encoded.length; offset += CHUNK_SIZE) chunks.push(encoded.slice(offset, offset + CHUNK_SIZE));
      const existing = (await read()).filter((cookie) => cookie.name.startsWith(`${base}.`));
      const writes: CookieToSet[] = chunks.map((chunk, index) => Object.freeze({ name: `${base}.${index}`, value: chunk, options: attributes(options) }));
      for (const cookie of existing) {
        const suffix = Number(cookie.name.slice(base.length + 1));
        if (!Number.isSafeInteger(suffix) || suffix >= chunks.length) writes.push(Object.freeze({ name: cookie.name, value: "", options: attributes(options, true) }));
      }
      await write(Object.freeze(writes));
    },
    async removeItem(key: string): Promise<void> {
      const base = baseName(options, key);
      await clear(base);
    },
  });
}
