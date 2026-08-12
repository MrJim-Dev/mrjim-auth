import type { Session, SupportedStorage } from "../shared/types.js";
import {
  awaitSafe,
  captureMethod,
  invoke,
  isObjectLike,
  ownData,
  parseJson,
  snapshotJson,
  stringifyJson,
} from "./boundary.js";

const storageObjectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const storageObjectHasOwnProperty = Object.prototype.hasOwnProperty;
const storageReflectApply = Reflect.apply;
const storageMap = Map;
const storageMapGet = Map.prototype.get;
const storageMapSet = Map.prototype.set;
const storageMapDelete = Map.prototype.delete;
const storageMapClear = Map.prototype.clear;
const storageMapHas = Map.prototype.has;
const storageArrayIsArray = Array.isArray;
const storageArrayPush = Array.prototype.push;
const storageArraySplice = Array.prototype.splice;
const storageObjectFreeze = Object.freeze;
const storageNumberIsSafeInteger = Number.isSafeInteger;
const storageMathMax = Math.max;
const storageDateNow = Date.now;
const storagePromiseThen = Promise.prototype.then;
const storagePromiseResolve = Promise.resolve.bind(Promise);
const storageGlobal = globalThis;
const storageJsonVersion = 1;
const STORAGE_RECORD_MAX = 1024 * 1024;
const PKCE_RECORD_MAX = 64 * 1024;

export interface PkceTransaction {
  readonly id: string;
  readonly provider: string;
  readonly flow: "sign_in" | "link_identity";
  readonly codeVerifier: string;
  readonly codeChallenge: string;
  readonly redirectTo: string;
  readonly createdAt: number;
  readonly expiresAt: number;
}

export interface StorageController {
  readonly storageKey: string;
  readonly sessionKey: string;
  readonly pkceKey: string;
  readonly persistent: boolean;
  readSession(): Promise<Session | null>;
  writeSession(session: Session): Promise<number>;
  clearSession(): Promise<number>;
  readRevision(): Promise<number>;
  writePkce(transaction: PkceTransaction): Promise<void>;
  findPkce(criteria?: { readonly flow?: PkceTransaction["flow"]; readonly redirectTo?: string }): Promise<PkceTransaction | null>;
  consumePkce(id: string): Promise<PkceTransaction | null>;
}

class StorageBoundaryError extends Error {
  readonly name = "StorageBoundaryError";
}

function storageFailure(): StorageBoundaryError {
  return new StorageBoundaryError("storage operation failed");
}

function isRecord(value: unknown): value is object {
  return isObjectLike(value) && !storageArrayIsArray(value);
}

function validSafeSession(value: unknown): value is Session {
  if (!isRecord(value)) return false;
  const accessToken = ownData(value, "access_token");
  const refreshToken = ownData(value, "refresh_token");
  const tokenType = ownData(value, "token_type");
  const expiresIn = ownData(value, "expires_in");
  const expiresAt = ownData(value, "expires_at");
  const user = ownData(value, "user");
  if (!accessToken.ok || !accessToken.present || typeof accessToken.value !== "string" || accessToken.value.length === 0 || accessToken.value.length > 8192) return false;
  if (!refreshToken.ok || !refreshToken.present || typeof refreshToken.value !== "string" || refreshToken.value.length === 0 || refreshToken.value.length > 8192) return false;
  if (!tokenType.ok || !tokenType.present || tokenType.value !== "bearer") return false;
  if (!expiresIn.ok || !expiresIn.present || typeof expiresIn.value !== "number" || !storageNumberIsSafeInteger(expiresIn.value) || expiresIn.value <= 0) return false;
  if (!expiresAt.ok || !expiresAt.present || typeof expiresAt.value !== "number" || !storageNumberIsSafeInteger(expiresAt.value) || expiresAt.value <= 0) return false;
  return user.ok && user.present && isRecord(user.value);
}

function readRevisionFromRecord(value: unknown): number {
  if (!isRecord(value)) return 0;
  const version = ownData(value, "version");
  const revision = ownData(value, "revision");
  if (!version.ok || !version.present || version.value !== storageJsonVersion || !revision.ok || !revision.present || typeof revision.value !== "number" || !storageNumberIsSafeInteger(revision.value) || revision.value < 0) return 0;
  return revision.value;
}

function readSessionFromRecord(value: unknown): Session | null {
  if (!isRecord(value)) return null;
  const version = ownData(value, "version");
  const session = ownData(value, "session");
  if (!version.ok || !version.present || version.value !== storageJsonVersion || !session.ok || !session.present) return null;
  if (session.value === null) return null;
  return validSafeSession(session.value) ? session.value : null;
}

function isValidPkce(value: unknown): value is PkceTransaction {
  if (!isRecord(value)) return false;
  const id = ownData(value, "id");
  const provider = ownData(value, "provider");
  const flow = ownData(value, "flow");
  const verifier = ownData(value, "codeVerifier");
  const challenge = ownData(value, "codeChallenge");
  const redirect = ownData(value, "redirectTo");
  const created = ownData(value, "createdAt");
  const expires = ownData(value, "expiresAt");
  return id.ok && id.present && typeof id.value === "string" && id.value.length > 0 && id.value.length <= 128
    && provider.ok && provider.present && typeof provider.value === "string" && provider.value.length > 0 && provider.value.length <= 128
    && flow.ok && flow.present && (flow.value === "sign_in" || flow.value === "link_identity")
    && verifier.ok && verifier.present && typeof verifier.value === "string" && verifier.value.length >= 43 && verifier.value.length <= 128
    && challenge.ok && challenge.present && typeof challenge.value === "string" && challenge.value.length >= 20 && challenge.value.length <= 256
    && redirect.ok && redirect.present && typeof redirect.value === "string" && redirect.value.length > 0 && redirect.value.length <= 2048
    && created.ok && created.present && typeof created.value === "number" && storageNumberIsSafeInteger(created.value)
    && expires.ok && expires.present && typeof expires.value === "number" && storageNumberIsSafeInteger(expires.value) && expires.value > created.value;
}

function getDefaultStorage(): SupportedStorage | null {
  let candidate: unknown;
  try {
    const descriptor = storageObjectGetOwnPropertyDescriptor(storageGlobal, "localStorage");
    if (descriptor !== undefined && !storageReflectApply(storageObjectHasOwnProperty, descriptor, ["value"]) && typeof descriptor.get !== "function") return null;
    candidate = (storageGlobal as unknown as { readonly localStorage?: unknown }).localStorage;
  } catch {
    return null;
  }
  if (!isObjectLike(candidate)) return null;
  try {
    captureMethod(candidate, "getItem", "localStorage.getItem", "programming");
    captureMethod(candidate, "setItem", "localStorage.setItem", "programming");
    captureMethod(candidate, "removeItem", "localStorage.removeItem", "programming");
    return candidate as SupportedStorage;
  } catch {
    return null;
  }
}

function createMemoryStorage(): SupportedStorage {
  const values = new storageMap<string, string>();
  return {
    getItem(key) {
      try {
        return storageMapGet.call(values, key) ?? null;
      } catch {
        throw storageFailure();
      }
    },
    setItem(key, value) {
      try {
        storageMapSet.call(values, key, value);
      } catch {
        throw storageFailure();
      }
    },
    removeItem(key) {
      try {
        storageMapDelete.call(values, key);
      } catch {
        throw storageFailure();
      }
    },
  };
}

function captureStorage(value: SupportedStorage): SupportedStorage {
  if (!isObjectLike(value)) throw new StorageBoundaryError("storage is malformed");
  const getItem = captureMethod(value, "getItem", "storage.getItem", "configuration");
  const setItem = captureMethod(value, "setItem", "storage.setItem", "configuration");
  const removeItem = captureMethod(value, "removeItem", "storage.removeItem", "configuration");
  return {
    async getItem(key) {
      try {
        const result = await awaitSafe(invoke<unknown>(getItem.method, getItem.receiver, [key]), "storage.getItem");
        if (result !== null && typeof result !== "string") throw storageFailure();
        return result;
      } catch {
        throw storageFailure();
      }
    },
    async setItem(key, value) {
      try {
        await awaitSafe(invoke<unknown>(setItem.method, setItem.receiver, [key, value]), "storage.setItem");
      } catch {
        throw storageFailure();
      }
    },
    async removeItem(key) {
      try {
        await awaitSafe(invoke<unknown>(removeItem.method, removeItem.receiver, [key]), "storage.removeItem");
      } catch {
        throw storageFailure();
      }
    },
  };
}

function safeStoredSession(value: Session): Session {
  const snapshot = snapshotJson(value, "session");
  if (!validSafeSession(snapshot)) throw storageFailure();
  return snapshot;
}

function safeStoredPkce(value: PkceTransaction): PkceTransaction {
  const snapshot = snapshotJson(value, "PKCE transaction");
  if (!isValidPkce(snapshot)) throw storageFailure();
  return snapshot;
}

async function removeQuiet(storage: SupportedStorage, key: string): Promise<void> {
  try {
    await storage.removeItem(key);
  } catch {
    // Malformed or unavailable storage is fail-closed.
  }
}

export function createStorageController(options: {
  readonly storageKey: string;
  readonly storage?: SupportedStorage | undefined;
  readonly persistSession: boolean;
}): StorageController {
  const persistent = options.persistSession;
  const provided = options.storage === undefined ? undefined : captureStorage(options.storage);
  const backing = persistent
    ? provided ?? captureStorage(getDefaultStorage() ?? createMemoryStorage())
    : captureStorage(createMemoryStorage());
  const sessionKey = `mrjim-auth:${options.storageKey}`;
  const pkceKey = `${sessionKey}:pkce`;
  let writeQueue = storagePromiseResolve();
  let localRevision = 0;

  const enqueue = <T>(operation: () => Promise<T>): Promise<T> => {
    const next = storageReflectApply(storagePromiseThen, writeQueue, [operation, operation]) as Promise<T>;
    writeQueue = storageReflectApply(storagePromiseThen, next, [() => undefined, () => undefined]) as Promise<void>;
    return next;
  };

  const readRecord = async (): Promise<{ readonly revision: number; readonly session: Session | null }> => {
    let raw: string | null;
    try {
      raw = await backing.getItem(sessionKey);
    } catch {
      throw storageFailure();
    }
    if (raw === null) return { revision: localRevision, session: null };
    if (raw.length > STORAGE_RECORD_MAX) {
      await removeQuiet(backing, sessionKey);
      return { revision: localRevision, session: null };
    }
    try {
      const parsed = parseJson(raw, "stored session");
      const revision = readRevisionFromRecord(parsed);
      const session = readSessionFromRecord(parsed);
      const storedSession = isRecord(parsed) ? ownData(parsed, "session") : { ok: false as const, present: false };
      const record = isRecord(parsed) && storedSession.ok && storedSession.present && (storedSession.value === null || session !== null);
      if (!record) {
        await removeQuiet(backing, sessionKey);
        return { revision: localRevision, session: null };
      }
      localRevision = storageMathMax(localRevision, revision);
      return { revision, session };
    } catch {
      await removeQuiet(backing, sessionKey);
      return { revision: localRevision, session: null };
    }
  };

  const writeRecord = async (session: Session | null): Promise<number> => enqueue(async () => {
    const latest = await readRecord();
    const revision = storageMathMax(localRevision, latest.revision) + 1;
    const safeSession = session === null ? null : safeStoredSession(session);
    const record = { version: storageJsonVersion, revision, session: safeSession };
    const serialized = stringifyJson(record, "stored session");
    await backing.setItem(sessionKey, serialized);
    localRevision = revision;
    return revision;
  });

  const writeSession = (session: Session): Promise<number> => writeRecord(session);

  const readPkceTransactions = async (): Promise<PkceTransaction[]> => {
    let raw: string | null;
    try {
      raw = await backing.getItem(pkceKey);
    } catch {
      throw storageFailure();
    }
    if (raw === null) return [];
    if (raw.length > PKCE_RECORD_MAX) {
      await removeQuiet(backing, pkceKey);
      return [];
    }
    try {
      const parsed = parseJson(raw, "stored PKCE transaction");
      if (!isRecord(parsed)) throw storageFailure();
      const version = ownData(parsed, "version");
      const transactions = ownData(parsed, "transactions");
      if (!version.ok || !version.present || version.value !== storageJsonVersion || !transactions.ok || !transactions.present || !storageArrayIsArray(transactions.value) || transactions.value.length > 4) throw storageFailure();
      const output: PkceTransaction[] = [];
      for (let index = 0; index < transactions.value.length; index += 1) {
        const item = transactions.value[index];
        if (item !== undefined && isValidPkce(item) && item.expiresAt > storageDateNow()) storageArrayPush.call(output, item);
      }
      if (output.length !== transactions.value.length) {
        if (output.length === 0) await removeQuiet(backing, pkceKey);
        else await backing.setItem(pkceKey, stringifyJson({ version: storageJsonVersion, transactions: output }, "stored PKCE transaction"));
      }
      return output;
    } catch {
      await removeQuiet(backing, pkceKey);
      return [];
    }
  };

  const writePkceTransactions = async (transactions: readonly PkceTransaction[]): Promise<void> => {
    if (transactions.length === 0) {
      await backing.removeItem(pkceKey);
      return;
    }
    const serialized = stringifyJson({ version: storageJsonVersion, transactions }, "stored PKCE transaction");
    await backing.setItem(pkceKey, serialized);
  };

  const controller: StorageController = {
    storageKey: options.storageKey,
    sessionKey,
    pkceKey,
    persistent,
    async readSession() {
      return (await readRecord()).session;
    },
    writeSession,
    clearSession() {
      return writeRecord(null);
    },
    async readRevision() {
      return (await readRecord()).revision;
    },
    writePkce(transaction) {
      return enqueue(async () => {
        const transactions = await readPkceTransactions();
        const next: PkceTransaction[] = [];
        for (let index = 0; index < transactions.length; index += 1) {
          const item = transactions[index];
          if (item !== undefined && item.id !== transaction.id && item.expiresAt > storageDateNow()) storageArrayPush.call(next, item);
        }
        storageArrayPush.call(next, safeStoredPkce(transaction));
        if (next.length > 4) storageArraySplice.call(next, 0, next.length - 4);
        await writePkceTransactions(next);
      });
    },
    async findPkce(criteria) {
      const transactions = await readPkceTransactions();
      for (let index = transactions.length - 1; index >= 0; index -= 1) {
        const item = transactions[index];
        if (item !== undefined && (criteria?.flow === undefined || item.flow === criteria.flow) && (criteria?.redirectTo === undefined || item.redirectTo === criteria.redirectTo)) return item;
      }
      return null;
    },
    consumePkce(id) {
      return enqueue(async () => {
        const transactions = await readPkceTransactions();
        let found: PkceTransaction | null = null;
        const remaining: PkceTransaction[] = [];
        for (let index = 0; index < transactions.length; index += 1) {
          const item = transactions[index];
          if (item === undefined) continue;
          if (item.id === id && found === null) found = item;
          else storageArrayPush.call(remaining, item);
        }
        await writePkceTransactions(remaining);
        return found;
      });
    },
  };
  return storageObjectFreeze(controller);
}

export { StorageBoundaryError };
