import { AuthApiError, AuthConfigurationError } from "../shared/errors.js";
import type { LockFunction } from "../shared/types.js";
import { awaitSafe, captureMethod, invoke, freeze } from "./boundary.js";

const lockGlobal = globalThis as unknown as Record<string, unknown>;
const lockMap = Map;
const lockMapGet = Map.prototype.get;
const lockMapSet = Map.prototype.set;
const lockMapDelete = Map.prototype.delete;
const lockPromise = Promise;
const lockPromiseThen = Promise.prototype.then;
const lockPromiseResolve = Promise.resolve.bind(Promise);
const lockReflectApply = Reflect.apply;
const lockSetTimeout = setTimeout;
const lockClearTimeout = clearTimeout;
const lockNumberIsSafeInteger = Number.isSafeInteger;

const queues = new lockMap<string, Promise<void>>();

class LockBoundaryError extends Error {
  readonly name = "LockBoundaryError";
}

function timeoutError(): LockBoundaryError {
  return new LockBoundaryError("lock acquisition timed out");
}

function webLocks(): { readonly receiver: object; readonly request: Function } | null {
  try {
    const navigatorValue = lockGlobal.navigator;
    if (navigatorValue === null || typeof navigatorValue !== "object") return null;
    const locks = (navigatorValue as Record<string, unknown>).locks;
    if (locks === null || typeof locks !== "object") return null;
    const captured = captureMethod(locks, "request", "navigator.locks.request");
    return { receiver: captured.receiver, request: captured.method };
  } catch {
    return null;
  }
}

function withTimeout<T>(value: Promise<T>, timeoutMs: number): Promise<T> {
  if (!lockNumberIsSafeInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > 60_000) throw new AuthConfigurationError("lock timeout is malformed");
  return new lockPromise<T>((resolve, reject) => {
    const timer = lockSetTimeout(() => reject(timeoutError()), timeoutMs);
    lockReflectApply(lockPromiseThen, value, [
      (result) => {
        lockClearTimeout(timer);
        resolve(result);
      },
      (error) => {
        lockClearTimeout(timer);
        reject(error);
      },
    ]);
  });
}

async function fallbackLock<T>(name: string, timeoutMs: number, callback: () => Promise<T>): Promise<T> {
  const previous = lockMapGet.call(queues, name) ?? lockPromiseResolve();
  let release: (() => void) | undefined;
  const current = new lockPromise<void>((resolve) => { release = resolve; });
  const queued = lockReflectApply(lockPromiseThen, previous, [() => current, () => current]) as Promise<void>;
  lockMapSet.call(queues, name, queued);
  try {
    await withTimeout(previous, timeoutMs);
    return await withTimeout(callback(), timeoutMs);
  } finally {
    release?.();
    if (lockMapGet.call(queues, name) === queued) lockMapDelete.call(queues, name);
  }
}

export interface LockController {
  readonly run: <T>(callback: () => Promise<T>) => Promise<T>;
}

export function createLockController(options: {
  readonly storageKey: string;
  readonly lock?: LockFunction | undefined;
  readonly timeoutMs?: number;
}): LockController {
  const timeoutMs = options.timeoutMs ?? 10_000;
  if (!lockNumberIsSafeInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > 60_000) throw new AuthConfigurationError("lock timeout is malformed");
  const name = `mrjim-auth:${options.storageKey}`;
  let injected: LockFunction | undefined;
  if (options.lock !== undefined) {
    if (typeof options.lock !== "function") throw new AuthConfigurationError("lock must be a function");
    injected = options.lock;
  }
  const locks = injected === undefined ? webLocks() : null;

  const run = async <T>(callback: () => Promise<T>): Promise<T> => {
    if (injected !== undefined) {
      try {
        const result = invoke<unknown>(injected, undefined, [name, timeoutMs, callback]);
        return await withTimeout(awaitSafe(result as T | Promise<T>, "lock"), timeoutMs);
      } catch (error) {
        if (error instanceof LockBoundaryError) throw error;
        throw new LockBoundaryError("lock operation failed");
      }
    }
    if (locks !== null) {
      try {
        const result = invoke<unknown>(locks.request, locks.receiver, [name, { mode: "exclusive" }, callback]);
        return await withTimeout(awaitSafe(result as T | Promise<T>, "web lock"), timeoutMs);
      } catch (error) {
        if (error instanceof LockBoundaryError) throw error;
        // A missing/hostile Web Locks implementation falls back locally.
      }
    }
    return fallbackLock(name, timeoutMs, callback);
  };
  return freeze({ run });
}

export function isLockBoundaryError(value: unknown): value is LockBoundaryError {
  return value instanceof LockBoundaryError;
}

export { LockBoundaryError };
