import type { AuthApiError, AuthConfigurationError, AuthProgrammingError } from "../shared/errors.js";

/** Errors intentionally created by trusted server-side policy code. */
export type TrustedServiceError = AuthApiError | AuthConfigurationError | AuthProgrammingError;

/*
 * The thrown marker is deliberately only an identity.  Its trusted error is
 * kept in module-private state so an injected transaction cannot read,
 * replace, serialize, or otherwise influence the value restored by a caller.
 */
const trustedFailures = new WeakMap<object, TrustedServiceError>();
const adapterFailures = new WeakSet<object>();

// Capture the realm intrinsics before any injected adapter executes. Adapter
// callbacks run in-process and may temporarily replace prototype methods; the
// security boundary must not dispatch through those mutable properties after
// control has crossed into adapter code.
const weakMapGet = Function.prototype.call.bind(WeakMap.prototype.get) as <K extends object, V>(
  map: WeakMap<K, V>,
  key: K,
) => V | undefined;
const weakMapSet = Function.prototype.call.bind(WeakMap.prototype.set) as <K extends object, V>(
  map: WeakMap<K, V>,
  key: K,
  value: V,
) => WeakMap<K, V>;
const weakSetAdd = Function.prototype.call.bind(WeakSet.prototype.add) as <T extends object>(
  set: WeakSet<T>,
  value: T,
) => WeakSet<T>;
const weakSetHas = Function.prototype.call.bind(WeakSet.prototype.has) as <T extends object>(
  set: WeakSet<T>,
  value: T,
) => boolean;
const objectCreate = Object.create;
const objectFreeze = Object.freeze;

function trustedFailureMarker(error: TrustedServiceError): object {
  // A null-prototype object has no constructor, inherited fields, accessors,
  // error surface, or constructible prototype for an adapter to discover.
  const marker = objectCreate(null) as object;
  weakMapSet(trustedFailures, marker, error);
  return objectFreeze(marker);
}

/** Fixed marker for any arbitrary value thrown by an injected adapter. */
function adapterFailureMarker(): object {
  const marker = objectCreate(null) as object;
  weakSetAdd(adapterFailures, marker);
  return objectFreeze(marker);
}

/** Identifies only the exact fixed adapter marker created in this module. */
export function isAdapterBoundaryFailure(error: unknown): boolean {
  if (error === null || (typeof error !== "object" && typeof error !== "function")) return false;
  return weakSetHas(adapterFailures, error);
}

/** Marks a service-owned expected/configuration error before an adapter call. */
export function trustedFailure(error: TrustedServiceError): never {
  throw trustedFailureMarker(error);
}

/** Trusted prevalidation never crosses an adapter transaction. */
export function trustedValidation<T>(operation: () => T): T {
  return operation();
}

/** Trusted server-service failures are already outside an adapter transaction. */
export async function trustedAsync<T>(operation: () => Promise<T>): Promise<T> {
  return operation();
}

/** Executes one injected operation without retaining or inspecting its thrown value. */
export async function adapterCall<T>(operation: () => Promise<T>): Promise<T> {
  try {
    return await operation();
  } catch {
    throw adapterFailureMarker();
  }
}

/** Executes an adapter-owned transaction while preserving only an exact trusted marker. */
export async function adapterTransaction<T>(
  operation: () => Promise<T>,
  onTrustedFailure: (error: TrustedServiceError) => never,
): Promise<T> {
  try {
    return await operation();
  } catch (error) {
    if (error !== null && (typeof error === "object" || typeof error === "function")) {
      const trusted = weakMapGet(trustedFailures, error);
      if (trusted !== undefined) return onTrustedFailure(trusted);
    }
    throw adapterFailureMarker();
  }
}
