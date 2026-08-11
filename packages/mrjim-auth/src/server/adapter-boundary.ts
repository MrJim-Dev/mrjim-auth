import type { AuthApiError, AuthConfigurationError, AuthProgrammingError } from "../shared/errors.js";

/** Errors intentionally created by trusted server-side policy code. */
export type TrustedServiceError = AuthApiError | AuthConfigurationError | AuthProgrammingError;

/*
 * The thrown marker is deliberately only an identity.  Its trusted error is
 * kept in module-private state so an injected transaction cannot read,
 * replace, serialize, or otherwise influence the value restored by a caller.
 */
const trustedFailures = new WeakMap<object, TrustedServiceError>();

function trustedFailureMarker(error: TrustedServiceError): object {
  // A null-prototype object has no constructor, inherited fields, accessors,
  // error surface, or constructible prototype for an adapter to discover.
  const marker = Object.create(null) as object;
  trustedFailures.set(marker, error);
  return Object.freeze(marker);
}

const adapterFailures = new WeakSet<object>();

/** Fixed marker for any arbitrary value thrown by an injected adapter. */
function adapterFailureMarker(): object {
  const marker = Object.create(null) as object;
  adapterFailures.add(marker);
  return Object.freeze(marker);
}

/** Identifies only the exact fixed adapter marker created in this module. */
export function isAdapterBoundaryFailure(error: unknown): boolean {
  if (error === null || (typeof error !== "object" && typeof error !== "function")) return false;
  return adapterFailures.has(error);
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
      const trusted = trustedFailures.get(error);
      if (trusted !== undefined) return onTrustedFailure(trusted);
    }
    throw adapterFailureMarker();
  }
}
