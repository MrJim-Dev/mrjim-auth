import type { AuthApiError, AuthConfigurationError, AuthProgrammingError } from "../shared/errors.js";

/** Errors intentionally created by trusted server-side policy code. */
export type TrustedServiceError = AuthApiError | AuthConfigurationError | AuthProgrammingError;

/*
 * The thrown marker is deliberately only an identity.  Its trusted error is
 * kept in module-private state so an injected transaction cannot read,
 * replace, serialize, or otherwise influence the value restored by a caller.
 */
const trustedFailures = new WeakMap<object, TrustedServiceError>();

class TrustedServiceFailure extends Error {
  constructor(error: TrustedServiceError) {
    super("trusted service failure");
    Object.setPrototypeOf(this, TrustedServiceFailure.prototype);
    Object.defineProperty(this, "name", {
      value: "TrustedServiceFailure",
      configurable: false,
      enumerable: false,
      writable: false,
    });
    Object.defineProperty(this, "stack", {
      value: "TrustedServiceFailure",
      configurable: false,
      enumerable: false,
      writable: false,
    });
    trustedFailures.set(this, error);
    Object.freeze(this);
  }
}

Object.freeze(TrustedServiceFailure.prototype);

const adapterFailures = new WeakSet<object>();

/** Fixed marker for any arbitrary value thrown by an injected adapter. */
class AdapterBoundaryFailure extends Error {
  constructor() {
    super("adapter operation failed");
    Object.setPrototypeOf(this, AdapterBoundaryFailure.prototype);
    Object.defineProperty(this, "name", {
      value: "AdapterBoundaryFailure",
      configurable: false,
      enumerable: false,
      writable: false,
    });
    Object.defineProperty(this, "stack", {
      value: "AdapterBoundaryFailure",
      configurable: false,
      enumerable: false,
      writable: false,
    });
    adapterFailures.add(this);
    Object.freeze(this);
  }
}

Object.freeze(AdapterBoundaryFailure.prototype);

/** Identifies only the exact fixed adapter marker created in this module. */
export function isAdapterBoundaryFailure(error: unknown): boolean {
  if (error === null || (typeof error !== "object" && typeof error !== "function")) return false;
  return adapterFailures.has(error);
}

/** Marks a service-owned expected/configuration error before an adapter call. */
export function trustedFailure(error: TrustedServiceError): never {
  throw new TrustedServiceFailure(error);
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
    throw new AdapterBoundaryFailure();
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
    throw new AdapterBoundaryFailure();
  }
}
