import { AuthApiError, AuthConfigurationError, AuthProgrammingError } from "../shared/errors.js";

/** Errors intentionally created by trusted server-side policy code. */
export type TrustedServiceError = AuthApiError | AuthConfigurationError | AuthProgrammingError;

/**
 * Carries only a trusted, already-constructed error across an adapter call.
 * Adapter-thrown values are never stored here.
 */
class TrustedServiceFailure extends Error {
  readonly name = "TrustedServiceFailure" as const;

  constructor(readonly error: TrustedServiceError) {
    super("trusted service failure");
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

interface TrustedServiceFailureShape {
  readonly error: TrustedServiceError;
}

/** Identifies only failures created by this private module. */
export function isTrustedServiceFailure(error: unknown): error is TrustedServiceFailureShape {
  return error instanceof TrustedServiceFailure;
}

/** Fixed internal classification for an error crossing an injected boundary. */
export type AdapterFailureClass = "adapter_error" | "email_exists";

/**
 * Deliberately contains no adapter message, cause, stack, or arbitrary fields.
 */
export class AdapterBoundaryFailure extends Error {
  readonly name = "AdapterBoundaryFailure" as const;

  constructor(readonly classification: AdapterFailureClass = "adapter_error") {
    super("adapter operation failed");
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/** Marks a service-owned expected/configuration error before an adapter call. */
export function trustedFailure(error: TrustedServiceError): never {
  throw new TrustedServiceFailure(error);
}

/** Preserves trusted synchronous prevalidation while keeping adapter failures opaque. */
export function trustedValidation<T>(operation: () => T): T {
  try {
    return operation();
  } catch (error) {
    if (error instanceof AuthApiError || error instanceof AuthConfigurationError || error instanceof AuthProgrammingError) {
      throw new TrustedServiceFailure(error);
    }
    throw error;
  }
}

/** Preserves trusted failures from another server service, never adapter details. */
export async function trustedAsync<T>(operation: () => Promise<T>): Promise<T> {
  try {
    return await operation();
  } catch (error) {
    if (error instanceof AuthApiError || error instanceof AuthConfigurationError || error instanceof AuthProgrammingError) {
      throw new TrustedServiceFailure(error);
    }
    throw error;
  }
}

/** Executes one injected operation without retaining or inspecting its thrown value. */
export async function adapterCall<T>(operation: () => Promise<T>): Promise<T> {
  try {
    return await operation();
  } catch (error) {
    throw new AdapterBoundaryFailure(classifyAdapterFailure(error));
  }
}

/** Executes an adapter-owned transaction while preserving only trusted callback failures. */
export async function adapterTransaction<T>(operation: () => Promise<T>): Promise<T> {
  try {
    return await operation();
  } catch (error) {
    if (isTrustedServiceFailure(error)) throw error;
    throw new AdapterBoundaryFailure(classifyAdapterFailure(error));
  }
}

/**
 * The only adapter classification retained is the repository's fixed,
 * non-secret uniqueness outcome needed for an authenticated email-change
 * conflict. All other adapter values become `adapter_error`.
 */
function classifyAdapterFailure(error: unknown): AdapterFailureClass {
  try {
    if (
      typeof error === "object" &&
      error !== null &&
      (error as { readonly name?: unknown }).name === "PostgresRepositoryError" &&
      (error as { readonly code?: unknown }).code === "email_exists"
    ) return "email_exists";
  } catch {
    // A hostile adapter object may expose throwing getters; it remains opaque.
  }
  return "adapter_error";
}
