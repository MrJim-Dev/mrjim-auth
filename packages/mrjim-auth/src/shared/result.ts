import { assertPublicAuthError, type AuthError } from "./errors.js";

/**
 * The mutually exclusive result returned by expected SDK operations.
 *
 * @compatibility Supabase-inspired `{ data, error }` result contract.
 */
export type AuthResult<T> =
  | { data: T; error: null }
  | { data: null; error: AuthError };

/**
 * Creates a successful SDK result.
 *
 * @param data - The operation's successful response data.
 * @returns A result with data and a null error.
 *
 * @example
 * ```ts
 * const result = authSuccess({ user: null });
 * // result.error is null
 * ```
 *
 * @since 0.1.0
 */
export function authSuccess<T>(data: T): AuthResult<T> {
  return { data, error: null };
}

/**
 * Creates a failed SDK result for an expected auth/API failure.
 *
 * Configuration and programming failures must throw instead of using this
 * helper.
 *
 * @param error - The stable public auth error.
 * @returns A result with a null data value and the supplied error.
 *
 * @example
 * ```ts
 * const result = authFailure(new AuthApiError(
 *   "invalid_credentials",
 *   401,
 *   "Invalid login credentials",
 * ));
 * ```
 *
 * @since 0.1.0
 */
export function authFailure(error: AuthError): AuthResult<never> {
  assertPublicAuthError(error);
  return { data: null, error };
}
