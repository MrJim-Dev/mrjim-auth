/**
 * Creates the browser-safe Task 1 client scaffold.
 *
 * @remarks
 * Compatibility status: experimental Task 1 scaffold only. The returned
 * object is immutable and intentionally has no `auth` methods, network calls,
 * storage behavior, or expected authentication-operation failures. The full
 * Supabase-inspired client contract is planned for a later task. When that
 * contract is implemented, expected failures must use `{ data, error }`.
 *
 * @param _baseUrl - Project-owned `/auth/v1` URL reserved for the future client.
 * @param _publishableKey - Project publishable key reserved for the future client.
 * @param _options - Future client options; ignored by the Task 1 scaffold.
 * @returns An immutable empty object with no authentication operations.
 *
 * @example
 * ```ts
 * import { createClient } from "mrjim-auth";
 *
 * const client = createClient(
 *   "https://project.example.com/auth/v1",
 *   "publishable-key",
 * );
 *
 * // Task 1 scaffold: no auth methods are exposed yet.
 * console.log(Object.keys(client)); // []
 * ```
 *
 * @since 0.1.0
 * @experimental
 */
export function createClient(
  _baseUrl: string,
  _publishableKey?: string,
  _options?: unknown,
): Readonly<Record<string, never>> {
  return Object.freeze({});
}
