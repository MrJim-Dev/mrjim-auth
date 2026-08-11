/** Stable public error codes returned by expected SDK/API failures. */
export const AUTH_ERROR_CODES = {
  invalid_request: "invalid_request",
  invalid_credentials: "invalid_credentials",
  unauthorized: "unauthorized",
  forbidden: "forbidden",
  insufficient_permission: "insufficient_permission",
  not_found: "not_found",
  conflict: "conflict",
  invalid_token: "invalid_token",
  token_expired: "token_expired",
  refresh_token_reused: "refresh_token_reused",
  session_expired: "session_expired",
  otp_invalid: "otp_invalid",
  otp_expired: "otp_expired",
  otp_attempts_exceeded: "otp_attempts_exceeded",
  rate_limit_exceeded: "rate_limit_exceeded",
  redirect_not_allowed: "redirect_not_allowed",
  oauth_state_invalid: "oauth_state_invalid",
  oauth_provider_error: "oauth_provider_error",
  identity_already_linked: "identity_already_linked",
  identity_unlink_not_allowed: "identity_unlink_not_allowed",
  internal_error: "internal_error",
} as const;

/** Alias that makes the public/non-enumerating boundary explicit. */
export const PUBLIC_AUTH_ERROR_CODES = AUTH_ERROR_CODES;

/** A constrained code that may cross the public SDK/API boundary. */
export type PublicAuthErrorCode =
  (typeof PUBLIC_AUTH_ERROR_CODES)[keyof typeof PUBLIC_AUTH_ERROR_CODES];

/**
 * Internal/admin-only codes that must be mapped before a public response.
 *
 * In particular, `email_exists` and `email_not_confirmed` must never identify
 * an account during signup, login, recovery, OTP, resend, or lookup flows.
 */
export const INTERNAL_AUTH_ERROR_CODES = {
  email_exists: "email_exists",
  email_not_confirmed: "email_not_confirmed",
  user_not_found: "user_not_found",
  identity_not_found: "identity_not_found",
  protected_role: "protected_role",
  role_rank_violation: "role_rank_violation",
} as const;

/** A code available only inside server/admin orchestration. */
export type InternalAuthErrorCode =
  (typeof INTERNAL_AUTH_ERROR_CODES)[keyof typeof INTERNAL_AUTH_ERROR_CODES];

/** Backwards-compatible name for the constrained public code union. */
export type AuthErrorCode = PublicAuthErrorCode;

const publicCodeSet = new Set<string>(Object.values(PUBLIC_AUTH_ERROR_CODES));

/** Returns whether a value is a supported public error code. */
export function isPublicAuthErrorCode(value: unknown): value is PublicAuthErrorCode {
  return typeof value === "string" && publicCodeSet.has(value);
}

/**
 * Maps an internal code to a non-enumerating public code.
 *
 * @param code - An internal code, or an already-safe public code.
 * @returns The only code permitted in an expected public SDK error.
 *
 * @example
 * ```ts
 * mapInternalAuthErrorCodeToPublic("email_exists");
 * // "invalid_request"
 * ```
 *
 * @since 0.1.0
 */
export function mapInternalAuthErrorCodeToPublic(
  code: InternalAuthErrorCode | PublicAuthErrorCode,
): PublicAuthErrorCode {
  if (isPublicAuthErrorCode(code)) {
    return code;
  }

  switch (code) {
    case INTERNAL_AUTH_ERROR_CODES.email_exists:
      return PUBLIC_AUTH_ERROR_CODES.invalid_request;
    case INTERNAL_AUTH_ERROR_CODES.email_not_confirmed:
      return PUBLIC_AUTH_ERROR_CODES.invalid_credentials;
    case INTERNAL_AUTH_ERROR_CODES.user_not_found:
      return PUBLIC_AUTH_ERROR_CODES.invalid_request;
    case INTERNAL_AUTH_ERROR_CODES.identity_not_found:
      return PUBLIC_AUTH_ERROR_CODES.not_found;
    case INTERNAL_AUTH_ERROR_CODES.protected_role:
    case INTERNAL_AUTH_ERROR_CODES.role_rank_violation:
      return PUBLIC_AUTH_ERROR_CODES.forbidden;
    default:
      throw new AuthProgrammingError("Unknown internal auth error code");
  }
}

/**
 * The serializable error shape returned by expected SDK failures.
 *
 * @compatibility Supabase-inspired. `request_id` is optional correlation data;
 * enumeration-sensitive/internal codes and provider credentials never cross
 * this boundary.
 */
export interface AuthError {
  /** The stable public error name. */
  readonly name: "AuthError";
  /** A safe human-readable message. */
  readonly message: string;
  /** The HTTP-compatible status associated with the failure. */
  readonly status: number;
  /** A constrained, stable public error code. */
  readonly code: PublicAuthErrorCode;
  /** Optional request correlation identifier. */
  readonly request_id?: string;
}

/**
 * Thrown when server/client configuration is malformed.
 *
 * Configuration failures are programming/deployment failures and must not be
 * converted into an expected `{ data, error }` result.
 */
export class AuthConfigurationError extends Error {
  readonly name = "AuthConfigurationError" as const;

  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/** Thrown when the SDK is called with an invalid programming contract. */
export class AuthProgrammingError extends Error {
  readonly name = "AuthProgrammingError" as const;

  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/** Returns whether a value conforms to the public auth-error shape. */
export function isAuthError(value: unknown): value is AuthError {
  if (typeof value !== "object" || value === null) {
    return false;
  }

  const candidate = value as Partial<AuthError>;
  const status = candidate.status;
  return (
    candidate.name === "AuthError" &&
    typeof candidate.message === "string" &&
    typeof status === "number" &&
    Number.isInteger(status) &&
    status >= 100 &&
    status <= 599 &&
    isPublicAuthErrorCode(candidate.code)
  );
}

/** Throws when a value cannot safely be returned as a public auth error. */
export function assertPublicAuthError(value: unknown): asserts value is AuthError {
  if (!isAuthError(value)) {
    throw new AuthProgrammingError("Expected a stable public AuthError");
  }
}

/**
 * Error returned inside an `AuthResult` for an expected API/auth failure.
 *
 * The constructor validates public codes at runtime as well as in TypeScript,
 * so an `as` cast cannot leak arbitrary or enumeration-sensitive codes.
 *
 * @example
 * ```ts
 * const error = new AuthApiError(
 *   "invalid_credentials",
 *   401,
 *   "Invalid login credentials",
 * );
 * ```
 *
 * @since 0.1.0
 */
export class AuthApiError extends Error implements AuthError {
  readonly name = "AuthError" as const;

  constructor(
    readonly code: PublicAuthErrorCode,
    readonly status: number,
    message: string,
    requestId?: string,
  ) {
    if (!isPublicAuthErrorCode(code)) {
      throw new AuthProgrammingError("AuthApiError requires a stable public error code");
    }
    if (!Number.isInteger(status) || status < 100 || status > 599) {
      throw new AuthProgrammingError("AuthApiError requires an HTTP-compatible status");
    }
    super(message);
    if (requestId !== undefined) {
      this.request_id = requestId;
    }
    Object.setPrototypeOf(this, new.target.prototype);
  }

  /** The request correlation identifier, when supplied by the API. */
  readonly request_id?: string;

  /** Returns the stable wire-safe error object. */
  toJSON(): AuthError {
    return {
      name: this.name,
      message: this.message,
      status: this.status,
      code: this.code,
      ...(this.request_id === undefined ? {} : { request_id: this.request_id }),
    };
  }
}
