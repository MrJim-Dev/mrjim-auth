/** Stable error codes used by expected SDK/API failures. */
export const AUTH_ERROR_CODES = {
  invalid_request: "invalid_request",
  invalid_credentials: "invalid_credentials",
  unauthorized: "unauthorized",
  forbidden: "forbidden",
  not_found: "not_found",
  conflict: "conflict",
  email_exists: "email_exists",
  email_not_confirmed: "email_not_confirmed",
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

/** A stable code shipped by the SDK for a known expected failure. */
export type AuthErrorCode = (typeof AUTH_ERROR_CODES)[keyof typeof AUTH_ERROR_CODES];

/**
 * The serializable error shape returned by expected SDK failures.
 *
 * @compatibility Supabase-inspired. `request_id` is optional correlation data;
 * provider credentials and bearer tokens are never part of this shape.
 */
export interface AuthError {
  /** The stable public error name. */
  readonly name: "AuthError";
  /** A safe human-readable message. */
  readonly message: string;
  /** The HTTP-compatible status associated with the failure. */
  readonly status: number;
  /** The stable machine-readable error code. */
  readonly code: string;
  /** Optional request correlation identifier. */
  readonly request_id?: string;
}

/**
 * Error returned inside an `AuthResult` for an expected API/auth failure.
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
    readonly code: string,
    readonly status: number,
    message: string,
    requestId?: string,
  ) {
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
  return (
    candidate.name === "AuthError" &&
    typeof candidate.message === "string" &&
    typeof candidate.status === "number" &&
    typeof candidate.code === "string"
  );
}
