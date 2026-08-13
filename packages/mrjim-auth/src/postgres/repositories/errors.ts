/** Stable adapter error codes for expected repository-boundary failures. */
export type PostgresRepositoryErrorCode =
  | "email_exists"
  | "phone_exists"
  | "user_id_exists"
  | "identity_exists"
  | "transaction_required"
  | "not_found"
  | "protected_role"
  | "refresh_token_not_rotatable"
  | "invalid_refresh_lineage";

/** Error raised by the adapter before or after a database operation. */
export class PostgresRepositoryError extends Error {
  /** Stable internal classification for service-layer mapping. */
  readonly code: PostgresRepositoryErrorCode;
  /** PostgreSQL constraint name when this error was derived from a constraint. */
  readonly constraint: string | undefined;

  constructor(
    code: PostgresRepositoryErrorCode,
    message: string,
    options: { readonly constraint?: string; readonly cause?: unknown } = {},
  ) {
    super(message, { cause: options.cause });
    this.name = "PostgresRepositoryError";
    this.code = code;
    this.constraint = options.constraint;
  }
}

/** Require an active Kysely transaction for a lock whose result is returned. */
export function requireTransaction(active: boolean): void {
  if (!active) {
    throw new PostgresRepositoryError(
      "transaction_required",
      "this repository operation requires an active transaction",
    );
  }
}

function postgresErrorDetails(error: unknown): {
  readonly code: string | undefined;
  readonly constraint: string | undefined;
} {
  if (typeof error !== "object" || error === null) {
    return { code: undefined, constraint: undefined };
  }
  const candidate = error as { readonly code?: unknown; readonly constraint?: unknown };
  return {
    code: typeof candidate.code === "string" ? candidate.code : undefined,
    constraint: typeof candidate.constraint === "string" ? candidate.constraint : undefined,
  };
}

/** Map only the normalized-email uniqueness violation; preserve all other DB errors. */
export function mapDuplicateNormalizedEmail(error: unknown): never {
  const details = postgresErrorDetails(error);
  if (details.code === "23505" && details.constraint === "users_email_normalized_key") {
    throw new PostgresRepositoryError(
      "email_exists",
      "a user with this normalized email already exists",
      { constraint: details.constraint, cause: error },
    );
  }
  throw error;
}

/** Map import-only user UUID/email/phone uniqueness failures deterministically. */
export function mapDuplicateImportedUser(error: unknown): never {
  const details = postgresErrorDetails(error);
  if (details.code === "23505" && details.constraint === "users_pkey") {
    throw new PostgresRepositoryError(
      "user_id_exists",
      "a user with this UUID already exists",
      { constraint: details.constraint, cause: error },
    );
  }
  if (details.code === "23505" && details.constraint === "users_email_normalized_key") {
    throw new PostgresRepositoryError(
      "email_exists",
      "a user with this normalized email already exists",
      { constraint: details.constraint, cause: error },
    );
  }
  if (details.code === "23505" && details.constraint === "users_phone_normalized_key") {
    throw new PostgresRepositoryError(
      "phone_exists",
      "a user with this normalized phone already exists",
      { constraint: details.constraint, cause: error },
    );
  }
  throw error;
}

/** Map the provider-subject uniqueness race without exposing SQL details. */
export function mapDuplicateIdentity(error: unknown): never {
  const details = postgresErrorDetails(error);
  if (details.code === "23505" && details.constraint === "identities_provider_subject_key") {
    throw new PostgresRepositoryError(
      "identity_exists",
      "this provider identity is already linked",
      { constraint: details.constraint, cause: error },
    );
  }
  throw error;
}
