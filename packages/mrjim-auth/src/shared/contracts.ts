import type {
  AuthorizationScope,
  Identity,
  JsonObject,
  LowercaseKey,
  Permission,
  RedactedMetadata,
  Role,
  User,
  UUID,
} from "./types.js";

/** Opaque signing/encryption material supplied by the installing project. */
export type KeyMaterial = string | Uint8Array | Readonly<Record<string, unknown>>;

/**
 * A project-provided key source for server-only signing and verification.
 *
 * @compatibility Project-owned adapter contract; no hosted key service is
 * required or implied.
 */
export interface KeyProvider {
  /** Returns the configured active signing key identifier. */
  getActiveKeyId(): string | Promise<string>;
  /** Resolves signing material for a key identifier. */
  getSigningKey(keyId: string): KeyMaterial | Promise<KeyMaterial>;
  /** Resolves the verification material currently published by the project. */
  getVerificationKeys():
    | ReadonlyMap<string, KeyMaterial>
    | Promise<ReadonlyMap<string, KeyMaterial>>;
}

/** A single templated project-owned email delivery request. */
export interface MailMessage {
  /** A stable template name owned by the project. */
  template: "confirmation" | "magic_link" | "email_otp" | "recovery" | "invite";
  /** The destination email address. */
  to: string;
  /** Template variables; raw secrets must only exist in memory for delivery. */
  variables: Readonly<Record<string, string>>;
}

/**
 * A project-owned email delivery adapter.
 *
 * @compatibility Project-owned adapter contract; SMTP or another free/project-
 * owned transport may implement it.
 */
export interface Mailer {
  /** Sends one rendered template request. */
  send(message: MailMessage): Promise<void>;
}

/** A named rate-limit policy. */
export interface RateLimitPolicy {
  /** Maximum allowed operations in the window. */
  limit: number;
  /** Window length in seconds. */
  windowSeconds: number;
  /** Optional bucket label for separating operation classes. */
  bucket?: string;
}

/** The result of consuming one rate-limit slot. */
export interface RateLimitDecision {
  /** Whether the operation may continue. */
  allowed: boolean;
  /** Remaining slots in the current window. */
  remaining: number;
  /** Retry delay when the operation is not allowed. */
  retryAfterSeconds?: number;
}

/**
 * A project-owned limiter used by login, recovery, OTP, OAuth, and admin flows.
 *
 * @compatibility Project-owned adapter contract; no paid limiter is required.
 */
export interface RateLimiter {
  /** Consumes one slot for a key under a named policy. */
  consume(key: string, policy: RateLimitPolicy): Promise<RateLimitDecision>;
}

/**
 * Optional transaction context passed through repository operations.
 *
 * @internal Repository contracts are prepared for later server/PostgreSQL
 * tasks and are not exported from the package root in Task 2.
 */
export interface RepositoryOperationOptions {
  /**
   * Adapter-owned transaction object; deliberately has no PostgreSQL type.
   * PostgreSQL adapters may reject lock-sensitive calls without their own
   * active transaction-scoped repository instead of treating this value as a
   * portable lock handle.
   */
  transaction?: unknown;
  /** Clock value used for deterministic expiry and replay checks. */
  now?: Date;
}

/** @internal Data needed to create a user record. */
export interface CreateUserInput {
  email?: string | null;
  phone?: string | null;
  email_confirmed_at?: Date | null;
  phone_confirmed_at?: Date | null;
  confirmed_at?: Date | null;
  user_metadata?: JsonObject;
  app_metadata?: JsonObject;
}

/** @internal Fields that may be changed by a user or an authorized administrator. */
export interface UpdateUserInput {
  email?: string | null;
  phone?: string | null;
  email_confirmed_at?: Date | null;
  phone_confirmed_at?: Date | null;
  confirmed_at?: Date | null;
  banned_until?: Date | null;
  user_metadata?: JsonObject;
  app_metadata?: JsonObject;
}

/**
 * User persistence boundary consumed by later auth services.
 *
 * @internal This transaction-neutral repository is not a Task 2 package-root
 * export; Task 4 supplies the PostgreSQL implementation.
 */
export interface UserRepository {
  /** Finds a non-deleted user by UUID. */
  findById(id: UUID, options?: RepositoryOperationOptions): Promise<User | null>;
  /** Finds a non-deleted user by normalized email. */
  findByNormalizedEmail(
    email: string,
    options?: RepositoryOperationOptions,
  ): Promise<User | null>;
  /** Creates a user and returns the safe public record. */
  create(input: CreateUserInput, options?: RepositoryOperationOptions): Promise<User>;
  /** Applies an authorized patch and returns the safe public record. */
  update(
    id: UUID,
    patch: UpdateUserInput,
    options?: RepositoryOperationOptions,
  ): Promise<User>;
  /** Soft-deletes a user without exposing a hard-delete contract. */
  softDelete(
    id: UUID,
    deletedAt?: Date,
    options?: RepositoryOperationOptions,
  ): Promise<void>;
}

/**
 * Identity persistence boundary that never returns provider credentials.
 *
 * @internal Not exported from the Task 2 package root.
 */
export interface IdentityRepository {
  /** Finds an identity by its provider and stable subject. */
  findByProviderSubject(
    provider: string,
    providerSubject: string,
    options?: RepositoryOperationOptions,
  ): Promise<Identity | null>;
  /** Lists all safe identities linked to one user. */
  listByUserId(userId: UUID, options?: RepositoryOperationOptions): Promise<readonly Identity[]>;
  /** Creates a safe identity record. */
  create(
    input: Omit<Identity, "id" | "created_at" | "updated_at">,
    options?: RepositoryOperationOptions,
  ): Promise<Identity>;
  /** Removes one identity after the final-login-method policy is checked. */
  deleteById(id: UUID, options?: RepositoryOperationOptions): Promise<void>;
}

/** @internal Durable password-credential repository; raw hashes never enter public User. */
export interface PasswordCredentialRepository {
  /** Finds the server-only encoded password hash for a user. */
  findByUserId(
    userId: UUID,
    options?: RepositoryOperationOptions,
  ): Promise<{ user_id: UUID; password_hash: string; password_updated_at: Date } | null>;
  /** Stores a versioned server-only encoded password hash. */
  upsert(
    userId: UUID,
    passwordHash: string,
    updatedAt?: Date,
    options?: RepositoryOperationOptions,
  ): Promise<void>;
  /** Removes the password credential during account deletion or unlinking. */
  deleteByUserId(userId: UUID, options?: RepositoryOperationOptions): Promise<void>;
}

/** A durable session record with no raw bearer tokens. */
export interface SessionRecord {
  id: UUID;
  user_id: UUID;
  aal: number;
  ip_address: string | null;
  user_agent: string | null;
  created_at: Date;
  refreshed_at: Date;
  expires_at: Date;
  revoked_at: Date | null;
}

/** A durable refresh-token record containing only its digest and lineage. */
export interface RefreshTokenRecord {
  id: UUID;
  session_id: UUID;
  token_hash: Uint8Array;
  family_id: UUID;
  parent_id: UUID | null;
  replacement_id: UUID | null;
  issued_at: Date;
  used_at: Date | null;
  expires_at: Date;
  revoked_at: Date | null;
}

/** Input for a new session and its first refresh-token family member. */
export interface CreateSessionInput {
  user_id: UUID;
  aal?: number;
  ip_address?: string | null;
  user_agent?: string | null;
  expires_at: Date;
  token_hash: Uint8Array;
  family_id: UUID;
}

/**
 * Session and refresh-token persistence boundary.
 *
 * @internal Not exported from the Task 2 package root.
 */
export interface SessionRepository {
  /** Creates a session and its initial refresh token atomically. */
  create(
    input: CreateSessionInput,
    options?: RepositoryOperationOptions,
  ): Promise<{ session: SessionRecord; refreshToken: RefreshTokenRecord }>;
  /**
   * Locks and reads a refresh-token row for rotation/replay handling. The
   * PostgreSQL adapter locks user, session, then refresh-token rows in sorted
   * order; used/revoked token state remains readable for later replay policy.
   */
  findRefreshForUpdate(
    tokenHash: Uint8Array,
    options?: RepositoryOperationOptions,
  ): Promise<{ session: SessionRecord; refreshToken: RefreshTokenRecord } | null>;
  /** Atomically marks a token used and inserts its replacement. */
  rotate(
    tokenId: UUID,
    replacement: Omit<RefreshTokenRecord, "id" | "issued_at">,
    options?: RepositoryOperationOptions,
  ): Promise<RefreshTokenRecord>;
  /** Revokes one session. */
  revokeSession(sessionId: UUID, options?: RepositoryOperationOptions): Promise<void>;
  /** Revokes every token in a refresh-token family. */
  revokeFamily(familyId: UUID, options?: RepositoryOperationOptions): Promise<void>;
  /** Revokes a user's sessions, optionally preserving the current one. */
  revokeUserSessions(
    userId: UUID,
    exceptSessionId?: UUID,
    options?: RepositoryOperationOptions,
  ): Promise<void>;
}

/** Purpose-bound one-time token input. Only the digest is persisted. */
export interface OneTimeTokenInput {
  user_id?: UUID | null;
  purpose: "signup" | "email_change" | "recovery" | "magic_link" | "email_otp" | "invite";
  token_hash: Uint8Array;
  target: string;
  redirect?: string | null;
  metadata?: RedactedMetadata;
  expires_at: Date;
}

/**
 * One-time token persistence boundary with atomic consume semantics.
 *
 * @internal Not exported from the Task 2 package root.
 */
export interface OneTimeTokenRepository {
  /** Persists a one-time token digest. */
  issue(input: OneTimeTokenInput, options?: RepositoryOperationOptions): Promise<void>;
  /** Consumes a matching token at most once, returning its safe metadata. */
  consume(
    tokenHash: Uint8Array,
    purpose: OneTimeTokenInput["purpose"],
    now: Date,
    options?: RepositoryOperationOptions,
  ): Promise<Omit<OneTimeTokenInput, "token_hash"> | null>;
}

/** An authorization role assignment with optional scope and expiry. */
export interface RoleAssignmentInput {
  user_id: UUID;
  role_id: UUID;
  scope?: AuthorizationScope | null;
  assigned_by?: UUID | null;
  expires_at?: Date | null;
}

/**
 * Authorization persistence boundary for dynamic roles and permissions.
 *
 * @internal Not exported from the Task 2 package root.
 */
export interface AuthorizationRepository {
  /** Resolves direct and inherited permissions for a user and scope. */
  effectivePermissions(
    userId: UUID,
    scope?: AuthorizationScope,
    options?: RepositoryOperationOptions,
  ): Promise<readonly Permission[]>;
  /** Assigns a role, enforcing the adapter's uniqueness constraints. */
  assignRole(
    input: RoleAssignmentInput,
    options?: RepositoryOperationOptions,
  ): Promise<void>;
  /** Removes one role assignment. */
  unassignRole(
    userId: UUID,
    roleId: UUID,
    scope?: AuthorizationScope | null,
    options?: RepositoryOperationOptions,
  ): Promise<void>;
  /** Replaces the permission set for one role. */
  setRolePermissions(
    roleId: UUID,
    permissionIds: readonly UUID[],
    options?: RepositoryOperationOptions,
  ): Promise<void>;
  /** Replaces inherited roles after cycle checks. */
  setRoleInheritance(
    roleId: UUID,
    inheritedRoleIds: readonly UUID[],
    options?: RepositoryOperationOptions,
  ): Promise<void>;
}

/**
 * Redacted audit event input. Secrets and raw tokens are not permitted.
 *
 * @internal Callers must create `metadata` with `sanitizeRedactedMetadata`.
 */
export interface AuditEventInput {
  actor_user_id?: UUID | null;
  actor_key_id?: UUID | null;
  actor_session_id?: UUID | null;
  action: string;
  target_type: string;
  target_id?: UUID | null;
  ip_address?: string | null;
  user_agent?: string | null;
  metadata?: RedactedMetadata;
  outcome: "success" | "failure";
  occurred_at?: Date;
}

/** @internal Safe API-key lookup result containing no raw key value. */
export interface ApiKeyRecord {
  id: UUID;
  prefix: string;
  kind: "publishable" | "secret";
  scopes: readonly string[];
  key_hash: Uint8Array;
  expires_at: Date | null;
  revoked_at: Date | null;
}

/**
 * Audit and API-key persistence boundary.
 *
 * @internal Not exported from the Task 2 package root.
 */
export interface OperationsRepository {
  /** Appends one immutable audit event. */
  appendAudit(
    input: AuditEventInput,
    options?: RepositoryOperationOptions,
  ): Promise<void>;
  /** Finds a non-revoked API key by its digest. */
  findApiKeyByHash(
    keyHash: Uint8Array,
    options?: RepositoryOperationOptions,
  ): Promise<ApiKeyRecord | null>;
}

/** @internal Input for creating a role through the server/admin boundary. */
export interface CreateRoleInput {
  key: LowercaseKey;
  name: string;
  description?: string | null;
  rank: number;
  is_system?: boolean;
}

/** @internal Patch for a role through the server/admin boundary. */
export interface UpdateRoleInput {
  key?: LowercaseKey;
  name?: string;
  description?: string | null;
  rank?: number;
  is_system?: boolean;
}

/**
 * Role CRUD persistence boundary for the documented admin API.
 *
 * @internal Not exported from the Task 2 package root; later administration
 * work will decide its package subpath.
 */
export interface RoleRepository {
  /** Lists all project roles. */
  list(options?: RepositoryOperationOptions): Promise<readonly Role[]>;
  /** Finds one role by UUID. */
  findById(id: UUID, options?: RepositoryOperationOptions): Promise<Role | null>;
  /** Creates a role after lowercase/rank policy validation. */
  create(input: CreateRoleInput, options?: RepositoryOperationOptions): Promise<Role>;
  /** Applies a role patch. */
  update(
    id: UUID,
    patch: UpdateRoleInput,
    options?: RepositoryOperationOptions,
  ): Promise<Role>;
  /** Deletes a role after protected-role policy validation. */
  delete(id: UUID, options?: RepositoryOperationOptions): Promise<void>;
}

/** @internal Input for creating a permission through the server/admin boundary. */
export interface CreatePermissionInput {
  key: LowercaseKey;
  resource: LowercaseKey;
  action: LowercaseKey;
  description?: string | null;
}

/** @internal Patch for a permission through the server/admin boundary. */
export interface UpdatePermissionInput {
  key?: LowercaseKey;
  resource?: LowercaseKey;
  action?: LowercaseKey;
  description?: string | null;
}

/**
 * Permission CRUD persistence boundary for the documented admin API.
 *
 * @internal Not exported from the Task 2 package root.
 */
export interface PermissionRepository {
  /** Lists all project permissions. */
  list(options?: RepositoryOperationOptions): Promise<readonly Permission[]>;
  /** Finds one permission by UUID. */
  findById(id: UUID, options?: RepositoryOperationOptions): Promise<Permission | null>;
  /** Creates a permission after key relationship validation. */
  create(input: CreatePermissionInput, options?: RepositoryOperationOptions): Promise<Permission>;
  /** Applies a permission patch. */
  update(
    id: UUID,
    patch: UpdatePermissionInput,
    options?: RepositoryOperationOptions,
  ): Promise<Permission>;
  /** Deletes a permission after assignment policy validation. */
  delete(id: UUID, options?: RepositoryOperationOptions): Promise<void>;
}

/** @internal OAuth state input; only hashes/encrypted verifier material persist. */
export interface OAuthStateInput {
  state_hash: Uint8Array;
  provider: string;
  flow: "sign_in" | "link_identity";
  pkce_challenge: string;
  encrypted_verifier?: Uint8Array | null;
  redirect: string;
  linking_user_id?: UUID | null;
  expires_at: Date;
}

/** @internal Safe OAuth state record used by server-side callback orchestration. */
export interface OAuthStateRecord extends Omit<OAuthStateInput, "state_hash"> {
  id: UUID;
  state_hash: Uint8Array;
  consumed_at: Date | null;
}

/**
 * OAuth state persistence boundary for signed PKCE callbacks.
 *
 * @internal Not exported from the Task 2 package root.
 */
export interface OAuthStateRepository {
  /** Stores one short-lived state record. */
  create(input: OAuthStateInput, options?: RepositoryOperationOptions): Promise<void>;
  /** Atomically consumes one state hash once. */
  consume(
    stateHash: Uint8Array,
    now: Date,
    options?: RepositoryOperationOptions,
  ): Promise<OAuthStateRecord | null>;
}

/**
 * Complete adapter boundary consumed by later server and PostgreSQL tasks.
 *
 * The transaction object is adapter-owned so this shared module remains free
 * of PostgreSQL, Kysely, Node-only, and migration imports.
 *
 * @internal This aggregate is intentionally not exported from the Task 2
 * package root. Later server/PostgreSQL tasks may expose an adapter-specific
 * subpath after implementing these boundaries.
 */
export interface AuthRepository {
  /**
   * Runs a callback in one adapter-owned transaction and passes a complete
   * transaction-scoped aggregate. A rejected callback rolls back every write
   * made through that aggregate; lock-sensitive methods must use this scope.
   */
  transaction<T>(callback: (repository: AuthRepository) => Promise<T>): Promise<T>;
  users: UserRepository;
  identities: IdentityRepository;
  passwordCredentials: PasswordCredentialRepository;
  sessions: SessionRepository;
  oneTimeTokens: OneTimeTokenRepository;
  oauthStates: OAuthStateRepository;
  authorization: AuthorizationRepository;
  roles: RoleRepository;
  permissions: PermissionRepository;
  operations: OperationsRepository;
}
