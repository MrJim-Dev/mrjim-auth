import type {
  AuthorizationScope,
  Identity,
  JsonObject,
  Permission,
  Role,
  User,
} from "./types.js";

/** Opaque signing/encryption material supplied by the installing project. */
export type KeyMaterial = string | Uint8Array | Readonly<Record<string, unknown>>;

/** A project-provided key source for server-only signing and verification. */
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

/** A project-owned email delivery adapter. */
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

/** A project-owned limiter used by login, recovery, OTP, OAuth, and admin flows. */
export interface RateLimiter {
  /** Consumes one slot for a key under a named policy. */
  consume(key: string, policy: RateLimitPolicy): Promise<RateLimitDecision>;
}

/** Optional transaction context passed through repository operations. */
export interface RepositoryOperationOptions {
  /** Adapter-owned transaction object; deliberately has no PostgreSQL type. */
  transaction?: unknown;
  /** Clock value used for deterministic expiry and replay checks. */
  now?: Date;
}

/** Data needed to create a user record. */
export interface CreateUserInput {
  email?: string | null;
  phone?: string | null;
  email_confirmed_at?: Date | null;
  phone_confirmed_at?: Date | null;
  confirmed_at?: Date | null;
  user_metadata?: JsonObject;
  app_metadata?: JsonObject;
}

/** Fields that may be changed by a user or an authorized administrator. */
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

/** User persistence boundary consumed by later auth services. */
export interface UserRepository {
  /** Finds a non-deleted user by UUID. */
  findById(id: string, options?: RepositoryOperationOptions): Promise<User | null>;
  /** Finds a non-deleted user by normalized email. */
  findByNormalizedEmail(
    email: string,
    options?: RepositoryOperationOptions,
  ): Promise<User | null>;
  /** Creates a user and returns the safe public record. */
  create(input: CreateUserInput, options?: RepositoryOperationOptions): Promise<User>;
  /** Applies an authorized patch and returns the safe public record. */
  update(
    id: string,
    patch: UpdateUserInput,
    options?: RepositoryOperationOptions,
  ): Promise<User>;
  /** Soft-deletes a user without exposing a hard-delete contract. */
  softDelete(
    id: string,
    deletedAt?: Date,
    options?: RepositoryOperationOptions,
  ): Promise<void>;
}

/** Identity persistence boundary that never returns provider credentials. */
export interface IdentityRepository {
  /** Finds an identity by its provider and stable subject. */
  findByProviderSubject(
    provider: string,
    providerSubject: string,
    options?: RepositoryOperationOptions,
  ): Promise<Identity | null>;
  /** Lists all safe identities linked to one user. */
  listByUserId(userId: string, options?: RepositoryOperationOptions): Promise<readonly Identity[]>;
  /** Creates a safe identity record. */
  create(
    input: Omit<Identity, "id" | "created_at" | "updated_at">,
    options?: RepositoryOperationOptions,
  ): Promise<Identity>;
  /** Removes one identity after the final-login-method policy is checked. */
  deleteById(id: string, options?: RepositoryOperationOptions): Promise<void>;
}

/** A durable session record with no raw bearer tokens. */
export interface SessionRecord {
  id: string;
  user_id: string;
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
  id: string;
  session_id: string;
  token_hash: Uint8Array;
  family_id: string;
  parent_id: string | null;
  replacement_id: string | null;
  issued_at: Date;
  used_at: Date | null;
  expires_at: Date;
  revoked_at: Date | null;
}

/** Input for a new session and its first refresh-token family member. */
export interface CreateSessionInput {
  user_id: string;
  aal?: number;
  ip_address?: string | null;
  user_agent?: string | null;
  expires_at: Date;
  token_hash: Uint8Array;
  family_id: string;
}

/** Session and refresh-token persistence boundary. */
export interface SessionRepository {
  /** Creates a session and its initial refresh token atomically. */
  create(
    input: CreateSessionInput,
    options?: RepositoryOperationOptions,
  ): Promise<{ session: SessionRecord; refreshToken: RefreshTokenRecord }>;
  /** Locks and reads a refresh-token row for rotation/replay handling. */
  findRefreshForUpdate(
    tokenHash: Uint8Array,
    options?: RepositoryOperationOptions,
  ): Promise<{ session: SessionRecord; refreshToken: RefreshTokenRecord } | null>;
  /** Atomically marks a token used and inserts its replacement. */
  rotate(
    tokenId: string,
    replacement: Omit<RefreshTokenRecord, "id" | "issued_at">,
    options?: RepositoryOperationOptions,
  ): Promise<RefreshTokenRecord>;
  /** Revokes one session. */
  revokeSession(sessionId: string, options?: RepositoryOperationOptions): Promise<void>;
  /** Revokes every token in a refresh-token family. */
  revokeFamily(familyId: string, options?: RepositoryOperationOptions): Promise<void>;
  /** Revokes a user's sessions, optionally preserving the current one. */
  revokeUserSessions(
    userId: string,
    exceptSessionId?: string,
    options?: RepositoryOperationOptions,
  ): Promise<void>;
}

/** Purpose-bound one-time token input. Only the digest is persisted. */
export interface OneTimeTokenInput {
  user_id?: string | null;
  purpose: "signup" | "email_change" | "recovery" | "magic_link" | "email_otp" | "invite";
  token_hash: Uint8Array;
  target: string;
  redirect?: string | null;
  metadata?: JsonObject;
  expires_at: Date;
}

/** One-time token persistence boundary with atomic consume semantics. */
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
  user_id: string;
  role_id: string;
  scope?: AuthorizationScope | null;
  assigned_by?: string | null;
  expires_at?: Date | null;
}

/** Authorization persistence boundary for dynamic roles and permissions. */
export interface AuthorizationRepository {
  /** Resolves direct and inherited permissions for a user and scope. */
  effectivePermissions(
    userId: string,
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
    userId: string,
    roleId: string,
    scope?: AuthorizationScope | null,
    options?: RepositoryOperationOptions,
  ): Promise<void>;
  /** Replaces the permission set for one role. */
  setRolePermissions(
    roleId: string,
    permissionIds: readonly string[],
    options?: RepositoryOperationOptions,
  ): Promise<void>;
  /** Replaces inherited roles after cycle checks. */
  setRoleInheritance(
    roleId: string,
    inheritedRoleIds: readonly string[],
    options?: RepositoryOperationOptions,
  ): Promise<void>;
}

/** Redacted audit event input. Secrets and raw tokens are not permitted. */
export interface AuditEventInput {
  actor_user_id?: string | null;
  actor_key_id?: string | null;
  actor_session_id?: string | null;
  action: string;
  target_type: string;
  target_id?: string | null;
  ip_address?: string | null;
  user_agent?: string | null;
  metadata?: JsonObject;
  outcome: "success" | "failure";
  occurred_at?: Date;
}

/** Safe API-key lookup result containing no raw key value. */
export interface ApiKeyRecord {
  id: string;
  prefix: string;
  kind: "publishable" | "secret";
  scopes: readonly string[];
  key_hash: Uint8Array;
  expires_at: Date | null;
  revoked_at: Date | null;
}

/** Audit and API-key persistence boundary. */
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

/**
 * Complete adapter boundary consumed by later server and PostgreSQL tasks.
 *
 * The transaction object is adapter-owned so this shared module remains free
 * of PostgreSQL, Kysely, Node-only, and migration imports.
 */
export interface AuthRepository {
  /** Runs a callback in an adapter-owned transaction. */
  transaction<T>(callback: (repository: AuthRepository) => Promise<T>): Promise<T>;
  users: UserRepository;
  identities: IdentityRepository;
  sessions: SessionRepository;
  oneTimeTokens: OneTimeTokenRepository;
  authorization: AuthorizationRepository;
  operations: OperationsRepository;
}
