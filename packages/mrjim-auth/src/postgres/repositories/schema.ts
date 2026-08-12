import type { ColumnType, Generated, Kysely, Transaction } from "kysely";
import type { JsonObject, UUID } from "../../shared/types.js";

/** PostgreSQL `timestamptz` row/insert/update mapping used by the adapter. */
export type Timestamptz = ColumnType<Date, Date | undefined, Date | undefined>;

/** Nullable PostgreSQL `timestamptz` row/insert/update mapping. */
export type NullableTimestamptz = ColumnType<
  Date | null,
  Date | null | undefined,
  Date | null | undefined
>;

/** PostgreSQL JSONB object mapping for the constrained auth tables. */
export type JsonbObject = ColumnType<
  JsonObject,
  JsonObject | Readonly<Record<string, unknown>> | undefined,
  JsonObject | Readonly<Record<string, unknown>> | undefined
>;

/** PostgreSQL bytea mapping; pg returns a Buffer for bytea columns. */
export type Bytea = ColumnType<Buffer, Buffer, Buffer>;

/** Nullable PostgreSQL bytea mapping for optional encrypted material. */
export type NullableBytea = ColumnType<Buffer | null, Buffer | null | undefined, Buffer | null | undefined>;

/** Typed row and write shape for `auth.users`. */
export interface UsersTable {
  id: Generated<UUID>;
  email: string | null;
  email_normalized: string | null;
  phone: string | null;
  phone_normalized: string | null;
  email_confirmed_at: NullableTimestamptz;
  phone_confirmed_at: NullableTimestamptz;
  last_sign_in_at: NullableTimestamptz;
  banned_until: NullableTimestamptz;
  user_metadata: JsonbObject;
  app_metadata: JsonbObject;
  created_at: Timestamptz;
  updated_at: Timestamptz;
  deleted_at: NullableTimestamptz;
}

/** Typed row and write shape for `auth.identities`. */
export interface IdentitiesTable {
  id: Generated<UUID>;
  user_id: UUID;
  provider: string;
  provider_subject: string;
  email: string | null;
  email_normalized: string | null;
  identity_data: JsonbObject;
  created_at: Timestamptz;
  updated_at: Timestamptz;
}

/** Typed row and write shape for `auth.password_credentials`. */
export interface PasswordCredentialsTable {
  user_id: UUID;
  password_hash: string;
  password_updated_at: Timestamptz;
}

/** Typed row and write shape for `auth.sessions`. */
export interface SessionsTable {
  id: Generated<UUID>;
  user_id: UUID;
  aal: number;
  ip_address: string | null;
  user_agent: string | null;
  created_at: Timestamptz;
  refreshed_at: Timestamptz;
  expires_at: Timestamptz;
  revoked_at: NullableTimestamptz;
}

/** Typed row and write shape for `auth.refresh_tokens`. */
export interface RefreshTokensTable {
  id: Generated<UUID>;
  session_id: UUID;
  token_hash: Bytea;
  family_id: UUID;
  parent_id: UUID | null;
  replacement_id: UUID | null;
  issued_at: Timestamptz;
  used_at: NullableTimestamptz;
  expires_at: Timestamptz;
  revoked_at: NullableTimestamptz;
}

/** Typed row and write shape for `auth.one_time_tokens`. */
export interface OneTimeTokensTable {
  id: Generated<UUID>;
  user_id: UUID | null;
  purpose: string;
  token_hash: Bytea;
  target: string;
  redirect: string | null;
  metadata: JsonbObject;
  attempt_count: number;
  created_at: Timestamptz;
  expires_at: Timestamptz;
  consumed_at: NullableTimestamptz;
}

/** Typed row and write shape for `auth.roles`. */
export interface RolesTable {
  id: Generated<UUID>;
  key: string;
  name: string;
  description: string | null;
  rank: number;
  is_system: boolean;
  created_at: Timestamptz;
  updated_at: Timestamptz;
}

/** Typed row and write shape for `auth.permissions`. */
export interface PermissionsTable {
  id: Generated<UUID>;
  key: string;
  resource: string;
  action: string;
  description: string | null;
  created_at: Timestamptz;
  updated_at: Timestamptz;
}

/** Typed row and write shape for `auth.role_permissions`. */
export interface RolePermissionsTable {
  role_id: UUID;
  permission_id: UUID;
}

/** Typed row and write shape for `auth.role_inheritance`. */
export interface RoleInheritanceTable {
  role_id: UUID;
  inherits_role_id: UUID;
}

/** Typed row and write shape for `auth.user_roles`. */
export interface UserRolesTable {
  user_id: UUID;
  role_id: UUID;
  scope_type: string | null;
  scope_id: string | null;
  assigned_by: UUID | null;
  assigned_at: Timestamptz;
  expires_at: NullableTimestamptz;
}

/** Typed row and write shape for `auth.oauth_states`. */
export interface OAuthStatesTable {
  id: Generated<UUID>;
  state_hash: Bytea;
  provider: string;
  flow: string;
  pkce_challenge: string;
  encrypted_verifier: NullableBytea;
  redirect_target: string;
  linking_user_id: UUID | null;
  expires_at: Timestamptz;
  consumed_at: NullableTimestamptz;
  created_at: Timestamptz;
}

/** Typed row and write shape for `auth.api_keys`. */
export interface ApiKeysTable {
  id: Generated<UUID>;
  prefix: string;
  key_hash: Bytea;
  kind: "publishable" | "secret";
  scopes: string[];
  last_used_at: NullableTimestamptz;
  expires_at: NullableTimestamptz;
  revoked_at: NullableTimestamptz;
  created_at: Timestamptz;
  name: string;
}

/** Typed row and write shape for `auth.audit_log`. */
export interface AuditLogTable {
  id: Generated<UUID>;
  actor_user_id: UUID | null;
  actor_key_id: UUID | null;
  actor_session_id: UUID | null;
  action: string;
  target_type: string;
  target_id: UUID | null;
  ip_address: string | null;
  user_agent: string | null;
  metadata: JsonbObject;
  outcome: "success" | "failure";
  occurred_at: Timestamptz;
}

/** Typed row and write shape for durable rate-limit buckets. */
export interface RateLimitBucketsTable {
  key_digest: Bytea;
  bucket: string;
  window_start: Timestamptz;
  window_end: Timestamptz;
  count: number;
  created_at: Timestamptz;
  updated_at: Timestamptz;
}

/** Complete typed Kysely database shape for the Task 3 auth schema. */
export interface Database {
  users: UsersTable;
  identities: IdentitiesTable;
  password_credentials: PasswordCredentialsTable;
  sessions: SessionsTable;
  refresh_tokens: RefreshTokensTable;
  one_time_tokens: OneTimeTokensTable;
  roles: RolesTable;
  permissions: PermissionsTable;
  role_permissions: RolePermissionsTable;
  role_inheritance: RoleInheritanceTable;
  user_roles: UserRolesTable;
  oauth_states: OAuthStatesTable;
  api_keys: ApiKeysTable;
  audit_log: AuditLogTable;
  rate_limit_buckets: RateLimitBucketsTable;
}

/** A root Kysely instance or an active transaction scoped to this schema. */
export type DatabaseExecutor = Kysely<Database> | Transaction<Database>;

/** Adapter-owned context shared by all repository members. */
export interface RepositoryContext {
  readonly db: DatabaseExecutor;
  readonly root: Kysely<Database>;
  readonly inTransaction: boolean;
}

/** Common explicit column list for `auth.users` reads/returning clauses. */
export const USER_COLUMNS = [
  "id",
  "email",
  "email_normalized",
  "phone",
  "phone_normalized",
  "email_confirmed_at",
  "phone_confirmed_at",
  "last_sign_in_at",
  "banned_until",
  "user_metadata",
  "app_metadata",
  "created_at",
  "updated_at",
  "deleted_at",
] as const;

/** Common explicit column list for `auth.identities` reads/returning clauses. */
export const IDENTITY_COLUMNS = [
  "id",
  "user_id",
  "provider",
  "provider_subject",
  "email",
  "email_normalized",
  "identity_data",
  "created_at",
  "updated_at",
] as const;

/** Common explicit column list for `auth.password_credentials` reads. */
export const PASSWORD_COLUMNS = ["user_id", "password_hash", "password_updated_at"] as const;

/** Common explicit column list for `auth.sessions` reads/returning clauses. */
export const SESSION_COLUMNS = [
  "id",
  "user_id",
  "aal",
  "ip_address",
  "user_agent",
  "created_at",
  "refreshed_at",
  "expires_at",
  "revoked_at",
] as const;

/** Common explicit column list for `auth.refresh_tokens` reads/returning clauses. */
export const REFRESH_TOKEN_COLUMNS = [
  "id",
  "session_id",
  "token_hash",
  "family_id",
  "parent_id",
  "replacement_id",
  "issued_at",
  "used_at",
  "expires_at",
  "revoked_at",
] as const;

/** Explicit columns returned from one-time-token consumption. */
export const ONE_TIME_TOKEN_COLUMNS = [
  "user_id",
  "purpose",
  "target",
  "redirect",
  "metadata",
  "expires_at",
] as const;

/** Explicit columns returned from OAuth state consumption. */
export const OAUTH_STATE_COLUMNS = [
  "id",
  "state_hash",
  "provider",
  "flow",
  "pkce_challenge",
  "encrypted_verifier",
  "redirect_target",
  "linking_user_id",
  "expires_at",
  "consumed_at",
] as const;

/** Common explicit column list for `auth.roles` reads/returning clauses. */
export const ROLE_COLUMNS = [
  "id",
  "key",
  "name",
  "description",
  "rank",
  "is_system",
  "created_at",
  "updated_at",
] as const;

/** Common explicit column list for `auth.permissions` reads/returning clauses. */
export const PERMISSION_COLUMNS = [
  "id",
  "key",
  "resource",
  "action",
  "description",
  "created_at",
  "updated_at",
] as const;

/** Explicit columns selected from `auth.api_keys`. */
export const API_KEY_COLUMNS = [
  "id",
  "prefix",
  "key_hash",
  "kind",
  "scopes",
  "expires_at",
  "revoked_at",
] as const;
