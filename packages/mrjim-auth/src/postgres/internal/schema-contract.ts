import { createHash } from "node:crypto";
import type {
  ColumnCatalogRow,
  ConstraintCatalogRow,
  FunctionCatalogRow,
  IndexCatalogRow,
  TableCatalogRow,
  TriggerCatalogRow,
} from "./catalog.js";

/** Canonical auth tables required by the baseline schema. */
export const REQUIRED_TABLES = [
  "users",
  "identities",
  "password_credentials",
  "sessions",
  "refresh_tokens",
  "one_time_tokens",
  "oauth_states",
  "roles",
  "permissions",
  "role_permissions",
  "role_inheritance",
  "user_roles",
  "api_keys",
  "audit_log",
  "rate_limit_buckets",
  "schema_migrations",
] as const;

export type RequiredTable = (typeof REQUIRED_TABLES)[number];

/** One canonical forbidden substring used across catalog verification and tests/docs. */
export const FORBIDDEN_AUTH_NAMES = [
  "mrjim",
  "shipping",
  "tenant",
  "passenger",
  "port",
  "vessel",
  "cabin",
  "tms",
  "marketplace",
  "hayahai",
  "ayahay",
] as const;

/** Expected PostgreSQL column shape, including type, nullability, and critical defaults. */
export interface ColumnContract {
  readonly columnName: string;
  readonly dataType: string;
  readonly udtName: string;
  readonly nullable: boolean;
  readonly defaultExpression: string | null;
}

function column(
  columnName: string,
  dataType: string,
  udtName: string,
  nullable: boolean,
  defaultExpression: string | null = null,
): ColumnContract {
  return { columnName, dataType, udtName, nullable, defaultExpression };
}

const uuid = (name: string, nullable = false, defaultExpression: string | null = "gen_random_uuid()") =>
  column(name, "uuid", "uuid", nullable, defaultExpression);
const text = (name: string, nullable = false, defaultExpression: string | null = null) =>
  column(name, "text", "text", nullable, defaultExpression);
const timestamp = (name: string, nullable = false, defaultExpression: string | null = null) =>
  column(name, "timestamp with time zone", "timestamptz", nullable, defaultExpression);
const jsonb = (name: string, defaultExpression = "'{}'::jsonb") =>
  column(name, "jsonb", "jsonb", false, defaultExpression);
const bytea = (name: string, nullable = false) => column(name, "bytea", "bytea", nullable);

/** Exact ordered column contracts for all required auth tables. */
export const REQUIRED_COLUMNS: Readonly<Record<RequiredTable, readonly ColumnContract[]>> = {
  users: [
    uuid("id"), text("email", true), text("email_normalized", true), text("phone", true),
    text("phone_normalized", true), timestamp("email_confirmed_at", true),
    timestamp("phone_confirmed_at", true), timestamp("last_sign_in_at", true),
    timestamp("banned_until", true), jsonb("user_metadata"), jsonb("app_metadata"),
    timestamp("created_at", false, "now()"), timestamp("updated_at", false, "now()"),
    timestamp("deleted_at", true),
  ],
  identities: [
    uuid("id"), uuid("user_id", false, null), text("provider"), text("provider_subject"),
    text("email", true), text("email_normalized", true), jsonb("identity_data"),
    timestamp("created_at", false, "now()"), timestamp("updated_at", false, "now()"),
  ],
  password_credentials: [
    uuid("user_id", false, null), text("password_hash"), timestamp("password_updated_at", false, "now()"),
  ],
  sessions: [
    uuid("id"), uuid("user_id", false, null), column("aal", "smallint", "int2", false, "1"),
    column("ip_address", "inet", "inet", true), text("user_agent", true),
    timestamp("created_at", false, "now()"), timestamp("refreshed_at", false, "now()"),
    timestamp("expires_at"), timestamp("revoked_at", true),
  ],
  refresh_tokens: [
    uuid("id"), uuid("session_id", false, null), bytea("token_hash"), uuid("family_id", false, null),
    uuid("parent_id", true, null), uuid("replacement_id", true, null),
    timestamp("issued_at", false, "now()"), timestamp("used_at", true),
    timestamp("expires_at"), timestamp("revoked_at", true),
  ],
  one_time_tokens: [
    uuid("id"), uuid("user_id", true, null), text("purpose"), bytea("token_hash"),
    text("target"), text("redirect", true), jsonb("metadata"),
    column("attempt_count", "integer", "int4", false, "0"), timestamp("created_at", false, "now()"),
    timestamp("expires_at"), timestamp("consumed_at", true),
  ],
  oauth_states: [
    uuid("id"), bytea("state_hash"), text("provider"), text("flow"), text("pkce_challenge"),
    bytea("encrypted_verifier", true), text("redirect_target"), uuid("linking_user_id", true, null),
    timestamp("expires_at"), timestamp("consumed_at", true), timestamp("created_at", false, "now()"),
  ],
  roles: [
    uuid("id"), text("key"), text("name"), text("description", true),
    column("rank", "integer", "int4", false, "0"), column("is_system", "boolean", "bool", false, "false"),
    timestamp("created_at", false, "now()"), timestamp("updated_at", false, "now()"),
  ],
  permissions: [
    uuid("id"), text("key"), text("resource"), text("action"), text("description", true),
    timestamp("created_at", false, "now()"), timestamp("updated_at", false, "now()"),
  ],
  role_permissions: [uuid("role_id", false, null), uuid("permission_id", false, null)],
  role_inheritance: [uuid("role_id", false, null), uuid("inherits_role_id", false, null)],
  user_roles: [
    uuid("user_id", false, null), uuid("role_id", false, null), text("scope_type", true),
    text("scope_id", true), uuid("assigned_by", true, null), timestamp("assigned_at", false, "now()"),
    timestamp("expires_at", true),
  ],
  api_keys: [
    uuid("id"), text("prefix"), bytea("key_hash"), text("kind"),
    column("scopes", "ARRAY", "_text", false, "ARRAY[]::text[]"), timestamp("last_used_at", true),
    timestamp("expires_at", true), timestamp("revoked_at", true), timestamp("created_at", false, "now()"),
    text("name"),
  ],
  audit_log: [
    uuid("id"), uuid("actor_user_id", true, null), uuid("actor_key_id", true, null),
    uuid("actor_session_id", true, null), text("action"), text("target_type"), uuid("target_id", true, null),
    column("ip_address", "inet", "inet", true), text("user_agent", true), jsonb("metadata"),
    text("outcome"), timestamp("occurred_at", false, "now()"),
  ],
  rate_limit_buckets: [
    bytea("key_digest"), text("bucket"), timestamp("window_start"), timestamp("window_end"),
    column("count", "integer", "int4", false, "0"),
    timestamp("created_at", false, "now()"), timestamp("updated_at", false, "now()"),
  ],
  schema_migrations: [
    text("version"), column("migration_order", "integer", "int4", false, null), text("checksum"),
    timestamp("applied_at", false, "now()"), text("package_version"),
  ],
};

/** Expected secondary and constraint-backed index definitions. */
export interface IndexContract {
  readonly indexName: string;
  readonly unique: boolean;
  readonly primary: boolean;
  readonly definition: string;
}

function primaryIndex(indexName: string, tableName: string, columns: string): IndexContract {
  return {
    indexName,
    unique: true,
    primary: true,
    definition: `CREATE UNIQUE INDEX ${indexName} ON auth.${tableName} USING btree (${columns})`,
  };
}

function uniqueIndex(indexName: string, tableName: string, columns: string): IndexContract {
  return {
    indexName,
    unique: true,
    primary: false,
    definition: `CREATE UNIQUE INDEX ${indexName} ON auth.${tableName} USING btree (${columns})`,
  };
}

export const REQUIRED_INDEXES: readonly IndexContract[] = [
  primaryIndex("schema_migrations_pkey", "schema_migrations", "version"),
  uniqueIndex("schema_migrations_migration_order_key", "schema_migrations", "migration_order"),
  primaryIndex("users_pkey", "users", "id"),
  {
    indexName: "users_email_normalized_key",
    unique: true,
    primary: false,
    definition: "CREATE UNIQUE INDEX users_email_normalized_key ON auth.users USING btree (email_normalized) WHERE (email_normalized IS NOT NULL)",
  },
  primaryIndex("identities_pkey", "identities", "id"),
  {
    indexName: "users_phone_normalized_key",
    unique: true,
    primary: false,
    definition: "CREATE UNIQUE INDEX users_phone_normalized_key ON auth.users USING btree (phone_normalized) WHERE (phone_normalized IS NOT NULL)",
  },
  primaryIndex("password_credentials_pkey", "password_credentials", "user_id"),
  primaryIndex("sessions_pkey", "sessions", "id"),
  primaryIndex("refresh_tokens_pkey", "refresh_tokens", "id"),
  {
    indexName: "identities_provider_subject_key",
    unique: true,
    primary: false,
    definition: "CREATE UNIQUE INDEX identities_provider_subject_key ON auth.identities USING btree (provider, provider_subject)",
  },
  primaryIndex("one_time_tokens_pkey", "one_time_tokens", "id"),
  {
    indexName: "refresh_tokens_token_hash_key",
    unique: true,
    primary: false,
    definition: "CREATE UNIQUE INDEX refresh_tokens_token_hash_key ON auth.refresh_tokens USING btree (token_hash)",
  },
  primaryIndex("oauth_states_pkey", "oauth_states", "id"),
  {
    indexName: "one_time_tokens_token_hash_key",
    unique: true,
    primary: false,
    definition: "CREATE UNIQUE INDEX one_time_tokens_token_hash_key ON auth.one_time_tokens USING btree (token_hash)",
  },
  primaryIndex("roles_pkey", "roles", "id"),
  {
    indexName: "roles_key_unique",
    unique: true,
    primary: false,
    definition: "CREATE UNIQUE INDEX roles_key_unique ON auth.roles USING btree (key)",
  },
  primaryIndex("permissions_pkey", "permissions", "id"),
  {
    indexName: "permissions_key_unique",
    unique: true,
    primary: false,
    definition: "CREATE UNIQUE INDEX permissions_key_unique ON auth.permissions USING btree (key)",
  },
  primaryIndex("role_permissions_pkey", "role_permissions", "role_id, permission_id"),
  primaryIndex("role_inheritance_pkey", "role_inheritance", "role_id, inherits_role_id"),
  {
    indexName: "user_roles_global_key",
    unique: true,
    primary: false,
    definition: "CREATE UNIQUE INDEX user_roles_global_key ON auth.user_roles USING btree (user_id, role_id) WHERE ((scope_type IS NULL) AND (scope_id IS NULL))",
  },
  primaryIndex("api_keys_pkey", "api_keys", "id"),
  {
    indexName: "user_roles_scoped_key",
    unique: true,
    primary: false,
    definition: "CREATE UNIQUE INDEX user_roles_scoped_key ON auth.user_roles USING btree (user_id, role_id, scope_type, scope_id) WHERE ((scope_type IS NOT NULL) AND (scope_id IS NOT NULL))",
  },
  {
    indexName: "oauth_states_state_hash_key",
    unique: true,
    primary: false,
    definition: "CREATE UNIQUE INDEX oauth_states_state_hash_key ON auth.oauth_states USING btree (state_hash)",
  },
  {
    indexName: "api_keys_key_hash_key",
    unique: true,
    primary: false,
    definition: "CREATE UNIQUE INDEX api_keys_key_hash_key ON auth.api_keys USING btree (key_hash)",
  },
  {
    indexName: "api_keys_prefix_key",
    unique: true,
    primary: false,
    definition: "CREATE UNIQUE INDEX api_keys_prefix_key ON auth.api_keys USING btree (prefix)",
  },
  primaryIndex("audit_log_pkey", "audit_log", "id"),
  {
    indexName: "api_keys_active_name_key",
    unique: true,
    primary: false,
    definition: "CREATE UNIQUE INDEX api_keys_active_name_key ON auth.api_keys USING btree (name) WHERE (revoked_at IS NULL)",
  },
  {
    indexName: "audit_log_occurred_at_id_idx",
    unique: false,
    primary: false,
    definition: "CREATE INDEX audit_log_occurred_at_id_idx ON auth.audit_log USING btree (occurred_at DESC, id DESC)",
  },
  {
    indexName: "audit_log_actor_user_occurred_at_id_idx",
    unique: false,
    primary: false,
    definition: "CREATE INDEX audit_log_actor_user_occurred_at_id_idx ON auth.audit_log USING btree (actor_user_id, occurred_at DESC, id DESC)",
  },
  {
    indexName: "rate_limit_buckets_window_end_idx",
    unique: false,
    primary: false,
    definition: "CREATE INDEX rate_limit_buckets_window_end_idx ON auth.rate_limit_buckets USING btree (window_end)",
  },
];

/** Expected constraint definition and catalog properties. */
export interface ConstraintContract {
  readonly constraintName: string;
  readonly constraintType: string;
  readonly definition: string;
  readonly isDeferrable: boolean;
  readonly initiallyDeferred: boolean;
  readonly deleteAction: string | null;
  readonly localColumns: readonly string[];
  readonly referencedTableName: string | null;
  readonly referencedColumns: readonly string[];
}

const checkConstraint = (constraintName: string, definition: string): ConstraintContract => ({
  constraintName,
  constraintType: "c",
  definition,
  isDeferrable: false,
  initiallyDeferred: false,
  deleteAction: null,
  localColumns: [],
  referencedTableName: null,
  referencedColumns: [],
});
const primaryKey = (constraintName: string, definition: string, localColumns: readonly string[]): ConstraintContract => ({
  constraintName,
  constraintType: "p",
  definition,
  isDeferrable: false,
  initiallyDeferred: false,
  deleteAction: null,
  localColumns,
  referencedTableName: null,
  referencedColumns: [],
});
const uniqueConstraint = (constraintName: string, definition: string, localColumns: readonly string[]): ConstraintContract => ({
  constraintName,
  constraintType: "u",
  definition,
  isDeferrable: false,
  initiallyDeferred: false,
  deleteAction: null,
  localColumns,
  referencedTableName: null,
  referencedColumns: [],
});
const foreignKey = (
  constraintName: string,
  definition: string,
  localColumns: readonly string[],
  deleteAction: string,
  referencedTableName = "users",
  referencedColumns: readonly string[] = ["id"],
): ConstraintContract => ({
  constraintName,
  constraintType: "f",
  definition,
  isDeferrable: false,
  initiallyDeferred: false,
  deleteAction,
  localColumns,
  referencedTableName,
  referencedColumns,
});
const constraintTrigger = (constraintName: string): ConstraintContract => ({
  constraintName,
  constraintType: "t",
  definition: "TRIGGER DEFERRABLE INITIALLY DEFERRED",
  isDeferrable: true,
  initiallyDeferred: true,
  deleteAction: null,
  localColumns: [],
  referencedTableName: null,
  referencedColumns: [],
});

/** Required named constraints; definitions are compared after catalog normalization. */
export const REQUIRED_CONSTRAINTS: readonly ConstraintContract[] = [
  primaryKey("schema_migrations_pkey", "PRIMARY KEY (version)", ["version"]),
  checkConstraint("schema_migrations_version_check", "CHECK (version ~ '^[0-9]{4}_[a-z0-9_]+$'::text)"),
  checkConstraint("schema_migrations_migration_order_check", "CHECK (migration_order > 0)"),
  uniqueConstraint("schema_migrations_migration_order_key", "UNIQUE (migration_order)", ["migration_order"]),
  checkConstraint("schema_migrations_checksum_check", "CHECK (checksum ~ '^[0-9a-f]{64}$'::text)"),
  checkConstraint("schema_migrations_package_version_check", "CHECK (btrim(package_version) <> ''::text)"),
  primaryKey("users_pkey", "PRIMARY KEY (id)", ["id"]),
  checkConstraint("users_user_metadata_object_check", "CHECK (jsonb_typeof(user_metadata) = 'object'::text)"),
  checkConstraint("users_app_metadata_object_check", "CHECK (jsonb_typeof(app_metadata) = 'object'::text)"),
  checkConstraint("users_email_normalized_check", "CHECK (email_normalized IS NULL OR email_normalized = lower(btrim(email_normalized)) AND btrim(email_normalized) <> ''::text)"),
  checkConstraint("users_phone_normalized_check", "CHECK (phone_normalized IS NULL OR phone_normalized = btrim(phone_normalized) AND btrim(phone_normalized) <> ''::text)"),
  primaryKey("identities_pkey", "PRIMARY KEY (id)", ["id"]),
  checkConstraint("identities_provider_check", "CHECK (provider = lower(btrim(provider)) AND btrim(provider) <> ''::text)"),
  checkConstraint("identities_provider_subject_check", "CHECK (btrim(provider_subject) <> ''::text)"),
  checkConstraint("identities_email_normalized_check", "CHECK (email_normalized IS NULL OR email_normalized = lower(btrim(email_normalized)) AND btrim(email_normalized) <> ''::text)"),
  checkConstraint("identities_identity_data_object_check", "CHECK (jsonb_typeof(identity_data) = 'object'::text)"),
  foreignKey("identities_user_id_fkey", "FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE CASCADE", ["user_id"], "CASCADE"),
  uniqueConstraint("identities_provider_subject_key", "UNIQUE (provider, provider_subject)", ["provider", "provider_subject"]),
  primaryKey("password_credentials_pkey", "PRIMARY KEY (user_id)", ["user_id"]),
  checkConstraint("password_credentials_hash_check", "CHECK (auth.is_strong_argon2id_hash(password_hash))"),
  foreignKey("password_credentials_user_id_fkey", "FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE CASCADE", ["user_id"], "CASCADE"),
  primaryKey("sessions_pkey", "PRIMARY KEY (id)", ["id"]),
  checkConstraint("sessions_aal_check", "CHECK (aal >= 1 AND aal <= 3)"),
  checkConstraint("sessions_expiry_check", "CHECK (expires_at > created_at)"),
  foreignKey("sessions_user_id_fkey", "FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE CASCADE", ["user_id"], "CASCADE"),
  primaryKey("refresh_tokens_pkey", "PRIMARY KEY (id)", ["id"]),
  checkConstraint("refresh_tokens_token_hash_length_check", "CHECK (octet_length(token_hash) = 32)"),
  checkConstraint("refresh_tokens_expiry_check", "CHECK (expires_at > issued_at)"),
  checkConstraint("refresh_tokens_parent_check", "CHECK (parent_id IS NULL OR parent_id <> id)"),
  checkConstraint("refresh_tokens_replacement_check", "CHECK (replacement_id IS NULL OR replacement_id <> id)"),
  foreignKey("refresh_tokens_session_id_fkey", "FOREIGN KEY (session_id) REFERENCES auth.sessions(id) ON DELETE CASCADE", ["session_id"], "CASCADE", "sessions"),
  foreignKey("refresh_tokens_parent_id_fkey", "FOREIGN KEY (parent_id) REFERENCES auth.refresh_tokens(id) ON DELETE SET NULL", ["parent_id"], "SET NULL", "refresh_tokens"),
  foreignKey("refresh_tokens_replacement_id_fkey", "FOREIGN KEY (replacement_id) REFERENCES auth.refresh_tokens(id) ON DELETE SET NULL", ["replacement_id"], "SET NULL", "refresh_tokens"),
  uniqueConstraint("refresh_tokens_token_hash_key", "UNIQUE (token_hash)", ["token_hash"]),
  primaryKey("one_time_tokens_pkey", "PRIMARY KEY (id)", ["id"]),
  checkConstraint("one_time_tokens_purpose_check", "CHECK (purpose = ANY (ARRAY['signup'::text, 'email_change'::text, 'recovery'::text, 'magic_link'::text, 'email_otp'::text, 'invite'::text, 'oauth_callback'::text]))"),
  checkConstraint("one_time_tokens_token_hash_length_check", "CHECK (octet_length(token_hash) = 32)"),
  checkConstraint("one_time_tokens_target_check", "CHECK (btrim(target) <> ''::text)"),
  checkConstraint("one_time_tokens_attempt_count_check", "CHECK (attempt_count >= 0 AND attempt_count <= 5)"),
  checkConstraint("one_time_tokens_metadata_object_check", "CHECK (jsonb_typeof(metadata) = 'object'::text)"),
  checkConstraint("one_time_tokens_metadata_redaction_check", "CHECK (auth.audit_metadata_is_safe(metadata))"),
  checkConstraint("one_time_tokens_expiry_check", "CHECK (expires_at > created_at)"),
  checkConstraint("one_time_tokens_recovery_ttl_check", "CHECK (purpose <> 'recovery'::text OR expires_at <= (created_at + '00:15:00'::interval))"),
  checkConstraint("one_time_tokens_signup_ttl_check", "CHECK (purpose <> 'signup'::text OR expires_at <= (created_at + '24:00:00'::interval))"),
  checkConstraint("one_time_tokens_oauth_callback_ttl_check", "CHECK (purpose <> 'oauth_callback'::text OR expires_at <= (created_at + '00:01:00'::interval))"),
  foreignKey("one_time_tokens_user_id_fkey", "FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE CASCADE", ["user_id"], "CASCADE"),
  uniqueConstraint("one_time_tokens_token_hash_key", "UNIQUE (token_hash)", ["token_hash"]),
  primaryKey("oauth_states_pkey", "PRIMARY KEY (id)", ["id"]),
  checkConstraint("oauth_states_state_hash_length_check", "CHECK (octet_length(state_hash) = 32)"),
  checkConstraint("oauth_states_provider_check", "CHECK (provider = lower(btrim(provider)) AND btrim(provider) <> ''::text)"),
  checkConstraint("oauth_states_flow_check", "CHECK (flow = ANY (ARRAY['sign_in'::text, 'link_identity'::text]))"),
  checkConstraint("oauth_states_pkce_challenge_check", "CHECK (btrim(pkce_challenge) <> ''::text)"),
  checkConstraint("oauth_states_redirect_target_check", "CHECK (btrim(redirect_target) <> ''::text)"),
  checkConstraint("oauth_states_expiry_check", "CHECK (expires_at > created_at)"),
  checkConstraint("oauth_states_ttl_check", "CHECK (expires_at <= (created_at + '00:10:00'::interval))"),
  foreignKey("oauth_states_linking_user_id_fkey", "FOREIGN KEY (linking_user_id) REFERENCES auth.users(id) ON DELETE SET NULL", ["linking_user_id"], "SET NULL"),
  uniqueConstraint("oauth_states_state_hash_key", "UNIQUE (state_hash)", ["state_hash"]),
  primaryKey("roles_pkey", "PRIMARY KEY (id)", ["id"]),
  checkConstraint("roles_key_check", "CHECK (key = lower(btrim(key)) AND key ~ '^[a-z0-9_:-]+$'::text)"),
  checkConstraint("roles_name_check", "CHECK (btrim(name) <> ''::text)"),
  checkConstraint("roles_rank_check", "CHECK (rank >= 0)"),
  uniqueConstraint("roles_key_unique", "UNIQUE (key)", ["key"]),
  primaryKey("permissions_pkey", "PRIMARY KEY (id)", ["id"]),
  checkConstraint("permissions_resource_check", "CHECK (resource = lower(btrim(resource)) AND (resource = '*'::text OR resource ~ '^[a-z0-9_:-]+(\\.[a-z0-9_:-]+)*$'::text))"),
  checkConstraint("permissions_action_check", "CHECK (action = lower(btrim(action)) AND (action = '*'::text OR action ~ '^[a-z0-9_:-]+$'::text))"),
  checkConstraint("permissions_key_check", "CHECK (key = lower(btrim(key)) AND key = ((resource || '.'::text) || action))"),
  checkConstraint("permissions_wildcard_check", "CHECK (resource <> '*'::text OR action = '*'::text)"),
  uniqueConstraint("permissions_key_unique", "UNIQUE (key)", ["key"]),
  primaryKey("role_permissions_pkey", "PRIMARY KEY (role_id, permission_id)", ["role_id", "permission_id"]),
  foreignKey("role_permissions_role_id_fkey", "FOREIGN KEY (role_id) REFERENCES auth.roles(id) ON DELETE CASCADE", ["role_id"], "CASCADE", "roles"),
  foreignKey("role_permissions_permission_id_fkey", "FOREIGN KEY (permission_id) REFERENCES auth.permissions(id) ON DELETE CASCADE", ["permission_id"], "CASCADE", "permissions"),
  primaryKey("role_inheritance_pkey", "PRIMARY KEY (role_id, inherits_role_id)", ["role_id", "inherits_role_id"]),
  foreignKey("role_inheritance_role_id_fkey", "FOREIGN KEY (role_id) REFERENCES auth.roles(id) ON DELETE CASCADE", ["role_id"], "CASCADE", "roles"),
  foreignKey("role_inheritance_inherits_role_id_fkey", "FOREIGN KEY (inherits_role_id) REFERENCES auth.roles(id) ON DELETE CASCADE", ["inherits_role_id"], "CASCADE", "roles"),
  constraintTrigger("role_inheritance_cycle_guard"),
  checkConstraint("user_roles_scope_pair_check", "CHECK (scope_type IS NULL AND scope_id IS NULL OR scope_type IS NOT NULL AND scope_id IS NOT NULL AND scope_type = lower(btrim(scope_type)) AND btrim(scope_type) <> ''::text AND btrim(scope_id) <> ''::text)"),
  checkConstraint("user_roles_expiry_check", "CHECK (expires_at IS NULL OR expires_at > assigned_at)"),
  foreignKey("user_roles_user_id_fkey", "FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE CASCADE", ["user_id"], "CASCADE"),
  foreignKey("user_roles_role_id_fkey", "FOREIGN KEY (role_id) REFERENCES auth.roles(id) ON DELETE CASCADE", ["role_id"], "CASCADE", "roles"),
  foreignKey("user_roles_assigned_by_fkey", "FOREIGN KEY (assigned_by) REFERENCES auth.users(id) ON DELETE SET NULL", ["assigned_by"], "SET NULL"),
  primaryKey("api_keys_pkey", "PRIMARY KEY (id)", ["id"]),
  checkConstraint("api_keys_prefix_check", "CHECK (btrim(prefix) <> ''::text)"),
  checkConstraint("api_keys_key_hash_length_check", "CHECK (octet_length(key_hash) = 32)"),
  checkConstraint("api_keys_kind_check", "CHECK (kind = ANY (ARRAY['publishable'::text, 'secret'::text]))"),
  checkConstraint("api_keys_expiry_check", "CHECK (expires_at IS NULL OR expires_at > created_at)"),
  uniqueConstraint("api_keys_key_hash_key", "UNIQUE (key_hash)", ["key_hash"]),
  uniqueConstraint("api_keys_prefix_key", "UNIQUE (prefix)", ["prefix"]),
  checkConstraint("api_keys_name_check", "CHECK (name = btrim(name) AND btrim(name) <> ''::text AND length(name) <= 128)"),
  primaryKey("audit_log_pkey", "PRIMARY KEY (id)", ["id"]),
  checkConstraint("audit_log_action_check", "CHECK (btrim(action) <> ''::text)"),
  checkConstraint("audit_log_target_type_check", "CHECK (btrim(target_type) <> ''::text)"),
  checkConstraint("audit_log_metadata_object_check", "CHECK (jsonb_typeof(metadata) = 'object'::text)"),
  checkConstraint("audit_log_metadata_redaction_check", "CHECK (auth.audit_metadata_is_safe(metadata))"),
  checkConstraint("audit_log_outcome_check", "CHECK (outcome = ANY (ARRAY['success'::text, 'failure'::text]))"),
  primaryKey("rate_limit_buckets_pkey", "PRIMARY KEY (key_digest, bucket, window_start)", ["key_digest", "bucket", "window_start"]),
  checkConstraint("rate_limit_buckets_key_digest_length_check", "CHECK (octet_length(key_digest) = 32)"),
  checkConstraint("rate_limit_buckets_bucket_check", "CHECK (bucket = btrim(bucket) AND btrim(bucket) <> ''::text AND length(bucket) <= 128)"),
  checkConstraint("rate_limit_buckets_window_check", "CHECK (window_end > window_start)"),
  checkConstraint("rate_limit_buckets_count_check", "CHECK (count >= 0 AND count <= 1000000)"),
  checkConstraint("rate_limit_buckets_updated_at_check", "CHECK (updated_at >= created_at)"),
];

/** Expected functions and properties that enforce non-bypassable invariants. */
export interface FunctionContract {
  readonly functionName: string;
  readonly identityArguments: string;
  readonly returnType: string;
  readonly languageName: string;
  readonly volatility: "i" | "s" | "v";
  readonly parallelSafety: "s" | "r" | "u";
  readonly securityDefiner: boolean;
  readonly leakproof: boolean;
  readonly isStrict: boolean;
  readonly config: readonly string[];
  /** SHA-256 of normalized pg_proc.prosrc, not a marker substring. */
  readonly sourceHash: string;
}

export const REQUIRED_FUNCTIONS: readonly FunctionContract[] = [
  {
    functionName: "is_strong_argon2id_hash",
    identityArguments: "password_hash text",
    returnType: "boolean",
    languageName: "sql",
    volatility: "i",
    parallelSafety: "s",
    securityDefiner: false,
    leakproof: false,
    isStrict: false,
    config: ["search_path=pg_catalog, auth"],
    sourceHash: "5e3e4b1b6cffa04eb85bebb1e4dcf19f88424b88bbd4b12765b3c6a6ffd5cb71",
  },
  {
    functionName: "prevent_role_inheritance_cycle",
    identityArguments: "",
    returnType: "trigger",
    languageName: "plpgsql",
    volatility: "v",
    parallelSafety: "u",
    securityDefiner: false,
    leakproof: false,
    isStrict: false,
    config: ["search_path=pg_catalog, auth"],
    sourceHash: "949ed5a52c4c627baf9caab0bd6acd10994f4711f423686f808c04953b926f43",
  },
  {
    functionName: "audit_metadata_is_safe",
    identityArguments: "metadata jsonb",
    returnType: "boolean",
    languageName: "sql",
    volatility: "i",
    parallelSafety: "s",
    securityDefiner: false,
    leakproof: false,
    isStrict: false,
    config: ["search_path=pg_catalog, auth"],
    sourceHash: "11f58c472f4032afa2972d32dde04194e4b77608dd64b48d4f4b71f69f306292",
  },
  {
    functionName: "audit_metadata_redaction_guard",
    identityArguments: "",
    returnType: "trigger",
    languageName: "plpgsql",
    volatility: "v",
    parallelSafety: "u",
    securityDefiner: false,
    leakproof: false,
    isStrict: false,
    config: ["search_path=pg_catalog, auth"],
    sourceHash: "ffa9e7cafd29af950875789bc92c3b07f77334bddfda75b4de39055c2c2a5eae",
  },
  {
    functionName: "reject_audit_mutation",
    identityArguments: "",
    returnType: "trigger",
    languageName: "plpgsql",
    volatility: "v",
    parallelSafety: "u",
    securityDefiner: false,
    leakproof: false,
    isStrict: false,
    config: ["search_path=pg_catalog, auth"],
    sourceHash: "08cbbf898278ad0337e747a823be3c21b4f89d3625c46141bfea08971d1c2738",
  },
];

/** Expected trigger definitions and enabled/properties catalog values. */
export interface TriggerContract {
  readonly triggerName: string;
  readonly tableName: string;
  readonly functionName: string;
  readonly enabled: string;
  readonly triggerType: number;
  readonly definition: string;
}

export const REQUIRED_TRIGGERS: readonly TriggerContract[] = [
  {
    triggerName: "role_inheritance_cycle_guard",
    tableName: "role_inheritance",
    functionName: "prevent_role_inheritance_cycle",
    enabled: "O",
    triggerType: 21,
    definition: "CREATE CONSTRAINT TRIGGER role_inheritance_cycle_guard AFTER INSERT OR UPDATE ON auth.role_inheritance DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION auth.prevent_role_inheritance_cycle()",
  },
  {
    triggerName: "audit_metadata_redaction_guard",
    tableName: "audit_log",
    functionName: "audit_metadata_redaction_guard",
    enabled: "O",
    triggerType: 7,
    definition: "CREATE TRIGGER audit_metadata_redaction_guard BEFORE INSERT ON auth.audit_log FOR EACH ROW EXECUTE FUNCTION auth.audit_metadata_redaction_guard()",
  },
  {
    triggerName: "audit_log_immutable_guard",
    tableName: "audit_log",
    functionName: "reject_audit_mutation",
    enabled: "O",
    triggerType: 27,
    definition: "CREATE TRIGGER audit_log_immutable_guard BEFORE DELETE OR UPDATE ON auth.audit_log FOR EACH ROW EXECUTE FUNCTION auth.reject_audit_mutation()",
  },
];

/** Collapse catalog formatting differences while preserving SQL structure. */
export function normalizeCatalogSql(value: string): string {
  return value.replace(/\s+/g, " ").trim().toLowerCase();
}

/** Normalize only platform formatting noise; preserve body tokens and structure. */
export function normalizeFunctionSource(value: string): string {
  return value
    .replace(/\r\n?/g, "\n")
    .split("\n")
    .map((line) => line.replace(/[ \t]+$/g, ""))
    .join("\n")
    .trim();
}

/** Return the authoritative stable hash used for complete function-body matching. */
export function hashFunctionSource(value: string): string {
  return createHash("sha256").update(normalizeFunctionSource(value), "utf8").digest("hex");
}

/** Check a catalog row against a column contract. */
export function columnMatches(row: ColumnCatalogRow | undefined, expected: ColumnContract): boolean {
  if (!row) return false;
  const actualDefault = row.column_default === null ? null : normalizeCatalogSql(row.column_default);
  const expectedDefault = expected.defaultExpression === null ? null : normalizeCatalogSql(expected.defaultExpression);
  return row.column_name === expected.columnName
    && row.data_type === expected.dataType
    && row.udt_name === expected.udtName
    && (row.is_nullable === "YES") === expected.nullable
    && actualDefault === expectedDefault;
}

/** Check an index row against its complete canonical definition. */
export function indexMatches(row: IndexCatalogRow | undefined, expected: IndexContract): boolean {
  return row !== undefined
    && row.index_name === expected.indexName
    && row.is_unique === expected.unique
    && row.is_primary === expected.primary
    && row.index_valid
    && row.index_ready
    && normalizeCatalogSql(row.index_definition) === normalizeCatalogSql(expected.definition);
}

/** Check a constraint row against its expression, columns, and referential actions. */
export function constraintMatches(row: ConstraintCatalogRow | undefined, expected: ConstraintContract): boolean {
  return row !== undefined
    && row.constraint_name === expected.constraintName
    && row.constraint_type === expected.constraintType
    && row.is_validated
    && row.is_deferrable === expected.isDeferrable
    && row.initially_deferred === expected.initiallyDeferred
    && row.delete_action === expected.deleteAction
    && (expected.constraintType === "c" || expected.constraintType === "t"
      || row.local_columns.join("\u0000") === expected.localColumns.join("\u0000"))
    && (expected.constraintType !== "f" || row.referenced_table_name === expected.referencedTableName)
    && (expected.constraintType !== "f"
      || row.referenced_columns.join("\u0000") === expected.referencedColumns.join("\u0000"))
    && normalizeCatalogSql(row.definition) === normalizeCatalogSql(expected.definition);
}

/** Check the complete normalized function catalog contract, including its body hash. */
export function functionMatches(row: FunctionCatalogRow | undefined, expected: FunctionContract): boolean {
  if (!row) return false;
  const actualConfig = (row.config ?? []).map((entry) => entry === null ? null : normalizeCatalogSql(entry));
  const expectedConfig = expected.config.map(normalizeCatalogSql);
  return row.function_name === expected.functionName
    && row.identity_arguments === expected.identityArguments
    && row.return_type === expected.returnType
    && row.language_name === expected.languageName
    && row.volatility === expected.volatility
    && row.parallel_safety === expected.parallelSafety
    && row.security_definer === expected.securityDefiner
    && row.leakproof === expected.leakproof
    && row.is_strict === expected.isStrict
    && actualConfig.length === expectedConfig.length
    && actualConfig.every((entry, index) => entry === expectedConfig[index])
    && hashFunctionSource(row.prosrc) === expected.sourceHash;
}

/** Check trigger definition, enabled state, trigger properties, table, and function. */
export function triggerMatches(row: TriggerCatalogRow | undefined, expected: TriggerContract): boolean {
  if (!row) return false;
  const definition = normalizeCatalogSql(row.definition);
  return row.trigger_name === expected.triggerName
    && row.table_name === expected.tableName
    && row.function_name === expected.functionName
    && row.enabled === expected.enabled
    && row.trigger_type === expected.triggerType
    && definition === normalizeCatalogSql(expected.definition);
}
