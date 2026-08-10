CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE SCHEMA IF NOT EXISTS auth;

CREATE TABLE auth.schema_migrations (
  version text PRIMARY KEY,
  migration_order integer NOT NULL,
  checksum text NOT NULL,
  applied_at timestamptz NOT NULL DEFAULT now(),
  package_version text NOT NULL,
  CONSTRAINT schema_migrations_version_check CHECK (version ~ '^[0-9]{4}_[a-z0-9_]+$'),
  CONSTRAINT schema_migrations_migration_order_check CHECK (migration_order > 0),
  CONSTRAINT schema_migrations_migration_order_key UNIQUE (migration_order),
  CONSTRAINT schema_migrations_checksum_check CHECK (checksum ~ '^[0-9a-f]{64}$'),
  CONSTRAINT schema_migrations_package_version_check CHECK (btrim(package_version) <> '')
);

CREATE OR REPLACE FUNCTION auth.is_strong_argon2id_hash(password_hash text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog, auth
AS $$
WITH parsed AS (
  SELECT regexp_match(
    password_hash,
    '^\$argon2id\$v=([0-9]+)\$m=([0-9]+),t=([0-9]+),p=([0-9]+)(,[a-z][a-z0-9_]*=[^,$]+)*\$([A-Za-z0-9+/]+={0,2})\$([A-Za-z0-9+/]+={0,2})$'
  ) AS parts
)
SELECT parts IS NOT NULL
   AND parts[1] = '19'
   AND parts[2]::numeric >= 65536
   AND parts[3]::numeric >= 3
   AND parts[4]::numeric >= 1
FROM parsed;
$$;

CREATE OR REPLACE FUNCTION auth.audit_metadata_is_safe(metadata jsonb)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog, auth
AS $$
WITH RECURSIVE nodes(value, depth) AS (
  SELECT metadata, 0
  UNION ALL
  SELECT child.value, nodes.depth + 1
    FROM nodes
    CROSS JOIN LATERAL (
      SELECT object_entry.value
        FROM jsonb_each(
          CASE WHEN jsonb_typeof(nodes.value) = 'object'
            THEN nodes.value ELSE '{}'::jsonb END
        ) AS object_entry(key, value)
      UNION ALL
      SELECT array_entry.value
        FROM jsonb_array_elements(
          CASE WHEN jsonb_typeof(nodes.value) = 'array'
            THEN nodes.value ELSE '[]'::jsonb END
        ) AS array_entry(value)
    ) AS child
   WHERE nodes.depth < 64
), strings AS (
  SELECT value #>> '{}' AS text_value
    FROM nodes
   WHERE jsonb_typeof(value) = 'string'
)
SELECT metadata IS NOT NULL
   AND jsonb_typeof(metadata) = 'object'
   AND NOT EXISTS (
     SELECT 1
       FROM jsonb_each(metadata) AS entry(key, value)
      WHERE CASE entry.key
        WHEN 'event' THEN
          jsonb_typeof(entry.value) = 'string'
          AND length(entry.value #>> '{}') BETWEEN 1 AND 64
          AND entry.value #>> '{}' ~ '^[a-z][a-z0-9_.:-]{0,63}$'
        WHEN 'reason' THEN
          jsonb_typeof(entry.value) = 'string'
          AND length(entry.value #>> '{}') BETWEEN 1 AND 64
          AND entry.value #>> '{}' ~ '^[a-z][a-z0-9_.:-]{0,63}$'
        WHEN 'error_code' THEN
          jsonb_typeof(entry.value) = 'string'
          AND length(entry.value #>> '{}') BETWEEN 1 AND 64
          AND entry.value #>> '{}' ~ '^[A-Za-z][A-Za-z0-9_.:-]{0,63}$'
        WHEN 'provider' THEN
          jsonb_typeof(entry.value) = 'string'
          AND length(entry.value #>> '{}') BETWEEN 1 AND 32
          AND entry.value #>> '{}' ~ '^[a-z][a-z0-9_.:-]{0,31}$'
        WHEN 'operation' THEN
          jsonb_typeof(entry.value) = 'string'
          AND length(entry.value #>> '{}') BETWEEN 1 AND 64
          AND entry.value #>> '{}' ~ '^[a-z][a-z0-9_.:-]{0,63}$'
        WHEN 'status' THEN
          jsonb_typeof(entry.value) = 'string'
          AND length(entry.value #>> '{}') BETWEEN 1 AND 32
          AND entry.value #>> '{}' ~ '^[a-z][a-z0-9_.:-]{0,31}$'
        WHEN 'user_id' THEN
          jsonb_typeof(entry.value) = 'string'
          AND entry.value #>> '{}' ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        WHEN 'session_id' THEN
          jsonb_typeof(entry.value) = 'string'
          AND entry.value #>> '{}' ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        WHEN 'api_key_id' THEN
          jsonb_typeof(entry.value) = 'string'
          AND entry.value #>> '{}' ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        WHEN 'target_id' THEN
          jsonb_typeof(entry.value) = 'string'
          AND entry.value #>> '{}' ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        WHEN 'request_id' THEN
          jsonb_typeof(entry.value) = 'string'
          AND length(entry.value #>> '{}') BETWEEN 1 AND 128
          AND entry.value #>> '{}' ~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$'
        WHEN 'success' THEN jsonb_typeof(entry.value) = 'boolean'
        WHEN 'changed' THEN jsonb_typeof(entry.value) = 'boolean'
        WHEN 'dry_run' THEN jsonb_typeof(entry.value) = 'boolean'
        WHEN 'count' THEN
          jsonb_typeof(entry.value) = 'number'
          AND entry.value #>> '{}' ~ '^(0|[1-9][0-9]{0,6})$'
          AND CASE WHEN entry.value #>> '{}' ~ '^(0|[1-9][0-9]{0,6})$'
            THEN (entry.value #>> '{}')::numeric ELSE -1 END BETWEEN 0 AND 1000000
        WHEN 'attempt_count' THEN
          jsonb_typeof(entry.value) = 'number'
          AND entry.value #>> '{}' ~ '^(0|[1-9][0-9]{0,6})$'
          AND CASE WHEN entry.value #>> '{}' ~ '^(0|[1-9][0-9]{0,6})$'
            THEN (entry.value #>> '{}')::numeric ELSE -1 END BETWEEN 0 AND 1000000
        WHEN 'rank' THEN
          jsonb_typeof(entry.value) = 'number'
          AND entry.value #>> '{}' ~ '^(0|[1-9][0-9]{0,6})$'
          AND CASE WHEN entry.value #>> '{}' ~ '^(0|[1-9][0-9]{0,6})$'
            THEN (entry.value #>> '{}')::numeric ELSE -1 END BETWEEN 0 AND 1000000
        WHEN 'changed_fields' THEN
          jsonb_typeof(entry.value) = 'array'
          AND jsonb_array_length(
            CASE WHEN jsonb_typeof(entry.value) = 'array'
              THEN entry.value ELSE '[]'::jsonb END
          ) BETWEEN 0 AND 32
          AND NOT EXISTS (
            SELECT 1
              FROM jsonb_array_elements(
                CASE WHEN jsonb_typeof(entry.value) = 'array'
                  THEN entry.value ELSE '[]'::jsonb END
              ) AS field(value)
             WHERE jsonb_typeof(field.value) <> 'string'
                OR length(field.value #>> '{}') NOT BETWEEN 1 AND 64
                OR field.value #>> '{}' !~ '^[a-z][a-z0-9_]{0,63}$'
          )
        ELSE false
      END IS NOT TRUE
   )
   AND NOT EXISTS (
     SELECT 1 FROM nodes
      WHERE depth > 0 AND jsonb_typeof(value) = 'object'
   )
   AND NOT EXISTS (
     SELECT 1 FROM nodes
      WHERE depth >= 64 AND jsonb_typeof(value) IN ('object', 'array')
   )
   AND NOT EXISTS (
     SELECT 1 FROM strings
      WHERE text_value ~* '^\s*(bearer|basic)\s+\S+'
         OR text_value ~ '^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$'
         OR text_value ~* '-----BEGIN[[:space:]]+[A-Z0-9 ]*(PRIVATE|ENCRYPTED)?[[:space:]]+KEY-----'
         OR text_value ~* '^[[:space:]]*(https?|postgres(?:ql)?|redis|mongodb(?:\+srv)?):\/\/[^[:space:]@\/]+:[^[:space:]@\/]+@'
         OR text_value ~* '^(sk|pk|rk|tok|secret|key)_[A-Za-z0-9_-]{8,}$'
         OR text_value ~* '^\$(argon2(id|i|d)|2[aby]?|scrypt|pbkdf2)\$'
         OR text_value ~ '^[0-9a-fA-F]{64}$'
   );
$$;

CREATE TABLE auth.users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email text,
  email_normalized text,
  phone text,
  phone_normalized text,
  email_confirmed_at timestamptz,
  phone_confirmed_at timestamptz,
  last_sign_in_at timestamptz,
  banned_until timestamptz,
  user_metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  app_metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz,
  CONSTRAINT users_user_metadata_object_check CHECK (jsonb_typeof(user_metadata) = 'object'),
  CONSTRAINT users_app_metadata_object_check CHECK (jsonb_typeof(app_metadata) = 'object'),
  CONSTRAINT users_email_normalized_check CHECK (
    email_normalized IS NULL OR (
      email_normalized = lower(btrim(email_normalized))
      AND btrim(email_normalized) <> ''
    )
  ),
  CONSTRAINT users_phone_normalized_check CHECK (
    phone_normalized IS NULL OR (
      phone_normalized = btrim(phone_normalized)
      AND btrim(phone_normalized) <> ''
    )
  )
);

CREATE UNIQUE INDEX users_email_normalized_key
  ON auth.users (email_normalized)
  WHERE email_normalized IS NOT NULL;

CREATE UNIQUE INDEX users_phone_normalized_key
  ON auth.users (phone_normalized)
  WHERE phone_normalized IS NOT NULL;

CREATE TABLE auth.identities (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL,
  provider text NOT NULL,
  provider_subject text NOT NULL,
  email text,
  email_normalized text,
  identity_data jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT identities_provider_check CHECK (provider = lower(btrim(provider)) AND btrim(provider) <> ''),
  CONSTRAINT identities_provider_subject_check CHECK (btrim(provider_subject) <> ''),
  CONSTRAINT identities_email_normalized_check CHECK (
    email_normalized IS NULL OR (
      email_normalized = lower(btrim(email_normalized))
      AND btrim(email_normalized) <> ''
    )
  ),
  CONSTRAINT identities_identity_data_object_check CHECK (jsonb_typeof(identity_data) = 'object'),
  CONSTRAINT identities_user_id_fkey FOREIGN KEY (user_id)
    REFERENCES auth.users (id) ON DELETE CASCADE,
  CONSTRAINT identities_provider_subject_key UNIQUE (provider, provider_subject)
);

CREATE TABLE auth.password_credentials (
  user_id uuid PRIMARY KEY,
  password_hash text NOT NULL,
  password_updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT password_credentials_hash_check CHECK (auth.is_strong_argon2id_hash(password_hash)),
  CONSTRAINT password_credentials_user_id_fkey FOREIGN KEY (user_id)
    REFERENCES auth.users (id) ON DELETE CASCADE
);

CREATE TABLE auth.sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL,
  aal smallint NOT NULL DEFAULT 1,
  ip_address inet,
  user_agent text,
  created_at timestamptz NOT NULL DEFAULT now(),
  refreshed_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  CONSTRAINT sessions_aal_check CHECK (aal BETWEEN 1 AND 3),
  CONSTRAINT sessions_expiry_check CHECK (expires_at > created_at),
  CONSTRAINT sessions_user_id_fkey FOREIGN KEY (user_id)
    REFERENCES auth.users (id) ON DELETE CASCADE
);

CREATE TABLE auth.refresh_tokens (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id uuid NOT NULL,
  token_hash bytea NOT NULL,
  family_id uuid NOT NULL,
  parent_id uuid,
  replacement_id uuid,
  issued_at timestamptz NOT NULL DEFAULT now(),
  used_at timestamptz,
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  CONSTRAINT refresh_tokens_token_hash_length_check CHECK (octet_length(token_hash) = 32),
  CONSTRAINT refresh_tokens_expiry_check CHECK (expires_at > issued_at),
  CONSTRAINT refresh_tokens_parent_check CHECK (parent_id IS NULL OR parent_id <> id),
  CONSTRAINT refresh_tokens_replacement_check CHECK (replacement_id IS NULL OR replacement_id <> id),
  CONSTRAINT refresh_tokens_session_id_fkey FOREIGN KEY (session_id)
    REFERENCES auth.sessions (id) ON DELETE CASCADE,
  CONSTRAINT refresh_tokens_parent_id_fkey FOREIGN KEY (parent_id)
    REFERENCES auth.refresh_tokens (id) ON DELETE SET NULL,
  CONSTRAINT refresh_tokens_replacement_id_fkey FOREIGN KEY (replacement_id)
    REFERENCES auth.refresh_tokens (id) ON DELETE SET NULL,
  CONSTRAINT refresh_tokens_token_hash_key UNIQUE (token_hash)
);

CREATE TABLE auth.one_time_tokens (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid,
  purpose text NOT NULL,
  token_hash bytea NOT NULL,
  target text NOT NULL,
  redirect text,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  attempt_count integer NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  CONSTRAINT one_time_tokens_purpose_check CHECK (
    purpose IN ('signup', 'email_change', 'recovery', 'magic_link', 'email_otp', 'invite')
  ),
  CONSTRAINT one_time_tokens_token_hash_length_check CHECK (octet_length(token_hash) = 32),
  CONSTRAINT one_time_tokens_target_check CHECK (btrim(target) <> ''),
  CONSTRAINT one_time_tokens_attempt_count_check CHECK (attempt_count BETWEEN 0 AND 5),
  CONSTRAINT one_time_tokens_metadata_object_check CHECK (jsonb_typeof(metadata) = 'object'),
  CONSTRAINT one_time_tokens_metadata_redaction_check CHECK (auth.audit_metadata_is_safe(metadata)),
  CONSTRAINT one_time_tokens_expiry_check CHECK (expires_at > created_at),
  CONSTRAINT one_time_tokens_recovery_ttl_check CHECK (
    purpose <> 'recovery' OR expires_at <= created_at + interval '15 minutes'
  ),
  CONSTRAINT one_time_tokens_signup_ttl_check CHECK (
    purpose <> 'signup' OR expires_at <= created_at + interval '24 hours'
  ),
  CONSTRAINT one_time_tokens_user_id_fkey FOREIGN KEY (user_id)
    REFERENCES auth.users (id) ON DELETE CASCADE,
  CONSTRAINT one_time_tokens_token_hash_key UNIQUE (token_hash)
);
