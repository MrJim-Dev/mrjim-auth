CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE SCHEMA IF NOT EXISTS auth;

CREATE TABLE auth.schema_migrations (
  version text PRIMARY KEY,
  checksum text NOT NULL,
  applied_at timestamptz NOT NULL DEFAULT now(),
  package_version text NOT NULL,
  CONSTRAINT schema_migrations_version_check CHECK (version ~ '^[0-9]{4}_[a-z0-9_]+$'),
  CONSTRAINT schema_migrations_checksum_check CHECK (checksum ~ '^[0-9a-f]{64}$'),
  CONSTRAINT schema_migrations_package_version_check CHECK (btrim(package_version) <> '')
);

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
    email_normalized IS NULL OR email_normalized = lower(btrim(email_normalized))
  ),
  CONSTRAINT users_phone_normalized_check CHECK (
    phone_normalized IS NULL OR phone_normalized = btrim(phone_normalized)
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
    email_normalized IS NULL OR email_normalized = lower(btrim(email_normalized))
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
  CONSTRAINT password_credentials_hash_check CHECK (password_hash ~ '^\$argon2id\$'),
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
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  CONSTRAINT one_time_tokens_purpose_check CHECK (
    purpose IN ('signup', 'email_change', 'recovery', 'magic_link', 'email_otp', 'invite')
  ),
  CONSTRAINT one_time_tokens_token_hash_length_check CHECK (octet_length(token_hash) = 32),
  CONSTRAINT one_time_tokens_target_check CHECK (btrim(target) <> ''),
  CONSTRAINT one_time_tokens_attempt_count_check CHECK (attempt_count BETWEEN 0 AND 5),
  CONSTRAINT one_time_tokens_metadata_object_check CHECK (jsonb_typeof(metadata) = 'object'),
  CONSTRAINT one_time_tokens_user_id_fkey FOREIGN KEY (user_id)
    REFERENCES auth.users (id) ON DELETE CASCADE,
  CONSTRAINT one_time_tokens_token_hash_key UNIQUE (token_hash)
);
