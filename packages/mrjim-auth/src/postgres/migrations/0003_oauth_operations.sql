CREATE TABLE auth.oauth_states (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  state_hash bytea NOT NULL,
  provider text NOT NULL,
  flow text NOT NULL,
  pkce_challenge text NOT NULL,
  encrypted_verifier bytea,
  redirect_target text NOT NULL,
  linking_user_id uuid,
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT oauth_states_state_hash_length_check CHECK (octet_length(state_hash) = 32),
  CONSTRAINT oauth_states_provider_check CHECK (provider = lower(btrim(provider)) AND btrim(provider) <> ''),
  CONSTRAINT oauth_states_flow_check CHECK (flow IN ('sign_in', 'link_identity')),
  CONSTRAINT oauth_states_pkce_challenge_check CHECK (btrim(pkce_challenge) <> ''),
  CONSTRAINT oauth_states_redirect_target_check CHECK (btrim(redirect_target) <> ''),
  CONSTRAINT oauth_states_expiry_check CHECK (expires_at > created_at),
  CONSTRAINT oauth_states_ttl_check CHECK (expires_at <= created_at + interval '10 minutes'),
  CONSTRAINT oauth_states_linking_user_id_fkey FOREIGN KEY (linking_user_id)
    REFERENCES auth.users (id) ON DELETE SET NULL,
  CONSTRAINT oauth_states_state_hash_key UNIQUE (state_hash)
);

CREATE TABLE auth.api_keys (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  prefix text NOT NULL,
  key_hash bytea NOT NULL,
  kind text NOT NULL,
  scopes text[] NOT NULL DEFAULT ARRAY[]::text[],
  last_used_at timestamptz,
  expires_at timestamptz,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT api_keys_prefix_check CHECK (btrim(prefix) <> ''),
  CONSTRAINT api_keys_key_hash_length_check CHECK (octet_length(key_hash) = 32),
  CONSTRAINT api_keys_kind_check CHECK (kind IN ('publishable', 'secret')),
  CONSTRAINT api_keys_expiry_check CHECK (expires_at IS NULL OR expires_at > created_at),
  CONSTRAINT api_keys_key_hash_key UNIQUE (key_hash),
  CONSTRAINT api_keys_prefix_key UNIQUE (prefix)
);

CREATE TABLE auth.audit_log (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  actor_user_id uuid,
  actor_key_id uuid,
  actor_session_id uuid,
  action text NOT NULL,
  target_type text NOT NULL,
  target_id uuid,
  ip_address inet,
  user_agent text,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  outcome text NOT NULL,
  occurred_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT audit_log_action_check CHECK (btrim(action) <> ''),
  CONSTRAINT audit_log_target_type_check CHECK (btrim(target_type) <> ''),
  CONSTRAINT audit_log_metadata_object_check CHECK (jsonb_typeof(metadata) = 'object'),
  CONSTRAINT audit_log_metadata_redaction_check CHECK (auth.audit_metadata_is_safe(metadata)),
  CONSTRAINT audit_log_outcome_check CHECK (outcome IN ('success', 'failure'))
);

CREATE OR REPLACE FUNCTION auth.audit_metadata_redaction_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, auth
AS $$
BEGIN
  IF NOT auth.audit_metadata_is_safe(NEW.metadata) THEN
    RAISE EXCEPTION 'audit_metadata_redaction: sensitive material is forbidden in audit metadata'
      USING ERRCODE = '23514', CONSTRAINT = 'audit_log_metadata_redaction_check';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER audit_metadata_redaction_guard
BEFORE INSERT ON auth.audit_log
FOR EACH ROW
EXECUTE FUNCTION auth.audit_metadata_redaction_guard();

CREATE OR REPLACE FUNCTION auth.reject_audit_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, auth
AS $$
BEGIN
  RAISE EXCEPTION 'audit_log_immutable: audit rows are immutable'
    USING ERRCODE = '55000', CONSTRAINT = 'audit_log_immutable';
END;
$$;

CREATE TRIGGER audit_log_immutable_guard
BEFORE UPDATE OR DELETE ON auth.audit_log
FOR EACH ROW
EXECUTE FUNCTION auth.reject_audit_mutation();
