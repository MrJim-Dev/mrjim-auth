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
  CONSTRAINT oauth_states_flow_check CHECK (btrim(flow) <> ''),
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
