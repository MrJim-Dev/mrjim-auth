ALTER TABLE auth.one_time_tokens
  ADD CONSTRAINT one_time_tokens_metadata_redaction_check
  CHECK (auth.audit_metadata_is_safe(metadata));

ALTER TABLE auth.oauth_states
  DROP CONSTRAINT oauth_states_flow_check;

ALTER TABLE auth.oauth_states
  ADD CONSTRAINT oauth_states_flow_check
  CHECK (flow IN ('sign_in', 'link_identity'));
