ALTER TABLE auth.one_time_tokens
  DROP CONSTRAINT one_time_tokens_purpose_check;

ALTER TABLE auth.one_time_tokens
  ADD CONSTRAINT one_time_tokens_purpose_check
  CHECK (purpose IN ('signup', 'email_change', 'recovery', 'magic_link', 'email_otp', 'invite', 'oauth_callback'));

ALTER TABLE auth.one_time_tokens
  ADD CONSTRAINT one_time_tokens_oauth_callback_ttl_check
  CHECK (
    purpose <> 'oauth_callback'
    OR expires_at <= created_at + interval '60 seconds'
  );
