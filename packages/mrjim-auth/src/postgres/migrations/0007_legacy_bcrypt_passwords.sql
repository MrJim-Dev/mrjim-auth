CREATE OR REPLACE FUNCTION auth.is_supported_password_hash(password_hash text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog, auth
AS $$
SELECT auth.is_strong_argon2id_hash(password_hash)
    OR password_hash ~ '^\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}$';
$$;

ALTER TABLE auth.password_credentials
  DROP CONSTRAINT password_credentials_hash_check;

ALTER TABLE auth.password_credentials
  ADD CONSTRAINT password_credentials_hash_check
  CHECK (auth.is_supported_password_hash(password_hash));
