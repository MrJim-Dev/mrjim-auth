ALTER TABLE auth.api_keys
  ADD COLUMN name text;

UPDATE auth.api_keys
   SET name = btrim(prefix)
 WHERE name IS NULL;

ALTER TABLE auth.api_keys
  ALTER COLUMN name SET NOT NULL;

ALTER TABLE auth.api_keys
  ADD CONSTRAINT api_keys_name_check
  CHECK (name = btrim(name) AND btrim(name) <> ''::text AND length(name) <= 128);

ALTER TABLE auth.permissions
  DROP CONSTRAINT permissions_resource_check;

ALTER TABLE auth.permissions
  ADD CONSTRAINT permissions_resource_check
  CHECK (
    resource = lower(btrim(resource))
    AND (
      resource = '*'::text
      OR resource ~ '^[a-z0-9_:-]+(\.[a-z0-9_:-]+)*$'::text
    )
  );

CREATE UNIQUE INDEX api_keys_active_name_key
    ON auth.api_keys USING btree (name)
 WHERE (revoked_at IS NULL);

CREATE INDEX audit_log_occurred_at_id_idx
    ON auth.audit_log USING btree (occurred_at DESC, id DESC);

CREATE INDEX audit_log_actor_user_occurred_at_id_idx
    ON auth.audit_log USING btree (actor_user_id, occurred_at DESC, id DESC);

CREATE TABLE auth.rate_limit_buckets (
  key_digest bytea NOT NULL,
  bucket text NOT NULL,
  window_start timestamptz NOT NULL,
  window_end timestamptz NOT NULL,
  count integer NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT rate_limit_buckets_pkey PRIMARY KEY (key_digest, bucket, window_start),
  CONSTRAINT rate_limit_buckets_key_digest_length_check CHECK (octet_length(key_digest) = 32),
  CONSTRAINT rate_limit_buckets_bucket_check CHECK (
    bucket = btrim(bucket)
    AND btrim(bucket) <> ''::text
    AND length(bucket) <= 128
  ),
  CONSTRAINT rate_limit_buckets_window_check CHECK (window_end > window_start),
  CONSTRAINT rate_limit_buckets_count_check CHECK (count >= 0 AND count <= 1000000),
  CONSTRAINT rate_limit_buckets_updated_at_check CHECK (updated_at >= created_at)
);

CREATE INDEX rate_limit_buckets_window_end_idx
    ON auth.rate_limit_buckets USING btree (window_end);
