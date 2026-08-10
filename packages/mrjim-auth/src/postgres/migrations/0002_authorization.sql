CREATE TABLE auth.roles (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  key text NOT NULL,
  name text NOT NULL,
  description text,
  rank integer NOT NULL DEFAULT 0,
  is_system boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT roles_key_check CHECK (key = lower(btrim(key)) AND key ~ '^[a-z0-9_:-]+$'),
  CONSTRAINT roles_name_check CHECK (btrim(name) <> ''),
  CONSTRAINT roles_rank_check CHECK (rank >= 0),
  CONSTRAINT roles_key_unique UNIQUE (key)
);

CREATE TABLE auth.permissions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  key text NOT NULL,
  resource text NOT NULL,
  action text NOT NULL,
  description text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT permissions_resource_check CHECK (
    resource = lower(btrim(resource)) AND (resource = '*' OR resource ~ '^[a-z0-9_:-]+$')
  ),
  CONSTRAINT permissions_action_check CHECK (
    action = lower(btrim(action)) AND (action = '*' OR action ~ '^[a-z0-9_:-]+$')
  ),
  CONSTRAINT permissions_key_check CHECK (
    key = lower(btrim(key)) AND key = resource || '.' || action
  ),
  CONSTRAINT permissions_wildcard_check CHECK (resource <> '*' OR action = '*'),
  CONSTRAINT permissions_key_unique UNIQUE (key)
);

CREATE TABLE auth.role_permissions (
  role_id uuid NOT NULL,
  permission_id uuid NOT NULL,
  CONSTRAINT role_permissions_pkey PRIMARY KEY (role_id, permission_id),
  CONSTRAINT role_permissions_role_id_fkey FOREIGN KEY (role_id)
    REFERENCES auth.roles (id) ON DELETE CASCADE,
  CONSTRAINT role_permissions_permission_id_fkey FOREIGN KEY (permission_id)
    REFERENCES auth.permissions (id) ON DELETE CASCADE
);

CREATE TABLE auth.role_inheritance (
  role_id uuid NOT NULL,
  inherits_role_id uuid NOT NULL,
  CONSTRAINT role_inheritance_pkey PRIMARY KEY (role_id, inherits_role_id),
  CONSTRAINT role_inheritance_role_id_fkey FOREIGN KEY (role_id)
    REFERENCES auth.roles (id) ON DELETE CASCADE,
  CONSTRAINT role_inheritance_inherits_role_id_fkey FOREIGN KEY (inherits_role_id)
    REFERENCES auth.roles (id) ON DELETE CASCADE
);

CREATE OR REPLACE FUNCTION auth.prevent_role_inheritance_cycle()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, auth
AS $$
DECLARE
  has_cycle boolean;
BEGIN
  WITH RECURSIVE reachable(role_id) AS (
    SELECT NEW.inherits_role_id
    UNION
    SELECT inheritance.inherits_role_id
      FROM auth.role_inheritance AS inheritance
      JOIN reachable ON reachable.role_id = inheritance.role_id
  )
  SELECT EXISTS (
    SELECT 1 FROM reachable WHERE reachable.role_id = NEW.role_id
  ) INTO has_cycle;

  IF has_cycle THEN
    RAISE EXCEPTION 'role_inheritance_cycle: role inheritance cycle detected'
      USING ERRCODE = '23514', CONSTRAINT = 'role_inheritance_cycle';
  END IF;
  RETURN NEW;
END;
$$;

CREATE CONSTRAINT TRIGGER role_inheritance_cycle_guard
AFTER INSERT OR UPDATE ON auth.role_inheritance
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION auth.prevent_role_inheritance_cycle();

CREATE TABLE auth.user_roles (
  user_id uuid NOT NULL,
  role_id uuid NOT NULL,
  scope_type text,
  scope_id text,
  assigned_by uuid,
  assigned_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz,
  CONSTRAINT user_roles_scope_pair_check CHECK (
    (scope_type IS NULL AND scope_id IS NULL)
    OR (scope_type IS NOT NULL AND scope_id IS NOT NULL
      AND scope_type = lower(btrim(scope_type)) AND btrim(scope_type) <> ''
      AND btrim(scope_id) <> '')
  ),
  CONSTRAINT user_roles_expiry_check CHECK (expires_at IS NULL OR expires_at > assigned_at),
  CONSTRAINT user_roles_user_id_fkey FOREIGN KEY (user_id)
    REFERENCES auth.users (id) ON DELETE CASCADE,
  CONSTRAINT user_roles_role_id_fkey FOREIGN KEY (role_id)
    REFERENCES auth.roles (id) ON DELETE CASCADE,
  CONSTRAINT user_roles_assigned_by_fkey FOREIGN KEY (assigned_by)
    REFERENCES auth.users (id) ON DELETE SET NULL
);

CREATE UNIQUE INDEX user_roles_global_key
  ON auth.user_roles (user_id, role_id)
  WHERE scope_type IS NULL AND scope_id IS NULL;

CREATE UNIQUE INDEX user_roles_scoped_key
  ON auth.user_roles (user_id, role_id, scope_type, scope_id)
  WHERE scope_type IS NOT NULL AND scope_id IS NOT NULL;
