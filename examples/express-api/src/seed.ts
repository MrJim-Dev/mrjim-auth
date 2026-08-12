import { Pool } from "pg";
import { requiredEnv } from "./config.js";

const seedSql = `
  INSERT INTO auth.roles (key, name, description, rank, is_system)
  VALUES
    ('user', 'User', 'Default authenticated role', 10, true),
    ('admin', 'Administrator', 'Protected project administrator', 100, true)
  ON CONFLICT (key) DO UPDATE
    SET name = EXCLUDED.name,
        description = EXCLUDED.description,
        rank = EXCLUDED.rank,
        is_system = EXCLUDED.is_system,
        updated_at = now();

  INSERT INTO auth.permissions (key, resource, action, description)
  VALUES ('invoice.read', 'invoice', 'read', 'Read project invoices')
  ON CONFLICT (key) DO UPDATE
    SET resource = EXCLUDED.resource,
        action = EXCLUDED.action,
        description = EXCLUDED.description,
        updated_at = now();

  INSERT INTO auth.role_permissions (role_id, permission_id)
  SELECT role.id, permission.id
    FROM auth.roles AS role
    CROSS JOIN auth.permissions AS permission
   WHERE role.key IN ('user', 'admin')
     AND permission.key = 'invoice.read'
  ON CONFLICT (role_id, permission_id) DO NOTHING;
`;

export async function seedAuthorization(connectionString = requiredEnv("DATABASE_URL")): Promise<void> {
  const pool = new Pool({ connectionString, max: 1 });
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query(seedSql);
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
    await pool.end();
  }
}

if (import.meta.main) {
  await seedAuthorization();
  console.log("seeded roles: user, admin; permission: invoice.read");
}
