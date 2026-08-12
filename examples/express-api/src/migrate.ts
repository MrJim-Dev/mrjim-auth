import { Pool } from "pg";
import { migrate, verifySchema } from "mrjim-auth/postgres";
import { requiredEnv } from "./config.js";

export async function migrateDatabase(connectionString = requiredEnv("DATABASE_URL")) {
  const pool = new Pool({ connectionString, max: 2 });
  try {
    const result = await migrate(pool, { direction: "up" });
    const verification = await verifySchema(pool);
    if (!verification.ok) throw new Error(`auth schema verification failed: ${verification.errors.join("; ")}`);
    return result;
  } finally {
    await pool.end();
  }
}

if (import.meta.main) {
  const result = await migrateDatabase();
  console.log(result.applied.length === 0 ? "auth schema is current" : `applied: ${result.applied.join(", ")}`);
}
