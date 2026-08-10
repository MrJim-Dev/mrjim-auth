import type { Pool } from "pg";
import { MIGRATIONS } from "./manifest.js";
import { readAppliedMigrationRows } from "./internal/catalog.js";
import {
  readMigrationStatuses,
  validateAppliedHistory,
  type MigrationState,
  type MigrationStatus,
} from "./internal/migration-state.js";
import { REQUIRED_TABLES } from "./internal/schema-contract.js";

const advisoryLockSql = "hashtext('auth.schema_migrations')";

/** A migration runner failure safe for CLI output and without database secrets. */
export class MigrationError extends Error {
  /** Stable error code for callers that need to classify migration failures. */
  readonly code = "migration_error";

  constructor(message: string, options?: { readonly cause?: unknown }) {
    super(message, options);
    this.name = "MigrationError";
  }
}

/** Explicitly supported migration direction; rollback and baseline are intentionally absent. */
export interface MigrationOptions {
  readonly direction: "up";
}

/** Result of one explicit ordered migration run. */
export interface MigrationRunResult {
  readonly applied: readonly string[];
}

export type { MigrationState, MigrationStatus } from "./internal/migration-state.js";

/** Apply packaged migrations in order with one same-client advisory lock and transaction per file. */
export async function migrate(
  pool: Pool,
  options: MigrationOptions,
): Promise<MigrationRunResult> {
  if (options.direction !== "up") {
    throw new MigrationError("Only migration direction 'up' is supported");
  }

  const client = await pool.connect();
  let lockAcquired = false;
  const applied: string[] = [];

  try {
    await client.query(`SELECT pg_advisory_lock(${advisoryLockSql})`);
    lockAcquired = true;

    const existingRows = await readAppliedMigrationRows(client);
    try {
      validateAppliedHistory(existingRows);
    } catch (error) {
      const message = error instanceof Error ? error.message : "Invalid migration history";
      throw new MigrationError(message, { cause: error });
    }
    const appliedVersions = new Set(existingRows.map((row) => row.version));

    for (const migration of MIGRATIONS) {
      if (appliedVersions.has(migration.version)) continue;

      await client.query("BEGIN");
      try {
        await client.query(migration.sql);
        await client.query(
          `INSERT INTO auth.schema_migrations
            (version, migration_order, checksum, package_version)
           VALUES ($1, $2, $3, $4)`,
          [migration.version, migration.migrationOrder, migration.checksum, migration.introducedIn],
        );
        await client.query("COMMIT");
      } catch (error) {
        await client.query("ROLLBACK").catch(() => undefined);
        throw new MigrationError(`Migration ${migration.version} failed`, { cause: error });
      }
      appliedVersions.add(migration.version);
      applied.push(migration.version);
    }

    return { applied };
  } finally {
    if (lockAcquired) {
      await client.query(`SELECT pg_advisory_unlock(${advisoryLockSql})`).catch(() => undefined);
    }
    client.release();
  }
}

/** Read migration state without creating a schema, table, lock, or row. */
export async function migrationStatus(pool: Pool): Promise<readonly MigrationStatus[]> {
  return readMigrationStatuses(pool);
}

export { verifySchema } from "./verify.js";
export type { SchemaVerification } from "./verify.js";
export { REQUIRED_TABLES };
