import type { Pool } from "pg";
import {
  migrate,
  migrationStatus,
  verifySchema,
  type MigrationState,
} from "../../postgres/migrate.js";

export type MigrateCommand = "status" | "up" | "verify";
export type OutputLine = (line: string) => void;

function formatState(state: MigrationState): string {
  return state === "checksum_mismatch" ? "checksum-mismatch" : state;
}

/** Execute a read-only migration status, explicit up migration, or read-only verification command. */
export async function runMigrateCommand(
  pool: Pool,
  command: MigrateCommand,
  write: OutputLine = (line) => console.log(line),
): Promise<void> {
  if (command === "status") {
    const statuses = await migrationStatus(pool);
    write("version\tstate\tchecksum\texpected_checksum\tpackage_version");
    for (const status of statuses) {
      write(
        [
          status.version,
          formatState(status.state),
          status.checksum,
          status.expectedChecksum ?? "-",
          status.packageVersion ?? "-",
        ].join("\t"),
      );
    }
    return;
  }

  if (command === "up") {
    const result = await migrate(pool, { direction: "up" });
    write(result.applied.length ? `applied: ${result.applied.join(", ")}` : "applied: none");
    return;
  }

  const verification = await verifySchema(pool);
  if (!verification.ok) {
    throw new Error(`schema verification failed: ${verification.errors.join("; ")}`);
  }
  write("schema: verified");
}
