import {
  MIGRATIONS,
  PACKAGE_VERSION,
  type MigrationDefinition,
} from "../manifest.js";
import {
  readAppliedMigrationRows,
  type AppliedMigrationCatalogRow,
  type QueryExecutor,
} from "./catalog.js";

/** Public migration state exposed by read-only status and verification. */
export type MigrationState =
  | "applied"
  | "pending"
  | "checksum_mismatch"
  | "package_version_mismatch"
  | "history_invalid";

/** Read-only status for one packaged migration or an unexpected database row. */
export interface MigrationStatus {
  /** Packaged version, or the unexpected recorded version. */
  readonly version: string;
  /** Recorded checksum, or the packaged checksum when pending. */
  readonly checksum: string;
  /** Packaged checksum, or null for an unexpected row. */
  readonly expectedChecksum: string | null;
  /** Recorded ordinal, or null when pending/unavailable. */
  readonly migrationOrder: number | null;
  /** Packaged ordinal, or null for an unexpected row. */
  readonly expectedMigrationOrder: number | null;
  /** Database application timestamp, or null when pending. */
  readonly appliedAt: Date | null;
  /** Recorded package version, or null when pending. */
  readonly packageVersion: string | null;
  /** Whether the row is clean, pending, or invalid. */
  readonly state: MigrationState;
}

/** Fail closed before any migration writes when history is not an exact manifest prefix. */
export function validateAppliedHistory(
  rows: readonly AppliedMigrationCatalogRow[],
  manifest: readonly MigrationDefinition[] = MIGRATIONS,
  currentPackageVersion: string = PACKAGE_VERSION,
): void {
  // The current package may be newer than the rows it is verifying. The third
  // parameter is retained for internal callers that carry current-version
  // context, but provenance is always checked against each migration entry.
  void currentPackageVersion;
  const known = new Map(manifest.map((migration) => [migration.version, migration]));
  const seenVersions = new Set<string>();

  for (const [index, row] of rows.entries()) {
    const expected = known.get(row.version);
    if (!expected) {
      throw new Error(`Unknown applied migration version: ${row.version}`);
    }
    if (seenVersions.has(row.version)) {
      throw new Error(`Duplicate applied migration version: ${row.version}`);
    }
    seenVersions.add(row.version);
    const expectedOrder = index + 1;
    if (row.migration_order !== expectedOrder || row.migration_order !== expected.migrationOrder) {
      throw new Error(`Non-contiguous migration history at ${row.version}: expected order ${expectedOrder}`);
    }
    if (row.checksum !== expected.checksum) {
      throw new Error(`Migration checksum mismatch for ${row.version}`);
    }
    if (row.package_version !== expected.introducedIn) {
      throw new Error(`Migration provenance mismatch for ${row.version}`);
    }
  }
}

/** Read applied history and convert it into a safe status report without writing. */
export async function readMigrationStatuses(
  executor: QueryExecutor,
  manifest: readonly MigrationDefinition[] = MIGRATIONS,
  currentPackageVersion: string = PACKAGE_VERSION,
): Promise<readonly MigrationStatus[]> {
  const rows = await readAppliedMigrationRows(executor);
  let historyError = false;
  try {
    validateAppliedHistory(rows, manifest, currentPackageVersion);
  } catch {
    historyError = true;
  }

  const byVersion = new Map(rows.map((row) => [row.version, row]));
  const knownVersions = new Set(manifest.map((migration) => migration.version));
  const statuses: MigrationStatus[] = manifest.map((migration) => {
    const row = byVersion.get(migration.version);
    if (!row) {
      return {
        version: migration.version,
        checksum: migration.checksum,
        expectedChecksum: migration.checksum,
        migrationOrder: null,
        expectedMigrationOrder: migration.migrationOrder,
        appliedAt: null,
        packageVersion: null,
        state: "pending",
      };
    }
    const state: MigrationState = historyError
      ? row.checksum !== migration.checksum
        ? "checksum_mismatch"
        : row.package_version !== migration.introducedIn
          ? "package_version_mismatch"
          : "history_invalid"
      : "applied";
    return {
      version: migration.version,
      checksum: row.checksum,
      expectedChecksum: migration.checksum,
      migrationOrder: row.migration_order,
      expectedMigrationOrder: migration.migrationOrder,
      appliedAt: row.applied_at,
      packageVersion: row.package_version,
      state,
    };
  });

  for (const row of rows) {
    if (knownVersions.has(row.version)) continue;
    statuses.push({
      version: row.version,
      checksum: row.checksum,
      expectedChecksum: null,
      migrationOrder: row.migration_order,
      expectedMigrationOrder: null,
      appliedAt: row.applied_at,
      packageVersion: row.package_version,
      state: "history_invalid",
    });
  }
  return statuses;
}
