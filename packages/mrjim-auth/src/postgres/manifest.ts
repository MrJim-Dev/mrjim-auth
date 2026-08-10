import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

/** One ordered SQL migration and its content-derived checksum. */
export interface MigrationDefinition {
  /** Positive contiguous ordinal in the packaged migration history. */
  readonly migrationOrder: number;
  readonly version: string;
  readonly fileName: string;
  readonly sql: string;
  readonly checksum: string;
}

const migrationFileNames = [
  ["0001_core", "0001_core.sql"],
  ["0002_authorization", "0002_authorization.sql"],
  ["0003_oauth_operations", "0003_oauth_operations.sql"],
] as const;

function readPackageVersion(): string {
  const packageJson = JSON.parse(
    readFileSync(new URL("../../package.json", import.meta.url), "utf8"),
  ) as { readonly version?: unknown };
  if (typeof packageJson.version !== "string" || packageJson.version.trim() === "") {
    throw new Error("mrjim-auth package version is missing");
  }
  return packageJson.version;
}

function readMigration(migrationOrder: number, version: string, fileName: string): MigrationDefinition {
  const sql = readFileSync(new URL(`./migrations/${fileName}`, import.meta.url), "utf8");
  const checksum = createHash("sha256").update(sql, "utf8").digest("hex");
  return Object.freeze({ migrationOrder, version, fileName, sql, checksum });
}

/** The deterministic, source-ordered migration manifest. */
export const MIGRATIONS: readonly MigrationDefinition[] = Object.freeze(
  migrationFileNames.map(([version, fileName], index) => readMigration(index + 1, version, fileName)),
);

/** Version recorded with every migration application. */
export const PACKAGE_VERSION = readPackageVersion();
