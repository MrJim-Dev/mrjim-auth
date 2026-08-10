import { describe, expect, it } from "vitest";
import { MIGRATIONS } from "../../src/postgres/manifest.js";
import { validateAppliedHistory } from "../../src/postgres/internal/migration-state.js";
import type { AppliedMigrationCatalogRow } from "../../src/postgres/internal/catalog.js";

describe("internal migration provenance state", () => {
  it("accepts historical rows introduced by 0.1.0 when current package is 0.2.0", () => {
    const manifest = MIGRATIONS.map((migration) => ({ ...migration, introducedIn: "0.1.0" }));
    const rows: AppliedMigrationCatalogRow[] = manifest.map((migration) => ({
      version: migration.version,
      migration_order: migration.migrationOrder,
      checksum: migration.checksum,
      applied_at: new Date("2026-08-10T00:00:00Z"),
      package_version: "0.1.0",
    }));

    expect(() => validateAppliedHistory(rows, manifest, "0.2.0")).not.toThrow();

    const tamperedRows = rows.map((row, index) => index === 1
      ? { ...row, package_version: "0.2.0" }
      : row);
    expect(() => validateAppliedHistory(tamperedRows, manifest, "0.2.0")).toThrow(/provenance|package version/i);
  });
});
