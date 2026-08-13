import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const packageRoot = resolve(import.meta.dirname, "../..");
const workspaceRoot = resolve(packageRoot, "../..");

describe("release package lifecycle ordering", () => {
  it("keeps mutable package lifecycle tests out of bulk and runs them serially", async () => {
    const rootManifest = JSON.parse(await readFile(resolve(workspaceRoot, "package.json"), "utf8")) as {
      readonly scripts: Record<string, string>;
    };
    const migrationsSource = await readFile(resolve(packageRoot, "test/integration/migrations.spec.ts"), "utf8");
    const releaseCheckSource = await readFile(resolve(workspaceRoot, "scripts/release-check.mjs"), "utf8");

    expect(rootManifest.scripts.test).toContain("pnpm test:bulk && pnpm test:package-lifecycle && pnpm playwright test");
    expect(rootManifest.scripts["test:bulk"]).toContain("package-build.spec.ts");
    expect(rootManifest.scripts["test:bulk"]).toContain("--exclude");
    expect(rootManifest.scripts["test:bulk"]).toContain("MRJIM_AUTH_SERIAL_PACK_TESTS=0");
    expect(rootManifest.scripts["test:package-lifecycle"]).toContain("package-build.spec.ts");
    expect(rootManifest.scripts["test:package-lifecycle"]).toContain("MRJIM_AUTH_SERIAL_PACK_TESTS=1");
    expect(migrationsSource).toContain("skipIf(!runSerialPackageLifecycleTests)");

    const bulkIndex = releaseCheckSource.indexOf('run("pnpm", ["test:bulk"]);');
    const lifecycleIndex = releaseCheckSource.indexOf('run("pnpm", ["test:package-lifecycle"]);');
    const browserIndex = releaseCheckSource.indexOf('run("pnpm", ["playwright", "test"]);');
    expect(bulkIndex).toBeGreaterThanOrEqual(0);
    expect(lifecycleIndex).toBeGreaterThan(bulkIndex);
    expect(browserIndex).toBeGreaterThan(lifecycleIndex);
  });
});
