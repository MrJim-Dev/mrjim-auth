import { access, readFile } from "node:fs/promises";
import { dirname, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

interface ExportTarget {
  readonly types: string;
  readonly import: string;
}

interface PackageManifest {
  readonly name: string;
  readonly exports: Record<string, ExportTarget>;
}

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const manifest = JSON.parse(
  await readFile(resolve(packageRoot, "package.json"), "utf8"),
) as PackageManifest;

const requiredExportKeys = [
  ".",
  "./server",
  "./postgres",
  "./express",
  "./nextjs",
  "./nextjs/server",
  "./testing",
] as const;

const browserEntryFiles = ["dist/index.js", "dist/adapters/nextjs-browser.js"] as const;
const nodeOnlySpecifiers = new Set([
  "assert",
  "buffer",
  "child_process",
  "cluster",
  "crypto",
  "dgram",
  "dns",
  "events",
  "fs",
  "http",
  "https",
  "module",
  "net",
  "os",
  "path",
  "perf_hooks",
  "process",
  "readline",
  "stream",
  "string_decoder",
  "timers",
  "tls",
  "tty",
  "url",
  "util",
  "v8",
  "vm",
  "worker_threads",
  "zlib",
]);

function packageSpecifier(exportKey: string): string {
  return exportKey === "." ? manifest.name : `${manifest.name}${exportKey.slice(1)}`;
}

function packageTarget(exportKey: string): ExportTarget {
  const target = manifest.exports[exportKey];
  if (!target) {
    throw new Error(`Missing package export target for ${exportKey}`);
  }
  return target;
}

function importSpecifiers(source: string): string[] {
  const matches = source.matchAll(
    /(?:\bimport\s+(?:(?:[^"']*?)\s+from\s+)?|\bexport\s+(?:[^"']*?)\s+from\s+)["']([^"']+)["']/g,
  );
  return [...matches].map((match) => match[1]).filter((specifier): specifier is string => Boolean(specifier));
}

async function browserGraphViolations(entryFile: string): Promise<string[]> {
  const violations: string[] = [];
  const pending = [resolve(packageRoot, entryFile)];
  const visited = new Set<string>();

  while (pending.length > 0) {
    const current = pending.pop();
    if (!current || visited.has(current)) {
      continue;
    }
    visited.add(current);

    const source = await readFile(current, "utf8");
    for (const specifier of importSpecifiers(source)) {
      const bareSpecifier = specifier.startsWith("node:") ? specifier.slice(5) : specifier;
      if (specifier.startsWith("node:") || nodeOnlySpecifiers.has(bareSpecifier)) {
        violations.push(`${relative(packageRoot, current)} imports ${specifier}`);
        continue;
      }

      if (!specifier.startsWith(".")) {
        continue;
      }

      const resolved = resolve(dirname(current), specifier);
      if (!resolved.startsWith(`${packageRoot}/`)) {
        violations.push(`${relative(packageRoot, current)} escapes the package graph via ${specifier}`);
        continue;
      }
      pending.push(resolved);
    }
  }

  return violations;
}

describe("package export boundaries", () => {
  it("loads every declared export through the built package self-reference", async () => {
    expect(manifest.name).toBe("mrjim-auth");
    expect(Object.keys(manifest.exports).sort()).toEqual([...requiredExportKeys].sort());

    const importTargets = requiredExportKeys.map((exportKey) => packageTarget(exportKey).import);
    expect(new Set(importTargets).size).toBe(requiredExportKeys.length);

    for (const exportKey of requiredExportKeys) {
      const target = packageTarget(exportKey);
      expect(target.import).toMatch(/^\.\/dist\/.+\.js$/);
      expect(target.types).toMatch(/^\.\/dist\/.+\.d\.ts$/);
      await access(resolve(packageRoot, target.import));
      await access(resolve(packageRoot, target.types));
      await import(packageSpecifier(exportKey));
    }
  });

  it("exposes only the documented temporary root scaffold", async () => {
    const root = await import(manifest.name);
    expect(Object.keys(root)).toEqual(["createClient"]);

    const client = root.createClient(
      "https://project.example.com/auth/v1",
      "publishable-key",
    );
    expect(Object.isFrozen(client)).toBe(true);
    expect(Object.keys(client)).toEqual([]);
  });

  it("does not expose unfinished behavior from later-task subpaths", async () => {
    for (const exportKey of requiredExportKeys.slice(1)) {
      expect(Object.keys(await import(packageSpecifier(exportKey)))).toEqual([]);
    }
  });

  it("keeps browser entry graphs free of Node-only imports", async () => {
    for (const entryFile of browserEntryFiles) {
      expect(await browserGraphViolations(entryFile)).toEqual([]);
    }
  });
});
