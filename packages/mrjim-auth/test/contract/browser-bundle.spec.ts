import { build, type BuildResult, type Metafile } from "esbuild";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const packageRoot = resolve(import.meta.dirname, "../..");

const browserEntries = [
  "src/index.ts",
  "src/adapters/nextjs-browser.ts",
  "src/storage/index.ts",
] as const;

function normalizePath(value: string): string {
  return value.replaceAll("\\", "/").toLowerCase();
}

function sourceGraphPath(value: string): string {
  return normalizePath(value).replace(/^\.\//u, "");
}

function isServerOrPrivateImplementation(value: string): boolean {
  const path = sourceGraphPath(value);
  return /(?:^|\/)src\/(?:server|postgres|cli)(?:\/|$)/u.test(path)
    || /(?:^|\/)src\/(?:admin|private-key)(?:\/|$)/u.test(path)
    || /(?:^|\/)migrations?(?:\/|$)/u.test(path)
    || path.endsWith(".sql");
}

function isForbiddenDependency(value: string): boolean {
  const path = sourceGraphPath(value);
  return path === "node:crypto"
    || /(?:^|\/)node_modules\/(?:@node-rs\/)?(?:argon2|pg|pg-native)(?:\/|$)/u.test(path)
    || /(?:^|\/)node_modules\/(?:postgres|postgresjs)(?:\/|$)/u.test(path);
}

const forbiddenOutputImportPattern = /(?:from\s+|import\s*(?:\(|)|require\s*\()\s*["'](?:node:crypto|pg|argon2)(?:\/[^"']*)?["']/u;

function buildBrowserEntry(entryPoint: string): Promise<BuildResult> {
  return build({
    absWorkingDir: packageRoot,
    bundle: true,
    entryPoints: [resolve(packageRoot, entryPoint)],
    format: "esm",
    logLevel: "silent",
    metafile: true,
    platform: "browser",
    write: false,
  });
}

function outputText(result: BuildResult): string {
  const files = result.outputFiles ?? [];
  return files.map((file) => file.text).join("\n");
}

function inputPaths(metafile: Metafile): readonly string[] {
  return Object.keys(metafile.inputs).map(sourceGraphPath);
}

function outputImports(metafile: Metafile): readonly string[] {
  return Object.values(metafile.outputs).flatMap((output) => output.imports.map((item) => item.path));
}

function includesPath(inputs: readonly string[], suffix: string): boolean {
  return inputs.some((path) => path === suffix || path.endsWith(`/${suffix}`));
}

function assertBrowserGraph(entryPoint: string, result: BuildResult): void {
  const metafile = result.metafile;
  expect(metafile, `${entryPoint} must expose an esbuild metafile`).toBeDefined();
  const inputs = inputPaths(metafile!);
  const imports = outputImports(metafile!);
  const output = outputText(result);

  expect(inputs.length, `${entryPoint} must have a non-empty actual module graph`).toBeGreaterThan(0);
  expect(result.outputFiles?.length, `${entryPoint} must produce a browser output`).toBe(1);
  expect(output.length, `${entryPoint} browser output must not be empty`).toBeGreaterThan(512);
  expect(inputs.filter(isServerOrPrivateImplementation), `${entryPoint} imported a server/private implementation`).toEqual([]);
  expect(inputs.filter(isForbiddenDependency), `${entryPoint} imported a server-only dependency`).toEqual([]);
  expect(imports.filter((item) => forbiddenOutputImportPattern.test(`import ${JSON.stringify(item)}`)), `${entryPoint} left a forbidden external import`).toEqual([]);
  expect(output, `${entryPoint} output must not contain a forbidden module reference`).not.toMatch(forbiddenOutputImportPattern);
  expect(output, `${entryPoint} output must not contain a migration asset`).not.toMatch(/(?:^|[\\/])migrations?(?:[\\/]|\.|$)/iu);
}

describe("browser bundle boundaries", () => {
  it("bundles the actual public root and browser adapter as browser modules", async () => {
    for (const entryPoint of browserEntries) {
      const result = await buildBrowserEntry(entryPoint);
      assertBrowserGraph(entryPoint, result);
    }
  });

  it("keeps the inspected graphs inside client, adapter, and shared source", async () => {
    for (const entryPoint of browserEntries) {
      const result = await buildBrowserEntry(entryPoint);
      const inputs = inputPaths(result.metafile!);
      expect(includesPath(inputs, "src/shared/safe-intrinsics.ts")).toBe(true);
      if (entryPoint.includes("storage/index")) {
        expect(includesPath(inputs, "src/storage/client.ts")).toBe(true);
      } else if (entryPoint.includes("nextjs-browser")) {
        expect(includesPath(inputs, "src/client/auth-client.ts")).toBe(true);
        expect(includesPath(inputs, "src/adapters/nextjs-browser.ts")).toBe(true);
      } else {
        expect(includesPath(inputs, "src/client/auth-client.ts")).toBe(true);
        expect(includesPath(inputs, "src/index.ts")).toBe(true);
      }
    }
  });
});
