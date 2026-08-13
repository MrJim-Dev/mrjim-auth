import { spawn } from "node:child_process";
import { access, lstat, mkdir, mkdtemp, readdir, rm, stat, symlink, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { MIGRATIONS } from "../../src/postgres/manifest.js";

const packageRoot = resolve(fileURLToPath(new URL("../..", import.meta.url)));
const workspaceRoot = resolve(packageRoot, "../..");
const distRoot = resolve(packageRoot, "dist");

type CommandResult = {
  readonly code: number | null;
  readonly stdout: string;
  readonly stderr: string;
};

function runCommand(command: string, args: readonly string[]): Promise<CommandResult> {
  return new Promise((resolveResult, reject) => {
    const child = spawn(command, args, {
      cwd: workspaceRoot,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk: Buffer) => { stdout += chunk.toString(); });
    child.stderr.on("data", (chunk: Buffer) => { stderr += chunk.toString(); });
    child.once("error", reject);
    child.once("close", (code) => { resolveResult({ code, stdout, stderr }); });
  });
}

async function exists(path: string): Promise<boolean> {
  return access(path).then(() => true).catch(() => false);
}

async function removeGeneratedPath(path: string): Promise<void> {
  const info = await lstat(path).catch((error) => {
    if (error?.code === "ENOENT") return null;
    throw error;
  });
  if (!info) return;
  if (info.isSymbolicLink()) {
    await unlink(path);
    return;
  }
  await rm(path, { recursive: true, force: true });
}

async function packPackage(): Promise<readonly string[]> {
  const destination = await mkdtemp(join(tmpdir(), "mrjim-auth-package-build-"));
  try {
    const result = await runCommand("pnpm", ["--filter", "mrjim-auth", "pack", "--pack-destination", destination]);
    expect(result.code, result.stderr).toBe(0);
    const tarballName = (await readdir(destination)).find((entry) => entry.endsWith(".tgz"));
    if (!tarballName) throw new Error("pnpm pack did not create a tarball");
    const archive = join(destination, tarballName);
    const listing = await runCommand("tar", ["-tzf", archive]);
    expect(listing.code, listing.stderr).toBe(0);
    return listing.stdout.trim().split("\n").filter(Boolean);
  } finally {
    await rm(destination, { recursive: true, force: true });
  }
}

describe.sequential("package build and pack lifecycle", () => {
  it("removes stale package dist files before packaging", async () => {
    await mkdir(distRoot, { recursive: true });
    const sentinel = join(distRoot, "stale-package-dist-sentinel.txt");
    await writeFile(sentinel, "stale output must not ship\n");

    const packedPaths = await packPackage();

    expect(await exists(sentinel)).toBe(false);
    expect(packedPaths.some((path) => path.endsWith("stale-package-dist-sentinel.txt"))).toBe(false);
  });

  it("builds exports and migrations through package-level pack from absent dist", async () => {
    await rm(distRoot, { recursive: true, force: true });

    const packedPaths = await packPackage();
    const requiredPaths = [
      "dist/index.js",
      "dist/index.d.ts",
      "dist/server/index.js",
      "dist/storage/index.js",
      ...MIGRATIONS.map((migration) => `dist/postgres/migrations/${migration.fileName}`),
    ];

    for (const requiredPath of requiredPaths) {
      expect(packedPaths.some((path) => path.endsWith(requiredPath)), requiredPath).toBe(true);
    }
    expect(await exists(join(distRoot, "index.js"))).toBe(true);
    expect(await exists(join(distRoot, "postgres/migrations/0001_core.sql"))).toBe(true);
    expect((await stat(join(distRoot, "cli/index.js"))).mode & 0o111).toBeGreaterThan(0);
  });

  it("fails closed on a symlinked package dist without touching its external target", async () => {
    await removeGeneratedPath(distRoot);
    const externalRoot = await mkdtemp(join(tmpdir(), "mrjim-auth-external-dist-"));
    const externalSentinel = join(externalRoot, "must-survive.txt");
    await writeFile(externalSentinel, "external output must remain untouched\n");
    await symlink(externalRoot, distRoot, "dir");

    try {
      const result = await runCommand("pnpm", ["build"]);

      expect(result.code).not.toBe(0);
      expect(`${result.stdout}\n${result.stderr}`).toContain("symlink");
      expect(await exists(externalSentinel)).toBe(true);
      expect(await exists(distRoot)).toBe(false);
    } finally {
      await removeGeneratedPath(distRoot);
      await rm(externalRoot, { recursive: true, force: true });
    }
  });
});
