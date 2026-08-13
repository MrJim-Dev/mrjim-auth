import { spawnSync } from "node:child_process";
import { chmod, cp, lstat, mkdir, rm } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const workspaceRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));
const packageRoot = resolve(workspaceRoot, "packages/mrjim-auth");
const distRoot = resolve(packageRoot, "dist");
const expectedDistRoot = resolve(workspaceRoot, "packages/mrjim-auth/dist");
const relativeDistRoot = relative(workspaceRoot, distRoot);

if (
  distRoot !== expectedDistRoot ||
  relativeDistRoot !== ["packages", "mrjim-auth", "dist"].join(sep) ||
  isAbsolute(relativeDistRoot) ||
  relativeDistRoot.startsWith(`..${sep}`)
) {
  throw new Error(`Refusing to clean unexpected package output path: ${distRoot}`);
}

const existingDist = await lstat(distRoot).catch((error) => {
  if (error?.code === "ENOENT") return null;
  throw error;
});
if (existingDist?.isSymbolicLink()) {
  throw new Error(`Refusing to clean symlinked package output path: ${distRoot}`);
}
if (existingDist && !existingDist.isDirectory()) {
  throw new Error(`Refusing to clean non-directory package output path: ${distRoot}`);
}
await rm(distRoot, { recursive: true, force: true });

const pnpmCommand = process.platform === "win32" ? "pnpm.cmd" : "pnpm";
function runTypeScript(configPath) {
  const result = spawnSync(pnpmCommand, ["exec", "tsc", "-p", configPath], {
    cwd: workspaceRoot,
    stdio: "inherit",
  });
  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status ?? 1);
}

runTypeScript("packages/mrjim-auth/tsconfig.browser.json");
runTypeScript("packages/mrjim-auth/tsconfig.node.json");

const migrationSource = resolve(packageRoot, "src/postgres/migrations");
const migrationDestination = resolve(distRoot, "postgres/migrations");
await mkdir(migrationDestination, { recursive: true });
await cp(migrationSource, migrationDestination, { recursive: true });
await chmod(resolve(distRoot, "cli/index.js"), 0o755);
