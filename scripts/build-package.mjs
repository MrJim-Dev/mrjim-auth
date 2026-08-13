import { spawnSync } from "node:child_process";
import { chmod, cp, lstat, mkdir, rename, rm, unlink } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";
import { randomUUID } from "node:crypto";
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

function uniqueSibling(prefix) {
  const sibling = resolve(packageRoot, `${prefix}${randomUUID()}`);
  const relativeSibling = relative(packageRoot, sibling);
  if (
    sibling === distRoot ||
    relativeSibling.includes(sep) ||
    isAbsolute(relativeSibling) ||
    relativeSibling.startsWith(`..${sep}`)
  ) {
    throw new Error(`Refusing to use unexpected package build path: ${sibling}`);
  }
  return sibling;
}

const quarantineRoot = uniqueSibling(".dist-quarantine-");
const buildRoot = uniqueSibling(".dist-build-");

async function readPath(path) {
  return lstat(path).catch((error) => {
    if (error?.code === "ENOENT") return null;
    throw error;
  });
}

function sameIdentity(first, second) {
  return first !== null && second !== null && first.dev === second.dev && first.ino === second.ino;
}

async function unlinkUnexpectedEntry(path) {
  const info = await readPath(path);
  if (!info) return;
  if (info.isSymbolicLink() || !info.isDirectory()) await unlink(path);
}

async function removeOwnedDirectory(path, expectedIdentity, label) {
  const info = await readPath(path);
  if (!info) return;
  if (info.isSymbolicLink()) {
    await unlink(path);
    throw new Error(`Refusing to recursively clean symlinked ${label}: ${path}`);
  }
  if (!info.isDirectory() || !sameIdentity(expectedIdentity, info)) {
    throw new Error(`Refusing to recursively clean changed ${label}: ${path}`);
  }
  await rm(path, { recursive: true, force: true });
}

async function quarantineExistingDist() {
  const beforeRename = await readPath(distRoot);
  try {
    await rename(distRoot, quarantineRoot);
  } catch (error) {
    if (error?.code === "ENOENT" && beforeRename === null) return null;
    throw error;
  }

  const quarantined = await readPath(quarantineRoot);
  if (!sameIdentity(beforeRename, quarantined)) {
    await unlinkUnexpectedEntry(quarantineRoot);
    throw new Error(`Package dist changed during atomic quarantine: ${distRoot}`);
  }
  if (quarantined.isSymbolicLink()) {
    await unlink(quarantineRoot);
    throw new Error(`Refusing to build from symlinked package output path: ${distRoot}`);
  }
  if (!quarantined.isDirectory()) {
    await unlink(quarantineRoot);
    throw new Error(`Refusing to build from non-directory package output path: ${distRoot}`);
  }
  return { dev: quarantined.dev, ino: quarantined.ino };
}

const pnpmCommand = process.platform === "win32" ? "pnpm.cmd" : "pnpm";
function runTypeScript(configPath) {
  const result = spawnSync(pnpmCommand, ["exec", "tsc", "-p", configPath, "--outDir", buildRoot], {
    cwd: workspaceRoot,
    stdio: "inherit",
  });
  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status ?? 1);
}

let quarantineIdentity = null;
let buildIdentity = null;
let buildPublished = false;
try {
  quarantineIdentity = await quarantineExistingDist();
  await mkdir(buildRoot);
  const freshBuild = await readPath(buildRoot);
  if (!freshBuild?.isDirectory() || freshBuild.isSymbolicLink()) {
    throw new Error(`Refusing to use unexpected package build path: ${buildRoot}`);
  }
  buildIdentity = { dev: freshBuild.dev, ino: freshBuild.ino };

  runTypeScript("packages/mrjim-auth/tsconfig.browser.json");
  runTypeScript("packages/mrjim-auth/tsconfig.node.json");
  if (!sameIdentity(buildIdentity, await readPath(buildRoot))) {
    throw new Error(`Package build output changed during compilation: ${buildRoot}`);
  }

  const migrationSource = resolve(packageRoot, "src/postgres/migrations");
  const migrationDestination = resolve(buildRoot, "postgres/migrations");
  await mkdir(migrationDestination, { recursive: true });
  await cp(migrationSource, migrationDestination, { recursive: true });
  await chmod(resolve(buildRoot, "cli/index.js"), 0o755);
  if (!sameIdentity(buildIdentity, await readPath(buildRoot))) {
    throw new Error(`Package build output changed before publication: ${buildRoot}`);
  }

  const reappearedDist = await readPath(distRoot);
  if (reappearedDist?.isSymbolicLink()) {
    await unlink(distRoot);
    throw new Error(`Package output path reappeared as a symlink: ${distRoot}`);
  }
  if (reappearedDist) {
    throw new Error(`Package output path reappeared during build: ${distRoot}`);
  }
  await rename(buildRoot, distRoot);
  buildPublished = true;
  buildIdentity = null;
  const publishedDist = await readPath(distRoot);
  if (!publishedDist?.isDirectory() || publishedDist.isSymbolicLink()) {
    await unlinkUnexpectedEntry(distRoot);
    throw new Error(`Package output was not published as a directory: ${distRoot}`);
  }

  if (quarantineIdentity) {
    await removeOwnedDirectory(quarantineRoot, quarantineIdentity, "package quarantine");
    quarantineIdentity = null;
  }
} finally {
  if (!buildPublished && buildIdentity) {
    await removeOwnedDirectory(buildRoot, buildIdentity, "package build output");
  }
  if (quarantineIdentity) {
    await removeOwnedDirectory(quarantineRoot, quarantineIdentity, "package quarantine");
  }
}
