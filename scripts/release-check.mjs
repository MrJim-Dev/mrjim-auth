import { spawnSync } from "node:child_process";

const root = new URL("../", import.meta.url);

function run(command, args, extra = {}) {
  console.log(`\n> ${command} ${args.join(" ")}`);
  const result = spawnSync(command, args, {
    cwd: root,
    env: { ...process.env, ...extra },
    encoding: "utf8",
    stdio: "inherit",
  });
  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status ?? 1);
}

function capture(command, args) {
  console.log(`\n> ${command} ${args.join(" ")}`);
  const result = spawnSync(command, args, {
    cwd: root,
    env: process.env,
    encoding: "utf8",
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    process.stderr.write(result.stderr);
    process.exit(result.status ?? 1);
  }
  return result.stdout;
}

const initialStatus = capture("git", ["status", "--porcelain", "--untracked-files=all"]);
if (initialStatus.trim() !== "") throw new Error("release:check requires a clean checkout");

run("pnpm", ["install", "--frozen-lockfile"]);
run("pnpm", ["build"]);
run("pnpm", ["lint"]);
run("pnpm", ["typecheck"]);
run("pnpm", ["docs:check"]);
run("pnpm", [
  "vitest", "run",
  "packages/mrjim-auth/test/security",
  "packages/mrjim-auth/test/contract/supabase-surface.spec.ts",
  "packages/mrjim-auth/test/contract/browser-bundle.spec.ts",
  "packages/mrjim-auth/test/integration/version-upgrade.spec.ts",
]);
run("pnpm", ["test:bulk"]);
run("pnpm", ["test:package-lifecycle"]);
run("pnpm", ["playwright", "test"]);
run("pnpm", ["--filter", "express-api", "typecheck"]);
run("pnpm", ["--filter", "express-api", "test"]);
run("pnpm", ["--filter", "nextjs-app-router", "typecheck"]);
run("pnpm", ["--filter", "nextjs-app-router", "test"]);
run("pnpm", ["--filter", "nextjs-app-router", "build"]);

const packed = JSON.parse(capture("pnpm", ["--config.ignore-scripts=true", "--filter", "mrjim-auth", "pack", "--dry-run", "--json"]));
const files = new Set(packed.files.map((entry) => entry.path));
const required = [
  "README.md",
  "LICENSE",
  "package.json",
  "dist/index.js",
  "dist/index.d.ts",
  "dist/index.js.map",
  "dist/postgres/migrations/0001_core.sql",
  "dist/postgres/migrations/0002_authorization.sql",
  "dist/postgres/migrations/0003_oauth_operations.sql",
  "dist/postgres/migrations/0004_repository_hardening.sql",
  "dist/postgres/migrations/0005_oauth_callback.sql",
  "dist/postgres/migrations/0006_admin_operations.sql",
];
for (const path of required) {
  if (!files.has(path)) throw new Error(`packed artifact is missing ${path}`);
}
for (const path of files) {
  if (
    path.includes("/test/") || path.startsWith("test/") ||
    path.endsWith(".env") || path.includes(".env.") ||
    path.endsWith(".sqlite") || path.endsWith(".db") ||
    path.includes("node_modules/")
  ) throw new Error(`packed artifact contains forbidden path ${path}`);
}

run("git", ["diff", "--check"]);
const finalStatus = capture("git", ["status", "--porcelain", "--untracked-files=all"]);
if (finalStatus.trim() !== "") throw new Error("release:check generated or found uncommitted files");
console.log(`\nrelease:check passed (${files.size} packed files inspected)`);
