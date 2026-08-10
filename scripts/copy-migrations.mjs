import { chmod, cp, mkdir } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const workspaceRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));
const source = resolve(workspaceRoot, "packages/mrjim-auth/src/postgres/migrations");
const destination = resolve(workspaceRoot, "packages/mrjim-auth/dist/postgres/migrations");

await mkdir(destination, { recursive: true });
await cp(source, destination, { recursive: true });
await chmod(resolve(workspaceRoot, "packages/mrjim-auth/dist/cli/index.js"), 0o755);
