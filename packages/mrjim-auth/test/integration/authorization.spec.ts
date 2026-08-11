import { spawn } from "node:child_process";
import { mkdtemp, mkdir, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Pool } from "pg";
import {
  AuthorizationService,
  createAuthorizationRequestContext,
} from "../../src/server/authorization.js";
import { permissionsRoute } from "../../src/server/routes/permissions.js";
import { migrate } from "../../src/postgres/migrate.js";
import { createPostgresAdapter, type PostgresAdapter } from "../../src/postgres/adapter.js";
import {
  lowercaseKeySchema,
  permissionKeySchema,
  roleKeySchema,
  scopeIdentifierSchema,
  type AuthorizationScope,
} from "../../src/shared/types.js";

type Cluster = {
  readonly root: string;
  readonly dataDirectory: string;
  readonly socketDirectory: string;
};

type DisposablePostgres = {
  readonly cluster: Cluster;
  readonly pool: Pool;
};

type CommandResult = {
  readonly code: number | null;
  readonly stdout: string;
  readonly stderr: string;
};

let repository: PostgresAdapter | undefined;
let disposable: DisposablePostgres | undefined;

async function runCommandResult(command: string, args: readonly string[]): Promise<CommandResult> {
  return new Promise<CommandResult>((resolve, reject) => {
    const child = spawn(command, args, { stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk: Buffer) => { stdout += chunk.toString(); });
    child.stderr.on("data", (chunk: Buffer) => { stderr += chunk.toString(); });
    child.once("error", reject);
    child.once("close", (code) => resolve({ code, stdout, stderr }));
  });
}

async function runCommand(
  command: string,
  args: readonly string[],
  logPath?: string,
): Promise<void> {
  const result = await runCommandResult(command, args);
  if (result.code === 0) return;
  const log = logPath === undefined ? "" : await readFile(logPath, "utf8").catch(() => "");
  throw new Error(`${command} ${args.join(" ")} exited with ${result.code ?? "unknown"}: ${(result.stderr || log).trim()}`);
}

async function startDisposablePostgres(label: string): Promise<DisposablePostgres> {
  const root = await mkdtemp(join(tmpdir(), `${label}-`));
  const dataDirectory = join(root, "data");
  const socketDirectory = join(root, "socket");
  const cluster = { root, dataDirectory, socketDirectory };
  try {
    await mkdir(socketDirectory);
    await runCommand("initdb", [
      "--pgdata", dataDirectory, "--auth=trust", "--username=postgres",
      "--no-locale", "--encoding=UTF8",
    ]);
    await runCommand(
      "pg_ctl",
      ["--pgdata", dataDirectory, "--log", join(root, "postgres.log"), "--options", `-h '' -k ${socketDirectory}`, "--wait", "start"],
      join(root, "postgres.log"),
    );
    const pool = new Pool({
      connectionString: `postgresql://postgres@localhost/postgres?host=${encodeURIComponent(socketDirectory)}`,
      max: 8,
    });
    try {
      await pool.query("SELECT 1");
      return { cluster, pool };
    } catch (error) {
      await pool.end().catch(() => undefined);
      throw error;
    }
  } catch (error) {
    await runCommand("pg_ctl", ["--pgdata", dataDirectory, "--mode=immediate", "--wait", "stop"]).catch(() => undefined);
    await rm(root, { recursive: true, force: true });
    throw error;
  }
}

async function stopDisposablePostgres(value: DisposablePostgres): Promise<void> {
  try {
    await value.pool.end();
  } finally {
    await runCommand("pg_ctl", ["--pgdata", value.cluster.dataDirectory, "--mode=immediate", "--wait", "stop"]).catch(() => undefined);
    await rm(value.cluster.root, { recursive: true, force: true });
  }
}

function requireRepository(): PostgresAdapter {
  if (repository === undefined) throw new Error("PostgreSQL adapter is not initialized");
  return repository;
}

function scope(type: string, id: string): AuthorizationScope {
  return { type, id: scopeIdentifierSchema.parse(id) };
}

const NOW = new Date("2026-08-11T00:00:00.000Z");

describe("Task 8 dynamic authorization", () => {
  beforeAll(async () => {
    disposable = await startDisposablePostgres("mrjim-auth-task8");
    await migrate(disposable.pool, { direction: "up" });
    repository = createPostgresAdapter({ pool: disposable.pool });
  }, 120_000);

  afterAll(async () => {
    try {
      await repository?.close();
    } finally {
      if (disposable !== undefined) await stopDisposablePostgres(disposable);
    }
  });

  it("unions direct role permissions, multiple roles, and recursive inherited permissions without rank grants", async () => {
    const current = requireRepository();
    const user = await current.users.create({ email: `authorization-${crypto.randomUUID()}@example.com` });
    const leaf = await current.roles.create({ key: roleKeySchema.parse(`leaf_${crypto.randomUUID().slice(0, 8)}`), name: "Leaf", rank: 999 });
    const second = await current.roles.create({ key: roleKeySchema.parse(`second_${crypto.randomUUID().slice(0, 8)}`), name: "Second", rank: 0 });
    const parent = await current.roles.create({ key: roleKeySchema.parse(`parent_${crypto.randomUUID().slice(0, 8)}`), name: "Parent", rank: 1 });
    const direct = await current.permissions.create({ key: permissionKeySchema.parse("invoice.read"), resource: lowercaseKeySchema.parse("invoice"), action: lowercaseKeySchema.parse("read") });
    const inherited = await current.permissions.create({ key: permissionKeySchema.parse("invoice.export"), resource: lowercaseKeySchema.parse("invoice"), action: lowercaseKeySchema.parse("export") });
    const secondPermission = await current.permissions.create({ key: permissionKeySchema.parse("billing.read"), resource: lowercaseKeySchema.parse("billing"), action: lowercaseKeySchema.parse("read") });
    await current.authorization.setRolePermissions(leaf.id, [direct.id]);
    await current.authorization.setRolePermissions(parent.id, [inherited.id]);
    await current.authorization.setRolePermissions(second.id, [secondPermission.id]);
    await current.authorization.setRoleInheritance(leaf.id, [parent.id]);
    await current.authorization.assignRole({ user_id: user.id, role_id: leaf.id }, { now: NOW });
    await current.authorization.assignRole({ user_id: user.id, role_id: second.id }, { now: NOW });

    const service = new AuthorizationService({ repository: current, clock: () => NOW });
    expect(await service.getPermissions(user.id)).toEqual([
      "billing.read",
      "invoice.export",
      "invoice.read",
    ]);
    await expect(service.authorize({ user_id: user.id }, { all: ["invoice.read", "invoice.export"] })).resolves.toMatchObject({ user_id: user.id });
    await expect(service.authorize({ user_id: user.id }, { any: ["invoice.delete", "billing.read"] })).resolves.toMatchObject({ user_id: user.id });
    await expect(service.authorize({ user_id: user.id }, { all: ["admin.read"] })).rejects.toMatchObject({ code: "insufficient_permission", status: 403 });
  });

  it("matches global and exact scopes, rejects missing or wrong scopes, and uses operation-time expiry", async () => {
    const current = requireRepository();
    const user = await current.users.create({ email: `scope-${crypto.randomUUID()}@example.com` });
    const role = await current.roles.create({ key: roleKeySchema.parse(`scope_${crypto.randomUUID().slice(0, 8)}`), name: "Scoped", rank: 1 });
    const permission = await current.permissions.create({ key: permissionKeySchema.parse("report.read"), resource: lowercaseKeySchema.parse("report"), action: lowercaseKeySchema.parse("read") });
    await current.authorization.setRolePermissions(role.id, [permission.id]);
    const organization = scope("organization", "org_123");
    const otherOrganization = scope("organization", "org_456");
    await current.authorization.assignRole({ user_id: user.id, role_id: role.id, scope: organization, expires_at: new Date(NOW.getTime() + 1_000) }, { now: NOW });

    const service = new AuthorizationService({ repository: current, clock: () => NOW });
    expect(await service.getPermissions(user.id)).toEqual([]);
    expect(await service.getPermissions(user.id, otherOrganization)).toEqual([]);
    expect(await service.getPermissions(user.id, organization)).toEqual(["report.read"]);

    const expiredService = new AuthorizationService({ repository: current, clock: () => new Date(NOW.getTime() + 1_000) });
    expect(await expiredService.getPermissions(user.id, organization)).toEqual([]);
  });

  it("terminates on the database cycle guard and deduplicates diamond inheritance", async () => {
    const current = requireRepository();
    const user = await current.users.create({ email: `cycle-${crypto.randomUUID()}@example.com` });
    const leaf = await current.roles.create({ key: roleKeySchema.parse(`diamond_leaf_${crypto.randomUUID().slice(0, 6)}`), name: "Diamond leaf", rank: 1 });
    const left = await current.roles.create({ key: roleKeySchema.parse(`diamond_left_${crypto.randomUUID().slice(0, 6)}`), name: "Diamond left", rank: 1 });
    const right = await current.roles.create({ key: roleKeySchema.parse(`diamond_right_${crypto.randomUUID().slice(0, 6)}`), name: "Diamond right", rank: 1 });
    const root = await current.roles.create({ key: roleKeySchema.parse(`diamond_root_${crypto.randomUUID().slice(0, 6)}`), name: "Diamond root", rank: 1 });
    const permission = await current.permissions.create({ key: permissionKeySchema.parse("diamond.read"), resource: lowercaseKeySchema.parse("diamond"), action: lowercaseKeySchema.parse("read") });
    await current.authorization.setRolePermissions(left.id, [permission.id]);
    await current.authorization.setRolePermissions(right.id, [permission.id]);
    await current.authorization.setRolePermissions(root.id, [permission.id]);
    await current.authorization.setRoleInheritance(leaf.id, [left.id, right.id]);
    await current.authorization.setRoleInheritance(left.id, [root.id]);
    await current.authorization.setRoleInheritance(right.id, [root.id]);
    await current.authorization.assignRole({ user_id: user.id, role_id: leaf.id }, { now: NOW });
    const service = new AuthorizationService({ repository: current, clock: () => NOW });
    expect(await service.getPermissions(user.id)).toEqual(["diamond.read"]);

    const cycleA = await current.roles.create({ key: roleKeySchema.parse(`cycle_a_${crypto.randomUUID().slice(0, 6)}`), name: "Cycle A", rank: 1 });
    const cycleB = await current.roles.create({ key: roleKeySchema.parse(`cycle_b_${crypto.randomUUID().slice(0, 6)}`), name: "Cycle B", rank: 1 });
    await expect(current.transaction(async (transaction) => {
      await transaction.authorization.setRoleInheritance(cycleA.id, [cycleB.id]);
      await transaction.authorization.setRoleInheritance(cycleB.id, [cycleA.id]);
    })).rejects.toThrow(/cycle/i);
  });

  it("fails closed after roles or permissions are removed and never derives access from rank", async () => {
    const current = requireRepository();
    const user = await current.users.create({ email: `missing-${crypto.randomUUID()}@example.com` });
    const role = await current.roles.create({ key: roleKeySchema.parse(`missing_${crypto.randomUUID().slice(0, 8)}`), name: "High rank only", rank: 1000 });
    const permission = await current.permissions.create({ key: permissionKeySchema.parse("missing.read"), resource: lowercaseKeySchema.parse("missing"), action: lowercaseKeySchema.parse("read") });
    await current.authorization.setRolePermissions(role.id, [permission.id]);
    await current.authorization.assignRole({ user_id: user.id, role_id: role.id }, { now: NOW });
    const service = new AuthorizationService({ repository: current, clock: () => NOW });
    expect(await service.getPermissions(user.id)).toEqual(["missing.read"]);
    await current.permissions.delete(permission.id);
    expect(await service.getPermissions(user.id)).toEqual([]);
    await current.roles.delete(role.id);
    expect(await service.getPermissions(user.id)).toEqual([]);
  });

  it("uses one cache per request subject and does not reuse permissions across request objects", async () => {
    const base = requireRepository();
    const user = await base.users.create({ email: `cache-${crypto.randomUUID()}@example.com` });
    const role = await base.roles.create({ key: roleKeySchema.parse(`cache_${crypto.randomUUID().slice(0, 8)}`), name: "Cache", rank: 1 });
    const permission = await base.permissions.create({ key: permissionKeySchema.parse("cache.read"), resource: lowercaseKeySchema.parse("cache"), action: lowercaseKeySchema.parse("read") });
    await base.authorization.setRolePermissions(role.id, [permission.id]);
    await base.authorization.assignRole({ user_id: user.id, role_id: role.id }, { now: NOW });
    let reads = 0;
    const countingRepository = {
      ...base,
      authorization: {
        ...base.authorization,
        effectivePermissions: async (...args: Parameters<typeof base.authorization.effectivePermissions>) => {
          reads += 1;
          return base.authorization.effectivePermissions(...args);
        },
      },
    } as PostgresAdapter;
    const service = new AuthorizationService({ repository: countingRepository, clock: () => NOW });
    const firstRequest = { user_id: user.id, request_id: "request-one" } as const;
    const firstContext = createAuthorizationRequestContext(firstRequest);
    expect(firstContext).not.toBeNull();
    if (firstContext === null) throw new Error("first request context was not created");
    await service.authorize(firstRequest, { all: ["cache.read"] }, firstContext);
    await service.authorize(firstRequest, { all: ["cache.read"] }, firstContext);
    expect(reads).toBe(1);
    const secondRequest = { user_id: user.id, request_id: "request-two" } as const;
    const secondContext = createAuthorizationRequestContext(secondRequest);
    expect(secondContext).not.toBeNull();
    if (secondContext === null) throw new Error("second request context was not created");
    await service.authorize(secondRequest, { all: ["cache.read"] }, secondContext);
    expect(reads).toBe(2);

    const secondPermission = await base.permissions.create({ key: permissionKeySchema.parse("cache.write"), resource: lowercaseKeySchema.parse("cache"), action: lowercaseKeySchema.parse("write") });
    await base.authorization.setRolePermissions(role.id, [permission.id, secondPermission.id]);
    await expect(service.authorize(firstRequest, { all: ["cache.write"] }, firstContext)).rejects.toMatchObject({ code: "insufficient_permission" });
    const thirdRequest = { user_id: user.id, request_id: "request-three" } as const;
    const thirdContext = createAuthorizationRequestContext(thirdRequest);
    expect(thirdContext).not.toBeNull();
    if (thirdContext === null) throw new Error("third request context was not created");
    await expect(service.authorize(thirdRequest, { all: ["cache.write"] }, thirdContext)).resolves.toMatchObject({ user_id: user.id });
    expect(reads).toBe(3);
  });

  it("returns a safe permission route with validated scopes and redacted guard errors", async () => {
    const current = requireRepository();
    const user = await current.users.create({ email: `route-${crypto.randomUUID()}@example.com` });
    const role = await current.roles.create({ key: roleKeySchema.parse(`route_${crypto.randomUUID().slice(0, 8)}`), name: "Route", rank: 1 });
    const permission = await current.permissions.create({ key: permissionKeySchema.parse("route.read"), resource: lowercaseKeySchema.parse("route"), action: lowercaseKeySchema.parse("read") });
    await current.authorization.setRolePermissions(role.id, [permission.id]);
    await current.authorization.assignRole({ user_id: user.id, role_id: role.id }, { now: NOW });
    const service = new AuthorizationService({ repository: current, clock: () => NOW });
    const subject = { user_id: user.id, request_id: "req-route" } as const;

    const response = await permissionsRoute(service, new Request("https://project.example.com/user/permissions"), subject);
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ data: { permissions: ["route.read"] }, error: null });

    const scopedResponse = await permissionsRoute(service, new Request("https://project.example.com/user/permissions?scope_type=organization&scope_id=org_123"), subject);
    expect(scopedResponse.status).toBe(200);
    expect((await scopedResponse.json()).data.permissions).toEqual(["route.read"]);

    const invalidResponse = await permissionsRoute(service, new Request("https://project.example.com/user/permissions?scope_type=organization"), subject);
    expect(invalidResponse.status).toBe(400);
    expect((await invalidResponse.json()).error.code).toBe("invalid_request");

    const duplicateResponse = await permissionsRoute(service, new Request("https://project.example.com/user/permissions?scope_type=organization&scope_type=organization&scope_id=org_123"), subject);
    expect(duplicateResponse.status).toBe(400);

    const methodResponse = await permissionsRoute(service, new Request("https://project.example.com/user/permissions", { method: "POST" }), subject);
    expect(methodResponse.status).toBe(405);

    const unauthenticatedResponse = await permissionsRoute(service, new Request("https://project.example.com/user/permissions", { headers: { "x-request-id": "req-unauthenticated" } }));
    expect(unauthenticatedResponse.status).toBe(401);
    expect((await unauthenticatedResponse.json()).error.request_id).toBe("req-unauthenticated");

    await expect(service.authorize({ user_id: user.id, request_id: "req-denied" }, { all: ["secret.read"] })).rejects.toSatisfy((error: unknown) => {
      if (!(error instanceof Error)) return false;
      const candidate = error as Error & { code?: string; status?: number; request_id?: string };
      return candidate.code === "insufficient_permission" && candidate.status === 403 && candidate.request_id === "req-denied" && !candidate.message.includes("route.read") && !candidate.message.includes("secret.read");
    });
  });
});
