import { spawn } from "node:child_process";
import { mkdtemp, mkdir, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Pool } from "pg";
import { migrate } from "../../src/postgres/migrate.js";
import {
  createPostgresAdapter,
  type PostgresAdapter,
} from "../../src/postgres/adapter.js";
import type {
  AuditEventInput,
  CreateSessionInput,
} from "../../src/shared/contracts.js";
import {
  lowercaseKeySchema,
  permissionKeySchema,
  roleKeySchema,
  sanitizeIdentityData,
  sanitizeRedactedMetadata,
  scopeIdentifierSchema,
  uuidSchema,
  type RedactedMetadata,
  type AuthorizationScope,
  type Permission,
  type UUID,
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

let repository: PostgresAdapter;
let disposable: DisposablePostgres;
let pool: Pool;

async function runCommandResult(
  command: string,
  args: readonly string[],
  cwd?: string,
): Promise<CommandResult> {
  return new Promise<CommandResult>((resolve, reject) => {
    const child = spawn(command, args, {
      cwd,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk: Buffer) => {
      stdout += chunk.toString();
    });
    child.stderr.on("data", (chunk: Buffer) => {
      stderr += chunk.toString();
    });
    child.once("error", reject);
    child.once("close", (code) => resolve({ code, stdout, stderr }));
  });
}

async function runCommand(
  command: string,
  args: readonly string[],
  options: { readonly cwd?: string; readonly logPath?: string } = {},
): Promise<void> {
  const result = await runCommandResult(command, args, options.cwd);
  if (result.code === 0) return;
  const log = options.logPath ? await readFile(options.logPath, "utf8").catch(() => "") : "";
  throw new Error(
    `${command} ${args.join(" ")} exited with ${result.code ?? "unknown"}: ${(result.stderr || log).trim()}`,
  );
}

async function startDisposablePostgres(label: string): Promise<DisposablePostgres> {
  const root = await mkdtemp(join(tmpdir(), `${label}-`));
  const dataDirectory = join(root, "data");
  const socketDirectory = join(root, "socket");
  const cluster = { root, dataDirectory, socketDirectory };

  try {
    await mkdir(socketDirectory);
    await runCommand("initdb", [
      "--pgdata",
      dataDirectory,
      "--auth=trust",
      "--username=postgres",
      "--no-locale",
      "--encoding=UTF8",
    ]);
    await runCommand(
      "pg_ctl",
      [
        "--pgdata",
        dataDirectory,
        "--log",
        join(root, "postgres.log"),
        "--options",
        `-h '' -k ${socketDirectory}`,
        "--wait",
        "start",
      ],
      { logPath: join(root, "postgres.log") },
    );

    const disposablePool = new Pool({
      connectionString: `postgresql://postgres@localhost/postgres?host=${encodeURIComponent(socketDirectory)}`,
      max: 12,
    });
    try {
      await disposablePool.query("SELECT 1");
      return { cluster, pool: disposablePool };
    } catch (error) {
      await disposablePool.end().catch(() => undefined);
      throw error;
    }
  } catch (error) {
    await runCommand(
      "pg_ctl",
      ["--pgdata", dataDirectory, "--mode=immediate", "--wait", "stop"],
    ).catch(() => undefined);
    await rm(root, { recursive: true, force: true });
    throw error;
  }
}

async function stopDisposablePostgres(value: DisposablePostgres): Promise<void> {
  try {
    await value.pool.end();
  } finally {
    await runCommand(
      "pg_ctl",
      [
        "--pgdata",
        value.cluster.dataDirectory,
        "--mode=immediate",
        "--wait",
        "stop",
      ],
    ).catch(() => undefined);
    await rm(value.cluster.root, { recursive: true, force: true });
  }
}

function localConnectionString(value = disposable): string {
  return `postgresql://postgres@localhost/postgres?host=${encodeURIComponent(value.cluster.socketDirectory)}`;
}

function digest(byte: number): Uint8Array {
  return new Uint8Array(32).fill(byte);
}

function uuid(value: string): UUID {
  return uuidSchema.parse(value);
}

function scope(type: string, id: string): AuthorizationScope {
  return { type, id: scopeIdentifierSchema.parse(id) };
}

function strongPasswordHash(suffix = "c2FsdA"): string {
  return `$argon2id$v=19$m=65536,t=3,p=1$${suffix}$${suffix}`;
}

async function rows<Row extends Record<string, unknown>>(
  text: string,
  values: readonly unknown[] = [],
): Promise<readonly Row[]> {
  const result = await pool.query<Row>(text, [...values]);
  return result.rows;
}

async function count(table: string): Promise<number> {
  const result = await pool.query<{ readonly value: number }>(
    `SELECT count(*)::int AS value FROM auth.${table}`,
  );
  return result.rows[0]?.value ?? 0;
}

async function expectCode(operation: Promise<unknown>, code: string): Promise<void> {
  await expect(operation).rejects.toMatchObject({ code });
}

describe("Task 4 PostgreSQL adapter", () => {
  beforeAll(async () => {
    disposable = await startDisposablePostgres("mrjim-auth-task4");
    pool = disposable.pool;
    await migrate(pool, { direction: "up" });
    repository = createPostgresAdapter({ pool });
  }, 120_000);

  afterAll(async () => {
    await repository.close();
    await stopDisposablePostgres(disposable);
  });

  it("creates a user, identity, and password atomically and rolls them back together", async () => {
    const created = await repository.transaction(async (transaction) => {
      const user = await transaction.users.create({
        email: " Alice@Example.com ",
        phone: " +639171234567 ",
        email_confirmed_at: new Date("2026-08-11T00:00:00.000Z"),
        user_metadata: { displayName: "Alice" },
      });
      const identity = await transaction.identities.create({
        user_id: user.id,
        provider: "Google",
        provider_subject: "google-subject-1",
        email: "Alice@Example.com",
        identity_data: sanitizeIdentityData({
          sub: "google-subject-1",
          name: "Alice",
          access_token: "must-not-persist",
        }),
      });
      await transaction.passwordCredentials.upsert(
        user.id,
        strongPasswordHash(),
        new Date("2026-08-11T00:00:01.000Z"),
      );
      return { user, identity };
    });

    expect(created.user.email).toBe("Alice@Example.com");
    expect(created.user.confirmed_at).toBe("2026-08-11T00:00:00.000Z");
    expect(created.identity.provider).toBe("google");
    expect(created.identity.identity_data).toEqual({
      sub: "google-subject-1",
      name: "Alice",
    });
    expect(created.identity).not.toHaveProperty("access_token");
    expect(await repository.users.findByNormalizedEmail("ALICE@example.com"))
      .toMatchObject({ id: created.user.id });
    expect(await repository.identities.findByProviderSubject("google", "google-subject-1"))
      .toMatchObject({ user_id: created.user.id });
    expect(await repository.passwordCredentials.findByUserId(created.user.id))
      .toMatchObject({ user_id: created.user.id, password_hash: strongPasswordHash() });

    const rolledBackEmail = "rolled-back@example.com";
    await expect(
      repository.transaction(async (transaction) => {
        const user = await transaction.users.create({ email: rolledBackEmail });
        await transaction.identities.create({
          user_id: user.id,
          provider: "github",
          provider_subject: "rollback-subject",
          email: rolledBackEmail,
          identity_data: sanitizeIdentityData({ sub: "rollback-subject" }),
        });
        await transaction.passwordCredentials.upsert(user.id, strongPasswordHash("cm9sbGJhY2s"));
        throw new Error("rollback transaction");
      }),
    ).rejects.toThrow("rollback transaction");
    expect(await repository.users.findByNormalizedEmail(rolledBackEmail)).toBeNull();

    const updated = await repository.users.update(created.user.id, {
      email: "alice+updated@example.com",
      app_metadata: { provider: "google" },
    });
    expect(updated.email).toBe("alice+updated@example.com");
    expect(updated.app_metadata).toEqual({ provider: "google" });
    await repository.passwordCredentials.deleteByUserId(created.user.id);
    expect(await repository.passwordCredentials.findByUserId(created.user.id)).toBeNull();
    await repository.identities.deleteById(created.identity.id);
    expect(await repository.identities.listByUserId(created.user.id)).toEqual([]);
    await repository.users.softDelete(created.user.id);
    expect(await repository.users.findById(created.user.id)).toBeNull();
  });

  it("lets PostgreSQL arbitrate normalized-email races and keeps unrelated errors visible", async () => {
    const outcomes = await Promise.allSettled([
      repository.users.create({ email: "Race@Example.com" }),
      repository.users.create({ email: " race@example.com " }),
    ]);
    expect(outcomes.filter((outcome) => outcome.status === "fulfilled")).toHaveLength(1);
    const rejected = outcomes.find((outcome) => outcome.status === "rejected");
    expect(rejected).toMatchObject({
      status: "rejected",
      reason: { code: "email_exists", constraint: "users_email_normalized_key" },
    });
    expect(await repository.users.findByNormalizedEmail("RACE@example.com"))
      .toMatchObject({ email: expect.stringMatching(/Race|race/) });

    await expectCode(
      repository.users.create({
        email: "unrelated@example.com",
        user_metadata: "not-an-object" as unknown as Record<string, never>,
      }),
      "22P02",
    );
  });

  it("treats SQL-injection-like values as data and keeps the schema intact", async () => {
    const injectionLike = "x'); DROP TABLE auth.users; --@example.com";
    const user = await repository.users.create({ email: injectionLike });
    expect(await repository.users.findByNormalizedEmail(injectionLike)).toMatchObject({
      id: user.id,
      email: injectionLike,
    });
    const table = await rows<{ readonly relation: string | null }>(
      "SELECT to_regclass('auth.users')::text AS relation",
    );
    expect(table[0]?.relation).toBe("auth.users");
  });

  it("consumes one-time tokens atomically with purpose, expiry, and attempt guards", async () => {
    const now = new Date();
    const tokenHash = digest(11);
    await repository.oneTimeTokens.issue({
      purpose: "recovery",
      token_hash: tokenHash,
      target: "user@example.com",
      redirect: "https://example.com/recover",
      metadata: sanitizeRedactedMetadata({ event: "recovery.issued", count: 1 }),
      expires_at: new Date(now.getTime() + 10 * 60 * 1000),
    });

    const consumed = await Promise.all([
      repository.oneTimeTokens.consume(tokenHash, "recovery", now),
      repository.oneTimeTokens.consume(tokenHash, "recovery", now),
    ]);
    expect(consumed.filter((value) => value !== null)).toHaveLength(1);
    expect(consumed.filter((value) => value === null)).toHaveLength(1);
    expect(consumed.find((value) => value !== null)).toMatchObject({
      purpose: "recovery",
      target: "user@example.com",
      metadata: { event: "recovery.issued", count: 1 },
    });

    const expiredHash = digest(12);
    await repository.oneTimeTokens.issue({
      purpose: "email_otp",
      token_hash: expiredHash,
      target: "otp@example.com",
      expires_at: new Date(now.getTime() + 5 * 60 * 1000),
    });
    expect(
      await repository.oneTimeTokens.consume(
        expiredHash,
        "email_otp",
        new Date(now.getTime() + 6 * 60 * 1000),
      ),
    ).toBeNull();

    const attemptsHash = digest(13);
    await repository.oneTimeTokens.issue({
      purpose: "email_otp",
      token_hash: attemptsHash,
      target: "attempts@example.com",
      expires_at: new Date(now.getTime() + 10 * 60 * 1000),
    });
    await pool.query(
      "UPDATE auth.one_time_tokens SET attempt_count = $1 WHERE token_hash = $2",
      [5, Buffer.from(attemptsHash)],
    );
    expect(
      await repository.oneTimeTokens.consume(attemptsHash, "email_otp", now),
    ).toBeNull();
  });

  it("requires a transaction for refresh locks and rotates one refresh token winner", async () => {
    const user = await repository.users.create({ email: "refresh@example.com" });
    const initialHash = digest(21);
    const familyId = uuid("00000000-0000-4000-8000-000000000021");
    const created = await repository.sessions.create({
      user_id: user.id,
      aal: 2,
      ip_address: "127.0.0.1",
      user_agent: "task4-test",
      expires_at: new Date(Date.now() + 60 * 60 * 1000),
      token_hash: initialHash,
      family_id: familyId,
    });

    await expectCode(
      repository.sessions.findRefreshForUpdate(initialHash),
      "transaction_required",
    );

    const rotate = async (replacementByte: number) =>
      repository.transaction(async (transaction) => {
        const found = await transaction.sessions.findRefreshForUpdate(initialHash);
        if (!found) return null;
        return transaction.sessions.rotate(found.refreshToken.id, {
          session_id: found.session.id,
          token_hash: digest(replacementByte),
          family_id: found.refreshToken.family_id,
          parent_id: found.refreshToken.id,
          replacement_id: null,
          used_at: null,
          expires_at: new Date(Date.now() + 60 * 60 * 1000),
          revoked_at: null,
        });
      });

    const rotations = await Promise.allSettled([rotate(22), rotate(23)]);
    expect(rotations.filter((value) => value.status === "fulfilled")).toHaveLength(1);
    expect(rotations.filter((value) => value.status === "rejected")).toHaveLength(1);
    const rotationError = rotations.find((value) => value.status === "rejected");
    expect(rotationError).toMatchObject({
      status: "rejected",
      reason: { code: "refresh_token_not_rotatable" },
    });

    const lineage = await rows<{
      readonly id: UUID;
      readonly token_hash: Buffer;
      readonly parent_id: UUID | null;
      readonly replacement_id: UUID | null;
      readonly used_at: Date | null;
      readonly family_id: UUID;
    }>(
      `SELECT id, token_hash, parent_id, replacement_id, used_at, family_id
         FROM auth.refresh_tokens
        WHERE session_id = $1
        ORDER BY issued_at, id`,
      [created.session.id],
    );
    expect(lineage).toHaveLength(2);
    const initial = lineage.find((row) => row.id === created.refreshToken.id);
    const replacement = lineage.find((row) => row.parent_id === created.refreshToken.id);
    expect(initial?.used_at).not.toBeNull();
    expect(initial?.replacement_id).toBe(replacement?.id);
    expect(initial?.family_id).toBe(familyId);
    expect(replacement?.parent_id).toBe(created.refreshToken.id);

    await repository.sessions.revokeFamily(familyId);
    const revokedFamily = await rows<{ readonly revoked_at: Date | null }>(
      "SELECT revoked_at FROM auth.refresh_tokens WHERE family_id = $1",
      [familyId],
    );
    expect(revokedFamily.every((row) => row.revoked_at !== null)).toBe(true);

    const preserved = await repository.sessions.create({
      user_id: user.id,
      expires_at: new Date(Date.now() + 60 * 60 * 1000),
      token_hash: digest(24),
      family_id: uuid("00000000-0000-4000-8000-000000000024"),
    });
    const revoked = await repository.sessions.create({
      user_id: user.id,
      expires_at: new Date(Date.now() + 60 * 60 * 1000),
      token_hash: digest(25),
      family_id: uuid("00000000-0000-4000-8000-000000000025"),
    });
    await repository.sessions.revokeUserSessions(user.id, preserved.session.id);
    const sessionStates = await rows<{
      readonly id: UUID;
      readonly revoked_at: Date | null;
    }>(
      "SELECT id, revoked_at FROM auth.sessions WHERE user_id = $1 ORDER BY id",
      [user.id],
    );
    expect(sessionStates.find((row) => row.id === preserved.session.id)?.revoked_at).toBeNull();
    expect(sessionStates.find((row) => row.id === revoked.session.id)?.revoked_at).not.toBeNull();
  });

  it("resolves direct and inherited scoped permissions while ignoring expired assignments", async () => {
    const user = await repository.users.create({ email: "authorization@example.com" });
    const parent = await repository.roles.create({
      key: roleKeySchema.parse("parent"),
      name: "Parent",
      rank: 10,
    });
    const child = await repository.roles.create({
      key: roleKeySchema.parse("child"),
      name: "Child",
      rank: 20,
    });
    const expired = await repository.roles.create({
      key: roleKeySchema.parse("expired"),
      name: "Expired",
      rank: 30,
    });
    const directPermission = await repository.permissions.create({
      key: permissionKeySchema.parse("billing.read"),
      resource: lowercaseKeySchema.parse("billing"),
      action: lowercaseKeySchema.parse("read"),
      description: "Read billing",
    });
    const inheritedPermission = await repository.permissions.create({
      key: permissionKeySchema.parse("billing.export"),
      resource: lowercaseKeySchema.parse("billing"),
      action: lowercaseKeySchema.parse("export"),
    });
    const expiredPermission = await repository.permissions.create({
      key: permissionKeySchema.parse("billing.delete"),
      resource: lowercaseKeySchema.parse("billing"),
      action: lowercaseKeySchema.parse("delete"),
    });
    const scopedPermission = await repository.permissions.create({
      key: permissionKeySchema.parse("reports.read"),
      resource: lowercaseKeySchema.parse("reports"),
      action: lowercaseKeySchema.parse("read"),
    });

    await repository.authorization.setRolePermissions(parent.id, [inheritedPermission.id]);
    await repository.authorization.setRolePermissions(child.id, [directPermission.id]);
    await repository.authorization.setRolePermissions(expired.id, [expiredPermission.id]);
    await repository.authorization.setRoleInheritance(child.id, [parent.id]);

    const orgScope = scope("org", "org_123");
    const otherScope = scope("org", "org_456");
    await repository.authorization.assignRole({ user_id: user.id, role_id: child.id, scope: orgScope });
    await repository.authorization.assignRole({ user_id: user.id, role_id: expired.id, expires_at: new Date(Date.now() + 1000) });
    await repository.authorization.assignRole({
      user_id: user.id,
      role_id: expired.id,
      scope: otherScope,
      expires_at: new Date(Date.now() + 1000),
    });

    const permissions = await repository.authorization.effectivePermissions(user.id, orgScope, {
      now: new Date(Date.now() + 5000),
    });
    expect(permissions.map((permission) => permission.key).sort()).toEqual([
      directPermission.key,
      inheritedPermission.key,
    ].sort());
    expect(permissions.every((permission) => permission.id && permission.updated_at)).toBe(true);
    expect(
      await repository.authorization.effectivePermissions(user.id, otherScope, {
        now: new Date(Date.now() + 5000),
      }),
    ).toEqual([]);

    await repository.authorization.assignRole({ user_id: user.id, role_id: parent.id });
    await repository.authorization.setRolePermissions(parent.id, [inheritedPermission.id, scopedPermission.id]);
    const global = await repository.authorization.effectivePermissions(user.id, undefined, {
      now: new Date(Date.now() + 5000),
    });
    expect(global.map((permission) => permission.key).sort()).toEqual([
      inheritedPermission.key,
      scopedPermission.key,
    ].sort());
    await repository.authorization.unassignRole(user.id, parent.id);
    expect(
      await repository.authorization.effectivePermissions(user.id, undefined, {
        now: new Date(Date.now() + 5000),
      }),
    ).toEqual([]);
  });

  it("keeps role relationship replacement atomic and preserves database cycle errors", async () => {
    const roleA = await repository.roles.create({
      key: roleKeySchema.parse("cycle_a"),
      name: "Cycle A",
      rank: 1,
    });
    const roleB = await repository.roles.create({
      key: roleKeySchema.parse("cycle_b"),
      name: "Cycle B",
      rank: 1,
    });

    await expect(
      repository.transaction(async (transaction) => {
        await transaction.authorization.setRoleInheritance(roleA.id, [roleB.id]);
        await transaction.authorization.setRoleInheritance(roleB.id, [roleA.id]);
      }),
    ).rejects.toThrow(/role_inheritance_cycle|cycle/i);

    const relationships = await rows<{
      readonly role_id: UUID;
      readonly inherits_role_id: UUID;
    }>(
      `SELECT role_id, inherits_role_id
         FROM auth.role_inheritance
        WHERE role_id IN ($1, $2) OR inherits_role_id IN ($1, $2)`,
      [roleA.id, roleB.id],
    );
    expect(relationships).toEqual([]);

    await repository.authorization.setRoleInheritance(roleA.id, [roleB.id]);
    await repository.authorization.setRoleInheritance(roleA.id, []);
    expect(
      await rows("SELECT role_id FROM auth.role_inheritance WHERE role_id = $1", [roleA.id]),
    ).toEqual([]);
  });

  it("implements role and permission CRUD with real row mappings and transaction rollback", async () => {
    const role = await repository.roles.create({
      key: roleKeySchema.parse("crud_role"),
      name: "CRUD role",
      description: "before",
      rank: 5,
    });
    const permission = await repository.permissions.create({
      key: permissionKeySchema.parse("crud.read"),
      resource: lowercaseKeySchema.parse("crud"),
      action: lowercaseKeySchema.parse("read"),
      description: "before",
    });
    expect(await repository.roles.list()).toContainEqual(role);
    expect(await repository.roles.findById(role.id)).toEqual(role);
    expect(await repository.permissions.findById(permission.id)).toEqual(permission);

    const updatedRole = await repository.roles.update(role.id, {
      name: "CRUD role updated",
      description: null,
      rank: 6,
    });
    const updatedPermission = await repository.permissions.update(permission.id, {
      description: "after",
    });
    expect(updatedRole).toMatchObject({ name: "CRUD role updated", description: null, rank: 6 });
    expect(updatedPermission).toMatchObject({ description: "after" });

    const rollbackRoleKey = roleKeySchema.parse("rollback_role");
    await expect(
      repository.transaction(async (transaction) => {
        await transaction.roles.create({ key: rollbackRoleKey, name: "rollback", rank: 0 });
        throw new Error("role rollback");
      }),
    ).rejects.toThrow("role rollback");
    expect(await repository.roles.list()).not.toContainEqual(
      expect.objectContaining({ key: rollbackRoleKey }),
    );

    await repository.permissions.delete(permission.id);
    await repository.roles.delete(role.id);
    expect(await repository.permissions.findById(permission.id)).toBeNull();
    expect(await repository.roles.findById(role.id)).toBeNull();
  });

  it("consumes OAuth state once and maps API keys without exposing raw credentials", async () => {
    const stateHash = digest(31);
    await repository.oauthStates.create({
      state_hash: stateHash,
      provider: "Google",
      flow: "sign_in",
      pkce_challenge: "pkce-challenge",
      encrypted_verifier: digest(32),
      redirect: "https://example.com/oauth/callback",
      expires_at: new Date(Date.now() + 5 * 60 * 1000),
    });
    const stateResults = await Promise.all([
      repository.oauthStates.consume(stateHash, new Date()),
      repository.oauthStates.consume(stateHash, new Date()),
    ]);
    expect(stateResults.filter((value) => value !== null)).toHaveLength(1);
    expect(stateResults.find((value) => value !== null)).toMatchObject({
      provider: "google",
      flow: "sign_in",
      redirect: "https://example.com/oauth/callback",
    });

    const apiKeyHash = digest(33);
    const apiKeyId = uuid("00000000-0000-4000-8000-000000000033");
    await pool.query(
      `INSERT INTO auth.api_keys (id, prefix, key_hash, kind, scopes, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [apiKeyId, "pk_test", Buffer.from(apiKeyHash), "publishable", ["billing.read"], new Date(Date.now() + 60_000)],
    );
    const apiKey = await repository.operations.findApiKeyByHash(apiKeyHash);
    expect(apiKey).toMatchObject({ id: apiKeyId, prefix: "pk_test", kind: "publishable", scopes: ["billing.read"] });
    expect(apiKey).not.toHaveProperty("raw_key");
    await pool.query("UPDATE auth.api_keys SET revoked_at = now() WHERE id = $1", [apiKeyId]);
    expect(await repository.operations.findApiKeyByHash(apiKeyHash)).toBeNull();
  });

  it("accepts only redacted audit metadata and leaves audit writes immutable", async () => {
    const input: AuditEventInput = {
      action: "user.created",
      target_type: "user",
      target_id: uuid("00000000-0000-4000-8000-000000000001"),
      metadata: sanitizeRedactedMetadata({
        event: "user.created",
        changed: true,
        changed_fields: ["email"],
      }),
      outcome: "success",
    };
    const before = await count("audit_log");
    await repository.operations.appendAudit(input);
    expect(await count("audit_log")).toBe(before + 1);

    const unsafe = {
      ...input,
      metadata: { token: "raw-token-value" } as unknown as RedactedMetadata,
    };
    await expect(repository.operations.appendAudit(unsafe)).rejects.toThrow(/audit|redact|sensitive/i);
    expect(await count("audit_log")).toBe(before + 1);
    await expect(
      pool.query("UPDATE auth.audit_log SET action = $1", ["mutated"]),
    ).rejects.toThrow(/immutable/i);
  });

  it("does not migrate or close caller-owned pools and provides close for owned pools", async () => {
    const before = await count("schema_migrations");
    const external = createPostgresAdapter({ pool });
    expect(external.ownsPool).toBe(false);
    await external.close();
    await expect(pool.query("SELECT 1")).resolves.toBeDefined();
    expect(await count("schema_migrations")).toBe(before);

    const owned = createPostgresAdapter({ connectionString: localConnectionString() });
    expect(owned.ownsPool).toBe(true);
    await expect(owned.users.findByNormalizedEmail("alice@example.com")).resolves.toBeDefined();
    await owned.close();
    await expect(owned.users.findByNormalizedEmail("alice@example.com")).rejects.toThrow();
    await owned.close();
  });
});
