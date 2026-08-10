import { generateKeyPairSync } from "node:crypto";
import { spawn } from "node:child_process";
import { mkdtemp, mkdir, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Pool } from "pg";
import type { KeyProvider } from "../../src/shared/contracts.js";
import { migrate } from "../../src/postgres/migrate.js";
import { createPostgresAdapter, type PostgresAdapter } from "../../src/postgres/adapter.js";
import { roleKeySchema, uuidSchema, type User } from "../../src/shared/types.js";
import { FakeMailer } from "../../src/testing/fake-mailer.js";
import { EmailService } from "../../src/server/email.js";
import { OneTimeTokenService } from "../../src/server/one-time-tokens.js";
import { PasswordService } from "../../src/server/passwords.js";
import { UserService } from "../../src/server/users.js";
import { SessionService } from "../../src/server/sessions.js";
import { TokenService } from "../../src/server/tokens.js";

const NOW = new Date("2026-08-11T06:00:00.000Z");
const CALLBACK = "https://project.example.com/auth/callback";
const TOKEN_HASH_KEY = Uint8Array.from({ length: 32 }, (_, index) => index + 1);
const PASSWORD = "correct horse battery staple";

type DisposablePostgres = {
  readonly root: string;
  readonly dataDirectory: string;
  readonly socketDirectory: string;
  readonly pool: Pool;
};

let disposable: DisposablePostgres | undefined;
let repository: PostgresAdapter | undefined;
let serviceNow = NOW;

function keyProvider(): KeyProvider {
  const pair = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return {
    getActiveKeyId: () => "task6",
    getSigningKey: () => pair.privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    getVerificationKeys: () => new Map([
      ["task6", pair.publicKey.export({ type: "spki", format: "pem" }).toString()],
    ]),
  };
}

async function command(command: string, args: readonly string[], logPath?: string): Promise<void> {
  const result = await new Promise<{ code: number | null; stderr: string }>((resolve, reject) => {
    const child = spawn(command, args, { stdio: ["ignore", "ignore", "pipe"] });
    let stderr = "";
    child.stderr.on("data", (chunk: Buffer) => { stderr += chunk.toString(); });
    child.once("error", reject);
    child.once("close", (code) => resolve({ code, stderr }));
  });
  if (result.code === 0) return;
  const log = logPath === undefined ? "" : await readFile(logPath, "utf8").catch(() => "");
  throw new Error(`${command} ${args.join(" ")} failed: ${(result.stderr || log).trim()}`);
}

async function startPostgres(): Promise<DisposablePostgres> {
  const root = await mkdtemp(join(tmpdir(), "mrjim-auth-task6-lifecycle-"));
  const dataDirectory = join(root, "data");
  const socketDirectory = join(root, "socket");
  const logPath = join(root, "postgres.log");
  try {
    await mkdir(socketDirectory);
    await command("initdb", ["--pgdata", dataDirectory, "--auth=trust", "--username=postgres", "--no-locale", "--encoding=UTF8"]);
    await command("pg_ctl", ["--pgdata", dataDirectory, "--log", logPath, "--options", `-h '' -k ${socketDirectory}`, "--wait", "start"], logPath);
    const pool = new Pool({
      connectionString: `postgresql://postgres@localhost/postgres?host=${encodeURIComponent(socketDirectory)}`,
      max: 12,
    });
    await pool.query("SELECT 1");
    return { root, dataDirectory, socketDirectory, pool };
  } catch (error) {
    await command("pg_ctl", ["--pgdata", dataDirectory, "--mode=immediate", "--wait", "stop"]).catch(() => undefined);
    await rm(root, { recursive: true, force: true });
    throw error;
  }
}

async function stopPostgres(value: DisposablePostgres): Promise<void> {
  try {
    await value.pool.end();
  } finally {
    await command("pg_ctl", ["--pgdata", value.dataDirectory, "--mode=immediate", "--wait", "stop"]).catch(() => undefined);
    await rm(value.root, { recursive: true, force: true });
  }
}

function services(options: { readonly concealUserExistence?: boolean; readonly requireEmailConfirmation?: boolean; readonly passwordPolicy?: { readonly memoryCost?: number } } = {}) {
  const currentRepository = repository;
  if (currentRepository === undefined) throw new Error("repository is not initialized");
  const mailer = new FakeMailer();
  const email = new EmailService({ allowedRedirects: [CALLBACK], defaultRedirect: CALLBACK });
  const tokens = new TokenService({
    issuer: "https://project.example.com/auth/v1",
    audience: "project",
    keyProvider: keyProvider(),
    tokenHashKey: TOKEN_HASH_KEY,
    clock: () => serviceNow,
  });
  const sessions = new SessionService({ repository: currentRepository, tokens, clock: () => serviceNow });
  const oneTimeTokens = new OneTimeTokenService({
    repository: currentRepository,
    mailer,
    email,
    tokenHashKey: TOKEN_HASH_KEY,
    allowedRedirects: [CALLBACK],
    defaultRedirect: CALLBACK,
    clock: () => serviceNow,
  });
  const passwords = new PasswordService(options.passwordPolicy);
  const users = new UserService({
    repository: currentRepository,
    passwords,
    email,
    mailer,
    oneTimeTokens,
    sessions,
    defaultRoleKeys: [roleKeySchema.parse("member")],
    requireEmailConfirmation: options.requireEmailConfirmation ?? true,
    concealUserExistence: options.concealUserExistence ?? true,
    clock: () => serviceNow,
  });
  return { users, passwords, oneTimeTokens, sessions, mailer, email, repository: currentRepository };
}

function data<T>(result: { readonly data: T | null; readonly error: unknown }): T {
  if (result.data === null) throw new Error(`expected success, got ${JSON.stringify(result.error)}`);
  return result.data;
}

describe("Task 6 user lifecycle", () => {
  beforeAll(async () => {
    disposable = await startPostgres();
    await migrate(disposable.pool, { direction: "up" });
    repository = createPostgresAdapter({ pool: disposable.pool });
    await repository.roles.create({ key: roleKeySchema.parse("member"), name: "Member", rank: 1 });
  }, 120_000);

  afterAll(async () => {
    await repository?.close();
    if (disposable !== undefined) await stopPostgres(disposable);
  });

  it("signs up with Unicode-only email normalization, assigns defaults, confirms email, and signs in", async () => {
    const service = services();
    const signup = await service.users.signUp({
      email: "  Cafe\u0301+tag@Example.com ",
      password: PASSWORD,
      options: { redirectTo: CALLBACK },
    }, { ip_address: "127.0.0.1", user_agent: "task6 browser" });

    expect(signup.error).toBeNull();
    expect(signup.data).toMatchObject({ user: null, session: null });
    const user = await service.repository.users.findByNormalizedEmail("CAFÉ+TAG@example.com");
    expect(user?.email).toBe("Café+tag@Example.com");
    expect(user?.email?.split("@")[0]).not.toContain(".");
    expect(user).not.toHaveProperty("password_hash");
    const roles = await disposable?.pool.query("SELECT r.key FROM auth.user_roles ur JOIN auth.roles r ON r.id = ur.role_id WHERE ur.user_id = $1", [user?.id]);
    expect(roles?.rows).toEqual([{ key: "member" }]);

    const confirmation = service.mailer.latest("confirmation");
    expect(confirmation?.to).toBe("Café+tag@Example.com");
    expect(confirmation?.variables.token).toEqual(expect.any(String));
    expect(JSON.stringify(signup)).not.toContain(confirmation?.variables.token ?? "never");

    const confirmed = await service.users.confirmEmail({
      email: "CAFÉ+TAG@example.com",
      token: confirmation?.variables.token ?? "",
      redirectTo: CALLBACK,
    });
    const confirmedData = data(confirmed);
    if (confirmedData.user === null) throw new Error("expected confirmed user");
    expect(confirmedData.user.email_confirmed_at).not.toBeNull();
    expect(confirmedData.session).toBeTruthy();

    const signedIn = await service.users.signIn({ email: "café+tag@example.com", password: PASSWORD }, { ip_address: "127.0.0.1" });
    const signedInData = data(signedIn);
    if (signedInData.session === null) throw new Error("expected password session");
    expect(signedInData.session.user.email).toBe("Café+tag@Example.com");
  });

  it("rehashes a valid lower-cost Argon2id credential after password sign-in", async () => {
    const service = services({ requireEmailConfirmation: false, concealUserExistence: false, passwordPolicy: { memoryCost: 128 * 1024 } });
    const signup = data(await service.users.signUp({ email: "rehash@example.com", password: PASSWORD }));
    const user = signup.user;
    if (user === null) throw new Error("expected visible signup user");
    const { hashPassword } = service.passwords;
    const weakForService = await hashPassword(PASSWORD, { memoryCost: 65_536, timeCost: 3, parallelism: 1 });
    await service.repository.passwordCredentials.upsert(user.id, weakForService, serviceNow);
    const before = await service.repository.passwordCredentials.findByUserId(user.id);
    const signedIn = await service.users.signIn({ email: user.email ?? "", password: PASSWORD });
    expect(signedIn.error).toBeNull();
    const after = await service.repository.passwordCredentials.findByUserId(user.id);
    expect(after?.password_hash).not.toBe(before?.password_hash);
  });

  it("sends magic links and atomically consumes an OTP on the fifth failed attempt", async () => {
    const service = services({ requireEmailConfirmation: false, concealUserExistence: false });
    const created = data(await service.users.signUp({ email: "otp@example.com", password: PASSWORD }));
    if (created.user === null) throw new Error("expected visible signup user");

    const magic = data(await service.users.signInWithOtp({ email: created.user.email ?? "", options: { type: "magic_link", redirectTo: CALLBACK } }));
    expect(magic.session).toBeNull();
    const magicMessage = service.mailer.latest("magic_link");
    const magicResult = await service.users.verifyMagicLink({ email: created.user.email ?? "", token: magicMessage?.variables.token ?? "", redirectTo: CALLBACK });
    expect(data(magicResult).session).toBeTruthy();
    const replayedMagic = await service.users.verifyMagicLink({ email: created.user.email ?? "", token: magicMessage?.variables.token ?? "", redirectTo: CALLBACK });
    expect(replayedMagic.data).toBeNull();
    expect(replayedMagic.error?.code).toBe("invalid_token");

    await service.users.signInWithOtp({ email: created.user.email ?? "", options: { type: "email_otp", redirectTo: CALLBACK } });
    const otpMessage = service.mailer.latest("email_otp");
    const wrongAttempts = await Promise.all(Array.from({ length: 10 }, (_, index) =>
      service.users.verifyOtp({ email: created.user?.email ?? "", token: `wrong-${index}`, type: "email_otp", redirectTo: CALLBACK }),
    ));
    expect(wrongAttempts.map((result) => result.error?.code)).toEqual(Array.from({ length: 10 }, () => "otp_invalid"));
    expect(wrongAttempts.filter((result) => result.data !== null)).toHaveLength(0);
    const row = await disposable?.pool.query("SELECT attempt_count, consumed_at FROM auth.one_time_tokens WHERE target = $1 AND purpose = 'email_otp' ORDER BY created_at DESC LIMIT 1", [created.user.email?.toLowerCase()]);
    expect(row?.rows[0]?.attempt_count).toBe(5);
    expect(row?.rows[0]?.consumed_at).not.toBeNull();
    expect(JSON.stringify(row?.rows[0])).not.toContain(otpMessage?.variables.token ?? "never");
    const correctAfterRace = await service.users.verifyOtp({ email: created.user.email ?? "", token: otpMessage?.variables.token ?? "", type: "email_otp", redirectTo: CALLBACK });
    expect(correctAfterRace.data).toBeNull();

    const auditRows = await disposable?.pool.query("SELECT action, metadata, user_agent, ip_address FROM auth.audit_log");
    const auditText = JSON.stringify(auditRows?.rows ?? []);
    expect(auditText).not.toContain(otpMessage?.variables.token ?? "never");
    expect(auditText).not.toContain(PASSWORD);
    expect(auditText).not.toContain("otp@example.com");
    expect(auditText).not.toContain("$argon2id$");
  });

  it("conceals recovery and password reset while revoking all sessions by default", async () => {
    const service = services({ requireEmailConfirmation: false, concealUserExistence: false });
    const created = data(await service.users.signUp({ email: "recovery@example.com", password: PASSWORD }));
    if (created.user === null || created.session === null) throw new Error("expected recovery fixture session");
    const recovery = await service.users.resetPasswordForEmail("recovery@example.com", { redirectTo: CALLBACK });
    const nonexistent = await service.users.resetPasswordForEmail("missing-recovery@example.com", { redirectTo: CALLBACK });
    expect(recovery).toEqual(expect.objectContaining({ data: expect.anything(), error: null }));
    expect(nonexistent).toEqual({ data: { sent: true }, error: null });
    expect(recovery.data).toEqual({ sent: true });
    const message = service.mailer.latest("recovery");
    const reset = await service.users.resetPassword({
      email: "recovery@example.com",
      token: message?.variables.token ?? "",
      password: "new correct horse battery staple",
      redirectTo: CALLBACK,
    });
    expect(data(reset).user.id).toBe(created.user.id);
    const oldRefresh = await service.sessions.refresh(created.session.refresh_token);
    expect(oldRefresh.data).toBeNull();
    const signedIn = await service.users.signIn({ email: "recovery@example.com", password: "new correct horse battery staple" });
    expect(signedIn.error).toBeNull();
  });

  it("rejects banned and soft-deleted users without returning credentials or sessions", async () => {
    const service = services({ requireEmailConfirmation: false, concealUserExistence: false });
    const created = data(await service.users.signUp({ email: "blocked@example.com", password: PASSWORD }));
    if (created.user === null) throw new Error("expected visible signup user");
    await service.repository.users.update(created.user.id, { banned_until: new Date(serviceNow.getTime() + 60 * 60 * 1000) });
    const banned = await service.users.signIn({ email: "blocked@example.com", password: PASSWORD });
    expect(banned.data).toBeNull();
    expect(banned.error).toBeTruthy();
    await service.repository.users.softDelete(created.user.id, serviceNow);
    const deleted = await service.users.signIn({ email: "blocked@example.com", password: PASSWORD });
    expect(deleted.data).toBeNull();
    expect(deleted.error).toBeTruthy();
  });
});
