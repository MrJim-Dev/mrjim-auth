import { generateKeyPairSync } from "node:crypto";
import { spawn } from "node:child_process";
import { mkdtemp, mkdir, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Pool } from "pg";
import type { AuthRepository, KeyProvider } from "../../src/shared/contracts.js";
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
const ALT_CALLBACK = "https://project.example.com/auth/alternate";
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

function services(options: {
  readonly concealUserExistence?: boolean;
  readonly requireEmailConfirmation?: boolean;
  readonly passwordPolicy?: { readonly memoryCost?: number };
  readonly repository?: PostgresAdapter;
} = {}) {
  const currentRepository = options.repository ?? repository;
  if (currentRepository === undefined) throw new Error("repository is not initialized");
  const mailer = new FakeMailer();
  const email = new EmailService({ allowedRedirects: [CALLBACK, ALT_CALLBACK], defaultRedirect: CALLBACK });
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
    allowedRedirects: [CALLBACK, ALT_CALLBACK],
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

function transactionFailureRepository(base: PostgresAdapter, failure: "repository" | "audit"): PostgresAdapter {
  return {
    ...base,
    async transaction<T>(callback: (transaction: AuthRepository) => Promise<T>): Promise<T> {
      return base.transaction((transaction) => callback({
        ...transaction,
        users: failure === "repository"
          ? { ...transaction.users, update: async () => { throw new Error("injected repository failure"); } }
          : transaction.users,
        operations: failure === "audit"
          ? { ...transaction.operations, appendAudit: async () => { throw new Error("injected audit failure"); } }
          : transaction.operations,
      } as AuthRepository));
    },
  };
}

function targetPrecheckBarrier(expected: number, timeoutMs: number) {
  let arrivalCount = 0;
  let opened = false;
  let resolveReady!: () => void;
  let resolveRelease!: () => void;
  const ready = new Promise<void>((resolve) => { resolveReady = resolve; });
  const released = new Promise<void>((resolve) => { resolveRelease = resolve; });
  const release = () => {
    if (opened) return;
    opened = true;
    resolveRelease();
  };
  return {
    ready,
    arrivals: () => arrivalCount,
    release,
    async arrive(): Promise<void> {
      if (opened) return;
      arrivalCount += 1;
      if (arrivalCount === expected) {
        resolveReady();
        release();
      }
      if (opened) return;
      let timer: ReturnType<typeof setTimeout> | undefined;
      try {
        await Promise.race([
          released,
          new Promise<never>((_, reject) => {
            timer = setTimeout(() => {
              release();
              reject(new Error("target-email precheck barrier timed out"));
            }, timeoutMs);
          }),
        ]);
      } finally {
        if (timer !== undefined) clearTimeout(timer);
      }
    },
  };
}

function targetPrecheckBarrierRepository(
  base: PostgresAdapter,
  target: string,
  barrier: ReturnType<typeof targetPrecheckBarrier>,
): PostgresAdapter {
  return {
    ...base,
    async transaction<T>(callback: (transaction: AuthRepository) => Promise<T>): Promise<T> {
      return base.transaction((transaction) => callback({
        ...transaction,
        users: {
          ...transaction.users,
          findByNormalizedEmail: async (email, options) => {
            const result = await transaction.users.findByNormalizedEmail(email, options);
            if (email === target) await barrier.arrive();
            return result;
          },
        },
      } as AuthRepository));
    },
  };
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
    const createdUser = created.user;
    if (createdUser === null) throw new Error("expected OTP user");
    const wrongAttempts = await Promise.all(Array.from({ length: 10 }, (_, index) =>
      service.users.verifyOtp({ email: createdUser.email ?? "", token: otpMessage?.variables.token ?? "", type: "email_otp", redirectTo: ALT_CALLBACK }),
    ));
    expect(wrongAttempts.map((result) => result.error?.code)).toEqual(Array.from({ length: 10 }, () => "otp_invalid"));
    expect(wrongAttempts.filter((result) => result.data !== null)).toHaveLength(0);
    const row = await disposable?.pool.query("SELECT attempt_count, consumed_at FROM auth.one_time_tokens WHERE target = $1 AND purpose = 'email_otp' ORDER BY created_at DESC LIMIT 1", [created.user.email?.toLowerCase()]);
    expect(row?.rows[0]?.attempt_count).toBe(5);
    expect(row?.rows[0]?.consumed_at).not.toBeNull();
    expect(JSON.stringify(row?.rows[0])).not.toContain(otpMessage?.variables.token ?? "never");
    const correctAfterRace = await service.users.verifyOtp({ email: created.user.email ?? "", token: otpMessage?.variables.token ?? "", type: "email_otp", redirectTo: CALLBACK });
    expect(correctAfterRace.data).toBeNull();

    const firstOtp = await service.users.signInWithOtp({ email: created.user.email ?? "", options: { type: "email_otp", redirectTo: CALLBACK } });
    expect(firstOtp.error).toBeNull();
    const firstMessage = service.mailer.latest("email_otp");
    const secondOtp = await service.users.signInWithOtp({ email: created.user.email ?? "", options: { type: "email_otp", redirectTo: CALLBACK } });
    expect(secondOtp.error).toBeNull();
    const secondMessage = service.mailer.latest("email_otp");
    expect(firstMessage?.variables.token).not.toBe(secondMessage?.variables.token);
    const firstTokenWrong = await Promise.all(Array.from({ length: 5 }, () =>
      service.users.verifyOtp({ email: created.user?.email ?? "", token: firstMessage?.variables.token ?? "", type: "email_otp", redirectTo: ALT_CALLBACK }),
    ));
    expect(firstTokenWrong.every((result) => result.error?.code === "otp_invalid")).toBe(true);
    const firstTokenAfterFailures = await service.users.verifyOtp({ email: created.user.email ?? "", token: firstMessage?.variables.token ?? "", type: "email_otp", redirectTo: CALLBACK });
    expect(firstTokenAfterFailures.data).toBeNull();
    const secondTokenStillWorks = await service.users.verifyOtp({ email: created.user.email ?? "", token: secondMessage?.variables.token ?? "", type: "email_otp", redirectTo: CALLBACK });
    expect(secondTokenStillWorks.error).toBeNull();

    await service.users.signInWithOtp({ email: created.user.email ?? "", options: { type: "email_otp", redirectTo: CALLBACK } });
    const thirdMessage = service.mailer.latest("email_otp");
    await service.users.signInWithOtp({ email: created.user.email ?? "", options: { type: "email_otp", redirectTo: CALLBACK } });
    const fourthMessage = service.mailer.latest("email_otp");
    const fourthTokenWrong = await Promise.all(Array.from({ length: 5 }, () =>
      service.users.verifyOtp({ email: createdUser.email ?? "", token: fourthMessage?.variables.token ?? "", type: "email_otp", redirectTo: ALT_CALLBACK }),
    ));
    expect(fourthTokenWrong.every((result) => result.error?.code === "otp_invalid")).toBe(true);
    const thirdTokenStillWorks = await service.users.verifyOtp({ email: createdUser.email ?? "", token: thirdMessage?.variables.token ?? "", type: "email_otp", redirectTo: CALLBACK });
    expect(thirdTokenStillWorks.error).toBeNull();
    const fourthTokenAfterFailures = await service.users.verifyOtp({ email: createdUser.email ?? "", token: fourthMessage?.variables.token ?? "", type: "email_otp", redirectTo: CALLBACK });
    expect(fourthTokenAfterFailures.data).toBeNull();

    const raceOtp = await service.users.signInWithOtp({ email: created.user.email ?? "", options: { type: "email_otp", redirectTo: CALLBACK } });
    expect(raceOtp.error).toBeNull();
    const raceMessage = service.mailer.latest("email_otp");
    const raceResults = await Promise.all([
      ...Array.from({ length: 5 }, () => service.users.verifyOtp({ email: createdUser.email ?? "", token: raceMessage?.variables.token ?? "", type: "email_otp", redirectTo: ALT_CALLBACK })),
      service.users.verifyOtp({ email: created.user.email ?? "", token: raceMessage?.variables.token ?? "", type: "email_otp", redirectTo: CALLBACK }),
    ]);
    expect(raceResults.filter((result) => result.data !== null).length).toBeLessThanOrEqual(1);
    const raceRow = await disposable?.pool.query("SELECT attempt_count, consumed_at FROM auth.one_time_tokens WHERE target = $1 AND purpose = 'email_otp' ORDER BY created_at DESC LIMIT 1", [createdUser.email?.toLowerCase()]);
    expect(raceRow?.rows[0]?.attempt_count).toBeLessThanOrEqual(5);
    expect(raceRow?.rows[0]?.consumed_at).not.toBeNull();
    const raceAfterConsume = await service.users.verifyOtp({ email: created.user.email ?? "", token: raceMessage?.variables.token ?? "", type: "email_otp", redirectTo: CALLBACK });
    expect(raceAfterConsume.data).toBeNull();

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

  it("binds direct OTP resend failures to the presented digest", async () => {
    const service = services({ requireEmailConfirmation: false, concealUserExistence: false });
    const created = data(await service.users.signUp({ email: "otp-resend-binding@example.com", password: PASSWORD }));
    if (created.user === null) throw new Error("expected OTP resend user");
    const target = created.user.email ?? "";
    await service.oneTimeTokens.resend({ purpose: "email_otp", userId: created.user.id, target, to: target, redirectTo: CALLBACK });
    const first = service.mailer.latest("email_otp");
    await service.oneTimeTokens.resend({ purpose: "email_otp", userId: created.user.id, target, to: target, redirectTo: CALLBACK });
    const second = service.mailer.latest("email_otp");
    expect(first?.variables.token).not.toBe(second?.variables.token);

    for (let attempt = 0; attempt < 5; attempt += 1) {
      const failed = await service.oneTimeTokens.verify({
        purpose: "email_otp",
        target,
        token: first?.variables.token ?? "",
        redirectTo: ALT_CALLBACK,
      });
      expect(failed.error?.code).toBe("otp_invalid");
    }
    const oldToken = await service.oneTimeTokens.verify({ purpose: "email_otp", target, token: first?.variables.token ?? "", redirectTo: CALLBACK });
    const newToken = await service.oneTimeTokens.verify({ purpose: "email_otp", target, token: second?.variables.token ?? "", redirectTo: CALLBACK });
    expect(oldToken.data).toBeNull();
    expect(newToken.error).toBeNull();
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

  it("rejects sessionless, cross-user, revoked, banned, and app_metadata self-service mutations", async () => {
    const service = services({ requireEmailConfirmation: false, concealUserExistence: false });
    const first = data(await service.users.signUp({ email: "self-service-a@example.com", password: PASSWORD }));
    const second = data(await service.users.signUp({ email: "self-service-b@example.com", password: PASSWORD }));
    if (first.user === null || first.session === null || second.user === null) throw new Error("expected self-service users");

    const legacyUpdate = service.users as unknown as { updateUser: (subject: unknown, patch: unknown) => Promise<{ data: unknown; error: unknown }> };
    const crossUser = await legacyUpdate.updateUser(second.user.id, { user_metadata: { crossed: true } });
    expect(crossUser.data).toBeNull();
    expect((await service.repository.users.findById(second.user.id))?.user_metadata).not.toHaveProperty("crossed");

    const missingProof = await (service.users as unknown as { updateUser: (subject: unknown, patch: unknown) => Promise<unknown> }).updateUser({}, { user_metadata: { changed: true } });
    expect(missingProof).toMatchObject({ data: null });
    const forgedTarget = await (service.users as unknown as { updateUser: (subject: unknown, patch: unknown) => Promise<unknown> }).updateUser(
      { session: first.session, userId: second.user.id },
      { user_metadata: { forged: true } },
    );
    expect(forgedTarget).toMatchObject({ error: null });
    expect((await service.repository.users.findById(first.user.id))?.user_metadata).toHaveProperty("forged", true);
    expect((await service.repository.users.findById(second.user.id))?.user_metadata).not.toHaveProperty("forged");

    const appMetadata = await legacyUpdate.updateUser(first.user.id, { app_metadata: { admin: true } });
    expect(appMetadata.data).toBeNull();
    expect((await service.repository.users.findById(first.user.id))?.app_metadata).toEqual({});

    await service.sessions.signOut(first.session, "local");
    const revoked = await (service.users as unknown as { updateUser: (subject: unknown, patch: unknown) => Promise<unknown> }).updateUser({ session: first.session }, { user_metadata: { revoked: true } });
    expect(revoked).toMatchObject({ data: null });

    await service.repository.users.update(second.user.id, { banned_until: new Date(serviceNow.getTime() + 60 * 60 * 1000) });
    const banned = await (service.users as unknown as { updateUser: (subject: unknown, patch: unknown) => Promise<unknown> }).updateUser({ session: second.session }, { user_metadata: { banned: true } });
    expect(banned).toMatchObject({ data: null });
    const bannedTarget = await legacyUpdate.updateUser(second.user.id, { user_metadata: { legacy_bypass: true } });
    expect(bannedTarget.data).toBeNull();

    await service.repository.users.softDelete(first.user.id, serviceNow);
    const deletedTarget = await legacyUpdate.updateUser(first.user.id, { user_metadata: { deleted: true } });
    expect(deletedTarget.data).toBeNull();
  });

  it("requires current-password proof for password changes and keeps recovery reset separate", async () => {
    const service = services({ requireEmailConfirmation: false, concealUserExistence: false });
    const created = data(await service.users.signUp({ email: "password-bound@example.com", password: PASSWORD }));
    if (created.user === null || created.session === null) throw new Error("expected password-bound user");

    const legacyChangePassword = service.users as unknown as { changePassword: (subject: unknown, password: string) => Promise<{ data: unknown; error: unknown }> };
    const arbitrary = await legacyChangePassword.changePassword(created.user.id, "new password for self service");
    expect(arbitrary.data).toBeNull();
    expect((await service.users.signIn({ email: created.user.email ?? "", password: PASSWORD })).error).toBeNull();

    const missingCurrent = await (service.users as unknown as { changePassword: (subject: unknown, password: string) => Promise<unknown> }).changePassword({ session: created.session }, "new password for self service");
    expect(missingCurrent).toMatchObject({ data: null });
    const wrongCurrent = await (service.users as unknown as { changePassword: (subject: unknown, password: string, options: unknown) => Promise<unknown> }).changePassword(
      { session: created.session },
      "new password for self service",
      { currentPassword: "not the current password" },
    );
    expect(wrongCurrent).toMatchObject({ data: null });

    const changed = await (service.users as unknown as { changePassword: (subject: unknown, password: string, options: unknown) => Promise<unknown> }).changePassword(
      { session: created.session },
      "new password for self service",
      { currentPassword: PASSWORD },
    );
    expect(changed).toMatchObject({ error: null });
    expect((await service.users.signIn({ email: created.user.email ?? "", password: PASSWORD })).data).toBeNull();
    expect((await service.users.signIn({ email: created.user.email ?? "", password: "new password for self service" })).error).toBeNull();
  });

  it("does not activate an email change until its exact proof is consumed", async () => {
    const service = services({ requireEmailConfirmation: false, concealUserExistence: false });
    const created = data(await service.users.signUp({ email: "email-change-old@example.com", password: PASSWORD }));
    if (created.user === null || created.session === null) throw new Error("expected email-change user");
    const target = "email-change-new@example.com";

    const requested = await (service.users as unknown as { updateUser: (subject: unknown, patch: unknown) => Promise<unknown> }).updateUser(
      { session: created.session },
      { email: target, redirectTo: CALLBACK },
    );
    expect(requested).toMatchObject({ error: null });
    expect((await service.repository.users.findById(created.user.id))?.email).toBe("email-change-old@example.com");
    expect((await service.users.signIn({ email: target, password: PASSWORD })).data).toBeNull();
    expect((await service.users.signIn({ email: "email-change-old@example.com", password: PASSWORD })).error).toBeNull();

    const message = service.mailer.latest("confirmation");
    const wrongConsumer = await service.users.confirmEmail({ email: target, token: message?.variables.token ?? "", redirectTo: CALLBACK });
    expect(wrongConsumer.data).toBeNull();
    const confirmed = await (service.users as unknown as { confirmEmailChange: (input: unknown) => Promise<unknown> }).confirmEmailChange({
      email: target,
      token: message?.variables.token ?? "",
      redirectTo: CALLBACK,
    });
    expect(confirmed).toMatchObject({ error: null });
    expect((await service.repository.users.findById(created.user.id))?.email).toBe(target);
    const replay = await (service.users as unknown as { confirmEmailChange: (input: unknown) => Promise<unknown> }).confirmEmailChange({
      email: target,
      token: message?.variables.token ?? "",
      redirectTo: CALLBACK,
    });
    expect(replay).toMatchObject({ data: null });
    expect((await service.users.signIn({ email: target, password: PASSWORD })).error).toBeNull();
    expect((await service.sessions.refresh(created.session.refresh_token)).data).toBeNull();
  });

  it("does not partially apply a duplicate email change", async () => {
    const service = services({ requireEmailConfirmation: false, concealUserExistence: false });
    const first = data(await service.users.signUp({ email: "email-change-duplicate-a@example.com", password: PASSWORD }));
    const second = data(await service.users.signUp({ email: "email-change-duplicate-b@example.com", password: PASSWORD }));
    if (first.user === null || first.session === null || second.user === null) throw new Error("expected duplicate email-change users");
    const requested = await (service.users as unknown as { updateUser: (subject: unknown, patch: unknown) => Promise<unknown> }).updateUser(
      { session: first.session },
      { email: second.user.email, redirectTo: CALLBACK },
    );
    expect(requested).toMatchObject({ error: null });
    const message = service.mailer.latest("confirmation");
    const consumed = await (service.users as unknown as { confirmEmailChange: (input: unknown) => Promise<unknown> }).confirmEmailChange({
      email: second.user.email,
      token: message?.variables.token ?? "",
      redirectTo: CALLBACK,
    });
    expect(consumed).toMatchObject({ data: null });
    expect((await service.repository.users.findById(first.user.id))?.email).toBe("email-change-duplicate-a@example.com");
    const retry = await (service.users as unknown as { confirmEmailChange: (input: unknown) => Promise<unknown> }).confirmEmailChange({
      email: second.user.email,
      token: message?.variables.token ?? "",
      redirectTo: CALLBACK,
    });
    expect(retry).toMatchObject({ error: { code: "conflict" } });
  });

  it("rolls back email-change proof, email, and sessions when the atomic consumer fails", async () => {
    for (const failure of ["repository", "audit"] as const) {
      const service = services({ requireEmailConfirmation: false, concealUserExistence: false });
      const created = data(await service.users.signUp({ email: `email-change-failure-${failure}@example.com`, password: PASSWORD }));
      if (created.user === null || created.session === null) throw new Error("expected email-change failure user");
      const target = `email-change-failure-target-${failure}@example.com`;
      const requested = await (service.users as unknown as { updateUser: (subject: unknown, patch: unknown) => Promise<unknown> }).updateUser(
        { session: created.session },
        { email: target, redirectTo: CALLBACK },
      );
      expect(requested).toMatchObject({ error: null });
      const message = service.mailer.latest("confirmation");
      const failing = services({
        requireEmailConfirmation: false,
        concealUserExistence: false,
        repository: transactionFailureRepository(service.repository, failure),
      });
      const failed = await (failing.users as unknown as { confirmEmailChange: (input: unknown) => Promise<unknown> }).confirmEmailChange({
        email: target,
        token: message?.variables.token ?? "",
        redirectTo: CALLBACK,
      });
      expect(failed).toMatchObject({ data: null, error: { code: "internal_error" } });
      expect((await service.repository.users.findById(created.user.id))?.email).toBe(`email-change-failure-${failure}@example.com`);
      const tokenRow = await disposable?.pool.query(
        "SELECT consumed_at FROM auth.one_time_tokens WHERE target = $1 AND purpose = 'email_change' ORDER BY created_at DESC LIMIT 1",
        [target],
      );
      expect(tokenRow?.rows[0]?.consumed_at).toBeNull();
      const sessionRows = await disposable?.pool.query(
        "SELECT revoked_at FROM auth.sessions WHERE user_id = $1",
        [created.user.id],
      );
      expect(sessionRows?.rows.every((row) => row.revoked_at === null)).toBe(true);
    }
  });

  it("does not consume an email-change proof for a banned or deleted owner", async () => {
    for (const state of ["banned", "deleted"] as const) {
      const service = services({ requireEmailConfirmation: false, concealUserExistence: false });
      const oldEmail = `email-change-blocked-${state}@example.com`;
      const target = `email-change-blocked-target-${state}@example.com`;
      const created = data(await service.users.signUp({ email: oldEmail, password: PASSWORD }));
      if (created.user === null || created.session === null) throw new Error("expected blocked email-change user");
      await (service.users as unknown as { updateUser: (subject: unknown, patch: unknown) => Promise<unknown> }).updateUser(
        { session: created.session },
        { email: target, redirectTo: CALLBACK },
      );
      const message = service.mailer.latest("confirmation");
      if (state === "banned") {
        await service.repository.users.update(created.user.id, { banned_until: new Date(serviceNow.getTime() + 60 * 60 * 1000) });
      } else {
        await service.repository.users.softDelete(created.user.id, serviceNow);
      }
      const blocked = await (service.users as unknown as { confirmEmailChange: (input: unknown) => Promise<unknown> }).confirmEmailChange({
        email: target,
        token: message?.variables.token ?? "",
        redirectTo: CALLBACK,
      });
      expect(blocked).toMatchObject({ data: null, error: { code: state === "banned" ? "invalid_credentials" : "invalid_token" } });
      const ownerRow = await disposable?.pool.query("SELECT email FROM auth.users WHERE id = $1", [created.user.id]);
      expect(ownerRow?.rows[0]?.email).toBe(state === "deleted" ? oldEmail : oldEmail);
      const tokenRow = await disposable?.pool.query(
        "SELECT consumed_at FROM auth.one_time_tokens WHERE target = $1 AND purpose = 'email_change' ORDER BY created_at DESC LIMIT 1",
        [target],
      );
      expect(tokenRow?.rows[0]?.consumed_at).toBeNull();
      const sessionRows = await disposable?.pool.query("SELECT revoked_at FROM auth.sessions WHERE user_id = $1", [created.user.id]);
      expect(sessionRows?.rows.every((row) => row.revoked_at === null)).toBe(true);
    }
  });

  it("allows only one concurrent proof to commit an email change and revoke sessions", async () => {
    const service = services({ requireEmailConfirmation: false, concealUserExistence: false });
    const created = data(await service.users.signUp({ email: "email-change-concurrent@example.com", password: PASSWORD }));
    if (created.user === null || created.session === null) throw new Error("expected concurrent email-change user");
    const target = "email-change-concurrent-target@example.com";
    await (service.users as unknown as { updateUser: (subject: unknown, patch: unknown) => Promise<unknown> }).updateUser(
      { session: created.session },
      { email: target, redirectTo: CALLBACK },
    );
    const message = service.mailer.latest("confirmation");
    const input = { email: target, token: message?.variables.token ?? "", redirectTo: CALLBACK };
    const results = await Promise.all([
      (service.users as unknown as { confirmEmailChange: (value: unknown) => Promise<unknown> }).confirmEmailChange(input),
      (service.users as unknown as { confirmEmailChange: (value: unknown) => Promise<unknown> }).confirmEmailChange(input),
    ]);
    expect(results.filter((result) => (result as { readonly error: unknown }).error === null)).toHaveLength(1);
    expect(results.filter((result) => (result as { readonly data: unknown }).data === null)).toHaveLength(1);
    expect((await service.repository.users.findById(created.user.id))?.email).toBe(target);
    const sessionRows = await disposable?.pool.query("SELECT revoked_at FROM auth.sessions WHERE user_id = $1", [created.user.id]);
    expect(sessionRows?.rows.every((row) => row.revoked_at !== null)).toBe(true);
  });

  it("resolves concurrent normalized-email target races with one committed proof", async () => {
    const setup = services({ requireEmailConfirmation: false, concealUserExistence: false });
    const first = data(await setup.users.signUp({ email: "email-change-race-a@example.com", password: PASSWORD }));
    const second = data(await setup.users.signUp({ email: "email-change-race-b@example.com", password: PASSWORD }));
    if (first.user === null || first.session === null || second.user === null || second.session === null) {
      throw new Error("expected target-race users");
    }
    const target = "email-change-race-target@example.com";
    await (setup.users as unknown as { updateUser: (subject: unknown, patch: unknown) => Promise<unknown> }).updateUser(
      { session: first.session },
      { email: target, redirectTo: CALLBACK },
    );
    const firstMessage = setup.mailer.latest("confirmation");
    await (setup.users as unknown as { updateUser: (subject: unknown, patch: unknown) => Promise<unknown> }).updateUser(
      { session: second.session },
      { email: target, redirectTo: CALLBACK },
    );
    const secondMessage = setup.mailer.latest("confirmation");
    const barrier = targetPrecheckBarrier(2, 10_000);
    const raced = services({
      requireEmailConfirmation: false,
      concealUserExistence: false,
      repository: targetPrecheckBarrierRepository(setup.repository, target, barrier),
    });
    const inputs = [
      {
        email: target,
        token: firstMessage?.variables.token ?? "",
        redirectTo: CALLBACK,
      },
      {
        email: target,
        token: secondMessage?.variables.token ?? "",
        redirectTo: CALLBACK,
      },
    ];
    let results: unknown[];
    try {
      results = await Promise.all(inputs.map((input) =>
        (raced.users as unknown as { confirmEmailChange: (value: unknown) => Promise<unknown> }).confirmEmailChange(input)));
    } finally {
      barrier.release();
    }
    expect(barrier.arrivals()).toBe(2);
    expect(results).toHaveLength(2);
    expect(results.filter((result) => (result as { readonly error: unknown }).error === null)).toHaveLength(1);
    expect(results.filter((result) => (result as { readonly error: { readonly code?: string } | null }).error?.code === "internal_error")).toHaveLength(1);
    const owners = await disposable?.pool.query("SELECT email FROM auth.users WHERE id IN ($1, $2) ORDER BY email", [first.user.id, second.user.id]);
    expect(owners?.rows.filter((row) => row.email === target)).toHaveLength(1);
    const tokenRows = await disposable?.pool.query(
      "SELECT consumed_at FROM auth.one_time_tokens WHERE target = $1 AND purpose = 'email_change' ORDER BY created_at",
      [target],
    );
    expect(tokenRows?.rows.filter((row) => row.consumed_at !== null)).toHaveLength(1);
    expect(tokenRows?.rows.filter((row) => row.consumed_at === null)).toHaveLength(1);
    const winnerIndex = results.findIndex((result) => (result as { readonly error: unknown }).error === null);
    const loserIndex = winnerIndex === 0 ? 1 : 0;
    const retry = await (raced.users as unknown as { confirmEmailChange: (value: unknown) => Promise<unknown> }).confirmEmailChange(inputs[loserIndex]);
    expect(retry).toMatchObject({ data: null, error: { code: "conflict", status: 409 } });
    const tokenRowsAfterRetry = await disposable?.pool.query(
      "SELECT consumed_at FROM auth.one_time_tokens WHERE target = $1 AND purpose = 'email_change' ORDER BY created_at",
      [target],
    );
    expect(tokenRowsAfterRetry?.rows.filter((row) => row.consumed_at !== null)).toHaveLength(1);
    expect(tokenRowsAfterRetry?.rows.filter((row) => row.consumed_at === null)).toHaveLength(1);
  });

  it("fails closed for banned session creation and refresh", async () => {
    const service = services({ requireEmailConfirmation: false, concealUserExistence: false });
    const created = data(await service.users.signUp({ email: "session-ban@example.com", password: PASSWORD }));
    if (created.user === null || created.session === null) throw new Error("expected session-ban user");
    await service.repository.users.update(created.user.id, { banned_until: new Date(serviceNow.getTime() + 60 * 60 * 1000) });

    const createAfterBan = await service.sessions.create(created.user);
    expect(createAfterBan.data).toBeNull();
    const refreshAfterBan = await service.sessions.refresh(created.session.refresh_token);
    expect(refreshAfterBan.data).toBeNull();
    expect(refreshAfterBan.error?.code).not.toBe("refresh_token_reused");
    const refreshRows = await disposable?.pool.query(
      "SELECT rt.used_at, rt.revoked_at FROM auth.refresh_tokens rt JOIN auth.sessions s ON s.id = rt.session_id WHERE s.user_id = $1",
      [created.user.id],
    );
    expect(refreshRows?.rows.every((row) => row.used_at === null && row.revoked_at === null)).toBe(true);
  });

  it("fails closed when a committed ban wins races with session creation and refresh", async () => {
    if (disposable === undefined) throw new Error("expected disposable PostgreSQL");
    const banRepository = createPostgresAdapter({ pool: disposable.pool });

    const createService = services({ requireEmailConfirmation: false, concealUserExistence: false });
    const createFixture = data(await createService.users.signUp({ email: "session-create-ban-race@example.com", password: PASSWORD }));
    if (createFixture.user === null) throw new Error("expected session-create race user");
    const createOriginalTransaction = createService.repository.transaction.bind(createService.repository);
    let createEnteredResolve: (() => void) | undefined;
    const createEntered = new Promise<void>((resolve) => { createEnteredResolve = resolve; });
    let createReleaseResolve: (() => void) | undefined;
    const createRelease = new Promise<void>((resolve) => { createReleaseResolve = resolve; });
    (createService.repository as unknown as { transaction: typeof createService.repository.transaction }).transaction = async (callback) =>
      createOriginalTransaction(async (transaction) => {
        createEnteredResolve?.();
        await createRelease;
        return callback(transaction);
      });
    try {
      const createAttempt = createService.sessions.create(createFixture.user);
      await createEntered;
      await banRepository.users.update(createFixture.user.id, { banned_until: new Date(serviceNow.getTime() + 60 * 60 * 1000) });
      createReleaseResolve?.();
      expect((await createAttempt).data).toBeNull();
      const createdSessionRows = await disposable.pool.query("SELECT id FROM auth.sessions WHERE user_id = $1", [createFixture.user.id]);
      expect(createdSessionRows.rows).toHaveLength(1);
    } finally {
      createReleaseResolve?.();
      (createService.repository as unknown as { transaction: typeof createService.repository.transaction }).transaction = createOriginalTransaction;
    }

    const refreshService = services({ requireEmailConfirmation: false, concealUserExistence: false });
    const refreshFixture = data(await refreshService.users.signUp({ email: "session-refresh-ban-race@example.com", password: PASSWORD }));
    if (refreshFixture.user === null || refreshFixture.session === null) throw new Error("expected session-refresh race user");
    const refreshOriginalTransaction = refreshService.repository.transaction.bind(refreshService.repository);
    let refreshEnteredResolve: (() => void) | undefined;
    const refreshEntered = new Promise<void>((resolve) => { refreshEnteredResolve = resolve; });
    let refreshReleaseResolve: (() => void) | undefined;
    const refreshRelease = new Promise<void>((resolve) => { refreshReleaseResolve = resolve; });
    (refreshService.repository as unknown as { transaction: typeof refreshService.repository.transaction }).transaction = async (callback) =>
      refreshOriginalTransaction(async (transaction) => {
        refreshEnteredResolve?.();
        await refreshRelease;
        return callback(transaction);
      });
    try {
      const refreshAttempt = refreshService.sessions.refresh(refreshFixture.session.refresh_token);
      await refreshEntered;
      await banRepository.users.update(refreshFixture.user.id, { banned_until: new Date(serviceNow.getTime() + 60 * 60 * 1000) });
      refreshReleaseResolve?.();
      expect((await refreshAttempt).data).toBeNull();
      const refreshRows = await disposable.pool.query(
        "SELECT rt.used_at, rt.revoked_at FROM auth.refresh_tokens rt JOIN auth.sessions s ON s.id = rt.session_id WHERE s.user_id = $1",
        [refreshFixture.user.id],
      );
      expect(refreshRows.rows).toHaveLength(1);
      expect(refreshRows.rows[0]?.used_at).toBeNull();
      expect(refreshRows.rows[0]?.revoked_at).toBeNull();
    } finally {
      refreshReleaseResolve?.();
      (refreshService.repository as unknown as { transaction: typeof refreshService.repository.transaction }).transaction = refreshOriginalTransaction;
      await banRepository.close();
    }
  });

  it("contains refresh replay durably when the owner is banned or soft-deleted", async () => {
    for (const state of ["banned", "deleted"] as const) {
      const service = services({ requireEmailConfirmation: false, concealUserExistence: false });
      const created = data(await service.users.signUp({ email: `refresh-replay-${state}@example.com`, password: PASSWORD }));
      if (created.user === null || created.session === null) throw new Error("expected refresh replay user");
      const rotated = data(await service.sessions.refresh(created.session.refresh_token));
      if (state === "banned") {
        await service.repository.users.update(created.user.id, { banned_until: new Date(serviceNow.getTime() + 60 * 60 * 1000) });
      } else {
        await service.repository.users.softDelete(created.user.id, serviceNow);
      }

      const replay = await service.sessions.refresh(created.session.refresh_token);
      expect(replay.data).toBeNull();
      expect(replay.error?.code).toBe("refresh_token_reused");
      const rows = await disposable?.pool.query(
        "SELECT s.revoked_at AS session_revoked_at, rt.revoked_at, rt.used_at FROM auth.sessions s JOIN auth.refresh_tokens rt ON rt.session_id = s.id WHERE s.user_id = $1",
        [created.user.id],
      );
      expect(rows?.rows.length).toBeGreaterThan(1);
      expect(rows?.rows.every((row) => row.session_revoked_at !== null && row.revoked_at !== null)).toBe(true);
      const replacementReplay = await service.sessions.refresh(rotated.refresh_token);
      expect(replacementReplay.data).toBeNull();
    }
  });

  it("cannot issue an old-password session after a real recovery reset commits first", async () => {
    const service = services({ requireEmailConfirmation: false, concealUserExistence: false });
    const created = data(await service.users.signUp({ email: "reset-race@example.com", password: PASSWORD }));
    if (created.user === null) throw new Error("expected reset-race user");
    const recoveryRequest = await service.users.resetPasswordForEmail(created.user.email ?? "", { redirectTo: CALLBACK });
    expect(recoveryRequest.error).toBeNull();
    const recoveryMessage = service.mailer.latest("recovery");
    if (disposable === undefined) throw new Error("expected disposable PostgreSQL");
    const alternateRepository = createPostgresAdapter({ pool: disposable.pool });
    const resetService = services({
      requireEmailConfirmation: false,
      concealUserExistence: false,
      repository: alternateRepository,
    });

    const originalTransaction = service.repository.transaction.bind(service.repository);
    let enteredResolve: (() => void) | undefined;
    const entered = new Promise<void>((resolve) => { enteredResolve = resolve; });
    let releaseResolve: (() => void) | undefined;
    const release = new Promise<void>((resolve) => { releaseResolve = resolve; });
    (service.repository as unknown as { transaction: typeof service.repository.transaction }).transaction = async (callback) =>
      originalTransaction(async (transaction) => {
        enteredResolve?.();
        await release;
        return callback(transaction);
      });

    try {
      const oldPasswordSignIn = service.users.signIn({ email: created.user.email ?? "", password: PASSWORD });
      await entered;
      const reset = await resetService.users.resetPassword({
        email: created.user.email ?? "",
        token: recoveryMessage?.variables.token ?? "",
        password: "reset-race-new-password",
        redirectTo: CALLBACK,
      });
      expect(reset.error).toBeNull();
      releaseResolve?.();
      const stale = await oldPasswordSignIn;
      expect(stale.data).toBeNull();
      expect(stale.error?.code).toBe("invalid_credentials");
    } finally {
      releaseResolve?.();
      (service.repository as unknown as { transaction: typeof service.repository.transaction }).transaction = originalTransaction;
      await alternateRepository.close();
    }
  });
});
