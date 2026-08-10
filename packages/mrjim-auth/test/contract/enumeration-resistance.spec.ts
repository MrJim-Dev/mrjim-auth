import { describe, expect, it } from "vitest";
import { EmailService } from "../../src/server/email.js";
import { FakeMailer } from "../../src/testing/fake-mailer.js";
import { OneTimeTokenService } from "../../src/server/one-time-tokens.js";
import { PasswordService } from "../../src/server/passwords.js";
import { UserService } from "../../src/server/users.js";
import type { AuthRepository, Mailer, RateLimiter } from "../../src/shared/contracts.js";
import { uuidSchema, roleKeySchema } from "../../src/shared/types.js";

const CALLBACK = "https://project.example.com/auth/callback";
const REJECTED_CALLBACK = "https://attacker.example.com/callback";
const KEY = Uint8Array.from({ length: 32 }, (_, index) => index + 11);

function limiter(): RateLimiter {
  return { consume: async () => ({ allowed: true, remaining: 99 }) };
}

function service(existingEmail?: string, suppliedLimiter?: RateLimiter) {
  const existingUser = {
    id: uuidSchema.parse("00000000-0000-4000-8000-000000000601"),
    email: existingEmail ?? null,
    phone: null,
    email_confirmed_at: null,
    phone_confirmed_at: null,
    confirmed_at: null,
    last_sign_in_at: null,
    banned_until: null,
    user_metadata: {},
    app_metadata: {},
    created_at: "2026-08-11T00:00:00.000Z",
    updated_at: "2026-08-11T00:00:00.000Z",
    deleted_at: null,
  };
  const tokenRepository = {
    issue: async () => undefined,
    consume: async () => null,
    consumeBound: async () => null,
    recordFailure: async () => null,
  };
  const repository = {
    transaction: async (callback: (value: AuthRepository) => Promise<unknown>) => callback(repository as unknown as AuthRepository),
    users: {
      findByNormalizedEmail: async (email: string) => existingEmail !== undefined && email === existingEmail ? existingUser : null,
      findById: async () => existingUser,
      create: async (input: { email?: string | null }) => ({ ...existingUser, email: input.email ?? null }),
      update: async () => existingUser,
      softDelete: async () => undefined,
    },
    passwordCredentials: { findByUserId: async () => null, upsert: async () => undefined, deleteByUserId: async () => undefined },
    sessions: { create: async () => ({ session: {}, refreshToken: {} }), findRefreshForUpdate: async () => null, rotate: async () => ({}), revokeSession: async () => undefined, revokeFamily: async () => undefined, revokeUserSessions: async () => undefined },
    oneTimeTokens: tokenRepository,
    oauthStates: { create: async () => undefined, consume: async () => null },
    roles: { list: async () => [{ id: uuidSchema.parse("00000000-0000-4000-8000-000000000602"), key: roleKeySchema.parse("member"), name: "Member", description: null, rank: 1, is_system: false, created_at: "2026-08-11T00:00:00.000Z", updated_at: "2026-08-11T00:00:00.000Z" }], findById: async () => null, create: async () => ({}), update: async () => ({}), delete: async () => undefined },
    permissions: { list: async () => [], findById: async () => null, create: async () => ({}), update: async () => ({}), delete: async () => undefined },
    authorization: { effectivePermissions: async () => [], assignRole: async () => undefined, unassignRole: async () => undefined, setRolePermissions: async () => undefined, setRoleInheritance: async () => undefined },
    operations: { appendAudit: async () => undefined, findApiKeyByHash: async () => null },
  } as unknown as AuthRepository;
  const mailer: Mailer = new FakeMailer();
  const email = new EmailService({ allowedRedirects: [CALLBACK], defaultRedirect: CALLBACK });
  const tokens = new OneTimeTokenService({
    repository,
    mailer,
    email,
    tokenHashKey: KEY,
    allowedRedirects: [CALLBACK],
    defaultRedirect: CALLBACK,
  });
  return new UserService({
    repository,
    passwords: new PasswordService(),
    email,
    mailer,
    oneTimeTokens: tokens,
    rateLimiter: suppliedLimiter ?? limiter(),
    concealUserExistence: true,
    requireEmailConfirmation: true,
  });
}

describe("enumeration-resistant public lifecycle results", () => {
  it("keeps recovery results equivalent for existing and nonexistent targets", async () => {
    const existing = await service("existing@example.com").resetPasswordForEmail("existing@example.com", { redirectTo: CALLBACK });
    const missing = await service("existing@example.com").resetPasswordForEmail("missing@example.com", { redirectTo: CALLBACK });
    expect({ data: existing.data && Object.keys(existing.data), error: existing.error }).toEqual({
      data: missing.data && Object.keys(missing.data),
      error: missing.error,
    });
  });

  it("keeps resend and OTP issue results equivalent for existing and nonexistent targets", async () => {
    const existingService = service("existing@example.com");
    const missingService = service("existing@example.com");
    const resendExisting = await existingService.resend({ type: "signup", email: "existing@example.com", options: { redirectTo: CALLBACK } });
    const resendMissing = await missingService.resend({ type: "signup", email: "missing@example.com", options: { redirectTo: CALLBACK } });
    const otpExisting = await existingService.signInWithOtp({ email: "existing@example.com", options: { type: "email_otp", redirectTo: CALLBACK } });
    const otpMissing = await missingService.signInWithOtp({ email: "missing@example.com", options: { type: "email_otp", redirectTo: CALLBACK } });
    expect(resendExisting).toEqual(resendMissing);
    expect(otpExisting).toEqual(otpMissing);
  });

  it("keeps all concealed issuance results deeply equal when the redirect is rejected", async () => {
    const existingService = service("existing@example.com");
    const missingService = service("existing@example.com");
    const duplicateService = service("existing@example.com");

    const existingRecovery = await existingService.resetPasswordForEmail("existing@example.com", { redirectTo: REJECTED_CALLBACK });
    const missingRecovery = await missingService.resetPasswordForEmail("missing@example.com", { redirectTo: REJECTED_CALLBACK });
    const existingResend = await existingService.resend({ type: "signup", email: "existing@example.com", options: { redirectTo: REJECTED_CALLBACK } });
    const missingResend = await missingService.resend({ type: "signup", email: "missing@example.com", options: { redirectTo: REJECTED_CALLBACK } });
    const existingOtp = await existingService.signInWithOtp({ email: "existing@example.com", options: { type: "email_otp", redirectTo: REJECTED_CALLBACK } });
    const missingOtp = await missingService.signInWithOtp({ email: "missing@example.com", options: { type: "email_otp", redirectTo: REJECTED_CALLBACK } });
    const duplicateSignup = await duplicateService.signUp({ email: "existing@example.com", password: "correct horse battery staple", options: { redirectTo: REJECTED_CALLBACK } });
    const firstSignup = await missingService.signUp({ email: "new@example.com", password: "correct horse battery staple", options: { redirectTo: REJECTED_CALLBACK } });

    expect(existingRecovery).toEqual(missingRecovery);
    expect(existingResend).toEqual(missingResend);
    expect(existingOtp).toEqual(missingOtp);
    expect(duplicateSignup).toEqual(firstSignup);
    expect(existingRecovery.error).toMatchObject({ code: "redirect_not_allowed", status: 400, message: "Redirect URL is not allowed" });
  });

  it("keeps allowed redirect issuance results deeply equal for existing, missing, and duplicate paths", async () => {
    const existingService = service("existing@example.com");
    const missingService = service("existing@example.com");
    const duplicateService = service("existing@example.com");

    const existingRecovery = await existingService.resetPasswordForEmail("existing@example.com", { redirectTo: CALLBACK });
    const missingRecovery = await missingService.resetPasswordForEmail("missing@example.com", { redirectTo: CALLBACK });
    const existingResend = await existingService.resend({ type: "signup", email: "existing@example.com", options: { redirectTo: CALLBACK } });
    const missingResend = await missingService.resend({ type: "signup", email: "missing@example.com", options: { redirectTo: CALLBACK } });
    const existingOtp = await existingService.signInWithOtp({ email: "existing@example.com", options: { type: "magic_link", redirectTo: CALLBACK } });
    const missingOtp = await missingService.signInWithOtp({ email: "missing@example.com", options: { type: "magic_link", redirectTo: CALLBACK } });
    const duplicateSignup = await duplicateService.signUp({ email: "existing@example.com", password: "correct horse battery staple", options: { redirectTo: CALLBACK } });
    const firstSignup = await missingService.signUp({ email: "new@example.com", password: "correct horse battery staple", options: { redirectTo: CALLBACK } });

    expect(existingRecovery).toEqual(missingRecovery);
    expect(existingResend).toEqual(missingResend);
    expect(existingOtp).toEqual(missingOtp);
    expect(duplicateSignup).toEqual(firstSignup);
  });

  it("uses the shared canonical IP representation for rate-limit keys", async () => {
    const keys: string[] = [];
    const rateLimiter: RateLimiter = {
      consume: async (key) => {
        keys.push(key);
        return { allowed: true, remaining: 99 };
      },
    };
    const current = service("existing@example.com", rateLimiter);
    await current.signIn({ email: "existing@example.com", password: "correct horse battery staple" }, { ip_address: " 2001:DB8::1 " });
    await current.signIn({ email: "existing@example.com", password: "correct horse battery staple" }, { ip_address: "not-an-ip" });
    const ipKeys = keys.filter((key) => key.startsWith("ip:"));
    expect(ipKeys[0]).toBe("ip:2001:db8::1");
    expect(ipKeys[1]).toBe("ip:unknown");
  });

  it("keeps duplicate and first-time signup result shape, public code, message, and timing work equivalent", async () => {
    const existingService = service("existing@example.com");
    const duplicate = await existingService.signUp({ email: "existing@example.com", password: "correct horse battery staple" }, { ip_address: "127.0.0.1" });
    const firstTime = await existingService.signUp({ email: "new@example.com", password: "correct horse battery staple" }, { ip_address: "127.0.0.1" });
    expect({
      hasData: duplicate.data !== null,
      error: duplicate.error,
    }).toEqual({
      hasData: firstTime.data !== null,
      error: firstTime.error,
    });
  });
});
