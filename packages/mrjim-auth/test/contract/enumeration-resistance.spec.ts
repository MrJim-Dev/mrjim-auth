import { describe, expect, it } from "vitest";
import { EmailService } from "../../src/server/email.js";
import { FakeMailer } from "../../src/testing/fake-mailer.js";
import { OneTimeTokenService } from "../../src/server/one-time-tokens.js";
import { PasswordService } from "../../src/server/passwords.js";
import { UserService } from "../../src/server/users.js";
import type { AuthRepository, Mailer, RateLimiter } from "../../src/shared/contracts.js";
import { AuthApiError } from "../../src/shared/errors.js";
import { uuidSchema, roleKeySchema } from "../../src/shared/types.js";

const CALLBACK = "https://project.example.com/auth/callback";
const REJECTED_CALLBACK = "https://attacker.example.com/callback";
const KEY = Uint8Array.from({ length: 32 }, (_, index) => index + 11);
const SECRET_EMAIL = "existing@example.com";
const SECRET_TOKEN = "raw-adapter-token-6f4e";
const SECRET_CODE = "raw-otp-code-918273";
const SECRET_PROVIDER = "provider-secret-4d2c";

const MALICIOUS_ADAPTER_ERRORS: readonly unknown[] = [
  new AuthApiError("invalid_request", 400, `adapter ${SECRET_EMAIL} token=${SECRET_TOKEN} code=${SECRET_CODE} provider=${SECRET_PROVIDER}`),
  new Error(`adapter ${SECRET_EMAIL} token=${SECRET_TOKEN} code=${SECRET_CODE} provider=${SECRET_PROVIDER}`),
  `adapter ${SECRET_EMAIL} token=${SECRET_TOKEN} code=${SECRET_CODE} provider=${SECRET_PROVIDER}`,
  {
    code: "internal_error",
    message: `adapter ${SECRET_EMAIL} token=${SECRET_TOKEN} code=${SECRET_CODE} provider=${SECRET_PROVIDER}`,
    details: { email: SECRET_EMAIL, token: SECRET_TOKEN, code: SECRET_CODE, provider: SECRET_PROVIDER },
    stack: `Error: ${SECRET_EMAIL} ${SECRET_TOKEN} ${SECRET_CODE} ${SECRET_PROVIDER}`,
  },
];

interface ServiceOptions {
  readonly mailer?: Mailer;
  readonly issueError?: unknown;
  readonly auditError?: unknown;
  readonly lookupError?: unknown;
  readonly observerError?: unknown;
  readonly auditEvents?: unknown[];
  readonly observerEvents?: unknown[];
  readonly onOperationalFailure?: (event: unknown) => void | Promise<void>;
}

function limiter(): RateLimiter {
  return { consume: async () => ({ allowed: true, remaining: 99 }) };
}

function service(existingEmail?: string, suppliedLimiter?: RateLimiter, options: ServiceOptions = {}) {
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
    issue: async () => {
      if (options.issueError !== undefined) throw options.issueError;
      return undefined;
    },
    consume: async () => null,
    consumeBound: async () => null,
    recordFailure: async () => null,
  };
  const repository = {
    transaction: async (callback: (value: AuthRepository) => Promise<unknown>) => callback(repository as unknown as AuthRepository),
    users: {
      findByNormalizedEmail: async (email: string) => {
        if (options.lookupError !== undefined) throw options.lookupError;
        return existingEmail !== undefined && email === existingEmail ? existingUser : null;
      },
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
    operations: {
      appendAudit: async (event: unknown) => {
        options.auditEvents?.push(event);
        if (options.auditError !== undefined) throw options.auditError;
      },
      findApiKeyByHash: async () => null,
    },
  } as unknown as AuthRepository;
  const mailer: Mailer = options.mailer ?? new FakeMailer();
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
    ...((options.onOperationalFailure === undefined && options.observerError === undefined && options.observerEvents === undefined)
      ? {}
      : {
          onOperationalFailure: async (event: unknown) => {
            options.observerEvents?.push(event);
            if (options.observerError !== undefined) throw options.observerError;
            await options.onOperationalFailure?.(event);
          },
        }),
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

  it("conceals mailer, audit, and repository issuance failures for recovery", async () => {
    const failures: Array<{ readonly label: string; readonly options: ServiceOptions }> = [
      { label: "mailer", options: { mailer: { send: async () => { throw new Error("delivery secret existing@example.com"); } } } },
      { label: "audit", options: { auditError: new Error("audit secret existing@example.com") } },
      { label: "repository", options: { issueError: new Error("repository secret existing@example.com") } },
    ];

    for (const failure of failures) {
      const existing = await service("existing@example.com", undefined, failure.options)
        .resetPasswordForEmail("existing@example.com", { redirectTo: CALLBACK });
      const missing = await service("existing@example.com")
        .resetPasswordForEmail("missing@example.com", { redirectTo: CALLBACK });
      expect(existing, failure.label).toEqual(missing);
    }
  });

  it.each([
    ["mailer", (error: unknown, auditEvents: unknown[], observerEvents: unknown[]): ServiceOptions => ({
      mailer: { send: async () => { throw error; } },
      auditEvents,
      observerEvents,
    })],
    ["repository", (error: unknown, auditEvents: unknown[], observerEvents: unknown[]): ServiceOptions => ({
      issueError: error,
      auditEvents,
      observerEvents,
    })],
    ["audit", (error: unknown, auditEvents: unknown[], observerEvents: unknown[]): ServiceOptions => ({
      auditError: error,
      auditEvents,
      observerEvents,
    })],
    ["account lookup", (error: unknown, auditEvents: unknown[], observerEvents: unknown[]): ServiceOptions => ({
      lookupError: error,
      auditEvents,
      observerEvents,
    })],
  ] as const)("sanitizes malicious %s failures before concealed recovery results and observability", async (_label, optionsForFailure) => {
    for (const adapterError of MALICIOUS_ADAPTER_ERRORS) {
      const auditEvents: unknown[] = [];
      const observerEvents: unknown[] = [];
      const existing = await service(SECRET_EMAIL, undefined, optionsForFailure(adapterError, auditEvents, observerEvents))
        .resetPasswordForEmail(SECRET_EMAIL, { redirectTo: CALLBACK }, {
          ip_address: " 2001:DB8::1 ",
          user_agent: "browser secret",
        });
      const missing = await service(SECRET_EMAIL)
        .resetPasswordForEmail("missing@example.com", { redirectTo: CALLBACK });

      expect(existing).toEqual(missing);
      expect(existing).toEqual({ data: { sent: true }, error: null });
      expect(observerEvents).toHaveLength(1);
      expect(observerEvents[0]).toMatchObject({
        action: "recovery",
        template: "recovery",
        outcome: "failure",
        error_class: "adapter_error",
        request: { ip_address: "2001:db8::1", user_agent: expect.stringMatching(/^ua-sha256:/u) },
      });
      const captured = JSON.stringify({ existing, missing, auditEvents, observerEvents });
      expect(captured).not.toContain(SECRET_EMAIL);
      expect(captured).not.toContain(SECRET_TOKEN);
      expect(captured).not.toContain(SECRET_CODE);
      expect(captured).not.toContain(SECRET_PROVIDER);
    }
  });

  it("keeps observer failures sanitized and non-recursive", async () => {
    const observerEvents: unknown[] = [];
    const existing = await service(SECRET_EMAIL, undefined, {
      mailer: { send: async () => { throw new Error("delivery failure"); } },
      observerError: MALICIOUS_ADAPTER_ERRORS[0],
      observerEvents,
    }).resetPasswordForEmail(SECRET_EMAIL, { redirectTo: CALLBACK });
    const missing = await service(SECRET_EMAIL)
      .resetPasswordForEmail("missing@example.com", { redirectTo: CALLBACK });

    expect(existing).toEqual(missing);
    expect(existing).toEqual({ data: { sent: true }, error: null });
    expect(observerEvents).toHaveLength(1);
    expect(JSON.stringify(observerEvents)).not.toContain(SECRET_EMAIL);
    expect(JSON.stringify(observerEvents)).not.toContain(SECRET_TOKEN);
    expect(JSON.stringify(observerEvents)).not.toContain(SECRET_CODE);
    expect(JSON.stringify(observerEvents)).not.toContain(SECRET_PROVIDER);
  });

  it("preserves trusted redirect prevalidation while sanitizing adapter failures", async () => {
    const existing = await service(SECRET_EMAIL, undefined, {
      mailer: { send: async () => { throw MALICIOUS_ADAPTER_ERRORS[0]; } },
    }).resetPasswordForEmail(SECRET_EMAIL, { redirectTo: REJECTED_CALLBACK });
    const missing = await service(SECRET_EMAIL)
      .resetPasswordForEmail("missing@example.com", { redirectTo: REJECTED_CALLBACK });

    expect(existing).toEqual(missing);
    expect(existing.error).toMatchObject({
      code: "redirect_not_allowed",
      status: 400,
      message: "Redirect URL is not allowed",
    });
  });

  it("conceals OTP, resend, and duplicate-signup mailer failures", async () => {
    const failingMailer: Mailer = {
      send: async () => { throw new Error("delivery secret existing@example.com"); },
    };
    const otpExisting = await service("existing@example.com", undefined, { mailer: failingMailer })
      .signInWithOtp({ email: "existing@example.com", options: { type: "email_otp", redirectTo: CALLBACK } });
    const otpMissing = await service("existing@example.com")
      .signInWithOtp({ email: "missing@example.com", options: { type: "email_otp", redirectTo: CALLBACK } });
    expect(otpExisting).toEqual(otpMissing);

    const resendExisting = await service("existing@example.com", undefined, { mailer: failingMailer })
      .resend({ type: "recovery", email: "existing@example.com", options: { redirectTo: CALLBACK } });
    const resendMissing = await service("existing@example.com")
      .resend({ type: "recovery", email: "missing@example.com", options: { redirectTo: CALLBACK } });
    expect(resendExisting).toEqual(resendMissing);

    const duplicate = await service("existing@example.com", undefined, { mailer: failingMailer })
      .signUp({ email: "existing@example.com", password: "correct horse battery staple", options: { redirectTo: CALLBACK } });
    const firstTime = await service("existing@example.com", undefined, { mailer: failingMailer })
      .signUp({ email: "new@example.com", password: "correct horse battery staple", options: { redirectTo: CALLBACK } });
    expect(duplicate).toEqual(firstTime);
  });

  it("reports only redacted operational failure metadata while concealing the public result", async () => {
    const events: unknown[] = [];
    const result = await service("existing@example.com", undefined, {
      mailer: { send: async () => { throw new Error("raw existing@example.com token=secret-code"); } },
      onOperationalFailure: (event) => { events.push(event); },
    }).resetPasswordForEmail("existing@example.com", { redirectTo: CALLBACK }, {
      ip_address: " 2001:DB8::1 ",
      user_agent: "browser secret existing@example.com",
    });
    expect(result).toEqual({ data: { sent: true }, error: null });
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({
      action: "recovery",
      template: "recovery",
      outcome: "failure",
      error_class: expect.any(String),
      request: { ip_address: "2001:db8::1", user_agent: expect.stringMatching(/^ua-sha256:/u) },
    });
    expect(JSON.stringify(events)).not.toContain("existing@example.com");
    expect(JSON.stringify(events)).not.toContain("secret-code");
    expect(JSON.stringify(events)).not.toContain("browser secret");
  });

  it("consumes rate-limit slots before validating redirects for every concealed issuance path", async () => {
    const operations: Array<(current: ReturnType<typeof service>) => Promise<unknown>> = [
      (current) => current.signUp({ email: "existing@example.com", password: "correct horse battery staple", options: { redirectTo: REJECTED_CALLBACK } }),
      (current) => current.signInWithOtp({ email: "existing@example.com", options: { type: "email_otp", redirectTo: REJECTED_CALLBACK } }),
      (current) => current.resetPasswordForEmail("existing@example.com", { redirectTo: REJECTED_CALLBACK }),
      (current) => current.resend({ type: "recovery", email: "existing@example.com", options: { redirectTo: REJECTED_CALLBACK } }),
    ];

    for (const operation of operations) {
      const keys: string[] = [];
      const current = service("existing@example.com", {
        consume: async (key) => {
          keys.push(key);
          return { allowed: true, remaining: 99 };
        },
      });
      const result = await operation(current);
      expect(result).toMatchObject({ error: { code: "redirect_not_allowed" } });
      expect(keys).toEqual(["ip:unknown", "identifier:existing@example.com"]);
    }
  });

  it("consumes recovery verification rate-limit slots before invalid redirect validation", async () => {
    const keys: string[] = [];
    const current = service(SECRET_EMAIL, {
      consume: async (key) => {
        keys.push(key);
        return { allowed: true, remaining: 99 };
      },
    });

    const result = await current.resetPassword({
      email: SECRET_EMAIL,
      token: "not-a-valid-token",
      password: "correct horse battery staple",
      redirectTo: REJECTED_CALLBACK,
    }, { ip_address: " 2001:DB8::1 " });

    expect(result.error).toMatchObject({ code: "redirect_not_allowed" });
    expect(keys).toEqual(["ip:2001:db8::1", "identifier:existing@example.com"]);
  });
});
