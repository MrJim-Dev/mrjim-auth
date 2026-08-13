import { describe, expect, it } from "vitest";
import { EmailService } from "../../src/server/email.js";
import {
  adapterCall,
  adapterTransaction,
  isAdapterBoundaryFailure,
  trustedFailure,
} from "../../src/server/adapter-boundary.js";
import { FakeMailer } from "../../src/testing/fake-mailer.js";
import { OneTimeTokenService } from "../../src/server/one-time-tokens.js";
import { PasswordService } from "../../src/server/passwords.js";
import { UserService } from "../../src/server/users.js";
import type { AuthRepository, Mailer, RateLimiter } from "../../src/shared/contracts.js";
import { AuthApiError } from "../../src/shared/errors.js";
import { PostgresRepositoryError } from "../../src/postgres/repositories/errors.js";
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
  readonly defaultRoleKeys?: readonly string[];
  readonly transactionError?: unknown;
  readonly transactionFailureTransform?: (error: unknown) => unknown;
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
    transaction: async (callback: (value: AuthRepository) => Promise<unknown>) => {
      if (options.transactionError !== undefined) throw options.transactionError;
      try {
        return await callback(repository as unknown as AuthRepository);
      } catch (error) {
        if (options.transactionFailureTransform !== undefined) {
          throw options.transactionFailureTransform(error);
        }
        throw error;
      }
    },
    users: {
      findByNormalizedEmail: async (email: string) => {
        if (options.lookupError !== undefined) throw options.lookupError;
        return existingEmail !== undefined && email === existingEmail ? existingUser : null;
      },
      findById: async () => existingUser,
      findByIdForUpdate: async () => existingUser,
      findByNormalizedEmailForUpdate: async () => existingUser,
      findByNormalizedPhoneForUpdate: async () => existingUser,
      create: async (input: { email?: string | null }) => ({ ...existingUser, email: input.email ?? null }),
      createWithId: async () => existingUser,
      createIfAvailable: async (input: { email?: string | null }) => ({ ...existingUser, email: input.email ?? null }),
      update: async () => existingUser,
      softDelete: async () => undefined,
    },
    identities: {
      findByProviderSubject: async () => null,
      listByUserId: async () => [],
      create: async () => null,
      createIfAvailable: async () => null,
      deleteById: async () => undefined,
    },
    passwordCredentials: { findByUserId: async () => null, upsert: async () => undefined, deleteByUserId: async () => undefined },
    sessions: { create: async () => ({ session: {}, refreshToken: {} }), findByIdForUpdate: async () => null, findRefreshForUpdate: async () => null, rotate: async () => ({}), revokeSession: async () => undefined, revokeFamily: async () => undefined, revokeUserSessions: async () => undefined },
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
    ...(options.defaultRoleKeys === undefined ? {} : { defaultRoleKeys: options.defaultRoleKeys }),
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
  it("uses captured WeakMap intrinsics to restore only the original trusted failure", async () => {
    const expected = new AuthApiError("invalid_token", 401, "Invalid or expired link");
    const injected = new AuthApiError(
      "invalid_request",
      400,
      `intrinsic ${SECRET_EMAIL} token=${SECRET_TOKEN} provider=${SECRET_PROVIDER}`,
    );
    const setDescriptor = Object.getOwnPropertyDescriptor(WeakMap.prototype, "set");
    const getDescriptor = Object.getOwnPropertyDescriptor(WeakMap.prototype, "get");
    if (setDescriptor === undefined || getDescriptor === undefined) throw new Error("WeakMap intrinsics are unavailable");
    const originalSet = WeakMap.prototype.set;
    const originalGet = WeakMap.prototype.get;

    try {
      Object.defineProperty(WeakMap.prototype, "set", {
        ...setDescriptor,
        value(this: WeakMap<object, unknown>, key: object, value: unknown) {
          return originalSet.call(this, key, value === expected ? injected : value);
        },
      });
      await expect(adapterTransaction(
        async () => trustedFailure(expected),
        (error) => { throw error; },
      )).rejects.toBe(expected);
    } finally {
      Object.defineProperty(WeakMap.prototype, "set", setDescriptor);
    }

    try {
      Object.defineProperty(WeakMap.prototype, "get", {
        ...getDescriptor,
        value(this: WeakMap<object, unknown>, key: object) {
          const value = originalGet.call(this, key);
          return value === expected ? injected : value;
        },
      });
      await expect(adapterTransaction(
        async () => trustedFailure(expected),
        (error) => { throw error; },
      )).rejects.toBe(expected);
    } finally {
      Object.defineProperty(WeakMap.prototype, "get", getDescriptor);
    }
  });

  it("uses captured WeakSet intrinsics for fixed adapter-boundary identities", async () => {
    const addDescriptor = Object.getOwnPropertyDescriptor(WeakSet.prototype, "add");
    const hasDescriptor = Object.getOwnPropertyDescriptor(WeakSet.prototype, "has");
    if (addDescriptor === undefined || hasDescriptor === undefined) throw new Error("WeakSet intrinsics are unavailable");
    const originalHas = WeakSet.prototype.has;
    let marker: unknown;

    try {
      Object.defineProperty(WeakSet.prototype, "add", {
        ...addDescriptor,
        value(this: WeakSet<object>) {
          return this;
        },
      });
      try {
        await adapterCall(async () => {
          throw new AuthApiError(
            "invalid_request",
            400,
            `adapter intrinsic ${SECRET_EMAIL} token=${SECRET_TOKEN}`,
          );
        });
      } catch (error) {
        marker = error;
      }
    } finally {
      Object.defineProperty(WeakSet.prototype, "add", addDescriptor);
    }

    expect(isAdapterBoundaryFailure(marker)).toBe(true);
    expect(JSON.stringify(marker)).toBe("{}");

    let classifiedWhilePatched = true;
    try {
      Object.defineProperty(WeakSet.prototype, "has", {
        ...hasDescriptor,
        value(this: WeakSet<object>, value: object) {
          return originalHas.call(this, value) ? false : originalHas.call(this, value);
        },
      });
      classifiedWhilePatched = isAdapterBoundaryFailure(marker);
    } finally {
      Object.defineProperty(WeakSet.prototype, "has", hasDescriptor);
    }
    expect(classifiedWhilePatched).toBe(true);
  });

  it("exposes only a constructorless identity marker and rejects constructor-forged trusted failures", async () => {
    const secret = new AuthApiError("invalid_request", 400, `forged ${SECRET_EMAIL} token=${SECRET_TOKEN} code=${SECRET_CODE} provider=${SECRET_PROVIDER}`);
    const observations: Array<{
      readonly prototype: object | null;
      readonly prototypeConstructor: unknown;
      readonly markerConstructor: unknown;
      readonly frozen: boolean;
      readonly keys: string[];
    }> = [];
    const current = service(SECRET_EMAIL, undefined, {
      transactionFailureTransform: (error) => {
        const marker = error as object;
        const prototype = Object.getPrototypeOf(marker);
        const prototypeConstructor = prototype === null ? undefined : Reflect.get(prototype, "constructor");
        observations.push({
          prototype,
          prototypeConstructor,
          markerConstructor: Reflect.get(marker, "constructor"),
          frozen: Object.isFrozen(marker),
          keys: Reflect.ownKeys(marker).map(String),
        });

        let forged: object;
        if (typeof prototypeConstructor === "function") {
          forged = Reflect.construct(prototypeConstructor, [secret]) as object;
        } else {
          forged = Object.create(null) as object;
          Object.defineProperty(forged, "error", { value: secret, enumerable: true });
        }
        return forged;
      },
    });
    const tokenService = (current as unknown as { readonly oneTimeTokens: OneTimeTokenService }).oneTimeTokens;

    const result = await tokenService.consumeForMutation({
      purpose: "email_change",
      target: SECRET_EMAIL,
      token: "valid-token",
      redirectTo: CALLBACK,
    }, async () => ({ committed: true }));

    expect(result).toMatchObject({
      data: null,
      error: { code: "internal_error", status: 500, message: "Internal authentication error" },
    });
    expect(observations).toHaveLength(1);
    expect(observations[0]?.prototype).toBeNull();
    expect(observations[0]?.prototypeConstructor).toBeUndefined();
    expect(observations[0]?.markerConstructor).toBeUndefined();
    expect(observations[0]?.frozen).toBe(true);
    expect(observations[0]?.keys).toEqual([]);
    expect(JSON.stringify(result)).not.toContain(SECRET_EMAIL);
    expect(JSON.stringify(result)).not.toContain(SECRET_TOKEN);
    expect(JSON.stringify(result)).not.toContain(SECRET_CODE);
    expect(JSON.stringify(result)).not.toContain(SECRET_PROVIDER);
  });

  it("does not restore a trusted policy error from a transaction-mutated marker", async () => {
    const secret = new AuthApiError("invalid_request", 400, `mutated ${SECRET_EMAIL} token=${SECRET_TOKEN} provider=${SECRET_PROVIDER}`);
    const markerObservations: Array<{ readonly keys: string[]; readonly serialized: string; readonly hasError: boolean; readonly hasCause: boolean }> = [];
    const current = service(SECRET_EMAIL, undefined, {
      transactionFailureTransform: (error) => {
        try {
          const marker = error as Record<PropertyKey, unknown>;
          markerObservations.push({
            keys: Reflect.ownKeys(marker).map(String),
            serialized: JSON.stringify(marker),
            hasError: Object.prototype.hasOwnProperty.call(marker, "error"),
            hasCause: Object.prototype.hasOwnProperty.call(marker, "cause"),
          });
          marker.error = secret;
          Object.defineProperty(marker, "error", { value: secret, configurable: true, writable: true });
          Object.setPrototypeOf(marker, Error.prototype);
          JSON.stringify(marker);
        } catch {
          // The regression intentionally attempts every mutable path.
        }
        return error;
      },
    });
    const tokenService = (current as unknown as { readonly oneTimeTokens: OneTimeTokenService }).oneTimeTokens;

    const result = await tokenService.consumeForMutation({
      purpose: "email_change",
      target: SECRET_EMAIL,
      token: "valid-token",
      redirectTo: CALLBACK,
    }, async () => ({ committed: true }));

    expect(result).toMatchObject({
      data: null,
      error: { code: "invalid_token", status: 401, message: "Invalid or expired link" },
    });
    expect(JSON.stringify(result)).not.toContain(SECRET_EMAIL);
    expect(JSON.stringify(result)).not.toContain(SECRET_TOKEN);
    expect(JSON.stringify(result)).not.toContain(SECRET_PROVIDER);
    expect(markerObservations).toHaveLength(1);
    expect(markerObservations[0]?.keys).not.toContain("error");
    expect(markerObservations[0]?.keys).not.toContain("cause");
    expect(markerObservations[0]?.hasError).toBe(false);
    expect(markerObservations[0]?.hasCause).toBe(false);
    expect(markerObservations[0]?.serialized).not.toContain(SECRET_EMAIL);
    expect(markerObservations[0]?.serialized).not.toContain(SECRET_TOKEN);
    expect(markerObservations[0]?.serialized).not.toContain(SECRET_PROVIDER);
  });

  it.each([
    ["clone", (error: unknown, secret: AuthApiError) => ({ ...(error as object), error: secret })],
    ["proxy", (error: unknown, secret: AuthApiError) => new Proxy(error as object, {
      get: (target, property, receiver) => property === "error" ? secret : Reflect.get(target, property, receiver),
    })],
    ["wrapped cause", (error: unknown) => new Error("adapter wrapper", { cause: error })],
    ["same-prototype clone", (error: unknown, secret: AuthApiError) => {
      const clone = Object.create(Object.getPrototypeOf(error)) as Record<PropertyKey, unknown>;
      Object.defineProperty(clone, "error", { value: secret, enumerable: true, configurable: true, writable: true });
      return clone;
    }],
    ["mutated-prototype error", (error: unknown, secret: AuthApiError) => {
      const lookalike = new Error("lookalike");
      Object.setPrototypeOf(lookalike, Object.getPrototypeOf(error));
      Object.defineProperty(lookalike, "error", { value: secret, enumerable: true, configurable: true, writable: true });
      return lookalike;
    }],
    ["null-prototype lookalike", (_error: unknown, secret: AuthApiError) => {
      const lookalike = Object.create(null) as Record<PropertyKey, unknown>;
      Object.defineProperty(lookalike, "error", { value: secret, enumerable: true, configurable: true, writable: true });
      return lookalike;
    }],
    ["structured clone", (error: unknown, secret: AuthApiError) => {
      const clone = structuredClone(error);
      Object.defineProperty(clone, "error", { value: secret, enumerable: true, configurable: true, writable: true });
      return clone;
    }],
  ] as const)("sanitizes a transaction %s/look-alike marker", async (_label, transform) => {
    const secret = new AuthApiError("invalid_request", 400, `lookalike ${SECRET_EMAIL} token=${SECRET_TOKEN}`);
    const current = service(SECRET_EMAIL, undefined, {
      transactionFailureTransform: (error) => transform(error, secret),
    });
    const tokenService = (current as unknown as { readonly oneTimeTokens: OneTimeTokenService }).oneTimeTokens;

    const result = await tokenService.consumeForMutation({
      purpose: "email_change",
      target: SECRET_EMAIL,
      token: "valid-token",
      redirectTo: CALLBACK,
    }, async () => ({ committed: true }));

    expect(result).toMatchObject({
      data: null,
      error: { code: "internal_error", status: 500, message: "Internal authentication error" },
    });
    expect(JSON.stringify(result)).not.toContain(SECRET_EMAIL);
    expect(JSON.stringify(result)).not.toContain(SECRET_TOKEN);
  });

  it("preserves a trusted configuration throw through a transaction that cannot mutate its marker", async () => {
    const secret = new AuthApiError("invalid_request", 400, `config leak ${SECRET_EMAIL} token=${SECRET_TOKEN}`);
    const current = service(SECRET_EMAIL, undefined, {
      defaultRoleKeys: ["missing"],
      transactionFailureTransform: (error) => {
        try {
          const marker = error as Record<PropertyKey, unknown>;
          marker.error = secret;
          Object.setPrototypeOf(marker, Error.prototype);
        } catch {
          // Frozen markers must remain opaque and rethrowable.
        }
        return error;
      },
    });

    await expect(current.signUp({
      email: "new@example.com",
      password: "correct horse battery staple",
    }, undefined)).rejects.toMatchObject({
      name: "AuthConfigurationError",
      message: "configured default role is missing",
    });
  });

  it.each([
    ["forged shape", { name: "PostgresRepositoryError", code: "email_exists", message: `forged ${SECRET_EMAIL} token=${SECRET_TOKEN}` }],
    ["real repository error", new PostgresRepositoryError("email_exists", `real ${SECRET_EMAIL} token=${SECRET_TOKEN}`)],
    ["subclass", new (class extends PostgresRepositoryError {}) ("email_exists", `subclass ${SECRET_EMAIL} token=${SECRET_TOKEN}`)],
    ["proxy", new Proxy(new PostgresRepositoryError("email_exists", `proxy ${SECRET_EMAIL} token=${SECRET_TOKEN}`), {})],
    ["forged AuthApiError", Object.assign(new AuthApiError("internal_error", 500, `auth ${SECRET_EMAIL} token=${SECRET_TOKEN}`), { name: "PostgresRepositoryError", code: "email_exists" })],
  ] as const)("maps %s email_exists adapter failures to fixed internal_error", async (_label, transactionError) => {
    const current = service(SECRET_EMAIL, undefined, { transactionError });
    const tokenService = (current as unknown as { readonly oneTimeTokens: OneTimeTokenService }).oneTimeTokens;

    const result = await tokenService.consumeForMutation({
      purpose: "email_change",
      target: SECRET_EMAIL,
      token: "valid-token",
      redirectTo: CALLBACK,
    }, async () => ({ committed: true }));

    expect(result).toMatchObject({
      data: null,
      error: { code: "internal_error", status: 500, message: "Internal authentication error" },
    });
    expect(JSON.stringify(result)).not.toContain(SECRET_EMAIL);
    expect(JSON.stringify(result)).not.toContain(SECRET_TOKEN);
  });

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
