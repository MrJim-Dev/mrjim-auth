import { describe, expect, it } from "vitest";
import { AuthConfigurationError } from "../../src/shared/errors.js";
import { EmailService } from "../../src/server/email.js";
import { AuthServer } from "../../src/server/auth-server.js";
import { OneTimeTokenService } from "../../src/server/one-time-tokens.js";
import { PasswordService } from "../../src/server/passwords.js";
import { SessionService } from "../../src/server/sessions.js";
import { TokenService } from "../../src/server/tokens.js";
import { UserService } from "../../src/server/users.js";

const NOW = new Date("2026-08-11T05:00:00.000Z");
const TOKEN_HASH_KEY = Uint8Array.from({ length: 32 }, (_, index) => index + 1);

describe("public server constructor callback boundaries", () => {
  it("does not invoke AuthServer runtime option accessors", () => {
    const options = Object.create(null) as Record<string, unknown>;
    let getterCalls = 0;
    Object.defineProperty(options, "config", {
      configurable: true,
      get: () => { getterCalls += 1; throw new Error("auth-server config sentinel"); },
    });
    let thrown: unknown;
    try {
      new AuthServer(options as never);
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(AuthConfigurationError);
    expect(String(thrown)).not.toContain("auth-server config sentinel");
    expect(getterCalls).toBe(0);

    const nestedConfig = Object.create(null) as Record<string, unknown>;
    const audience = ["audience"] as string[];
    let audienceGetterCalls = 0;
    Object.defineProperty(audience, "0", {
      configurable: true,
      get: () => { audienceGetterCalls += 1; throw new Error("auth-server audience sentinel"); },
    });
    nestedConfig.signingKeys = { issuer: "https://project.example.com/auth/v1", audience };
    let nestedThrown: unknown;
    try {
      new AuthServer({
        config: nestedConfig,
        repository: {},
        services: {},
        apiKeyHashKey: TOKEN_HASH_KEY,
        baseOrigin: "https://project.example.com",
        basePath: "/auth/v1",
        allowedOrigins: [],
        allowedRedirects: [],
      } as never);
    } catch (error) {
      nestedThrown = error;
    }
    expect(nestedThrown).toBeInstanceOf(AuthConfigurationError);
    expect(String(nestedThrown)).not.toContain("auth-server audience sentinel");
    expect(audienceGetterCalls).toBe(0);
  });

  it("does not invoke SessionService or OneTimeTokenService repository accessors", () => {
    const tokenService = Object.create(TokenService.prototype) as TokenService;
    const oneTimeRepository = Object.create(null) as Record<string, unknown>;
    let oneTimeGetterCalls = 0;
    Object.defineProperty(oneTimeRepository, "transaction", {
      configurable: true,
      get: () => { oneTimeGetterCalls += 1; throw new Error("one-time repository sentinel"); },
    });
    expect(() => new OneTimeTokenService({
      repository: oneTimeRepository as never,
      mailer: { send: async () => undefined },
      email: Object.create(EmailService.prototype) as EmailService,
      tokenHashKey: TOKEN_HASH_KEY,
    })).toThrow(AuthConfigurationError);
    expect(oneTimeGetterCalls).toBe(0);

    const sessionRepository = Object.create(null) as Record<string, unknown>;
    let sessionGetterCalls = 0;
    Object.defineProperty(sessionRepository, "transaction", {
      configurable: true,
      get: () => { sessionGetterCalls += 1; throw new Error("session repository sentinel"); },
    });
    expect(() => new SessionService({
      repository: sessionRepository as never,
      tokens: tokenService,
    })).toThrow(AuthConfigurationError);
    expect(sessionGetterCalls).toBe(0);
  });

  it("does not invoke UserService mailer accessors and rejects thenable clocks", () => {
    const mailer = Object.create(null) as Record<string, unknown>;
    let mailerGetterCalls = 0;
    Object.defineProperty(mailer, "send", {
      configurable: true,
      get: () => { mailerGetterCalls += 1; throw new Error("user mailer sentinel"); },
    });
    const fakeOptions = {
      repository: {},
      passwords: Object.create(PasswordService.prototype) as PasswordService,
      email: Object.create(EmailService.prototype) as EmailService,
      oneTimeTokens: Object.create(OneTimeTokenService.prototype) as OneTimeTokenService,
      mailer,
    } as never;
    expect(() => new UserService(fakeOptions)).toThrow(AuthConfigurationError);
    expect(mailerGetterCalls).toBe(0);

    const thenableClock = (() => NOW) as (() => Date) & { then?: () => void };
    let thenCalls = 0;
    Object.defineProperty(thenableClock, "then", {
      configurable: true,
      value: () => { thenCalls += 1; },
    });
    const validOptions = {
      repository: {},
      passwords: Object.create(PasswordService.prototype) as PasswordService,
      email: Object.create(EmailService.prototype) as EmailService,
      oneTimeTokens: Object.create(OneTimeTokenService.prototype) as OneTimeTokenService,
      mailer: { send: async () => undefined },
      clock: thenableClock,
    } as never;
    expect(() => new UserService(validOptions)).toThrow(AuthConfigurationError);
    expect(thenCalls).toBe(0);
  });

  it("does not invoke exported redirect or password-policy accessors", () => {
    const redirects = ["https://project.example.com/callback"] as string[];
    let redirectGetterCalls = 0;
    Object.defineProperty(redirects, "0", {
      configurable: true,
      get: () => { redirectGetterCalls += 1; throw new Error("email-redirect-sentinel"); },
    });
    let redirectThrown: unknown;
    try {
      new EmailService({ allowedRedirects: redirects });
    } catch (error) {
      redirectThrown = error;
    }
    expect(redirectThrown).toBeInstanceOf(AuthConfigurationError);
    expect(String(redirectThrown)).not.toContain("email-redirect-sentinel");
    expect(redirectGetterCalls).toBe(0);

    const policy = Object.create(null) as Record<string, unknown>;
    let policyGetterCalls = 0;
    Object.defineProperty(policy, "memoryCost", {
      configurable: true,
      get: () => { policyGetterCalls += 1; throw new Error("password-policy-sentinel"); },
    });
    let policyThrown: unknown;
    try {
      new PasswordService(policy as never);
    } catch (error) {
      policyThrown = error;
    }
    expect(policyThrown).toBeInstanceOf(AuthConfigurationError);
    expect(String(policyThrown)).not.toContain("password-policy-sentinel");
    expect(policyGetterCalls).toBe(0);
  });

  it("rejects thenable exported redirect and password-policy configuration", () => {
    const redirects = ["https://project.example.com/callback"] as string[];
    let redirectThenCalls = 0;
    Object.defineProperty(redirects, "then", {
      configurable: true,
      value: () => { redirectThenCalls += 1; },
    });
    expect(() => new EmailService({ allowedRedirects: redirects })).toThrow(AuthConfigurationError);
    expect(redirectThenCalls).toBe(0);

    const policy = { memoryCost: 64 * 1024 } as Record<string, unknown>;
    let policyThenCalls = 0;
    const policyPrototype = Object.create(null) as Record<string, unknown>;
    Object.defineProperty(policyPrototype, "then", {
      configurable: true,
      value: () => { policyThenCalls += 1; },
    });
    Object.setPrototypeOf(policy, policyPrototype);
    try {
      expect(() => new PasswordService(policy as never)).toThrow(AuthConfigurationError);
    } finally {
      Object.setPrototypeOf(policy, Object.prototype);
    }
    expect(policyThenCalls).toBe(0);
  });
});
