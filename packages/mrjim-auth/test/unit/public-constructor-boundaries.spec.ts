import { describe, expect, it } from "vitest";
import type { AuthRepository } from "../../src/shared/contracts.js";
import { AuthConfigurationError } from "../../src/shared/errors.js";
import { EmailService } from "../../src/server/email.js";
import { AuthServer } from "../../src/server/auth-server.js";
import { OneTimeTokenService } from "../../src/server/one-time-tokens.js";
import { PasswordService } from "../../src/server/passwords.js";
import { SessionService } from "../../src/server/sessions.js";
import { TokenService } from "../../src/server/tokens.js";
import { UserService } from "../../src/server/users.js";
import { captureBoundaryMapEntries } from "../../src/server/callback-boundary.js";

const NOW = new Date("2026-08-11T05:00:00.000Z");
const TOKEN_HASH_KEY = Uint8Array.from({ length: 32 }, (_, index) => index + 1);
const CALLBACK = "https://project.example.com/auth/callback";

function repositoryFixture(): AuthRepository {
  const noop = async () => undefined;
  const repository = {
    transaction: async (callback: (value: AuthRepository) => unknown) => callback(repository as unknown as AuthRepository),
    users: {
      findById: noop, findByIdForUpdate: noop, findByNormalizedEmail: noop,
      findByNormalizedEmailForUpdate: noop, create: noop, createIfAvailable: noop,
      update: noop, softDelete: noop,
    },
    identities: {
      findByProviderSubject: noop, listByUserId: noop, create: noop,
      createIfAvailable: noop, deleteById: noop,
    },
    passwordCredentials: { findByUserId: noop, upsert: noop, deleteByUserId: noop },
    sessions: {
      create: noop, findByIdForUpdate: noop, findRefreshForUpdate: noop,
      rotate: noop, revokeSession: noop, revokeFamily: noop, revokeUserSessions: noop,
    },
    oneTimeTokens: { issue: noop, consume: noop, consumeBound: noop, recordFailure: noop },
    oauthStates: { create: noop, consume: noop },
    authorization: {
      effectivePermissions: noop, assignRole: noop, unassignRole: noop,
      setRolePermissions: noop, setRoleInheritance: noop,
    },
    roles: { list: noop, findById: noop, create: noop, update: noop, delete: noop },
    permissions: { list: noop, findById: noop, create: noop, update: noop, delete: noop },
    operations: { appendAudit: noop, findApiKeyByHash: noop },
  };
  return repository as unknown as AuthRepository;
}

function expectRedactedConfigurationFailure(operation: () => unknown, sentinel: string): void {
  let thrown: unknown;
  try {
    operation();
  } catch (error) {
    thrown = error;
  }
  expect(thrown).toBeInstanceOf(AuthConfigurationError);
  expect(String(thrown)).not.toContain(sentinel);
}

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

  it("redacts hostile collection traps and ignores mutable collection intrinsics", () => {
    const revoked = Proxy.revocable([CALLBACK], {});
    revoked.revoke();
    expectRedactedConfigurationFailure(
      () => new EmailService({ allowedRedirects: revoked.proxy }),
      "revoked",
    );

    const ownKeys = new Proxy([CALLBACK], {
      ownKeys: () => { throw new Error("ownKeys sentinel"); },
    });
    expectRedactedConfigurationFailure(
      () => new EmailService({ allowedRedirects: ownKeys }),
      "ownKeys sentinel",
    );

    const originalSome = Array.prototype.some;
    const originalPush = Array.prototype.push;
    const originalSetHas = Set.prototype.has;
    const originalSetAdd = Set.prototype.add;
    const originalEntries = Object.entries;
    try {
      Array.prototype.some = (() => { throw new Error("array some sentinel"); }) as typeof Array.prototype.some;
      expect(() => new EmailService({ allowedRedirects: [CALLBACK] })).not.toThrow();
      Array.prototype.some = originalSome;
      Array.prototype.push = (() => { throw new Error("array push sentinel"); }) as typeof Array.prototype.push;
      expect(() => new EmailService({ allowedRedirects: [CALLBACK] })).not.toThrow();
      Array.prototype.push = originalPush;
      Set.prototype.has = (() => { throw new Error("set has sentinel"); }) as typeof Set.prototype.has;
      expect(() => new EmailService({ allowedRedirects: [CALLBACK] })).not.toThrow();
      Set.prototype.has = originalSetHas;
      Set.prototype.add = (() => { throw new Error("set add sentinel"); }) as typeof Set.prototype.add;
      expect(() => new EmailService({ allowedRedirects: [CALLBACK] })).not.toThrow();
      Set.prototype.add = originalSetAdd;
      Object.entries = (() => { throw new Error("object entries sentinel"); }) as typeof Object.entries;
      expect(() => new OneTimeTokenService({
        repository: repositoryFixture(),
        mailer: { send: async () => undefined },
        email: new EmailService({ allowedRedirects: [CALLBACK] }),
        tokenHashKey: TOKEN_HASH_KEY,
      })).not.toThrow();
    } finally {
      Array.prototype.some = originalSome;
      Array.prototype.push = originalPush;
      Set.prototype.has = originalSetHas;
      Set.prototype.add = originalSetAdd;
      Object.entries = originalEntries;
    }
  });

  it("does not trust post-import Array, Number, String, or Map entry intrinsics", () => {
    const cases: readonly [string, (operation: () => void) => void, () => void][] = [
      ["array numeric setter", (operation) => {
        const descriptor = Object.getOwnPropertyDescriptor(Array.prototype, "0");
        try {
          Object.defineProperty(Array.prototype, "0", {
            configurable: true,
            set: () => { throw new Error("array-index-sentinel"); },
          });
          operation();
        } finally {
          if (descriptor === undefined) Reflect.deleteProperty(Array.prototype, "0");
          else Object.defineProperty(Array.prototype, "0", descriptor);
        }
      }, () => new EmailService({ allowedRedirects: [CALLBACK] })],
      ["number safe integer", (operation) => {
        const descriptor = Object.getOwnPropertyDescriptor(Number, "isSafeInteger");
        try {
          Object.defineProperty(Number, "isSafeInteger", {
            configurable: true,
            enumerable: false,
            writable: true,
            value: () => { throw new Error("number-sentinel"); },
          });
          operation();
        } finally {
          if (descriptor === undefined) Reflect.deleteProperty(Number, "isSafeInteger");
          else Object.defineProperty(Number, "isSafeInteger", descriptor);
        }
      }, () => new EmailService({ allowedRedirects: [CALLBACK] })],
      ["String conversion", (operation) => {
        const descriptor = Object.getOwnPropertyDescriptor(globalThis, "String");
        try {
          Object.defineProperty(globalThis, "String", {
            configurable: true,
            enumerable: descriptor?.enumerable ?? false,
            writable: true,
            value: () => { throw new Error("string-sentinel"); },
          });
          operation();
        } finally {
          if (descriptor === undefined) Reflect.deleteProperty(globalThis, "String");
          else Object.defineProperty(globalThis, "String", descriptor);
        }
      }, () => new EmailService({ allowedRedirects: [CALLBACK] })],
      ["Map entry copy", (operation) => {
        const descriptor = Object.getOwnPropertyDescriptor(Array.prototype, "0");
        try {
          Object.defineProperty(Array.prototype, "0", {
            configurable: true,
            set: () => { throw new Error("map-entry-array-sentinel"); },
          });
          operation();
        } finally {
          if (descriptor === undefined) Reflect.deleteProperty(Array.prototype, "0");
          else Object.defineProperty(Array.prototype, "0", descriptor);
        }
      }, () => {
        captureBoundaryMapEntries(new Map([["key", "value"]]), "test map");
      }],
    ];

    for (const [label, install, operation] of cases) {
      let thrown: unknown;
      try {
        install(operation);
      } catch (error) {
        thrown = error;
      }
      expect(thrown, label).toBeUndefined();
    }
  });

  it("rejects array-like and revoked byte key material synchronously", () => {
    let lengthReads = 0;
    const arrayLike = Object.create(null) as Record<string, unknown>;
    Object.defineProperty(arrayLike, "length", {
      configurable: true,
      get: () => {
        lengthReads += 1;
        throw new Error("byte length sentinel");
      },
    });
    expectRedactedConfigurationFailure(() => new OneTimeTokenService({
      repository: repositoryFixture(),
      mailer: { send: async () => undefined },
      email: new EmailService({ allowedRedirects: [CALLBACK] }),
      tokenHashKey: arrayLike as never,
    }), "byte length sentinel");
    expect(lengthReads).toBe(0);

    const revoked = Proxy.revocable(TOKEN_HASH_KEY, {});
    revoked.revoke();
    expectRedactedConfigurationFailure(() => new OneTimeTokenService({
      repository: repositoryFixture(),
      mailer: { send: async () => undefined },
      email: new EmailService({ allowedRedirects: [CALLBACK] }),
      tokenHashKey: revoked.proxy,
    }), "TypeError");
  });
});
