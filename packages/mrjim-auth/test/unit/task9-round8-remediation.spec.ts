import { afterEach, describe, expect, it } from "vitest";
import { AuthApiError, AuthConfigurationError, AuthProgrammingError } from "../../src/shared/errors.js";
import { OAuthProviderError, OidcOAuthProvider } from "../../src/server/oauth-providers.js";

const CALLBACK = "https://project.example.com/auth/callback";

type SetterMode = "throw" | "mislead";

function withPoisonedPrototypeSetter<T>(mode: SetterMode, operation: () => T): { readonly value?: T; readonly error?: unknown; readonly calls: number } {
  const descriptor = Object.getOwnPropertyDescriptor(Object, "setPrototypeOf");
  if (descriptor === undefined) throw new Error("Object.setPrototypeOf is unavailable");
  let calls = 0;
  Object.defineProperty(Object, "setPrototypeOf", {
    configurable: descriptor.configurable ?? true,
    enumerable: descriptor.enumerable ?? false,
    writable: true,
    value: (..._args: unknown[]) => {
      calls += 1;
      if (mode === "throw") throw new Error("round8-setPrototypeOf-sentinel");
      return Object.create(null);
    },
  });
  try {
    return { value: operation(), calls };
  } catch (error) {
    return { error, calls };
  } finally {
    Object.defineProperty(Object, "setPrototypeOf", descriptor);
  }
}

async function withPoisonedPrototypeSetterAsync<T>(mode: SetterMode, operation: () => Promise<T>): Promise<{ readonly value?: T; readonly error?: unknown; readonly calls: number }> {
  const descriptor = Object.getOwnPropertyDescriptor(Object, "setPrototypeOf");
  if (descriptor === undefined) throw new Error("Object.setPrototypeOf is unavailable");
  let calls = 0;
  Object.defineProperty(Object, "setPrototypeOf", {
    configurable: descriptor.configurable ?? true,
    enumerable: descriptor.enumerable ?? false,
    writable: true,
    value: (..._args: unknown[]) => {
      calls += 1;
      if (mode === "throw") throw new Error("round8-setPrototypeOf-sentinel");
      return Object.create(null);
    },
  });
  try {
    return { value: await operation(), calls };
  } catch (error) {
    return { error, calls };
  } finally {
    Object.defineProperty(Object, "setPrototypeOf", descriptor);
  }
}

function expectStableError(error: unknown, expected: new (...args: never[]) => Error): void {
  expect(error).toBeInstanceOf(Error);
  expect(error).toBeInstanceOf(expected);
  expect(String(error)).not.toContain("round8-setPrototypeOf-sentinel");
  expect(JSON.stringify(error)).not.toContain("round8-setPrototypeOf-sentinel");
  expect((error as { readonly cause?: unknown }).cause).toBeUndefined();
}

function oidcProvider(): OidcOAuthProvider {
  return new OidcOAuthProvider({
    name: "oidc",
    clientId: "client",
    clientSecret: "secret",
    issuer: "https://issuer.example",
  });
}

function authorizationInput(codeChallengeMethod: "S256" | "plain" = "S256") {
    return {
    clientId: "client",
    redirectUri: CALLBACK,
    state: "provider-state-sentinel",
    nonce: "provider-nonce-sentinel",
    scopes: ["openid"],
    codeChallenge: "client-challenge",
    codeChallengeMethod: codeChallengeMethod as never,
  };
}

function exchangeInput() {
  return {
    code: "provider-code-sentinel",
    state: "provider-state-sentinel",
    expectedState: "provider-state-sentinel",
    redirectUri: CALLBACK,
    codeVerifier: "too-short",
    nonce: "provider-nonce-sentinel",
  };
}

afterEach(() => {
  const descriptor = Object.getOwnPropertyDescriptor(Object, "setPrototypeOf");
  if (descriptor !== undefined && descriptor.value !== Object.setPrototypeOf) {
    throw new Error("Object.setPrototypeOf was not restored");
  }
});

describe("Task 9 round 8 prototype-setting boundary", () => {
  it.each(["throw", "mislead"] as const)("keeps every exported auth error subclass valid when Object.setPrototypeOf %s", (mode) => {
    const cases: readonly [string, () => Error, new (...args: never[]) => Error][] = [
      ["configuration", () => new AuthConfigurationError("configuration failure"), AuthConfigurationError],
      ["programming", () => new AuthProgrammingError("programming failure"), AuthProgrammingError],
      ["api", () => new AuthApiError("invalid_request", 400, "invalid request"), AuthApiError],
      ["provider", () => new OAuthProviderError("provider failure"), OAuthProviderError],
    ];

    for (const [_label, operation, expected] of cases) {
      const outcome = withPoisonedPrototypeSetter(mode, operation);
      expect(outcome.calls).toBe(0);
      expect(outcome.error).toBeUndefined();
      expectStableError(outcome.value, expected);
    }
  });

  it.each(["throw", "mislead"] as const)("keeps OIDC authorization, discovery, and exchange failures redacted when Object.setPrototypeOf %s", async (mode) => {
    class RejectingConfigurationProvider extends OidcOAuthProvider {
      protected override async configuration(): Promise<never> {
        throw new Error("round8-oidc-discovery-sentinel");
      }
    }

    const provider = oidcProvider();
    const rejecting = new RejectingConfigurationProvider({
      name: "oidc",
      clientId: "client",
      clientSecret: "secret",
      issuer: "https://issuer.example",
    });
    const operations: readonly [string, () => Promise<unknown>][] = [
      ["authorization", () => provider.authorizationUrl(authorizationInput("plain"))],
      ["discovery", () => rejecting.authorizationUrl(authorizationInput())],
      ["exchange", () => provider.exchange(exchangeInput())],
    ];

    for (const [_label, operation] of operations) {
      const outcome = await withPoisonedPrototypeSetterAsync(mode, operation);
      expect(outcome.calls).toBe(0);
      expect(outcome.value).toBeUndefined();
      expectStableError(outcome.error, OAuthProviderError);
      expect(String(outcome.error)).not.toContain("round8-oidc-discovery-sentinel");
      expect(String(outcome.error)).not.toContain("provider-code-sentinel");
      expect(String(outcome.error)).not.toContain("provider-state-sentinel");
    }
  });

  it("captures the prototype setter during a clean dynamic import before post-import poisoning", async () => {
    // @ts-expect-error The query suffix intentionally asks Vite for a clean module instance.
    const errors = await import("../../src/shared/errors.js?round8-clean-import");
    // @ts-expect-error The query suffix intentionally asks Vite for a clean module instance.
    const providers = await import("../../src/server/oauth-providers.js?round8-clean-import");
    const outcome = withPoisonedPrototypeSetter("throw", () => ({
      configuration: new errors.AuthConfigurationError("configuration failure"),
      programming: new errors.AuthProgrammingError("programming failure"),
      api: new errors.AuthApiError("invalid_request", 400, "invalid request"),
      provider: new providers.OAuthProviderError("provider failure"),
    }));

    expect(outcome.calls).toBe(0);
    expect(outcome.error).toBeUndefined();
    expect(outcome.value?.configuration).toBeInstanceOf(errors.AuthConfigurationError);
    expect(outcome.value?.programming).toBeInstanceOf(errors.AuthProgrammingError);
    expect(outcome.value?.api).toBeInstanceOf(errors.AuthApiError);
    expect(outcome.value?.provider).toBeInstanceOf(providers.OAuthProviderError);
  });
});
