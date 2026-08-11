import { beforeEach, describe, expect, it, vi } from "vitest";

const openidMocks = vi.hoisted(() => ({
  claims: {
    iss: "https://accounts.google.com",
    sub: "google-subject",
    aud: "google-client",
    email: "alice@example.com",
    email_verified: true,
    name: "Alice",
  } as Record<string, unknown>,
  checks: undefined as Record<string, unknown> | undefined,
  discovery: vi.fn(async () => ({})),
  authorizationCodeGrant: vi.fn(async (_configuration: unknown, _url: URL, checks: Record<string, unknown>) => {
    openidMocks.checks = checks;
    return { claims: () => openidMocks.claims };
  }),
  buildAuthorizationUrl: vi.fn((_configuration: unknown, parameters: Record<string, string>) => {
    const url = new URL("https://accounts.google.com/o/oauth2/v2/auth");
    for (const [key, value] of Object.entries(parameters)) url.searchParams.set(key, value);
    return url;
  }),
  clientSecretPost: vi.fn(() => "client-auth"),
}));

vi.mock("openid-client", () => ({
  authorizationCodeGrant: openidMocks.authorizationCodeGrant,
  buildAuthorizationUrl: openidMocks.buildAuthorizationUrl,
  calculatePKCECodeChallenge: vi.fn(async () => "calculated-challenge"),
  ClientSecretPost: openidMocks.clientSecretPost,
  discovery: openidMocks.discovery,
  randomNonce: vi.fn(() => "provider-nonce-value"),
}));

import {
  GoogleOAuthProvider,
  OAuthProviderError,
  OidcOAuthProvider,
} from "../../src/server/oauth-providers.js";

const exchangeInput = {
  code: "provider-code",
  state: "state-value",
  redirectUri: "https://project.example.com/auth/callback",
  codeVerifier: "a".repeat(43),
  nonce: "nonce-value",
} as const;

describe("OAuth provider adapters", () => {
  beforeEach(() => {
    openidMocks.claims = {
      iss: "https://accounts.google.com",
      sub: "google-subject",
      aud: "google-client",
      email: "alice@example.com",
      email_verified: true,
      name: "Alice",
    };
    openidMocks.checks = undefined;
    openidMocks.discovery.mockClear();
    openidMocks.authorizationCodeGrant.mockClear();
    openidMocks.buildAuthorizationUrl.mockClear();
    openidMocks.clientSecretPost.mockClear();
  });

  it("builds Google authorization with the required scopes and validates nonce/PKCE checks", async () => {
    const provider = new GoogleOAuthProvider({ clientId: "google-client", clientSecret: "google-secret" });
    const url = await provider.authorizationUrl({
      clientId: provider.clientId,
      redirectUri: exchangeInput.redirectUri,
      state: exchangeInput.state,
      nonce: exchangeInput.nonce,
      scopes: provider.scopes,
      codeChallenge: "challenge-value",
      codeChallengeMethod: "S256",
    });

    expect(provider.scopes).toEqual(["openid", "email", "profile"]);
    expect(url).toContain("code_challenge_method=S256");
    expect(url).toContain("scope=openid+email+profile");
    expect(openidMocks.discovery).toHaveBeenCalledWith(
      new URL("https://accounts.google.com"),
      "google-client",
      { client_secret: "google-secret" },
      "client-auth",
    );

    const profile = await provider.exchange(exchangeInput);
    expect(profile).toMatchObject({
      provider: "google",
      subject: "google-subject",
      issuer: "https://accounts.google.com",
      email: "alice@example.com",
      emailVerified: true,
    });
    expect(openidMocks.checks).toEqual({
      expectedState: "state-value",
      expectedNonce: "nonce-value",
      pkceCodeVerifier: "a".repeat(43),
      idTokenExpected: true,
    });
  });

  it.each([
    ["issuer", { iss: "https://evil.example.com" }],
    ["audience", { aud: "other-client" }],
    ["subject", { sub: "" }],
  ])("rejects an invalid OIDC %s claim", async (_label, invalidClaim) => {
    openidMocks.claims = { ...openidMocks.claims, ...invalidClaim };
    const provider = new GoogleOAuthProvider({ clientId: "google-client", clientSecret: "google-secret" });

    await expect(provider.exchange(exchangeInput)).rejects.toBeInstanceOf(OAuthProviderError);
  });

  it("uses discovery and the same issuer/audience/nonce/sub validation for generic OIDC", async () => {
    openidMocks.claims = {
      ...openidMocks.claims,
      iss: "https://issuer.example.com/tenant",
      sub: "oidc-subject",
      aud: ["oidc-client", "other-audience"],
    };
    const provider = new OidcOAuthProvider({
      name: "Acme-OIDC",
      clientId: "oidc-client",
      clientSecret: "oidc-secret",
      issuer: "https://issuer.example.com/tenant",
    });

    const profile = await provider.exchange({ ...exchangeInput, nonce: "generic-nonce" });
    expect(profile).toMatchObject({
      provider: "acme-oidc",
      subject: "oidc-subject",
      issuer: "https://issuer.example.com/tenant",
    });
    expect(openidMocks.checks?.expectedNonce).toBe("generic-nonce");
    expect(openidMocks.checks?.expectedState).toBe(exchangeInput.state);
  });
});
