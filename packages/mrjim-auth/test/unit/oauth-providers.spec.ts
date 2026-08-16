import { createHash } from "node:crypto";
import { once } from "node:events";
import { createServer, request as httpsRequest, type Server } from "node:https";
import type { AddressInfo } from "node:net";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import type { CustomFetch } from "openid-client";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  FacebookOAuthProvider,
  GoogleOAuthProvider,
  OAuthProviderError,
  OidcOAuthProvider,
  providerCodeChallenge,
} from "../../src/server/oauth-providers.js";
import { AuthConfigurationError } from "../../src/shared/errors.js";

const TLS_KEY = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgt3zy1YONNbO3EPT2
IwFnt6ok2cWzPxVye6Qn0LtzrHOhRANCAAT78colovI9PzE09ECF447pLL3RF/Ii
TVfiBAVwt/uohf7pZzOtLYuK4FOvUEZvbbRenLLXzu8XwHIXc1Y3RL0L
-----END PRIVATE KEY-----`;

const TLS_CERT = `-----BEGIN CERTIFICATE-----
MIIBmTCCAT+gAwIBAgIUF0aI8wkIJdcKvUUxbaR2eNN3/ZowCgYIKoZIzj0EAwIw
FDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDgxMTAyNDM1NVoXDTM2MDgwODAy
NDM1NVowFDESMBAGA1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAE+/HKJaLyPT8xNPRAheOO6Sy90RfyIk1X4gQFcLf7qIX+6WczrS2LiuBT
r1BGb220Xpyy187vF8ByF3NWN0S9C6NvMG0wHQYDVR0OBBYEFFXotiSJO+2xTa6R
9/yokmi7ZvpkMB8GA1UdIwQYMBaAFFXotiSJO+2xTa6R9/yokmi7ZvpkMA8GA1Ud
EwEB/wQFMAMBAf8wGgYDVR0RBBMwEYIJbG9jYWxob3N0hwR/AAABMAoGCCqGSM49
BAMCA0gAMEUCIFvExd9bRvWtAm4XJ0sjtbLhdOH2D9hxF9pl1iiJFMUUAiEA77vJ
rgMqPDqZHld0TD+AhGndG7NhXp5ZZZAM5u7zgUU=
-----END CERTIFICATE-----`;

const CLIENT_ID = "local-oidc-client";
const CLIENT_SECRET = "local-oidc-secret";
const CALLBACK = "https://project.example.com/auth/callback";
const ALT_CALLBACK = "https://project.example.com/auth/alternate";
const VERIFIER = "a".repeat(43);

type TokenScenario = {
  readonly issuer?: string;
  readonly audience?: string | readonly string[];
  readonly nonce?: string;
  readonly subject?: string | null;
  readonly signingKey?: CryptoKey;
};

type AuthorizationGrant = {
  readonly challenge: string;
  readonly redirect: string;
  readonly nonce: string;
  readonly scenario: TokenScenario;
};

function localHttpsFetch(url: string, options: Parameters<CustomFetch>[1]): Promise<Response> {
  return new Promise((resolve, reject) => {
    const request = httpsRequest(url, {
      method: options.method,
      headers: options.headers,
      rejectUnauthorized: false,
      signal: options.signal,
    }, (response) => {
      const chunks: Buffer[] = [];
      response.on("data", (chunk: Buffer) => chunks.push(chunk));
      response.once("error", reject);
      response.once("end", () => {
        const headers = new Headers();
        for (let index = 0; index < response.rawHeaders.length; index += 2) {
          const name = response.rawHeaders[index];
          const value = response.rawHeaders[index + 1];
          if (name !== undefined && value !== undefined) headers.append(name, value);
        }
        resolve(new Response(Uint8Array.from(Buffer.concat(chunks)), {
          status: response.statusCode ?? 500,
          headers,
        }));
      });
    });
    request.once("error", reject);
    if (options.body === undefined) {
      request.end();
    } else if (options.body instanceof URLSearchParams) {
      request.end(options.body.toString());
    } else if (typeof options.body === "string" || options.body instanceof Uint8Array) {
      request.end(options.body);
    } else {
      request.destroy(new TypeError("unsupported local fixture request body"));
    }
  });
}

class LocalHttpsOidcFixture {
  readonly requests: string[] = [];
  issuer = "";
  private server: Server | undefined;
  private signingKey: CryptoKey | undefined;
  private publicJwk: Record<string, unknown> | undefined;
  private sequence = 0;
  private readonly grants = new Map<string, AuthorizationGrant>();

  async start(): Promise<void> {
    const pair = await generateKeyPair("ES256", { extractable: true });
    this.signingKey = pair.privateKey;
    this.publicJwk = {
      ...await exportJWK(pair.publicKey),
      alg: "ES256",
      kid: "local-signing-key",
      use: "sig",
    };
    this.server = createServer({ key: TLS_KEY, cert: TLS_CERT }, (request, response) => {
      void this.handle(request, response);
    });
    this.server.listen(0, "127.0.0.1");
    await once(this.server, "listening");
    const address = this.server.address() as AddressInfo;
    this.issuer = `https://127.0.0.1:${address.port}`;
  }

  async stop(): Promise<void> {
    if (this.server === undefined) return;
    this.server.close();
    await once(this.server, "close");
  }

  issue(grant: Omit<AuthorizationGrant, "scenario"> & { readonly scenario?: TokenScenario }): string {
    this.sequence += 1;
    const code = `fixture-code-${this.sequence}`;
    this.grants.set(code, { ...grant, scenario: grant.scenario ?? {} });
    return code;
  }

  private json(response: Parameters<NonNullable<Parameters<typeof createServer>[1]>>[1], status: number, value: unknown): void {
    response.writeHead(status, { "content-type": "application/json", "cache-control": "no-store" });
    response.end(JSON.stringify(value));
  }

  private async handle(
    request: Parameters<NonNullable<Parameters<typeof createServer>[1]>>[0],
    response: Parameters<NonNullable<Parameters<typeof createServer>[1]>>[1],
  ): Promise<void> {
    const path = new URL(request.url ?? "/", this.issuer || "https://127.0.0.1").pathname;
    this.requests.push(path);
    if (request.method === "GET" && path === "/.well-known/openid-configuration") {
      this.json(response, 200, {
        issuer: this.issuer,
        authorization_endpoint: `${this.issuer}/authorize`,
        token_endpoint: `${this.issuer}/token`,
        jwks_uri: `${this.issuer}/jwks`,
        response_types_supported: ["code"],
        grant_types_supported: ["authorization_code"],
        subject_types_supported: ["public"],
        authorization_response_iss_parameter_supported: true,
        id_token_signing_alg_values_supported: ["ES256"],
        token_endpoint_auth_methods_supported: ["client_secret_post"],
        code_challenge_methods_supported: ["S256"],
        scopes_supported: ["openid", "email", "profile"],
      });
      return;
    }
    if (request.method === "GET" && path === "/jwks") {
      this.json(response, 200, { keys: [this.publicJwk] });
      return;
    }
    if (request.method !== "POST" || path !== "/token") {
      this.json(response, 404, { error: "not_found" });
      return;
    }
    const body: Buffer[] = [];
    for await (const chunk of request) body.push(Buffer.from(chunk));
    const parameters = new URLSearchParams(Buffer.concat(body).toString("utf8"));
    const code = parameters.get("code") ?? "";
    const grant = this.grants.get(code);
    const verifier = parameters.get("code_verifier") ?? "";
    const challenge = createHash("sha256").update(verifier, "utf8").digest("base64url");
    if (
      grant === undefined
      || parameters.get("grant_type") !== "authorization_code"
      || parameters.get("client_id") !== CLIENT_ID
      || parameters.get("client_secret") !== CLIENT_SECRET
      || parameters.get("redirect_uri") !== grant.redirect
      || challenge !== grant.challenge
    ) {
      this.json(response, 400, { error: "invalid_grant" });
      return;
    }
    this.grants.delete(code);
    const signingKey = grant.scenario.signingKey ?? this.signingKey;
    if (signingKey === undefined) throw new Error("fixture signing key is missing");
    const tokenAudience = grant.scenario.audience;
    let token = new SignJWT({
      email: "alice@example.com",
      email_verified: true,
      name: "Alice",
      nonce: grant.scenario.nonce ?? grant.nonce,
    })
      .setProtectedHeader({ alg: "ES256", kid: "local-signing-key" })
      .setIssuer(grant.scenario.issuer ?? this.issuer)
      .setAudience(tokenAudience === undefined || typeof tokenAudience === "string"
        ? tokenAudience ?? CLIENT_ID
        : [...tokenAudience])
      .setIssuedAt()
      .setExpirationTime("5m");
    if (grant.scenario.subject !== null) token = token.setSubject(grant.scenario.subject ?? "local-subject");
    const idToken = await token.sign(signingKey);
    this.json(response, 200, {
      access_token: "fixture-access-token",
      token_type: "Bearer",
      expires_in: 300,
      id_token: idToken,
    });
  }
}

const fixture = new LocalHttpsOidcFixture();

function provider(): OidcOAuthProvider {
  return new OidcOAuthProvider({
    name: "local-oidc",
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
    issuer: fixture.issuer,
    customFetch: localHttpsFetch,
  } as ConstructorParameters<typeof OidcOAuthProvider>[0] & { readonly customFetch: CustomFetch });
}

async function flow(currentProvider = provider()): Promise<{
  readonly provider: OidcOAuthProvider;
  readonly challenge: string;
  readonly nonce: string;
  readonly state: string;
}> {
  const state = "returned-state";
  const nonce = "fixture-nonce-value";
  const challenge = await providerCodeChallenge(VERIFIER);
  const url = await currentProvider.authorizationUrl({
    clientId: CLIENT_ID,
    redirectUri: CALLBACK,
    state,
    nonce,
    scopes: currentProvider.scopes,
    codeChallenge: challenge,
    codeChallengeMethod: "S256",
  });
  expect(new URL(url).searchParams.get("code_challenge_method")).toBe("S256");
  return { provider: currentProvider, challenge, nonce, state };
}

function exchangeInput(value: {
  readonly code: string;
  readonly state: string;
  readonly nonce: string;
  readonly verifier?: string;
  readonly redirect?: string;
  readonly expectedState?: string;
}) {
  return {
    code: value.code,
    state: value.state,
    expectedState: value.expectedState ?? value.state,
    redirectUri: value.redirect ?? CALLBACK,
    codeVerifier: value.verifier ?? VERIFIER,
    nonce: value.nonce,
  } as Parameters<OidcOAuthProvider["exchange"]>[0] & { readonly expectedState: string };
}

describe("OAuth provider adapters with a local HTTPS OIDC server", () => {
  beforeAll(async () => fixture.start());
  afterAll(async () => fixture.stop());

  it("does not invoke Google credential option accessors", () => {
    const options = Object.create(null) as Record<string, unknown>;
    let getterCalls = 0;
    Object.defineProperty(options, "clientId", {
      configurable: true,
      get: () => { getterCalls += 1; throw new Error("google-client-id-sentinel"); },
    });
    let thrown: unknown;
    try {
      new GoogleOAuthProvider(options as never);
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(AuthConfigurationError);
    expect(String(thrown)).not.toContain("google-client-id-sentinel");
    expect(getterCalls).toBe(0);
  });

  it("rejects thenable Google credential options without assimilation", () => {
    const options = { clientId: "google-client", clientSecret: "google-secret" } as Record<string, unknown>;
    let thenCalls = 0;
    Object.defineProperty(options, "then", {
      configurable: true,
      value: () => { thenCalls += 1; },
    });
    expect(() => new GoogleOAuthProvider(options as never)).toThrow(AuthConfigurationError);
    expect(thenCalls).toBe(0);
  });

  it("rejects non-HTTPS issuers at construction and keeps Google scopes fixed", () => {
    expect(() => new OidcOAuthProvider({
      name: "insecure",
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      issuer: "http://127.0.0.1:4444",
    })).toThrow(/HTTPS/i);
    const google = new GoogleOAuthProvider({ clientId: "google-client", clientSecret: "google-secret" });
    expect(google.scopes).toEqual(["openid", "email", "profile"]);
  });

  it("builds a Facebook authorization URL and validates the Graph profile", async () => {
    const calls: string[] = [];
    const facebook = new FacebookOAuthProvider({
      clientId: "facebook-client",
      clientSecret: "facebook-secret",
      customFetch: async (input) => {
        const url = new URL(String(input));
        calls.push(url.pathname);
        if (url.pathname.endsWith("/oauth/access_token")) {
          return new Response(JSON.stringify({ access_token: "facebook-access-token" }), { status: 200 });
        }
        return new Response(JSON.stringify({
          id: "facebook-subject",
          name: "Facebook User",
          email: "facebook@example.com",
          picture: { data: { url: "https://example.com/avatar.png" } },
        }), { status: 200 });
      },
    });
    const authorization = await facebook.authorizationUrl({
      clientId: facebook.clientId,
      redirectUri: CALLBACK,
      state: "facebook-state",
      nonce: "facebook-nonce",
      scopes: facebook.scopes,
      codeChallenge: "challenge-value",
      codeChallengeMethod: "S256",
    });
    const authorizationUrl = new URL(authorization);
    expect(authorizationUrl.hostname).toBe("www.facebook.com");
    expect(authorizationUrl.searchParams.get("state")).toBe("facebook-state");
    expect(authorizationUrl.searchParams.get("code_challenge_method")).toBe("S256");
    const profile = await facebook.exchange({
      code: "facebook-code",
      state: "facebook-state",
      expectedState: "facebook-state",
      redirectUri: CALLBACK,
      codeVerifier: VERIFIER,
      nonce: "facebook-nonce",
    });
    expect(profile).toMatchObject({
      provider: "facebook",
      subject: "facebook-subject",
      issuer: "https://www.facebook.com",
      email: "facebook@example.com",
    });
    expect(profile.claims).toMatchObject({ sub: "facebook-subject", name: "Facebook User" });
    expect(calls).toEqual(["/oauth/access_token", "/me"]);
  });

  it("rejects a custom-fetch accessor without invoking it", () => {
    const options = {
      name: "local-oidc",
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      issuer: "https://issuer.example.com",
    } as Record<string, unknown>;
    let getterCalls = 0;
    Object.defineProperty(options, "customFetch", {
      configurable: true,
      get: () => { getterCalls += 1; throw new Error("custom-fetch-sentinel"); },
    });
    let thrown: unknown;
    try {
      new OidcOAuthProvider(options as never);
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(Error);
    expect(String(thrown)).not.toContain("custom-fetch-sentinel");
    expect(getterCalls).toBe(0);
  });

  it("performs discovery, authorization, token exchange, JWKS signature validation, and one-use code handling", async () => {
    const current = await flow();
    const code = fixture.issue({ challenge: current.challenge, redirect: CALLBACK, nonce: current.nonce });
    const profile = await current.provider.exchange(exchangeInput({ code, state: current.state, nonce: current.nonce }));
    expect(profile).toMatchObject({
      provider: "local-oidc",
      subject: "local-subject",
      issuer: fixture.issuer,
      email: "alice@example.com",
      emailVerified: true,
    });
    expect(fixture.requests).toEqual(expect.arrayContaining([
      "/.well-known/openid-configuration",
      "/token",
      "/jwks",
    ]));
    await expect(current.provider.exchange(exchangeInput({ code, state: current.state, nonce: current.nonce })))
      .rejects.toBeInstanceOf(OAuthProviderError);
  });

  it.each([
    ["state", { expectedState: "different-state" }],
    ["PKCE", { verifier: "b".repeat(43) }],
    ["redirect", { redirect: ALT_CALLBACK }],
  ])("rejects a mismatched %s binding", async (_label, override) => {
    const current = await flow();
    const code = fixture.issue({ challenge: current.challenge, redirect: CALLBACK, nonce: current.nonce });
    await expect(current.provider.exchange(exchangeInput({
      code,
      state: current.state,
      nonce: current.nonce,
      ...override,
    }))).rejects.toBeInstanceOf(OAuthProviderError);
  });

  it.each([
    ["issuer", { issuer: "https://evil.example.com" }],
    ["audience", { audience: "other-client" }],
    ["nonce", { nonce: "wrong-nonce" }],
    ["subject", { subject: null }],
  ] as const)("rejects an invalid signed %s claim", async (_label, scenario) => {
    const current = await flow();
    const code = fixture.issue({ challenge: current.challenge, redirect: CALLBACK, nonce: current.nonce, scenario });
    await expect(current.provider.exchange(exchangeInput({ code, state: current.state, nonce: current.nonce })))
      .rejects.toBeInstanceOf(OAuthProviderError);
  });

  it("accepts a valid array audience claim without ambient array membership", async () => {
    const current = await flow();
    const code = fixture.issue({
      challenge: current.challenge,
      redirect: CALLBACK,
      nonce: current.nonce,
      scenario: { audience: [CLIENT_ID] },
    });
    const originalIncludes = Array.prototype.includes;
    let thrown: unknown;
    try {
      Array.prototype.includes = function (this: unknown[], candidate: unknown): boolean {
        const stack = new Error().stack ?? "";
        if (stack.includes("profileFromClaims") && candidate === CLIENT_ID) {
          throw new Error("provider-audience-includes-sentinel");
        }
        return originalIncludes.call(this, candidate);
      } as typeof Array.prototype.includes;
      await current.provider.exchange(exchangeInput({ code, state: current.state, nonce: current.nonce }));
    } catch (error) {
      thrown = error;
    } finally {
      Array.prototype.includes = originalIncludes;
    }
    expect(thrown).toBeUndefined();
  });

  it("rejects an ID token signed by a key absent from discovered JWKS", async () => {
    const rogue = await generateKeyPair("ES256");
    const current = await flow();
    const code = fixture.issue({
      challenge: current.challenge,
      redirect: CALLBACK,
      nonce: current.nonce,
      scenario: { signingKey: rogue.privateKey },
    });
    await expect(current.provider.exchange(exchangeInput({ code, state: current.state, nonce: current.nonce })))
      .rejects.toBeInstanceOf(OAuthProviderError);
  });
});
