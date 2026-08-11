import {
  authorizationCodeGrant,
  buildAuthorizationUrl,
  calculatePKCECodeChallenge,
  ClientSecretPost,
  discovery,
  randomNonce,
  type Configuration,
} from "openid-client";
import { sanitizeIdentityData, type SafeIdentityData } from "../shared/types.js";

/** A stable public capability advertised by provider discovery. */
export interface OAuthProviderCapabilities {
  readonly authorization_code: true;
  readonly pkce: true;
  readonly identity_linking: true;
}

/** Inputs supplied by OAuthService to a provider's authorization endpoint. */
export interface OAuthProviderAuthorizationInput {
  readonly clientId: string;
  readonly redirectUri: string;
  readonly state: string;
  readonly nonce: string;
  readonly scopes: readonly string[];
  readonly codeChallenge: string;
  readonly codeChallengeMethod: "S256";
}

/** Inputs supplied by OAuthService to a provider's code-exchange adapter. */
export interface OAuthProviderExchangeInput {
  readonly code: string;
  readonly state: string;
  readonly redirectUri: string;
  readonly codeVerifier: string;
  readonly nonce: string;
}

/** Sanitized identity claims returned after provider validation. */
export interface OAuthProviderProfile {
  readonly provider: string;
  readonly subject: string;
  readonly issuer: string;
  readonly email: string | null;
  readonly emailVerified: boolean;
  readonly claims: SafeIdentityData;
}

/** Provider adapter contract; adapters never return provider credentials. */
export interface OAuthProvider {
  /** Stable lower-case provider key used in identity uniqueness. */
  readonly name: string;
  /** Public OAuth client identifier used only to build the authorization URL. */
  readonly clientId: string;
  /** Configured issuer, when the adapter has a fixed OIDC issuer. */
  readonly issuer?: string;
  /** Requested provider scopes. */
  readonly scopes: readonly string[];
  /** Safe public capability flags. */
  readonly capabilities: OAuthProviderCapabilities;
  /** Builds an authorization-code URL with PKCE S256. */
  authorizationUrl(input: OAuthProviderAuthorizationInput): string | Promise<string>;
  /** Exchanges and validates a provider code, returning safe profile claims only. */
  exchange(input: OAuthProviderExchangeInput): Promise<OAuthProviderProfile>;
}

/** Error classification used to conceal provider protocol details. */
export class OAuthProviderError extends Error {
  readonly name = "OAuthProviderError" as const;

  constructor(message = "OAuth provider exchange failed", options?: ErrorOptions) {
    super(message, options);
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

interface OidcProviderOptions {
  readonly name: string;
  readonly clientId: string;
  readonly clientSecret: string;
  readonly issuer: string;
  readonly scopes?: readonly string[];
}

function validString(value: unknown, label: string): string {
  if (typeof value !== "string" || value.trim() === "") {
    throw new TypeError(`${label} must be non-empty`);
  }
  return value;
}

function asIssuer(value: unknown): string {
  const issuer = validString(value, "OIDC issuer");
  let parsed: URL;
  try {
    parsed = new URL(issuer);
  } catch {
    throw new TypeError("OIDC issuer must be an absolute URL");
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw new TypeError("OIDC issuer must use http or https");
  }
  if (parsed.hash !== "" || parsed.search !== "") {
    throw new TypeError("OIDC issuer must not contain a query or fragment");
  }
  return issuer;
}

function safeEmail(value: unknown): string | null {
  return typeof value === "string" && value.trim() !== "" ? value.trim() : null;
}

function profileFromClaims(
  provider: string,
  expectedIssuer: string,
  clientId: string,
  claims: Record<string, unknown>,
): OAuthProviderProfile {
  const issuer = claims.iss;
  const subject = claims.sub;
  const audience = claims.aud;
  if (issuer !== expectedIssuer || typeof subject !== "string" || subject.trim() === "") {
    throw new OAuthProviderError("OIDC issuer or subject validation failed");
  }
  const audiences = typeof audience === "string" ? [audience] : Array.isArray(audience) ? audience : [];
  if (!audiences.includes(clientId)) {
    throw new OAuthProviderError("OIDC audience validation failed");
  }
  const email = safeEmail(claims.email);
  const emailVerified = claims.email_verified === true;
  return {
    provider,
    subject,
    issuer,
    email,
    emailVerified,
    claims: sanitizeIdentityData({
      sub: subject,
      email: email ?? undefined,
      email_verified: email === null ? undefined : emailVerified,
      name: claims.name,
      given_name: claims.given_name,
      family_name: claims.family_name,
      picture: claims.picture,
      locale: claims.locale,
      hd: claims.hd,
      preferred_username: claims.preferred_username,
    }),
  };
}

/**
 * Generic OIDC discovery-backed provider adapter.
 *
 * `openid-client` performs issuer, authorization-code, ID-token signature,
 * audience, nonce, and PKCE validation. The adapter applies an additional
 * exact issuer/audience/subject check before returning a safe profile.
 */
export class OidcOAuthProvider implements OAuthProvider {
  readonly name: string;
  readonly clientId: string;
  readonly issuer: string;
  readonly scopes: readonly string[];
  readonly capabilities: OAuthProviderCapabilities = {
    authorization_code: true,
    pkce: true,
    identity_linking: true,
  };

  private readonly clientSecret: string;
  private configurationPromise: Promise<Configuration> | undefined;

  constructor(options: OidcProviderOptions) {
    this.name = validString(options.name, "OIDC provider name").trim().toLowerCase();
    this.clientId = validString(options.clientId, "OIDC client ID");
    this.clientSecret = validString(options.clientSecret, "OIDC client secret");
    this.issuer = asIssuer(options.issuer);
    this.scopes = Object.freeze([...(options.scopes ?? ["openid", "email", "profile"])]) as readonly string[];
    if (!this.scopes.includes("openid")) {
      throw new TypeError("OIDC scopes must include openid");
    }
  }

  /** Performs issuer discovery lazily so construction is deterministic/offline. */
  protected async configuration(): Promise<Configuration> {
    this.configurationPromise ??= discovery(
      new URL(this.issuer),
      this.clientId,
      { client_secret: this.clientSecret },
      ClientSecretPost(this.clientSecret),
    );
    return this.configurationPromise;
  }

  async authorizationUrl(input: OAuthProviderAuthorizationInput): Promise<string> {
    if (input.codeChallengeMethod !== "S256") {
      throw new OAuthProviderError("Only PKCE S256 is supported");
    }
    if (input.clientId !== this.clientId) {
      throw new OAuthProviderError("OAuth client ID does not match provider configuration");
    }
    const config = await this.configuration();
    const url = buildAuthorizationUrl(config, {
      client_id: this.clientId,
      redirect_uri: input.redirectUri,
      response_type: "code",
      scope: input.scopes.join(" "),
      state: input.state,
      nonce: input.nonce,
      code_challenge: input.codeChallenge,
      code_challenge_method: "S256",
    });
    return url.toString();
  }

  async exchange(input: OAuthProviderExchangeInput): Promise<OAuthProviderProfile> {
    if (!/^[A-Za-z0-9._~-]{43,128}$/.test(input.codeVerifier)) {
      throw new OAuthProviderError("Invalid PKCE verifier");
    }
    const config = await this.configuration();
    const responseUrl = new URL(input.redirectUri);
    responseUrl.searchParams.set("code", input.code);
    responseUrl.searchParams.set("state", input.state);
    try {
      const tokens = await authorizationCodeGrant(config, responseUrl, {
        expectedState: input.state,
        expectedNonce: input.nonce,
        pkceCodeVerifier: input.codeVerifier,
        idTokenExpected: true,
      });
      const claims = tokens.claims();
      if (claims === undefined) throw new OAuthProviderError("OIDC ID token is missing");
      return profileFromClaims(this.name, this.issuer, this.clientId, claims as Record<string, unknown>);
    } catch (error) {
      if (error instanceof OAuthProviderError) throw error;
      throw new OAuthProviderError("OIDC validation failed", { cause: error });
    }
  }
}

/** Google OpenID Connect adapter with the required identity scopes. */
export class GoogleOAuthProvider extends OidcOAuthProvider {
  constructor(options: { readonly clientId: string; readonly clientSecret: string }) {
    super({
      name: "google",
      clientId: options.clientId,
      clientSecret: options.clientSecret,
      issuer: "https://accounts.google.com",
      scopes: ["openid", "email", "profile"],
    });
  }
}

/** Compatibility alias using the specification's generic-provider wording. */
export const GenericOidcProvider = OidcOAuthProvider;

/** Generates a nonce for deterministic/custom provider adapters. */
export function generateProviderNonce(): string {
  return randomNonce();
}

/** Uses the same S256 implementation as the OIDC adapter for provider tests. */
export const providerCodeChallenge = calculatePKCECodeChallenge;
