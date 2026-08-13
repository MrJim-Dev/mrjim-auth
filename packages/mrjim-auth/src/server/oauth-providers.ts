import { createHmac } from "node:crypto";
import {
  authorizationCodeGrant,
  buildAuthorizationUrl,
  calculatePKCECodeChallenge,
  ClientSecretPost,
  customFetch,
  discovery,
  enableNonRepudiationChecks,
  randomNonce,
  type CustomFetch,
  type Configuration,
} from "openid-client";
import { sanitizeIdentityData, type SafeIdentityData } from "../shared/types.js";
import {
  assertBoundaryObject,
  captureBoundaryFunction,
  captureBoundaryStringArray,
  optionalBoundaryOption,
  requiredBoundaryOption,
} from "./callback-boundary.js";
import {
  safeStringToLowerCase,
  safeStringTrim,
  safeSetPrototypeOf,
} from "../shared/safe-intrinsics.js";

const oauthArrayIsArray = Array.isArray;

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
  /** State returned by the provider callback. */
  readonly state: string;
  /** Independently persisted state expectation. */
  readonly expectedState: string;
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

  constructor(_message = "OAuth provider exchange failed", _options?: ErrorOptions) {
    super("OAuth provider exchange failed");
    safeSetPrototypeOf(this, new.target.prototype);
  }
}

interface OidcProviderOptions {
  readonly name: string;
  readonly clientId: string;
  readonly clientSecret: string;
  readonly issuer: string;
  readonly scopes?: readonly string[];
  /** Optional project-owned fetch implementation, useful for private/self-hosted issuers. */
  readonly customFetch?: CustomFetch;
}

function captureGoogleOptions(value: unknown): { readonly clientId: unknown; readonly clientSecret: unknown } {
  if (value === null || typeof value !== "object") {
    throw new TypeError("Google provider options are incomplete");
  }
  const source = value as object;
  assertBoundaryObject(source, "Google provider options");
  return {
    clientId: requiredBoundaryOption(source, "clientId", "Google client ID"),
    clientSecret: requiredBoundaryOption(source, "clientSecret", "Google client secret"),
  };
}

function captureFacebookOptions(value: unknown): { readonly clientId: unknown; readonly clientSecret: unknown; readonly customFetch?: unknown } {
  if (value === null || typeof value !== "object") {
    throw new TypeError("Facebook provider options are incomplete");
  }
  const source = value as object;
  assertBoundaryObject(source, "Facebook provider options");
  const customFetch = optionalBoundaryOption(source, "customFetch", "Facebook custom fetch");
  return {
    clientId: requiredBoundaryOption(source, "clientId", "Facebook client ID"),
    clientSecret: requiredBoundaryOption(source, "clientSecret", "Facebook client secret"),
    ...(customFetch === undefined ? {} : { customFetch }),
  };
}

function validString(value: unknown, label: string): string {
  if (typeof value !== "string" || safeStringTrim(value) === null || safeStringTrim(value) === "") {
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
  if (parsed.protocol !== "https:") {
    throw new TypeError("OIDC issuer must use HTTPS");
  }
  if (parsed.hash !== "" || parsed.search !== "") {
    throw new TypeError("OIDC issuer must not contain a query or fragment");
  }
  return issuer;
}

function safeEmail(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const trimmed = safeStringTrim(value);
  return trimmed === null || trimmed === "" ? null : trimmed;
}

function containsString(values: readonly string[], candidate: string): boolean {
  for (let index = 0; index < values.length; index += 1) {
    if (values[index] === candidate) return true;
  }
  return false;
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
  if (issuer !== expectedIssuer || typeof subject !== "string" || safeStringTrim(subject) === null || safeStringTrim(subject) === "") {
    throw new OAuthProviderError("OIDC issuer or subject validation failed");
  }
  const audiences = typeof audience === "string" ? [audience] : oauthArrayIsArray(audience) ? audience as string[] : [];
  if (!containsString(audiences, clientId)) {
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
  private readonly providerFetch: CustomFetch | undefined;
  private configurationPromise: Promise<Configuration> | undefined;

  constructor(options: OidcProviderOptions) {
    if (options === null || typeof options !== "object") throw new TypeError("OIDC provider options are incomplete");
    const source = options as unknown as object;
    assertBoundaryObject(source, "OIDC provider options");
    const nameValue = requiredBoundaryOption(source, "name", "OIDC provider name");
    const clientIdValue = requiredBoundaryOption(source, "clientId", "OIDC client ID");
    const clientSecretValue = requiredBoundaryOption(source, "clientSecret", "OIDC client secret");
    const issuerValue = requiredBoundaryOption(source, "issuer", "OIDC issuer");
    const scopesValue = optionalBoundaryOption(source, "scopes", "OIDC scopes");
    const customFetchValue = optionalBoundaryOption(source, "customFetch", "OIDC custom fetch");
    const normalizedName = safeStringTrim(validString(nameValue, "OIDC provider name"));
    const lowerName = normalizedName === null ? null : safeStringToLowerCase(normalizedName);
    if (lowerName === null) throw new TypeError("OIDC provider name must be non-empty");
    this.name = lowerName;
    this.clientId = validString(clientIdValue, "OIDC client ID");
    this.clientSecret = validString(clientSecretValue, "OIDC client secret");
    this.issuer = asIssuer(issuerValue);
    this.providerFetch = customFetchValue === undefined
      ? undefined
      : captureBoundaryFunction(customFetchValue, "OIDC custom fetch") as CustomFetch;
    this.scopes = captureBoundaryStringArray(scopesValue ?? ["openid", "email", "profile"], "OIDC scopes", 1) as readonly string[];
    if (!containsString(this.scopes, "openid")) {
      throw new TypeError("OIDC scopes must include openid");
    }
  }

  /** Performs issuer discovery lazily so construction is deterministic/offline. */
  protected async configuration(): Promise<Configuration> {
    const discoveryOptions = this.providerFetch === undefined
      ? { execute: [enableNonRepudiationChecks] }
      : { execute: [enableNonRepudiationChecks], [customFetch]: this.providerFetch };
    this.configurationPromise ??= discovery(
      new URL(this.issuer),
      this.clientId,
      { client_secret: this.clientSecret },
      ClientSecretPost(this.clientSecret),
      discoveryOptions,
    );
    return this.configurationPromise;
  }

  async authorizationUrl(input: OAuthProviderAuthorizationInput): Promise<string> {
    try {
      if (input.codeChallengeMethod !== "S256") {
        throw new OAuthProviderError("Only PKCE S256 is supported");
      }
      if (input.clientId !== this.clientId) {
        throw new OAuthProviderError("OAuth client ID does not match provider configuration");
      }
      const scopes = captureBoundaryStringArray(input.scopes, "OIDC authorization scopes", 1, 128);
      let scope = "";
      for (let index = 0; index < scopes.length; index += 1) {
        const value = scopes[index];
        if (value === undefined) throw new OAuthProviderError();
        if (index > 0) scope += " ";
        scope += value;
      }
      const config = await this.configuration();
      const url = buildAuthorizationUrl(config, {
        client_id: this.clientId,
        redirect_uri: input.redirectUri,
        response_type: "code",
        scope,
        state: input.state,
        nonce: input.nonce,
        code_challenge: input.codeChallenge,
        code_challenge_method: "S256",
      });
      return url.toString();
    } catch (error) {
      if (error instanceof OAuthProviderError) throw error;
      throw new OAuthProviderError();
    }
  }

  async exchange(input: OAuthProviderExchangeInput): Promise<OAuthProviderProfile> {
    try {
      if (!/^[A-Za-z0-9._~-]{43,128}$/.test(input.codeVerifier)) {
        throw new OAuthProviderError("Invalid PKCE verifier");
      }
      const config = await this.configuration();
      const responseUrl = new URL(input.redirectUri);
      responseUrl.searchParams.set("code", input.code);
      responseUrl.searchParams.set("state", input.state);
      const tokens = await authorizationCodeGrant(config, responseUrl, {
        expectedState: input.expectedState,
        expectedNonce: input.nonce,
        pkceCodeVerifier: input.codeVerifier,
        idTokenExpected: true,
      });
      const claims = tokens.claims();
      if (claims === undefined) throw new OAuthProviderError("OIDC ID token is missing");
      return profileFromClaims(this.name, this.issuer, this.clientId, claims as Record<string, unknown>);
    } catch (error) {
      if (error instanceof OAuthProviderError) throw error;
      throw new OAuthProviderError("OIDC validation failed");
    }
  }
}

/** Google OpenID Connect adapter with the required identity scopes. */
export class GoogleOAuthProvider extends OidcOAuthProvider {
  constructor(options: { readonly clientId: string; readonly clientSecret: string }) {
    const captured = captureGoogleOptions(options);
    super({
      name: "google",
      clientId: captured.clientId as string,
      clientSecret: captured.clientSecret as string,
      issuer: "https://accounts.google.com",
      scopes: ["openid", "email", "profile"],
    });
  }
}

/** Facebook Login adapter using the authorization-code flow and Graph API. */
export class FacebookOAuthProvider implements OAuthProvider {
  readonly name = "facebook";
  readonly issuer = "https://www.facebook.com";
  readonly scopes = ["email", "public_profile"] as const;
  readonly capabilities: OAuthProviderCapabilities = {
    authorization_code: true,
    pkce: true,
    identity_linking: true,
  };

  readonly clientId: string;
  private readonly clientSecret: string;
  private readonly providerFetch: typeof fetch;

  constructor(options: { readonly clientId: string; readonly clientSecret: string; readonly customFetch?: typeof fetch }) {
    const captured = captureFacebookOptions(options);
    this.clientId = validString(captured.clientId, "Facebook client ID");
    this.clientSecret = validString(captured.clientSecret, "Facebook client secret");
    this.providerFetch = captured.customFetch === undefined
      ? fetch
      : captureBoundaryFunction(captured.customFetch, "Facebook custom fetch") as typeof fetch;
  }

  async authorizationUrl(input: OAuthProviderAuthorizationInput): Promise<string> {
    try {
      if (input.codeChallengeMethod !== "S256") throw new OAuthProviderError("Invalid PKCE method");
      const url = new URL("https://www.facebook.com/dialog/oauth");
      url.searchParams.set("client_id", input.clientId);
      url.searchParams.set("redirect_uri", input.redirectUri);
      url.searchParams.set("state", input.state);
      url.searchParams.set("response_type", "code");
      url.searchParams.set("scope", input.scopes.join(","));
      url.searchParams.set("code_challenge", input.codeChallenge);
      url.searchParams.set("code_challenge_method", "S256");
      return url.toString();
    } catch (error) {
      if (error instanceof OAuthProviderError) throw error;
      throw new OAuthProviderError();
    }
  }

  async exchange(input: OAuthProviderExchangeInput): Promise<OAuthProviderProfile> {
    try {
      if (!/^[A-Za-z0-9._~-]{43,128}$/.test(input.codeVerifier)) {
        throw new OAuthProviderError("Invalid PKCE verifier");
      }
      const tokenUrl = new URL("https://graph.facebook.com/oauth/access_token");
      tokenUrl.searchParams.set("client_id", this.clientId);
      tokenUrl.searchParams.set("client_secret", this.clientSecret);
      tokenUrl.searchParams.set("redirect_uri", input.redirectUri);
      tokenUrl.searchParams.set("code", input.code);
      tokenUrl.searchParams.set("code_verifier", input.codeVerifier);
      const tokenResponse = await this.providerFetch(tokenUrl, { method: "GET", headers: { accept: "application/json" } });
      const tokenPayload: unknown = await tokenResponse.json();
      if (!tokenResponse.ok || tokenPayload === null || typeof tokenPayload !== "object" || Array.isArray(tokenPayload)) {
        throw new OAuthProviderError("Facebook token exchange failed");
      }
      const accessToken = (tokenPayload as Record<string, unknown>).access_token;
      if (typeof accessToken !== "string" || accessToken.length < 1 || accessToken.length > 4096) {
        throw new OAuthProviderError("Facebook access token is malformed");
      }

      const appSecretProof = createHmac("sha256", this.clientSecret).update(accessToken, "utf8").digest("hex");
      const profileUrl = new URL("https://graph.facebook.com/me");
      profileUrl.searchParams.set("fields", "id,name,email,picture");
      profileUrl.searchParams.set("access_token", accessToken);
      profileUrl.searchParams.set("appsecret_proof", appSecretProof);
      const profileResponse = await this.providerFetch(profileUrl, { method: "GET", headers: { accept: "application/json" } });
      const profilePayload: unknown = await profileResponse.json();
      if (!profileResponse.ok || profilePayload === null || typeof profilePayload !== "object" || Array.isArray(profilePayload)) {
        throw new OAuthProviderError("Facebook profile request failed");
      }
      const profile = profilePayload as Record<string, unknown>;
      const subject = profile.id;
      if (typeof subject !== "string" || subject.trim() === "") throw new OAuthProviderError("Facebook subject is missing");
      const email = typeof profile.email === "string" && profile.email.trim() !== "" ? profile.email : null;
      const pictureData = profile.picture;
      const picture = pictureData !== null && typeof pictureData === "object" && !Array.isArray(pictureData)
        ? (pictureData as Record<string, unknown>).data
        : undefined;
      const pictureUrl = picture !== null && typeof picture === "object" && !Array.isArray(picture)
        ? (picture as Record<string, unknown>).url
        : undefined;
      const emailVerified = profile.email_verified === true || profile.verified === true;
      return {
        provider: this.name,
        subject,
        issuer: this.issuer,
        email,
        emailVerified,
        claims: sanitizeIdentityData({
          sub: subject,
          email: email ?? undefined,
          email_verified: email === null ? undefined : emailVerified,
          name: typeof profile.name === "string" ? profile.name : undefined,
          picture: typeof pictureUrl === "string" ? pictureUrl : undefined,
        }),
      };
    } catch (error) {
      if (error instanceof OAuthProviderError) throw error;
      throw new OAuthProviderError("Facebook validation failed");
    }
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
