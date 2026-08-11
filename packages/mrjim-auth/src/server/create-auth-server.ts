import type { AuthRepository, KeyMaterial, KeyProvider } from "../shared/contracts.js";
import { authServerOptionsSchema, type AuthServerOptions } from "../shared/config.js";
import { AuthConfigurationError } from "../shared/errors.js";
import {
  AuthorizationService,
  type AuthorizationServiceOptions,
} from "./authorization.js";
import { EmailService } from "./email.js";
import { OneTimeTokenService } from "./one-time-tokens.js";
import { OAuthService } from "./oauth.js";
import { GoogleOAuthProvider, OidcOAuthProvider, type OAuthProvider } from "./oauth-providers.js";
import { PasswordService } from "./passwords.js";
import { SessionService } from "./sessions.js";
import { TokenService } from "./tokens.js";
import { UserService } from "./users.js";
import {
  AuthServer,
  captureAuthServerMailer,
  captureAuthServerRateLimiter,
  captureAuthServerRepository,
  captureAuthServerServices,
  type AuthServerRuntimeOptions,
} from "./auth-server.js";
import type { AuthServerServices } from "./routes/contracts.js";

/** Optional service seams used by tests and by projects that compose services themselves. */
export type AuthServerServiceOverrides = Partial<AuthServerServices>;

/** Public synchronous construction options for the framework-neutral server. */
export type CreateAuthServerOptions = AuthServerOptions & {
  readonly services?: AuthServerServiceOverrides;
};

function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null ? value as Record<string, unknown> : null;
}

const SERVER_OPTION_MEMBERS = [
  "environment",
  "baseUrl",
  "siteUrl",
  "database",
  "signingKeys",
  "secrets",
  "email",
  "rateLimiter",
  "oauth",
  "redirects",
  "authorization",
  "accessTokenTtlSeconds",
  "refreshTokenTtlSeconds",
] as const;

function dataOptionMember(source: object, member: string): unknown {
  let descriptor: PropertyDescriptor | undefined;
  try {
    descriptor = Object.getOwnPropertyDescriptor(source, member);
  } catch {
    throw new AuthConfigurationError(`auth server ${member} must be a data property`);
  }
  if (descriptor === undefined) return undefined;
  if (!("value" in descriptor)) throw new AuthConfigurationError(`auth server ${member} must be a data property`);
  return descriptor.value;
}

/** Captures all configured executable adapters before Zod inspects them. */
function captureConfiguredCallbacks(input: CreateAuthServerOptions): CreateAuthServerOptions {
  const source = asRecord(input);
  if (source === null) throw new AuthConfigurationError("auth server configuration must be an object");
  const captured = Object.create(null) as Record<string, unknown>;
  for (const member of SERVER_OPTION_MEMBERS) {
    const value = dataOptionMember(source, member);
    if (value !== undefined) captured[member] = value;
  }
  captured.database = captureAuthServerRepository(dataOptionMember(source, "database") as AuthRepository);
  captured.email = captureAuthServerMailer(dataOptionMember(source, "email") as AuthServerOptions["email"]);
  const rateLimiter = dataOptionMember(source, "rateLimiter");
  if (rateLimiter !== undefined) captured.rateLimiter = captureAuthServerRateLimiter(rateLimiter as NonNullable<AuthServerOptions["rateLimiter"]>);
  return captured as CreateAuthServerOptions;
}

function parseAbsoluteUrl(value: string, label: string): URL {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new AuthConfigurationError(`${label} must be an absolute URL`);
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:" || parsed.username !== "" || parsed.password !== "" || parsed.search !== "" || parsed.hash !== "") {
    throw new AuthConfigurationError(`${label} must be a credential-free HTTP(S) URL without a query or fragment`);
  }
  return parsed;
}

function normalizedBasePath(baseUrl: URL): string {
  const path = baseUrl.pathname.replace(/\/+$/u, "");
  return path === "" || path === "/" ? "/auth/v1" : path;
}

function secretString(value: string | Uint8Array): string {
  if (typeof value === "string") return value;
  return Buffer.from(value).toString("base64url");
}

function keyProvider(options: AuthServerOptions): KeyProvider {
  const configured = options.signingKeys.keys;
  const activeKeyId = options.signingKeys.activeKeyId;
  const verificationKeys = new Map<string, KeyMaterial>(Object.entries(configured));
  return {
    getActiveKeyId: () => activeKeyId,
    getSigningKey: (keyId) => {
      const material = configured[keyId];
      if (material === undefined) throw new AuthConfigurationError(`signing key is not configured: ${keyId}`);
      return material;
    },
    getVerificationKeys: () => new Map(verificationKeys),
  };
}

function createProviders(options: AuthServerOptions): readonly OAuthProvider[] {
  const configured = options.oauth;
  if (configured === undefined) return [];
  const providers: OAuthProvider[] = [];
  if (configured.google !== undefined) {
    providers.push(new GoogleOAuthProvider({
      clientId: configured.google.clientId,
      clientSecret: secretString(configured.google.clientSecret),
    }));
  }
  if (configured.oidc !== undefined) {
    providers.push(new OidcOAuthProvider({
      name: "oidc",
      clientId: configured.oidc.clientId,
      clientSecret: secretString(configured.oidc.clientSecret),
      issuer: configured.oidc.issuer,
      ...(configured.oidc.scopes === undefined ? {} : { scopes: configured.oidc.scopes }),
    }));
  }
  return providers;
}

function createDefaultServices(
  options: AuthServerOptions,
  repository: AuthRepository,
  clock: () => Date,
  allowedRedirects: readonly string[],
): AuthServerServices {
  const defaultRedirect = allowedRedirects[0];
  if (defaultRedirect === undefined) throw new AuthConfigurationError("at least one redirect is required");
  const email = new EmailService({
    allowedRedirects,
    defaultRedirect,
  });
  const tokens = new TokenService({
    issuer: options.signingKeys.issuer,
    audience: options.signingKeys.audience,
    keyProvider: keyProvider(options),
    tokenHashKey: options.secrets.tokenHashKey,
    accessTokenTtlSeconds: options.accessTokenTtlSeconds,
    clock,
  });
  const sessions = new SessionService({
    repository,
    tokens,
    refreshTokenTtlSeconds: options.refreshTokenTtlSeconds,
    clock,
  });
  const oneTimeTokens = new OneTimeTokenService({
    repository,
    mailer: options.email,
    email,
    tokenHashKey: options.secrets.tokenHashKey,
    allowedRedirects,
    defaultRedirect,
    clock,
  });
  const passwords = new PasswordService();
  const users = new UserService({
    repository,
    passwords,
    email,
    mailer: options.email,
    oneTimeTokens,
    sessions,
    ...(options.rateLimiter === undefined ? {} : { rateLimiter: options.rateLimiter }),
    ...(options.authorization?.defaultRoleKeys === undefined ? {} : { defaultRoleKeys: options.authorization.defaultRoleKeys }),
    clock,
  });
  const authorizationOptions: AuthorizationServiceOptions = { repository, clock };
  const authorization = new AuthorizationService(authorizationOptions);
  const providers = createProviders(options);
  const oauth = providers.length === 0 ? undefined : new OAuthService({
    repository,
    sessions,
    providers,
    tokenHashKey: options.secrets.tokenHashKey,
    encryptionKey: options.secrets.encryptionKey,
    allowedRedirects,
    defaultRedirect,
    ...(options.authorization?.defaultRoleKeys === undefined ? {} : { defaultRoleKeys: options.authorization.defaultRoleKeys }),
    clock,
  });
  return {
    users,
    sessions,
    tokens,
    authorization,
    ...(oauth === undefined ? {} : { oauth }),
  };
}

function mergeServices(defaults: AuthServerServices, overrides: AuthServerServiceOverrides | undefined): AuthServerServices {
  const merged: Record<string, unknown> = {
    users: defaults.users,
    sessions: defaults.sessions,
    tokens: defaults.tokens,
    authorization: defaults.authorization,
    ...(defaults.oauth === undefined ? {} : { oauth: defaults.oauth }),
  };
  if (overrides !== undefined) {
    const source = asRecord(overrides);
    if (source === null) throw new AuthConfigurationError("auth server service composition is incomplete");
    for (const member of ["users", "sessions", "tokens", "authorization", "oauth"] as const) {
      let descriptor: PropertyDescriptor | undefined;
      try {
        descriptor = Object.getOwnPropertyDescriptor(source, member);
      } catch {
        throw new AuthConfigurationError("auth server service composition is incomplete");
      }
      if (descriptor === undefined) continue;
      if (!("value" in descriptor)) throw new AuthConfigurationError(`auth server ${member} must be a data property`);
      merged[member] = descriptor.value;
    }
  }
  return captureAuthServerServices(merged as unknown as AuthServerServices);
}

/** Creates a fully validated, framework-neutral server synchronously. */
export function createAuthServer(input: CreateAuthServerOptions): AuthServer {
  const capturedInput = captureConfiguredCallbacks(input);
  const parsed = authServerOptionsSchema.parse(capturedInput);
  const raw = asRecord(input);
  let rawServices: AuthServerServiceOverrides | undefined;
  if (raw !== null) {
    const descriptor = Object.getOwnPropertyDescriptor(raw, "services");
    if (descriptor !== undefined) {
      if (!("value" in descriptor)) throw new AuthConfigurationError("auth server services must be a data property");
      rawServices = descriptor.value as AuthServerServiceOverrides | undefined;
    }
  }
  const baseUrl = parseAbsoluteUrl(parsed.baseUrl, "baseUrl");
  const issuer = parseAbsoluteUrl(parsed.signingKeys.issuer, "signingKeys.issuer");
  if (issuer.href !== baseUrl.href) throw new AuthConfigurationError("baseUrl must exactly match signingKeys.issuer");
  const siteUrl = parseAbsoluteUrl(parsed.siteUrl, "siteUrl");
  const basePath = normalizedBasePath(baseUrl);
  const baseOrigin = baseUrl.origin;
  const allowedOrigins = Object.freeze([...new Set([baseOrigin, siteUrl.origin])]);
  const allowedRedirects = Object.freeze([...parsed.redirects.allowed]);
  const clock = () => new Date();
  const repository = captureAuthServerRepository(parsed.database);
  const defaults = createDefaultServices(parsed, repository, clock, allowedRedirects);
  const services = mergeServices(defaults, rawServices);
  const runtime: AuthServerRuntimeOptions = {
    config: parsed,
    repository,
    services,
    apiKeyHashKey: typeof parsed.secrets.tokenHashKey === "string"
      ? new TextEncoder().encode(parsed.secrets.tokenHashKey)
      : Uint8Array.from(parsed.secrets.tokenHashKey),
    baseOrigin,
    basePath,
    allowedOrigins,
    allowedRedirects,
  };
  return new AuthServer(runtime);
}
