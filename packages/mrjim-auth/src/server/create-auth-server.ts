import { KeyObject } from "node:crypto";
import type { AuthRepository, KeyMaterial, KeyProvider } from "../shared/contracts.js";
import { authServerOptionsSchema, type AuthServerOptions } from "../shared/config.js";
import { AuthConfigurationError } from "../shared/errors.js";
import {
  boundaryHasThen,
  boundaryOwnDataProperty,
} from "./callback-boundary.js";
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

const configObjectGetPrototypeOf = Object.getPrototypeOf;
const configObjectGetOwnPropertyNames = Object.getOwnPropertyNames;
const configObjectGetOwnPropertySymbols = Object.getOwnPropertySymbols;
const configObjectDefineProperty = Object.defineProperty;
const configObjectCreate = Object.create;
const configObjectFreeze = Object.freeze;
const configArrayIsArray = Array.isArray;
const CONFIG_SNAPSHOT_MAX_DEPTH = 32;
const CONFIG_SNAPSHOT_MAX_KEYS = 100_000;
const configCryptoKeyConstructor = (globalThis as { readonly CryptoKey?: unknown }).CryptoKey;

function isConfigPlainRecord(value: unknown): value is object {
  if (value === null || typeof value !== "object" || configArrayIsArray(value)) return false;
  try {
    const prototype = configObjectGetPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
  } catch {
    return false;
  }
}

function rejectDangerousConfigValue(value: unknown, label: string): void {
  if (typeof value === "function") throw new AuthConfigurationError(`${label} must not be executable`);
  if (value !== null && typeof value === "object" && boundaryHasThen(value)) {
    throw new AuthConfigurationError(`${label} must not be thenable`);
  }
}

function assertConfigRecord(value: unknown, label: string): asserts value is object {
  if (!isConfigPlainRecord(value)) throw new AuthConfigurationError(`${label} must be a plain data record`);
  if (boundaryHasThen(value)) throw new AuthConfigurationError(`${label} must not be thenable`);
  let names: string[];
  try {
    names = configObjectGetOwnPropertyNames(value);
    if (configObjectGetOwnPropertySymbols(value).length > 0) {
      throw new AuthConfigurationError(`${label} must not contain symbol properties`);
    }
  } catch (error) {
    if (error instanceof AuthConfigurationError) throw error;
    throw new AuthConfigurationError(`${label} must be a data record`);
  }
  if (names.length > CONFIG_SNAPSHOT_MAX_KEYS) throw new AuthConfigurationError(`${label} is too large`);
  for (const name of names) {
    const property = boundaryOwnDataProperty(value, name);
    if (!property.valid || !property.present) throw new AuthConfigurationError(`${label}.${name} must be a data property`);
    rejectDangerousConfigValue(property.value, `${label}.${name}`);
  }
}

function configMember(value: object, key: string, label: string, required = true): unknown {
  const property = boundaryOwnDataProperty(value, key);
  if (!property.valid || (required && !property.present)) {
    throw new AuthConfigurationError(`${label} must be a data property`);
  }
  return property.present ? property.value : undefined;
}

function snapshotBytes(value: unknown, label: string): Uint8Array {
  if (!(value instanceof Uint8Array) || boundaryHasThen(value)) {
    throw new AuthConfigurationError(`${label} must be non-empty key material`);
  }
  const copy = Uint8Array.from(value);
  if (copy.byteLength === 0) throw new AuthConfigurationError(`${label} must be non-empty key material`);
  return copy;
}

function isOpaqueKeyMaterial(value: object): boolean {
  try {
    if (value instanceof KeyObject) return true;
    return typeof configCryptoKeyConstructor === "function" && value instanceof (configCryptoKeyConstructor as Function);
  } catch {
    return false;
  }
}

function snapshotOwnedValue(value: unknown, label: string, depth = 0): unknown {
  if (depth > CONFIG_SNAPSHOT_MAX_DEPTH) throw new AuthConfigurationError(`${label} is too deeply nested`);
  if (value === null || (typeof value !== "object" && typeof value !== "function")) return value;
  if (typeof value === "function") throw new AuthConfigurationError(`${label} must not be executable`);
  if (value instanceof Uint8Array) return snapshotBytes(value, label);
  if (configArrayIsArray(value)) {
    if (boundaryHasThen(value)) throw new AuthConfigurationError(`${label} must not be thenable`);
    const lengthProperty = boundaryOwnDataProperty(value, "length");
    if (!lengthProperty.valid || !lengthProperty.present || typeof lengthProperty.value !== "number" || !Number.isSafeInteger(lengthProperty.value) || lengthProperty.value > CONFIG_SNAPSHOT_MAX_KEYS) {
      throw new AuthConfigurationError(`${label} must be a bounded dense array`);
    }
    const length = lengthProperty.value as number;
    const names = configObjectGetOwnPropertyNames(value);
    if (names.length !== length + 1 || names.some((name) => name !== "length" && (!/^\d+$/u.test(name) || Number(name) >= length))) {
      throw new AuthConfigurationError(`${label} must be a bounded dense array`);
    }
    const copy: unknown[] = [];
    for (let index = 0; index < length; index += 1) {
      const property = boundaryOwnDataProperty(value, String(index));
      if (!property.valid || !property.present) throw new AuthConfigurationError(`${label} must be a dense array`);
      copy.push(snapshotOwnedValue(property.value, `${label}[${index}]`, depth + 1));
    }
    return configObjectFreeze(copy);
  }
  if (isOpaqueKeyMaterial(value)) return value;
  assertConfigRecord(value, label);
  const copy = configObjectCreate(null) as Record<string, unknown>;
  for (const name of configObjectGetOwnPropertyNames(value)) {
    const property = boundaryOwnDataProperty(value, name);
    if (!property.valid || !property.present) throw new AuthConfigurationError(`${label}.${name} must be a data property`);
    configObjectDefineProperty(copy, name, {
      configurable: false,
      enumerable: true,
      writable: false,
      value: snapshotOwnedValue(property.value, `${label}.${name}`, depth + 1),
    });
  }
  return configObjectFreeze(copy);
}

function snapshotKeyMaterial(value: unknown, label: string): KeyMaterial {
  const snapshot = snapshotOwnedValue(value, label);
  if (
    typeof snapshot === "string" ||
    snapshot instanceof Uint8Array ||
    isOpaqueKeyMaterial(snapshot as object) ||
    isConfigPlainRecord(snapshot)
  ) return snapshot as KeyMaterial;
  throw new AuthConfigurationError(`${label} must be valid key material`);
}

function snapshotKeyMap(value: unknown, label: string): Readonly<Record<string, KeyMaterial>> {
  assertConfigRecord(value, label);
  const copy = configObjectCreate(null) as Record<string, KeyMaterial>;
  for (const name of configObjectGetOwnPropertyNames(value)) {
    const property = boundaryOwnDataProperty(value, name);
    if (!property.valid || !property.present) throw new AuthConfigurationError(`${label}.${name} must be a data property`);
    configObjectDefineProperty(copy, name, {
      configurable: false,
      enumerable: true,
      writable: false,
      value: snapshotKeyMaterial(property.value, `${label}.${name}`),
    });
  }
  if (configObjectGetOwnPropertyNames(copy).length === 0) throw new AuthConfigurationError(`${label} must not be empty`);
  return configObjectFreeze(copy);
}

function snapshotStringArray(value: unknown, label: string): readonly string[] {
  const snapshot = snapshotOwnedValue(value, label);
  if (!configArrayIsArray(snapshot) || snapshot.some((entry) => typeof entry !== "string")) {
    throw new AuthConfigurationError(`${label} must be a string array`);
  }
  return snapshot as readonly string[];
}

function snapshotSecret(value: unknown, label: string): string | Uint8Array {
  if (typeof value === "string") return value;
  return snapshotBytes(value, label);
}

function snapshotSigningKeys(value: unknown): Record<string, unknown> {
  assertConfigRecord(value, "signingKeys");
  const copy = configObjectCreate(null) as Record<string, unknown>;
  configObjectDefineProperty(copy, "issuer", { configurable: false, enumerable: true, writable: false, value: configMember(value, "issuer", "signingKeys.issuer") });
  configObjectDefineProperty(copy, "audience", { configurable: false, enumerable: true, writable: false, value: configMember(value, "audience", "signingKeys.audience") });
  configObjectDefineProperty(copy, "activeKeyId", { configurable: false, enumerable: true, writable: false, value: configMember(value, "activeKeyId", "signingKeys.activeKeyId") });
  configObjectDefineProperty(copy, "keys", { configurable: false, enumerable: true, writable: false, value: snapshotKeyMap(configMember(value, "keys", "signingKeys.keys"), "signingKeys.keys") });
  return configObjectFreeze(copy);
}

function snapshotSecrets(value: unknown): Record<string, unknown> {
  assertConfigRecord(value, "secrets");
  const copy = configObjectCreate(null) as Record<string, unknown>;
  configObjectDefineProperty(copy, "tokenHashKey", { configurable: false, enumerable: true, writable: false, value: snapshotSecret(configMember(value, "tokenHashKey", "secrets.tokenHashKey"), "secrets.tokenHashKey") });
  configObjectDefineProperty(copy, "encryptionKey", { configurable: false, enumerable: true, writable: false, value: snapshotSecret(configMember(value, "encryptionKey", "secrets.encryptionKey"), "secrets.encryptionKey") });
  return configObjectFreeze(copy);
}

function snapshotRedirects(value: unknown): Record<string, unknown> {
  assertConfigRecord(value, "redirects");
  const copy = configObjectCreate(null) as Record<string, unknown>;
  configObjectDefineProperty(copy, "allowed", { configurable: false, enumerable: true, writable: false, value: snapshotStringArray(configMember(value, "allowed", "redirects.allowed"), "redirects.allowed") });
  return configObjectFreeze(copy);
}

function snapshotAuthorization(value: unknown): Record<string, unknown> {
  assertConfigRecord(value, "authorization");
  const copy = configObjectCreate(null) as Record<string, unknown>;
  for (const key of ["defaultRoleKeys", "protectedRoleKeys"] as const) {
    const member = configMember(value, key, `authorization.${key}`, false);
    if (member !== undefined) configObjectDefineProperty(copy, key, { configurable: false, enumerable: true, writable: false, value: snapshotStringArray(member, `authorization.${key}`) });
  }
  const allowWildcards = configMember(value, "allowWildcards", "authorization.allowWildcards", false);
  if (allowWildcards !== undefined) configObjectDefineProperty(copy, "allowWildcards", { configurable: false, enumerable: true, writable: false, value: allowWildcards });
  return configObjectFreeze(copy);
}

function snapshotOAuthClient(value: unknown, label: string, oidc: boolean): Record<string, unknown> {
  assertConfigRecord(value, label);
  const copy = configObjectCreate(null) as Record<string, unknown>;
  configObjectDefineProperty(copy, "clientId", { configurable: false, enumerable: true, writable: false, value: configMember(value, "clientId", `${label}.clientId`) });
  configObjectDefineProperty(copy, "clientSecret", { configurable: false, enumerable: true, writable: false, value: snapshotSecret(configMember(value, "clientSecret", `${label}.clientSecret`), `${label}.clientSecret`) });
  if (oidc) {
    configObjectDefineProperty(copy, "issuer", { configurable: false, enumerable: true, writable: false, value: configMember(value, "issuer", `${label}.issuer`) });
    const scopes = configMember(value, "scopes", `${label}.scopes`, false);
    if (scopes !== undefined) configObjectDefineProperty(copy, "scopes", { configurable: false, enumerable: true, writable: false, value: snapshotStringArray(scopes, `${label}.scopes`) });
  }
  return configObjectFreeze(copy);
}

function snapshotOAuth(value: unknown): Record<string, unknown> {
  assertConfigRecord(value, "oauth");
  const copy = configObjectCreate(null) as Record<string, unknown>;
  const google = configMember(value, "google", "oauth.google", false);
  if (google !== undefined) configObjectDefineProperty(copy, "google", { configurable: false, enumerable: true, writable: false, value: snapshotOAuthClient(google, "oauth.google", false) });
  const oidc = configMember(value, "oidc", "oauth.oidc", false);
  if (oidc !== undefined) configObjectDefineProperty(copy, "oidc", { configurable: false, enumerable: true, writable: false, value: snapshotOAuthClient(oidc, "oauth.oidc", true) });
  return configObjectFreeze(copy);
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
  captured.signingKeys = snapshotSigningKeys(dataOptionMember(source, "signingKeys"));
  captured.secrets = snapshotSecrets(dataOptionMember(source, "secrets"));
  captured.redirects = snapshotRedirects(dataOptionMember(source, "redirects"));
  const authorization = dataOptionMember(source, "authorization");
  if (authorization !== undefined) captured.authorization = snapshotAuthorization(authorization);
  const oauth = dataOptionMember(source, "oauth");
  if (oauth !== undefined) captured.oauth = snapshotOAuth(oauth);
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
