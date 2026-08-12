import { KeyObject } from "node:crypto";
import type { AuthRepository, KeyMaterial, KeyProvider } from "../shared/contracts.js";
import { authServerOptionsSchema, type AuthServerOptions } from "../shared/config.js";
import { AuthConfigurationError } from "../shared/errors.js";
import {
  assertBoundaryObject,
  boundaryIsArray,
  boundaryOwnDataProperty,
  captureBoundaryBytes,
  captureBoundaryDenseArray,
  defineBoundaryArrayValue,
  createBoundaryMap,
  boundaryMapGetValue,
  boundaryMapSetValue,
  captureBoundaryStringArray,
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
import { AdminService } from "./admin-service.js";
import {
  AuthServer,
  captureAuthServerMailer,
  captureAuthServerRateLimiter,
  captureAuthServerRepository,
  captureAuthServerServiceOverrides,
  captureAuthServerServices,
  type AuthServerRuntimeOptions,
} from "./auth-server.js";
import type { AuthServerServices } from "./routes/contracts.js";
import { safeStringReplace } from "../shared/safe-intrinsics.js";

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
  const property = boundaryOwnDataProperty(source, member);
  if (!property.valid) throw new AuthConfigurationError(`auth server ${member} must be a data property`);
  return property.present ? property.value : undefined;
}

const configObjectGetPrototypeOf = Object.getPrototypeOf;
const configObjectGetOwnPropertyNames = Object.getOwnPropertyNames;
const configObjectGetOwnPropertySymbols = Object.getOwnPropertySymbols;
const configObjectDefineProperty = Object.defineProperty;
const configObjectCreate = Object.create;
const configObjectFreeze = Object.freeze;
const configObjectPrototype = Object.prototype;
const configUint8Array = Uint8Array;
const CONFIG_SNAPSHOT_MAX_DEPTH = 32;
const CONFIG_SNAPSHOT_MAX_KEYS = 100_000;
const configCryptoKeyConstructor = (globalThis as { readonly CryptoKey?: unknown }).CryptoKey;

function configOwnPropertyNames(value: object, label: string): string[] {
  try {
    return configObjectGetOwnPropertyNames(value);
  } catch {
    throw new AuthConfigurationError(`${label} must be a data record`);
  }
}

function configOwnPropertySymbols(value: object, label: string): symbol[] {
  try {
    return configObjectGetOwnPropertySymbols(value);
  } catch {
    throw new AuthConfigurationError(`${label} must be a data record`);
  }
}

function isConfigPlainRecord(value: unknown): value is object {
  if (value === null || typeof value !== "object") return false;
  try {
    if (boundaryIsArray(value, "configuration value")) return false;
    const prototype = configObjectGetPrototypeOf(value);
    return prototype === configObjectPrototype || prototype === null;
  } catch {
    return false;
  }
}

function rejectDangerousConfigValue(value: unknown, label: string): void {
  if (typeof value === "function") throw new AuthConfigurationError(`${label} must not be executable`);
  if (value !== null && typeof value === "object") {
    assertBoundaryObject(value, label);
  }
}

function assertConfigRecord(value: unknown, label: string): asserts value is object {
  if (!isConfigPlainRecord(value)) throw new AuthConfigurationError(`${label} must be a plain data record`);
  const names = configOwnPropertyNames(value, label);
  if (configOwnPropertySymbols(value, label).length > 0) throw new AuthConfigurationError(`${label} must not contain symbol properties`);
  if (names.length > CONFIG_SNAPSHOT_MAX_KEYS) throw new AuthConfigurationError(`${label} is too large`);
  for (let index = 0; index < names.length; index += 1) {
    const name = names[index];
    if (name === undefined) throw new AuthConfigurationError(`${label} is malformed`);
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
  const copy = captureBoundaryBytes(value, label, 1);
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
  let isUint8Array = false;
  try {
    isUint8Array = value instanceof configUint8Array;
  } catch {
    throw new AuthConfigurationError(`${label} must be valid key material`);
  }
  if (isUint8Array) return snapshotBytes(value, label);
  if (boundaryIsArray(value, label)) {
    const values = captureBoundaryDenseArray(value, label, 0, CONFIG_SNAPSHOT_MAX_KEYS);
    const copy: unknown[] = [];
    for (let index = 0; index < values.length; index += 1) {
      defineBoundaryArrayValue(copy, index, snapshotOwnedValue(values[index], `${label}[${index}]`, depth + 1), label);
    }
    return configObjectFreeze(copy);
  }
  if (isOpaqueKeyMaterial(value)) return value;
  assertConfigRecord(value, label);
  const copy = configObjectCreate(null) as Record<string, unknown>;
  const names = configOwnPropertyNames(value, label);
  for (let index = 0; index < names.length; index += 1) {
    const name = names[index];
    if (name === undefined) throw new AuthConfigurationError(`${label} is malformed`);
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
    snapshot instanceof configUint8Array ||
    isOpaqueKeyMaterial(snapshot as object) ||
    isConfigPlainRecord(snapshot)
  ) return snapshot as KeyMaterial;
  throw new AuthConfigurationError(`${label} must be valid key material`);
}

function snapshotKeyMap(value: unknown, label: string): Readonly<Record<string, KeyMaterial>> {
  assertConfigRecord(value, label);
  const copy = configObjectCreate(null) as Record<string, KeyMaterial>;
  const names = configOwnPropertyNames(value, label);
  for (let index = 0; index < names.length; index += 1) {
    const name = names[index];
    if (name === undefined) throw new AuthConfigurationError(`${label} is malformed`);
    const property = boundaryOwnDataProperty(value, name);
    if (!property.valid || !property.present) throw new AuthConfigurationError(`${label}.${name} must be a data property`);
    configObjectDefineProperty(copy, name, {
      configurable: false,
      enumerable: true,
      writable: false,
      value: snapshotKeyMaterial(property.value, `${label}.${name}`),
    });
  }
  if (names.length === 0) throw new AuthConfigurationError(`${label} must not be empty`);
  return configObjectFreeze(copy);
}

function snapshotStringArray(value: unknown, label: string): readonly string[] {
  return captureBoundaryStringArray(value, label, 0, CONFIG_SNAPSHOT_MAX_KEYS);
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
  const keys = ["defaultRoleKeys", "protectedRoleKeys"] as const;
  for (let index = 0; index < keys.length; index += 1) {
    const key = keys[index];
    if (key === undefined) throw new AuthConfigurationError("authorization configuration is malformed");
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
  assertBoundaryObject(source, "auth server configuration");
  const captured = configObjectCreate(null) as Record<string, unknown>;
  for (let index = 0; index < SERVER_OPTION_MEMBERS.length; index += 1) {
    const member = SERVER_OPTION_MEMBERS[index];
    if (member === undefined) throw new AuthConfigurationError("auth server configuration is malformed");
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
  const services = dataOptionMember(source, "services");
  if (services !== undefined) captured.services = captureAuthServerServiceOverrides(services);
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
  const path = safeStringReplace(baseUrl.pathname, /\/+$/u, "");
  if (path === null) throw new AuthConfigurationError("baseUrl path is invalid");
  return path === "" || path === "/" ? "/auth/v1" : path;
}

function secretString(value: string | Uint8Array): string {
  if (typeof value === "string") return value;
  return Buffer.from(value).toString("base64url");
}

function keyProvider(options: AuthServerOptions): KeyProvider {
  const configured = options.signingKeys.keys;
  const activeKeyId = options.signingKeys.activeKeyId;
  const verificationKeys = createBoundaryMap<string, KeyMaterial>();
  const names = configOwnPropertyNames(configured, "signingKeys.keys");
  for (let index = 0; index < names.length; index += 1) {
    const name = names[index];
    if (name === undefined) throw new AuthConfigurationError("signingKeys.keys is malformed");
    const property = boundaryOwnDataProperty(configured, name);
    if (!property.valid || !property.present) throw new AuthConfigurationError(`signingKeys.keys.${name} is unavailable`);
    boundaryMapSetValue(verificationKeys, name, property.value as KeyMaterial, "signingKeys.keys");
  }
  return {
    getActiveKeyId: () => activeKeyId,
    getSigningKey: (keyId) => {
      const material = configured[keyId];
      if (material === undefined) throw new AuthConfigurationError(`signing key is not configured: ${keyId}`);
      return material;
    },
    getVerificationKeys: () => {
      const copy = createBoundaryMap<string, KeyMaterial>();
      const entries = configOwnPropertyNames(configured, "signingKeys.keys");
      for (let index = 0; index < entries.length; index += 1) {
        const name = entries[index];
        if (name === undefined) throw new AuthConfigurationError("signingKeys.keys is malformed");
        const material = boundaryMapGetValue(verificationKeys, name, "signingKeys.keys");
        if (material === undefined) throw new AuthConfigurationError(`signing key is not configured: ${name}`);
        boundaryMapSetValue(copy, name, material, "signingKeys.keys");
      }
      return copy;
    },
  };
}

function createProviders(options: AuthServerOptions): readonly OAuthProvider[] {
  const configured = options.oauth;
  if (configured === undefined) return [];
  const providers: OAuthProvider[] = [];
  if (configured.google !== undefined) {
    defineBoundaryArrayValue(providers, providers.length, new GoogleOAuthProvider({
      clientId: configured.google.clientId,
      clientSecret: secretString(configured.google.clientSecret),
    }), "OAuth providers");
  }
  if (configured.oidc !== undefined) {
    defineBoundaryArrayValue(providers, providers.length, new OidcOAuthProvider({
      name: "oidc",
      clientId: configured.oidc.clientId,
      clientSecret: secretString(configured.oidc.clientSecret),
      issuer: configured.oidc.issuer,
      ...(configured.oidc.scopes === undefined ? {} : { scopes: configured.oidc.scopes }),
    }), "OAuth providers");
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
  const admin = repository.admin === undefined ? undefined : new AdminService({ repository, clock, ...(options.rateLimiter === undefined ? {} : { rateLimiter: options.rateLimiter }) });
  return {
    users,
    sessions,
    tokens,
    authorization,
    ...(oauth === undefined ? {} : { oauth }),
    ...(admin === undefined ? {} : { admin }),
  };
}

function mergeServices(defaults: AuthServerServices, overrides: AuthServerServiceOverrides | undefined): AuthServerServices {
  const merged: Record<string, unknown> = {
    users: defaults.users,
    sessions: defaults.sessions,
    tokens: defaults.tokens,
    authorization: defaults.authorization,
    ...(defaults.oauth === undefined ? {} : { oauth: defaults.oauth }),
    ...(defaults.admin === undefined ? {} : { admin: defaults.admin }),
  };
  if (overrides !== undefined) {
    const source = asRecord(overrides);
    if (source === null) throw new AuthConfigurationError("auth server service composition is incomplete");
    const members = ["users", "sessions", "tokens", "authorization", "oauth", "admin"] as const;
    for (let index = 0; index < members.length; index += 1) {
      const member = members[index];
      if (member === undefined) throw new AuthConfigurationError("auth server service composition is incomplete");
      const property = boundaryOwnDataProperty(source, member);
      if (!property.valid) throw new AuthConfigurationError(`auth server ${member} must be a data property`);
      if (property.present) merged[member] = property.value;
    }
  }
  return captureAuthServerServices(merged as unknown as AuthServerServices);
}

/** Creates a fully validated, framework-neutral server synchronously. */
export function createAuthServer(input: CreateAuthServerOptions): AuthServer {
  const capturedInput = captureConfiguredCallbacks(input);
  const capturedServicesProperty = boundaryOwnDataProperty(capturedInput as object, "services");
  if (!capturedServicesProperty.valid) throw new AuthConfigurationError("auth server services must be a data property");
  const rawServices = capturedServicesProperty.present
    ? capturedServicesProperty.value as AuthServerServiceOverrides
    : undefined;
  let parsed: AuthServerOptions;
  try {
    parsed = authServerOptionsSchema.parse(capturedInput);
  } catch {
    throw new AuthConfigurationError("auth server configuration is invalid");
  }
  const baseUrl = parseAbsoluteUrl(parsed.baseUrl, "baseUrl");
  const issuer = parseAbsoluteUrl(parsed.signingKeys.issuer, "signingKeys.issuer");
  if (issuer.href !== baseUrl.href) throw new AuthConfigurationError("baseUrl must exactly match signingKeys.issuer");
  const siteUrl = parseAbsoluteUrl(parsed.siteUrl, "siteUrl");
  const basePath = normalizedBasePath(baseUrl);
  const baseOrigin = baseUrl.origin;
  const allowedOrigins = baseOrigin === siteUrl.origin
    ? configObjectFreeze([baseOrigin])
    : configObjectFreeze([baseOrigin, siteUrl.origin]);
  const allowedRedirects = captureBoundaryStringArray(parsed.redirects.allowed, "auth server allowed redirects", 1, 100_000);
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
      : captureBoundaryBytes(parsed.secrets.tokenHashKey, "API-key hash key", 32),
    baseOrigin,
    basePath,
    allowedOrigins,
    allowedRedirects,
  };
  return new AuthServer(runtime);
}
