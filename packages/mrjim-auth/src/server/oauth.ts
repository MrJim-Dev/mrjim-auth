import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";
import type {
  AuthRepository,
  OAuthStateRecord,
  RepositoryOperationOptions,
} from "../shared/contracts.js";
import { authFailure, authSuccess, type AuthResult } from "../shared/result.js";
import {
  AuthApiError,
  AuthConfigurationError,
  AuthProgrammingError,
} from "../shared/errors.js";
import {
  sanitizeIdentityData,
  sanitizeRedactedMetadata,
  roleKeySchema,
  type Identity,
  type Session,
  type User,
  type UUID,
  uuidSchema,
} from "../shared/types.js";
import { normalizeAndValidateEmail } from "./email.js";
import {
  adapterCall,
  adapterTransaction,
  isAdapterBoundaryFailure,
  trustedFailure,
  type TrustedServiceError,
} from "./adapter-boundary.js";
import {
  generateProviderNonce,
  type OAuthProvider,
  type OAuthProviderProfile,
} from "./oauth-providers.js";
import { isCodeVerifier } from "../client/pkce.js";
import { SessionService, type AuthenticatedSession, type SessionContext } from "./sessions.js";

const OAUTH_STATE_TTL_SECONDS = 10 * 60;
const OAUTH_CALLBACK_TTL_SECONDS = 60;
const OAUTH_CALLBACK_PURPOSE = "oauth_callback" as const;
const OAUTH_FLOW_VALUES = ["sign_in", "link_identity"] as const;
const CALLBACK_CODE_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const PROVIDER_SUBJECT_MAX_LENGTH = 512;

const oauthTransactionValues = new WeakMap<object, unknown>();
const transactionValueSet = Function.prototype.call.bind(WeakMap.prototype.set) as <K extends object, V>(
  map: WeakMap<K, V>,
  key: K,
  value: V,
) => WeakMap<K, V>;
const transactionValueHas = Function.prototype.call.bind(WeakMap.prototype.has) as <K extends object>(
  map: WeakMap<K, unknown>,
  key: K,
) => boolean;
const transactionValueGet = Function.prototype.call.bind(WeakMap.prototype.get) as <K extends object, V>(
  map: WeakMap<K, V>,
  key: K,
) => V | undefined;
const transactionValueDelete = Function.prototype.call.bind(WeakMap.prototype.delete) as <K extends object>(
  map: WeakMap<K, unknown>,
  key: K,
) => boolean;
const createTransactionMarker = Object.create;
const freezeTransactionMarker = Object.freeze;

function trustedTransactionValue<T>(value: T): object {
  const marker = createTransactionMarker(null) as object;
  transactionValueSet(oauthTransactionValues, marker, value);
  return freezeTransactionMarker(marker);
}

function takeTrustedTransactionValue<T>(candidate: unknown): { readonly found: true; readonly value: T } | { readonly found: false } {
  if (candidate === null || (typeof candidate !== "object" && typeof candidate !== "function")) return { found: false };
  if (!transactionValueHas(oauthTransactionValues, candidate)) return { found: false };
  const value = transactionValueGet(oauthTransactionValues, candidate) as T;
  transactionValueDelete(oauthTransactionValues, candidate);
  return { found: true, value };
}

/** OAuth flow mode persisted with signed state. */
export type OAuthFlow = "sign_in" | "link_identity";

/** Input for starting a provider authorization flow. */
export interface OAuthAuthorizeInput {
  readonly provider: string;
  readonly redirectTo?: string | null;
  readonly flow?: OAuthFlow;
  readonly subject?: OAuthSubject;
}

/** A server-trusted authenticated subject used for identity linking. */
export interface OAuthSubject {
  readonly session: Session;
}

/** Public authorization response; it contains no client secret or provider token. */
export interface OAuthAuthorizeResult {
  readonly provider: string;
  readonly url: string;
  readonly redirect: string;
  readonly state: string;
  readonly codeVerifier: string;
  readonly expiresAt: string;
}

/** Input from a provider callback endpoint. */
export interface OAuthCallbackInput {
  readonly provider: string;
  readonly code: string;
  readonly state: string;
  readonly redirectTo?: string | null;
  readonly codeChallengeMethod?: "S256" | "plain";
}

/** Safe callback response containing only the short-lived internal exchange code. */
export interface OAuthCallbackResult {
  readonly code: string;
  readonly redirect: string;
  readonly url: string;
  readonly expiresAt: string;
}

/** Input for consuming the short-lived callback exchange code. */
export interface OAuthExchangeInput {
  readonly code: string;
  readonly codeVerifier: string;
  readonly redirectTo?: string | null;
  readonly context?: SessionContext;
}

/** Result of a successful provider sign-in or callback-code exchange. */
export interface OAuthSessionResult {
  readonly user: User;
  readonly identity: Identity;
  readonly session: Session;
}

/** Result of a direct authenticated identity link. */
export interface OAuthLinkResult {
  readonly user: User;
  readonly identity: Identity;
}

/** Public provider discovery data; credentials and endpoint metadata are omitted. */
export interface OAuthProviderDiscovery {
  readonly name: string;
  readonly scopes: readonly string[];
  readonly capabilities: OAuthProvider["capabilities"];
}

/** Server-only OAuth/OIDC orchestration configuration. */
export interface OAuthServiceOptions {
  readonly repository: AuthRepository;
  readonly sessions: SessionService;
  readonly providers: readonly OAuthProvider[] | ReadonlyMap<string, OAuthProvider>;
  readonly tokenHashKey: string | Uint8Array;
  readonly encryptionKey: string | Uint8Array;
  readonly allowedRedirects: readonly string[];
  readonly defaultRedirect?: string;
  readonly allowVerifiedEmailAutoLink?: boolean;
  /** Role keys assigned atomically whenever OAuth creates a user. */
  readonly defaultRoleKeys?: readonly string[];
  /** Maximum age of a session allowed to begin authenticated linking. */
  readonly freshSessionMaxAgeSeconds?: number;
  readonly clock?: () => Date;
}

type EncryptedStatePayload = {
  readonly verifier: string;
  readonly nonce: string;
  readonly linkingSessionId: UUID | null;
};

type ProfileResolution = {
  readonly user: User;
  readonly identity: Identity;
};

function validNow(clock: () => Date): Date {
  const now = clock();
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) {
    throw new AuthConfigurationError("OAuth clock must return a valid Date");
  }
  return now;
}

function validKey(value: string | Uint8Array, label: string): Buffer {
  let bytes: Buffer;
  if (typeof value === "string") {
    if (value !== value.trim() || !/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1) {
      throw new AuthConfigurationError(`${label} must be unpadded base64url key material`);
    }
    bytes = Buffer.from(value, "base64url");
    if (bytes.toString("base64url") !== value) {
      throw new AuthConfigurationError(`${label} must be canonical unpadded base64url key material`);
    }
  } else {
    bytes = Buffer.from(value);
  }
  if (bytes.byteLength < 32) throw new AuthConfigurationError(`${label} must contain at least 32 decoded bytes`);
  return bytes;
}

function deriveEncryptionKey(value: string | Uint8Array): Buffer {
  return createHash("sha256").update(validKey(value, "OAuth encryption key")).digest();
}

function normalizeProvider(value: unknown): string {
  if (typeof value !== "string" || value.trim() === "") {
    throw new AuthProgrammingError("OAuth provider must be non-empty");
  }
  const provider = value.trim().toLowerCase();
  if (!/^[a-z][a-z0-9_.:-]{0,31}$/.test(provider)) {
    throw new AuthProgrammingError("OAuth provider must be a stable identifier");
  }
  return provider;
}

function parsePublicProvider(value: unknown): string {
  try {
    return normalizeProvider(value);
  } catch {
    throw new AuthApiError("invalid_request", 400, "Invalid OAuth provider");
  }
}

function normalizeRedirect(value: unknown): string {
  if (typeof value !== "string" || value.trim() === "") {
    throw new AuthConfigurationError("OAuth redirect must be non-empty");
  }
  const redirect = value.trim();
  let parsed: URL;
  try {
    parsed = new URL(redirect);
  } catch {
    throw new AuthConfigurationError("OAuth redirect must be an absolute URL");
  }
  if ((parsed.protocol !== "http:" && parsed.protocol !== "https:") || parsed.hash !== "") {
    throw new AuthConfigurationError("OAuth redirect must be an HTTP(S) URL without a fragment");
  }
  return redirect;
}

function validVerifier(value: unknown): string {
  if (!isCodeVerifier(value)) throw new AuthApiError("invalid_token", 401, "Invalid OAuth code");
  return value;
}

function validCode(value: unknown): string {
  if (typeof value !== "string" || !CALLBACK_CODE_PATTERN.test(value)) {
    throw new AuthApiError("invalid_token", 401, "Invalid OAuth code");
  }
  return value;
}

function constantTimeEqual(left: Uint8Array, right: Uint8Array): boolean {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.byteLength === b.byteLength && timingSafeEqual(a, b);
}

function hmac(key: Buffer, purpose: string, value: string): Uint8Array {
  return Uint8Array.from(createHmac("sha256", key).update(`${purpose}\0${value}`, "utf8").digest());
}

function randomOpaque(): string {
  return randomBytes(32).toString("base64url");
}

function pkceChallenge(verifier: string): string {
  return createHash("sha256").update(verifier, "utf8").digest("base64url");
}

function stateBinding(state: string, provider: string, flow: OAuthFlow, redirect: string): string {
  return `${state}\0${provider}\0${flow}\0${redirect}`;
}

function encryptState(payload: EncryptedStatePayload, key: Buffer): Uint8Array {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([
    cipher.update(JSON.stringify(payload), "utf8"),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  return Uint8Array.from(Buffer.concat([iv, tag, ciphertext]));
}

function decryptState(value: Uint8Array | null, key: Buffer): EncryptedStatePayload {
  if (value === null || value.byteLength < 28) throw new AuthApiError("oauth_state_invalid", 400, "Invalid OAuth state");
  try {
    const bytes = Buffer.from(value);
    const decipher = createDecipheriv("aes-256-gcm", key, bytes.subarray(0, 12));
    decipher.setAuthTag(bytes.subarray(12, 28));
    const parsed: unknown = JSON.parse(Buffer.concat([
      decipher.update(bytes.subarray(28)),
      decipher.final(),
    ]).toString("utf8"));
    if (typeof parsed !== "object" || parsed === null) throw new Error("invalid state payload");
    const candidate = parsed as Record<string, unknown>;
    if (
      typeof candidate.verifier !== "string"
      || typeof candidate.nonce !== "string"
      || !("linkingSessionId" in candidate)
      || (candidate.linkingSessionId !== null && !uuidSchema.safeParse(candidate.linkingSessionId).success)
      || !isCodeVerifier(candidate.verifier)
      || candidate.nonce.length < 16
    ) throw new Error("invalid state payload");
    return {
      verifier: candidate.verifier,
      nonce: candidate.nonce,
      linkingSessionId: candidate.linkingSessionId as UUID | null,
    };
  } catch (error) {
    if (error instanceof AuthApiError) throw error;
    throw new AuthApiError("oauth_state_invalid", 400, "Invalid OAuth state");
  }
}

function internalError(): AuthApiError {
  return new AuthApiError("internal_error", 500, "Internal authentication error");
}

function oauthStateInvalid(): AuthApiError {
  return new AuthApiError("oauth_state_invalid", 400, "Invalid OAuth state");
}

function providerFailure(): AuthApiError {
  return new AuthApiError("oauth_provider_error", 502, "OAuth provider authentication failed");
}

function unauthorized(): AuthApiError {
  return new AuthApiError("unauthorized", 401, "Authenticated session is required");
}

function mapUnexpected(error: unknown): AuthResult<never> {
  if (isAdapterBoundaryFailure(error)) return authFailure(internalError());
  if (error instanceof AuthApiError) return authFailure(error);
  if (error instanceof AuthConfigurationError || error instanceof AuthProgrammingError) throw error;
  return authFailure(internalError());
}

function rethrowTrusted(error: TrustedServiceError): never {
  throw error;
}

function trustedAuthError(error: { readonly code: AuthApiError["code"]; readonly status: number; readonly message: string; readonly request_id?: string }): never {
  trustedFailure(new AuthApiError(error.code, error.status, error.message, error.request_id));
}

function isBanned(user: User, now: Date): boolean {
  return user.banned_until !== null && new Date(user.banned_until).getTime() > now.getTime();
}

function isDeleted(user: User): boolean {
  return user.deleted_at !== null;
}

async function providerCall<T>(operation: () => Promise<T>): Promise<T> {
  try {
    return await adapterCall(operation);
  } catch (error) {
    if (isAdapterBoundaryFailure(error)) throw providerFailure();
    throw error;
  }
}

function safeProfile(provider: OAuthProvider, profile: OAuthProviderProfile): OAuthProviderProfile {
  const providerName = normalizeProvider(provider.name);
  if (typeof profile !== "object" || profile === null) throw providerFailure();
  let profileProvider: string;
  try {
    profileProvider = normalizeProvider(profile.provider);
  } catch {
    throw providerFailure();
  }
  if (profileProvider !== providerName) throw providerFailure();
  if (provider.issuer !== undefined && profile.issuer !== provider.issuer) throw providerFailure();
  if (typeof profile.issuer !== "string" || profile.issuer.trim() === "") throw providerFailure();
  if (typeof profile.subject !== "string" || profile.subject.trim() === "" || profile.subject.length > PROVIDER_SUBJECT_MAX_LENGTH) {
    throw providerFailure();
  }
  let claims: ReturnType<typeof sanitizeIdentityData>;
  try {
    claims = sanitizeIdentityData(profile.claims);
  } catch {
    throw providerFailure();
  }
  if (claims.sub !== profile.subject) throw providerFailure();
  let email: string | null;
  try {
    email = profile.email === null || profile.email === undefined
      ? null
      : normalizeAndValidateEmail(profile.email).display;
  } catch {
    throw providerFailure();
  }
  return {
    provider: providerName,
    subject: profile.subject,
    issuer: profile.issuer,
    email,
    emailVerified: profile.emailVerified === true && email !== null,
    claims: sanitizeIdentityData({
      ...claims,
      sub: profile.subject,
      email: email ?? undefined,
      email_verified: email === null ? undefined : profile.emailVerified === true,
    }),
  };
}

type OAuthStateBinding = {
  readonly stateHash: Uint8Array;
  readonly provider: string;
  readonly flow: OAuthFlow;
  readonly redirect: string;
};

function copyAdapterDate(value: unknown, nullable: false): Date;
function copyAdapterDate(value: unknown, nullable: true): Date | null;
function copyAdapterDate(value: unknown, nullable: boolean): Date | null {
  if (value === null && nullable) return null;
  if (!(value instanceof Date)) throw new TypeError("invalid OAuth state adapter value");
  const time = value.getTime();
  if (!Number.isFinite(time)) throw new TypeError("invalid OAuth state adapter value");
  return new Date(time);
}

function safeOAuthStateRecord(value: unknown, expected: OAuthStateBinding): OAuthStateRecord {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new TypeError("invalid OAuth state adapter value");
  }
  const candidate = value as Record<string, unknown>;
  const idValue = candidate.id;
  const stateHashValue = candidate.state_hash;
  const providerValue = candidate.provider;
  const flowValue = candidate.flow;
  const pkceChallengeValue = candidate.pkce_challenge;
  const encryptedVerifierValue = candidate.encrypted_verifier;
  const redirectValue = candidate.redirect;
  const linkingUserIdValue = candidate.linking_user_id;
  const expiresAtValue = candidate.expires_at;
  const consumedAtValue = candidate.consumed_at;

  const id = uuidSchema.safeParse(idValue);
  if (!id.success || !(stateHashValue instanceof Uint8Array)) {
    throw new TypeError("invalid OAuth state adapter value");
  }
  let provider: string;
  try {
    provider = normalizeProvider(providerValue);
  } catch {
    throw new TypeError("invalid OAuth state adapter value");
  }
  if (
    provider !== expected.provider
    || flowValue !== expected.flow
    || !OAUTH_FLOW_VALUES.includes(flowValue as OAuthFlow)
    || redirectValue !== expected.redirect
    || typeof pkceChallengeValue !== "string"
    || !(encryptedVerifierValue instanceof Uint8Array)
  ) throw new TypeError("invalid OAuth state adapter value");
  const stateHash = Uint8Array.from(stateHashValue);
  if (!constantTimeEqual(stateHash, expected.stateHash)) {
    throw new TypeError("invalid OAuth state adapter value");
  }
  const linkingUserId = linkingUserIdValue === null
    ? null
    : uuidSchema.safeParse(linkingUserIdValue);
  if (linkingUserId !== null && !linkingUserId.success) {
    throw new TypeError("invalid OAuth state adapter value");
  }
  return Object.freeze({
    id: id.data,
    state_hash: stateHash,
    provider,
    flow: flowValue as OAuthFlow,
    pkce_challenge: pkceChallengeValue,
    encrypted_verifier: Uint8Array.from(encryptedVerifierValue),
    redirect: redirectValue as string,
    linking_user_id: linkingUserId === null ? null : linkingUserId.data,
    expires_at: copyAdapterDate(expiresAtValue, false),
    consumed_at: copyAdapterDate(consumedAtValue, true),
  });
}

type IdentityBinding = {
  readonly provider?: string;
  readonly subject?: string;
  readonly userId?: UUID;
};

function safeRepositoryIdentity(value: unknown, expected: IdentityBinding = {}): Identity {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new TypeError("invalid identity adapter value");
  }
  const candidate = value as Record<string, unknown>;
  const idValue = candidate.id;
  const userIdValue = candidate.user_id;
  const providerValue = candidate.provider;
  const providerSubjectValue = candidate.provider_subject;
  const emailValue = candidate.email;
  const identityDataValue = candidate.identity_data;
  const createdAtValue = candidate.created_at;
  const updatedAtValue = candidate.updated_at;
  const id = uuidSchema.safeParse(idValue);
  const userId = uuidSchema.safeParse(userIdValue);
  if (!id.success || !userId.success) throw new TypeError("invalid identity adapter value");
  let provider: string;
  try {
    provider = normalizeProvider(providerValue);
  } catch {
    throw new TypeError("invalid identity adapter value");
  }
  if (
    typeof providerSubjectValue !== "string"
    || providerSubjectValue.trim() === ""
    || providerSubjectValue.length > PROVIDER_SUBJECT_MAX_LENGTH
    || (emailValue !== null && typeof emailValue !== "string")
    || typeof createdAtValue !== "string"
    || !Number.isFinite(Date.parse(createdAtValue))
    || typeof updatedAtValue !== "string"
    || !Number.isFinite(Date.parse(updatedAtValue))
    || typeof identityDataValue !== "object"
    || identityDataValue === null
    || Array.isArray(identityDataValue)
  ) throw new TypeError("invalid identity adapter value");
  let email: string | null;
  try {
    email = emailValue === null
      ? null
      : normalizeAndValidateEmail(emailValue).display;
  } catch {
    throw new TypeError("invalid identity adapter value");
  }
  const identityData = sanitizeIdentityData(identityDataValue);
  if (
    identityData.sub !== providerSubjectValue
    || (expected.provider !== undefined && provider !== expected.provider)
    || (expected.subject !== undefined && providerSubjectValue !== expected.subject)
    || (expected.userId !== undefined && userId.data !== expected.userId)
  ) throw new TypeError("invalid identity adapter value");
  return Object.freeze({
    id: id.data,
    user_id: userId.data,
    provider,
    provider_subject: providerSubjectValue,
    email,
    identity_data: identityData,
    created_at: createdAtValue,
    updated_at: updatedAtValue,
  });
}

function safeRepositoryIdentities(value: unknown, expectedUserId: UUID): readonly Identity[] {
  if (!Array.isArray(value)) throw new TypeError("invalid identity-list adapter value");
  return Object.freeze(value.map((identity) => safeRepositoryIdentity(identity, { userId: expectedUserId })));
}

function redirectWithCode(redirect: string, code: string): string {
  const url = new URL(redirect);
  url.searchParams.set("code", code);
  return url.toString();
}

/**
 * Server-only Google/OIDC state, callback-code, and identity orchestration.
 *
 * State and callback values are random opaque values; only HMAC digests are
 * persisted. The callback exchange stores the resolved user id and PKCE
 * challenge binding in PostgreSQL, so a restart cannot replay or lose it.
 */
export class OAuthService {
  private readonly repository: AuthRepository;
  private readonly sessions: SessionService;
  private readonly providers: ReadonlyMap<string, OAuthProvider>;
  private readonly tokenHashKey: Buffer;
  private readonly encryptionKey: Buffer;
  private readonly allowedRedirects: readonly string[];
  private readonly defaultRedirect: string;
  private readonly allowVerifiedEmailAutoLink: boolean;
  private readonly defaultRoleKeys: readonly string[];
  private readonly freshSessionMaxAgeSeconds: number;
  private readonly clock: () => Date;

  constructor(options: OAuthServiceOptions) {
    if (options.repository === null || typeof options.repository !== "object" || typeof options.repository.transaction !== "function") {
      throw new AuthConfigurationError("OAuth repository is incomplete");
    }
    if (!(options.sessions instanceof SessionService)) throw new AuthConfigurationError("OAuth session service is required");
    const providerEntries: readonly (readonly [string, OAuthProvider])[] = Array.isArray(options.providers)
      ? options.providers.map((provider) => [provider.name, provider] as const)
      : [...options.providers.entries()];
    const providers = new Map<string, OAuthProvider>();
    for (const [key, provider] of providerEntries) {
      if (provider === null || typeof provider !== "object" || typeof provider.authorizationUrl !== "function" || typeof provider.exchange !== "function") {
        throw new AuthConfigurationError("OAuth provider adapter is incomplete");
      }
      const name = normalizeProvider(key);
      if (providers.has(name)) throw new AuthConfigurationError(`duplicate OAuth provider: ${name}`);
      if (normalizeProvider(provider.name) !== name) throw new AuthConfigurationError("OAuth provider map key does not match adapter name");
      if (typeof provider.clientId !== "string" || provider.clientId.trim() === "") throw new AuthConfigurationError("OAuth provider client ID is required");
      if (!Array.isArray(provider.scopes) || provider.scopes.length === 0 || !provider.scopes.every((scope) => typeof scope === "string" && scope.trim() !== "")) {
        throw new AuthConfigurationError("OAuth provider scopes are required");
      }
      providers.set(name, provider);
    }
    if (providers.size === 0) throw new AuthConfigurationError("at least one OAuth provider is required");
    const allowed = options.allowedRedirects.map(normalizeRedirect);
    if (allowed.length === 0 || new Set(allowed).size !== allowed.length) throw new AuthConfigurationError("OAuth redirects must be non-empty and unique");
    const defaultRedirect = normalizeRedirect(options.defaultRedirect ?? allowed[0]);
    if (!allowed.includes(defaultRedirect)) throw new AuthConfigurationError("OAuth default redirect must be exactly allowlisted");
    const freshAge = options.freshSessionMaxAgeSeconds ?? 5 * 60;
    if (!Number.isSafeInteger(freshAge) || freshAge <= 0 || freshAge > 15 * 60) throw new AuthConfigurationError("OAuth fresh-session age is invalid");
    const defaultRoleKeys = [...(options.defaultRoleKeys ?? [])];
    if (!defaultRoleKeys.every((key) => roleKeySchema.safeParse(key).success)) {
      throw new AuthConfigurationError("OAuth default role keys are invalid");
    }
    this.repository = options.repository;
    this.sessions = options.sessions;
    this.providers = providers;
    this.tokenHashKey = validKey(options.tokenHashKey, "OAuth token hash key");
    this.encryptionKey = deriveEncryptionKey(options.encryptionKey);
    this.allowedRedirects = Object.freeze([...allowed]);
    this.defaultRedirect = defaultRedirect;
    this.allowVerifiedEmailAutoLink = options.allowVerifiedEmailAutoLink === true;
    this.defaultRoleKeys = Object.freeze([...new Set(defaultRoleKeys)]);
    this.freshSessionMaxAgeSeconds = freshAge;
    this.clock = options.clock ?? (() => new Date());
    validNow(this.clock);
  }

  /** Lists enabled provider names and public capabilities without credentials. */
  listProviders(): readonly OAuthProviderDiscovery[] {
    return Object.freeze([...this.providers.values()].map((provider) => ({
      name: normalizeProvider(provider.name),
      scopes: Object.freeze([...provider.scopes]),
      capabilities: Object.freeze({
        authorization_code: true,
        pkce: true,
        identity_linking: true,
      }),
    })));
  }

  /** Compatibility alias for HTTP provider-discovery handlers. */
  discoverProviders(): readonly OAuthProviderDiscovery[] {
    return this.listProviders();
  }

  /** Starts a signed, exact-redirect-bound authorization-code PKCE flow. */
  async authorize(input: OAuthAuthorizeInput): Promise<AuthResult<OAuthAuthorizeResult>> {
    try {
      const providerName = parsePublicProvider(input.provider);
      const provider = this.providers.get(providerName);
      if (provider === undefined) return authFailure(new AuthApiError("not_found", 404, "OAuth provider is not enabled"));
      const redirect = this.resolveRedirect(input.redirectTo);
      const flow = input.flow ?? "sign_in";
      if (!OAUTH_FLOW_VALUES.includes(flow)) return authFailure(new AuthApiError("invalid_request", 400, "Invalid OAuth flow"));
      let linkingSubject: AuthenticatedSession | null = null;
      if (flow === "link_identity") {
        if (input.subject === undefined) return authFailure(unauthorized());
        const authorized = await this.authorizeSubject(input.subject);
        if (authorized.error !== null || authorized.data === null) return authFailure(authorized.error ?? unauthorized());
        linkingSubject = authorized.data;
      }
      const now = validNow(this.clock);
      const codeVerifier = randomOpaque();
      const codeChallenge = pkceChallenge(codeVerifier);
      const state = randomOpaque();
      const nonce = generateProviderNonce();
      const expiresAt = new Date(now.getTime() + OAUTH_STATE_TTL_SECONDS * 1000);
      const url = await providerCall(async () => {
        const value = await provider.authorizationUrl({
          clientId: provider.clientId,
          redirectUri: redirect,
          state,
          nonce,
          scopes: provider.scopes,
          codeChallenge,
          codeChallengeMethod: "S256",
        });
        if (typeof value !== "string" || value.trim() === "") throw new TypeError("invalid provider authorization URL");
        return value;
      });
      await this.runTransaction(async (transaction) => {
        if (flow === "link_identity") {
          if (linkingSubject === null) trustedFailure(unauthorized());
          await this.requireFreshLinkingSession(transaction, linkingSubject.session_id, linkingSubject.user_id, now);
        }
        await transaction.oauthStates.create({
          state_hash: hmac(this.tokenHashKey, "oauth_state", stateBinding(state, providerName, flow, redirect)),
          provider: providerName,
          flow,
          pkce_challenge: codeChallenge,
          encrypted_verifier: encryptState({
            verifier: codeVerifier,
            nonce,
            linkingSessionId: linkingSubject?.session_id ?? null,
          }, this.encryptionKey),
          redirect,
          linking_user_id: linkingSubject?.user_id ?? null,
          expires_at: expiresAt,
        }, { now });
      });
      return authSuccess({
        provider: providerName,
        url,
        redirect,
        state,
        codeVerifier,
        expiresAt: expiresAt.toISOString(),
      });
    } catch (error) {
      return mapUnexpected(error);
    }
  }

  /** Validates provider state and converts the provider result to a 60-second code. */
  async callback(input: OAuthCallbackInput): Promise<AuthResult<OAuthCallbackResult>> {
    try {
      const providerName = parsePublicProvider(input.provider);
      const provider = this.providers.get(providerName);
      if (provider === undefined) return authFailure(new AuthApiError("not_found", 404, "OAuth provider is not enabled"));
      if (input.codeChallengeMethod !== undefined && input.codeChallengeMethod !== "S256") return authFailure(oauthStateInvalid());
      const redirectCandidates = input.redirectTo === undefined || input.redirectTo === null
        ? this.allowedRedirects
        : [this.resolveRedirect(input.redirectTo)];
      if (typeof input.state !== "string" || input.state.length < 43 || input.state.length > 128) return authFailure(oauthStateInvalid());
      if (typeof input.code !== "string" || input.code.trim() === "" || input.code.length > 2048) return authFailure(providerFailure());
      const now = validNow(this.clock);
      let consumed: OAuthStateRecord | null = null;
      let redirect: string | null = null;
      for (const candidate of redirectCandidates) {
        for (const flow of OAUTH_FLOW_VALUES) {
          const stateHash = hmac(this.tokenHashKey, "oauth_state", stateBinding(input.state, providerName, flow, candidate));
          consumed = await adapterCall(async () => {
            const value = await this.repository.oauthStates.consume(stateHash, now, {
              now,
              provider: providerName,
              flow,
              redirect: candidate,
            });
            if (value === null) return null;
            return safeOAuthStateRecord(value, {
              stateHash,
              provider: providerName,
              flow,
              redirect: candidate,
            });
          });
          if (consumed !== null) {
            redirect = candidate;
            break;
          }
        }
        if (consumed !== null) break;
      }
      if (consumed === null || redirect === null) return authFailure(oauthStateInvalid());
      const payload = decryptState(consumed.encrypted_verifier ?? null, this.encryptionKey);
      if (pkceChallenge(payload.verifier) !== consumed.pkce_challenge) return authFailure(oauthStateInvalid());
      if (
        (consumed.flow === "link_identity" && (
          payload.linkingSessionId === null
          || consumed.linking_user_id === null
          || consumed.linking_user_id === undefined
        ))
        || (consumed.flow === "sign_in" && payload.linkingSessionId !== null)
      ) return authFailure(oauthStateInvalid());
      const profile = await providerCall(async () => safeProfile(provider, await provider.exchange({
          code: input.code,
          state: input.state,
          expectedState: input.state,
          redirectUri: redirect,
          codeVerifier: payload.verifier,
          nonce: payload.nonce,
        })));
      const callbackCode = randomOpaque();
      const expiresAt = new Date(now.getTime() + OAUTH_CALLBACK_TTL_SECONDS * 1000);
      await this.runTransaction(async (transaction) => {
        if (consumed.flow === "link_identity") {
          if (payload.linkingSessionId === null || consumed.linking_user_id === null || consumed.linking_user_id === undefined) {
            trustedFailure(oauthStateInvalid());
          }
          await this.requireFreshLinkingSession(
            transaction,
            payload.linkingSessionId,
            consumed.linking_user_id,
            now,
          );
        }
        const identity = await this.resolveProfile(transaction, profile, consumed.flow, consumed.linking_user_id ?? null, now);
        const callbackMetadata = sanitizeRedactedMetadata({
          event: "oauth.callback",
          provider: providerName,
          operation: consumed.flow,
          target_id: identity.identity.id,
        });
        await transaction.oneTimeTokens.issue({
          user_id: identity.user.id,
          purpose: OAUTH_CALLBACK_PURPOSE,
          token_hash: hmac(this.tokenHashKey, OAUTH_CALLBACK_PURPOSE, callbackCode),
          target: consumed.pkce_challenge,
          redirect,
          metadata: callbackMetadata,
          expires_at: expiresAt,
        }, { now });
        await transaction.operations.appendAudit({
          actor_user_id: identity.user.id,
          action: "oauth.callback.created",
          target_type: "user",
          target_id: identity.user.id,
          metadata: callbackMetadata,
          outcome: "success",
          occurred_at: now,
        }, { now });
        if (consumed.flow === "link_identity") {
          await transaction.operations.appendAudit({
            actor_user_id: identity.user.id,
            actor_session_id: payload.linkingSessionId,
            action: "identity.linked",
            target_type: "identity",
            target_id: identity.identity.id,
            metadata: sanitizeRedactedMetadata({
              event: "identity.linked",
              provider: providerName,
              operation: "link_identity",
              target_id: identity.identity.id,
            }),
            outcome: "success",
            occurred_at: now,
          }, { now });
        }
        return identity;
      });
      return authSuccess({
        code: callbackCode,
        redirect,
        url: redirectWithCode(redirect, callbackCode),
        expiresAt: expiresAt.toISOString(),
      });
    } catch (error) {
      return mapUnexpected(error);
    }
  }

  /** Atomically consumes a callback code, verifies PKCE, and creates a session. */
  async exchangeCode(input: OAuthExchangeInput): Promise<AuthResult<OAuthSessionResult>> {
    try {
      const redirect = this.resolveRedirect(input.redirectTo);
      const code = validCode(input.code);
      const verifier = validVerifier(input.codeVerifier);
      const now = validNow(this.clock);
      const challenge = pkceChallenge(verifier);
      const result = await this.runTransaction(async (transaction) => {
        const consumed = await transaction.oneTimeTokens.consumeBound(
          hmac(this.tokenHashKey, OAUTH_CALLBACK_PURPOSE, code),
          OAUTH_CALLBACK_PURPOSE,
          challenge,
          redirect,
          now,
          { now },
        );
        const consumedUserId = consumed?.user_id;
        if (consumed === null || consumedUserId === null || consumedUserId === undefined) trustedFailure(new AuthApiError("invalid_token", 401, "Invalid OAuth code"));
        const user = await transaction.users.findByIdForUpdate(consumedUserId, { now });
        if (user === null || isBanned(user, now)) trustedFailure(unauthorized());
        const identities = safeRepositoryIdentities(
          await transaction.identities.listByUserId(user.id, { now }),
          user.id,
        );
        const identityId = typeof consumed.metadata?.target_id === "string"
          ? uuidSchema.safeParse(consumed.metadata.target_id).data
          : undefined;
        const identity = identityId === undefined
          ? undefined
          : identities.find((candidate) => candidate.id === identityId);
        if (identity === undefined) trustedFailure(new AuthApiError("invalid_request", 400, "OAuth identity is unavailable"));
        const signedInUser = await transaction.users.update(user.id, { last_sign_in_at: now }, { now });
        const session = await this.sessions.create(signedInUser, input.context ?? {}, transaction);
        if (session.error !== null || session.data === null) trustedAuthError(session.error ?? internalError());
        await transaction.operations.appendAudit({
          actor_user_id: user.id,
          action: "oauth.exchange",
          target_type: "user",
          target_id: user.id,
          metadata: sanitizeRedactedMetadata({
            event: "oauth.exchange",
            provider: typeof consumed.metadata?.provider === "string" ? consumed.metadata.provider : undefined,
            operation: "callback",
          }),
          outcome: "success",
          occurred_at: now,
        }, { now });
        return { user: signedInUser, identity, session: session.data };
      });
      return authSuccess(result);
    } catch (error) {
      return mapUnexpected(error);
    }
  }

  /** Signs in or creates an account from a provider profile in one transaction. */
  async signInFromProfile(profile: OAuthProviderProfile, context?: SessionContext): Promise<AuthResult<OAuthSessionResult>> {
    try {
      const providerName = parsePublicProvider(
        typeof profile === "object" && profile !== null ? profile.provider : undefined,
      );
      const provider = this.providers.get(providerName);
      if (provider === undefined) return authFailure(new AuthApiError("not_found", 404, "OAuth provider is not enabled"));
      const safe = await providerCall(async () => safeProfile(provider, profile));
      const now = validNow(this.clock);
      const result = await this.runTransaction(async (transaction) => {
        const identity = await this.resolveProfile(transaction, safe, "sign_in", null, now);
        const signedInUser = await transaction.users.update(identity.user.id, { last_sign_in_at: now }, { now });
        await transaction.operations.appendAudit({
          actor_user_id: signedInUser.id,
          action: "oauth.sign_in",
          target_type: "user",
          target_id: signedInUser.id,
          metadata: sanitizeRedactedMetadata({ event: "oauth.sign_in", provider: safe.provider, operation: "sign_in" }),
          outcome: "success",
          occurred_at: now,
        }, { now });
        const session = await this.sessions.create(signedInUser, context ?? {}, transaction);
        if (session.error !== null || session.data === null) trustedAuthError(session.error ?? internalError());
        return { user: signedInUser, identity: identity.identity, session: session.data };
      });
      return authSuccess(result);
    } catch (error) {
      return mapUnexpected(error);
    }
  }

  /** Starts authenticated linking or directly links a deterministic test/provider profile. */
  async linkIdentity(subject: OAuthSubject, input: OAuthProviderProfile | { readonly provider: string; readonly redirectTo?: string | null }): Promise<AuthResult<OAuthAuthorizeResult | OAuthLinkResult>> {
    if (!("subject" in input)) {
      return this.authorize({
        provider: input.provider,
        ...(input.redirectTo === undefined ? {} : { redirectTo: input.redirectTo }),
        flow: "link_identity",
        subject,
      });
    }
    const authorized = await this.authorizeSubject(subject);
    if (authorized.error !== null || authorized.data === null) return authFailure(authorized.error ?? unauthorized());
    try {
      const provider = this.providers.get(parsePublicProvider(input.provider));
      if (provider === undefined) return authFailure(new AuthApiError("not_found", 404, "OAuth provider is not enabled"));
      const safe = await providerCall(async () => safeProfile(provider, input));
      const now = validNow(this.clock);
      const result = await this.runTransaction(async (transaction) => {
        await this.requireFreshLinkingSession(
          transaction,
          authorized.data.session_id,
          authorized.data.user_id,
          now,
        );
        const identity = await this.resolveProfile(transaction, safe, "link_identity", authorized.data.user_id, now);
        await transaction.operations.appendAudit({
          actor_user_id: authorized.data.user_id,
          actor_session_id: authorized.data.session_id,
          action: "identity.linked",
          target_type: "identity",
          target_id: identity.identity.id,
          metadata: sanitizeRedactedMetadata({ event: "identity.linked", provider: safe.provider, operation: "link_identity" }),
          outcome: "success",
          occurred_at: now,
        }, { now });
        return { user: identity.user, identity: identity.identity };
      });
      return authSuccess(result);
    } catch (error) {
      return mapUnexpected(error);
    }
  }

  /** Unlinks an identity only if a password or another identity remains usable. */
  async unlinkIdentity(subject: OAuthSubject, identityId: UUID): Promise<AuthResult<null>> {
    const authorized = await this.sessions.authorizeSession(subject.session);
    if (authorized.error !== null || authorized.data === null) return authFailure(authorized.error ?? unauthorized());
    const now = validNow(this.clock);
    try {
      await this.runTransaction(async (transaction) => {
        const user = await transaction.users.findByIdForUpdate(authorized.data.user_id, { now });
        if (user === null) trustedFailure(unauthorized());
        const currentUser = user;
        const identities = safeRepositoryIdentities(
          await transaction.identities.listByUserId(currentUser.id, { now }),
          currentUser.id,
        );
        const identity = identities.find((candidate) => candidate.id === identityId);
        if (identity === undefined) trustedFailure(new AuthApiError("not_found", 404, "Identity not found"));
        const password = await transaction.passwordCredentials.findByUserId(currentUser.id, { now });
        if (password === null && identities.length <= 1) trustedFailure(new AuthApiError("identity_unlink_not_allowed", 400, "A final usable login method cannot be removed"));
        await transaction.identities.deleteById(identityId, { now });
        await transaction.operations.appendAudit({
          actor_user_id: user.id,
          actor_session_id: authorized.data.session_id,
          action: "identity.unlinked",
          target_type: "identity",
          target_id: identityId,
          metadata: sanitizeRedactedMetadata({ event: "identity.unlinked", operation: "unlink_identity" }),
          outcome: "success",
          occurred_at: now,
        }, { now });
      });
      return authSuccess(null);
    } catch (error) {
      return mapUnexpected(error);
    }
  }

  /** Lists the authenticated user's safe identity projections. */
  async listIdentities(subject: OAuthSubject): Promise<AuthResult<readonly Identity[]>> {
    const authorized = await this.sessions.authorizeSession(subject.session);
    if (authorized.error !== null || authorized.data === null) return authFailure(authorized.error ?? unauthorized());
    try {
      return authSuccess(await adapterCall(async () => safeRepositoryIdentities(
        await this.repository.identities.listByUserId(authorized.data.user_id),
        authorized.data.user_id,
      )));
    } catch (error) {
      return mapUnexpected(error);
    }
  }

  private async runTransaction<T>(operation: (transaction: AuthRepository) => Promise<T>): Promise<T> {
    const candidate = await adapterTransaction(
      () => this.repository.transaction(async (transaction) =>
        trustedTransactionValue(await operation(transaction))),
      rethrowTrusted,
    );
    const trusted = takeTrustedTransactionValue<T>(candidate);
    if (!trusted.found) throw internalError();
    return trusted.value;
  }

  private resolveRedirect(value: string | null | undefined): string {
    const candidate = value ?? this.defaultRedirect;
    if (!this.allowedRedirects.includes(candidate)) throw new AuthApiError("redirect_not_allowed", 400, "Redirect URL is not allowed");
    return candidate;
  }

  private async authorizeSubject(subject: OAuthSubject): Promise<AuthResult<AuthenticatedSession>> {
    return this.sessions.authorizeSession(subject.session);
  }

  private async requireFreshLinkingSession(
    transaction: AuthRepository,
    sessionId: UUID,
    userId: UUID,
    now: Date,
  ): Promise<void> {
    const durable = await transaction.sessions.findByIdForUpdate(sessionId, { now });
    if (
      durable === null
      || durable.user_id !== userId
      || durable.revoked_at !== null
      || durable.expires_at <= now
      || now.getTime() < durable.created_at.getTime()
      || now.getTime() - durable.created_at.getTime() > this.freshSessionMaxAgeSeconds * 1000
    ) trustedFailure(unauthorized());
  }

  private async resolveProfile(
    transaction: AuthRepository,
    profile: OAuthProviderProfile,
    flow: OAuthFlow,
    linkingUserId: UUID | null,
    now: Date,
  ): Promise<ProfileResolution> {
    const foundIdentity = await transaction.identities.findByProviderSubject(profile.provider, profile.subject, { now });
    const existingIdentity = foundIdentity === null ? null : safeRepositoryIdentity(foundIdentity, {
      provider: profile.provider,
      subject: profile.subject,
    });
    if (existingIdentity !== null) {
      if (flow === "link_identity" && existingIdentity.user_id !== linkingUserId) {
        trustedFailure(new AuthApiError("identity_already_linked", 409, "This login identity is already linked"));
      }
      const user = await transaction.users.findByIdForUpdate(existingIdentity.user_id, { now });
      if (user === null || isBanned(user, now)) trustedFailure(unauthorized());
      if (flow === "link_identity" && existingIdentity.user_id === linkingUserId) {
        trustedFailure(new AuthApiError("identity_already_linked", 409, "This login identity is already linked"));
      }
      return { user, identity: existingIdentity };
    }

    let user: User | null = null;
    let emailAutoLinked = false;
    if (flow === "link_identity") {
      if (linkingUserId === null) trustedFailure(unauthorized());
      user = await transaction.users.findByIdForUpdate(linkingUserId, { now });
      if (user === null || isBanned(user, now)) trustedFailure(unauthorized());
    } else if (profile.email !== null) {
      user = await transaction.users.findByNormalizedEmailForUpdate(profile.email, { now });
      if (user !== null) {
        if (isDeleted(user) || isBanned(user, now)) trustedFailure(unauthorized());
        if (!(this.allowVerifiedEmailAutoLink && profile.emailVerified)) {
          trustedFailure(new AuthApiError("conflict", 409, "A user with this email already exists"));
        }
      }
      emailAutoLinked = user !== null;
    }
    if (user === null) {
      const created = await transaction.users.createIfAvailable({
        email: profile.email,
        email_confirmed_at: profile.emailVerified ? now : null,
        confirmed_at: profile.emailVerified ? now : null,
        user_metadata: {},
        app_metadata: {},
      }, { now });
      user = created;
      if (user === null && profile.email !== null) {
        const matched = await transaction.users.findByNormalizedEmailForUpdate(profile.email, { now });
        if (matched !== null && (isDeleted(matched) || isBanned(matched, now))) trustedFailure(unauthorized());
        if (matched !== null && this.allowVerifiedEmailAutoLink && profile.emailVerified) {
          user = matched;
          emailAutoLinked = true;
        } else {
          trustedFailure(new AuthApiError("conflict", 409, "A user with this email already exists"));
        }
      }
      if (user === null) trustedFailure(new AuthApiError("conflict", 409, "OAuth account could not be created"));
      if (created !== null) {
        const roles = await transaction.roles.list({ now });
        for (const key of this.defaultRoleKeys) {
          const role = roles.find((candidate) => candidate.key === key);
          if (role === undefined) trustedFailure(new AuthConfigurationError("configured default role is missing"));
          await transaction.authorization.assignRole({ user_id: user.id, role_id: role.id }, { now });
        }
      }
    }
    const createdIdentity = await transaction.identities.createIfAvailable({
      user_id: user.id,
      provider: profile.provider,
      provider_subject: profile.subject,
      email: profile.email,
      identity_data: profile.claims,
    }, { now });
    if (createdIdentity === null) {
      trustedFailure(new AuthApiError("identity_already_linked", 409, "This login identity is already linked"));
    }
    const identity = safeRepositoryIdentity(createdIdentity, {
      provider: profile.provider,
      subject: profile.subject,
      userId: user.id,
    });
    if (emailAutoLinked) {
      await transaction.operations.appendAudit({
        actor_user_id: user.id,
        action: "identity.email_auto_linked",
        target_type: "identity",
        target_id: identity.id,
        metadata: sanitizeRedactedMetadata({
          event: "identity.email_auto_linked",
          provider: profile.provider,
          operation: flow,
          target_id: identity.id,
        }),
        outcome: "success",
        occurred_at: now,
      }, { now });
    }
    return { user, identity };
  }
}
