import { z, type ZodType } from "zod";
import type { AuthRepository } from "../../shared/contracts.js";
import type { AuthResult } from "../../shared/result.js";
import { IMPORT_METADATA_LIMITS, isSafeImportMetadata, type JsonObject, type Session, type User } from "../../shared/types.js";
import type { AdminService } from "../admin-service.js";
import type {
  AuthenticatedSubject,
  OtpInput,
  PublicAuthData,
  ResendInput,
  SignInInput,
  SignUpInput,
  UpdateUserInput,
  UserRequestContext,
  VerifyOtpInput,
} from "../users.js";
import type { OAuthAuthorizeInput, OAuthCallbackInput, OAuthExchangeInput, OAuthProviderDiscovery, OAuthSessionResult, OAuthSubject } from "../oauth.js";
import type { AccessTokenClaims, TokenService } from "../tokens.js";
import type { AuthenticatedSession, SessionContext, SessionService, SignOutScope } from "../sessions.js";
import type { AuthorizationRequestContext, AuthorizationRequirement, AuthorizationService, AuthorizationSubject } from "../authorization.js";

const contractsTextEncoder = TextEncoder;
const contractsEncoder = new contractsTextEncoder();
const contractsEncode = contractsTextEncoder.prototype.encode;
const contractsReflectApply = Reflect.apply;
const RECOVERY_PASSWORD_MAX_UTF8_BYTES = 1024;
const nonEmptyString = z.string().min(1);
const emailString = z.string().min(1).max(320);
const passwordString = z.string().min(8).max(1024);
const recoveryPasswordString = passwordString.refine((value) => {
  try {
    const encoded = contractsReflectApply(contractsEncode, contractsEncoder, [value]) as Uint8Array;
    return encoded.byteLength <= RECOVERY_PASSWORD_MAX_UTF8_BYTES;
  } catch {
    return false;
  }
}, { message: "Password exceeds the UTF-8 byte limit" }).meta({
  description: "Password containing at most 1,024 UTF-8 bytes",
  "x-mrjim-maxUtf8Bytes": RECOVERY_PASSWORD_MAX_UTF8_BYTES,
});
const redirectString = z.string().min(1).max(2048);
const jsonObject = z.record(z.string(), z.json());
const boundedImportMetadataSchema = z.record(z.string().max(IMPORT_METADATA_LIMITS.maxKeyLength), z.json()).superRefine((value, context) => {
  if (!isSafeImportMetadata(value)) context.addIssue({ code: "custom", message: "metadata contains reserved credential material or exceeds the import bounds" });
}).meta({
  description: "Bounded JSON metadata up to 16 KiB; detectable reserved credential-bearing keys and values are rejected recursively. Callers must not send secrets or sessions.",
  "x-mrjim-maxDepth": IMPORT_METADATA_LIMITS.maxDepth,
  "x-mrjim-maxKeys": IMPORT_METADATA_LIMITS.maxKeys,
  "x-mrjim-maxKeyLength": IMPORT_METADATA_LIMITS.maxKeyLength,
  "x-mrjim-maxStringLength": IMPORT_METADATA_LIMITS.maxStringLength,
  "x-mrjim-maxBytes": IMPORT_METADATA_LIMITS.maxBytes,
  "x-mrjim-reservedKeyRule": "Rejects detectable password, password_hash, access/refresh tokens, sessions, OAuth/client secrets, private keys, and other sensitive key segments at every depth; detectable credential-bearing values are also rejected.",
});

export const userSchema = z.object({
  id: z.string().uuid(),
  email: z.string().nullable(),
  phone: z.string().nullable(),
  email_confirmed_at: z.string().nullable(),
  phone_confirmed_at: z.string().nullable(),
  confirmed_at: z.string().nullable(),
  last_sign_in_at: z.string().nullable(),
  banned_until: z.string().nullable(),
  user_metadata: jsonObject,
  app_metadata: jsonObject,
  created_at: z.string().min(1),
  updated_at: z.string().min(1),
  deleted_at: z.string().nullable(),
}).strict();

const identityDataSchema = z.object({
  sub: z.string().min(1).optional(),
  email: z.string().min(1).optional(),
  email_verified: z.boolean().optional(),
  name: z.string().min(1).optional(),
  given_name: z.string().min(1).optional(),
  family_name: z.string().min(1).optional(),
  picture: z.string().url().optional(),
  avatar_url: z.string().url().optional(),
  locale: z.string().min(1).optional(),
  hd: z.string().min(1).optional(),
  preferred_username: z.string().min(1).optional(),
}).strict();

export const identitySchema = z.object({
  id: z.string().uuid(),
  user_id: z.string().uuid(),
  provider: nonEmptyString,
  provider_subject: nonEmptyString,
  email: z.string().nullable(),
  identity_data: identityDataSchema,
  created_at: z.string().min(1),
  updated_at: z.string().min(1),
}).strict();

export const sessionSchema = z.object({
  access_token: nonEmptyString,
  refresh_token: nonEmptyString,
  token_type: z.literal("bearer"),
  expires_in: z.number().int().positive(),
  expires_at: z.number().int().positive(),
  user: userSchema,
}).strict();

export const publicAuthDataSchema = z.object({
  user: userSchema.nullable(),
  session: sessionSchema.nullable(),
}).strict();

export const sentSchema = z.object({ sent: z.literal(true) }).strict();
export const userDataSchema = z.object({ user: userSchema }).strict();
export const identitiesDataSchema = z.object({ identities: z.array(identitySchema) }).strict();
export const permissionsDataSchema = z.object({ permissions: z.array(nonEmptyString) }).strict();
export const providersDataSchema = z.object({ providers: z.array(z.object({
  name: nonEmptyString,
  scopes: z.array(nonEmptyString),
  capabilities: z.object({
    authorization_code: z.literal(true),
    pkce: z.literal(true),
    identity_linking: z.literal(true),
  }).strict(),
}).strict()) }).strict();
export const authorizeDataSchema = z.object({
  provider: nonEmptyString,
  url: z.string().url(),
  redirect: z.string().url(),
  expires_at: z.string().min(1),
}).strict();
export const exchangeDataSchema = z.object({
  user: userSchema,
  identity: identitySchema,
  session: sessionSchema,
}).strict();
export const jwksDataSchema = z.object({
  keys: z.array(z.record(z.string(), z.json())),
}).strict();

const optionsSchema = z.object({
  redirect_to: redirectString.optional(),
  data: jsonObject.optional(),
}).strict();

/** Strict wire request for `POST /signup`. */
export const signupRequestSchema = z.object({
  email: emailString,
  password: passwordString,
  options: optionsSchema.optional(),
}).strict();

/** Strict wire request for password token issuance. */
export const passwordTokenRequestSchema = z.object({
  email: emailString,
  password: passwordString,
}).strict();

/** Strict wire request for refresh-token rotation. */
export const refreshTokenRequestSchema = z.object({
  refresh_token: nonEmptyString,
}).strict();

export const tokenRequestSchema = z.union([passwordTokenRequestSchema, refreshTokenRequestSchema]);

/** Strict wire request for OTP/magic-link issuance. */
export const otpRequestSchema = z.object({
  email: emailString,
  options: z.object({
    type: z.enum(["magic_link", "email_otp"]).optional(),
    redirect_to: redirectString.optional(),
  }).strict().optional(),
}).strict();

/** Strict wire request for OTP/magic-link verification. */
export const verifyRequestSchema = z.object({
  email: emailString,
  token: nonEmptyString,
  type: z.enum(["magic_link", "email_otp"]),
  redirect_to: redirectString.optional(),
}).strict();

/** Strict wire request for non-enumerating recovery issuance. */
export const recoverRequestSchema = z.object({
  email: emailString,
  redirect_to: redirectString.optional(),
}).strict();

/** Strict wire request for consuming a recovery proof and replacing a password. */
export const recoverVerifyRequestSchema = z.object({
  email: emailString,
  token: z.string().min(1).max(128),
  password: recoveryPasswordString,
  redirect_to: redirectString.optional(),
}).strict();

/** Strict wire request for signup/recovery resend. */
export const resendRequestSchema = z.object({
  type: z.enum(["signup", "recovery"]),
  email: emailString,
  options: z.object({ redirect_to: redirectString.optional() }).strict().optional(),
}).strict();

/** Strict wire request for self-service user changes. */
export const updateUserRequestSchema = z.object({
  email: emailString.optional(),
  user_metadata: jsonObject.optional(),
  redirect_to: redirectString.optional(),
}).strict();

/** Strict wire request for logout by session or refresh token. */
export const logoutRequestSchema = z.object({
  scope: z.enum(["local", "global", "others"]).optional(),
  refresh_token: nonEmptyString.optional(),
}).strict();

/** Strict wire request for one-time OAuth-code exchange. */
export const exchangeRequestSchema = z.object({
  code: nonEmptyString,
  code_verifier: nonEmptyString,
  redirect_to: redirectString.optional(),
}).strict();

export const nullDataSchema = z.null();

const uuidString = z.string().uuid();
const nullableIsoInput = z.iso.datetime({ offset: true }).nullable();
export const adminPageQuery = [
  { name: "page", required: false, description: "One-based page number" },
  { name: "per_page", required: false, description: "Page size from 1 to 100" },
] as const;
export const adminUserCreateRequestSchema = z.object({
  email: emailString.nullable().optional(), phone: z.string().min(1).max(64).nullable().optional(),
  email_confirmed_at: nullableIsoInput.optional(), phone_confirmed_at: nullableIsoInput.optional(),
  confirmed_at: nullableIsoInput.optional(), user_metadata: jsonObject.optional(), app_metadata: jsonObject.optional(),
}).strict();
export const adminUserImportRequestSchema = z.object({
  id: uuidString,
  email: emailString.nullable().optional(), phone: z.string().min(1).max(64).nullable().optional(),
  email_confirmed_at: nullableIsoInput.optional(), phone_confirmed_at: nullableIsoInput.optional(),
  confirmed_at: nullableIsoInput.optional(), last_sign_in_at: nullableIsoInput.optional(),
  banned_until: nullableIsoInput.optional(), user_metadata: boundedImportMetadataSchema.optional(),
  app_metadata: boundedImportMetadataSchema.optional(),
}).strict().meta({
  description: "Import-only user creation. Requires a secret API key carrying the literal auth.users.import scope. The supplied UUID is preserved; equivalent retries are idempotent, conflicts return 409, and detectable credential/session material is rejected. Callers must not send secrets or sessions.",
});
export const adminUserUpdateRequestSchema = adminUserCreateRequestSchema.extend({
  last_sign_in_at: nullableIsoInput.optional(), banned_until: nullableIsoInput.optional(),
}).strict();
export const adminInviteRequestSchema = z.object({ email: emailString, options: jsonObject.optional() }).strict();
export const adminRoleCreateRequestSchema = z.object({ key: z.string().min(1).max(128), name: z.string().min(1).max(256), description: z.string().max(2048).nullable().optional(), rank: z.number().int().nonnegative(), is_system: z.boolean().optional() }).strict();
export const adminRoleUpdateRequestSchema = adminRoleCreateRequestSchema.partial().strict();
export const adminPermissionCreateRequestSchema = z.object({ key: z.string().min(3).max(256), resource: z.string().min(1).max(192), action: z.string().min(1).max(64), description: z.string().max(2048).nullable().optional() }).strict();
export const adminPermissionUpdateRequestSchema = adminPermissionCreateRequestSchema.partial().strict();
export const adminPermissionIdsRequestSchema = z.object({ permission_ids: z.array(uuidString).max(10_000) }).strict();
export const adminInheritedRoleIdsRequestSchema = z.object({ inherited_role_ids: z.array(uuidString).max(10_000) }).strict();
export const adminUsersDataSchema = z.object({ users: z.array(userSchema), total: z.number().int().nonnegative(), page: z.number().int().positive(), per_page: z.number().int().positive() }).strict();
export const adminUserDataSchema = z.object({ user: userSchema.nullable() }).strict();
const adminRoleResponseSchema = z.object({
  id: uuidString, key: z.string().min(1), name: z.string().min(1), description: z.string().nullable(),
  rank: z.number().int().nonnegative(), is_system: z.boolean(), created_at: z.string().min(1), updated_at: z.string().min(1),
}).strict();
const adminPermissionResponseSchema = z.object({
  id: uuidString, key: z.string().min(1), resource: z.string().min(1), action: z.string().min(1), description: z.string().nullable(),
  created_at: z.string().min(1), updated_at: z.string().min(1),
}).strict();
export const adminRolesDataSchema = z.object({ roles: z.array(adminRoleResponseSchema) }).strict();
export const adminRoleDataSchema = z.object({ role: adminRoleResponseSchema }).strict();
export const adminPermissionsDataSchema = z.object({ permissions: z.array(adminPermissionResponseSchema) }).strict();
export const adminPermissionDataSchema = z.object({ permission: adminPermissionResponseSchema }).strict();
export const adminAuditEventSchema = z.object({
  id: uuidString, actor_user_id: uuidString.nullable(), actor_key_id: uuidString.nullable(), actor_session_id: uuidString.nullable(),
  action: nonEmptyString, target_type: nonEmptyString, target_id: uuidString.nullable(), ip_address: z.string().nullable(),
  user_agent: z.string().nullable(), metadata: jsonObject, outcome: z.enum(["success", "failure"]), occurred_at: nonEmptyString,
}).strict();
export const adminAuditDataSchema = z.object({ events: z.array(adminAuditEventSchema), total: z.number().int().nonnegative(), page: z.number().int().positive(), per_page: z.number().int().positive() }).strict();

/** A safe response produced by a route before the final response boundary. */
export type RouteOutput =
  | {
      readonly kind: "service";
      readonly result: unknown;
      readonly mapData: (data: unknown) => unknown;
      readonly schema: ZodType;
      readonly status?: number;
      readonly cache?: "no-store" | "public";
    }
  | {
      readonly kind: "redirect";
      readonly status: 303;
      readonly location: string;
    }
  | {
      readonly kind: "callback";
      readonly result: unknown;
    };

/** The request-local authentication state passed to current-user routes. */
export interface RouteAuthContext {
  readonly key: {
    readonly id: string;
    readonly kind: "publishable" | "secret";
    readonly scopes: readonly string[];
  };
  readonly subject?: AuthenticatedSubject;
  readonly authorizationSubject?: AuthorizationSubject;
  readonly authorizationContext?: AuthorizationRequestContext;
  readonly session?: AuthenticatedSession;
}

/** Structural service surface used by the framework-neutral route handlers. */
export interface AuthServerServices {
  readonly users: {
    signUp(input: SignUpInput, context?: UserRequestContext): unknown;
    signIn(input: SignInInput, context?: UserRequestContext): unknown;
    signInWithOtp(input: OtpInput, context?: UserRequestContext): unknown;
    verifyOtp(input: VerifyOtpInput, context?: UserRequestContext): unknown;
    resetPasswordForEmail(email: string, options?: { readonly redirectTo?: string }, context?: UserRequestContext): unknown;
    resetPassword(input: { readonly email: string; readonly token: string; readonly password: string; readonly redirectTo?: string }, context?: UserRequestContext): unknown;
    resend(input: ResendInput, context?: UserRequestContext): unknown;
    updateUser(subject: AuthenticatedSubject, patch: UpdateUserInput, context?: UserRequestContext): unknown;
  };
  readonly sessions: {
    refresh(refreshToken: string, context?: SessionContext): unknown;
    authorizeSession(session: Session): unknown;
    signOut(session: Session, scope: SignOutScope): unknown;
    revokeRefreshToken?(refreshToken: string, scope: SignOutScope): unknown;
  };
  readonly tokens: Pick<TokenService, "verifyAccessToken" | "jwks"> & {
    verifyAccessToken(jwt: string): unknown;
    jwks(): unknown;
  };
  readonly oauth?: {
    listProviders(): readonly OAuthProviderDiscovery[];
    authorize(input: OAuthAuthorizeInput): unknown;
    callback(input: OAuthCallbackInput): unknown;
    exchangeCode(input: OAuthExchangeInput): unknown;
    listIdentities(subject: OAuthSubject): unknown;
    unlinkIdentity(subject: OAuthSubject, identityId: string): unknown;
  };
  readonly authorization: Pick<AuthorizationService, "getPermissions" | "authorize"> & {
    getPermissions(userId: string, scope?: unknown, context?: AuthorizationRequestContext): unknown;
    authorize(subject: unknown, requirement: AuthorizationRequirement, context?: AuthorizationRequestContext): unknown;
  };
  readonly admin?: AdminService;
}

/** Request context supplied to public and current-user route handlers. */
export interface RouteContext {
  readonly request: Request;
  readonly requestId: string;
  readonly query: URLSearchParams;
  readonly body: unknown;
  readonly params?: Readonly<Record<string, string>>;
  readonly auth?: RouteAuthContext;
  readonly services: AuthServerServices;
  invoke<T>(operation: () => unknown): Promise<T>;
}

/** Shared route metadata used for exact dispatch and OpenAPI generation. */
export interface RouteContract {
  readonly method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  readonly path: string;
  readonly operationId: string;
  readonly security: "api_key" | "user" | "admin" | "admin_import" | "signed";
  readonly query?: readonly { readonly name: string; readonly required: boolean; readonly description: string }[];
  readonly body?: ZodType;
  readonly response: ZodType;
  readonly example?: Readonly<Record<string, unknown>>;
  readonly description?: string;
}

const authResult = (schema: ZodType) => z.object({ data: schema, error: z.null() }).strict();

/** The single contract source for every Task 9 public/current-user route. */
export const routeContracts: readonly RouteContract[] = Object.freeze([
  { method: "POST", path: "/signup", operationId: "signUp", security: "api_key", body: signupRequestSchema, response: authResult(publicAuthDataSchema), example: { email: "user@example.com", password: "correct horse battery staple" } },
  { method: "POST", path: "/token", operationId: "signInWithPasswordOrRefresh", security: "api_key", query: [{ name: "grant_type", required: true, description: "password or refresh_token" }], body: tokenRequestSchema, response: authResult(sessionSchema), example: { email: "user@example.com", password: "correct horse battery staple" } },
  { method: "POST", path: "/otp", operationId: "signInWithOtp", security: "api_key", body: otpRequestSchema, response: authResult(publicAuthDataSchema), example: { email: "user@example.com", options: { type: "email_otp" } } },
  { method: "POST", path: "/verify", operationId: "verifyOtp", security: "api_key", body: verifyRequestSchema, response: authResult(publicAuthDataSchema), example: { email: "user@example.com", token: "123456", type: "email_otp" } },
  { method: "POST", path: "/recover", operationId: "resetPasswordForEmail", security: "api_key", body: recoverRequestSchema, response: authResult(sentSchema), example: { email: "user@example.com" } },
  { method: "POST", path: "/recover/verify", operationId: "resetPassword", security: "api_key", body: recoverVerifyRequestSchema, response: authResult(userDataSchema), example: { email: "user@example.com", token: "123456", password: "new correct horse battery staple" } },
  { method: "POST", path: "/resend", operationId: "resend", security: "api_key", body: resendRequestSchema, response: authResult(sentSchema), example: { type: "signup", email: "user@example.com" } },
  { method: "GET", path: "/providers", operationId: "listProviders", security: "api_key", response: authResult(providersDataSchema) },
  { method: "GET", path: "/authorize", operationId: "authorizeOAuth", security: "api_key", query: [{ name: "provider", required: true, description: "Configured provider key" }, { name: "code_challenge", required: true, description: "Client-generated RFC 7636 S256 challenge" }, { name: "code_challenge_method", required: false, description: "Must be S256 when supplied" }, { name: "redirect_to", required: false, description: "Exact allowlisted redirect" }, { name: "flow", required: false, description: "sign_in or link_identity" }], response: authResult(authorizeDataSchema) },
  { method: "GET", path: "/callback/{provider}", operationId: "oauthCallback", security: "signed", query: [{ name: "code", required: true, description: "Provider authorization code" }, { name: "state", required: true, description: "Signed PKCE state" }], response: nullDataSchema },
  { method: "POST", path: "/exchange", operationId: "exchangeCodeForSession", security: "api_key", body: exchangeRequestSchema, response: authResult(exchangeDataSchema), example: { code: "callback-code", code_verifier: "verifier" } },
  { method: "GET", path: "/user", operationId: "getUser", security: "user", response: authResult(userDataSchema) },
  { method: "PUT", path: "/user", operationId: "updateUser", security: "user", body: updateUserRequestSchema, response: authResult(userDataSchema), example: { user_metadata: { display_name: "Updated" } } },
  { method: "GET", path: "/user/identities", operationId: "getUserIdentities", security: "user", response: authResult(identitiesDataSchema) },
  { method: "DELETE", path: "/user/identities/{id}", operationId: "unlinkIdentity", security: "user", response: authResult(nullDataSchema) },
  { method: "GET", path: "/user/permissions", operationId: "getUserPermissions", security: "user", query: [{ name: "scope_type", required: false, description: "Scope type" }, { name: "scope_id", required: false, description: "Scope identifier" }], response: authResult(permissionsDataSchema) },
  { method: "POST", path: "/logout", operationId: "signOut", security: "api_key", body: logoutRequestSchema, response: authResult(nullDataSchema) },
  { method: "GET", path: "/.well-known/jwks.json", operationId: "jwks", security: "api_key", response: authResult(jwksDataSchema) },
  { method: "GET", path: "/admin/users", operationId: "adminListUsers", security: "admin", query: adminPageQuery, response: authResult(adminUsersDataSchema) },
  { method: "POST", path: "/admin/users", operationId: "adminCreateUser", security: "admin", body: adminUserCreateRequestSchema, response: authResult(adminUserDataSchema) },
  { method: "POST", path: "/admin/users/import", operationId: "adminImportUser", security: "admin_import", body: adminUserImportRequestSchema, response: authResult(adminUserDataSchema), example: { id: "11111111-1111-4111-8111-111111111111", email: "user@example.com", user_metadata: { source: "legacy" } }, description: "Import one user with a preserved UUID. Requires a non-interactive secret API key with the literal auth.users.import scope; publishable keys, bearer sessions, wildcard scopes, and detectable reserved credential material are rejected. Callers must not send secrets or sessions." },
  { method: "GET", path: "/admin/users/find", operationId: "adminFindUser", security: "admin", query: [{ name: "email", required: true, description: "Exact normalized email" }], response: authResult(adminUserDataSchema) },
  { method: "POST", path: "/admin/users/invite", operationId: "adminInviteUser", security: "admin", body: adminInviteRequestSchema, response: authResult(z.object({ invited: z.unknown() }).strict()) },
  { method: "GET", path: "/admin/users/{id}", operationId: "adminGetUser", security: "admin", response: authResult(adminUserDataSchema) },
  { method: "PATCH", path: "/admin/users/{id}", operationId: "adminUpdateUser", security: "admin", body: adminUserUpdateRequestSchema, response: authResult(adminUserDataSchema) },
  { method: "DELETE", path: "/admin/users/{id}", operationId: "adminDeleteUser", security: "admin", query: [{ name: "soft", required: false, description: "Must be true; hard delete is unsupported" }], response: authResult(adminUserDataSchema) },
  { method: "PUT", path: "/admin/users/{id}/roles/{roleId}", operationId: "adminAssignRole", security: "admin", query: [{ name: "scope_type", required: false, description: "Optional scope type" }, { name: "scope_id", required: false, description: "Optional scope id" }], response: authResult(nullDataSchema) },
  { method: "DELETE", path: "/admin/users/{id}/roles/{roleId}", operationId: "adminUnassignRole", security: "admin", query: [{ name: "scope_type", required: false, description: "Optional scope type" }, { name: "scope_id", required: false, description: "Optional scope id" }], response: authResult(nullDataSchema) },
  { method: "GET", path: "/admin/roles", operationId: "adminListRoles", security: "admin", response: authResult(adminRolesDataSchema) },
  { method: "POST", path: "/admin/roles", operationId: "adminCreateRole", security: "admin", body: adminRoleCreateRequestSchema, response: authResult(adminRoleDataSchema) },
  { method: "PATCH", path: "/admin/roles/{id}", operationId: "adminUpdateRole", security: "admin", body: adminRoleUpdateRequestSchema, response: authResult(adminRoleDataSchema) },
  { method: "DELETE", path: "/admin/roles/{id}", operationId: "adminDeleteRole", security: "admin", response: authResult(nullDataSchema) },
  { method: "PUT", path: "/admin/roles/{id}/permissions", operationId: "adminSetRolePermissions", security: "admin", body: adminPermissionIdsRequestSchema, response: authResult(nullDataSchema) },
  { method: "PUT", path: "/admin/roles/{id}/inheritance", operationId: "adminSetRoleInheritance", security: "admin", body: adminInheritedRoleIdsRequestSchema, response: authResult(nullDataSchema) },
  { method: "GET", path: "/admin/permissions", operationId: "adminListPermissions", security: "admin", response: authResult(adminPermissionsDataSchema) },
  { method: "POST", path: "/admin/permissions", operationId: "adminCreatePermission", security: "admin", body: adminPermissionCreateRequestSchema, response: authResult(adminPermissionDataSchema) },
  { method: "PATCH", path: "/admin/permissions/{id}", operationId: "adminUpdatePermission", security: "admin", body: adminPermissionUpdateRequestSchema, response: authResult(adminPermissionDataSchema) },
  { method: "DELETE", path: "/admin/permissions/{id}", operationId: "adminDeletePermission", security: "admin", response: authResult(nullDataSchema) },
  { method: "GET", path: "/admin/audit", operationId: "adminListAudit", security: "admin", query: adminPageQuery, response: authResult(adminAuditDataSchema) },
]);

export type {
  AccessTokenClaims,
  AuthenticatedSession,
  AuthRepository,
  AuthorizationRequestContext,
  AuthorizationRequirement,
  AuthorizationService,
  AuthorizationSubject,
  AuthenticatedSubject,
  JsonObject,
  OAuthSessionResult,
  PublicAuthData,
  Session,
  User,
  AuthResult,
};
