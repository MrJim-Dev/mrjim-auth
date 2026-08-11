import { z, type ZodType } from "zod";
import type { AuthRepository } from "../../shared/contracts.js";
import type { AuthResult } from "../../shared/result.js";
import type { JsonObject, Session, User } from "../../shared/types.js";
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

const nonEmptyString = z.string().min(1);
const emailString = z.string().min(1).max(320);
const passwordString = z.string().min(8).max(1024);
const redirectString = z.string().min(1).max(2048);
const jsonObject = z.record(z.string(), z.json());

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
}

/** Request context supplied to public and current-user route handlers. */
export interface RouteContext {
  readonly request: Request;
  readonly requestId: string;
  readonly query: URLSearchParams;
  readonly body: unknown;
  readonly auth?: RouteAuthContext;
  readonly services: AuthServerServices;
  invoke<T>(operation: () => unknown): Promise<T>;
}

/** Shared route metadata used for exact dispatch and OpenAPI generation. */
export interface RouteContract {
  readonly method: "GET" | "POST" | "PUT" | "DELETE";
  readonly path: string;
  readonly operationId: string;
  readonly security: "api_key" | "user" | "signed";
  readonly query?: readonly { readonly name: string; readonly required: boolean; readonly description: string }[];
  readonly body?: ZodType;
  readonly response: ZodType;
  readonly example?: Readonly<Record<string, unknown>>;
}

const authResult = (schema: ZodType) => z.object({ data: schema, error: z.null() }).strict();

/** The single contract source for every Task 9 public/current-user route. */
export const routeContracts: readonly RouteContract[] = Object.freeze([
  { method: "POST", path: "/signup", operationId: "signUp", security: "api_key", body: signupRequestSchema, response: authResult(publicAuthDataSchema), example: { email: "user@example.com", password: "correct horse battery staple" } },
  { method: "POST", path: "/token", operationId: "signInWithPasswordOrRefresh", security: "api_key", query: [{ name: "grant_type", required: true, description: "password or refresh_token" }], body: tokenRequestSchema, response: authResult(sessionSchema), example: { email: "user@example.com", password: "correct horse battery staple" } },
  { method: "POST", path: "/otp", operationId: "signInWithOtp", security: "api_key", body: otpRequestSchema, response: authResult(publicAuthDataSchema), example: { email: "user@example.com", options: { type: "email_otp" } } },
  { method: "POST", path: "/verify", operationId: "verifyOtp", security: "api_key", body: verifyRequestSchema, response: authResult(publicAuthDataSchema), example: { email: "user@example.com", token: "123456", type: "email_otp" } },
  { method: "POST", path: "/recover", operationId: "resetPasswordForEmail", security: "api_key", body: recoverRequestSchema, response: authResult(sentSchema), example: { email: "user@example.com" } },
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
