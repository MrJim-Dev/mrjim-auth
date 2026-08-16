export {
  TokenService,
  type AccessTokenClaims,
  type TokenServiceOptions,
} from "./tokens.js";
export {
  SessionService,
  type AuthenticatedSession,
  type SessionContext,
  type SessionServiceOptions,
  type SignOutScope,
} from "./sessions.js";
export {
  ES256_ALGORITHM,
  type Es256Key,
  type PublicEs256Jwk,
} from "./jwks.js";
export {
  EmailService,
  type NormalizedEmail,
} from "./email.js";
export type { MailMessage, Mailer } from "../shared/contracts.js";
export {
  PasswordService,
  ARGON2ID_PASSWORD_POLICY,
  type PasswordPolicy,
  type PasswordVerification,
} from "./passwords.js";
export {
  OneTimeTokenService,
  type OneTimeTokenContext,
  type OneTimeTokenIssueInput,
  type OneTimeTokenIssueResult,
  type OneTimeTokenPurpose,
  type OneTimeTokenResendInput,
  type OneTimeTokenServiceOptions,
  type OneTimeTokenVerification,
  type OneTimeTokenVerifyInput,
} from "./one-time-tokens.js";
export {
  UserService,
  type AuthenticatedSubject,
  type ChangePasswordOptions,
  type OtpInput,
  type PublicAuthData,
  type ResendInput,
  type SignInInput,
  type SignUpInput,
  type SafeOperationalFailure,
  type UpdateUserInput,
  type UserRequestContext,
  type UserServiceOptions,
  type VerifyOtpInput,
} from "./users.js";
export {
  OAuthService,
  type OAuthAuthorizeInput,
  type OAuthAuthorizeResult,
  type OAuthCallbackInput,
  type OAuthCallbackResult,
  type OAuthExchangeInput,
  type OAuthFlow,
  type OAuthLinkResult,
  type OAuthProviderDiscovery,
  type OAuthServiceOptions,
  type OAuthSessionResult,
  type OAuthSubject,
} from "./oauth.js";
export {
  FacebookOAuthProvider,
  GenericOidcProvider,
  GoogleOAuthProvider,
  OAuthProviderError,
  OidcOAuthProvider,
  type OAuthProvider,
  type OAuthProviderAuthorizationInput,
  type OAuthProviderCapabilities,
  type OAuthProviderExchangeInput,
  type OAuthProviderProfile,
} from "./oauth-providers.js";
export {
  authorizeRoute,
  callbackRoute,
  createOAuthRoutes,
  exchangeRoute,
  providersRoute,
} from "./routes/oauth.js";
export {
  AuthorizationService,
  createAuthorizationRequestContext,
  normalizePermissionKey,
  permissionMatchRank,
  permissionMatches,
  subjectUserId,
  type AuthorizationRequirement,
  type AuthorizationRequestContext,
  type AuthorizationServiceOptions,
  type AuthorizationSubject,
} from "./authorization.js";
export {
  createPermissionRoutes,
  permissionsRoute,
} from "./routes/permissions.js";
export {
  AuthServer,
  type AuthServerRuntimeOptions,
  type AuthSubject,
} from "./auth-server.js";
export {
  createAuthServer,
  type AuthServerServiceOverrides,
  type CreateAuthServerOptions,
} from "./create-auth-server.js";
export { generateOpenApiDocument, type OpenApiDocumentOptions } from "./openapi.js";
export { createAdminClient, type AdminClient, type AdminClientOptions, type AdminNamespace } from "./admin.js";
export { AdminService, type AdminPrincipal, type AdminServiceOptions } from "./admin-service.js";
export { ApiKeyService, type ApiKeyServiceOptions, type ApiKeyStore, type SafeApiKeyRecord } from "./api-keys.js";
export { AuditService, type AuditStore, type PublicAuditEventRecord } from "./audit.js";
export {
  ADMIN_MUTATION_RATE_LIMIT_POLICY,
  InMemoryRateLimiter,
  LOGIN_IDENTIFIER_RATE_LIMIT_POLICY,
  LOGIN_IP_RATE_LIMIT_POLICY,
  OAUTH_START_RATE_LIMIT_POLICY,
  OTP_ISSUE_RATE_LIMIT_POLICY,
  OTP_VERIFY_RATE_LIMIT_POLICY,
  PostgresRateLimiter,
  RATE_LIMIT_POLICIES,
  RECOVERY_RATE_LIMIT_POLICY,
  RESEND_RATE_LIMIT_POLICY,
  SIGNUP_RATE_LIMIT_POLICY,
  type InMemoryRateLimiterOptions,
  type PostgresRateLimiterOptions,
  type RateLimitQueryExecutor,
} from "./rate-limit.js";
export type {
  RateLimitDecision,
  RateLimitPolicy,
  RateLimiter,
} from "../shared/contracts.js";
