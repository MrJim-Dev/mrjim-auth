import { createHash } from "node:crypto";
import type {
  AuthRepository,
  MailMessage,
  Mailer,
  RateLimiter,
  RepositoryOperationOptions,
} from "../shared/contracts.js";
import { authFailure, authSuccess, type AuthResult } from "../shared/result.js";
import { AuthApiError, AuthConfigurationError, AuthProgrammingError } from "../shared/errors.js";
import type { JsonObject, Session, User, UUID } from "../shared/types.js";
import { sanitizeRedactedMetadata, uuidSchema } from "../shared/types.js";
import { EmailService, normalizeAndValidateEmail } from "./email.js";
import { OneTimeTokenService, type OneTimeTokenPurpose } from "./one-time-tokens.js";
import { PasswordService } from "./passwords.js";
import { normalizeIpAddress, SessionService, type AuthenticatedSession, type SessionContext } from "./sessions.js";

export interface UserRequestContext extends SessionContext {
  readonly request_id?: string;
}

export interface SignUpInput {
  readonly email: string;
  readonly password: string;
  readonly options?: { readonly redirectTo?: string; readonly data?: JsonObject };
}

export interface SignInInput {
  readonly email: string;
  readonly password: string;
}

export interface OtpInput {
  readonly email: string;
  readonly options?: {
    readonly type?: "magic_link" | "email_otp";
    readonly redirectTo?: string;
  };
}

export interface VerifyOtpInput {
  readonly email: string;
  readonly token: string;
  readonly type: "magic_link" | "email_otp";
  readonly redirectTo?: string;
}

export interface ResendInput {
  readonly type: "signup" | "recovery";
  readonly email: string;
  readonly options?: { readonly redirectTo?: string };
}

export interface UpdateUserInput {
  readonly email?: string;
  readonly user_metadata?: JsonObject;
  readonly redirectTo?: string;
}

/** A self-service subject supplied by a trusted server-side auth boundary. */
export interface AuthenticatedSubject {
  readonly session: Session;
}

export interface ChangePasswordOptions {
  readonly currentPassword?: string;
  /** Optional explicit preservation of the calling session only. */
  readonly preserveSessionId?: UUID;
  readonly context?: UserRequestContext | undefined;
}

/** Redacted operational signal for a project-owned observer. */
export interface SafeOperationalFailure {
  readonly action: "signup" | "otp" | "recovery" | "resend";
  readonly template: MailMessage["template"];
  readonly outcome: "failure";
  readonly error_class: string;
  readonly request: {
    readonly ip_address: string | null;
    readonly user_agent: string | null;
  };
}

export interface UserServiceOptions {
  readonly repository: AuthRepository;
  readonly passwords: PasswordService;
  readonly email: EmailService;
  readonly mailer: Mailer;
  readonly oneTimeTokens: OneTimeTokenService;
  readonly sessions?: SessionService;
  readonly rateLimiter?: RateLimiter;
  readonly defaultRoleKeys?: readonly (string & {})[];
  readonly requireEmailConfirmation?: boolean;
  readonly concealUserExistence?: boolean;
  /** Receives only safe action/template/outcome/error-class fingerprints. */
  readonly onOperationalFailure?: (event: SafeOperationalFailure) => void | Promise<void>;
  readonly clock?: () => Date;
}

export interface PublicAuthData {
  readonly user: User | null;
  readonly session: Session | null;
}

function validNow(clock: () => Date): Date {
  const now = clock();
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) {
    throw new AuthConfigurationError("user service clock must return a valid Date");
  }
  return now;
}

function internalError(): AuthApiError {
  return new AuthApiError("internal_error", 500, "Internal authentication error");
}

function invalidCredentials(): AuthApiError {
  return new AuthApiError("invalid_credentials", 401, "Invalid login credentials");
}

function unauthorizedSubject(): AuthApiError {
  return new AuthApiError("unauthorized", 401, "Authenticated session is required");
}

function invalidApplicationMetadata(): AuthApiError {
  return new AuthApiError("invalid_request", 400, "Application metadata is managed by the server");
}

function repositoryCode(error: unknown): string | undefined {
  if (typeof error !== "object" || error === null) return undefined;
  const code = (error as { readonly code?: unknown }).code;
  return typeof code === "string" ? code : undefined;
}

function mapUnexpected(error: unknown): AuthResult<never> {
  if (error instanceof AuthApiError) return authFailure(error);
  if (error instanceof AuthConfigurationError || error instanceof AuthProgrammingError) throw error;
  return authFailure(internalError());
}

function contextOptions(context: UserRequestContext | undefined): UserRequestContext {
  return context ?? {};
}

function publicData(user: User | null, session: Session | null, conceal: boolean): PublicAuthData {
  return conceal ? { user: null, session: null } : { user, session };
}

function purposeForResend(type: ResendInput["type"]): OneTimeTokenPurpose {
  return type === "signup" ? "signup" : "recovery";
}

function isBanned(user: User, now: Date): boolean {
  return user.banned_until !== null && new Date(user.banned_until).getTime() > now.getTime();
}

function issueTemplate(purpose: OneTimeTokenPurpose): MailMessage["template"] {
  switch (purpose) {
    case "recovery": return "recovery";
    case "magic_link": return "magic_link";
    case "email_otp": return "email_otp";
    case "invite": return "invite";
    case "signup":
    case "email_change": return "confirmation";
  }
}

/** User/password, verification, OTP, recovery, and session orchestration. */
export class UserService {
  private readonly repository: AuthRepository;
  private readonly passwords: PasswordService;
  private readonly email: EmailService;
  private readonly mailer: Mailer;
  private readonly oneTimeTokens: OneTimeTokenService;
  private readonly sessions: SessionService | undefined;
  private readonly rateLimiter: RateLimiter | undefined;
  private readonly defaultRoleKeys: readonly string[];
  private readonly requireEmailConfirmation: boolean;
  private readonly concealUserExistence: boolean;
  private readonly onOperationalFailure: ((event: SafeOperationalFailure) => void | Promise<void>) | undefined;
  private readonly clock: () => Date;

  constructor(options: UserServiceOptions) {
    if (options.repository === null || typeof options.repository !== "object") {
      throw new AuthConfigurationError("user repository is required");
    }
    if (!(options.passwords instanceof PasswordService)) {
      throw new AuthConfigurationError("password service is required");
    }
    if (!(options.email instanceof EmailService)) {
      throw new AuthConfigurationError("email service is required");
    }
    if (!(options.oneTimeTokens instanceof OneTimeTokenService)) {
      throw new AuthConfigurationError("one-time-token service is required");
    }
    if (options.mailer === null || typeof options.mailer !== "object" || typeof options.mailer.send !== "function") {
      throw new AuthConfigurationError("mailer is required");
    }
    this.repository = options.repository;
    this.passwords = options.passwords;
    this.email = options.email;
    this.mailer = options.mailer;
    this.oneTimeTokens = options.oneTimeTokens;
    this.sessions = options.sessions;
    this.rateLimiter = options.rateLimiter;
    this.defaultRoleKeys = [...(options.defaultRoleKeys ?? [])].map((key) => key.toLowerCase());
    this.requireEmailConfirmation = options.requireEmailConfirmation ?? true;
    this.concealUserExistence = options.concealUserExistence ?? true;
    this.onOperationalFailure = options.onOperationalFailure;
    this.clock = options.clock ?? (() => new Date());
    validNow(this.clock);
  }

  /** Creates a user, password credential, default roles, and confirmation mail. */
  async signUp(input: SignUpInput, context?: UserRequestContext): Promise<AuthResult<PublicAuthData>> {
    let parsed: ReturnType<typeof normalizeAndValidateEmail>;
    try {
      parsed = normalizeAndValidateEmail(input.email);
      const limited = await this.checkRateLimits("signup", parsed.normalized, contextOptions(context));
      if (limited !== null) return limited;
      const redirectTo = this.oneTimeTokens.resolveRedirect(this.email.resolveRedirect(input.options?.redirectTo));
      const existing = await this.repository.users.findByNormalizedEmail(parsed.normalized);
      if (existing !== null) {
        await this.passwords.hash(input.password);
        if (this.concealUserExistence) return authSuccess(publicData(null, null, true));
        return authFailure(new AuthApiError("conflict", 409, "Email address is already registered"));
      }

      const passwordHash = await this.passwords.hash(input.password);
      const now = validNow(this.clock);
      const user = await this.repository.transaction(async (transaction) => {
        const created = await transaction.users.create({
          email: parsed.display,
          user_metadata: input.options?.data ?? {},
          app_metadata: {},
        }, { now });
        await transaction.passwordCredentials.upsert(created.id, passwordHash, now, { now });
        const roles = await transaction.roles.list({ now });
        for (const key of this.defaultRoleKeys) {
          const role = roles.find((candidate) => candidate.key === key);
          if (role === undefined) throw new AuthConfigurationError("configured default role is missing");
          await transaction.authorization.assignRole({ user_id: created.id, role_id: role.id }, { now });
        }
        return created;
      });

      let session: Session | null = null;
      if (this.requireEmailConfirmation) {
        const delivery = await this.oneTimeTokens.issue({
          purpose: "signup",
          userId: user.id,
          target: parsed.normalized,
          to: parsed.display,
          redirectTo,
          context,
        });
        const deliveryFailure = await this.handleIssuanceFailure(delivery, "signup", "confirmation", context);
        if (deliveryFailure !== null) return deliveryFailure;
      } else {
        if (this.sessions === undefined) throw new AuthConfigurationError("session service is required when confirmation is disabled");
        const createdSession = await this.sessions.create(user, contextOptions(context));
        if (createdSession.error !== null) return authFailure(createdSession.error);
        session = createdSession.data;
      }
      try {
        await this.audit(user.id, "user.signup", "success", context, now);
      } catch (error) {
        if (await this.concealOperationalFailure(error, "signup", "confirmation", context)) {
          return authSuccess(publicData(null, null, true));
        }
        throw error;
      }
      return authSuccess(publicData(user, session, this.concealUserExistence));
    } catch (error) {
      if (repositoryCode(error) === "email_exists" && this.concealUserExistence) {
        await this.passwords.hash(input.password);
        return authSuccess(publicData(null, null, true));
      }
      return mapUnexpected(error);
    }
  }

  /** Authenticates a password while doing equivalent dummy verification for unknown emails. */
  async signIn(input: SignInInput, context?: UserRequestContext): Promise<AuthResult<PublicAuthData>> {
    try {
      const parsed = normalizeAndValidateEmail(input.email);
      const limited = await this.checkRateLimits("sign_in", parsed.normalized, contextOptions(context));
      if (limited !== null) return limited;
      const user = await this.repository.users.findByNormalizedEmail(parsed.normalized);
      const credential = user === null ? null : await this.repository.passwordCredentials.findByUserId(user.id);
      const verification = await this.passwords.verify(input.password, credential?.password_hash ?? null);
      if (user === null || credential === null || !verification.valid) return authFailure(invalidCredentials());
      const sessions = this.sessions;
      if (sessions === undefined) throw new AuthConfigurationError("session service is required for password sign-in");
      const now = validNow(this.clock);
      const result = await this.repository.transaction(async (transaction) => {
        const lockedUser = await transaction.users.findByIdForUpdate(user.id, { now });
        const lockedCredential = lockedUser === null
          ? null
          : await transaction.passwordCredentials.findByUserId(user.id, { now });
        const lockedVerification = await this.passwords.verify(input.password, lockedCredential?.password_hash ?? null);
        if (
          lockedUser === null ||
          lockedCredential === null ||
          !lockedVerification.valid ||
          isBanned(lockedUser, now) ||
          (this.requireEmailConfirmation && lockedUser.email_confirmed_at === null)
        ) {
          throw invalidCredentials();
        }
        if (lockedVerification.needsRehash) {
          await transaction.passwordCredentials.upsert(user.id, await this.passwords.hash(input.password), now, { now });
        }
        const updated = await transaction.users.update(user.id, { last_sign_in_at: now }, { now });
        const createdSession = await sessions.create(updated, contextOptions(context), transaction);
        if (createdSession.error !== null) {
          if (createdSession.error.code === "invalid_request") throw invalidCredentials();
          throw createdSession.error;
        }
        return { user: updated, session: createdSession.data };
      });
      const updated = result.user;
      await this.audit(updated.id, "user.sign_in", "success", context, now);
      return authSuccess(publicData(updated, result.session, false));
    } catch (error) {
      return mapUnexpected(error);
    }
  }

  /** Starts a magic-link or email-OTP sign-in without revealing account state. */
  async signInWithOtp(input: OtpInput, context?: UserRequestContext): Promise<AuthResult<PublicAuthData>> {
    try {
      const parsed = normalizeAndValidateEmail(input.email);
      const limited = await this.checkRateLimits("otp", parsed.normalized, contextOptions(context));
      if (limited !== null) return limited;
      const redirectTo = this.oneTimeTokens.resolveRedirect(this.email.resolveRedirect(input.options?.redirectTo));
      const user = await this.repository.users.findByNormalizedEmail(parsed.normalized);
      if (user !== null) {
        const purpose = input.options?.type ?? "email_otp";
        await this.passwords.verify("enumeration-resistant dummy password", null);
        if (isBanned(user, validNow(this.clock))) {
          return authSuccess(publicData(null, null, true));
        }
        const issued = await this.oneTimeTokens.issue({
          purpose,
          userId: user.id,
          target: parsed.normalized,
          to: parsed.display,
          redirectTo,
          context,
        });
        const issuedFailure = await this.handleIssuanceFailure(issued, "otp", issueTemplate(purpose), context);
        if (issuedFailure !== null) return issuedFailure;
      } else {
        await this.passwords.verify("enumeration-resistant dummy password", null);
      }
      return authSuccess(publicData(null, null, true));
    } catch (error) {
      return mapUnexpected(error);
    }
  }

  /** Consumes an OTP or magic link and creates a session for a verified user. */
  async verifyOtp(input: VerifyOtpInput, context?: UserRequestContext): Promise<AuthResult<PublicAuthData>> {
    try {
      const parsed = normalizeAndValidateEmail(input.email);
      const purpose = input.type;
      const limited = await this.checkRateLimits("otp_verify", parsed.normalized, contextOptions(context));
      if (limited !== null) return limited;
      const verified = await this.oneTimeTokens.verify({
        purpose,
        target: parsed.normalized,
        token: input.token,
        redirectTo: input.redirectTo,
      });
      if (verified.error !== null) return authFailure(verified.error);
      if (verified.data.user_id === null) return authFailure(invalidCredentials());
      const user = await this.repository.users.findById(verified.data.user_id);
      if (user === null || isBanned(user, validNow(this.clock))) {
        return authFailure(invalidCredentials());
      }
      const now = validNow(this.clock);
      const confirmed = await this.repository.users.update(user.id, {
        email_confirmed_at: now,
        confirmed_at: now,
      }, { now });
      if (this.sessions === undefined) throw new AuthConfigurationError("session service is required for OTP verification");
      const session = await this.sessions.create(confirmed, contextOptions(context));
      if (session.error !== null) return authFailure(session.error);
      await this.audit(confirmed.id, `user.${purpose}.verified`, "success", context, now);
      return authSuccess(publicData(confirmed, session.data, false));
    } catch (error) {
      return mapUnexpected(error);
    }
  }

  /** Convenience wrapper for magic-link verification. */
  verifyMagicLink(input: Omit<VerifyOtpInput, "type">, context?: UserRequestContext): Promise<AuthResult<PublicAuthData>> {
    return this.verifyOtp({ ...input, type: "magic_link" }, context);
  }

  /** Confirms a signup/email-change token and optionally starts a session. */
  async confirmEmail(input: { readonly email: string; readonly token: string; readonly redirectTo?: string }, context?: UserRequestContext): Promise<AuthResult<PublicAuthData>> {
    try {
      const parsed = normalizeAndValidateEmail(input.email);
      const limited = await this.checkRateLimits("signup_verify", parsed.normalized, contextOptions(context));
      if (limited !== null) return limited;
      const verified = await this.oneTimeTokens.verify({ purpose: "signup", target: parsed.normalized, token: input.token, redirectTo: input.redirectTo });
      if (verified.error !== null) return authFailure(verified.error);
      if (verified.data.user_id === null) return authFailure(invalidCredentials());
      const now = validNow(this.clock);
      const user = await this.repository.users.findById(verified.data.user_id);
      if (user === null || isBanned(user, now)) return authFailure(invalidCredentials());
      const confirmed = await this.repository.users.update(user.id, { email_confirmed_at: now, confirmed_at: now }, { now });
      let session: Session | null = null;
      if (this.sessions !== undefined) {
        const created = await this.sessions.create(confirmed, contextOptions(context));
        if (created.error !== null) return authFailure(created.error);
        session = created.data;
      }
      await this.audit(confirmed.id, "user.email_confirmed", "success", context, now);
      return authSuccess({ user: confirmed, session });
    } catch (error) {
      return mapUnexpected(error);
    }
  }

  /** Sends a recovery request with one identical public result for every target. */
  async resetPasswordForEmail(email: string, options: { readonly redirectTo?: string } = {}, context?: UserRequestContext): Promise<AuthResult<{ readonly sent: true }>> {
    try {
      const parsed = normalizeAndValidateEmail(email);
      const limited = await this.checkRateLimits("recovery", parsed.normalized, contextOptions(context));
      if (limited !== null) return limited as AuthResult<{ readonly sent: true }>;
      const redirectTo = this.oneTimeTokens.resolveRedirect(this.email.resolveRedirect(options.redirectTo));
      const user = await this.repository.users.findByNormalizedEmail(parsed.normalized);
      const now = validNow(this.clock);
      if (user !== null && user.deleted_at === null && !isBanned(user, now)) {
        await this.passwords.verify("enumeration-resistant dummy password", null);
        const issued = await this.oneTimeTokens.issue({ purpose: "recovery", userId: user.id, target: parsed.normalized, to: parsed.display, redirectTo, context });
        const issuedFailure = await this.handleIssuanceFailure(issued, "recovery", "recovery", context);
        if (issuedFailure !== null) return issuedFailure as AuthResult<{ readonly sent: true }>;
      } else {
        await this.passwords.verify("enumeration-resistant dummy password", null);
      }
      return authSuccess({ sent: true });
    } catch (error) {
      return mapUnexpected(error);
    }
  }

  /** Resends signup or recovery mail while suppressing nonexistent-user delivery. */
  async resend(input: ResendInput, context?: UserRequestContext): Promise<AuthResult<{ readonly sent: true }>> {
    try {
      const parsed = normalizeAndValidateEmail(input.email);
      const limited = await this.checkRateLimits("resend", parsed.normalized, contextOptions(context));
      if (limited !== null) return limited as AuthResult<{ readonly sent: true }>;
      const redirectTo = this.oneTimeTokens.resolveRedirect(this.email.resolveRedirect(input.options?.redirectTo));
      const user = await this.repository.users.findByNormalizedEmail(parsed.normalized);
      const now = validNow(this.clock);
      if (user !== null && user.deleted_at === null && !isBanned(user, now)) {
        await this.passwords.verify("enumeration-resistant dummy password", null);
        const purpose = purposeForResend(input.type);
        const issued = await this.oneTimeTokens.resend({ purpose, userId: user.id, target: parsed.normalized, to: parsed.display, redirectTo, context });
        const issuedFailure = await this.handleIssuanceFailure(issued, "resend", issueTemplate(purpose), context);
        if (issuedFailure !== null) return issuedFailure as AuthResult<{ readonly sent: true }>;
      } else {
        await this.passwords.verify("enumeration-resistant dummy password", null);
      }
      return authSuccess({ sent: true });
    } catch (error) {
      return mapUnexpected(error);
    }
  }

  /** Updates only self-service metadata or starts a proof-gated email change. */
  async updateUser(subject: AuthenticatedSubject, patch: UpdateUserInput, context?: UserRequestContext): Promise<AuthResult<{ readonly user: User }>> {
    try {
      if (patch === null || typeof patch !== "object") return authFailure(new AuthApiError("invalid_request", 400, "Invalid user update"));
      if (Object.prototype.hasOwnProperty.call(patch, "app_metadata")) return authFailure(invalidApplicationMetadata());
      const allowedKeys = new Set(["email", "user_metadata", "redirectTo"]);
      if (Object.keys(patch).some((key) => !allowedKeys.has(key))) return authFailure(new AuthApiError("invalid_request", 400, "Invalid user update"));
      if (patch.email !== undefined && typeof patch.email !== "string") return authFailure(new AuthApiError("invalid_request", 400, "Invalid email address"));
      if (patch.email === undefined && patch.redirectTo !== undefined) return authFailure(new AuthApiError("invalid_request", 400, "Invalid user update"));
      const pendingEmail = patch.email === undefined ? undefined : normalizeAndValidateEmail(patch.email);
      const redirectTo = pendingEmail === undefined
        ? undefined
        : this.oneTimeTokens.resolveRedirect(this.email.resolveRedirect(patch.redirectTo));
      const authenticated = await this.authorizeSubject(subject);
      if (authenticated.error !== null || authenticated.data === null) return authFailure(authenticated.error ?? unauthorizedSubject());
      const now = validNow(this.clock);
      const user = await this.repository.transaction(async (transaction) => {
        const current = await this.lockAuthorizedUser(transaction, authenticated.data, now);
        const input: Parameters<AuthRepository["users"]["update"]>[1] = {};
        if (patch.user_metadata !== undefined) input.user_metadata = patch.user_metadata;
        return Object.keys(input).length === 0
          ? current
          : transaction.users.update(current.id, input, { now });
      });
      if (pendingEmail !== undefined) {
        const issued = await this.oneTimeTokens.issue({
          purpose: "email_change",
          userId: user.id,
          target: pendingEmail.normalized,
          to: pendingEmail.display,
          redirectTo,
          context,
        });
        if (issued.error !== null) return authFailure(issued.error);
      }
      await this.audit(user.id, "user.updated", "success", context, now);
      return authSuccess({ user });
    } catch (error) {
      return mapUnexpected(error);
    }
  }

  /** Changes the authenticated subject's password after current-password proof. */
  async changePassword(
    subject: AuthenticatedSubject,
    password: string,
    options: ChangePasswordOptions = {},
  ): Promise<AuthResult<{ readonly user: User }>> {
    try {
      const authenticated = await this.authorizeSubject(subject);
      if (authenticated.error !== null || authenticated.data === null) return authFailure(authenticated.error ?? unauthorizedSubject());
      if (options.currentPassword === undefined) return authFailure(invalidCredentials());
      if (options.preserveSessionId !== undefined && options.preserveSessionId !== authenticated.data.session_id) {
        return authFailure(new AuthApiError("invalid_request", 400, "Invalid session preservation request"));
      }
      const updated = await this.changePasswordForUser(
        authenticated.data,
        password,
        options.currentPassword,
        options.preserveSessionId,
        options.context,
      );
      return authSuccess({ user: updated });
    } catch (error) {
      return mapUnexpected(error);
    }
  }

  /** Consumes a proof-bound email-change token and only then replaces email. */
  async confirmEmailChange(
    input: { readonly email: string; readonly token: string; readonly redirectTo?: string },
    context?: UserRequestContext,
  ): Promise<AuthResult<{ readonly user: User }>> {
    try {
      const parsed = normalizeAndValidateEmail(input.email);
      const limited = await this.checkRateLimits("email_change_verify", parsed.normalized, contextOptions(context));
      if (limited !== null) return authFailure(limited.error ?? unauthorizedSubject());
      const consumed = await this.oneTimeTokens.consumeForMutation({
        purpose: "email_change",
        target: parsed.normalized,
        token: input.token,
        redirectTo: input.redirectTo,
      }, async (transaction, verified) => {
        if (verified.user_id === null || verified.target !== parsed.normalized) throw invalidCredentials();
        const now = validNow(this.clock);
        const current = await transaction.users.findByIdForUpdate(verified.user_id, { now });
        if (current === null || isBanned(current, now)) throw invalidCredentials();
        const duplicate = await transaction.users.findByNormalizedEmail(parsed.normalized, { now });
        if (duplicate !== null && duplicate.id !== current.id) {
          throw new AuthApiError("conflict", 409, "Email address is already registered");
        }
        const updated = await transaction.users.update(current.id, {
          email: parsed.display,
          email_confirmed_at: now,
          confirmed_at: now,
        }, { now });
        await transaction.sessions.revokeUserSessions(current.id, undefined, { now });
        await transaction.operations.appendAudit({
          actor_user_id: current.id,
          target_type: "user",
          target_id: current.id,
          action: "user.email_change_confirmed",
          metadata: sanitizeRedactedMetadata({ event: "user.email_change_confirmed" }),
          outcome: "success",
          occurred_at: now,
        }, { now } satisfies RepositoryOperationOptions);
        return updated;
      });
      if (consumed.error !== null) return authFailure(consumed.error);
      return authSuccess({ user: consumed.data });
    } catch (error) {
      if (repositoryCode(error) === "email_exists") return authFailure(new AuthApiError("conflict", 409, "Email address is already registered"));
      return mapUnexpected(error);
    }
  }

  /** Consumes a recovery token and applies the default all-session revocation policy. */
  async resetPassword(input: { readonly email: string; readonly token: string; readonly password: string; readonly redirectTo?: string }, context?: UserRequestContext): Promise<AuthResult<{ readonly user: User }>> {
    try {
      const parsed = normalizeAndValidateEmail(input.email);
      const redirectTo = this.email.resolveRedirect(input.redirectTo);
      const limited = await this.checkRateLimits("recovery_verify", parsed.normalized, contextOptions(context));
      if (limited !== null) return limited as AuthResult<{ readonly user: User }>;
      const verified = await this.oneTimeTokens.verify({ purpose: "recovery", target: parsed.normalized, token: input.token, redirectTo });
      if (verified.error !== null) return authFailure(verified.error);
      if (verified.data.user_id === null) return authFailure(invalidCredentials());
      const user = await this.changePasswordForRecovery(verified.data.user_id, input.password, context);
      return authSuccess({ user });
    } catch (error) {
      return mapUnexpected(error);
    }
  }

  private async authorizeSubject(subject: AuthenticatedSubject): Promise<AuthResult<AuthenticatedSession>> {
    if (
      subject === null ||
      typeof subject !== "object" ||
      subject.session === null ||
      typeof subject.session !== "object"
    ) return authFailure(unauthorizedSubject());
    if (this.sessions === undefined) throw new AuthConfigurationError("session service is required for self-service mutations");
    return this.sessions.authorizeSession(subject.session);
  }

  private async lockAuthorizedUser(
    transaction: AuthRepository,
    authenticated: AuthenticatedSession,
    now: Date,
  ): Promise<User> {
    const durableSession = await transaction.sessions.findByIdForUpdate(authenticated.session_id, { now });
    if (
      durableSession === null ||
      durableSession.user_id !== authenticated.user_id ||
      durableSession.revoked_at !== null ||
      durableSession.expires_at <= now
    ) throw unauthorizedSubject();
    const user = await transaction.users.findByIdForUpdate(authenticated.user_id, { now });
    if (user === null || isBanned(user, now)) throw unauthorizedSubject();
    return user;
  }

  private async changePasswordForUser(
    authenticated: AuthenticatedSession,
    password: string,
    currentPassword: string,
    preserveSessionId: UUID | undefined,
    context: UserRequestContext | undefined,
  ): Promise<User> {
    void context;
    const passwordHash = await this.passwords.hash(password);
    const now = validNow(this.clock);
    return this.repository.transaction(async (transaction) => {
      const currentUser = await this.lockAuthorizedUser(transaction, authenticated, now);
      const current = await transaction.passwordCredentials.findByUserId(currentUser.id, { now });
      const verified = await this.passwords.verify(currentPassword, current?.password_hash ?? null);
      if (!verified.valid) throw invalidCredentials();
      await transaction.passwordCredentials.upsert(currentUser.id, passwordHash, now, { now });
      await transaction.sessions.revokeUserSessions(currentUser.id, preserveSessionId, { now });
      const changed = await transaction.users.findByIdForUpdate(currentUser.id, { now });
      if (changed === null) throw invalidCredentials();
      await transaction.operations.appendAudit({
        actor_user_id: currentUser.id,
        target_type: "user",
        target_id: currentUser.id,
        action: "user.password_changed",
        metadata: sanitizeRedactedMetadata({ event: "user.password_changed" }),
        outcome: "success",
        occurred_at: now,
      }, { now } satisfies RepositoryOperationOptions);
      return changed;
    });
  }

  private async changePasswordForRecovery(
    userId: UUID,
    password: string,
    context: UserRequestContext | undefined,
  ): Promise<User> {
    void context;
    const passwordHash = await this.passwords.hash(password);
    const now = validNow(this.clock);
    return this.repository.transaction(async (transaction) => {
      const current = await transaction.users.findByIdForUpdate(userId, { now });
      if (current === null || isBanned(current, now)) throw invalidCredentials();
      await transaction.passwordCredentials.upsert(userId, passwordHash, now, { now });
      await transaction.sessions.revokeUserSessions(userId, undefined, { now });
      const changed = await transaction.users.findByIdForUpdate(userId, { now });
      if (changed === null) throw invalidCredentials();
      await transaction.operations.appendAudit({
        actor_user_id: userId,
        target_type: "user",
        target_id: userId,
        action: "user.password_reset",
        metadata: sanitizeRedactedMetadata({ event: "user.password_reset" }),
        outcome: "success",
        occurred_at: now,
      }, { now } satisfies RepositoryOperationOptions);
      return changed;
    });
  }

  private async handleIssuanceFailure(
    result: AuthResult<unknown>,
    action: SafeOperationalFailure["action"],
    template: MailMessage["template"],
    context: UserRequestContext | undefined,
  ): Promise<AuthResult<never> | null> {
    if (result.error === null) return null;
    if (await this.concealOperationalFailure(result.error, action, template, context)) return null;
    return authFailure(result.error);
  }

  private async concealOperationalFailure(
    error: unknown,
    action: SafeOperationalFailure["action"],
    template: MailMessage["template"],
    context: UserRequestContext | undefined,
  ): Promise<boolean> {
    if (!this.concealUserExistence || error instanceof AuthConfigurationError || error instanceof AuthProgrammingError) {
      return false;
    }
    if (error instanceof AuthApiError && error.code !== "internal_error") return false;
    await this.reportOperationalFailure(error, action, template, context);
    return true;
  }

  private async reportOperationalFailure(
    error: unknown,
    action: SafeOperationalFailure["action"],
    template: MailMessage["template"],
    context: UserRequestContext | undefined,
  ): Promise<void> {
    if (this.onOperationalFailure === undefined) return;
    const userAgent = typeof context?.user_agent === "string" && context.user_agent.length > 0
      ? `ua-sha256:${createHash("sha256").update(context.user_agent, "utf8").digest("hex")}`
      : null;
    const errorClass = error instanceof AuthApiError
      ? error.code
      : repositoryCode(error) === undefined
        ? "operational_error"
        : "repository_error";
    try {
      await this.onOperationalFailure({
        action,
        template,
        outcome: "failure",
        error_class: errorClass,
        request: {
          ip_address: normalizeIpAddress(context?.ip_address),
          user_agent: userAgent,
        },
      });
    } catch {
      // Observability is project-owned and must never change the auth result.
    }
  }

  private async checkRateLimits(operation: string, identifier: string, context: UserRequestContext): Promise<AuthResult<never> | null> {
    if (this.rateLimiter === undefined) return null;
    const ip = normalizeIpAddress(context.ip_address) ?? "unknown";
    const policy = { limit: operation === "sign_in" ? 10 : 5, windowSeconds: operation === "sign_in" ? 900 : 3600, bucket: operation } as const;
    const decisions = await Promise.all([
      this.rateLimiter.consume(`ip:${ip}`, policy),
      this.rateLimiter.consume(`identifier:${identifier}`, policy),
    ]);
    const denied = decisions.find((decision) => !decision.allowed);
    if (denied !== undefined) {
      return authFailure(new AuthApiError("rate_limit_exceeded", 429, "Too many authentication attempts"));
    }
    return null;
  }

  private async audit(userId: UUID, action: string, outcome: "success" | "failure", context: UserRequestContext | undefined, now: Date): Promise<void> {
    const userAgent = typeof context?.user_agent === "string" && context.user_agent.length > 0
      ? `ua-sha256:${createHash("sha256").update(context.user_agent, "utf8").digest("hex")}`
      : null;
    const ip = normalizeIpAddress(context?.ip_address);
    await this.repository.operations.appendAudit({
      actor_user_id: userId,
      target_type: "user",
      target_id: userId,
      action,
      ip_address: ip,
      user_agent: userAgent,
      metadata: sanitizeRedactedMetadata({ event: action.replaceAll(".", "_") }),
      outcome,
      occurred_at: now,
    }, { now } satisfies RepositoryOperationOptions);
  }
}
