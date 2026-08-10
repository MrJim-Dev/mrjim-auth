import { createHash } from "node:crypto";
import type {
  AuthRepository,
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
import { SessionService, type SessionContext } from "./sessions.js";

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
  readonly email?: string | null;
  readonly password?: string;
  readonly user_metadata?: Record<string, unknown>;
  readonly app_metadata?: Record<string, unknown>;
  readonly redirectTo?: string;
}

export interface ChangePasswordOptions {
  readonly currentPassword?: string;
  readonly preserveSessionId?: UUID;
  readonly context?: UserRequestContext | undefined;
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
          redirectTo: input.options?.redirectTo,
          context,
        });
        if (delivery.error !== null) return authFailure(delivery.error);
      } else {
        if (this.sessions === undefined) throw new AuthConfigurationError("session service is required when confirmation is disabled");
        const createdSession = await this.sessions.create(user, contextOptions(context));
        if (createdSession.error !== null) return authFailure(createdSession.error);
        session = createdSession.data;
      }
      await this.audit(user.id, "user.signup", "success", context, now);
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
      const now = validNow(this.clock);
      if (
        user.deleted_at !== null ||
        (user.banned_until !== null && new Date(user.banned_until).getTime() > now.getTime()) ||
        (this.requireEmailConfirmation && user.email_confirmed_at === null)
      ) {
        return authFailure(invalidCredentials());
      }

      const updated = await this.repository.transaction(async (transaction) => {
        if (verification.needsRehash) await transaction.passwordCredentials.upsert(user.id, await this.passwords.hash(input.password), now, { now });
        return transaction.users.update(user.id, { last_sign_in_at: now }, { now });
      });
      if (this.sessions === undefined) throw new AuthConfigurationError("session service is required for password sign-in");
      const createdSession = await this.sessions.create(updated, contextOptions(context));
      if (createdSession.error !== null) return authFailure(createdSession.error);
      await this.audit(updated.id, "user.sign_in", "success", context, now);
      return authSuccess(publicData(updated, createdSession.data, false));
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
          redirectTo: input.options?.redirectTo,
          context,
        });
        if (issued.error !== null) return authFailure(issued.error);
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
      const user = await this.repository.users.findByNormalizedEmail(parsed.normalized);
      const now = validNow(this.clock);
      if (user !== null && user.deleted_at === null && !isBanned(user, now)) {
        await this.passwords.verify("enumeration-resistant dummy password", null);
        const issued = await this.oneTimeTokens.issue({ purpose: "recovery", userId: user.id, target: parsed.normalized, to: parsed.display, redirectTo: options.redirectTo, context });
        if (issued.error !== null) return authFailure(issued.error);
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
      const user = await this.repository.users.findByNormalizedEmail(parsed.normalized);
      const now = validNow(this.clock);
      if (user !== null && user.deleted_at === null && !isBanned(user, now)) {
        await this.passwords.verify("enumeration-resistant dummy password", null);
        const issued = await this.oneTimeTokens.resend({ purpose: purposeForResend(input.type), userId: user.id, target: parsed.normalized, to: parsed.display, redirectTo: input.options?.redirectTo, context });
        if (issued.error !== null) return authFailure(issued.error);
      } else {
        await this.passwords.verify("enumeration-resistant dummy password", null);
      }
      return authSuccess({ sent: true });
    } catch (error) {
      return mapUnexpected(error);
    }
  }

  /** Updates profile/email fields; password changes use the dedicated revocation path. */
  async updateUser(userId: UUID, patch: UpdateUserInput, context?: UserRequestContext): Promise<AuthResult<{ readonly user: User }>> {
    try {
      const parsedId = uuidSchema.parse(userId);
      if (patch.password !== undefined) {
        const changed = await this.changePassword(parsedId, patch.password, { context });
        if (changed.error !== null || changed.data === null) return authFailure(changed.error ?? internalError());
        return authSuccess({ user: changed.data.user });
      }
      const now = validNow(this.clock);
      const input: Parameters<AuthRepository["users"]["update"]>[1] = {};
      if (patch.email !== undefined) {
        const email = patch.email === null ? null : normalizeAndValidateEmail(patch.email);
        input.email = email === null ? null : email.display;
        input.email_confirmed_at = null;
        input.confirmed_at = null;
      }
      if (patch.user_metadata !== undefined) input.user_metadata = patch.user_metadata as never;
      if (patch.app_metadata !== undefined) input.app_metadata = patch.app_metadata as never;
      const user = await this.repository.users.update(parsedId, input, { now });
      if (patch.email !== undefined && patch.email !== null) {
        const email = normalizeAndValidateEmail(patch.email);
        const issued = await this.oneTimeTokens.issue({ purpose: "email_change", userId: user.id, target: email.normalized, to: email.display, redirectTo: patch.redirectTo, context });
        if (issued.error !== null) return authFailure(issued.error);
      }
      await this.audit(user.id, "user.updated", "success", context, now);
      return authSuccess({ user });
    } catch (error) {
      return mapUnexpected(error);
    }
  }

  /** Changes a password and revokes every session unless preservation is explicit. */
  async changePassword(
    userId: UUID,
    password: string,
    options: ChangePasswordOptions = {},
  ): Promise<AuthResult<{ readonly user: User }>> {
    try {
      const id = uuidSchema.parse(userId);
      const user = await this.repository.users.findById(id);
      if (user === null) return authFailure(invalidCredentials());
      const now = validNow(this.clock);
      if (isBanned(user, now)) return authFailure(invalidCredentials());
      if (options.currentPassword !== undefined) {
        const current = await this.repository.passwordCredentials.findByUserId(id);
        const verified = await this.passwords.verify(options.currentPassword, current?.password_hash ?? null);
        if (!verified.valid) return authFailure(invalidCredentials());
      }
      const passwordHash = await this.passwords.hash(password);
      const updated = await this.repository.transaction(async (transaction) => {
        await transaction.passwordCredentials.upsert(id, passwordHash, now, { now });
        await transaction.sessions.revokeUserSessions(id, options.preserveSessionId, { now });
        const changed = await transaction.users.findById(id, { now });
        if (changed === null) throw new AuthApiError("invalid_credentials", 401, "Invalid login credentials");
        await transaction.operations.appendAudit({
          actor_user_id: id,
          target_type: "user",
          target_id: id,
          action: "user.password_changed",
          metadata: sanitizeRedactedMetadata({ event: "user.password_changed" }),
          outcome: "success",
          occurred_at: now,
        }, { now } satisfies RepositoryOperationOptions);
        return changed;
      });
      return authSuccess({ user: updated });
    } catch (error) {
      return mapUnexpected(error);
    }
  }

  /** Consumes a recovery token and applies the default all-session revocation policy. */
  async resetPassword(input: { readonly email: string; readonly token: string; readonly password: string; readonly redirectTo?: string }, context?: UserRequestContext): Promise<AuthResult<{ readonly user: User }>> {
    try {
      const parsed = normalizeAndValidateEmail(input.email);
      const limited = await this.checkRateLimits("recovery_verify", parsed.normalized, contextOptions(context));
      if (limited !== null) return limited as AuthResult<{ readonly user: User }>;
      const verified = await this.oneTimeTokens.verify({ purpose: "recovery", target: parsed.normalized, token: input.token, redirectTo: input.redirectTo });
      if (verified.error !== null) return authFailure(verified.error);
      if (verified.data.user_id === null) return authFailure(invalidCredentials());
      return this.changePassword(verified.data.user_id, input.password, { context });
    } catch (error) {
      return mapUnexpected(error);
    }
  }

  private async checkRateLimits(operation: string, identifier: string, context: UserRequestContext): Promise<AuthResult<never> | null> {
    if (this.rateLimiter === undefined) return null;
    const ip = typeof context.ip_address === "string" && context.ip_address.trim() !== "" ? context.ip_address.trim() : "unknown";
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
    const ip = typeof context?.ip_address === "string" && context.ip_address.trim() !== "" ? context.ip_address.trim() : null;
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
