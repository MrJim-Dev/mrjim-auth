import { createHash, createHmac, randomBytes } from "node:crypto";
import { isIP } from "node:net";
import type {
  AuthRepository,
  MailMessage,
  Mailer,
  OneTimeTokenInput,
  RepositoryOperationOptions,
} from "../shared/contracts.js";
import { authFailure, authSuccess, type AuthResult } from "../shared/result.js";
import { AuthApiError, AuthConfigurationError, AuthProgrammingError } from "../shared/errors.js";
import { sanitizeRedactedMetadata, type UUID } from "../shared/types.js";
import { EmailService, normalizeAndValidateEmail } from "./email.js";

/** Every supported one-time flow is purpose-bound in PostgreSQL. */
export type OneTimeTokenPurpose = OneTimeTokenInput["purpose"];

export interface OneTimeTokenIssueInput {
  readonly purpose: OneTimeTokenPurpose;
  readonly userId?: UUID | null;
  readonly user_id?: UUID | null;
  /** Internal normalized binding target. */
  readonly target: string;
  /** Display destination used only at the mailer boundary. */
  readonly to?: string;
  readonly redirectTo?: string | null | undefined;
  readonly redirect?: string | null | undefined;
  readonly metadata?: unknown;
  readonly ttlSeconds?: number;
  readonly context?: OneTimeTokenContext | undefined;
}

export interface OneTimeTokenVerifyInput {
  readonly purpose: OneTimeTokenPurpose;
  readonly target: string;
  readonly token: string;
  readonly redirectTo?: string | null | undefined;
  readonly redirect?: string | null | undefined;
}

export interface OneTimeTokenResendInput extends OneTimeTokenIssueInput {}

export interface OneTimeTokenContext {
  readonly ip_address?: string | null;
  readonly user_agent?: string | null;
}

export interface OneTimeTokenIssueResult {
  readonly sent: true;
  readonly expires_at: string;
}

export interface OneTimeTokenVerification {
  readonly user_id: UUID | null;
  readonly purpose: OneTimeTokenPurpose;
  readonly target: string;
  readonly redirect: string | null;
  readonly expires_at: Date;
}

export interface OneTimeTokenServiceOptions {
  readonly repository: AuthRepository;
  readonly mailer: Mailer;
  readonly email: EmailService;
  readonly tokenHashKey: string | Uint8Array;
  readonly allowedRedirects?: readonly string[];
  readonly defaultRedirect?: string;
  readonly clock?: () => Date;
}

const DEFAULT_RECOVERY_TTL_SECONDS = 15 * 60;
const DEFAULT_SIGNUP_TTL_SECONDS = 24 * 60 * 60;
const DEFAULT_SHORT_TTL_SECONDS = 15 * 60;
const tokenPurposeSet = new Set<OneTimeTokenPurpose>([
  "signup",
  "email_change",
  "recovery",
  "magic_link",
  "email_otp",
  "invite",
]);

function validNow(clock: () => Date): Date {
  const now = clock();
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) {
    throw new AuthConfigurationError("one-time-token clock must return a valid Date");
  }
  return now;
}

function validPurpose(value: unknown): OneTimeTokenPurpose {
  if (typeof value !== "string" || !tokenPurposeSet.has(value as OneTimeTokenPurpose)) {
    throw new AuthProgrammingError("unsupported one-time-token purpose");
  }
  return value as OneTimeTokenPurpose;
}

function defaultTtl(purpose: OneTimeTokenPurpose): number {
  if (purpose === "recovery") return DEFAULT_RECOVERY_TTL_SECONDS;
  if (purpose === "signup") return DEFAULT_SIGNUP_TTL_SECONDS;
  return DEFAULT_SHORT_TTL_SECONDS;
}

function templateFor(purpose: OneTimeTokenPurpose): MailMessage["template"] {
  switch (purpose) {
    case "signup":
    case "email_change":
      return "confirmation";
    case "recovery":
      return "recovery";
    case "magic_link":
      return "magic_link";
    case "email_otp":
      return "email_otp";
    case "invite":
      return "invite";
  }
}

function auditContext(context: OneTimeTokenContext | undefined): {
  readonly ip_address: string | null;
  readonly user_agent: string | null;
} {
  const ip = typeof context?.ip_address === "string" ? context.ip_address.trim() : "";
  const ip_address = ip !== "" && ip.length <= 45 && isIP(ip) !== 0 ? ip.toLowerCase() : null;
  const userAgent = context?.user_agent;
  const user_agent = typeof userAgent === "string" && userAgent.length > 0
    ? `ua-sha256:${createHash("sha256").update(userAgent, "utf8").digest("hex")}`
    : null;
  return { ip_address, user_agent };
}

function internalError(): AuthApiError {
  return new AuthApiError("internal_error", 500, "Internal authentication error");
}

function mapOperationalError(error: unknown): AuthResult<never> {
  if (error instanceof AuthApiError) return authFailure(error);
  if (error instanceof AuthConfigurationError || error instanceof AuthProgrammingError) throw error;
  return authFailure(internalError());
}

/** Server-only purpose-bound token issuer/verifier with project-owned mail. */
export class OneTimeTokenService {
  private readonly repository: AuthRepository;
  private readonly mailer: Mailer;
  private readonly email: EmailService;
  private readonly tokenHashKey: Uint8Array;
  private readonly clock: () => Date;
  private readonly allowedRedirects: readonly string[];
  private readonly defaultRedirect: string;

  constructor(options: OneTimeTokenServiceOptions) {
    if (options.repository === null || typeof options.repository !== "object" || typeof options.repository.transaction !== "function") {
      throw new AuthConfigurationError("one-time-token repository is incomplete");
    }
    if (options.mailer === null || typeof options.mailer !== "object" || typeof options.mailer.send !== "function") {
      throw new AuthConfigurationError("one-time-token mailer is incomplete");
    }
    if (!(options.email instanceof EmailService)) {
      throw new AuthConfigurationError("email redirect service is required");
    }
    const tokenHashKey = typeof options.tokenHashKey === "string"
      ? new TextEncoder().encode(options.tokenHashKey)
      : Uint8Array.from(options.tokenHashKey);
    if (tokenHashKey.byteLength === 0) throw new AuthConfigurationError("one-time-token hash key is empty");
    this.repository = options.repository;
    this.mailer = options.mailer;
    this.email = options.email;
    this.tokenHashKey = tokenHashKey;
    this.clock = options.clock ?? (() => new Date());
    this.allowedRedirects = [...(options.allowedRedirects ?? options.email.allowedRedirects)];
    this.defaultRedirect = options.defaultRedirect ?? this.allowedRedirects[0] ?? options.email.defaultRedirect;
    if (this.allowedRedirects.length === 0 || !this.allowedRedirects.includes(this.defaultRedirect)) {
      throw new AuthConfigurationError("one-time-token default redirect must be exactly allowlisted");
    }
    validNow(this.clock);
    for (const redirect of this.allowedRedirects) this.email.resolveRedirect(redirect);
    this.email.resolveRedirect(this.defaultRedirect);
  }

  /** Issues, persists, and delivers a token without returning raw bearer material. */
  async issue(input: OneTimeTokenIssueInput): Promise<AuthResult<OneTimeTokenIssueResult>> {
    const purpose = validPurpose(input.purpose);
    const binding = this.binding(input);
    const now = validNow(this.clock);
    const ttlSeconds = input.ttlSeconds ?? defaultTtl(purpose);
    const maximumTtl = purpose === "recovery"
      ? DEFAULT_RECOVERY_TTL_SECONDS
      : purpose === "signup"
        ? DEFAULT_SIGNUP_TTL_SECONDS
        : DEFAULT_SHORT_TTL_SECONDS;
    if (!Number.isSafeInteger(ttlSeconds) || ttlSeconds <= 0 || ttlSeconds > maximumTtl) {
      throw new AuthApiError("invalid_request", 400, "Invalid one-time-token expiry");
    }
    const expiresAt = new Date(now.getTime() + ttlSeconds * 1000);
    const rawToken = randomBytes(32).toString("base64url");
    const tokenHash = this.hash(rawToken);
    const metadata = sanitizeRedactedMetadata(input.metadata ?? {});
    try {
      await this.repository.oneTimeTokens.issue({
        user_id: input.userId ?? input.user_id ?? null,
        purpose,
        token_hash: tokenHash,
        target: binding.target,
        redirect: binding.redirect,
        metadata,
        expires_at: expiresAt,
      }, { now });

      const template = templateFor(purpose);
      const variables: Record<string, string> = {
        token: rawToken,
        code: rawToken,
        redirect: binding.redirect ?? "",
      };
      if (purpose !== "email_otp") variables.link = this.email.link(binding.redirect, rawToken);
      await this.mailer.send({
        template,
        to: input.to ?? binding.target,
        variables,
      });
      await this.auditEmail(input.userId ?? input.user_id ?? null, template, input.context, now);
      return authSuccess({ sent: true, expires_at: expiresAt.toISOString() });
    } catch (error) {
      return mapOperationalError(error);
    }
  }

  /** Verifies and consumes a target- and redirect-bound token at most once. */
  async verify(input: OneTimeTokenVerifyInput): Promise<AuthResult<OneTimeTokenVerification>> {
    const purpose = validPurpose(input.purpose);
    const target = this.bindingTarget(input.target);
    const redirect = this.resolveRedirect(input.redirectTo ?? input.redirect);
    if (typeof input.token !== "string" || input.token.length < 1 || input.token.length > 128) {
      return this.failedVerification(purpose, target, redirect, nowFrom(this.clock));
    }
    const now = validNow(this.clock);
    try {
      const consumed = await this.repository.oneTimeTokens.consumeBound(
        this.hash(input.token),
        purpose,
        target,
        redirect,
        now,
        { now },
      );
      if (consumed === null) return this.failedVerification(purpose, target, redirect, now);
      return authSuccess({
        user_id: consumed.user_id ?? null,
        purpose,
        target: consumed.target,
        redirect: consumed.redirect ?? null,
        expires_at: consumed.expires_at,
      });
    } catch (error) {
      return mapOperationalError(error);
    }
  }

  /** Reissues a same-purpose token while keeping the public result generic. */
  async resend(input: OneTimeTokenResendInput): Promise<AuthResult<OneTimeTokenIssueResult>> {
    return this.issue(input);
  }

  private binding(input: OneTimeTokenIssueInput): { readonly target: string; readonly redirect: string } {
    const target = this.bindingTarget(input.target);
    const redirect = this.resolveRedirect(input.redirectTo ?? input.redirect);
    return { target, redirect };
  }

  private resolveRedirect(redirect: string | null | undefined): string {
    const candidate = redirect ?? this.defaultRedirect;
    if (!this.allowedRedirects.includes(candidate)) {
      throw new AuthApiError("redirect_not_allowed", 400, "Redirect URL is not allowed");
    }
    return this.email.resolveRedirect(candidate);
  }

  private bindingTarget(value: string): string {
    const parsed = normalizeAndValidateEmail(value);
    return parsed.normalized;
  }

  private hash(rawToken: string): Uint8Array {
    return Uint8Array.from(createHmac("sha256", this.tokenHashKey).update(rawToken, "utf8").digest());
  }

  private async failedVerification(
    purpose: OneTimeTokenPurpose,
    target: string,
    redirect: string,
    now: Date,
  ): Promise<AuthResult<never>> {
    try {
      if (purpose === "email_otp") {
        await this.repository.oneTimeTokens.recordFailure(purpose, target, redirect, now, { now });
      }
    } catch (error) {
      return mapOperationalError(error);
    }
    return authFailure(new AuthApiError(
      purpose === "email_otp" ? "otp_invalid" : "invalid_token",
      401,
      purpose === "email_otp" ? "Invalid one-time code" : "Invalid or expired link",
    ));
  }

  private async auditEmail(
    userId: UUID | null | undefined,
    template: MailMessage["template"],
    context: OneTimeTokenContext | undefined,
    now: Date,
  ): Promise<void> {
    const durableContext = auditContext(context);
    await this.repository.operations.appendAudit({
      actor_user_id: userId ?? null,
      target_type: "user",
      target_id: userId ?? null,
      action: `email.sent.${template}`,
      ip_address: durableContext.ip_address,
      user_agent: durableContext.user_agent,
      metadata: sanitizeRedactedMetadata({ event: "email.sent", operation: template }),
      outcome: "success",
      occurred_at: now,
    }, { now } satisfies RepositoryOperationOptions);
  }
}

function nowFrom(clock: () => Date): Date {
  const now = clock();
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) {
    throw new AuthConfigurationError("one-time-token clock must return a valid Date");
  }
  return now;
}
