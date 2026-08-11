import { createHash, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { isIP } from "node:net";
import { decodeJwt } from "jose";
import { authFailure, authSuccess, type AuthResult } from "../shared/result.js";
import {
  AuthApiError,
  AuthConfigurationError,
  AuthProgrammingError,
} from "../shared/errors.js";
import type {
  AuthRepository,
  RefreshTokenRecord,
  SessionRecord,
} from "../shared/contracts.js";
import type { Session, User, UUID } from "../shared/types.js";
import { sanitizeRedactedMetadata, uuidSchema } from "../shared/types.js";
import type { AccessTokenClaims } from "./tokens.js";
import { TokenService } from "./tokens.js";
import {
  assertBoundaryObject,
  captureBoundaryClock,
  captureBoundaryMethodGroup,
  captureBoundaryRepository,
  optionalBoundaryOption,
  requiredBoundaryOption,
} from "./callback-boundary.js";

/** Context attached to a session operation; raw user-agent values are never persisted. */
export interface SessionContext {
  readonly ip_address?: string | null;
  /** Untrusted input used only to derive a bounded `ua-sha256:` fingerprint. */
  readonly user_agent?: string | null;
  /** Authentication assurance level for a newly created session. */
  readonly aal?: number;
}

/** Logout scopes supported by the server session service. */
export type SignOutScope = "local" | "global" | "others";

/** Configuration for the server-only session service. */
export interface SessionServiceOptions {
  /** Transaction-aware project-owned PostgreSQL repository boundary. */
  readonly repository: AuthRepository;
  /** ES256 access-token and opaque-token primitive. */
  readonly tokens: TokenService;
  /** Maximum refresh-family/session lifetime in seconds. */
  readonly refreshTokenTtlSeconds?: number;
  /** Injectable clock shared with the token service. */
  readonly clock?: () => Date;
}

/** A session whose bearer claims and durable user/session rows were rechecked. */
export interface AuthenticatedSession {
  readonly session: Session;
  readonly session_id: UUID;
  readonly user_id: UUID;
  readonly user: User;
}

type RefreshOutcome =
  | { readonly kind: "missing" }
  | { readonly kind: "expired" }
  | { readonly kind: "inactive" }
  | {
      readonly kind: "reused";
      readonly familyId: UUID;
      readonly sessionId: UUID;
      readonly userId: UUID;
    }
  | { readonly kind: "revoked" }
  | { readonly kind: "success"; readonly session: Session };

const DEFAULT_REFRESH_TOKEN_TTL_SECONDS = 30 * 24 * 60 * 60;
const OPAQUE_REFRESH_TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const USER_AGENT_FINGERPRINT_PREFIX = "ua-sha256:";

type NormalizedSessionContext = {
  readonly ip_address: string | null;
  readonly user_agent: string | null;
  readonly aal: number;
};

function nowFrom(clock: () => Date): Date {
  const now = clock();
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) {
    throw new AuthConfigurationError("session clock must return a valid Date");
  }
  return now;
}

function newOpaqueRefreshToken(): string {
  return randomBytes(32).toString("base64url");
}

function isOpaqueRefreshToken(value: string): boolean {
  return OPAQUE_REFRESH_TOKEN_PATTERN.test(value);
}

export function normalizeIpAddress(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const normalized = value.trim();
  if (normalized === "" || normalized.length > 45 || isIP(normalized) === 0) return null;
  return normalized.toLowerCase();
}

function userAgentFingerprint(value: unknown): string | null {
  if (typeof value !== "string" || value.length === 0) return null;
  return `${USER_AGENT_FINGERPRINT_PREFIX}${createHash("sha256")
    .update(value, "utf8")
    .digest("hex")}`;
}

function normalizeSessionContext(
  context: SessionContext | null | undefined,
): NormalizedSessionContext {
  const source = (context !== null && typeof context === "object" ? context : {}) as SessionContext;
  return {
    ip_address: normalizeIpAddress(source.ip_address),
    user_agent: userAgentFingerprint(source.user_agent),
    aal: sessionAal(source),
  };
}

function sessionAal(context: SessionContext): number {
  const aal = context.aal ?? 1;
  if (!Number.isInteger(aal) || aal < 1 || aal > 3) {
    throw new AuthConfigurationError("session AAL must be an integer from 1 to 3");
  }
  return aal;
}

function sameDigest(left: Uint8Array, right: Uint8Array): boolean {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  return (
    leftBuffer.byteLength === rightBuffer.byteLength &&
    timingSafeEqual(leftBuffer, rightBuffer)
  );
}

function repositoryCode(error: unknown): string | undefined {
  if (typeof error !== "object" || error === null) return undefined;
  const code = (error as { readonly code?: unknown }).code;
  return typeof code === "string" ? code : undefined;
}

function invalidRefreshToken(): AuthApiError {
  return new AuthApiError("invalid_token", 401, "Invalid refresh token");
}

function unauthorizedSession(): AuthApiError {
  return new AuthApiError("unauthorized", 401, "Authenticated session is required");
}

function userIsBanned(user: User, now: Date): boolean {
  return user.banned_until !== null && new Date(user.banned_until).getTime() > now.getTime();
}

function sessionExpired(): AuthApiError {
  return new AuthApiError("session_expired", 401, "Session has expired");
}

function refreshTokenReused(): AuthApiError {
  return new AuthApiError("refresh_token_reused", 401, "Refresh token reuse detected");
}

function internalError(): AuthApiError {
  return new AuthApiError("internal_error", 500, "Internal authentication error");
}

function mapUnexpectedOperationalError(error: unknown): AuthResult<never> {
  if (error instanceof AuthConfigurationError || error instanceof AuthProgrammingError) {
    throw error;
  }
  return authFailure(internalError());
}

function publicSession(user: User, accessToken: string, refreshToken: string): Session {
  const claims = decodeJwt<AccessTokenClaims>(accessToken);
  if (
    typeof claims.iat !== "number" ||
    typeof claims.exp !== "number" ||
    !Number.isSafeInteger(claims.iat) ||
    !Number.isSafeInteger(claims.exp) ||
    claims.exp <= claims.iat
  ) {
    throw new AuthConfigurationError("issued access token does not contain valid lifetime claims");
  }
  return {
    access_token: accessToken,
    refresh_token: refreshToken,
    token_type: "bearer",
    expires_in: claims.exp - claims.iat,
    expires_at: claims.exp,
    user,
  };
}

function auditMetadata(
  event: string,
  values: Readonly<Record<string, string | number | boolean>> = {},
) {
  return sanitizeRedactedMetadata({ event, ...values });
}

function mapCreateError(error: unknown): AuthApiError | null {
  switch (repositoryCode(error)) {
    case "not_found":
      return new AuthApiError("invalid_request", 400, "Invalid session request");
    default:
      return null;
  }
}

/**
 * Server-only rotating refresh-session service.
 *
 * Refresh lookup, lineage validation, and rotation run through one real
 * PostgreSQL transaction. A replay is first classified in that transaction,
 * then family/session containment runs in separate committed operations before
 * the stable `refresh_token_reused` result is returned.
 */
export class SessionService {
  private readonly repository: AuthRepository;
  private readonly tokens: Pick<TokenService, "hashOpaqueToken" | "issueAccessToken" | "verifyAccessToken">;
  private readonly refreshTokenTtlSeconds: number;
  private readonly clock: () => Date;

  constructor(options: SessionServiceOptions) {
    if (options === null || typeof options !== "object") {
      throw new AuthConfigurationError("session options are incomplete");
    }
    const source = options as unknown as object;
    assertBoundaryObject(source, "session options");
    const repositoryValue = requiredBoundaryOption(source, "repository", "session repository");
    const tokensValue = requiredBoundaryOption(source, "tokens", "session token service");
    const refreshTokenTtlValue = optionalBoundaryOption(source, "refreshTokenTtlSeconds", "refresh token TTL");
    const clockValue = optionalBoundaryOption(source, "clock", "session clock");
    assertBoundaryObject(tokensValue, "session token service");
    if (!(tokensValue instanceof TokenService)) {
      throw new AuthConfigurationError("session token service is required");
    }
    this.repository = captureBoundaryRepository(repositoryValue);
    this.tokens = captureBoundaryMethodGroup(
      tokensValue,
      "session token service",
      ["hashOpaqueToken", "issueAccessToken", "verifyAccessToken"],
    ) as unknown as Pick<TokenService, "hashOpaqueToken" | "issueAccessToken" | "verifyAccessToken">;
    this.refreshTokenTtlSeconds =
      (refreshTokenTtlValue as number | undefined) ?? DEFAULT_REFRESH_TOKEN_TTL_SECONDS;
    if (
      !Number.isSafeInteger(this.refreshTokenTtlSeconds) ||
      this.refreshTokenTtlSeconds < 3_600 ||
      this.refreshTokenTtlSeconds > 90 * 24 * 60 * 60
    ) {
      throw new AuthConfigurationError("refresh token TTL must be between 3600 seconds and 90 days");
    }
    this.clock = captureBoundaryClock(clockValue, "session clock", () => new Date());
    nowFrom(this.clock);
  }

  /** Creates a session and its first refresh-family member atomically. */
  async create(user: User, context: SessionContext = {}, transaction?: AuthRepository): Promise<AuthResult<Session>> {
    const normalizedContext = normalizeSessionContext(context);
    const now = nowFrom(this.clock);
    const rawRefreshToken = newOpaqueRefreshToken();
    const refreshExpiresAt = new Date(now.getTime() + this.refreshTokenTtlSeconds * 1000);
    const familyId = uuidSchema.parse(randomUUID());

    try {
      const createInTransaction = async (currentRepository: AuthRepository): Promise<Session> => {
        const created = await currentRepository.sessions.create(
          {
            user_id: user.id,
            aal: normalizedContext.aal,
            ip_address: normalizedContext.ip_address,
            user_agent: normalizedContext.user_agent,
            expires_at: refreshExpiresAt,
            token_hash: this.tokens.hashOpaqueToken(rawRefreshToken),
            family_id: familyId,
          },
          { now },
        );
        const accessToken = await this.tokens.issueAccessToken(user, created.session);
        const publicValue = publicSession(user, accessToken, rawRefreshToken);
        await currentRepository.operations.appendAudit(
          {
            actor_user_id: user.id,
            actor_session_id: created.session.id,
            action: "session.created",
            target_type: "session",
            target_id: created.session.id,
            ip_address: normalizedContext.ip_address,
            user_agent: normalizedContext.user_agent,
            metadata: auditMetadata("session.created", { session_id: created.session.id }),
            outcome: "success",
            occurred_at: now,
          },
          { now },
        );
        return publicValue;
      };
      const session = transaction === undefined
        ? await this.repository.transaction(createInTransaction)
        : await createInTransaction(transaction);
      return authSuccess(session);
    } catch (error) {
      const mapped = mapCreateError(error);
      if (mapped !== null) return authFailure(mapped);
      return mapUnexpectedOperationalError(error);
    }
  }

  /** Rotates a refresh token once and contains any detected replay. */
  async refresh(
    refreshToken: string,
    context: SessionContext = {},
  ): Promise<AuthResult<Session>> {
    const normalizedContext = normalizeSessionContext(context);
    if (typeof refreshToken !== "string" || !isOpaqueRefreshToken(refreshToken)) {
      return authFailure(invalidRefreshToken());
    }
    const now = nowFrom(this.clock);
    const tokenHash = this.tokens.hashOpaqueToken(refreshToken);
    let outcome: RefreshOutcome;

    try {
      outcome = await this.repository.transaction(async (transaction) => {
        const found = await transaction.sessions.findRefreshForUpdate(tokenHash, { now });
        if (found === null || !sameDigest(tokenHash, found.refreshToken.token_hash)) {
          return { kind: "missing" };
        }

        const current = found.refreshToken;
        if (
          current.used_at !== null ||
          current.replacement_id !== null
        ) {
          return {
            kind: "reused",
            familyId: current.family_id,
            sessionId: found.session.id,
            userId: found.session.user_id,
          };
        }
        if (current.revoked_at !== null) return { kind: "revoked" };
        if (current.expires_at <= now || found.session.expires_at <= now) {
          return { kind: "expired" };
        }
        if (found.session.revoked_at !== null) return { kind: "inactive" };

        const user = await transaction.users.findById(found.session.user_id, { now });
        if (user === null || userIsBanned(user, now)) return { kind: "missing" };

        const replacementRaw = newOpaqueRefreshToken();
        const replacementExpiresAt = new Date(
          Math.min(
            found.session.expires_at.getTime(),
            now.getTime() + this.refreshTokenTtlSeconds * 1000,
          ),
        );
        const replacement: Omit<RefreshTokenRecord, "id" | "issued_at"> = {
          session_id: found.session.id,
          token_hash: this.tokens.hashOpaqueToken(replacementRaw),
          family_id: current.family_id,
          parent_id: current.id,
          replacement_id: null,
          used_at: null,
          expires_at: replacementExpiresAt,
          revoked_at: null,
        };
        await transaction.sessions.rotate(current.id, replacement, { now });
        const accessToken = await this.tokens.issueAccessToken(user, found.session);
        const publicValue = publicSession(user, accessToken, replacementRaw);
        await transaction.operations.appendAudit(
          {
            actor_user_id: user.id,
            actor_session_id: found.session.id,
            action: "session.refreshed",
            target_type: "session",
            target_id: found.session.id,
            ip_address: normalizedContext.ip_address,
            user_agent: normalizedContext.user_agent,
            metadata: auditMetadata("session.refreshed", { session_id: found.session.id }),
            outcome: "success",
            occurred_at: now,
          },
          { now },
        );
        return { kind: "success", session: publicValue };
      });
    } catch (error) {
      if (
        repositoryCode(error) === "refresh_token_not_rotatable" ||
        repositoryCode(error) === "invalid_refresh_lineage"
      ) {
        return authFailure(invalidRefreshToken());
      }
      return mapUnexpectedOperationalError(error);
    }

    switch (outcome.kind) {
      case "success":
        return authSuccess(outcome.session);
      case "expired":
        return authFailure(sessionExpired());
      case "inactive":
        return authFailure(sessionExpired());
      case "revoked":
        return authFailure(invalidRefreshToken());
      case "missing":
        return authFailure(invalidRefreshToken());
      case "reused":
        try {
          await this.containReuse(outcome, normalizedContext, now);
        } catch (error) {
          return mapUnexpectedOperationalError(error);
        }
        return authFailure(refreshTokenReused());
    }
  }

  /** Verifies a trusted session against the current durable user/session state. */
  async authorizeSession(session: Session): Promise<AuthResult<AuthenticatedSession>> {
    if (session === null || typeof session !== "object") return authFailure(unauthorizedSession());
    try {
      const verified = await this.tokens.verifyAccessToken(session.access_token);
      if (verified.data === null) return authFailure(unauthorizedSession());
      const userId = uuidSchema.safeParse(verified.data.sub);
      const sessionId = uuidSchema.safeParse(verified.data.sid);
      if (!userId.success || !sessionId.success || session.user.id !== userId.data) {
        return authFailure(unauthorizedSession());
      }
      const now = nowFrom(this.clock);
      const current = await this.repository.transaction(async (transaction) => {
        const durableSession = await transaction.sessions.findByIdForUpdate(sessionId.data, { now });
        if (
          durableSession === null ||
          durableSession.user_id !== userId.data ||
          durableSession.revoked_at !== null ||
          durableSession.expires_at <= now
        ) return null;
        const user = await transaction.users.findByIdForUpdate(userId.data, { now });
        if (user === null || userIsBanned(user, now)) return null;
        return { session, session_id: sessionId.data, user_id: userId.data, user };
      });
      return current === null ? authFailure(unauthorizedSession()) : authSuccess(current);
    } catch (error) {
      return mapUnexpectedOperationalError(error);
    }
  }

  /** Revokes a session selected by a refresh token without returning token state. */
  async revokeRefreshToken(
    refreshToken: string,
    scope: SignOutScope,
  ): Promise<AuthResult<null>> {
    if (scope !== "local" && scope !== "global" && scope !== "others") {
      return authFailure(new AuthApiError("invalid_request", 400, "Invalid sign-out scope"));
    }
    if (typeof refreshToken !== "string" || !isOpaqueRefreshToken(refreshToken)) {
      return authFailure(invalidRefreshToken());
    }
    const now = nowFrom(this.clock);
    const tokenHash = this.tokens.hashOpaqueToken(refreshToken);
    try {
      await this.repository.transaction(async (transaction) => {
        const found = await transaction.sessions.findRefreshForUpdate(tokenHash, { now });
        if (found === null || !sameDigest(tokenHash, found.refreshToken.token_hash)) return;
        if (scope === "local") {
          await transaction.sessions.revokeSession(found.session.id, { now });
        } else if (scope === "global") {
          await transaction.sessions.revokeUserSessions(found.session.user_id, undefined, { now });
        } else {
          await transaction.sessions.revokeUserSessions(found.session.user_id, found.session.id, { now });
        }
        await transaction.operations.appendAudit({
          actor_user_id: found.session.user_id,
          actor_session_id: found.session.id,
          action: `session.sign_out.${scope}`,
          target_type: scope === "local" ? "session" : "user",
          target_id: scope === "local" ? found.session.id : found.session.user_id,
          metadata: auditMetadata("session.sign_out", { operation: scope, credential: "refresh_token" }),
          outcome: "success",
          occurred_at: now,
        }, { now });
      });
      return authSuccess(null);
    } catch (error) {
      return mapUnexpectedOperationalError(error);
    }
  }

  /** Revokes the current session, every session, or every other session. */
  async signOut(
    session: Session,
    scope: SignOutScope,
  ): Promise<AuthResult<null>> {
    if (scope !== "local" && scope !== "global" && scope !== "others") {
      return authFailure(new AuthApiError("invalid_request", 400, "Invalid sign-out scope"));
    }

    const verified = await this.tokens.verifyAccessToken(session.access_token);
    if (verified.data === null) return authFailure(verified.error);
    const userId = uuidSchema.safeParse(verified.data.sub);
    const sessionId = uuidSchema.safeParse(verified.data.sid);
    if (!userId.success || !sessionId.success || session.user.id !== userId.data) {
      return authFailure(invalidRefreshToken());
    }

    const now = nowFrom(this.clock);
    try {
      await this.repository.transaction(async (transaction) => {
        if (scope === "local") {
          await transaction.sessions.revokeSession(sessionId.data, { now });
        } else if (scope === "global") {
          await transaction.sessions.revokeUserSessions(userId.data, undefined, { now });
        } else {
          await transaction.sessions.revokeUserSessions(userId.data, sessionId.data, { now });
        }

        await transaction.operations.appendAudit(
          {
            actor_user_id: userId.data,
            actor_session_id: sessionId.data,
            action: `session.sign_out.${scope}`,
            target_type: scope === "local" ? "session" : "user",
            target_id: scope === "local" ? sessionId.data : userId.data,
            metadata: auditMetadata("session.sign_out", { operation: scope }),
            outcome: "success",
            occurred_at: now,
          },
          { now },
        );
      });
    } catch (error) {
      return mapUnexpectedOperationalError(error);
    }
    return authSuccess(null);
  }

  private async containReuse(
    outcome: Extract<RefreshOutcome, { readonly kind: "reused" }>,
    context: NormalizedSessionContext,
    now: Date,
  ): Promise<void> {
    // These are intentionally separate committed operations. Returning the
    // expected replay error from the discovery transaction must not roll back
    // the containment writes.
    await this.repository.transaction(async (transaction) => {
      await transaction.sessions.revokeFamily(outcome.familyId, { now });
      await transaction.sessions.revokeSession(outcome.sessionId, { now });
      await transaction.operations.appendAudit(
        {
          actor_user_id: outcome.userId,
          actor_session_id: outcome.sessionId,
          action: "session.refresh_reused",
          target_type: "session",
          target_id: outcome.sessionId,
          ip_address: context.ip_address,
          user_agent: context.user_agent,
          metadata: auditMetadata("session.refresh_reused", {
            session_id: outcome.sessionId,
            error_code: "refresh_token_reused",
          }),
          outcome: "failure",
          occurred_at: now,
        },
        { now },
      );
    });
  }
}
