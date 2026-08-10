import { randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { decodeJwt } from "jose";
import { authFailure, authSuccess, type AuthResult } from "../shared/result.js";
import { AuthApiError, AuthConfigurationError } from "../shared/errors.js";
import type {
  AuthRepository,
  RefreshTokenRecord,
  SessionRecord,
} from "../shared/contracts.js";
import type { Session, User, UUID } from "../shared/types.js";
import { sanitizeRedactedMetadata, uuidSchema } from "../shared/types.js";
import type { AccessTokenClaims } from "./tokens.js";
import { TokenService } from "./tokens.js";

/** Context attached to a session operation and its redacted audit event. */
export interface SessionContext {
  readonly ip_address?: string | null;
  readonly user_agent?: string | null;
  /** Authentication assurance level for a newly created session. */
  readonly aal?: number;
  readonly now?: Date;
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
  | { readonly kind: "success"; readonly session: Session };

const DEFAULT_REFRESH_TOKEN_TTL_SECONDS = 30 * 24 * 60 * 60;
const OPAQUE_REFRESH_TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;

function nowFrom(clock: () => Date, context?: SessionContext): Date {
  const now = context?.now ?? clock();
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

function sessionExpired(): AuthApiError {
  return new AuthApiError("session_expired", 401, "Session has expired");
}

function refreshTokenReused(): AuthApiError {
  return new AuthApiError("refresh_token_reused", 401, "Refresh token reuse detected");
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
  private readonly tokens: TokenService;
  private readonly refreshTokenTtlSeconds: number;
  private readonly clock: () => Date;

  constructor(options: SessionServiceOptions) {
    if (
      options.repository === null ||
      typeof options.repository !== "object" ||
      typeof options.repository.transaction !== "function"
    ) {
      throw new AuthConfigurationError("session repository is incomplete");
    }
    if (!(options.tokens instanceof TokenService)) {
      throw new AuthConfigurationError("session token service is required");
    }
    this.repository = options.repository;
    this.tokens = options.tokens;
    this.refreshTokenTtlSeconds =
      options.refreshTokenTtlSeconds ?? DEFAULT_REFRESH_TOKEN_TTL_SECONDS;
    if (
      !Number.isSafeInteger(this.refreshTokenTtlSeconds) ||
      this.refreshTokenTtlSeconds < 3_600 ||
      this.refreshTokenTtlSeconds > 90 * 24 * 60 * 60
    ) {
      throw new AuthConfigurationError("refresh token TTL must be between 3600 seconds and 90 days");
    }
    this.clock = options.clock ?? (() => new Date());
    nowFrom(this.clock);
  }

  /** Creates a session and its first refresh-family member atomically. */
  async create(user: User, context: SessionContext = {}): Promise<AuthResult<Session>> {
    const now = nowFrom(this.clock, context);
    const aal = sessionAal(context);
    const rawRefreshToken = newOpaqueRefreshToken();
    const refreshExpiresAt = new Date(now.getTime() + this.refreshTokenTtlSeconds * 1000);
    const familyId = uuidSchema.parse(randomUUID());

    try {
      const session = await this.repository.transaction(async (transaction) => {
        const created = await transaction.sessions.create(
          {
            user_id: user.id,
            aal,
            ip_address: context.ip_address ?? null,
            user_agent: context.user_agent ?? null,
            expires_at: refreshExpiresAt,
            token_hash: this.tokens.hashOpaqueToken(rawRefreshToken),
            family_id: familyId,
          },
          { now },
        );
        const accessToken = await this.tokens.issueAccessToken(user, created.session);
        const publicValue = publicSession(user, accessToken, rawRefreshToken);
        await transaction.operations.appendAudit(
          {
            actor_user_id: user.id,
            actor_session_id: created.session.id,
            action: "session.created",
            target_type: "session",
            target_id: created.session.id,
            ip_address: context.ip_address ?? null,
            user_agent: context.user_agent ?? null,
            metadata: auditMetadata("session.created", { session_id: created.session.id }),
            outcome: "success",
            occurred_at: now,
          },
          { now },
        );
        return publicValue;
      });
      return authSuccess(session);
    } catch (error) {
      const mapped = mapCreateError(error);
      if (mapped !== null) return authFailure(mapped);
      throw error;
    }
  }

  /** Rotates a refresh token once and contains any detected replay. */
  async refresh(
    refreshToken: string,
    context: SessionContext = {},
  ): Promise<AuthResult<Session>> {
    if (typeof refreshToken !== "string" || !isOpaqueRefreshToken(refreshToken)) {
      return authFailure(invalidRefreshToken());
    }
    const now = nowFrom(this.clock, context);
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
          current.replacement_id !== null ||
          current.revoked_at !== null
        ) {
          return {
            kind: "reused",
            familyId: current.family_id,
            sessionId: found.session.id,
            userId: found.session.user_id,
          };
        }
        if (current.expires_at <= now || found.session.expires_at <= now) {
          return { kind: "expired" };
        }
        if (found.session.revoked_at !== null) return { kind: "inactive" };

        const user = await transaction.users.findById(found.session.user_id, { now });
        if (user === null) return { kind: "missing" };

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
            ip_address: context.ip_address ?? null,
            user_agent: context.user_agent ?? null,
            metadata: auditMetadata("session.refreshed", { session_id: found.session.id }),
            outcome: "success",
            occurred_at: now,
          },
          { now },
        );
        return { kind: "success", session: publicValue };
      });
    } catch (error) {
      if (repositoryCode(error) === "refresh_token_not_rotatable") {
        return authFailure(invalidRefreshToken());
      }
      throw error;
    }

    switch (outcome.kind) {
      case "success":
        return authSuccess(outcome.session);
      case "expired":
        return authFailure(sessionExpired());
      case "inactive":
        return authFailure(sessionExpired());
      case "missing":
        return authFailure(invalidRefreshToken());
      case "reused":
        await this.containReuse(outcome, context, now);
        return authFailure(refreshTokenReused());
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
    return authSuccess(null);
  }

  private async containReuse(
    outcome: Extract<RefreshOutcome, { readonly kind: "reused" }>,
    context: SessionContext,
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
          ip_address: context.ip_address ?? null,
          user_agent: context.user_agent ?? null,
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
