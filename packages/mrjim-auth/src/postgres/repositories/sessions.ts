import type {
  CreateSessionInput,
  RefreshTokenRecord,
  SessionRepository,
} from "../../shared/contracts.js";
import type { InsertObject, Selectable } from "kysely";
import type { UUID } from "../../shared/types.js";
import { PostgresRepositoryError, requireTransaction } from "./errors.js";
import { assertDigest, authDb, operationNow, withTransaction } from "./context.js";
import {
  REFRESH_TOKEN_COLUMNS,
  SESSION_COLUMNS,
  type Database,
  type RefreshTokensTable,
  type RepositoryContext,
  type SessionsTable,
} from "./schema.js";
import { mapRefreshToken, mapSession } from "./mapping.js";

/**
 * Stable lock order for every session/refresh operation:
 * owning user, sessions sorted by UUID, then refresh tokens sorted by UUID.
 * Discovery reads are intentionally unlocked; callers re-read and validate
 * after acquiring these locks in this order.
 */
export const SESSION_LOCK_ORDER = "user -> sessions ascending by id -> refresh tokens ascending by id";

type SessionRow = Selectable<SessionsTable>;
type RefreshRow = Selectable<RefreshTokensTable>;

function tokenNotRotatable(tokenId: UUID): PostgresRepositoryError {
  return new PostgresRepositoryError(
    "refresh_token_not_rotatable",
    `refresh token ${tokenId} is expired, revoked, or already used`,
  );
}

function invalidLineage(): PostgresRepositoryError {
  return new PostgresRepositoryError(
    "invalid_refresh_lineage",
    "refresh-token replacement violates session, family, parent, or expiry invariants",
  );
}

async function discoverSessionOwner(
  context: RepositoryContext,
  sessionId: UUID,
): Promise<{ readonly id: UUID; readonly user_id: UUID } | undefined> {
  return authDb(context)
    .selectFrom("sessions")
    .select(["id", "user_id"])
    .where("id", "=", sessionId)
    .executeTakeFirst();
}

async function discoverRefresh(
  context: RepositoryContext,
  tokenId: UUID,
): Promise<{ readonly id: UUID; readonly session_id: UUID } | undefined> {
  return authDb(context)
    .selectFrom("refresh_tokens")
    .select(["id", "session_id"])
    .where("id", "=", tokenId)
    .executeTakeFirst();
}

async function lockUser(
  context: RepositoryContext,
  userId: UUID,
  activeOnly: boolean,
): Promise<boolean> {
  let query = authDb(context)
    .selectFrom("users")
    .select(["id"])
    .where("id", "=", userId);
  if (activeOnly) query = query.where("deleted_at", "is", null);
  return (await query.forUpdate().executeTakeFirst()) !== undefined;
}

async function lockSession(
  context: RepositoryContext,
  sessionId: UUID,
): Promise<SessionRow | undefined> {
  return authDb(context)
    .selectFrom("sessions")
    .select(SESSION_COLUMNS)
    .where("id", "=", sessionId)
    .forUpdate()
    .executeTakeFirst();
}

async function lockSessionRows(
  context: RepositoryContext,
  sessionIds: readonly UUID[],
): Promise<readonly SessionRow[]> {
  if (sessionIds.length === 0) return [];
  return authDb(context)
    .selectFrom("sessions")
    .select(SESSION_COLUMNS)
    .where("id", "in", sessionIds)
    .orderBy("id", "asc")
    .forUpdate()
    .execute();
}

async function lockRefreshRows(
  context: RepositoryContext,
  sessionId: UUID,
): Promise<readonly RefreshRow[]> {
  return authDb(context)
    .selectFrom("refresh_tokens")
    .select(REFRESH_TOKEN_COLUMNS)
    .where("session_id", "=", sessionId)
    .orderBy("id", "asc")
    .forUpdate()
    .execute();
}

async function lockRefreshRowsForSessions(
  context: RepositoryContext,
  sessionIds: readonly UUID[],
): Promise<readonly RefreshRow[]> {
  if (sessionIds.length === 0) return [];
  return authDb(context)
    .selectFrom("refresh_tokens")
    .select(REFRESH_TOKEN_COLUMNS)
    .where("session_id", "in", sessionIds)
    .orderBy("id", "asc")
    .forUpdate()
    .execute();
}

async function lockFamilyRefreshRows(
  context: RepositoryContext,
  familyId: UUID,
): Promise<readonly RefreshRow[]> {
  return authDb(context)
    .selectFrom("refresh_tokens")
    .select(REFRESH_TOKEN_COLUMNS)
    .where("family_id", "=", familyId)
    .orderBy("id", "asc")
    .forUpdate()
    .execute();
}

function validateReplacement(
  current: RefreshRow,
  session: SessionRow,
  tokenId: UUID,
  replacement: Omit<RefreshTokenRecord, "id" | "issued_at">,
  now: Date,
): void {
  if (
    replacement.session_id !== current.session_id ||
    replacement.family_id !== current.family_id ||
    replacement.parent_id !== tokenId ||
    replacement.replacement_id !== null ||
    replacement.used_at !== null ||
    replacement.revoked_at !== null ||
    replacement.expires_at <= now ||
    replacement.expires_at > session.expires_at
  ) {
    throw invalidLineage();
  }
  assertDigest(replacement.token_hash, "refresh token hash");
}

function validateCurrentLineage(
  current: RefreshRow,
  tokens: readonly RefreshRow[],
): void {
  if (current.parent_id === null) return;
  const parent = tokens.find((token) => token.id === current.parent_id);
  if (
    parent === undefined ||
    parent.session_id !== current.session_id ||
    parent.family_id !== current.family_id ||
    parent.used_at === null ||
    parent.replacement_id !== current.id
  ) {
    throw invalidLineage();
  }
}

async function createSessionInTransaction(
  context: RepositoryContext,
  input: CreateSessionInput,
  now: Date,
): Promise<{ session: ReturnType<typeof mapSession>; refreshToken: ReturnType<typeof mapRefreshToken> }> {
  if (!(await lockUser(context, input.user_id, true))) {
    throw new PostgresRepositoryError("not_found", `user ${input.user_id} was not found`);
  }

  const sessionValues: InsertObject<Database, "sessions"> = {
    user_id: input.user_id,
    aal: input.aal ?? 1,
    ip_address: input.ip_address ?? null,
    user_agent: input.user_agent ?? null,
    created_at: now,
    refreshed_at: now,
    expires_at: input.expires_at,
    revoked_at: null,
  };
  const sessionRow = await authDb(context)
    .insertInto("sessions")
    .values(sessionValues)
    .returning(SESSION_COLUMNS)
    .executeTakeFirstOrThrow();

  const refreshValues: InsertObject<Database, "refresh_tokens"> = {
    session_id: sessionRow.id,
    token_hash: assertDigest(input.token_hash, "refresh token hash"),
    family_id: input.family_id,
    parent_id: null,
    replacement_id: null,
    issued_at: now,
    used_at: null,
    expires_at: input.expires_at,
    revoked_at: null,
  };
  const refreshRow = await authDb(context)
    .insertInto("refresh_tokens")
    .values(refreshValues)
    .returning(REFRESH_TOKEN_COLUMNS)
    .executeTakeFirstOrThrow();
  return { session: mapSession(sessionRow), refreshToken: mapRefreshToken(refreshRow) };
}

async function findRefreshForUpdateInTransaction(
  context: RepositoryContext,
  tokenHash: Uint8Array,
  now: Date,
): Promise<{ session: ReturnType<typeof mapSession>; refreshToken: ReturnType<typeof mapRefreshToken> } | null> {
  const hash = assertDigest(tokenHash, "refresh token hash");
  const discovered = await authDb(context)
    .selectFrom("refresh_tokens")
    .select(["id", "session_id"])
    .where("token_hash", "=", hash)
    .executeTakeFirst();
  if (discovered === undefined) return null;
  const owner = await discoverSessionOwner(context, discovered.session_id);
  if (owner === undefined || !(await lockUser(context, owner.user_id, true))) return null;

  const session = await lockSession(context, owner.id);
  if (
    session === undefined ||
    session.user_id !== owner.user_id ||
    session.revoked_at !== null ||
    session.expires_at <= now
  ) return null;

  const tokens = await lockRefreshRows(context, session.id);
  const current = tokens.find((token) => token.id === discovered.id);
  if (current === undefined) return null;
  validateCurrentLineage(current, tokens);
  return { session: mapSession(session), refreshToken: mapRefreshToken(current) };
}

async function rotateInTransaction(
  context: RepositoryContext,
  tokenId: UUID,
  replacement: Omit<RefreshTokenRecord, "id" | "issued_at">,
  now: Date,
): Promise<RefreshTokenRecord> {
  requireTransaction(context.inTransaction);
  const discovered = await discoverRefresh(context, tokenId);
  if (discovered === undefined) throw tokenNotRotatable(tokenId);
  const owner = await discoverSessionOwner(context, discovered.session_id);
  if (owner === undefined || !(await lockUser(context, owner.user_id, true))) {
    throw tokenNotRotatable(tokenId);
  }

  const session = await lockSession(context, owner.id);
  if (
    session === undefined ||
    session.user_id !== owner.user_id ||
    session.revoked_at !== null ||
    session.expires_at <= now
  ) throw tokenNotRotatable(tokenId);

  const tokens = await lockRefreshRows(context, session.id);
  const current = tokens.find((token) => token.id === tokenId);
  if (
    current === undefined ||
    current.used_at !== null ||
    current.revoked_at !== null ||
    current.replacement_id !== null ||
    current.expires_at <= now
  ) throw tokenNotRotatable(tokenId);
  validateCurrentLineage(current, tokens);
  validateReplacement(current, session, tokenId, replacement, now);

  const marked = await authDb(context)
    .updateTable("refresh_tokens")
    .set({ used_at: now })
    .where("id", "=", tokenId)
    .where("used_at", "is", null)
    .where("revoked_at", "is", null)
    .where("expires_at", ">", now)
    .returning(REFRESH_TOKEN_COLUMNS)
    .executeTakeFirst();
  if (marked === undefined) throw tokenNotRotatable(tokenId);

  const replacementValues: InsertObject<Database, "refresh_tokens"> = {
    session_id: current.session_id,
    token_hash: assertDigest(replacement.token_hash, "refresh token hash"),
    family_id: current.family_id,
    parent_id: tokenId,
    replacement_id: null,
    issued_at: now,
    used_at: null,
    expires_at: replacement.expires_at,
    revoked_at: null,
  };
  const replacementRow = await authDb(context)
    .insertInto("refresh_tokens")
    .values(replacementValues)
    .returning(REFRESH_TOKEN_COLUMNS)
    .executeTakeFirstOrThrow();
  await authDb(context)
    .updateTable("refresh_tokens")
    .set({ replacement_id: replacementRow.id })
    .where("id", "=", tokenId)
    .executeTakeFirst();

  const refreshedSession = await authDb(context)
    .updateTable("sessions")
    .set({ refreshed_at: now })
    .where("id", "=", session.id)
    .where("revoked_at", "is", null)
    .where("expires_at", ">", now)
    .returning(["id"])
    .executeTakeFirst();
  if (refreshedSession === undefined) throw tokenNotRotatable(tokenId);
  return mapRefreshToken(replacementRow);
}

/** Build the transaction-aware session and refresh-token repository. */
export function createSessionRepository(context: RepositoryContext): SessionRepository {
  return {
    async create(input, options) {
      return withTransaction(context, (transaction) =>
        createSessionInTransaction(transaction, input, operationNow(options)),
      );
    },

    async findRefreshForUpdate(tokenHash, options) {
      requireTransaction(context.inTransaction);
      return findRefreshForUpdateInTransaction(context, tokenHash, operationNow(options));
    },

    async rotate(tokenId, replacement, options) {
      return withTransaction(context, (transaction) =>
        rotateInTransaction(transaction, tokenId, replacement, operationNow(options)),
      );
    },

    async revokeSession(sessionId, options) {
      await withTransaction(context, async (transaction) => {
        const owner = await discoverSessionOwner(transaction, sessionId);
        if (owner === undefined || !(await lockUser(transaction, owner.user_id, false))) return;
        const session = await lockSession(transaction, sessionId);
        if (session === undefined) return;
        const tokens = await lockRefreshRows(transaction, session.id);
        const now = operationNow(options);
        await authDb(transaction)
          .updateTable("sessions")
          .set({ revoked_at: now })
          .where("id", "=", session.id)
          .execute();
        if (tokens.length > 0) {
          await authDb(transaction)
            .updateTable("refresh_tokens")
            .set({ revoked_at: now })
            .where("id", "in", tokens.map((token) => token.id))
            .execute();
        }
      });
    },

    async revokeFamily(familyId, options) {
      await withTransaction(context, async (transaction) => {
        const discoveredTokens = await authDb(transaction)
          .selectFrom("refresh_tokens")
          .select(["session_id"])
          .where("family_id", "=", familyId)
          .execute();
        const discoveredSessionIds = [...new Set(discoveredTokens.map((token) => token.session_id))]
          .sort((left, right) => left.localeCompare(right));
        if (discoveredSessionIds.length === 0) return;
        const discoveredSessions = await authDb(transaction)
          .selectFrom("sessions")
          .select(["id", "user_id"])
          .where("id", "in", discoveredSessionIds)
          .execute();
        const userIds = [...new Set(discoveredSessions.map((session) => session.user_id))]
          .sort((left, right) => left.localeCompare(right));
        for (const userId of userIds) await lockUser(transaction, userId, false);
        const sessions = await lockSessionRows(transaction, discoveredSessionIds);
        if (sessions.length === 0) return;
        const tokens = await lockFamilyRefreshRows(transaction, familyId);
        if (tokens.length === 0) return;
        await authDb(transaction)
          .updateTable("refresh_tokens")
          .set({ revoked_at: operationNow(options) })
          .where("id", "in", tokens.map((token) => token.id))
          .execute();
      });
    },

    async revokeUserSessions(userId, exceptSessionId, options) {
      await withTransaction(context, async (transaction) => {
        if (!(await lockUser(transaction, userId, false))) return;
        let discovered = authDb(transaction)
          .selectFrom("sessions")
          .select(["id"])
          .where("user_id", "=", userId);
        if (exceptSessionId !== undefined) discovered = discovered.where("id", "<>", exceptSessionId);
        const discoveredSessions = await discovered
          .orderBy("id", "asc")
          .execute();
        const sessionIds = discoveredSessions.map((session) => session.id);
        if (sessionIds.length === 0) return;
        const sessions = await lockSessionRows(transaction, sessionIds);
        if (sessions.length === 0) return;
        const tokens = await lockRefreshRowsForSessions(transaction, sessionIds);
        const now = operationNow(options);
        if (tokens.length > 0) {
          await authDb(transaction)
            .updateTable("refresh_tokens")
            .set({ revoked_at: now })
            .where("id", "in", tokens.map((token) => token.id))
            .execute();
        }
        await authDb(transaction)
          .updateTable("sessions")
          .set({ revoked_at: now })
          .where("id", "in", sessions.map((session) => session.id))
          .execute();
      });
    },
  } satisfies SessionRepository;
}
