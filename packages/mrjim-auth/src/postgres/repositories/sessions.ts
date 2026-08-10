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

function tokenNotRotatable(tokenId: UUID): PostgresRepositoryError {
  return new PostgresRepositoryError(
    "refresh_token_not_rotatable",
    `refresh token ${tokenId} is expired, revoked, or already used`,
  );
}

function validateReplacement(
  current: Selectable<RefreshTokensTable>,
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
    replacement.expires_at <= now
  ) {
    throw new PostgresRepositoryError(
      "invalid_refresh_lineage",
      "refresh-token replacement violates session, family, parent, or expiry invariants",
    );
  }
  assertDigest(replacement.token_hash, "refresh token hash");
}

async function createSessionInTransaction(
  context: RepositoryContext,
  input: CreateSessionInput,
  now: Date,
): Promise<{ session: ReturnType<typeof mapSession>; refreshToken: ReturnType<typeof mapRefreshToken> }> {
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

async function rotateInTransaction(
  context: RepositoryContext,
  tokenId: UUID,
  replacement: Omit<RefreshTokenRecord, "id" | "issued_at">,
  now: Date,
): Promise<RefreshTokenRecord> {
  requireTransaction(context.inTransaction);
  const current = await authDb(context)
    .selectFrom("refresh_tokens")
    .select(REFRESH_TOKEN_COLUMNS)
    .where("id", "=", tokenId)
    .forUpdate()
    .executeTakeFirst();
  if (
    current === undefined ||
    current.used_at !== null ||
    current.revoked_at !== null ||
    current.replacement_id !== null ||
    current.expires_at <= now
  ) {
    throw tokenNotRotatable(tokenId);
  }
  validateReplacement(current, tokenId, replacement, now);

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
    session_id: replacement.session_id,
    token_hash: assertDigest(replacement.token_hash, "refresh token hash"),
    family_id: replacement.family_id,
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

    async findRefreshForUpdate(tokenHash) {
      requireTransaction(context.inTransaction);
      const refreshRow = await authDb(context)
        .selectFrom("refresh_tokens")
        .select(REFRESH_TOKEN_COLUMNS)
        .where("token_hash", "=", assertDigest(tokenHash, "refresh token hash"))
        .forUpdate()
        .executeTakeFirst();
      if (refreshRow === undefined) return null;
      const sessionRow = await authDb(context)
        .selectFrom("sessions")
        .select(SESSION_COLUMNS)
        .where("id", "=", refreshRow.session_id)
        .executeTakeFirst();
      if (sessionRow === undefined) return null;
      return { session: mapSession(sessionRow), refreshToken: mapRefreshToken(refreshRow) };
    },

    async rotate(tokenId, replacement, options) {
      return withTransaction(context, (transaction) =>
        rotateInTransaction(transaction, tokenId, replacement, operationNow(options)),
      );
    },

    async revokeSession(sessionId, options) {
      await withTransaction(context, async (transaction) => {
        const now = operationNow(options);
        await authDb(transaction)
          .updateTable("sessions")
          .set({ revoked_at: now })
          .where("id", "=", sessionId)
          .execute();
        await authDb(transaction)
          .updateTable("refresh_tokens")
          .set({ revoked_at: now })
          .where("session_id", "=", sessionId)
          .execute();
      });
    },

    async revokeFamily(familyId, options) {
      await withTransaction(context, async (transaction) => {
        await authDb(transaction)
          .updateTable("refresh_tokens")
          .set({ revoked_at: operationNow(options) })
          .where("family_id", "=", familyId)
          .execute();
      });
    },

    async revokeUserSessions(userId, exceptSessionId, options) {
      await withTransaction(context, async (transaction) => {
        const now = operationNow(options);
        let sessions = authDb(transaction)
          .selectFrom("sessions")
          .select("id")
          .where("user_id", "=", userId);
        if (exceptSessionId !== undefined) sessions = sessions.where("id", "<>", exceptSessionId);

        await authDb(transaction)
          .updateTable("refresh_tokens")
          .set({ revoked_at: now })
          .where("session_id", "in", sessions)
          .execute();

        let update = authDb(transaction)
          .updateTable("sessions")
          .set({ revoked_at: now })
          .where("user_id", "=", userId);
        if (exceptSessionId !== undefined) update = update.where("id", "<>", exceptSessionId);
        await update.execute();
      });
    },
  } satisfies SessionRepository;
}
