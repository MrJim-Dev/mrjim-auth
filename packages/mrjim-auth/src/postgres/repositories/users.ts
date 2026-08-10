import type {
  CreateUserInput,
  IdentityRepository,
  OneTimeTokenRepository,
  OAuthStateRepository,
  PasswordCredentialRepository,
  UpdateUserInput,
  UserRepository,
} from "../../shared/contracts.js";
import type { Identity, User, UUID } from "../../shared/types.js";
import {
  oauthFlowSchema,
  redactedMetadataSchema,
  safeIdentityDataSchema,
} from "../../shared/types.js";
import { sql, type InsertObject, type Selectable, type UpdateObject } from "kysely";
import { PostgresRepositoryError, mapDuplicateNormalizedEmail } from "./errors.js";
import type { OneTimeTokenInput } from "../../shared/contracts.js";
import {
  assertDigest,
  authDb,
  normalizeEmail,
  normalizePhone,
  operationNow,
  withTransaction,
} from "./context.js";
import {
  IDENTITY_COLUMNS,
  ONE_TIME_TOKEN_COLUMNS,
  OAUTH_STATE_COLUMNS,
  PASSWORD_COLUMNS,
  USER_COLUMNS,
  type Database,
  type IdentitiesTable,
  type OneTimeTokensTable,
  type OAuthStatesTable,
  type PasswordCredentialsTable,
  type RepositoryContext,
  type UsersTable,
} from "./schema.js";
import {
  mapConsumedOneTimeToken,
  mapIdentity,
  mapOAuthState,
  mapUser,
} from "./mapping.js";

function userNotFound(id: UUID): PostgresRepositoryError {
  return new PostgresRepositoryError("not_found", `user ${id} was not found`);
}

function mapUserRow(row: Selectable<UsersTable>): User {
  return mapUser(row);
}

const IDENTITY_JOIN_COLUMNS = [
  "identities.id as id",
  "identities.user_id as user_id",
  "identities.provider as provider",
  "identities.provider_subject as provider_subject",
  "identities.email as email",
  "identities.email_normalized as email_normalized",
  "identities.identity_data as identity_data",
  "identities.created_at as created_at",
  "identities.updated_at as updated_at",
] as const;

async function lockActiveUser(context: RepositoryContext, userId: UUID): Promise<boolean> {
  const row = await authDb(context)
    .selectFrom("users")
    .select(["id"])
    .where("id", "=", userId)
    .where("deleted_at", "is", null)
    .forUpdate()
    .executeTakeFirst();
  return row !== undefined;
}

function createUsersRepository(context: RepositoryContext): UserRepository {
  return {
    async findById(id, options) {
      const row = await authDb(context)
        .selectFrom("users")
        .select(USER_COLUMNS)
        .where("id", "=", id)
        .where("deleted_at", "is", null)
        .executeTakeFirst();
      return row === undefined ? null : mapUserRow(row);
    },

    async findByNormalizedEmail(email) {
      const normalized = normalizeEmail(email).normalized;
      if (normalized === null) return null;
      const row = await authDb(context)
        .selectFrom("users")
        .select(USER_COLUMNS)
        .where("email_normalized", "=", normalized)
        .where("deleted_at", "is", null)
        .executeTakeFirst();
      return row === undefined ? null : mapUserRow(row);
    },

    async create(input: CreateUserInput, options) {
      const email = normalizeEmail(input.email);
      const phone = normalizePhone(input.phone);
      const confirmedAt = input.confirmed_at;
      const emailConfirmedAt =
        input.email_confirmed_at !== undefined
          ? input.email_confirmed_at
          : confirmedAt !== undefined && email.display !== null
            ? confirmedAt
            : null;
      const phoneConfirmedAt =
        input.phone_confirmed_at !== undefined
          ? input.phone_confirmed_at
          : confirmedAt !== undefined && email.display === null && phone.display !== null
            ? confirmedAt
            : null;
      const now = operationNow(options);
      const values: InsertObject<Database, "users"> = {
        email: email.display,
        email_normalized: email.normalized,
        phone: phone.display,
        phone_normalized: phone.normalized,
        email_confirmed_at: emailConfirmedAt,
        phone_confirmed_at: phoneConfirmedAt,
        last_sign_in_at: null,
        banned_until: null,
        user_metadata: input.user_metadata ?? {},
        app_metadata: input.app_metadata ?? {},
        created_at: now,
        updated_at: now,
        deleted_at: null,
      };

      try {
        const row = await authDb(context)
          .insertInto("users")
          .values(values)
          .returning(USER_COLUMNS)
          .executeTakeFirstOrThrow();
        return mapUserRow(row);
      } catch (error) {
        mapDuplicateNormalizedEmail(error);
      }
    },

    async update(id: UUID, patch: UpdateUserInput, options) {
      const values: UpdateObject<Database, "users"> = {
        updated_at: operationNow(options),
      };
      if (patch.email !== undefined) {
        const email = normalizeEmail(patch.email);
        values.email = email.display;
        values.email_normalized = email.normalized;
      }
      if (patch.phone !== undefined) {
        const phone = normalizePhone(patch.phone);
        values.phone = phone.display;
        values.phone_normalized = phone.normalized;
      }
      if (patch.email_confirmed_at !== undefined) values.email_confirmed_at = patch.email_confirmed_at;
      if (patch.phone_confirmed_at !== undefined) values.phone_confirmed_at = patch.phone_confirmed_at;
      if (patch.confirmed_at !== undefined) {
        if (patch.email_confirmed_at === undefined) values.email_confirmed_at = patch.confirmed_at;
        if (patch.phone_confirmed_at === undefined) values.phone_confirmed_at = patch.confirmed_at;
      }
      if (patch.last_sign_in_at !== undefined) values.last_sign_in_at = patch.last_sign_in_at;
      if (patch.banned_until !== undefined) values.banned_until = patch.banned_until;
      if (patch.user_metadata !== undefined) values.user_metadata = patch.user_metadata;
      if (patch.app_metadata !== undefined) values.app_metadata = patch.app_metadata;

      try {
        const row = await authDb(context)
          .updateTable("users")
          .set(values)
          .where("id", "=", id)
          .where("deleted_at", "is", null)
          .returning(USER_COLUMNS)
          .executeTakeFirst();
        if (row === undefined) throw userNotFound(id);
        return mapUserRow(row);
      } catch (error) {
        if (error instanceof PostgresRepositoryError) throw error;
        mapDuplicateNormalizedEmail(error);
      }
    },

    async softDelete(id, deletedAt, options) {
      await withTransaction(context, async (transaction) => {
        const row = await authDb(transaction)
          .selectFrom("users")
          .select(["id"])
          .where("id", "=", id)
          .forUpdate()
          .executeTakeFirst();
        if (row === undefined) return;
        const now = operationNow(options);
        await authDb(transaction)
          .updateTable("users")
          .set({ deleted_at: deletedAt ?? now, updated_at: now })
          .where("id", "=", id)
          .execute();
      });
    },
  } satisfies UserRepository;
}

function createIdentityRepository(context: RepositoryContext): IdentityRepository {
  return {
    async findByProviderSubject(provider, providerSubject) {
      const row = await authDb(context)
        .selectFrom("identities")
        .innerJoin("users", "users.id", "identities.user_id")
        .select(IDENTITY_JOIN_COLUMNS)
        .where("provider", "=", provider.trim().toLowerCase())
        .where("provider_subject", "=", providerSubject)
        .where("users.deleted_at", "is", null)
        .executeTakeFirst();
      return row === undefined ? null : mapIdentity(row);
    },

    async listByUserId(userId) {
      const rows = await authDb(context)
        .selectFrom("identities")
        .innerJoin("users", "users.id", "identities.user_id")
        .select(IDENTITY_JOIN_COLUMNS)
        .where("user_id", "=", userId)
        .where("users.deleted_at", "is", null)
        .orderBy("identities.created_at", "asc")
        .orderBy("identities.id", "asc")
        .execute();
      return rows.map(mapIdentity);
    },

    async create(input, options) {
      return withTransaction(context, async (transaction) => {
        if (!(await lockActiveUser(transaction, input.user_id))) {
          throw userNotFound(input.user_id);
        }
        const email = normalizeEmail(input.email);
        const now = operationNow(options);
        const values: InsertObject<Database, "identities"> = {
          user_id: input.user_id,
          provider: input.provider.trim().toLowerCase(),
          provider_subject: input.provider_subject,
          email: email.display,
          email_normalized: email.normalized,
          identity_data: safeIdentityDataSchema.parse(input.identity_data),
          created_at: now,
          updated_at: now,
        };
        const row = await authDb(transaction)
          .insertInto("identities")
          .values(values)
          .returning(IDENTITY_COLUMNS)
          .executeTakeFirstOrThrow();
        return mapIdentity(row);
      });
    },

    async deleteById(id) {
      await authDb(context).deleteFrom("identities").where("id", "=", id).execute();
    },
  } satisfies IdentityRepository;
}

function createPasswordCredentialRepository(context: RepositoryContext): PasswordCredentialRepository {
  return {
    async findByUserId(userId) {
      const row = await authDb(context)
        .selectFrom("password_credentials")
        .innerJoin("users", "users.id", "password_credentials.user_id")
        .select(PASSWORD_COLUMNS)
        .where("password_credentials.user_id", "=", userId)
        .where("users.deleted_at", "is", null)
        .executeTakeFirst();
      if (row === undefined) return null;
      return {
        user_id: row.user_id,
        password_hash: row.password_hash,
        password_updated_at: row.password_updated_at,
      };
    },

    async upsert(userId, passwordHash, updatedAt, options) {
      await withTransaction(context, async (transaction) => {
        if (!(await lockActiveUser(transaction, userId))) throw userNotFound(userId);
        const now = updatedAt ?? operationNow(options);
        await authDb(transaction)
          .insertInto("password_credentials")
          .values({ user_id: userId, password_hash: passwordHash, password_updated_at: now })
          .onConflict((conflict) =>
            conflict.column("user_id").doUpdateSet({
              password_hash: passwordHash,
              password_updated_at: now,
            }),
          )
          .execute();
      });
    },

    async deleteByUserId(userId) {
      await authDb(context).deleteFrom("password_credentials").where("user_id", "=", userId).execute();
    },
  } satisfies PasswordCredentialRepository;
}

function createOneTimeTokenRepository(context: RepositoryContext): OneTimeTokenRepository {
  return {
    async issue(input, options) {
      const metadata = redactedMetadataSchema.parse(input.metadata ?? {});
      const tokenHash = assertDigest(input.token_hash, "one-time token hash");
      await withTransaction(context, async (transaction) => {
        if (input.user_id !== null && input.user_id !== undefined
          && !(await lockActiveUser(transaction, input.user_id))) {
          throw userNotFound(input.user_id);
        }
        const values: InsertObject<Database, "one_time_tokens"> = {
          user_id: input.user_id ?? null,
          purpose: input.purpose,
          token_hash: tokenHash,
          target: input.target,
          redirect: input.redirect ?? null,
          metadata,
          attempt_count: 0,
          created_at: operationNow(options),
          expires_at: input.expires_at,
          consumed_at: null,
        };
        await authDb(transaction).insertInto("one_time_tokens").values(values).execute();
      });
    },

    async consume(tokenHash, purpose, now) {
      return consumeOneTimeToken(context, tokenHash, purpose, now);
    },

    async consumeBound(tokenHash, purpose, target, redirect, now) {
      return consumeOneTimeToken(context, tokenHash, purpose, now, { target, redirect });
    },

    async recordFailure(purpose, target, redirect, now) {
      return withTransaction(context, async (transaction) => {
        const result = await sql<{ attempt_count: number; consumed_at: Date | null }>`
          WITH candidate AS (
            SELECT token.id
              FROM auth.one_time_tokens AS token
             WHERE token.purpose = ${purpose}
               AND token.target = ${target}
               AND (
                 (CAST(${redirect} AS text) IS NULL AND token.redirect IS NULL)
                 OR token.redirect = ${redirect}
               )
               AND token.consumed_at IS NULL
               AND token.expires_at > ${now}
               AND token.attempt_count < 5
               AND (
                 token.user_id IS NULL
                 OR EXISTS (
                   SELECT 1 FROM auth.users AS owner
                    WHERE owner.id = token.user_id AND owner.deleted_at IS NULL
                 )
               )
             ORDER BY token.created_at DESC, token.id DESC
             LIMIT 1
             FOR UPDATE
          ), updated AS (
            UPDATE auth.one_time_tokens AS token
               SET attempt_count = token.attempt_count + 1,
                   consumed_at = CASE WHEN token.attempt_count + 1 >= 5 THEN CAST(${now} AS timestamptz) ELSE NULL END
              FROM candidate
             WHERE token.id = candidate.id
             RETURNING token.attempt_count, token.consumed_at
          )
          SELECT attempt_count, consumed_at FROM updated
        `.execute(transaction.db);
        const row = result.rows[0];
        return row === undefined ? null : { attempt_count: row.attempt_count, consumed: row.consumed_at !== null };
      });
    },
  } satisfies OneTimeTokenRepository;
}

async function consumeOneTimeToken(
  context: RepositoryContext,
  tokenHash: Uint8Array,
  purpose: OneTimeTokenInput["purpose"],
  now: Date,
  binding?: { readonly target: string; readonly redirect: string | null },
): Promise<Omit<OneTimeTokenInput, "token_hash"> | null> {
  return withTransaction(context, async (transaction) => {
    const query = authDb(transaction)
      .updateTable("one_time_tokens")
      .set({ consumed_at: now })
      .where("token_hash", "=", assertDigest(tokenHash, "one-time token hash"))
      .where("purpose", "=", purpose)
      .where("consumed_at", "is", null)
      .where("expires_at", ">", now)
      .where("attempt_count", "<", 5)
      .where((expression) => expression.or([
        expression("user_id", "is", null),
        expression.exists(
          expression
            .selectFrom("users")
            .select("id")
            .whereRef("users.id", "=", "one_time_tokens.user_id")
            .where("deleted_at", "is", null),
        ),
      ]));
    let boundQuery = query;
    if (binding !== undefined) {
      boundQuery = boundQuery.where("target", "=", binding.target);
      boundQuery = binding.redirect === null
        ? boundQuery.where("redirect", "is", null)
        : boundQuery.where("redirect", "=", binding.redirect);
    }
    const row = await boundQuery
      .returning(ONE_TIME_TOKEN_COLUMNS)
      .executeTakeFirst();
    return row === undefined ? null : mapConsumedOneTimeToken(row);
  });
}

function createOAuthStateRepository(context: RepositoryContext): OAuthStateRepository {
  return {
    async create(input, options) {
      const flow = oauthFlowSchema.parse(input.flow);
      const stateHash = assertDigest(input.state_hash, "OAuth state hash");
      await withTransaction(context, async (transaction) => {
        if (input.linking_user_id !== null && input.linking_user_id !== undefined
          && !(await lockActiveUser(transaction, input.linking_user_id))) {
          throw userNotFound(input.linking_user_id);
        }
        const values: InsertObject<Database, "oauth_states"> = {
          state_hash: stateHash,
          provider: input.provider.trim().toLowerCase(),
          flow,
          pkce_challenge: input.pkce_challenge,
          encrypted_verifier:
            input.encrypted_verifier === undefined || input.encrypted_verifier === null
              ? null
              : Buffer.from(input.encrypted_verifier),
          redirect_target: input.redirect,
          linking_user_id: input.linking_user_id ?? null,
          expires_at: input.expires_at,
          consumed_at: null,
          created_at: operationNow(options),
        };
        await authDb(transaction).insertInto("oauth_states").values(values).execute();
      });
    },

    async consume(stateHash, now) {
      return withTransaction(context, async (transaction) => {
        const row = await authDb(transaction)
          .updateTable("oauth_states")
          .set({ consumed_at: now })
          .where("state_hash", "=", assertDigest(stateHash, "OAuth state hash"))
          .where("consumed_at", "is", null)
          .where("expires_at", ">", now)
          .where((expression) => expression.or([
            expression("linking_user_id", "is", null),
            expression.exists(
              expression
                .selectFrom("users")
                .select("id")
                .whereRef("users.id", "=", "oauth_states.linking_user_id")
                .where("deleted_at", "is", null),
            ),
          ]))
          .returning(OAUTH_STATE_COLUMNS)
          .executeTakeFirst();
        return row === undefined ? null : mapOAuthState(row);
      });
    },
  } satisfies OAuthStateRepository;
}

/** Build the account, identity, credential, token, and OAuth repository members. */
export function createUserRepositories(context: RepositoryContext): {
  readonly users: UserRepository;
  readonly identities: IdentityRepository;
  readonly passwordCredentials: PasswordCredentialRepository;
  readonly oneTimeTokens: OneTimeTokenRepository;
  readonly oauthStates: OAuthStateRepository;
} {
  return {
    users: createUsersRepository(context),
    identities: createIdentityRepository(context),
    passwordCredentials: createPasswordCredentialRepository(context),
    oneTimeTokens: createOneTimeTokenRepository(context),
    oauthStates: createOAuthStateRepository(context),
  };
}
