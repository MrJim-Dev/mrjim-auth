import { Kysely, PostgresDialect } from "kysely";
import { Pool, type PoolConfig } from "pg";
import type { AuthRepository } from "../shared/contracts.js";
import {
  createAuthorizationRepositories,
} from "./repositories/authorization.js";
import { createOperationsRepository } from "./repositories/operations.js";
import { createAdminRepository } from "./repositories/admin.js";
import { createSessionRepository } from "./repositories/sessions.js";
import type { Database, RepositoryContext } from "./repositories/schema.js";
import { createUserRepositories } from "./repositories/users.js";

/** Options for the project-owned PostgreSQL repository adapter. */
export interface PostgresAdapterOptions {
  /** A caller-owned pg pool. The adapter never closes this pool. */
  readonly pool?: Pool;
  /** A connection string from which the adapter creates and owns a pg pool. */
  readonly connectionString?: string;
  /** Optional pg pool settings used only when `connectionString` is supplied. */
  readonly poolOptions?: Omit<PoolConfig, "connectionString">;
}
/**
 * The complete PostgreSQL-backed AuthRepository plus explicit pool lifecycle.
 *
 * `close()` is idempotent. It ends only a pool created by this adapter; for a
 * caller-supplied pool it is a documented no-op, so application ownership is
 * preserved. Constructing this object never runs migrations or performs a
 * schema bootstrap query. Call the explicit `migrate` API before use.
 */
export interface PostgresAdapter extends AuthRepository {
  /** Whether this adapter created the underlying pg pool. */
  readonly ownsPool: boolean;
  /** Closes an internally owned pool; never closes a caller-supplied pool. */
  close(): Promise<void>;
}

interface AdapterLifecycle {
  readonly ownsPool: boolean;
  readonly close: () => Promise<void>;
}

function createRepository(
  context: RepositoryContext,
  lifecycle: AdapterLifecycle,
): PostgresAdapter {
  const accountRepositories = createUserRepositories(context);
  const sessionRepository = createSessionRepository(context);
  const authorizationRepositories = createAuthorizationRepositories(context);
  const operationsRepository = createOperationsRepository(context);
  const adminRepository = createAdminRepository(context);

  const repository: PostgresAdapter = {
    async transaction<T>(callback: (repository: AuthRepository) => Promise<T>): Promise<T> {
      if (context.inTransaction) return callback(repository);
      return context.root.transaction().execute(async (transaction) =>
        callback(
          createRepository(
            { ...context, db: transaction, inTransaction: true },
            lifecycle,
          ),
        ),
      );
    },
    users: accountRepositories.users,
    identities: accountRepositories.identities,
    passwordCredentials: accountRepositories.passwordCredentials,
    sessions: sessionRepository,
    oneTimeTokens: accountRepositories.oneTimeTokens,
    oauthStates: accountRepositories.oauthStates,
    authorization: authorizationRepositories.authorization,
    roles: authorizationRepositories.roles,
    permissions: authorizationRepositories.permissions,
    operations: operationsRepository,
    admin: adminRepository,
    ownsPool: lifecycle.ownsPool,
    close: lifecycle.close,
  };
  return repository;
}

/**
 * Creates a complete Kysely/PostgreSQL AuthRepository for the Task 3 schema.
 *
 * Exactly one of `pool` or `connectionString` is required. The adapter uses
 * Kysely's parameterized PostgresDialect for every repository operation,
 * passes a transaction-scoped complete aggregate to `transaction(callback)`,
 * and does not run migrations automatically. A caller supplying `pool`
 * retains ownership and must close it; a connection-string adapter owns its
 * pool and can close it safely with the returned `close()` method.
 *
 * @param options - Caller-owned pool or connection string plus optional pool settings.
 * @returns The complete internal AuthRepository and explicit pool lifecycle.
 * @throws TypeError when neither or both connection sources are supplied.
 *
 * @example
 * ```ts
 * const repository = createPostgresAdapter({ pool });
 * await repository.transaction(async (transaction) => {
 *   const user = await transaction.users.create({ email: "user@example.com" });
 *   await transaction.passwordCredentials.upsert(user.id, passwordHash);
 * });
 * ```
 */
export function createPostgresAdapter(options: PostgresAdapterOptions): PostgresAdapter {
  const hasPool = options.pool !== undefined;
  const hasConnectionString =
    typeof options.connectionString === "string" && options.connectionString.trim() !== "";
  if (hasPool === hasConnectionString) {
    throw new TypeError("provide exactly one of pool or connectionString");
  }

  const pool = hasPool
    ? options.pool
    : new Pool({
        ...options.poolOptions,
        connectionString: options.connectionString,
      });
  if (pool === undefined) {
    throw new TypeError("PostgreSQL pool could not be created");
  }

  const ownsPool = !hasPool;
  const db = new Kysely<Database>({ dialect: new PostgresDialect({ pool }) });
  let closed = false;
  const lifecycle: AdapterLifecycle = {
    ownsPool,
    close: async () => {
      if (closed) return;
      closed = true;
      if (ownsPool) await pool.end();
    },
  };
  return createRepository(
    { db, root: db, inTransaction: false },
    lifecycle,
  );
}
