import type { RepositoryOperationOptions } from "../../shared/contracts.js";
import type { QueryCreator } from "kysely";
import type { Database, DatabaseExecutor, RepositoryContext } from "./schema.js";

/** Run one repository operation in the current transaction or an atomic one. */
export async function withTransaction<T>(
  context: RepositoryContext,
  callback: (transaction: RepositoryContext) => Promise<T>,
): Promise<T> {
  if (context.inTransaction) return callback(context);
  return context.root.transaction().execute(async (transaction) =>
    callback({ ...context, db: transaction, inTransaction: true }),
  );
}

/** Resolve the operation clock without consulting a global wall-clock source. */
export function operationNow(options?: RepositoryOperationOptions): Date {
  return options?.now ?? new Date();
}

/** Convert a digest to the pg bytea parameter representation. */
export function digestParameter(value: Uint8Array): Buffer {
  return Buffer.from(value);
}

/** Ensure a digest meets the schema's exact 32-byte contract before a write. */
export function assertDigest(value: Uint8Array, label: string): Buffer {
  if (value.byteLength !== 32) {
    throw new TypeError(`${label} must contain exactly 32 bytes`);
  }
  return digestParameter(value);
}

/** Normalize an optional email while retaining the trimmed display value. */
export function normalizeEmail(email: string | null | undefined): {
  readonly display: string | null;
  readonly normalized: string | null;
} {
  if (email === undefined || email === null) return { display: null, normalized: null };
  const display = email.trim();
  if (display === "") return { display: null, normalized: null };
  return { display, normalized: display.toLowerCase() };
}

/** Normalize an optional phone value according to the Task 3 schema contract. */
export function normalizePhone(phone: string | null | undefined): {
  readonly display: string | null;
  readonly normalized: string | null;
} {
  if (phone === undefined || phone === null) return { display: null, normalized: null };
  const display = phone.trim();
  if (display === "") return { display: null, normalized: null };
  return { display, normalized: display };
}

/** Return the Kysely executor owned by this repository boundary. */
export function executor(context: RepositoryContext): DatabaseExecutor {
  return context.db;
}

/** Return a typed query creator with every adapter statement scoped to auth. */
export function authDb(context: RepositoryContext): QueryCreator<Database> {
  return context.db.withSchema("auth");
}
