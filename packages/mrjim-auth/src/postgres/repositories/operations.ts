import type { OperationsRepository } from "../../shared/contracts.js";
import { redactedMetadataSchema } from "../../shared/types.js";
import type { InsertObject, Selectable } from "kysely";
import { assertDigest, authDb, operationNow } from "./context.js";
import {
  API_KEY_COLUMNS,
  type ApiKeysTable,
  type Database,
  type RepositoryContext,
} from "./schema.js";
import { mapApiKey } from "./mapping.js";

function mapApiKeyRow(
  row: Pick<Selectable<ApiKeysTable>, "id" | "prefix" | "key_hash" | "kind" | "scopes" | "expires_at" | "revoked_at">,
) {
  return mapApiKey(row);
}

/** Build immutable audit append and active API-key lookup operations. */
export function createOperationsRepository(context: RepositoryContext): OperationsRepository {
  return {
    async appendAudit(input, options) {
      const metadata = redactedMetadataSchema.parse(input.metadata ?? {});
      const values: InsertObject<Database, "audit_log"> = {
        actor_user_id: input.actor_user_id ?? null,
        actor_key_id: input.actor_key_id ?? null,
        actor_session_id: input.actor_session_id ?? null,
        action: input.action,
        target_type: input.target_type,
        target_id: input.target_id ?? null,
        ip_address: input.ip_address ?? null,
        user_agent: input.user_agent ?? null,
        metadata,
        outcome: input.outcome,
        occurred_at: input.occurred_at ?? operationNow(options),
      };
      await authDb(context).insertInto("audit_log").values(values).execute();
    },

    async findApiKeyByHash(keyHash, options) {
      const row = await authDb(context)
        .selectFrom("api_keys")
        .select(API_KEY_COLUMNS)
        .where("key_hash", "=", assertDigest(keyHash, "API key hash"))
        .where("revoked_at", "is", null)
        .where((expression) =>
          expression.or([
            expression("expires_at", "is", null),
            expression("expires_at", ">", operationNow(options)),
          ]),
        )
        .executeTakeFirst();
      return row === undefined ? null : mapApiKeyRow(row);
    },
  } satisfies OperationsRepository;
}
