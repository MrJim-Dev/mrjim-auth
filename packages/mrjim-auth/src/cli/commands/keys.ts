import type { Pool } from "pg";
import type { DoctorEnvironment } from "./doctor.js";
import { createPostgresAdapter } from "../../postgres/adapter.js";
import { ApiKeyService, type ApiKeyStore } from "../../server/api-keys.js";

export interface GenerateKeyCommand {
  readonly kind: "publishable" | "secret";
  readonly name: string;
}

function decodeHashKey(environment: DoctorEnvironment): Uint8Array {
  const value = environment.MRJIM_AUTH_API_KEY_HASH_KEY;
  if (typeof value !== "string" || value.length === 0) throw new Error("MRJIM_AUTH_API_KEY_HASH_KEY is required");
  let bytes: Buffer;
  if (/^[0-9a-f]{64}$/iu.test(value)) bytes = Buffer.from(value, "hex");
  else if (/^[A-Za-z0-9_-]{43}$/u.test(value)) bytes = Buffer.from(value, "base64url");
  else throw new Error("MRJIM_AUTH_API_KEY_HASH_KEY must encode exactly 32 bytes as hex or base64url");
  if (bytes.byteLength !== 32) throw new Error("MRJIM_AUTH_API_KEY_HASH_KEY must encode exactly 32 bytes as hex or base64url");
  return Uint8Array.from(bytes);
}

/** Generate one project-owned API key and write its raw value exactly once. */
export async function runGenerateKeyCommand(
  pool: Pool,
  command: GenerateKeyCommand,
  environment: DoctorEnvironment,
  write: (line: string) => void,
): Promise<void> {
  const adapter = createPostgresAdapter({ pool });
  const admin = adapter.admin;
  if (admin === undefined) throw new Error("administration repository is unavailable");
  const store: ApiKeyStore = {
    create: (input) => admin.createApiKey(input),
    list: (input = { page: 1, perPage: 50 }) => admin.listApiKeys(input),
    revoke: (id, revokedAt) => admin.revokeApiKey(id as never, revokedAt),
    touchLastUsed: (id, usedAt) => admin.touchApiKeyLastUsed(id as never, usedAt),
  };
  const service = new ApiKeyService({ store, hashKey: decodeHashKey(environment) });
  const result = await service.generate({
    kind: command.kind,
    name: command.name,
    scopes: command.kind === "secret" ? ["auth.*"] : ["auth.public"],
  });
  if (result.error !== null) throw new Error("API key generation failed");
  write(result.data.key);
}
