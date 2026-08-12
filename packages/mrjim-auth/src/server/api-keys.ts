import { createHmac, randomBytes as nodeRandomBytes } from "node:crypto";
import {
  AuthApiError,
  AuthConfigurationError,
  type AuthError,
} from "../shared/errors.js";
import { authFailure, authSuccess, type AuthResult } from "../shared/result.js";
import {
  isSensitiveKeyName,
  type UUID,
} from "../shared/types.js";
import type {
  AdminPageInput,
  ApiKeyAdminRecord,
  CreateApiKeyRecordInput,
} from "../shared/contracts.js";
import {
  assertBoundaryObject,
  boundaryOwnDataProperty,
  captureBoundaryBytes,
  captureBoundaryClock,
  captureBoundaryFunction,
  captureBoundaryMethodGroup,
  captureBoundaryDenseArray,
  invokeBoundaryResult,
  optionalBoundaryOption,
  requiredBoundaryOption,
} from "./callback-boundary.js";

const apiKeyObjectFreeze = Object.freeze;
const apiKeyObjectDefineProperty = Object.defineProperty;
const apiKeyArrayPush = Array.prototype.push;
const apiKeyDate = Date;
const apiKeyDateGetTime = Date.prototype.getTime;
const apiKeyNumberIsFinite = Number.isFinite;
const apiKeyNumberIsSafeInteger = Number.isSafeInteger;
const apiKeyTextEncoder = TextEncoder;
const apiKeySet = Set;
const apiKeySetHas = Set.prototype.has;
const apiKeySetAdd = Set.prototype.add;
const apiKeyReflectApply = Reflect.apply;

const MAX_API_KEY_NAME = 128;
const MAX_API_KEY_NAME_BYTES = 512;
const MAX_API_KEY_SCOPES = 128;
const MAX_API_KEY_SCOPE = 128;
const MAX_API_KEY_SCOPE_BYTES = 512;
const MAX_API_KEY_PAGE = 100;
const MAX_API_KEY_TOTAL = 1_000_000_000;
const API_KEY_BYTES = 32;
const API_KEY_PREFIX_LENGTH = 11;
const API_KEY_DOMAIN = "apikey\0";

/** A safe API-key record returned by the service. Raw values and digests are excluded. */
export type SafeApiKeyRecord = ApiKeyAdminRecord;

/** The durable boundary used by {@link ApiKeyService}. */
export interface ApiKeyStore {
  /** Persists an already-digested key and returns its safe projection. */
  create(input: CreateApiKeyRecordInput): Promise<unknown>;
  /** Lists safe key projections. */
  list(input?: AdminPageInput): Promise<{
    readonly apiKeys: readonly unknown[];
    readonly total: number;
  }>;
  /** Revokes one key and returns whether it was active. */
  revoke(id: string, revokedAt: Date): Promise<boolean>;
  /** Best-effort last-use update after successful authentication. */
  touchLastUsed(id: string, usedAt: Date): Promise<void>;
}

/** Optional actor context accepted for audit-aware callers. It is never persisted by this slice. */
export interface ApiKeyActor {
  readonly userId?: UUID | null;
  readonly keyId?: UUID | null;
  readonly sessionId?: UUID | null;
}

/** Input for one-time API-key generation. */
export interface ApiKeyGenerateInput {
  readonly kind: "publishable" | "secret";
  readonly name: string;
  readonly scopes: readonly string[];
  readonly expiresAt?: Date | null;
  readonly actor?: ApiKeyActor | null;
}

/** Bounded API-key listing input. */
export interface ApiKeyListInput extends Partial<AdminPageInput> {
  readonly kind?: "publishable" | "secret";
}

/** The single successful raw-key response. Callers must persist the key immediately. */
export interface ApiKeyGenerateData {
  readonly key: string;
  readonly apiKey: SafeApiKeyRecord;
}

/** Result returned by an API-key revocation. */
export interface ApiKeyRevokeData {
  readonly id: UUID;
  readonly revoked: boolean;
}

/** Configuration for the server-only API-key service. */
export interface ApiKeyServiceOptions {
  readonly store: ApiKeyStore;
  /** Exactly 32 project-owned bytes used for HMAC key derivation. */
  readonly hashKey: Uint8Array;
  readonly clock?: () => Date;
  /** Test/project entropy hook. The default is Node's cryptographic RNG. */
  readonly randomBytes?: (size: number) => Uint8Array;
}

function invalidRequest(): AuthResult<never> {
  return frozenFailure(new AuthApiError("invalid_request", 400, "Invalid API-key request"));
}

function internalError(): AuthResult<never> {
  return frozenFailure(new AuthApiError("internal_error", 500, "Internal authentication error"));
}

function frozenFailure(error: AuthError): AuthResult<never> {
  return apiKeyObjectFreeze(authFailure(error));
}

function frozenSuccess<T>(data: T): AuthResult<T> {
  return apiKeyObjectFreeze(authSuccess(data));
}

function dataProperty(source: object, key: PropertyKey): unknown {
  const property = boundaryOwnDataProperty(source, key);
  if (!property.valid || !property.present) throw new TypeError("missing data property");
  return property.value;
}

function optionalDataProperty(source: object, key: PropertyKey): unknown {
  const property = boundaryOwnDataProperty(source, key);
  if (!property.valid) throw new TypeError("invalid data property");
  return property.present ? property.value : undefined;
}

function validUtf8String(value: unknown, label: string, maximum: number, maximumBytes: number): string {
  if (typeof value !== "string" || value.length === 0 || value.length > maximum) {
    throw new TypeError(`${label} is malformed`);
  }
  const trimmed = value.trim();
  if (trimmed.length === 0 || trimmed !== value || /[\u0000-\u001f\u007f-\u009f]/u.test(value)) {
    throw new TypeError(`${label} is malformed`);
  }
  const bytes = new apiKeyTextEncoder().encode(value).byteLength;
  if (bytes > maximumBytes) throw new TypeError(`${label} is oversized`);
  return value;
}

function containsSecretMaterial(value: string): boolean {
  if (isSensitiveKeyName(value)) return true;
  if (/^Bearer\s+\S+/iu.test(value)) return true;
  if (/^(?:pk|sk)_[A-Za-z0-9_-]+$/u.test(value)) return true;
  // Permission scopes such as `auth.users.manage` contain dots too. Treat a
  // dotted value as JWT-like only when all three encoded segments are
  // materially larger than a normal resource/action scope.
  if (/^[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}$/u.test(value)) return true;
  if (/(?:access|refresh)[ _-]?token|client[ _-]?secret|private[ _-]?key|password|credential|oauth|pkce|verifier|secret/iu.test(value)) return true;
  return false;
}

function normalizedName(value: unknown): string {
  const name = validUtf8String(value, "API-key name", MAX_API_KEY_NAME, MAX_API_KEY_NAME_BYTES);
  if (containsSecretMaterial(name)) throw new TypeError("API-key name contains secret material");
  return name;
}

function normalizedScopes(value: unknown): readonly string[] {
  const values = captureBoundaryDenseArray(value, "API-key scopes", 0, MAX_API_KEY_SCOPES);
  const seen = new apiKeySet<string>();
  const output: string[] = [];
  let totalBytes = 0;
  for (let index = 0; index < values.length; index += 1) {
    const entry = values[index];
    if (typeof entry !== "string" || entry.length === 0 || entry.length > MAX_API_KEY_SCOPE) {
      throw new TypeError("API-key scopes are malformed");
    }
    const trimmed = entry.trim();
    const scope = trimmed.toLowerCase();
    if (trimmed.length === 0 || /[\u0000-\u001f\u007f-\u009f]/u.test(trimmed)) {
      throw new TypeError("API-key scopes are malformed");
    }
    const bytes = new apiKeyTextEncoder().encode(scope).byteLength;
    if (bytes > MAX_API_KEY_SCOPE_BYTES || !/^[a-z0-9_.*-]+$/u.test(scope) || containsSecretMaterial(scope)) {
      throw new TypeError("API-key scopes are malformed");
    }
    totalBytes += bytes;
    if (totalBytes > MAX_API_KEY_SCOPES * MAX_API_KEY_SCOPE_BYTES) {
      throw new TypeError("API-key scopes are oversized");
    }
    if (apiKeyReflectApply(apiKeySetHas, seen, [scope])) continue;
    apiKeyReflectApply(apiKeySetAdd, seen, [scope]);
    apiKeyReflectApply(apiKeyArrayPush, output, [scope]);
  }
  return apiKeyObjectFreeze(output);
}

function validKind(value: unknown): value is "publishable" | "secret" {
  return value === "publishable" || value === "secret";
}

function validDate(value: unknown, label: string, nullable: boolean): Date | null {
  if (value === null && nullable) return null;
  if (!(value instanceof apiKeyDate)) throw new TypeError(`${label} is malformed`);
  const milliseconds = apiKeyReflectApply(apiKeyDateGetTime, value, []) as number;
  if (!apiKeyNumberIsFinite(milliseconds)) throw new TypeError(`${label} is malformed`);
  return apiKeyObjectFreeze(new apiKeyDate(milliseconds));
}

function dateValue(value: unknown, label: string, nullable: boolean): Date | null {
  if (value === undefined && nullable) return null;
  if (typeof value === "string") {
    const parsed = new apiKeyDate(value);
    if (!apiKeyNumberIsFinite(parsed.getTime())) throw new TypeError(`${label} is malformed`);
    return apiKeyObjectFreeze(new apiKeyDate(parsed.getTime()));
  }
  return validDate(value, label, nullable);
}

function validUuid(value: unknown, label: string): UUID {
  if (typeof value !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(value)) {
    throw new TypeError(`${label} is malformed`);
  }
  return value as UUID;
}

function validActor(value: unknown): void {
  if (value === undefined || value === null) return;
  if (typeof value !== "object" || Array.isArray(value)) throw new TypeError("API-key actor is malformed");
  const source = value as object;
  for (const key of ["userId", "keyId", "sessionId"] as const) {
    const candidate = optionalDataProperty(source, key);
    if (candidate !== undefined && candidate !== null) validUuid(candidate, `API-key actor ${key}`);
  }
}

function safeRecord(value: unknown, expected?: { readonly name: string; readonly prefix: string; readonly kind: "publishable" | "secret"; readonly scopes: readonly string[] }): SafeApiKeyRecord {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new TypeError("API-key store record is malformed");
  const source = value as object;
  const id = validUuid(dataProperty(source, "id"), "API-key id");
  const name = validUtf8String(dataProperty(source, "name"), "API-key name", MAX_API_KEY_NAME, MAX_API_KEY_NAME_BYTES);
  const prefix = validUtf8String(dataProperty(source, "prefix"), "API-key prefix", API_KEY_PREFIX_LENGTH, API_KEY_PREFIX_LENGTH);
  const kind = dataProperty(source, "kind");
  if (!validKind(kind) || prefix.length !== API_KEY_PREFIX_LENGTH || !prefix.startsWith(kind === "secret" ? "sk_" : "pk_")) {
    throw new TypeError("API-key store record is malformed");
  }
  const scopes = normalizedScopes(dataProperty(source, "scopes"));
  const lastUsedAt = dateValue(optionalDataProperty(source, "last_used_at"), "API-key last-use time", true);
  const expiresAt = dateValue(optionalDataProperty(source, "expires_at"), "API-key expiry", true);
  const revokedAt = dateValue(optionalDataProperty(source, "revoked_at"), "API-key revocation time", true);
  const createdAt = dateValue(dataProperty(source, "created_at"), "API-key creation time", false);
  if (createdAt === null) throw new TypeError("API-key creation time is malformed");
  if (expected !== undefined && (name !== expected.name || prefix !== expected.prefix || kind !== expected.kind || scopes.length !== expected.scopes.length)) {
    throw new TypeError("API-key store record does not match the request");
  }
  if (expected !== undefined) {
    for (let index = 0; index < scopes.length; index += 1) {
      if (scopes[index] !== expected.scopes[index]) throw new TypeError("API-key store record does not match the request");
    }
  }
  const output = {
    id,
    name,
    prefix,
    kind,
    scopes,
    last_used_at: lastUsedAt,
    expires_at: expiresAt,
    revoked_at: revokedAt,
    created_at: createdAt,
  } satisfies SafeApiKeyRecord;
  return apiKeyObjectFreeze(output);
}

function boundedPage(value: unknown, fallback: number, label: string): number {
  if (value === undefined) return fallback;
  if (!apiKeyNumberIsSafeInteger(value) || (value as number) < 1 || (value as number) > MAX_API_KEY_PAGE) {
    throw new TypeError(`${label} is malformed`);
  }
  return value as number;
}

function frozenData<T extends object>(value: T): T {
  return apiKeyObjectFreeze(value);
}

/** Server-only API-key lifecycle service. The raw credential is returned once and never crosses the store boundary. */
export class ApiKeyService {
  private readonly store: ApiKeyStore;
  private readonly hashKey: Uint8Array;
  private readonly clock: () => Date;
  private readonly randomBytes: (size: number) => Uint8Array;

  constructor(options: ApiKeyServiceOptions) {
    if (options === null || typeof options !== "object") throw new AuthConfigurationError("API-key options are incomplete");
    const source = options as unknown as object;
    assertBoundaryObject(source, "API-key options");
    const storeValue = requiredBoundaryOption(source, "store", "API-key store");
    const hashKeyValue = requiredBoundaryOption(source, "hashKey", "API-key HMAC key");
    const clockValue = optionalBoundaryOption(source, "clock", "API-key clock");
    const randomValue = optionalBoundaryOption(source, "randomBytes", "API-key random source");
    this.store = captureBoundaryMethodGroup(
      storeValue,
      "API-key store",
      ["create", "list", "revoke", "touchLastUsed"],
    ) as unknown as ApiKeyStore;
    const hashKey = captureBoundaryBytes(hashKeyValue, "API-key HMAC key", API_KEY_BYTES);
    if (hashKey.byteLength !== API_KEY_BYTES) throw new AuthConfigurationError("API-key HMAC key must contain exactly 32 bytes");
    // Typed-array views with elements cannot be frozen on the supported Node
    // runtime. Keep a private defensive copy; it is never returned or passed
    // outside the HMAC operation.
    this.hashKey = Uint8Array.from(hashKey);
    this.clock = captureBoundaryClock(clockValue, "API-key clock", () => new apiKeyDate());
    const randomBytes = randomValue === undefined
      ? (size: number): Uint8Array => Uint8Array.from(nodeRandomBytes(size))
      : captureBoundaryFunction(randomValue, "API-key random source") as (size: number) => Uint8Array;
    this.randomBytes = randomBytes;
    const now = this.clock();
    if (!(now instanceof apiKeyDate) || !apiKeyNumberIsFinite(apiKeyReflectApply(apiKeyDateGetTime, now, []) as number)) {
      throw new AuthConfigurationError("API-key clock must return a valid Date");
    }
  }

  /** Generates one publishable or secret key and returns its raw value exactly once. */
  async generate(input: ApiKeyGenerateInput): Promise<AuthResult<ApiKeyGenerateData>> {
    let kind: "publishable" | "secret";
    let name: string;
    let scopes: readonly string[];
    let expiresAt: Date | null;
    try {
      if (input === null || typeof input !== "object") throw new TypeError("input is malformed");
      const source = input as unknown as object;
      assertBoundaryObject(source, "API-key input");
      const kindValue = dataProperty(source, "kind");
      if (!validKind(kindValue)) throw new TypeError("kind is malformed");
      kind = kindValue;
      name = normalizedName(dataProperty(source, "name"));
      scopes = normalizedScopes(dataProperty(source, "scopes"));
      validActor(optionalDataProperty(source, "actor"));
      const now = validDate(this.clock(), "API-key clock", false);
      if (now === null) throw new TypeError("clock is malformed");
      const expiresValue = optionalDataProperty(source, "expiresAt");
      expiresAt = expiresValue === undefined ? null : validDate(expiresValue, "API-key expiry", true);
      if (expiresAt !== null && expiresAt.getTime() <= now.getTime()) throw new TypeError("API-key expiry is not in the future");
    } catch {
      return invalidRequest() as AuthResult<ApiKeyGenerateData>;
    }

    let raw: string;
    let keyHash: Uint8Array;
    let createdAt: Date;
    try {
      const bytes = this.randomBytes(API_KEY_BYTES);
      if (!(bytes instanceof Uint8Array) || bytes.byteLength !== API_KEY_BYTES) throw new TypeError("random source is malformed");
      const encoded = Buffer.from(bytes).toString("base64url");
      if (encoded.length !== 43) throw new TypeError("random source is malformed");
      raw = `${kind === "secret" ? "sk_" : "pk_"}${encoded}`;
      keyHash = Uint8Array.from(createHmac("sha256", this.hashKey).update(`${API_KEY_DOMAIN}${raw}`, "utf8").digest());
      createdAt = validDate(this.clock(), "API-key clock", false) as Date;
    } catch {
      return internalError() as AuthResult<ApiKeyGenerateData>;
    }

    let stored: SafeApiKeyRecord;
    try {
      const inputForStore: CreateApiKeyRecordInput = {
        name,
        prefix: raw.slice(0, API_KEY_PREFIX_LENGTH),
        key_hash: Uint8Array.from(keyHash),
        kind,
        scopes: apiKeyObjectFreeze(Array.from(scopes)),
        expires_at: expiresAt === null ? null : new apiKeyDate(expiresAt.getTime()),
        created_at: new apiKeyDate(createdAt.getTime()),
      };
      const result = await invokeBoundaryResult<unknown>(this.store.create, this.store, [inputForStore], "API-key store.create");
      stored = safeRecord(result, { name, prefix: inputForStore.prefix, kind, scopes });
    } catch {
      return internalError() as AuthResult<ApiKeyGenerateData>;
    }

    const data = frozenData({
      key: raw,
      apiKey: stored,
    });
    return frozenSuccess(data);
  }

  /** Lists safe API-key records with deterministic bounded pagination. */
  async list(input?: ApiKeyListInput): Promise<AuthResult<{ readonly apiKeys: readonly SafeApiKeyRecord[]; readonly total: number }>> {
    let page: number;
    let perPage: number;
    let kind: "publishable" | "secret" | undefined;
    try {
      if (input !== undefined) {
        if (input === null || typeof input !== "object") throw new TypeError("input is malformed");
        const source = input as unknown as object;
        assertBoundaryObject(source, "API-key list input");
        page = boundedPage(optionalDataProperty(source, "page"), 1, "API-key page");
        perPage = boundedPage(optionalDataProperty(source, "perPage"), 50, "API-key page size");
        const kindValue = optionalDataProperty(source, "kind");
        if (kindValue !== undefined && !validKind(kindValue)) throw new TypeError("API-key kind is malformed");
        kind = kindValue as "publishable" | "secret" | undefined;
      } else {
        page = 1;
        perPage = 50;
      }
    } catch {
      return invalidRequest() as AuthResult<{ readonly apiKeys: readonly SafeApiKeyRecord[]; readonly total: number }>;
    }

    try {
      const result = await invokeBoundaryResult<unknown>(this.store.list, this.store, [{ page, perPage }], "API-key store.list");
      if (result === null || typeof result !== "object" || Array.isArray(result)) throw new TypeError("API-key list is malformed");
      const source = result as object;
      const values = dataProperty(source, "apiKeys");
      const rows = captureBoundaryDenseArray(values, "API-key list", 0, perPage);
      const total = dataProperty(source, "total");
      if (!apiKeyNumberIsSafeInteger(total) || (total as number) < 0 || (total as number) > MAX_API_KEY_TOTAL) throw new TypeError("API-key total is malformed");
      const output: SafeApiKeyRecord[] = [];
      for (let index = 0; index < rows.length; index += 1) {
        const row = safeRecord(rows[index]);
        if (kind !== undefined && row.kind !== kind) continue;
        apiKeyReflectApply(apiKeyArrayPush, output, [row]);
      }
      return frozenSuccess({
        apiKeys: apiKeyObjectFreeze(output),
        total: total as number,
      });
    } catch {
      return internalError() as AuthResult<{ readonly apiKeys: readonly SafeApiKeyRecord[]; readonly total: number }>;
    }
  }

  /** Revokes one API key. Raw values and digests never appear in the result. */
  async revoke(id: UUID): Promise<AuthResult<ApiKeyRevokeData>> {
    let keyId: UUID;
    let revokedAt: Date;
    try {
      keyId = validUuid(id, "API-key id");
      revokedAt = validDate(this.clock(), "API-key clock", false) as Date;
    } catch {
      return invalidRequest() as AuthResult<ApiKeyRevokeData>;
    }
    try {
      const revoked = await invokeBoundaryResult<unknown>(this.store.revoke, this.store, [keyId, new apiKeyDate(revokedAt.getTime())], "API-key store.revoke");
      if (typeof revoked !== "boolean") throw new TypeError("API-key revoke result is malformed");
      return frozenSuccess(frozenData({ id: keyId, revoked }));
    } catch {
      return internalError() as AuthResult<ApiKeyRevokeData>;
    }
  }

  /** Performs a best-effort last-use update; authentication success remains authoritative. */
  async touchLastUsed(id: UUID, usedAt = this.clock()): Promise<void> {
    try {
      const keyId = validUuid(id, "API-key id");
      const time = validDate(usedAt, "API-key last-use time", false);
      if (time === null) return;
      await invokeBoundaryResult<unknown>(this.store.touchLastUsed, this.store, [keyId, new apiKeyDate(time.getTime())], "API-key store.touchLastUsed");
    } catch {
      // Last-use telemetry is deliberately non-authoritative and must not turn
      // a successfully authenticated request into an authentication failure.
    }
  }
}
