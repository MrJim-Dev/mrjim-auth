import {
  AuthApiError,
  AuthConfigurationError,
  type AuthError,
} from "../shared/errors.js";
import { authFailure, authSuccess, type AuthResult } from "../shared/result.js";
import {
  isRedactedMetadata,
  sanitizeRedactedMetadata,
  type RedactedMetadata,
  type UUID,
} from "../shared/types.js";
import type {
  AdminPageInput,
  AuditEventInput,
  AuditEventRecord,
} from "../shared/contracts.js";
import {
  assertBoundaryObject,
  boundaryOwnDataProperty,
  captureBoundaryClock,
  captureBoundaryDenseArray,
  captureBoundaryMethodGroup,
  invokeBoundaryResult,
  optionalBoundaryOption,
  requiredBoundaryOption,
} from "./callback-boundary.js";

const auditObjectFreeze = Object.freeze;
const auditDate = Date;
const auditDateGetTime = Date.prototype.getTime;
const auditNumberIsFinite = Number.isFinite;
const auditNumberIsSafeInteger = Number.isSafeInteger;
const auditArrayIsArray = Array.isArray;
const auditArrayPush = Array.prototype.push;
const auditReflectApply = Reflect.apply;

const MAX_AUDIT_PAGE = 100;
const MAX_AUDIT_TOTAL = 1_000_000_000;
const MAX_AUDIT_ACTION = 128;
const MAX_AUDIT_TARGET_TYPE = 128;
const MAX_AUDIT_IP = 128;
const MAX_AUDIT_USER_AGENT = 512;
const MAX_AUDIT_EVENTS_PER_PAGE = 100;

export type PublicAuditEventRecord = Omit<AuditEventRecord, "occurred_at"> & {
  readonly occurred_at: string;
};

/** The persistence boundary used by {@link AuditService}. */
export interface AuditStore {
  /** Appends one already-validated immutable audit event. */
  append(input: AuditEventInput): Promise<void>;
  /** Lists rows; the service owns pagination and projection validation. */
  list(input?: AdminPageInput): Promise<{
    readonly events: readonly unknown[];
    readonly total: number;
  }>;
}

/** Bounded audit listing input. */
export interface AuditListInput extends Partial<AdminPageInput> {
  readonly cursor?: string;
}

function invalidRequest(): AuthResult<never> {
  return frozenFailure(new AuthApiError("invalid_request", 400, "Invalid audit request"));
}

function internalError(): AuthResult<never> {
  return frozenFailure(new AuthApiError("internal_error", 500, "Internal authentication error"));
}

function frozenFailure(error: AuthError): AuthResult<never> {
  return auditObjectFreeze(authFailure(error));
}

function frozenSuccess<T>(data: T): AuthResult<T> {
  return auditObjectFreeze(authSuccess(data));
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

function validText(value: unknown, label: string, maximum: number, allowEmpty = false): string {
  if (typeof value !== "string" || value.length > maximum || (!allowEmpty && value.length === 0)) {
    throw new TypeError(`${label} is malformed`);
  }
  const trimmed = value.trim();
  if ((!allowEmpty && trimmed.length === 0) || trimmed !== value || /[\u0000-\u001f\u007f-\u009f]/u.test(value)) {
    throw new TypeError(`${label} is malformed`);
  }
  return value;
}

function validNullableText(value: unknown, label: string, maximum: number): string | null {
  if (value === undefined || value === null) return null;
  return validText(value, label, maximum);
}

function validUuid(value: unknown, label: string): UUID | null {
  if (value === null || value === undefined) return null;
  if (typeof value !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(value)) {
    throw new TypeError(`${label} is malformed`);
  }
  return value as UUID;
}

function validDate(value: unknown, label: string, nullable: boolean): Date | null {
  if (value === undefined || (value === null && nullable)) return null;
  if (typeof value === "string") {
    const parsed = new auditDate(value);
    const milliseconds = parsed.getTime();
    if (!auditNumberIsFinite(milliseconds)) throw new TypeError(`${label} is malformed`);
    return auditObjectFreeze(new auditDate(milliseconds));
  }
  if (!(value instanceof auditDate)) throw new TypeError(`${label} is malformed`);
  const milliseconds = auditReflectApply(auditDateGetTime, value, []) as number;
  if (!auditNumberIsFinite(milliseconds)) throw new TypeError(`${label} is malformed`);
  return auditObjectFreeze(new auditDate(milliseconds));
}

function safeMetadata(value: unknown): RedactedMetadata {
  if (!isRedactedMetadata(value)) throw new TypeError("audit metadata is not redacted");
  return deepFreezeJson(sanitizeRedactedMetadata(value));
}

function projectedMetadata(value: unknown): RedactedMetadata {
  // Database rows are untrusted at this response boundary. Project legacy
  // nested metadata through the recursive sanitizer before returning it.
  return deepFreezeJson(sanitizeRedactedMetadata(value));
}

function deepFreezeJson<T>(value: T): T {
  if (value !== null && typeof value === "object") {
    if (auditArrayIsArray(value)) {
      for (let index = 0; index < value.length; index += 1) {
        deepFreezeJson(value[index]);
      }
    } else {
      const source = value as Record<string, unknown>;
      for (const key of Object.keys(source)) deepFreezeJson(source[key]);
    }
    auditObjectFreeze(value);
  }
  return value;
}

function boundedPage(value: unknown, fallback: number, label: string): number {
  if (value === undefined) return fallback;
  if (!auditNumberIsSafeInteger(value) || (value as number) < 1 || (value as number) > MAX_AUDIT_PAGE) {
    throw new TypeError(`${label} is malformed`);
  }
  return value as number;
}

function validCursor(value: unknown): string | undefined {
  if (value === undefined) return undefined;
  const cursor = validText(value, "audit cursor", 512);
  return cursor;
}

function safeProjection(value: unknown): PublicAuditEventRecord {
  if (value === null || typeof value !== "object" || auditArrayIsArray(value)) throw new TypeError("audit row is malformed");
  const source = value as object;
  const id = validUuid(dataProperty(source, "id"), "audit id");
  const actorUserId = validUuid(optionalDataProperty(source, "actor_user_id"), "audit actor user id");
  const actorKeyId = validUuid(optionalDataProperty(source, "actor_key_id"), "audit actor key id");
  const actorSessionId = validUuid(optionalDataProperty(source, "actor_session_id"), "audit actor session id");
  if (id === null) throw new TypeError("audit id is malformed");
  const action = validText(dataProperty(source, "action"), "audit action", MAX_AUDIT_ACTION);
  const targetType = validText(dataProperty(source, "target_type"), "audit target type", MAX_AUDIT_TARGET_TYPE);
  const targetId = validUuid(optionalDataProperty(source, "target_id"), "audit target id");
  const ipAddress = validNullableText(optionalDataProperty(source, "ip_address"), "audit IP address", MAX_AUDIT_IP);
  const userAgent = validNullableText(optionalDataProperty(source, "user_agent"), "audit user agent", MAX_AUDIT_USER_AGENT);
  const metadata = projectedMetadata(dataProperty(source, "metadata"));
  const outcome = dataProperty(source, "outcome");
  if (outcome !== "success" && outcome !== "failure") throw new TypeError("audit outcome is malformed");
  const occurredAt = validDate(dataProperty(source, "occurred_at"), "audit timestamp", false);
  if (occurredAt === null) throw new TypeError("audit timestamp is malformed");
  return auditObjectFreeze({
    id,
    actor_user_id: actorUserId,
    actor_key_id: actorKeyId,
    actor_session_id: actorSessionId,
    action,
    target_type: targetType,
    target_id: targetId,
    ip_address: ipAddress,
    user_agent: userAgent,
    metadata,
    outcome,
    occurred_at: occurredAt.toISOString(),
  });
}

function inputEvent(value: unknown, clock: () => Date): AuditEventInput {
  if (value === null || typeof value !== "object" || auditArrayIsArray(value)) throw new TypeError("audit input is malformed");
  const source = value as object;
  assertBoundaryObject(source, "audit input");
  const action = validText(dataProperty(source, "action"), "audit action", MAX_AUDIT_ACTION);
  const targetType = validText(dataProperty(source, "target_type"), "audit target type", MAX_AUDIT_TARGET_TYPE);
  const targetId = validUuid(optionalDataProperty(source, "target_id"), "audit target id");
  const actorUserId = validUuid(optionalDataProperty(source, "actor_user_id"), "audit actor user id");
  const actorKeyId = validUuid(optionalDataProperty(source, "actor_key_id"), "audit actor key id");
  const actorSessionId = validUuid(optionalDataProperty(source, "actor_session_id"), "audit actor session id");
  const ipAddress = validNullableText(optionalDataProperty(source, "ip_address"), "audit IP address", MAX_AUDIT_IP);
  const userAgent = validNullableText(optionalDataProperty(source, "user_agent"), "audit user agent", MAX_AUDIT_USER_AGENT);
  const metadataValue = optionalDataProperty(source, "metadata");
  const metadata = metadataValue === undefined ? deepFreezeJson(sanitizeRedactedMetadata({})) : safeMetadata(metadataValue);
  const outcome = dataProperty(source, "outcome");
  if (outcome !== "success" && outcome !== "failure") throw new TypeError("audit outcome is malformed");
  const occurredValue = optionalDataProperty(source, "occurred_at");
  const occurredAt = occurredValue === undefined ? validDate(clock(), "audit clock", false) : validDate(occurredValue, "audit timestamp", false);
  if (occurredAt === null) throw new TypeError("audit timestamp is malformed");
  return {
    actor_user_id: actorUserId,
    actor_key_id: actorKeyId,
    actor_session_id: actorSessionId,
    action,
    target_type: targetType,
    target_id: targetId,
    ip_address: ipAddress,
    user_agent: userAgent,
    metadata,
    outcome,
    occurred_at: occurredAt,
  };
}

/** Server-only redacted audit append/list service. Store rows are never returned wholesale. */
export class AuditService {
  private readonly store: AuditStore;
  private readonly clock: () => Date;

  constructor(options: { readonly store: AuditStore; readonly clock?: () => Date }) {
    if (options === null || typeof options !== "object") throw new AuthConfigurationError("audit options are incomplete");
    const source = options as unknown as object;
    assertBoundaryObject(source, "audit options");
    const storeValue = requiredBoundaryOption(source, "store", "audit store");
    const clockValue = optionalBoundaryOption(source, "clock", "audit clock");
    this.store = captureBoundaryMethodGroup(storeValue, "audit store", ["append", "list"]) as unknown as AuditStore;
    this.clock = captureBoundaryClock(clockValue, "audit clock", () => new auditDate());
    const now = this.clock();
    if (!(now instanceof auditDate) || !auditNumberIsFinite(auditReflectApply(auditDateGetTime, now, []) as number)) {
      throw new AuthConfigurationError("audit clock must return a valid Date");
    }
  }

  /** Validates and appends one redacted immutable audit event. */
  async append(input: AuditEventInput): Promise<AuthResult<null>> {
    let event: AuditEventInput;
    try {
      event = inputEvent(input, this.clock);
    } catch {
      return invalidRequest() as AuthResult<null>;
    }
    try {
      await invokeBoundaryResult<unknown>(this.store.append, this.store, [event], "audit store.append");
      return frozenSuccess(null);
    } catch {
      return internalError() as AuthResult<null>;
    }
  }

  /** Lists bounded immutable audit projections through an explicit allowlist. */
  async list(input?: AuditListInput): Promise<AuthResult<{ readonly events: readonly PublicAuditEventRecord[]; readonly total: number }>> {
    let page: number;
    let perPage: number;
    try {
      if (input === undefined) {
        page = 1;
        perPage = 50;
      } else {
        if (input === null || typeof input !== "object") throw new TypeError("audit list input is malformed");
        const source = input as unknown as object;
        assertBoundaryObject(source, "audit list input");
        page = boundedPage(optionalDataProperty(source, "page"), 1, "audit page");
        perPage = boundedPage(optionalDataProperty(source, "perPage"), 50, "audit page size");
        validCursor(optionalDataProperty(source, "cursor"));
      }
    } catch {
      return invalidRequest() as AuthResult<{ readonly events: readonly PublicAuditEventRecord[]; readonly total: number }>;
    }
    try {
      const result = await invokeBoundaryResult<unknown>(this.store.list, this.store, [{ page, perPage }], "audit store.list");
      if (result === null || typeof result !== "object" || auditArrayIsArray(result)) throw new TypeError("audit list is malformed");
      const source = result as object;
      const values = captureBoundaryDenseArray(dataProperty(source, "events"), "audit events", 0, MAX_AUDIT_EVENTS_PER_PAGE);
      const total = dataProperty(source, "total");
      if (!auditNumberIsSafeInteger(total) || (total as number) < 0 || (total as number) > MAX_AUDIT_TOTAL) throw new TypeError("audit total is malformed");
      const events: PublicAuditEventRecord[] = [];
      for (let index = 0; index < values.length; index += 1) {
        const event = safeProjection(values[index]);
        auditReflectApply(auditArrayPush, events, [event]);
      }
      return frozenSuccess({ events: auditObjectFreeze(events), total: total as number });
    } catch {
      return internalError() as AuthResult<{ readonly events: readonly PublicAuditEventRecord[]; readonly total: number }>;
    }
  }
}
