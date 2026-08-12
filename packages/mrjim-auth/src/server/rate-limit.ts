import { createHmac } from "node:crypto";
import { AuthConfigurationError } from "../shared/errors.js";
import type {
  RateLimitDecision,
  RateLimitPolicy,
  RateLimiter,
} from "../shared/contracts.js";
import { captureBoundaryBytes } from "./callback-boundary.js";

const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const objectGetPrototypeOf = Object.getPrototypeOf;
const reflectApply = Reflect.apply;
const objectFreeze = Object.freeze;
const arrayIsArray = Array.isArray;
const numberIsSafeInteger = Number.isSafeInteger;
const dateGetTime = Function.prototype.call.bind(Date.prototype.getTime) as (value: Date) => number;

/** Maximum raw caller-key length accepted before it is HMAC'd. */
export const RATE_LIMIT_KEY_MAX_LENGTH = 512;
/** Maximum policy bucket label length. */
export const RATE_LIMIT_BUCKET_MAX_LENGTH = 128;
/** Maximum operations allowed in one bounded policy window. */
export const RATE_LIMIT_MAX_LIMIT = 1_000_000;
/** Maximum policy window and retry delay in seconds. */
export const RATE_LIMIT_MAX_WINDOW_SECONDS = 604_800;
/** Maximum number of in-memory caller/bucket entries retained. */
export const RATE_LIMIT_MAX_MEMORY_ENTRIES = 100_000;
const RATE_LIMIT_CLEANUP_BATCH = 256;

function freezePolicy(limit: number, windowSeconds: number, bucket: string): RateLimitPolicy {
  return objectFreeze({ limit, windowSeconds, bucket });
}

/** Signup issuance policy. */
export const SIGNUP_RATE_LIMIT_POLICY = freezePolicy(5, 3_600, "signup");
/** Per-client-IP login policy. */
export const LOGIN_IP_RATE_LIMIT_POLICY = freezePolicy(10, 900, "login:ip");
/** Per-identifier login policy. */
export const LOGIN_IDENTIFIER_RATE_LIMIT_POLICY = freezePolicy(10, 900, "login:identifier");
/** Password-recovery issuance policy. */
export const RECOVERY_RATE_LIMIT_POLICY = freezePolicy(5, 3_600, "recovery");
/** Confirmation/recovery resend policy. */
export const RESEND_RATE_LIMIT_POLICY = freezePolicy(3, 3_600, "resend");
/** OTP issuance policy. */
export const OTP_ISSUE_RATE_LIMIT_POLICY = freezePolicy(5, 900, "otp:issue");
/** OTP verification policy. */
export const OTP_VERIFY_RATE_LIMIT_POLICY = freezePolicy(5, 900, "otp:verify");
/** OAuth authorization-start policy. */
export const OAUTH_START_RATE_LIMIT_POLICY = freezePolicy(20, 900, "oauth:start");
/** Trusted/delegated administration mutation policy. */
export const ADMIN_MUTATION_RATE_LIMIT_POLICY = freezePolicy(60, 60, "admin:mutation");

/** All standard policies, frozen as a convenient inspection/configuration surface. */
export const RATE_LIMIT_POLICIES = objectFreeze({
  signup: SIGNUP_RATE_LIMIT_POLICY,
  loginIp: LOGIN_IP_RATE_LIMIT_POLICY,
  loginIdentifier: LOGIN_IDENTIFIER_RATE_LIMIT_POLICY,
  recovery: RECOVERY_RATE_LIMIT_POLICY,
  resend: RESEND_RATE_LIMIT_POLICY,
  otpIssue: OTP_ISSUE_RATE_LIMIT_POLICY,
  otpVerify: OTP_VERIFY_RATE_LIMIT_POLICY,
  oauthStart: OAUTH_START_RATE_LIMIT_POLICY,
  adminMutation: ADMIN_MUTATION_RATE_LIMIT_POLICY,
} as const);

type DataProperty =
  | { readonly valid: true; readonly present: false }
  | { readonly valid: true; readonly present: true; readonly value: unknown }
  | { readonly valid: false; readonly present: boolean };

function ownDataProperty(value: object, key: PropertyKey): DataProperty {
  try {
    const descriptor = objectGetOwnPropertyDescriptor(value, key);
    if (descriptor === undefined) return { valid: true, present: false };
    if (!("value" in descriptor)) return { valid: false, present: true };
    return { valid: true, present: true, value: descriptor.value };
  } catch {
    return { valid: false, present: false };
  }
}

function isPlainRecord(value: unknown): value is object {
  if (value === null || typeof value !== "object") return false;
  try {
    const prototype = objectGetPrototypeOf(value);
    return !arrayIsArray(value) && (prototype === Object.prototype || prototype === null);
  } catch {
    return false;
  }
}

function configurationFailure(message: string): AuthConfigurationError {
  return new AuthConfigurationError(message);
}

function validNow(clock: () => Date, label: string): Date {
  let value: Date;
  try {
    value = reflectApply(clock, undefined, []) as Date;
    const time = dateGetTime(value);
    if (!(value instanceof Date) || !Number.isFinite(time)) throw new Error("invalid clock");
  } catch {
    throw configurationFailure(`${label} must return a valid Date`);
  }
  return value;
}

function captureClock(options: object, label: string): () => Date {
  const property = ownDataProperty(options, "clock");
  if (!property.valid) throw configurationFailure(`${label} must be a data-property function`);
  const clock = property.present ? property.value : undefined;
  if (clock === undefined) return () => new Date();
  if (typeof clock !== "function") throw configurationFailure(`${label} must be a function`);
  const captured = clock as () => Date;
  validNow(captured, label);
  return captured;
}

function normalizeKey(value: unknown): string {
  if (typeof value !== "string" || value.length < 1 || value.length > RATE_LIMIT_KEY_MAX_LENGTH) {
    throw configurationFailure("rate-limit key is invalid");
  }
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code === 0 || code < 0x20 || code === 0x7f) {
      throw configurationFailure("rate-limit key is invalid");
    }
  }
  return value;
}

interface NormalizedPolicy {
  readonly limit: number;
  readonly windowSeconds: number;
  readonly bucket: string;
}

function normalizePolicy(value: unknown): NormalizedPolicy {
  if (!isPlainRecord(value)) throw configurationFailure("rate-limit policy must be a data record");
  const limitProperty = ownDataProperty(value, "limit");
  const windowProperty = ownDataProperty(value, "windowSeconds");
  const bucketProperty = ownDataProperty(value, "bucket");
  if (!limitProperty.valid || !limitProperty.present || !windowProperty.valid || !windowProperty.present || !bucketProperty.valid) {
    throw configurationFailure("rate-limit policy must contain data properties");
  }
  const limit = limitProperty.value;
  const windowSeconds = windowProperty.value;
  const bucketValue = bucketProperty.present ? bucketProperty.value : undefined;
  const bucket = bucketValue === undefined ? "default" : bucketValue;
  if (
    typeof limit !== "number" || !numberIsSafeInteger(limit) || limit < 1 || limit > RATE_LIMIT_MAX_LIMIT
    || typeof windowSeconds !== "number" || !numberIsSafeInteger(windowSeconds)
    || windowSeconds < 1 || windowSeconds > RATE_LIMIT_MAX_WINDOW_SECONDS
  ) {
    throw configurationFailure("rate-limit policy is invalid");
  }
  if (typeof bucket !== "string" || bucket.length < 1 || bucket.length > RATE_LIMIT_BUCKET_MAX_LENGTH || bucket !== bucket.trim()) {
    throw configurationFailure("rate-limit policy bucket is invalid");
  }
  for (let index = 0; index < bucket.length; index += 1) {
    const code = bucket.charCodeAt(index);
    if (code === 0 || code < 0x20 || code === 0x7f) throw configurationFailure("rate-limit policy bucket is invalid");
  }
  return objectFreeze({ limit, windowSeconds, bucket });
}

function boundedRetryAfter(windowEndMs: number, nowMs: number, windowSeconds: number): number {
  const seconds = Math.ceil(Math.max(0, windowEndMs - nowMs) / 1_000);
  return Math.max(1, Math.min(windowSeconds, Math.min(RATE_LIMIT_MAX_WINDOW_SECONDS, seconds)));
}

function decision(
  allowed: boolean,
  remaining: number,
  retryAfterSeconds?: number,
): RateLimitDecision {
  return objectFreeze({
    allowed,
    remaining,
    ...(retryAfterSeconds === undefined ? {} : { retryAfterSeconds }),
  });
}

interface MemoryBucket {
  windowEndMs: number;
  count: number;
}

/** Options for the process-local limiter intended for tests and one-process deployments. */
export interface InMemoryRateLimiterOptions {
  readonly clock?: () => Date;
  readonly maxEntries?: number;
}

/** A bounded, synchronous-in-operation, process-local implementation of RateLimiter. */
export class InMemoryRateLimiter implements RateLimiter {
  private readonly clock: () => Date;
  private readonly maxEntries: number;
  private readonly buckets = new Map<string, MemoryBucket>();

  constructor(options: InMemoryRateLimiterOptions = {}) {
    if (!isPlainRecord(options)) throw configurationFailure("in-memory rate limiter options must be a data record");
    this.clock = captureClock(options, "in-memory rate limiter clock");
    const maxEntriesProperty = ownDataProperty(options, "maxEntries");
    if (!maxEntriesProperty.valid) throw configurationFailure("in-memory rate limiter maxEntries must be a data property");
    const maxEntries = maxEntriesProperty.present ? maxEntriesProperty.value : RATE_LIMIT_MAX_MEMORY_ENTRIES;
    if (typeof maxEntries !== "number" || !numberIsSafeInteger(maxEntries) || maxEntries < 1 || maxEntries > RATE_LIMIT_MAX_MEMORY_ENTRIES) {
      throw configurationFailure("in-memory rate limiter maxEntries is invalid");
    }
    this.maxEntries = maxEntries;
  }

  async consume(keyValue: string, policyValue: RateLimitPolicy): Promise<RateLimitDecision> {
    const key = normalizeKey(keyValue);
    const policy = normalizePolicy(policyValue);
    const now = validNow(this.clock, "in-memory rate limiter clock");
    const nowMs = dateGetTime(now);
    const windowMs = policy.windowSeconds * 1_000;
    const windowEndMs = (Math.floor(nowMs / windowMs) + 1) * windowMs;
    const mapKey = `${policy.bucket}\u0000${key}`;
    const current = this.buckets.get(mapKey);

    if (current !== undefined && current.windowEndMs > nowMs) {
      if (current.count >= policy.limit) {
        return decision(false, 0, boundedRetryAfter(current.windowEndMs, nowMs, policy.windowSeconds));
      }
      current.count += 1;
      return decision(true, policy.limit - current.count);
    }

    for (const [entryKey, entry] of this.buckets) {
      if (entry.windowEndMs <= nowMs) this.buckets.delete(entryKey);
    }
    if (this.buckets.size >= this.maxEntries) {
      return decision(false, 0, policy.windowSeconds);
    }
    this.buckets.set(mapKey, { windowEndMs, count: 1 });
    return decision(true, policy.limit - 1);
  }
}

/** Minimal project-owned query boundary accepted by PostgresRateLimiter. */
export interface RateLimitQueryExecutor {
  query<Row extends object = Record<string, unknown>>(
    sql: string,
    values?: readonly unknown[],
  ): Promise<{ readonly rows: readonly Row[] }>;
}

/** Options for the durable PostgreSQL limiter; it never creates a pool or reads a connection string. */
export interface PostgresRateLimiterOptions {
  readonly pool: RateLimitQueryExecutor;
  /** Distinct project-owned 32-byte HMAC key; only its derived digests reach PostgreSQL. */
  readonly hmacKey: Uint8Array;
}

function findDataMethod(value: object, name: string): (...args: unknown[]) => unknown {
  let current: object | null = value;
  try {
    while (current !== null) {
      const descriptor = objectGetOwnPropertyDescriptor(current, name);
      if (descriptor !== undefined) {
        if (!("value" in descriptor) || typeof descriptor.value !== "function") {
          throw configurationFailure(`rate-limit database ${name} must be a data-property function`);
        }
        return descriptor.value as (...args: unknown[]) => unknown;
      }
      current = objectGetPrototypeOf(current);
    }
  } catch (error) {
    if (error instanceof AuthConfigurationError) throw error;
    throw configurationFailure("rate-limit database adapter is invalid");
  }
  throw configurationFailure(`rate-limit database ${name} is unavailable`);
}

function rowDataProperty(row: object, name: string): DataProperty {
  return ownDataProperty(row, name);
}

/** PostgreSQL-backed limiter using one atomic statement and database-authoritative time. */
export class PostgresRateLimiter implements RateLimiter {
  private readonly pool: object;
  private readonly query: (...args: unknown[]) => unknown;
  private readonly hmacKey: Uint8Array;

  constructor(options: PostgresRateLimiterOptions) {
    if (!isPlainRecord(options)) throw configurationFailure("PostgreSQL rate limiter options must be a data record");
    const poolProperty = ownDataProperty(options, "pool");
    if (!poolProperty.valid || !poolProperty.present || poolProperty.value === null || typeof poolProperty.value !== "object") {
      throw configurationFailure("PostgreSQL rate limiter pool is invalid");
    }
    this.pool = poolProperty.value;
    this.query = findDataMethod(this.pool, "query");
    const keyProperty = ownDataProperty(options, "hmacKey");
    if (!keyProperty.valid || !keyProperty.present) throw configurationFailure("PostgreSQL rate limiter hmacKey is required");
    this.hmacKey = captureBoundaryBytes(keyProperty.value, "PostgreSQL rate limiter hmacKey");
    if (this.hmacKey.byteLength !== 32) throw configurationFailure("PostgreSQL rate limiter hmacKey must contain exactly 32 bytes");
  }

  async consume(keyValue: string, policyValue: RateLimitPolicy): Promise<RateLimitDecision> {
    const key = normalizeKey(keyValue);
    const policy = normalizePolicy(policyValue);
    const digest = createHmac("sha256", this.hmacKey).update(key, "utf8").digest();
    const sql = `
      WITH database_now AS (
        SELECT clock_timestamp() AS now
      ), expired AS (
        DELETE FROM auth.rate_limit_buckets AS stale
         USING database_now
         WHERE stale.window_end <= database_now.now
           AND stale.ctid IN (
             SELECT candidate.ctid
               FROM auth.rate_limit_buckets AS candidate
              WHERE candidate.window_end <= database_now.now
              ORDER BY candidate.window_end
              LIMIT ${RATE_LIMIT_CLEANUP_BATCH}
           )
      ), current_window AS (
        SELECT database_now.now,
               date_bin(make_interval(secs => $3::double precision), database_now.now, timestamptz 'epoch') AS window_start
          FROM database_now
      ), window_definition AS (
        SELECT now,
               window_start,
               window_start + make_interval(secs => $3::double precision) AS window_end
          FROM current_window
      ), attempt AS (
        INSERT INTO auth.rate_limit_buckets
          (key_digest, bucket, window_start, window_end, count, created_at, updated_at)
        SELECT $1::bytea, $2::text, window_start, window_end, 1, now, now
          FROM window_definition
        ON CONFLICT (key_digest, bucket, window_start)
        DO UPDATE SET count = auth.rate_limit_buckets.count + 1,
                      updated_at = EXCLUDED.updated_at
              WHERE auth.rate_limit_buckets.count < $4::integer
        RETURNING count, window_end
      )
      SELECT (attempt.count IS NOT NULL) AS allowed,
             CASE WHEN attempt.count IS NULL THEN 0 ELSE $4::integer - attempt.count END AS remaining,
             CASE WHEN attempt.count IS NULL
                  THEN LEAST($3::integer, GREATEST(1, CEIL(EXTRACT(EPOCH FROM (window_definition.window_end - window_definition.now)))::integer))
                  ELSE NULL::integer
             END AS retry_after_seconds
        FROM window_definition
        LEFT JOIN attempt ON true`;

    let rawResult: unknown;
    try {
      rawResult = await reflectApply(this.query, this.pool, [sql, [digest, policy.bucket, policy.windowSeconds, policy.limit]]);
    } catch {
      throw configurationFailure("rate-limit database operation failed");
    }
    if (rawResult === null || typeof rawResult !== "object") throw configurationFailure("rate-limit database result is invalid");
    const rowsProperty = ownDataProperty(rawResult, "rows");
    if (!rowsProperty.valid || !rowsProperty.present || !arrayIsArray(rowsProperty.value) || rowsProperty.value.length !== 1) {
      throw configurationFailure("rate-limit database decision is invalid");
    }
    const row = rowsProperty.value[0];
    if (row === null || typeof row !== "object" || arrayIsArray(row)) throw configurationFailure("rate-limit database decision is invalid");
    const allowedProperty = rowDataProperty(row, "allowed");
    const remainingProperty = rowDataProperty(row, "remaining");
    const retryProperty = rowDataProperty(row, "retry_after_seconds");
    if (!allowedProperty.valid || !allowedProperty.present || typeof allowedProperty.value !== "boolean"
      || !remainingProperty.valid || !remainingProperty.present || typeof remainingProperty.value !== "number"
      || !numberIsSafeInteger(remainingProperty.value) || remainingProperty.value < 0 || remainingProperty.value > policy.limit
      || !retryProperty.valid || !retryProperty.present
      || (retryProperty.value !== null && (typeof retryProperty.value !== "number"
        || !numberIsSafeInteger(retryProperty.value) || retryProperty.value < 1
        || retryProperty.value > policy.windowSeconds))) {
      throw configurationFailure("rate-limit database decision is invalid");
    }
    if (allowedProperty.value && retryProperty.value !== null) throw configurationFailure("rate-limit database decision is invalid");
    if (!allowedProperty.value && retryProperty.value === null) throw configurationFailure("rate-limit database decision is invalid");
    return decision(
      allowedProperty.value,
      remainingProperty.value,
      retryProperty.value === null ? undefined : retryProperty.value,
    );
  }
}
