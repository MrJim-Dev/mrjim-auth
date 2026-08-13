import argon2 from "argon2";
import bcrypt from "bcryptjs";
import { AuthApiError, AuthConfigurationError } from "../shared/errors.js";
import {
  assertBoundaryObject,
  optionalBoundaryOption,
} from "./callback-boundary.js";
import { safeNumberIsSafeInteger, safeStringReplace } from "../shared/safe-intrinsics.js";

/** The minimum Argon2id password policy required by the auth schema. */
export const ARGON2ID_PASSWORD_POLICY = Object.freeze({
  memoryCost: 64 * 1024,
  timeCost: 3,
  parallelism: 1,
  version: 19,
  type: argon2.argon2id,
} as const);

const DUMMY_PASSWORD_HASH =
  "$argon2id$v=19$m=65536,t=3,p=1$CZkVMQPqPBYxj8mD1te76w$nxfqv7qdqAz+cacdCnL/AmlBR68JuZ9zyXYqVFf6Puw";

// These are parser safety limits, not the password-policy floor. A valid
// weaker hash may still be verified and rehashed; attacker-controlled costs
// above these bounds must take the fixed dummy path instead.
const MAX_VERIFIABLE_MEMORY_COST = 256 * 1024;
const MAX_VERIFIABLE_TIME_COST = 10;

const BCRYPT_HASH_PATTERN = /^\$2[aby]\$(\d{2})\$[./A-Za-z0-9]{53}$/u;

export interface PasswordPolicy {
  readonly memoryCost?: number;
  readonly timeCost?: number;
  readonly parallelism?: number;
  readonly version?: number;
}

export interface PasswordVerification {
  readonly valid: boolean;
  readonly needsRehash: boolean;
}

/** Returns whether a hash is a legacy bcrypt credential accepted only for migration. */
export function isLegacyBcryptHash(encodedHash: unknown): boolean {
  return typeof encodedHash === "string" && BCRYPT_HASH_PATTERN.test(encodedHash);
}

function validatePassword(password: unknown): asserts password is string {
  if (typeof password !== "string") {
    throw new AuthApiError("invalid_request", 400, "Invalid password");
  }
  const bytes = new TextEncoder().encode(password).byteLength;
  if (password.length < 8 || bytes > 1024) {
    throw new AuthApiError("invalid_request", 400, "Invalid password");
  }
}
function validPhcBase64(value: string, minimumBytes: number, maximumBytes: number): boolean {
  if (!/^[A-Za-z0-9+/]+={0,2}$/u.test(value)) return false;
  const unpadded = safeStringReplace(value, /=+$/u, "");
  if (unpadded === null) return false;
  const decoded = Buffer.from(value, "base64");
  if (decoded.byteLength < minimumBytes || decoded.byteLength > maximumBytes) return false;
  const canonical = safeStringReplace(decoded.toString("base64"), /=+$/u, "");
  return canonical !== null && canonical === unpadded;
}

function parseParams(encodedHash: string): { memoryCost: number; timeCost: number; parallelism: number; version: number } | null {
  const match = /^\$argon2id\$v=(\d+)\$m=(\d+),t=(\d+),p=(\d+)\$([A-Za-z0-9+/]+={0,2})\$([A-Za-z0-9+/]+={0,2})$/u.exec(encodedHash);
  if (match === null) return null;
  const salt = match[5];
  const hash = match[6];
  if (salt === undefined || hash === undefined) return null;
  const version = Number(match[1]);
  const memoryCost = Number(match[2]);
  const timeCost = Number(match[3]);
  const parallelism = Number(match[4]);
  if (
    !safeNumberIsSafeInteger(version) ||
    !safeNumberIsSafeInteger(memoryCost) ||
    !safeNumberIsSafeInteger(timeCost) ||
    !safeNumberIsSafeInteger(parallelism)
  ) return null;
  if (
    version !== ARGON2ID_PASSWORD_POLICY.version ||
    memoryCost < 8 ||
    memoryCost > MAX_VERIFIABLE_MEMORY_COST ||
    timeCost < 1 ||
    timeCost > MAX_VERIFIABLE_TIME_COST ||
    parallelism !== ARGON2ID_PASSWORD_POLICY.parallelism ||
    !validPhcBase64(salt, 8, 64) ||
    !validPhcBase64(hash, 4, 1024)
  ) return null;
  return { version, memoryCost, timeCost, parallelism };
}

function normalizedPolicy(policy: PasswordPolicy = {}): Required<PasswordPolicy> {
  if (policy === null || typeof policy !== "object") {
    throw new AuthConfigurationError("password policy must be an object");
  }
  const source = policy as unknown as object;
  assertBoundaryObject(source, "password policy");
  const memoryCost = optionalBoundaryOption(source, "memoryCost", "password policy memory cost") as number | undefined;
  const timeCost = optionalBoundaryOption(source, "timeCost", "password policy time cost") as number | undefined;
  const parallelism = optionalBoundaryOption(source, "parallelism", "password policy parallelism") as number | undefined;
  const version = optionalBoundaryOption(source, "version", "password policy version") as number | undefined;
  const result = {
    memoryCost: memoryCost ?? ARGON2ID_PASSWORD_POLICY.memoryCost,
    timeCost: timeCost ?? ARGON2ID_PASSWORD_POLICY.timeCost,
    parallelism: parallelism ?? ARGON2ID_PASSWORD_POLICY.parallelism,
    version: version ?? ARGON2ID_PASSWORD_POLICY.version,
  };
  if (
    !safeNumberIsSafeInteger(result.memoryCost) ||
    result.memoryCost < ARGON2ID_PASSWORD_POLICY.memoryCost ||
    !safeNumberIsSafeInteger(result.timeCost) ||
    result.timeCost < ARGON2ID_PASSWORD_POLICY.timeCost ||
    !safeNumberIsSafeInteger(result.parallelism) ||
    result.parallelism !== ARGON2ID_PASSWORD_POLICY.parallelism ||
    result.version !== ARGON2ID_PASSWORD_POLICY.version
  ) {
    throw new AuthConfigurationError("password policy is below the Argon2id security floor");
  }
  return result;
}

/** Returns whether an encoded password uses the required Argon2id family and floor. */
export function isStrongArgon2idHash(encodedHash: unknown, policy: PasswordPolicy = {}): boolean {
  if (typeof encodedHash !== "string") return false;
  const params = parseParams(encodedHash);
  if (params === null) return false;
  const required = normalizedPolicy(policy);
  return (
    params.version === required.version &&
    params.memoryCost >= required.memoryCost &&
    params.timeCost >= required.timeCost &&
    params.parallelism === required.parallelism
  );
}

/** Hashes a password with Argon2id and the configured minimum policy. */
export async function hashPassword(password: string, policy: PasswordPolicy = {}): Promise<string> {
  validatePassword(password);
  const parameters = normalizedPolicy(policy);
  return argon2.hash(password, {
    type: argon2.argon2id,
    memoryCost: parameters.memoryCost,
    timeCost: parameters.timeCost,
    parallelism: parameters.parallelism,
    version: parameters.version,
  });
}

/** Verifies a password; an unknown hash still performs the dummy Argon2id work. */
export async function verifyPassword(
  password: string,
  encodedHash: string | null | undefined,
  policy: PasswordPolicy = {},
): Promise<PasswordVerification> {
  validatePassword(password);
  const required = normalizedPolicy(policy);
  const knownArgonHash = typeof encodedHash === "string" && parseParams(encodedHash) !== null;
  const knownBcryptHash = isLegacyBcryptHash(encodedHash);
  if (knownBcryptHash) {
    let valid = false;
    try {
      valid = await bcrypt.compare(password, encodedHash as string);
    } catch {
      valid = false;
    }
    return { valid, needsRehash: valid };
  }
  const hash = knownArgonHash ? encodedHash : DUMMY_PASSWORD_HASH;
  let valid = false;
  try {
    valid = await argon2.verify(hash, password);
  } catch {
    valid = false;
  }
  return {
    valid: knownArgonHash && valid,
    needsRehash: knownArgonHash && valid && !isStrongArgon2idHash(hash, required),
  };
}

/** Server-only password hashing and verification service. */
export class PasswordService {
  readonly policy: Required<PasswordPolicy>;

  constructor(policy: PasswordPolicy = {}) {
    this.policy = normalizedPolicy(policy);
  }

  hashPassword(password: string, policy?: PasswordPolicy): Promise<string> {
    return hashPassword(password, policy ?? this.policy);
  }

  hash(password: string, policy?: PasswordPolicy): Promise<string> {
    return this.hashPassword(password, policy);
  }

  verifyPassword(password: string, encodedHash: string | null | undefined): Promise<PasswordVerification> {
    return verifyPassword(password, encodedHash, this.policy);
  }

  verify(password: string, encodedHash: string | null | undefined): Promise<PasswordVerification> {
    return this.verifyPassword(password, encodedHash);
  }

  needsRehash(encodedHash: string): boolean {
    return !isStrongArgon2idHash(encodedHash, this.policy);
  }
}
