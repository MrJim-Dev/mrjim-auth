import { AuthConfigurationError, AuthProgrammingError } from "../shared/errors.js";
import {
  safeArrayIsArray,
  safeDefineArrayValue,
  safeDefineData,
  safeGetPrototypeOf,
  safeOwnDataEntries,
  safeOwnDataProperty,
  safeObjectPrototype,
  safeStringTrim,
} from "../shared/safe-intrinsics.js";

const boundaryObject = Object;
const boundaryObjectDefineProperty = Object.defineProperty;
const boundaryObjectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const boundaryObjectGetOwnPropertyNames = Object.getOwnPropertyNames;
const boundaryObjectGetOwnPropertySymbols = Object.getOwnPropertySymbols;
const boundaryObjectGetPrototypeOf = Object.getPrototypeOf;
const boundaryObjectFreeze = Object.freeze;
const boundaryObjectHasOwnProperty = Object.prototype.hasOwnProperty;
const boundaryObjectCreate = Object.create;
const boundaryReflectApply = Reflect.apply;
const boundaryArray = Array;
const boundaryArrayIsArray = Array.isArray;
const boundaryArrayPush = Array.prototype.push;
const boundaryNumberIsFinite = Number.isFinite;
const boundaryNumberIsSafeInteger = Number.isSafeInteger;
const boundarySetAdd = Set.prototype.add;
const boundarySetHas = Set.prototype.has;
const boundaryPromise = Promise;
const boundaryPromisePrototype = Promise.prototype;
const boundaryPromiseThen = Promise.prototype.then;
const boundaryJsonParse = JSON.parse;
const boundaryJsonStringify = JSON.stringify;
const boundaryString = String;

export const MAX_CLIENT_STRING = 16_384;
export const MAX_CLIENT_KEYS = 100_000;
export const MAX_CLIENT_DEPTH = 32;
export const MAX_CLIENT_BODY_BYTES = 1024 * 1024;

export type BoundaryResult<T> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false };

export type OwnDataResult =
  { readonly ok: boolean; readonly present: boolean; readonly value: unknown };

export function ownData(value: object, key: PropertyKey): OwnDataResult {
  const property = safeOwnDataProperty(value, key);
  if (!property.valid) return { ok: false, present: true, value: undefined };
  return property.present
    ? { ok: true, present: true, value: property.value }
    : { ok: true, present: false, value: undefined };
}

export function hasOwnData(value: object, key: PropertyKey): boolean {
  const property = ownData(value, key);
  return property.ok && property.present;
}

export function requireOwnData<T>(value: object, key: PropertyKey, label: string): T {
  const property = ownData(value, key);
  if (!property.ok || !property.present) throw new AuthProgrammingError(`${label} is malformed`);
  return property.value as T;
}

export function isObjectLike(value: unknown): value is object {
  return value !== null && (typeof value === "object" || typeof value === "function");
}

export function assertObject(value: unknown, label: string): asserts value is object {
  if (!isObjectLike(value) || safeArrayIsArray(value)) {
    throw new AuthProgrammingError(`${label} must be an object`);
  }
}

export function assertConfigurationObject(value: unknown, label: string): asserts value is object {
  if (!isObjectLike(value) || safeArrayIsArray(value)) {
    throw new AuthConfigurationError(`${label} must be an object`);
  }
  const prototype = safeGetPrototypeOf(value);
  if (prototype === undefined) throw new AuthConfigurationError(`${label} is inaccessible`);
}

export function captureMethod(
  target: object,
  key: PropertyKey,
  label: string,
  error: "configuration" | "programming" = "programming",
): { readonly receiver: object; readonly method: Function } {
  let current: object | null | undefined = target;
  for (let depth = 0; current !== null && current !== undefined && depth < 32; depth += 1) {
    let descriptor: PropertyDescriptor | undefined;
    try {
      descriptor = boundaryObjectGetOwnPropertyDescriptor(current, key);
    } catch {
      throw error === "configuration"
        ? new AuthConfigurationError(`${label} is inaccessible`)
        : new AuthProgrammingError(`${label} is inaccessible`);
    }
    if (descriptor !== undefined) {
      if (!boundaryReflectApply(boundaryObjectHasOwnProperty, descriptor, ["value"]) || typeof descriptor.value !== "function") {
        throw error === "configuration"
          ? new AuthConfigurationError(`${label} must be a data method`)
          : new AuthProgrammingError(`${label} must be a data method`);
      }
      return { receiver: target, method: descriptor.value };
    }
    try {
      current = boundaryObjectGetPrototypeOf(current);
    } catch {
      throw error === "configuration"
        ? new AuthConfigurationError(`${label} is inaccessible`)
        : new AuthProgrammingError(`${label} is inaccessible`);
    }
  }
  throw error === "configuration"
    ? new AuthConfigurationError(`${label} is unavailable`)
    : new AuthProgrammingError(`${label} is unavailable`);
}

export function invoke<T>(method: Function, receiver: unknown, args: readonly unknown[] = []): T {
  return boundaryReflectApply(method, receiver, args as unknown[]) as T;
}

function isPlainObject(value: object): boolean {
  const prototype = safeGetPrototypeOf(value);
  return prototype === safeObjectPrototype || prototype === null;
}

function ownNames(value: object): readonly string[] | null {
  try {
    const names = boundaryObjectGetOwnPropertyNames(value);
    const symbols = boundaryObjectGetOwnPropertySymbols(value);
    if (symbols.length !== 0 || names.length > MAX_CLIENT_KEYS) return null;
    return names;
  } catch {
    return null;
  }
}

function putRecordValue(target: Record<string, unknown>, key: string, value: unknown): boolean {
  return safeDefineData(target, key, value);
}

function putArrayValue<T>(target: T[], index: number, value: T): boolean {
  return safeDefineArrayValue(target, index, value);
}

function snapshotInternal(
  value: unknown,
  seen: Set<object>,
  depth: number,
  keyBudget: { value: number },
): BoundaryResult<unknown> {
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    if (typeof value === "string" && value.length > MAX_CLIENT_STRING) return { ok: false };
    return { ok: true, value };
  }
  if (typeof value === "number") {
    return boundaryNumberIsFinite(value) ? { ok: true, value } : { ok: false };
  }
  if (!isObjectLike(value) || depth > MAX_CLIENT_DEPTH || boundaryReflectApply(boundarySetHas, seen, [value])) return { ok: false };
  boundaryReflectApply(boundarySetAdd, seen, [value]);

  if (boundaryArrayIsArray(value)) {
    const length = ownData(value, "length");
    if (!length.ok || !length.present || typeof length.value !== "number" || !boundaryNumberIsSafeInteger(length.value) || length.value < 0 || length.value > MAX_CLIENT_KEYS) return { ok: false };
    const names = ownNames(value);
    if (names === null || names.length !== length.value + 1) return { ok: false };
    const output: unknown[] = new boundaryArray(length.value);
    for (let index = 0; index < length.value; index += 1) {
      keyBudget.value += 1;
      if (keyBudget.value > MAX_CLIENT_KEYS) return { ok: false };
      const property = ownData(value, `${index}`);
      if (!property.ok || !property.present) return { ok: false };
      const nested = snapshotInternal(property.value, seen, depth + 1, keyBudget);
      if (!nested.ok || !putArrayValue(output, index, nested.value)) return { ok: false };
    }
    return { ok: true, value: boundaryObjectFreeze(output) };
  }

  if (!isPlainObject(value)) return { ok: false };
  const names = ownNames(value);
  if (names === null) return { ok: false };
  const output = {} as Record<string, unknown>;
  for (let index = 0; index < names.length; index += 1) {
    const key = names[index];
    if (key === undefined) return { ok: false };
    keyBudget.value += 1;
    if (keyBudget.value > MAX_CLIENT_KEYS) return { ok: false };
    const property = ownData(value, key);
    if (!property.ok || !property.present) return { ok: false };
    const nested = snapshotInternal(property.value, seen, depth + 1, keyBudget);
    if (!nested.ok || !putRecordValue(output, key, nested.value)) return { ok: false };
  }
  return { ok: true, value: boundaryObjectFreeze(output) };
}

export function snapshotJson(value: unknown, label: string): unknown {
  const result = snapshotInternal(value, new Set<object>(), 0, { value: 0 });
  if (!result.ok) throw new AuthProgrammingError(`${label} is malformed`);
  return result.value;
}

export function trySnapshotJson(value: unknown): BoundaryResult<unknown> {
  return snapshotInternal(value, new Set<object>(), 0, { value: 0 });
}

export function parseJson(value: string, label: string): unknown {
  if (value.length > MAX_CLIENT_BODY_BYTES) throw new AuthProgrammingError(`${label} is oversized`);
  let parsed: unknown;
  try {
    parsed = boundaryJsonParse(value);
  } catch {
    throw new AuthProgrammingError(`${label} is malformed`);
  }
  return snapshotJson(parsed, label);
}

export function stringifyJson(value: unknown, label: string): string {
  try {
    const output = boundaryJsonStringify(value);
    if (typeof output !== "string" || output.length > MAX_CLIENT_BODY_BYTES) throw new Error("oversized");
    return output;
  } catch {
    throw new AuthProgrammingError(`${label} is malformed`);
  }
}

export function hasThenProperty(value: object): boolean {
  let current: object | null | undefined = value;
  for (let depth = 0; current !== null && current !== undefined && depth < 16; depth += 1) {
    let descriptor: PropertyDescriptor | undefined;
    try {
      descriptor = boundaryObjectGetOwnPropertyDescriptor(current, "then");
    } catch {
      return true;
    }
    if (descriptor !== undefined) return true;
    try {
      current = boundaryObjectGetPrototypeOf(current);
    } catch {
      return true;
    }
  }
  return current !== null;
}

function isNativePromise(value: unknown): value is Promise<unknown> {
  if (!isObjectLike(value)) return false;
  try {
    return boundaryObjectGetPrototypeOf(value) === boundaryPromisePrototype
      && boundaryObjectGetOwnPropertyDescriptor(value, "then") === undefined;
  } catch {
    return false;
  }
}

/** Resolves only intrinsic native promises; arbitrary thenables fail closed. */
export async function awaitSafe<T>(value: T | Promise<T>, label: string): Promise<T> {
  if (!isObjectLike(value)) return value as T;
  if (!isNativePromise(value)) {
    if (hasThenProperty(value)) throw new AuthProgrammingError(`${label} returned an invalid thenable`);
    return value as T;
  }
  try {
    return await boundaryReflectApply(boundaryPromiseThen, value, []) as T;
  } catch {
    throw new AuthProgrammingError(`${label} failed`);
  }
}

export function trimString(value: unknown, label: string, maximum = MAX_CLIENT_STRING): string {
  if (typeof value !== "string" || value.length === 0 || value.length > maximum) {
    throw new AuthProgrammingError(`${label} is malformed`);
  }
  const trimmed = safeStringTrim(value);
  if (trimmed === null || trimmed !== value || trimmed.length === 0) {
    throw new AuthProgrammingError(`${label} is malformed`);
  }
  return trimmed;
}

export function isSafeString(value: unknown, maximum = MAX_CLIENT_STRING): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= maximum && safeStringTrim(value) === value;
}

export function objectKeys(value: object): readonly string[] {
  const entries = safeOwnDataEntries(value, MAX_CLIENT_KEYS);
  if (entries === null) throw new AuthProgrammingError("object is malformed");
  const keys: string[] = [];
  for (let index = 0; index < entries.length; index += 1) {
    const entry = entries[index];
    if (entry === undefined) throw new AuthProgrammingError("object is malformed");
    boundaryReflectApply(boundaryArrayPush, keys, [entry[0]]);
  }
  return keys;
}

export function createNullRecord(): Record<string, unknown> {
  return boundaryObjectCreate(null) as Record<string, unknown>;
}

export function freeze<T>(value: T): Readonly<T> {
  return boundaryObjectFreeze(value);
}
