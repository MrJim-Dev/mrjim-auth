import type { AuthRepository, KeyMaterial, KeyProvider } from "../shared/contracts.js";
import { AuthConfigurationError } from "../shared/errors.js";

/*
 * These are captured once, before any configured adapter or caller value is
 * inspected. Construction code below never dispatches through mutable global
 * collection methods or ordinary properties of caller-owned collections.
 */
const boundaryArrayConstructor = Array;
const boundaryArrayIsArray = Array.isArray;
const boundaryArraySort = Array.prototype.sort;
const boundaryMapConstructor = Map;
const boundaryMapEntries = Map.prototype.entries;
const boundaryMapGet = Map.prototype.get;
const boundaryMapHas = Map.prototype.has;
const boundaryMapSet = Map.prototype.set;
const boundarySetConstructor = Set;
const boundarySetHas = Set.prototype.has;
const boundarySetAdd = Set.prototype.add;
const boundaryObjectCreate = Object.create;
const boundaryObjectDefineProperty = Object.defineProperty;
const boundaryObjectFreeze = Object.freeze;
const boundaryObjectPrototype = Object.prototype;
const boundaryObjectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const boundaryObjectGetOwnPropertyNames = Object.getOwnPropertyNames;
const boundaryObjectGetOwnPropertySymbols = Object.getOwnPropertySymbols;
const boundaryObjectGetPrototypeOf = Object.getPrototypeOf;
const boundaryReflectApply = Reflect.apply;
const boundaryNumber = Number;
const boundaryNumberIsFinite = Number.isFinite;
const boundaryNumberIsSafeInteger = Number.isSafeInteger;
const boundaryString = String;
const boundaryPromise = Promise;
const boundaryPromisePrototype = Promise.prototype;
const boundaryUint8Array = Uint8Array;
const boundaryTypedArrayPrototype = boundaryObjectGetPrototypeOf(boundaryUint8Array.prototype);
const boundaryTypedArrayByteLengthGetter = (() => {
  const descriptor = boundaryObjectGetOwnPropertyDescriptor(boundaryTypedArrayPrototype, "byteLength");
  if (descriptor === undefined || typeof descriptor.get !== "function") {
    throw new AuthConfigurationError("required typed-array byte-length getter is unavailable");
  }
  return descriptor.get;
})();
const boundaryTypedArraySet = (() => {
  const descriptor = boundaryObjectGetOwnPropertyDescriptor(boundaryTypedArrayPrototype, "set");
  if (descriptor === undefined || typeof descriptor.value !== "function") {
    throw new AuthConfigurationError("required typed-array set method is unavailable");
  }
  return descriptor.value;
})();
const boundaryTypedArrayTagGetter = (() => {
  const descriptor = boundaryObjectGetOwnPropertyDescriptor(boundaryTypedArrayPrototype, Symbol.toStringTag);
  if (descriptor === undefined || typeof descriptor.get !== "function") {
    throw new AuthConfigurationError("required typed-array tag getter is unavailable");
  }
  return descriptor.get;
})();
const boundaryMapIteratorNext = (() => {
  const iterator = boundaryReflectApply(boundaryMapEntries, new boundaryMapConstructor(), []) as object;
  const prototype = boundaryObjectGetPrototypeOf(iterator);
  if (prototype === null) throw new AuthConfigurationError("required map iterator is unavailable");
  const descriptor = boundaryObjectGetOwnPropertyDescriptor(prototype, "next");
  if (descriptor === undefined || typeof descriptor.value !== "function") {
    throw new AuthConfigurationError("required map iterator is unavailable");
  }
  return descriptor.value;
})();
const MAX_PROTOTYPE_DEPTH = 32;
const MAX_BOUNDARY_COLLECTION_LENGTH = 100_000;
const MAX_BOUNDARY_VALUE_DEPTH = 32;

function configFailure(label: string): never {
  throw new AuthConfigurationError(label);
}

function safeOwnPropertyNames(value: object, label: string): string[] {
  try {
    return boundaryObjectGetOwnPropertyNames(value);
  } catch {
    return configFailure(`${label} must be a data collection`);
  }
}

function safeOwnPropertySymbols(value: object, label: string): symbol[] {
  try {
    return boundaryObjectGetOwnPropertySymbols(value);
  } catch {
    return configFailure(`${label} must be a data collection`);
  }
}

/** Safely classifies an array without allowing a revoked proxy to escape. */
export function boundaryIsArray(value: unknown, label: string): boolean {
  try {
    return boundaryArrayIsArray(value);
  } catch {
    return configFailure(`${label} must be a data array`);
  }
}

/** Safely classifies a Map without invoking caller-defined methods. */
export function boundaryIsMap(value: unknown, label: string): boolean {
  if (value === null || (typeof value !== "object" && typeof value !== "function")) return false;
  try {
    return value instanceof boundaryMapConstructor;
  } catch {
    return configFailure(`${label} must be a data map`);
  }
}

/** Creates a map through the captured constructor and methods. */
export function createBoundaryMap<K, V>(): Map<K, V> {
  return new boundaryMapConstructor<K, V>();
}

/** Reads an internally captured Map without dispatching through its prototype. */
export function boundaryMapHasValue<K, V>(map: ReadonlyMap<K, V>, key: K, label: string): boolean {
  try {
    return boundaryReflectApply(boundaryMapHas, map, [key]);
  } catch {
    return configFailure(`${label} must be a data map`);
  }
}

/** Writes an internally captured Map without dispatching through its prototype. */
export function boundaryMapSetValue<K, V>(map: Map<K, V>, key: K, value: V, label: string): void {
  try {
    boundaryReflectApply(boundaryMapSet, map, [key, value]);
  } catch {
    configFailure(`${label} must be a data map`);
  }
}

/** Reads an internally captured Map value without its mutable prototype. */
export function boundaryMapGetValue<K, V>(map: ReadonlyMap<K, V>, key: K, label: string): V | undefined {
  try {
    return boundaryReflectApply(boundaryMapGet, map, [key]) as V | undefined;
  } catch {
    return configFailure(`${label} must be a data map`);
  }
}

/** A descriptor-only snapshot used by server construction boundaries. */
export type BoundaryDataProperty =
  | { readonly valid: true; readonly present: false }
  | { readonly valid: true; readonly present: true; readonly value: unknown }
  | { readonly valid: false; readonly present: boolean };

/**
 * Reads one own data descriptor without invoking an accessor. Configuration
 * objects intentionally use own properties; executable adapter methods use
 * `boundaryDataProperty`, which also permits bounded prototype methods.
 */
export function boundaryOwnDataProperty(value: object, key: PropertyKey): BoundaryDataProperty {
  try {
    const descriptor = boundaryObjectGetOwnPropertyDescriptor(value, key);
    if (descriptor === undefined) return { valid: true, present: false };
    if (!("value" in descriptor)) return { valid: false, present: true };
    return { valid: true, present: true, value: descriptor.value };
  } catch {
    return { valid: false, present: false };
  }
}

/**
 * Reads a data descriptor through a bounded prototype chain. Accessors,
 * cycles, and hostile prototype traps are invalid and never executed.
 */
export function boundaryDataProperty(value: object, key: PropertyKey): BoundaryDataProperty {
  let current: object | null = value;
  const seen = new boundarySetConstructor<object>();
  for (let depth = 0; current !== null && depth < MAX_PROTOTYPE_DEPTH; depth += 1) {
    if (boundaryReflectApply(boundarySetHas, seen, [current])) return { valid: false, present: true };
    boundaryReflectApply(boundarySetAdd, seen, [current]);
    // Object.prototype is ambient global state, not an adapter prototype.
    // Continue rejecting its `then` in boundaryHasThen, but never accept a
    // method polluted onto it as a configured callback.
    if (current === boundaryObjectPrototype) return { valid: true, present: false };
    let descriptor: PropertyDescriptor | undefined;
    try {
      descriptor = boundaryObjectGetOwnPropertyDescriptor(current, key);
    } catch {
      return { valid: false, present: false };
    }
    if (descriptor !== undefined) {
      if (!("value" in descriptor)) return { valid: false, present: true };
      return { valid: true, present: true, value: descriptor.value };
    }
    try {
      current = boundaryObjectGetPrototypeOf(current);
    } catch {
      return { valid: false, present: false };
    }
  }
  return current === null ? { valid: true, present: false } : { valid: false, present: true };
}

/**
 * Detects own or inherited thenability using descriptors only. A malformed
 * or unwalkable prototype is treated as thenable so construction fails closed.
 */
export function boundaryHasThen(value: object, allowObjectPrototypeThen = false): boolean {
  let current: object | null = value;
  const seen = new boundarySetConstructor<object>();
  for (let depth = 0; current !== null && depth < MAX_PROTOTYPE_DEPTH; depth += 1) {
    if (boundaryReflectApply(boundarySetHas, seen, [current])) return true;
    boundaryReflectApply(boundarySetAdd, seen, [current]);
    if (allowObjectPrototypeThen && current === boundaryObjectPrototype) return false;
    try {
      const descriptor = boundaryObjectGetOwnPropertyDescriptor(current, "then");
      if (descriptor !== undefined) {
        // Result objects deliberately install an own data `then: undefined`
        // shield. Accessors and callable values remain hostile thenables.
        if (!("value" in descriptor) || typeof descriptor.value === "function") return true;
      }
      current = boundaryObjectGetPrototypeOf(current);
    } catch {
      return true;
    }
  }
  return current !== null;
}

/** Validates an object boundary without reading ordinary properties. */
export function assertBoundaryObject(
  value: unknown,
  label: string,
  allowObjectPrototypeThen = false,
): asserts value is object {
  if (value === null || (typeof value !== "object" && typeof value !== "function")) {
    throw new AuthConfigurationError(`${label} must be an object`);
  }
  if (boundaryHasThen(value as object, allowObjectPrototypeThen)) {
    throw new AuthConfigurationError(`${label} must not be thenable`);
  }
}

/** Captures one configured callback as a data-property function. */
export function captureBoundaryFunction(value: unknown, label: string, allowObjectPrototypeThen = false): Function {
  if (typeof value !== "function" || boundaryHasThen(value, allowObjectPrototypeThen)) {
    throw new AuthConfigurationError(`${label} must be a non-thenable function`);
  }
  return value;
}

/** Returns a required own option without invoking a getter. */
export function requiredBoundaryOption(source: object, key: PropertyKey, label: string): unknown {
  const property = boundaryOwnDataProperty(source, key);
  if (!property.valid || !property.present) {
    throw new AuthConfigurationError(`${label} must be a data property`);
  }
  return property.value;
}

/** Returns an optional own option without invoking a getter. */
export function optionalBoundaryOption(source: object, key: PropertyKey, label: string): unknown {
  const property = boundaryOwnDataProperty(source, key);
  if (!property.valid) throw new AuthConfigurationError(`${label} must be a data property`);
  return property.present ? property.value : undefined;
}

/** Captures required/optional methods with the original receiver preserved. */
export function captureBoundaryMethodGroup(
  value: unknown,
  label: string,
  required: readonly string[],
  optional: readonly string[] = [],
  properties: Readonly<Record<string, unknown>> = {},
  receiver: "source" | "facade" = "source",
  allowObjectPrototypeThen = false,
): Record<string, unknown> {
  if (value === null || (typeof value !== "object" && typeof value !== "function")) {
    throw new AuthConfigurationError(`${label} is incomplete`);
  }
  const source = value as object;
  assertBoundaryObject(source, label, allowObjectPrototypeThen);
  const facade = boundaryObjectCreate(null) as Record<string, unknown>;
  const propertyNames = safeOwnPropertyNames(properties, `${label} properties`);
  if (safeOwnPropertySymbols(properties, `${label} properties`).length !== 0) {
    throw new AuthConfigurationError(`${label} properties must not contain symbols`);
  }
  for (let index = 0; index < propertyNames.length; index += 1) {
    const property = propertyNames[index];
    if (property === undefined) throw new AuthConfigurationError(`${label} properties are malformed`);
    const propertyValue = boundaryOwnDataProperty(properties, property);
    if (!propertyValue.valid || !propertyValue.present) {
      throw new AuthConfigurationError(`${label}.${property} must be a data property`);
    }
    boundaryObjectDefineProperty(facade, property, {
      configurable: false,
      enumerable: true,
      writable: false,
      value: propertyValue.value,
    });
  }
  const capture = (method: string): void => {
    const property = boundaryDataProperty(source, method);
    if (!property.valid || !property.present) {
      throw new AuthConfigurationError(`${label}.${method} must be a data-property function`);
    }
    const callback = captureBoundaryFunction(property.value, `${label}.${method}`, allowObjectPrototypeThen);
    boundaryObjectDefineProperty(facade, method, {
      configurable: false,
      enumerable: true,
      writable: false,
      value: (...args: unknown[]) => boundaryReflectApply(callback, receiver === "facade" ? facade : source, args),
    });
  };
  for (let index = 0; index < required.length; index += 1) {
    const method = required[index];
    if (method === undefined) throw new AuthConfigurationError(`${label} is incomplete`);
    capture(method);
  }
  for (let index = 0; index < optional.length; index += 1) {
    const method = optional[index];
    if (method === undefined) throw new AuthConfigurationError(`${label} is incomplete`);
    const property = boundaryDataProperty(source, method);
    if (!property.valid) throw new AuthConfigurationError(`${label}.${method} must be a data-property function`);
    if (!property.present) continue;
    capture(method);
  }
  return boundaryObjectFreeze(facade);
}

/** Captures the public TokenService key-provider contract once. */
export function captureBoundaryKeyProvider(value: unknown): KeyProvider {
  if (value === null || typeof value !== "object") {
    throw new AuthConfigurationError("token key provider is incomplete");
  }
  return captureBoundaryMethodGroup(
    value,
    "token key provider",
    ["getActiveKeyId", "getSigningKey", "getVerificationKeys"],
  ) as unknown as KeyProvider;
}

/** Defines one internal array element without dispatching through its prototype. */
export function defineBoundaryArrayValue<T>(
  target: T[],
  index: number,
  value: T,
  label = "boundary array",
): void {
  if (!boundaryNumberIsSafeInteger(index) || index < 0 || index > MAX_BOUNDARY_COLLECTION_LENGTH) {
    throw new AuthConfigurationError(`${label} is malformed`);
  }
  try {
    boundaryObjectDefineProperty(target, boundaryString(index), {
      configurable: true,
      enumerable: true,
      writable: true,
      value,
    });
  } catch {
    throw new AuthConfigurationError(`${label} is malformed`);
  }
}

/** Uses the captured Array sort method on an internal array only. */
export function sortBoundaryArray<T>(
  target: T[],
  compare: (left: T, right: T) => number,
  label = "boundary array",
): T[] {
  try {
    return boundaryReflectApply(boundaryArraySort, target, [compare]) as T[];
  } catch {
    throw new AuthConfigurationError(`${label} is malformed`);
  }
}

/** Copies a bounded dense string array without invoking element accessors. */
export function captureBoundaryStringArray(
  value: unknown,
  label: string,
  minimum = 0,
  maximum = MAX_BOUNDARY_COLLECTION_LENGTH,
): readonly string[] {
  const values = captureBoundaryDenseArray(value, label, minimum, maximum);
  const copy = new boundaryArrayConstructor<string>(values.length);
  for (let index = 0; index < values.length; index += 1) {
    const entry = values[index];
    if (typeof entry !== "string") throw new AuthConfigurationError(`${label} must be a dense string array`);
    defineBoundaryArrayValue(copy, index, entry, label);
  }
  return boundaryObjectFreeze(copy);
}

/** Copies a bounded dense own-data array without invoking caller iteration. */
export function captureBoundaryDenseArray(
  value: unknown,
  label: string,
  minimum = 0,
  maximum = MAX_BOUNDARY_COLLECTION_LENGTH,
): readonly unknown[] {
  if (!boundaryIsArray(value, label)) throw new AuthConfigurationError(`${label} must be a data array`);
  const candidate = value as object;
  // Ignore a polluted ambient Object.prototype.then for data snapshots while
  // still rejecting own and custom-prototype thenables.
  if (boundaryHasThen(candidate, true)) throw new AuthConfigurationError(`${label} must not be thenable`);
  const lengthProperty = boundaryOwnDataProperty(candidate, "length");
  if (
    !lengthProperty.valid || !lengthProperty.present || typeof lengthProperty.value !== "number"
    || !boundaryNumberIsSafeInteger(lengthProperty.value) || lengthProperty.value < minimum || lengthProperty.value > maximum
  ) throw new AuthConfigurationError(`${label} must be a bounded dense array`);
  const length = lengthProperty.value as number;
  const names = safeOwnPropertyNames(candidate, label);
  if (safeOwnPropertySymbols(candidate, label).length !== 0 || names.length !== length + 1) {
    throw new AuthConfigurationError(`${label} must be a dense own-data array`);
  }
  for (let nameIndex = 0; nameIndex < names.length; nameIndex += 1) {
    const name = names[nameIndex];
    if (name === undefined || (name !== "length" && (!/^\d+$/u.test(name) || boundaryNumber(name) >= length))) {
      throw new AuthConfigurationError(`${label} must be a dense own-data array`);
    }
  }
  const copy = new boundaryArrayConstructor<unknown>(length);
  for (let index = 0; index < length; index += 1) {
    const property = boundaryOwnDataProperty(candidate, boundaryString(index));
    if (!property.valid || !property.present) {
      throw new AuthConfigurationError(`${label} must be a dense own-data array`);
    }
    defineBoundaryArrayValue(copy, index, property.value, label);
  }
  return boundaryObjectFreeze(copy);
}

/** Copies and deduplicates a bounded dense string array with safe Set calls. */
export function captureBoundaryUniqueStringArray(
  value: unknown,
  label: string,
  minimum = 0,
  maximum = MAX_BOUNDARY_COLLECTION_LENGTH,
): readonly string[] {
  const values = captureBoundaryStringArray(value, label, minimum, maximum);
  const seen = new boundarySetConstructor<string>();
  const copy = new boundaryArrayConstructor<string>();
  let length = 0;
  for (let index = 0; index < values.length; index += 1) {
    const valueAtIndex = values[index];
    if (valueAtIndex === undefined) throw new AuthConfigurationError(`${label} must be a dense string array`);
    if (boundaryReflectApply(boundarySetHas, seen, [valueAtIndex])) {
      throw new AuthConfigurationError(`${label} must not contain duplicate values`);
    }
    boundaryReflectApply(boundarySetAdd, seen, [valueAtIndex]);
    defineBoundaryArrayValue(copy, length, valueAtIndex, label);
    length += 1;
  }
  return boundaryObjectFreeze(copy);
}

/** Copies genuine Uint8Array data through captured typed-array intrinsics. */
export function captureBoundaryBytes(value: unknown, label: string, minimum = 0): Uint8Array {
  if (typeof value !== "object" || value === null) {
    throw new AuthConfigurationError(`${label} must be a Uint8Array`);
  }
  if (boundaryHasThen(value, true)) throw new AuthConfigurationError(`${label} must not be thenable`);
  let tag: unknown;
  let byteLength: unknown;
  try {
    tag = boundaryReflectApply(boundaryTypedArrayTagGetter, value, []);
    byteLength = boundaryReflectApply(boundaryTypedArrayByteLengthGetter, value, []);
  } catch {
    throw new AuthConfigurationError(`${label} must be a Uint8Array`);
  }
  if (tag !== "Uint8Array" || typeof byteLength !== "number" || !boundaryNumberIsSafeInteger(byteLength) || byteLength < minimum) {
    throw new AuthConfigurationError(`${label} must contain valid Uint8Array material`);
  }
  try {
    const copy = new boundaryUint8Array(byteLength);
    boundaryReflectApply(boundaryTypedArraySet, copy, [value]);
    return copy;
  } catch {
    throw new AuthConfigurationError(`${label} must contain valid Uint8Array material`);
  }
}

/** Safely identifies a genuine Uint8Array through captured typed-array accessors. */
export function boundaryIsUint8Array(value: unknown, label: string): boolean {
  if (value === null || (typeof value !== "object" && typeof value !== "function")) return false;
  try {
    return boundaryReflectApply(boundaryTypedArrayTagGetter, value, []) === "Uint8Array";
  } catch {
    throw new AuthConfigurationError(`${label} must contain valid Uint8Array material`);
  }
}

/** Copies JSON-like provider/configuration data without invoking accessors or iterators. */
export function captureBoundaryDataValue(
  value: unknown,
  label: string,
  depth = 0,
): unknown {
  if (depth > MAX_BOUNDARY_VALUE_DEPTH) throw new AuthConfigurationError(`${label} is too deeply nested`);
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!boundaryNumberIsFinite(value)) throw new AuthConfigurationError(`${label} contains an invalid number`);
    return value;
  }
  if (typeof value === "undefined") return undefined;
  if (typeof value === "function") throw new AuthConfigurationError(`${label} must not be executable`);
  if (boundaryIsUint8Array(value, label)) return captureBoundaryBytes(value, label);
  if (boundaryIsArray(value, label)) {
    const values = captureBoundaryDenseArray(value, label, 0, MAX_BOUNDARY_COLLECTION_LENGTH);
    const copy = new boundaryArrayConstructor<unknown>(values.length);
    for (let index = 0; index < values.length; index += 1) {
      defineBoundaryArrayValue(copy, index, captureBoundaryDataValue(values[index], `${label}[${index}]`, depth + 1), label);
    }
    return boundaryObjectFreeze(copy);
  }
  // Provider/service result snapshots may inherit a polluted ambient
  // Object.prototype.then. It is never read or assimilated.
  assertBoundaryObject(value, label, true);
  let prototype: object | null;
  try {
    prototype = boundaryObjectGetPrototypeOf(value);
  } catch {
    throw new AuthConfigurationError(`${label} must be a plain data record`);
  }
  if (prototype !== boundaryObjectPrototype && prototype !== null) {
    throw new AuthConfigurationError(`${label} must be a plain data record`);
  }
  const names = safeOwnPropertyNames(value, label);
  if (safeOwnPropertySymbols(value, label).length !== 0 || names.length > MAX_BOUNDARY_COLLECTION_LENGTH) {
    throw new AuthConfigurationError(`${label} must be a bounded data record`);
  }
  const copy = boundaryObjectCreate(null) as Record<string, unknown>;
  for (let index = 0; index < names.length; index += 1) {
    const name = names[index];
    if (name === undefined) throw new AuthConfigurationError(`${label} is malformed`);
    const property = boundaryOwnDataProperty(value, name);
    if (!property.valid || !property.present) throw new AuthConfigurationError(`${label}.${name} must be a data property`);
    boundaryObjectDefineProperty(copy, name, {
      configurable: false,
      enumerable: true,
      writable: false,
      value: captureBoundaryDataValue(property.value, `${label}.${name}`, depth + 1),
    });
  }
  return boundaryObjectFreeze(copy);
}

/** Captures a provider key material value before any JWK property is read. */
export function captureBoundaryKeyMaterial(value: unknown, label: string): KeyMaterial {
  const snapshot = captureBoundaryDataValue(value, label);
  if (
    typeof snapshot === "string" ||
    boundaryIsUint8Array(snapshot, label) ||
    (snapshot !== null && typeof snapshot === "object")
  ) {
    return snapshot as KeyMaterial;
  }
  throw new AuthConfigurationError(`${label} must be valid key material`);
}

/** Resolves one provider result without assimilating hostile thenables. */
export async function resolveBoundaryResult<T>(value: unknown, label: string): Promise<T> {
  try {
    let isNativePromise = false;
    if (value !== null && (typeof value === "object" || typeof value === "function")) {
      try {
        isNativePromise = boundaryObjectGetPrototypeOf(value) === boundaryPromisePrototype
          && value instanceof boundaryPromise
          && boundaryObjectGetOwnPropertyDescriptor(value, "then") === undefined;
      } catch {
        throw new AuthConfigurationError(`${label} returned invalid data`);
      }
      if (!isNativePromise && boundaryHasThen(value as object)) {
        throw new AuthConfigurationError(`${label} returned an unsupported thenable`);
      }
    }
    if (isNativePromise) return await value as T;
    return value as T;
  } catch (error) {
    let configurationError = false;
    try {
      configurationError = error instanceof AuthConfigurationError;
    } catch {
      configurationError = false;
    }
    if (configurationError) throw error;
    throw new AuthConfigurationError(`${label} returned invalid data`);
  }
}

/** Invokes one captured provider callback and safely resolves its return value. */
export async function invokeBoundaryResult<T>(
  callback: Function,
  receiver: unknown,
  args: readonly unknown[],
  label: string,
): Promise<T> {
  try {
    const value = boundaryReflectApply(callback, receiver, args as unknown[]);
    return await resolveBoundaryResult<T>(value, label);
  } catch (error) {
    let configurationError = false;
    try {
      configurationError = error instanceof AuthConfigurationError;
    } catch {
      configurationError = false;
    }
    if (configurationError) throw error;
    throw new AuthConfigurationError(`${label} failed`);
  }
}

/** Captures Map entries without caller iterators, prototype methods, or unbounded work. */
export function captureBoundaryMapEntries(
  value: unknown,
  label: string,
  maximum = MAX_BOUNDARY_COLLECTION_LENGTH,
): readonly (readonly [unknown, unknown])[] {
  if (!boundaryIsMap(value, label)) throw new AuthConfigurationError(`${label} must be a data map`);
  const map = value as Map<unknown, unknown>;
  if (boundaryHasThen(map, true)) throw new AuthConfigurationError(`${label} must not be thenable`);
  let iterator: object;
  try {
    iterator = boundaryReflectApply(boundaryMapEntries, map, []) as object;
  } catch {
    throw new AuthConfigurationError(`${label} must be a data map`);
  }
  const entries = new boundaryArrayConstructor<readonly [unknown, unknown]>();
  for (let index = 0; index <= maximum; index += 1) {
    let step: unknown;
    try {
      step = boundaryReflectApply(boundaryMapIteratorNext, iterator, []);
    } catch {
      throw new AuthConfigurationError(`${label} must be a bounded data map`);
    }
    if (step === null || typeof step !== "object") throw new AuthConfigurationError(`${label} must be a bounded data map`);
    const done = boundaryOwnDataProperty(step, "done");
    const entry = boundaryOwnDataProperty(step, "value");
    if (!done.valid || !done.present || typeof done.value !== "boolean" || !entry.valid) {
      throw new AuthConfigurationError(`${label} must be a bounded data map`);
    }
    if (done.value) return boundaryObjectFreeze(entries);
    if (!entry.present) throw new AuthConfigurationError(`${label} must be a bounded data map`);
    const pair = captureBoundaryDenseArray(entry.value, `${label} entry`, 2, 2);
    const pairCopy = new boundaryArrayConstructor<unknown>(2) as unknown as [unknown, unknown];
    defineBoundaryArrayValue(pairCopy, 0, pair[0], `${label} entry`);
    defineBoundaryArrayValue(pairCopy, 1, pair[1], `${label} entry`);
    boundaryObjectFreeze(pairCopy);
    defineBoundaryArrayValue(entries, index, pairCopy, label);
  }
  throw new AuthConfigurationError(`${label} exceeds the configured collection limit`);
}

/** Captures the complete repository method tree, including transaction scopes. */
export function captureBoundaryRepository(value: unknown): AuthRepository {
  if (value === null || (typeof value !== "object" && typeof value !== "function")) {
    throw new AuthConfigurationError("database repository is incomplete");
  }
  const source = value as object;
  assertBoundaryObject(source, "database repository");
  const methods: Readonly<Record<string, readonly string[]>> = {
    users: ["findById", "findByIdForUpdate", "findByNormalizedEmail", "findByNormalizedEmailForUpdate", "findByNormalizedPhoneForUpdate", "create", "createWithId", "createIfAvailable", "update", "softDelete"],
    identities: ["findByProviderSubject", "listByUserId", "create", "createIfAvailable", "deleteById"],
    passwordCredentials: ["findByUserId", "upsert", "deleteByUserId"],
    sessions: ["create", "findByIdForUpdate", "findRefreshForUpdate", "rotate", "revokeSession", "revokeFamily", "revokeUserSessions"],
    oneTimeTokens: ["issue", "consume", "consumeBound", "recordFailure"],
    oauthStates: ["create", "consume"],
    authorization: ["effectivePermissions", "assignRole", "unassignRole", "setRolePermissions", "setRoleInheritance"],
    roles: ["list", "findById", "create", "update", "delete"],
    permissions: ["list", "findById", "create", "update", "delete"],
    operations: ["appendAudit", "findApiKeyByHash"],
    admin: ["listUsers", "createApiKey", "listApiKeys", "revokeApiKey", "touchApiKeyLastUsed", "listAudit", "assignedRolesForUpdate", "rolesForUpdate", "countActiveRoleAssignments"],
  };
  const facade = boundaryObjectCreate(null) as Record<string, unknown>;
  const members = ["users", "identities", "passwordCredentials", "sessions", "oneTimeTokens", "oauthStates", "authorization", "roles", "permissions", "operations"] as const;
  const transactionProperty = boundaryDataProperty(source, "transaction");
  if (!transactionProperty.valid || !transactionProperty.present) throw new AuthConfigurationError("database.transaction must be a data-property function");
  const transaction = captureBoundaryFunction(transactionProperty.value, "database.transaction");
  boundaryObjectDefineProperty(facade, "transaction", {
    configurable: false,
    enumerable: true,
    writable: false,
    value: (...args: unknown[]) => {
      const callback = args[0];
      if (typeof callback !== "function") return boundaryReflectApply(transaction, source, args);
      const wrapped = (transactionRepository: unknown, ...callbackArgs: unknown[]) => {
        const callbackArguments: unknown[] = [captureBoundaryRepository(transactionRepository)];
        for (let index = 0; index < callbackArgs.length; index += 1) {
          defineBoundaryArrayValue(callbackArguments, index + 1, callbackArgs[index], "database transaction arguments");
        }
        return boundaryReflectApply(callback, undefined, callbackArguments);
      };
      const forwarded: unknown[] = [wrapped];
      for (let index = 1; index < args.length; index += 1) {
        defineBoundaryArrayValue(forwarded, index, args[index], "database transaction arguments");
      }
      return boundaryReflectApply(transaction, source, forwarded);
    },
  });
  for (let index = 0; index < members.length; index += 1) {
    const member = members[index];
    if (member === undefined) throw new AuthConfigurationError("database repository is incomplete");
    const memberMethods = methods[member];
    if (memberMethods === undefined) throw new AuthConfigurationError("database repository is incomplete");
    const memberProperty = boundaryDataProperty(source, member);
    if (!memberProperty.valid || !memberProperty.present) throw new AuthConfigurationError(`database.${member} is incomplete`);
    boundaryObjectDefineProperty(facade, member, {
      configurable: false,
      enumerable: true,
      writable: false,
      value: captureBoundaryMethodGroup(memberProperty.value, `database.${member}`, memberMethods),
    });
  }
  const adminProperty = boundaryDataProperty(source, "admin");
  if (!adminProperty.valid) throw new AuthConfigurationError("database.admin must be a data property");
  if (adminProperty.present && adminProperty.value !== undefined) {
    boundaryObjectDefineProperty(facade, "admin", {
      configurable: false,
      enumerable: true,
      writable: false,
      value: captureBoundaryMethodGroup(adminProperty.value, "database.admin", methods.admin ?? []),
    });
  }
  return boundaryObjectFreeze(facade) as unknown as AuthRepository;
}

/** Captures an optional clock callback before ordinary option validation. */
export function captureBoundaryClock(
  value: unknown,
  label: string,
  defaultClock: () => Date,
): () => Date {
  if (value === undefined) return defaultClock;
  return captureBoundaryFunction(value, label) as () => Date;
}
