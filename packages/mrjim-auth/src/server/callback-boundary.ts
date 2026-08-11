import type { AuthRepository, KeyProvider } from "../shared/contracts.js";
import { AuthConfigurationError } from "../shared/errors.js";

/*
 * These are captured once, before any configured adapter or caller value is
 * inspected. Construction code below never dispatches through mutable global
 * collection methods or ordinary properties of caller-owned collections.
 */
const boundaryArrayConstructor = Array;
const boundaryArrayIsArray = Array.isArray;
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
export function boundaryMapHasValue<K, V>(map: Map<K, V>, key: K, label: string): boolean {
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
export function boundaryMapGetValue<K, V>(map: Map<K, V>, key: K, label: string): V | undefined {
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
export function boundaryHasThen(value: object): boolean {
  let current: object | null = value;
  const seen = new boundarySetConstructor<object>();
  for (let depth = 0; current !== null && depth < MAX_PROTOTYPE_DEPTH; depth += 1) {
    if (boundaryReflectApply(boundarySetHas, seen, [current])) return true;
    boundaryReflectApply(boundarySetAdd, seen, [current]);
    try {
      if (boundaryObjectGetOwnPropertyDescriptor(current, "then") !== undefined) return true;
      current = boundaryObjectGetPrototypeOf(current);
    } catch {
      return true;
    }
  }
  return current !== null;
}

/** Validates an object boundary without reading ordinary properties. */
export function assertBoundaryObject(value: unknown, label: string): asserts value is object {
  if (value === null || (typeof value !== "object" && typeof value !== "function")) {
    throw new AuthConfigurationError(`${label} must be an object`);
  }
  if (boundaryHasThen(value as object)) {
    throw new AuthConfigurationError(`${label} must not be thenable`);
  }
}

/** Captures one configured callback as a data-property function. */
export function captureBoundaryFunction(value: unknown, label: string): Function {
  if (typeof value !== "function" || boundaryHasThen(value)) {
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
): Record<string, unknown> {
  if (value === null || (typeof value !== "object" && typeof value !== "function")) {
    throw new AuthConfigurationError(`${label} is incomplete`);
  }
  const source = value as object;
  assertBoundaryObject(source, label);
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
    const callback = captureBoundaryFunction(property.value, `${label}.${method}`);
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
    copy[index] = entry;
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
  if (boundaryHasThen(candidate)) throw new AuthConfigurationError(`${label} must not be thenable`);
  const lengthProperty = boundaryOwnDataProperty(candidate, "length");
  if (
    !lengthProperty.valid || !lengthProperty.present || typeof lengthProperty.value !== "number"
    || !Number.isSafeInteger(lengthProperty.value) || lengthProperty.value < minimum || lengthProperty.value > maximum
  ) throw new AuthConfigurationError(`${label} must be a bounded dense array`);
  const length = lengthProperty.value as number;
  const names = safeOwnPropertyNames(candidate, label);
  if (safeOwnPropertySymbols(candidate, label).length !== 0 || names.length !== length + 1) {
    throw new AuthConfigurationError(`${label} must be a dense own-data array`);
  }
  for (let nameIndex = 0; nameIndex < names.length; nameIndex += 1) {
    const name = names[nameIndex];
    if (name === undefined || (name !== "length" && (!/^\d+$/u.test(name) || Number(name) >= length))) {
      throw new AuthConfigurationError(`${label} must be a dense own-data array`);
    }
  }
  const copy = new boundaryArrayConstructor<unknown>(length);
  for (let index = 0; index < length; index += 1) {
    const property = boundaryOwnDataProperty(candidate, String(index));
    if (!property.valid || !property.present) {
      throw new AuthConfigurationError(`${label} must be a dense own-data array`);
    }
    copy[index] = property.value;
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
    copy[length] = valueAtIndex;
    length += 1;
  }
  return boundaryObjectFreeze(copy);
}

/** Copies genuine Uint8Array data through captured typed-array intrinsics. */
export function captureBoundaryBytes(value: unknown, label: string, minimum = 0): Uint8Array {
  if (typeof value !== "object" || value === null) {
    throw new AuthConfigurationError(`${label} must be a Uint8Array`);
  }
  let tag: unknown;
  let byteLength: unknown;
  try {
    tag = boundaryReflectApply(boundaryTypedArrayTagGetter, value, []);
    byteLength = boundaryReflectApply(boundaryTypedArrayByteLengthGetter, value, []);
  } catch {
    throw new AuthConfigurationError(`${label} must be a Uint8Array`);
  }
  if (tag !== "Uint8Array" || typeof byteLength !== "number" || !Number.isSafeInteger(byteLength) || byteLength < minimum) {
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

/** Captures Map entries without caller iterators, prototype methods, or unbounded work. */
export function captureBoundaryMapEntries(
  value: unknown,
  label: string,
  maximum = MAX_BOUNDARY_COLLECTION_LENGTH,
): readonly (readonly [unknown, unknown])[] {
  if (!boundaryIsMap(value, label)) throw new AuthConfigurationError(`${label} must be a data map`);
  const map = value as Map<unknown, unknown>;
  if (boundaryHasThen(map)) throw new AuthConfigurationError(`${label} must not be thenable`);
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
    entries[index] = [pair[0], pair[1]];
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
    users: ["findById", "findByIdForUpdate", "findByNormalizedEmail", "findByNormalizedEmailForUpdate", "create", "createIfAvailable", "update", "softDelete"],
    identities: ["findByProviderSubject", "listByUserId", "create", "createIfAvailable", "deleteById"],
    passwordCredentials: ["findByUserId", "upsert", "deleteByUserId"],
    sessions: ["create", "findByIdForUpdate", "findRefreshForUpdate", "rotate", "revokeSession", "revokeFamily", "revokeUserSessions"],
    oneTimeTokens: ["issue", "consume", "consumeBound", "recordFailure"],
    oauthStates: ["create", "consume"],
    authorization: ["effectivePermissions", "assignRole", "unassignRole", "setRolePermissions", "setRoleInheritance"],
    roles: ["list", "findById", "create", "update", "delete"],
    permissions: ["list", "findById", "create", "update", "delete"],
    operations: ["appendAudit", "findApiKeyByHash"],
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
        for (let index = 0; index < callbackArgs.length; index += 1) callbackArguments[index + 1] = callbackArgs[index];
        return boundaryReflectApply(callback, undefined, callbackArguments);
      };
      const forwarded: unknown[] = [wrapped];
      for (let index = 1; index < args.length; index += 1) forwarded[index] = args[index];
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
