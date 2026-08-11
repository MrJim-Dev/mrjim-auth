import { randomUUID } from "node:crypto";
import type {
  AuthRepository,
  AuthorizationRepository,
  RepositoryOperationOptions,
} from "../shared/contracts.js";
import {
  AuthApiError,
  AuthConfigurationError,
  AuthProgrammingError,
} from "../shared/errors.js";
import {
  type AuthorizationScope,
  type LowercaseKey,
  type Permission,
  type ScopeIdentifier,
  type UUID,
} from "../shared/types.js";

/*
 * Authorization is a security boundary. Capture the object/array operations
 * used to inspect untrusted request and adapter values before any caller can
 * replace their prototypes. All later collection work is numeric/manual.
 */
const reflectApply = Reflect.apply;
const objectCreate = Object.create;
const objectDefineProperty = Object.defineProperty;
const objectFreeze = Object.freeze;
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const objectGetOwnPropertyNames = Object.getOwnPropertyNames;
const objectGetOwnPropertySymbols = Object.getOwnPropertySymbols;
const objectGetPrototypeOf = Object.getPrototypeOf;
const objectSetPrototypeOf = Object.setPrototypeOf;
const objectHasOwnProperty = Object.prototype.hasOwnProperty;
const objectPrototype = Object.prototype;
const arrayIsArray = Array.isArray;
const arraySort = Array.prototype.sort;
const dateConstructor = Date;
const dateGetTime = Date.prototype.getTime;
const mapConstructor = Map;
const mapHas = Map.prototype.has;
const mapSet = Map.prototype.set;
const numberIsFinite = Number.isFinite;
const numberIsSafeInteger = Number.isSafeInteger;
const promiseConstructor = Promise;
const promisePrototype = Promise.prototype;
const promiseThen = Promise.prototype.then;
const promiseSpeciesKey = Symbol.species;
const promisePrototypeConstructorDescriptor = objectGetOwnPropertyDescriptor(
  promisePrototype,
  "constructor",
);
const promiseSpeciesDescriptor = objectGetOwnPropertyDescriptor(
  promiseConstructor,
  promiseSpeciesKey,
);
const reflectConstruct = Reflect.construct;
const stringTrim = String.prototype.trim;
const stringToLowerCase = String.prototype.toLowerCase;
const weakMapConstructor = WeakMap;
const weakMapGet = WeakMap.prototype.get;
const weakMapSet = WeakMap.prototype.set;
const weakSetConstructor = WeakSet;
const weakSetAdd = WeakSet.prototype.add;
const weakSetHas = WeakSet.prototype.has;
const promiseSignalOwnership = new weakSetConstructor<object>();

const MAX_REQUIREMENT_KEYS = 100_000;
const MAX_PERMISSION_ROWS = 100_000;
const PERMISSION_FIELDS = [
  "id",
  "key",
  "resource",
  "action",
  "description",
  "created_at",
  "updated_at",
] as const;

type DataProperty =
  | { readonly valid: true; readonly present: false }
  | { readonly valid: true; readonly present: true; readonly value: unknown }
  | { readonly valid: false; readonly present: boolean };

function invoke<T>(method: Function, receiver: unknown, args: readonly unknown[]): T {
  return reflectApply(method, receiver, args as unknown[]) as T;
}

function ownDataProperty(value: object, key: PropertyKey): DataProperty {
  try {
    const descriptor = objectGetOwnPropertyDescriptor(value, key);
    if (descriptor === undefined) return { valid: true, present: false };
    if (!invoke<boolean>(objectHasOwnProperty, descriptor, ["value"])) {
      return { valid: false, present: true };
    }
    return { valid: true, present: true, value: descriptor.value };
  } catch {
    return { valid: false, present: false };
  }
}

function captureAuthorizationFunction(value: unknown, label: string): Function {
  if (typeof value !== "function") throw new AuthConfigurationError(`${label} must be a function`);
  let current: object | null = value;
  for (let depth = 0; current !== null && current !== objectPrototype && depth < 32; depth += 1) {
    let descriptor: PropertyDescriptor | undefined;
    try {
      descriptor = objectGetOwnPropertyDescriptor(current, "then");
      if (descriptor !== undefined) throw new AuthConfigurationError(`${label} must be a non-thenable function`);
      current = objectGetPrototypeOf(current);
    } catch (error) {
      if (error instanceof AuthConfigurationError) throw error;
      throw new AuthConfigurationError(`${label} must be a data-property function`);
    }
  }
  if (current !== null && current !== objectPrototype) throw new AuthConfigurationError(`${label} must be a non-thenable function`);
  return value;
}

function captureAuthorizationClock(value: unknown): () => Date {
  if (value === undefined) return defaultClock;
  return captureAuthorizationFunction(value, "authorization clock") as () => Date;
}

function isPlainRecord(value: unknown): value is object {
  if (value === null || typeof value !== "object") return false;
  try {
    const prototype = objectGetPrototypeOf(value);
    return prototype === objectPrototype || prototype === null;
  } catch {
    return false;
  }
}

function containsNul(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    if (value[index] === "\u0000") return true;
  }
  return false;
}

function safePermissionKey(value: unknown): string | null {
  if (typeof value !== "string" || !validPermissionKey(value)) return null;
  return value;
}

function safeUserId(value: unknown): UUID | null {
  if (typeof value !== "string") return null;
  if (value.length !== 36) return null;
  for (let index = 0; index < value.length; index += 1) {
    const separator = index === 8 || index === 13 || index === 18 || index === 23;
    if (separator) {
      if (value[index] !== "-") return null;
      continue;
    }
    if (!isHexCharacter(value[index])) return null;
  }
  return value as UUID;
}

function isHexCharacter(value: string | undefined): boolean {
  if (value === undefined) return false;
  return (
    (value >= "0" && value <= "9") ||
    (value >= "a" && value <= "f") ||
    (value >= "A" && value <= "F")
  );
}

function isAsciiAlphaNumeric(value: string | undefined): boolean {
  if (value === undefined) return false;
  return (
    (value >= "a" && value <= "z") ||
    (value >= "A" && value <= "Z") ||
    (value >= "0" && value <= "9")
  );
}

function isRequestId(value: unknown): value is string {
  if (typeof value !== "string" || value.length < 1 || value.length > 128) return false;
  if (!isAsciiAlphaNumeric(value[0])) return false;
  for (let index = 1; index < value.length; index += 1) {
    const character = value[index];
    if (character === undefined) return false;
    if (!isAsciiAlphaNumeric(character) && character !== "_" && character !== "-") return false;
  }
  return true;
}

function isScopeType(value: unknown): value is string {
  if (typeof value !== "string" || value.length < 1 || value.length > 64) return false;
  const first = value[0];
  if (first === undefined || first < "a" || first > "z") return false;
  for (let index = 1; index < value.length; index += 1) {
    const character = value[index];
    if (
      character === undefined ||
      !(
        (character >= "a" && character <= "z") ||
        (character >= "0" && character <= "9") ||
        character === "_" ||
        character === "-"
      )
    ) {
      return false;
    }
  }
  return true;
}

function isLowerIdentifier(value: unknown, allowWildcard: boolean): value is string {
  if (typeof value !== "string") return false;
  if (allowWildcard && value === "*") return true;
  if (value.length === 0) return false;
  const first = value[0];
  if (first === undefined || first < "a" || first > "z") return false;
  for (let index = 1; index < value.length; index += 1) {
    const character = value[index];
    if (
      !(
        character !== undefined &&
        ((character >= "a" && character <= "z") ||
        (character >= "0" && character <= "9") ||
        character === "_" ||
        character === "-")
      )
    ) {
      return false;
    }
  }
  return true;
}

function validPermissionKey(value: string): boolean {
  const separator = keySeparator(value);
  if (separator <= 0 || separator >= value.length - 1) return false;
  if (value[separator + 1] === ".") return false;
  const resource = keyPart(value, 0, separator);
  const action = keyPart(value, separator + 1, value.length);
  if (resource === "*" && action === "*") return true;
  return isLowerIdentifier(resource, false) && isLowerIdentifier(action, true);
}

function compareKeys(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function appendValue<T>(values: T[], value: T): void {
  const index = values.length;
  objectDefineProperty(values, `${index}`, {
    configurable: true,
    enumerable: true,
    value,
    writable: true,
  });
}

function newNullPrototypeArray<T>(): T[] {
  const values: T[] = [];
  invoke<object>(objectSetPrototypeOf, undefined, [values, null]);
  return values;
}

function publicPermissionArray(keys: readonly string[]): readonly string[] {
  const values: string[] = [];
  for (let index = 0; index < keys.length; index += 1) {
    const key = keys[index];
    if (key === undefined) continue;
    appendValue(values, key);
  }
  objectDefineProperty(values, "then", {
    configurable: false,
    enumerable: false,
    value: undefined,
    writable: false,
  });
  return objectFreeze(values);
}

function sortKeys(values: string[]): void {
  invoke<void>(arraySort, values, [compareKeys]);
}

function keySeparator(value: string): number {
  for (let index = 0; index < value.length; index += 1) {
    if (value[index] === ".") return index;
  }
  return -1;
}

function keyPart(value: string, start: number, end: number): string {
  let result = "";
  for (let index = start; index < end; index += 1) {
    result += value[index];
  }
  return result;
}

function validNow(clock: () => Date): Date {
  let now: unknown;
  let epoch: number;
  try {
    now = clock();
    epoch = invoke<number>(dateGetTime, now, []);
  } catch {
    throw new AuthConfigurationError("authorization clock must return a valid Date");
  }
  if (!invoke<boolean>(numberIsFinite, undefined, [epoch])) {
    throw new AuthConfigurationError("authorization clock must return a valid Date");
  }
  try {
    return invoke<Date>(reflectConstruct, undefined, [dateConstructor, [epoch]]);
  } catch {
    throw new AuthConfigurationError("authorization clock must return a valid Date");
  }
}

function defaultClock(): Date {
  return invoke<Date>(reflectConstruct, undefined, [dateConstructor, []]);
}

/** A permission requirement for an authoritative server-side authorization check. */
export interface AuthorizationRequirement {
  readonly any?: readonly string[];
  readonly all?: readonly string[];
  readonly scope?: AuthorizationScope;
}

/** A request-local subject accepted by the authorization guard. */
export interface AuthorizationSubject {
  readonly user_id: UUID;
  readonly request_id?: string;
}

/** Configuration for the server-only authorization service. */
export interface AuthorizationServiceOptions {
  readonly repository: AuthRepository;
  readonly clock?: () => Date;
}

type NormalizedRequirement = {
  readonly any?: readonly string[];
  readonly all?: readonly string[];
  readonly scope?: AuthorizationScope;
};

type PermissionIndex = {
  readonly keys: readonly string[];
  readonly exact: Map<string, true>;
  readonly resourceWildcards: Map<string, true>;
  readonly globalWildcard: boolean;
};

type PermissionCacheEntry = {
  readonly scope: AuthorizationScope | undefined;
  readonly pending: Promise<PermissionIndex>;
};

type PermissionCache = PermissionCacheEntry[];

/** A cache explicitly owned by one immutable request subject. */
export interface AuthorizationRequestContext {
  readonly subject: AuthorizationSubject;
}

type RequestContextState = {
  readonly subject: AuthorizationSubject;
  readonly serviceCaches: WeakMap<object, PermissionCache>;
};

/*
 * Context authenticity is an object-identity fact held only in this module.
 * Reflected symbols, copied properties, and caller-provided loaders carry no
 * authority. Each authentic context has a separate cache per service object.
 */
const requestContextOwnership = new weakMapConstructor<object, RequestContextState>();

function createContextFromSnapshot(subject: AuthorizationSubject): AuthorizationRequestContext {
  const context = objectFreeze({ subject });
  const state: RequestContextState = {
    subject,
    serviceCaches: new weakMapConstructor<object, PermissionCache>(),
  };
  invoke<void>(weakMapSet, requestContextOwnership, [context, state]);
  return context;
}

/** Creates a frozen request-local authorization context bound to one UUID. */
export function createAuthorizationRequestContext(
  subject: unknown,
): AuthorizationRequestContext | null {
  const snapshot = snapshotAuthorizationSubject(subject);
  return snapshot === null ? null : createContextFromSnapshot(snapshot);
}

function sameScope(
  left: AuthorizationScope | undefined,
  right: AuthorizationScope | undefined,
): boolean {
  if (left === undefined || right === undefined) return left === right;
  return left.type === right.type && left.id === right.id;
}

function contextPermissions(
  state: RequestContextState,
  service: object,
  scope: AuthorizationScope | undefined,
  loader: () => Promise<PermissionIndex>,
): Promise<PermissionIndex> {
  let entries = invoke<PermissionCache | undefined>(weakMapGet, state.serviceCaches, [service]);
  if (entries === undefined) {
    entries = [];
    invoke<void>(weakMapSet, state.serviceCaches, [service, entries]);
  }
  for (let index = 0; index < entries.length; index += 1) {
    const entry = entries[index];
    if (entry !== undefined && sameScope(entry.scope, scope)) return entry.pending;
  }

  let pending: Promise<PermissionIndex>;
  try {
    pending = loader();
  } catch {
    pending = Promise.resolve(createEmptyPermissionIndex());
  }
  appendValue(entries, { scope, pending });
  return pending;
}

/** Parses one canonical lowercase `resource.action` permission key. */
export function normalizePermissionKey(value: unknown): LowercaseKey {
  const parsed = safePermissionKey(value);
  if (parsed === null) {
    throw new AuthProgrammingError("permission keys must be canonical lowercase resource.action values");
  }
  return parsed as LowercaseKey;
}

/**
 * Returns the deterministic specificity of a grant for one required key.
 * Exact grants outrank resource wildcards, which outrank the global wildcard.
 */
export function permissionMatchRank(granted: unknown, required: unknown): number {
  const grant = safePermissionKey(granted);
  const requirement = safePermissionKey(required);
  if (grant === null || requirement === null) return 0;
  if (grant === requirement) return 3;

  const grantSeparator = keySeparator(grant);
  const requiredSeparator = keySeparator(requirement);
  if (grantSeparator < 0 || requiredSeparator < 0) return 0;
  const grantResource = keyPart(grant, 0, grantSeparator);
  const grantAction = keyPart(grant, grantSeparator + 1, grant.length);
  const requiredResource = keyPart(requirement, 0, requiredSeparator);
  const requiredAction = keyPart(requirement, requiredSeparator + 1, requirement.length);

  if (
    grantAction === "*" &&
    grantResource === requiredResource &&
    requiredAction !== "*"
  ) {
    return 2;
  }
  if (
    grant === "*.*" &&
    requiredResource !== "*" &&
    requiredAction !== "*"
  ) {
    return 1;
  }
  return 0;
}

/** Returns whether one granted permission covers one required permission. */
export function permissionMatches(granted: unknown, required: unknown): boolean {
  return permissionMatchRank(granted, required) > 0;
}

function normalizedScope(scope: unknown): AuthorizationScope | null | undefined {
  if (scope === undefined) return undefined;
  if (!isPlainRecord(scope)) return null;

  const typeProperty = ownDataProperty(scope, "type");
  const idProperty = ownDataProperty(scope, "id");
  if (
    !typeProperty.valid ||
    !typeProperty.present ||
    !idProperty.valid ||
    !idProperty.present ||
    typeof typeProperty.value !== "string" ||
    typeof idProperty.value !== "string"
  ) {
    return null;
  }

  try {
    const trimmedType = invoke<string>(stringTrim, typeProperty.value, []);
    const type = invoke<string>(stringToLowerCase, trimmedType, []);
    const idValue = invoke<string>(stringTrim, idProperty.value, []);
    if (!isScopeType(type) || containsNul(type) || containsNul(idValue)) return null;
    if (idValue.length === 0) return null;
    return objectFreeze({ type, id: idValue as ScopeIdentifier });
  } catch {
    return null;
  }
}

function snapshotPermissionArray(value: unknown): unknown[] | null {
  try {
    if (!arrayIsArray(value)) return null;
    if (hasThenProperty(value)) return null;
    const lengthProperty = ownDataProperty(value, "length");
    if (
      !lengthProperty.valid ||
      !lengthProperty.present ||
      typeof lengthProperty.value !== "number" ||
      !numberIsSafeInteger(lengthProperty.value) ||
      lengthProperty.value < 0 ||
      lengthProperty.value > MAX_PERMISSION_ROWS
    ) {
      return null;
    }

    const snapshot: unknown[] = [];
    for (let index = 0; index < lengthProperty.value; index += 1) {
      const item = ownDataProperty(value, `${index}`);
      if (!item.valid || !item.present) return null;
      appendValue(snapshot, item.value);
    }
    return snapshot;
  } catch {
    return null;
  }
}

function hasThenProperty(value: object): boolean {
  let current: object | null = value;
  for (let depth = 0; current !== null && depth < 8; depth += 1) {
    try {
      if (objectGetOwnPropertyDescriptor(current, "then") !== undefined) return true;
      current = objectGetPrototypeOf(current);
    } catch {
      return true;
    }
  }
  return current !== null;
}

type NativePromiseOutcome = {
  readonly signal: Promise<void>;
  readonly state: { rejected: boolean; value: unknown };
};

function samePropertyDescriptor(
  left: PropertyDescriptor | undefined,
  right: PropertyDescriptor | undefined,
): boolean {
  if (left === undefined || right === undefined) return left === right;
  return (
    left.configurable === right.configurable &&
    left.enumerable === right.enumerable &&
    left.writable === right.writable &&
    left.value === right.value &&
    left.get === right.get &&
    left.set === right.set
  );
}

function nativePromiseOutcome(value: unknown): NativePromiseOutcome | null {
  try {
    if (
      value === null ||
      (typeof value !== "object" && typeof value !== "function") ||
      objectGetPrototypeOf(value) !== promisePrototype ||
      objectGetOwnPropertyDescriptor(value, "constructor") !== undefined ||
      objectGetOwnPropertyDescriptor(value, "then") !== undefined ||
      !samePropertyDescriptor(
        objectGetOwnPropertyDescriptor(promisePrototype, "constructor"),
        promisePrototypeConstructorDescriptor,
      ) ||
      !samePropertyDescriptor(
        objectGetOwnPropertyDescriptor(promiseConstructor, promiseSpeciesKey),
        promiseSpeciesDescriptor,
      )
    ) {
      return null;
    }

    const state = objectCreate(null) as { rejected: boolean; value: unknown };
    objectDefineProperty(state, "rejected", {
      configurable: false,
      enumerable: false,
      value: false,
      writable: true,
    });
    objectDefineProperty(state, "value", {
      configurable: false,
      enumerable: false,
      value: undefined,
      writable: true,
    });

    let settleSignal: ((value?: unknown) => void) | undefined;
    const signal = invoke<Promise<void>>(reflectConstruct, undefined, [
      promiseConstructor,
      [
        (resolve: (value?: unknown) => void) => {
          settleSignal = resolve;
        },
      ],
    ]);
    invoke(weakSetAdd, promiseSignalOwnership, [signal]);
    if (!isOwnedPromiseSignal(signal) || settleSignal === undefined) return null;
    const resolveSignal = settleSignal;

    // A fully rebased Promise subclass cannot be distinguished from a native
    // instance by reflection alone. It is therefore never trusted directly:
    // the captured native `then` only transfers settlement into package-owned
    // state, and the package-owned bridge settles with `undefined` so an
    // adapter-controlled settlement value can never be then-assimilated by
    // the signal that is awaited below.
    invoke<unknown>(promiseThen, value, [
      (resolved: unknown) => {
        state.value = resolved;
        resolveSignal(undefined);
      },
      (_reason: unknown) => {
        state.rejected = true;
        resolveSignal(undefined);
      },
    ]);
    return { signal, state };
  } catch {
    // Raw adapter values and all source errors are fail closed. The raw
    // promise is never awaited or cached as an authority.
    return null;
  }
}

function isOwnedPromiseSignal(value: unknown): value is Promise<void> {
  if (value === null || (typeof value !== "object" && typeof value !== "function")) return false;
  try {
    return invoke<boolean>(weakSetHas, promiseSignalOwnership, [value]);
  } catch {
    return false;
  }
}

function completePermissionRecord(value: unknown): Permission | null {
  if (!isPlainRecord(value)) return null;

  try {
    const names = objectGetOwnPropertyNames(value);
    for (let index = 0; index < names.length; index += 1) {
      let known = false;
      for (let fieldIndex = 0; fieldIndex < PERMISSION_FIELDS.length; fieldIndex += 1) {
        if (names[index] === PERMISSION_FIELDS[fieldIndex]) {
          known = true;
          break;
        }
      }
      if (!known) return null;
    }
    if (objectGetOwnPropertySymbols(value).length !== 0) return null;

    const snapshot = objectCreate(null) as Record<string, unknown>;
    for (let index = 0; index < PERMISSION_FIELDS.length; index += 1) {
      const field = PERMISSION_FIELDS[index];
      if (field === undefined) return null;
      const property = ownDataProperty(value, field);
      if (property.valid !== true || property.present !== true) return null;
      objectDefineProperty(snapshot, field, {
        configurable: true,
        enumerable: true,
        value: property.value,
        writable: true,
      });
    }

    const id = safeUserId(snapshot.id);
    const key = safePermissionKey(snapshot.key);
    const resource = snapshot.resource;
    const action = snapshot.action;
    if (
      id === null ||
      key === null ||
      !isLowerIdentifier(resource, true) ||
      !isLowerIdentifier(action, true) ||
      (resource === "*" && action !== "*") ||
      key !== `${resource}.${action}` ||
      !(snapshot.description === null || typeof snapshot.description === "string") ||
      typeof snapshot.created_at !== "string" ||
      snapshot.created_at.length === 0 ||
      typeof snapshot.updated_at !== "string" ||
      snapshot.updated_at.length === 0
    ) {
      return null;
    }
    return {
      id,
      key: key as LowercaseKey,
      resource: resource as LowercaseKey,
      action: action as LowercaseKey,
      description: snapshot.description,
      created_at: snapshot.created_at,
      updated_at: snapshot.updated_at,
    };
  } catch {
    return null;
  }
}

function newPermissionMap(): Map<string, true> {
  return new mapConstructor<string, true>();
}

function mapContains(map: Map<string, true>, key: string): boolean {
  return invoke<boolean>(mapHas, map, [key]);
}

function mapAdd(map: Map<string, true>, key: string): void {
  invoke<Map<string, true>>(mapSet, map, [key, true]);
}

function createEmptyPermissionIndex(): PermissionIndex {
  const index = objectCreate(null) as PermissionIndex;
  objectDefineProperty(index, "keys", {
    configurable: false,
    enumerable: true,
    value: objectFreeze(newNullPrototypeArray<string>()),
    writable: false,
  });
  objectDefineProperty(index, "exact", {
    configurable: false,
    enumerable: true,
    value: newPermissionMap(),
    writable: false,
  });
  objectDefineProperty(index, "resourceWildcards", {
    configurable: false,
    enumerable: true,
    value: newPermissionMap(),
    writable: false,
  });
  objectDefineProperty(index, "globalWildcard", {
    configurable: false,
    enumerable: true,
    value: false,
    writable: false,
  });
  return objectFreeze(index);
}

function permissionIndex(records: readonly Permission[]): PermissionIndex {
  const keys = newNullPrototypeArray<string>();
  const exact = newPermissionMap();
  const resourceWildcards = newPermissionMap();
  let globalWildcard = false;

  for (let index = 0; index < records.length; index += 1) {
    const record = records[index];
    if (record === undefined || mapContains(exact, record.key)) continue;
    mapAdd(exact, record.key);
    appendValue(keys, record.key);
    if (record.resource === "*" && record.action === "*") {
      globalWildcard = true;
    } else if (record.action === "*") {
      mapAdd(resourceWildcards, record.resource);
    }
  }

  sortKeys(keys);
  const index = objectCreate(null) as PermissionIndex;
  objectDefineProperty(index, "keys", {
    configurable: false,
    enumerable: true,
    value: objectFreeze(keys),
    writable: false,
  });
  objectDefineProperty(index, "exact", {
    configurable: false,
    enumerable: true,
    value: exact,
    writable: false,
  });
  objectDefineProperty(index, "resourceWildcards", {
    configurable: false,
    enumerable: true,
    value: resourceWildcards,
    writable: false,
  });
  objectDefineProperty(index, "globalWildcard", {
    configurable: false,
    enumerable: true,
    value: globalWildcard,
    writable: false,
  });
  return objectFreeze(index);
}

function normalizedRequirement(requirement: unknown): NormalizedRequirement | null {
  if (!isPlainRecord(requirement)) return null;

  const anyProperty = ownDataProperty(requirement, "any");
  const allProperty = ownDataProperty(requirement, "all");
  const scopeProperty = ownDataProperty(requirement, "scope");
  if (!anyProperty.valid || !allProperty.valid || !scopeProperty.valid) return null;

  const normalizeKeys = (
    property: DataProperty,
  ): readonly string[] | null | undefined => {
    if (!property.present) return undefined;
    if (property.valid !== true) return null;
    let candidate: unknown[];
    try {
      if (!arrayIsArray(property.value)) return null;
      candidate = property.value as unknown[];
    } catch {
      return null;
    }
    let length: number;
    try {
      const lengthProperty = ownDataProperty(candidate, "length");
      if (
        !lengthProperty.valid ||
        !lengthProperty.present ||
        typeof lengthProperty.value !== "number" ||
        !numberIsSafeInteger(lengthProperty.value) ||
        lengthProperty.value <= 0 ||
        lengthProperty.value > MAX_REQUIREMENT_KEYS
      ) {
        return null;
      }
      length = lengthProperty.value;
    } catch {
      return null;
    }

    const normalized: string[] = [];
    const seen = newPermissionMap();
    for (let index = 0; index < length; index += 1) {
      const item = ownDataProperty(candidate, `${index}`);
      if (item.valid !== true || item.present !== true || typeof item.value !== "string") return null;
      const key = safePermissionKey(item.value);
      if (key === null) return null;
      if (!mapContains(seen, key)) {
        mapAdd(seen, key);
        appendValue(normalized, key);
      }
    }
    if (normalized.length === 0) return null;
    sortKeys(normalized);
    return objectFreeze(normalized);
  };

  const any = normalizeKeys(anyProperty);
  const all = normalizeKeys(allProperty);
  if (any === null || all === null || (any === undefined && all === undefined)) return null;

  const scope = scopeProperty.present ? normalizedScope(scopeProperty.value) : undefined;
  if (scope === null) return null;
  const normalized = objectCreate(null) as {
    any?: readonly string[];
    all?: readonly string[];
    scope?: AuthorizationScope;
  };
  if (any !== undefined) {
    objectDefineProperty(normalized, "any", {
      configurable: false,
      enumerable: true,
      value: any,
      writable: false,
    });
  }
  if (all !== undefined) {
    objectDefineProperty(normalized, "all", {
      configurable: false,
      enumerable: true,
      value: all,
      writable: false,
    });
  }
  if (scope !== undefined) {
    objectDefineProperty(normalized, "scope", {
      configurable: false,
      enumerable: true,
      value: scope,
      writable: false,
    });
  }
  return objectFreeze(normalized);
}

/**
 * Snapshots and validates the only identity accepted by authorization. The
 * returned subject is frozen and contains an own UUID value, so later checks
 * cannot observe caller-controlled getters or a changed user binding.
 */
export function snapshotAuthorizationSubject(subject: unknown): AuthorizationSubject | null {
  if (!isPlainRecord(subject)) return null;
  const userProperty = ownDataProperty(subject, "user_id");
  if (!userProperty.valid || !userProperty.present) return null;
  const userId = safeUserId(userProperty.value);
  if (userId === null) return null;

  const requestProperty = ownDataProperty(subject, "request_id");
  const snapshot = objectCreate(null) as { user_id: UUID; request_id?: string };
  objectDefineProperty(snapshot, "user_id", {
    configurable: false,
    enumerable: true,
    value: userId,
    writable: false,
  });
  if (
    requestProperty.valid &&
    requestProperty.present &&
    isRequestId(requestProperty.value)
  ) {
    objectDefineProperty(snapshot, "request_id", {
      configurable: false,
      enumerable: true,
      value: requestProperty.value,
      writable: false,
    });
  }
  return objectFreeze(snapshot);
}

/** Extracts a validated own user UUID without exposing session internals. */
export function subjectUserId(subject: unknown): UUID | null {
  return snapshotAuthorizationSubject(subject)?.user_id ?? null;
}

function requestId(subject: AuthorizationSubject | null): string {
  return subject?.request_id ?? randomUUID();
}

function insufficientPermission(subject: AuthorizationSubject | null): AuthApiError {
  return new AuthApiError(
    "insufficient_permission",
    403,
    "Insufficient permission",
    requestId(subject),
  );
}

function hasPermission(index: PermissionIndex, required: string): boolean {
  if (mapContains(index.exact, required)) return true;
  const separator = keySeparator(required);
  if (separator < 0) return false;
  const action = keyPart(required, separator + 1, required.length);
  if (action === "*") return false;
  const resource = keyPart(required, 0, separator);
  return mapContains(index.resourceWildcards, resource) || index.globalWildcard;
}

function satisfiesRequirement(
  permissions: PermissionIndex,
  requirement: NormalizedRequirement,
): boolean {
  if (requirement.any !== undefined) {
    let anySatisfied = false;
    for (let index = 0; index < requirement.any.length; index += 1) {
      const required = requirement.any[index];
      if (required !== undefined && hasPermission(permissions, required)) {
        anySatisfied = true;
        break;
      }
    }
    if (!anySatisfied) return false;
  }

  if (requirement.all !== undefined) {
    for (let index = 0; index < requirement.all.length; index += 1) {
      const required = requirement.all[index];
      if (required === undefined || !hasPermission(permissions, required)) return false;
    }
  }
  return true;
}

/** Server-only dynamic authorization service. */
export class AuthorizationService {
  private readonly authorization: AuthorizationRepository;
  private readonly effectivePermissions: AuthorizationRepository["effectivePermissions"];
  private readonly clock: () => Date;

  constructor(options: AuthorizationServiceOptions) {
    if (options === null || typeof options !== "object") {
      throw new AuthConfigurationError("authorization repository is incomplete");
    }
    const source = options as unknown as object;

    const repositoryProperty = ownDataProperty(source, "repository");
    if (!repositoryProperty.valid || !repositoryProperty.present) {
      throw new AuthConfigurationError("authorization repository is incomplete");
    }
    const repository = repositoryProperty.value;
    if (repository === null || (typeof repository !== "object" && typeof repository !== "function")) {
      throw new AuthConfigurationError("authorization repository is incomplete");
    }

    const authorizationProperty = ownDataProperty(repository, "authorization");
    if (!authorizationProperty.valid || !authorizationProperty.present) {
      throw new AuthConfigurationError("authorization repository is incomplete");
    }
    const authorization = authorizationProperty.value;
    if (authorization === null || (typeof authorization !== "object" && typeof authorization !== "function")) {
      throw new AuthConfigurationError("authorization repository is incomplete");
    }

    const effectivePermissionsProperty = ownDataProperty(authorization, "effectivePermissions");
    if (!effectivePermissionsProperty.valid || !effectivePermissionsProperty.present || typeof effectivePermissionsProperty.value !== "function") {
      throw new AuthConfigurationError("authorization repository is incomplete");
    }
    const effectivePermissions = captureAuthorizationFunction(
      effectivePermissionsProperty.value,
      "authorization repository.effectivePermissions",
    );

    const clockProperty = ownDataProperty(source, "clock");
    if (!clockProperty.valid) {
      throw new AuthConfigurationError("authorization clock must be a function");
    }
    const configuredClock = clockProperty.present ? clockProperty.value : undefined;
    if (configuredClock !== undefined && typeof configuredClock !== "function") {
      throw new AuthConfigurationError("authorization clock must be a function");
    }

    this.authorization = authorization as AuthorizationRepository;
    this.effectivePermissions = effectivePermissions as AuthorizationRepository["effectivePermissions"];
    this.clock = captureAuthorizationClock(configuredClock);
    validNow(this.clock);
  }

  private async resolvePermissions(
    userId: UUID,
    scope: AuthorizationScope | undefined,
  ): Promise<PermissionIndex> {
    const normalized = normalizedScope(scope);
    if (normalized === null) return createEmptyPermissionIndex();
    const options: RepositoryOperationOptions = { now: validNow(this.clock) };
    try {
      const rawRecords = invoke<unknown>(
        this.effectivePermissions,
        this.authorization,
        [userId, normalized, options],
      );
      let records: unknown;
      if (arrayIsArray(rawRecords)) {
        records = rawRecords;
      } else {
        const outcome = nativePromiseOutcome(rawRecords);
        if (outcome === null) return createEmptyPermissionIndex();
        if (!isOwnedPromiseSignal(outcome.signal)) return createEmptyPermissionIndex();
        await outcome.signal;
        if (outcome.state.rejected) return createEmptyPermissionIndex();
        records = outcome.state.value;
      }
      const snapshot = snapshotPermissionArray(records);
      if (snapshot === null) return createEmptyPermissionIndex();

      const recordsSnapshot: Permission[] = [];
      for (let index = 0; index < snapshot.length; index += 1) {
        const record = completePermissionRecord(snapshot[index]);
        if (record === null) return createEmptyPermissionIndex();
        appendValue(recordsSnapshot, record);
      }
      return permissionIndex(recordsSnapshot);
    } catch {
      // Missing/corrupt authorization data and adapter failures are fail closed.
      return createEmptyPermissionIndex();
    }
  }

  private contextForUser(
    context: AuthorizationRequestContext | undefined,
    userId: UUID,
  ): RequestContextState | null {
    if (context === undefined) return null;
    if (context === null || typeof context !== "object") return null;
    const state = invoke<RequestContextState | undefined>(weakMapGet, requestContextOwnership, [context]);
    if (state === undefined || state.subject.user_id !== userId) return null;
    return state;
  }

  /** Resolves normalized effective permission keys for a user and optional scope. */
  async getPermissions(
    userId: UUID,
    scope?: AuthorizationScope,
    context?: AuthorizationRequestContext,
  ): Promise<readonly string[]> {
    const validatedUserId = safeUserId(userId);
    const normalized = normalizedScope(scope);
    if (validatedUserId === null || normalized === null) return publicPermissionArray([]);

    const requestContext = this.contextForUser(context, validatedUserId);
    if (context !== undefined && requestContext === null) return publicPermissionArray([]);
    if (requestContext !== null) {
      const resolved = await contextPermissions(
        requestContext,
        this,
        normalized,
        () => this.resolvePermissions(validatedUserId, normalized),
      );
      return publicPermissionArray(resolved.keys);
    }
    return publicPermissionArray((await this.resolvePermissions(validatedUserId, normalized)).keys);
  }

  /**
   * Authorizes one validated request-local subject. A supplied context must
   * be created for that same subject; without one, this check has no cache.
   */
  async authorize(
    subject: unknown,
    requirement: AuthorizationRequirement,
    context?: AuthorizationRequestContext,
  ): Promise<AuthorizationSubject> {
    const boundSubject = snapshotAuthorizationSubject(subject);
    const normalized = normalizedRequirement(requirement);
    if (boundSubject === null || normalized === null) {
      throw insufficientPermission(boundSubject);
    }

    const requestContext = this.contextForUser(context, boundSubject.user_id);
    if (context !== undefined && requestContext === null) {
      throw insufficientPermission(boundSubject);
    }
    const permissions = requestContext === null
      ? await this.resolvePermissions(boundSubject.user_id, normalized.scope)
      : await contextPermissions(
        requestContext,
        this,
        normalized.scope,
        () => this.resolvePermissions(boundSubject.user_id, normalized.scope),
      );
    if (!satisfiesRequirement(permissions, normalized)) {
      throw insufficientPermission(boundSubject);
    }
    return requestContext?.subject ?? boundSubject;
  }
}
