import type { AuthRepository, KeyProvider } from "../shared/contracts.js";
import { AuthConfigurationError } from "../shared/errors.js";

const objectCreate = Object.create;
const objectDefineProperty = Object.defineProperty;
const objectFreeze = Object.freeze;
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const objectGetPrototypeOf = Object.getPrototypeOf;
const reflectApply = Reflect.apply;
const MAX_PROTOTYPE_DEPTH = 32;

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
    const descriptor = objectGetOwnPropertyDescriptor(value, key);
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
  const seen = new Set<object>();
  for (let depth = 0; current !== null && depth < MAX_PROTOTYPE_DEPTH; depth += 1) {
    if (seen.has(current)) return { valid: false, present: true };
    seen.add(current);
    let descriptor: PropertyDescriptor | undefined;
    try {
      descriptor = objectGetOwnPropertyDescriptor(current, key);
    } catch {
      return { valid: false, present: false };
    }
    if (descriptor !== undefined) {
      if (!("value" in descriptor)) return { valid: false, present: true };
      return { valid: true, present: true, value: descriptor.value };
    }
    try {
      current = objectGetPrototypeOf(current);
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
  const seen = new Set<object>();
  for (let depth = 0; current !== null && depth < MAX_PROTOTYPE_DEPTH; depth += 1) {
    if (seen.has(current)) return true;
    seen.add(current);
    try {
      if (objectGetOwnPropertyDescriptor(current, "then") !== undefined) return true;
      current = objectGetPrototypeOf(current);
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
  const facade = objectCreate(null) as Record<string, unknown>;
  for (const [property, propertyValue] of Object.entries(properties)) {
    objectDefineProperty(facade, property, {
      configurable: false,
      enumerable: true,
      writable: false,
      value: propertyValue,
    });
  }
  const capture = (method: string): void => {
    const property = boundaryDataProperty(source, method);
    if (!property.valid || !property.present) {
      throw new AuthConfigurationError(`${label}.${method} must be a data-property function`);
    }
    const callback = captureBoundaryFunction(property.value, `${label}.${method}`);
    objectDefineProperty(facade, method, {
      configurable: false,
      enumerable: true,
      writable: false,
      value: (...args: unknown[]) => reflectApply(callback, receiver === "facade" ? facade : source, args),
    });
  };
  for (const method of required) capture(method);
  for (const method of optional) {
    const property = boundaryDataProperty(source, method);
    if (!property.valid) throw new AuthConfigurationError(`${label}.${method} must be a data-property function`);
    if (!property.present) continue;
    capture(method);
  }
  return objectFreeze(facade);
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
  maximum = 100_000,
): readonly string[] {
  if (!Array.isArray(value) || boundaryHasThen(value)) {
    throw new AuthConfigurationError(`${label} must be a data array`);
  }
  const lengthProperty = boundaryOwnDataProperty(value, "length");
  if (!lengthProperty.valid || !lengthProperty.present || typeof lengthProperty.value !== "number" || !Number.isSafeInteger(lengthProperty.value) || lengthProperty.value < minimum || lengthProperty.value > maximum) {
    throw new AuthConfigurationError(`${label} must be a bounded string array`);
  }
  const length = lengthProperty.value as number;
  const names = Object.getOwnPropertyNames(value);
  if (Object.getOwnPropertySymbols(value).length > 0 || names.length !== length + 1 || names.some((name) => name !== "length" && (!/^\d+$/u.test(name) || Number(name) >= length))) {
    throw new AuthConfigurationError(`${label} must be a dense string array`);
  }
  const copy: string[] = [];
  for (let index = 0; index < length; index += 1) {
    const property = boundaryOwnDataProperty(value, String(index));
    if (!property.valid || !property.present || typeof property.value !== "string") {
      throw new AuthConfigurationError(`${label} must be a dense string array`);
    }
    copy.push(property.value);
  }
  return objectFreeze(copy);
}

/** Captures the complete repository method tree, including transaction scopes. */
export function captureBoundaryRepository(value: unknown): AuthRepository {
  if (value === null || (typeof value !== "object" && typeof value !== "function")) {
    throw new AuthConfigurationError("database repository is incomplete");
  }
  const source = value as object;
  assertBoundaryObject(source, "database repository");
  const methods: Readonly<Record<string, readonly string[]>> = {
    root: ["transaction"],
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
  const facade = objectCreate(null) as Record<string, unknown>;
  for (const [member, memberMethods] of Object.entries(methods)) {
    if (member === "root") {
      const transactionProperty = boundaryDataProperty(source, "transaction");
      if (!transactionProperty.valid || !transactionProperty.present) throw new AuthConfigurationError("database.transaction must be a data-property function");
      const transaction = captureBoundaryFunction(transactionProperty.value, "database.transaction");
      objectDefineProperty(facade, "transaction", {
        configurable: false,
        enumerable: true,
        writable: false,
        value: (...args: unknown[]) => {
          const callback = args[0];
          if (typeof callback !== "function") return reflectApply(transaction, source, args);
          const wrapped = (transactionRepository: unknown, ...callbackArgs: unknown[]) => reflectApply(
            callback,
            undefined,
            [captureBoundaryRepository(transactionRepository), ...callbackArgs],
          );
          return reflectApply(transaction, source, [wrapped, ...args.slice(1)]);
        },
      });
      continue;
    }
    const memberProperty = boundaryDataProperty(source, member);
    if (!memberProperty.valid || !memberProperty.present) throw new AuthConfigurationError(`database.${member} is incomplete`);
    objectDefineProperty(facade, member, {
      configurable: false,
      enumerable: true,
      writable: false,
      value: captureBoundaryMethodGroup(memberProperty.value, `database.${member}`, memberMethods),
    });
  }
  return objectFreeze(facade) as unknown as AuthRepository;
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
