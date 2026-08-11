import { describe, expect, it } from "vitest";
import {
  AuthorizationService,
  createAuthorizationRequestContext,
  normalizePermissionKey,
  permissionMatchRank,
  permissionMatches,
} from "../../src/server/authorization.js";
import { permissionsRoute } from "../../src/server/routes/permissions.js";
import type { AuthRepository } from "../../src/shared/contracts.js";
import {
  lowercaseKeySchema,
  permissionKeySchema,
  scopeIdentifierSchema,
  uuidSchema,
  type AuthorizationScope,
  type Permission,
  type UUID,
} from "../../src/shared/types.js";

const NOW = new Date("2026-08-11T00:00:00.000Z");
const USER_ID = uuidSchema.parse("00000000-0000-4000-8000-000000000001");
const OTHER_USER_ID = uuidSchema.parse("00000000-0000-4000-8000-000000000002");

function permission(key: string): Permission {
  const [resource, action] = key.split(".");
  return {
    id: uuidSchema.parse("00000000-0000-4000-8000-000000000010"),
    key: permissionKeySchema.parse(key),
    resource: lowercaseKeySchema.parse(resource),
    action: lowercaseKeySchema.parse(action),
    description: null,
    created_at: NOW.toISOString(),
    updated_at: NOW.toISOString(),
  };
}

function serviceFor(
  effectivePermissions: (
    userId: UUID,
    scope?: AuthorizationScope,
  ) => Promise<unknown> | unknown,
): AuthorizationService {
  const repository = {
    authorization: { effectivePermissions },
  } as unknown as AuthRepository;
  return new AuthorizationService({ repository, clock: () => NOW });
}

function subject(userId: UUID = USER_ID): { readonly user_id: UUID; readonly request_id: string } {
  return { user_id: userId, request_id: "req-authorization" };
}

async function expectInsufficient(operation: Promise<unknown>): Promise<void> {
  await expect(operation).rejects.toMatchObject({
    code: "insufficient_permission",
    status: 403,
  });
}

async function captureFailure(operation: Promise<unknown>): Promise<unknown> {
  try {
    await operation;
    return null;
  } catch (error) {
    return error;
  }
}

async function withPrototypeValue<T>(
  value: unknown,
  callback: () => Promise<T>,
): Promise<T> {
  return withPrototypeProperty("value", {
    configurable: true,
    enumerable: false,
    value,
    writable: true,
  }, callback);
}

async function withPrototypeProperty<T>(
  key: PropertyKey,
  descriptor: PropertyDescriptor,
  callback: () => Promise<T>,
): Promise<T> {
  const original = Object.getOwnPropertyDescriptor(Object.prototype, key);
  Object.defineProperty(Object.prototype, key, descriptor);
  try {
    return await callback();
  } finally {
    if (original === undefined) {
      Reflect.deleteProperty(Object.prototype, key);
    } else {
      Object.defineProperty(Object.prototype, key, original);
    }
  }
}

function generatedPermission(index: number): Permission {
  const resource = `resource_${index.toString(36)}` as Permission["resource"];
  return {
    id: "00000000-0000-4000-8000-000000000010" as Permission["id"],
    key: `${resource}.read` as Permission["key"],
    resource,
    action: "read" as Permission["action"],
    description: null,
    created_at: NOW.toISOString(),
    updated_at: NOW.toISOString(),
  };
}

describe("authorization permission matching", () => {
  it("accepts canonical exact resource.action keys and rejects non-canonical keys", () => {
    expect(normalizePermissionKey("invoice.read")).toBe("invoice.read");
    expect(() => normalizePermissionKey("Invoice.Read")).toThrow();
    expect(() => normalizePermissionKey("invoice.*.read")).toThrow();
    expect(() => normalizePermissionKey("*.read")).toThrow();
  });

  it("matches exact permissions before resource and global wildcards", () => {
    expect(permissionMatches("invoice.read", "invoice.read")).toBe(true);
    expect(permissionMatches("invoice.*", "invoice.read")).toBe(true);
    expect(permissionMatches("*.*", "invoice.read")).toBe(true);
    expect(permissionMatches("payment.*", "invoice.read")).toBe(false);
    expect(permissionMatches("invoice.read", "invoice.update")).toBe(false);
    expect(permissionMatches("invoice.read", "invoice.*")).toBe(false);
  });

  it("uses deterministic exact > resource wildcard > global precedence", () => {
    expect(permissionMatchRank("invoice.read", "invoice.read")).toBe(3);
    expect(permissionMatchRank("invoice.*", "invoice.read")).toBe(2);
    expect(permissionMatchRank("*.*", "invoice.read")).toBe(1);
    expect(permissionMatchRank("payment.*", "invoice.read")).toBe(0);
  });

  it("fails closed for malformed grants and requirements", () => {
    expect(permissionMatches("Invoice.read", "invoice.read")).toBe(false);
    expect(permissionMatches("invoice.*.read", "invoice.read")).toBe(false);
    expect(permissionMatches("invoice.read", "Invoice.read")).toBe(false);
    expect(permissionMatchRank("*.*", "not-a-permission")).toBe(0);
  });

  it("rejects iterator-hidden and empty all/any requirements", async () => {
    const service = serviceFor(() => []);
    const all = ["invoice.read"] as string[];
    Object.defineProperty(all, Symbol.iterator, {
      configurable: true,
      value: function* emptyIterator() {
        // A non-empty caller array must not be normalized through this iterator.
      },
    });

    await expectInsufficient(service.authorize(subject(), { all }));
    await expectInsufficient(service.authorize(subject(), { all: [] }));
    await expectInsufficient(service.authorize(subject(), { any: [] }));
  });

  it("rejects sparse, accessor-backed, inherited, and changing requirement objects", async () => {
    const service = serviceFor(() => [permission("invoice.read")]);
    const sparse = new Array<string>(1);
    await expectInsufficient(service.authorize(subject(), { all: sparse }));

    let fieldReads = 0;
    const changingField = {} as { readonly all?: readonly string[] };
    Object.defineProperty(changingField, "all", {
      configurable: true,
      get() {
        fieldReads += 1;
        return [fieldReads === 1 ? "invoice.read" : "secret.read"];
      },
    });
    await expectInsufficient(service.authorize(subject(), changingField));
    expect(fieldReads).toBe(0);

    const throwingField = {} as { readonly all?: readonly string[] };
    Object.defineProperty(throwingField, "all", {
      configurable: true,
      get() {
        throw new Error("requirement getter must not run");
      },
    });
    await expectInsufficient(service.authorize(subject(), throwingField));

    const inherited = Object.create({ all: ["invoice.read"] }) as { readonly all?: readonly string[] };
    await expectInsufficient(service.authorize(subject(), inherited));

    const accessorElement = [] as string[];
    Object.defineProperty(accessorElement, "0", {
      configurable: true,
      get() {
        throw new Error("array element getter must not run");
      },
    });
    await expectInsufficient(service.authorize(subject(), { all: accessorElement }));
  });

  it("requires one own UUID user_id and never invokes or rereads identity accessors", async () => {
    const service = serviceFor((userId) => userId === USER_ID ? [permission("invoice.read")] : []);

    const inherited = Object.create({ user_id: USER_ID }) as { readonly user_id: UUID };
    await expectInsufficient(service.authorize(inherited, { all: ["invoice.read"] }));

    await expectInsufficient(service.authorize(
      { user_id: "not-a-uuid" } as unknown as { readonly user_id: UUID },
      { all: ["invoice.read"] },
    ));
    await expectInsufficient(service.authorize(
      { user_id: 123 } as unknown as { readonly user_id: UUID },
      { all: ["invoice.read"] },
    ));

    let reads = 0;
    const accessorSubject = {} as { readonly user_id: UUID };
    Object.defineProperty(accessorSubject, "user_id", {
      configurable: true,
      get() {
        reads += 1;
        return USER_ID;
      },
    });
    await expectInsufficient(service.authorize(accessorSubject, { all: ["invoice.read"] }));
    expect(reads).toBe(0);
  });

  it("binds a changing route subject once instead of crossing users", async () => {
    const service = serviceFor((userId) => userId === USER_ID ? [permission("invoice.read")] : []);
    let reads = 0;
    const changingSubject = new Proxy({ user_id: USER_ID } as { readonly user_id: UUID }, {
      get(target, property, receiver) {
        if (property === "user_id") {
          reads += 1;
          return reads === 1 ? USER_ID : OTHER_USER_ID;
        }
        return Reflect.get(target, property, receiver);
      },
    });

    const response = await permissionsRoute(
      service,
      new Request("https://project.example.com/user/permissions"),
      changingSubject,
    );
    expect(response.status).toBe(200);
    expect((await response.json()).data.permissions).toEqual(["invoice.read"]);
    expect(reads).toBe(0);
  });

  it("rejects NUL scope identities instead of allowing cache-key collisions", async () => {
    const service = serviceFor(() => [permission("invoice.read")]);
    const first: AuthorizationScope = {
      type: "tenant\u0000alpha",
      id: scopeIdentifierSchema.parse("beta"),
    };
    const colliding: AuthorizationScope = {
      type: "tenant",
      id: scopeIdentifierSchema.parse("alpha\u0000beta"),
    };

    await expectInsufficient(service.authorize(subject(), { all: ["invoice.read"], scope: first }));
    await expectInsufficient(service.authorize(subject(), { all: ["invoice.read"], scope: colliding }));
  });

  it("does not inherit scope, any, or all from Object.prototype after normalization", async () => {
    const scopedOnlyService = serviceFor((_userId, requestedScope) => (
      requestedScope?.type === "tenant" && requestedScope.id === "tenant_1"
        ? [permission("invoice.read")]
        : []
    ));
    const pollutedScope: AuthorizationScope = {
      type: "tenant",
      id: scopeIdentifierSchema.parse("tenant_1"),
    };
    const unscopedFailure = await withPrototypeProperty(
      "scope",
      { configurable: true, enumerable: false, value: pollutedScope, writable: true },
      () => captureFailure(scopedOnlyService.authorize(subject(), { all: ["invoice.read"] })),
    );
    expect(unscopedFailure).toMatchObject({ code: "insufficient_permission", status: 403 });

    const grantService = serviceFor(() => [permission("invoice.read")]);
    const anyPollutionFailure = await withPrototypeProperty(
      "any",
      { configurable: true, enumerable: false, value: ["secret.read"], writable: true },
      () => captureFailure(grantService.authorize(subject(), { all: ["invoice.read"] })),
    );
    expect(anyPollutionFailure).toBeNull();

    const allPollutionFailure = await withPrototypeProperty(
      "all",
      { configurable: true, enumerable: false, value: ["secret.read"], writable: true },
      () => captureFailure(grantService.authorize(subject(), { any: ["invoice.read"] })),
    );
    expect(allPollutionFailure).toBeNull();
  });

  it("ignores throwing inherited scope, any, and all getters", async () => {
    const service = serviceFor(() => [permission("invoice.read")]);
    const throwing = () => {
      throw new Error("inherited requirement getter must not run");
    };

    const scopeResult = await withPrototypeProperty(
      "scope",
      { configurable: true, enumerable: false, get: throwing },
      () => captureFailure(service.authorize(subject(), { all: ["invoice.read"] })),
    );
    expect(scopeResult).toBeNull();

    const anyResult = await withPrototypeProperty(
      "any",
      { configurable: true, enumerable: false, get: throwing },
      () => captureFailure(service.authorize(subject(), { all: ["invoice.read"] })),
    );
    expect(anyResult).toBeNull();

    const allResult = await withPrototypeProperty(
      "all",
      { configurable: true, enumerable: false, get: throwing },
      () => captureFailure(service.authorize(subject(), { any: ["invoice.read"] })),
    );
    expect(allResult).toBeNull();
  });

  it("rejects non-array iterables and incomplete or inherited permission rows", async () => {
    const valid = permission("invoice.read");

    const iterableService = serviceFor(() => new Set([valid]));
    expect(await iterableService.getPermissions(USER_ID)).toEqual([]);

    const iteratorHidden = [valid] as Permission[];
    Object.defineProperty(iteratorHidden, Symbol.iterator, {
      configurable: true,
      value: function* emptyIterator() {
        // Adapter arrays are snapshotted numerically, never through this iterator.
      },
    });
    const iteratorService = serviceFor(() => iteratorHidden);
    expect(await iteratorService.getPermissions(USER_ID)).toEqual(["invoice.read"]);

    const partialService = serviceFor(() => [{ key: valid.key, resource: valid.resource, action: valid.action }]);
    expect(await partialService.getPermissions(USER_ID)).toEqual([]);

    const inherited = Object.create(valid) as Partial<Permission>;
    const inheritedService = serviceFor(() => [inherited]);
    expect(await inheritedService.getPermissions(USER_ID)).toEqual([]);
  });

  it("rejects accessor-backed adapter rows and array elements without invoking them", async () => {
    const valid = permission("invoice.read");
    let rowReads = 0;
    const row = { ...valid } as Record<string, unknown>;
    Object.defineProperty(row, "key", {
      configurable: true,
      get() {
        rowReads += 1;
        return valid.key;
      },
    });
    const rowService = serviceFor(() => [row]);
    expect(await rowService.getPermissions(USER_ID)).toEqual([]);
    expect(rowReads).toBe(0);

    const rows = new Array<Permission>(1);
    Object.defineProperty(rows, "0", {
      configurable: true,
      get() {
        throw new Error("adapter array getter must not run");
      },
    });
    const arrayService = serviceFor(() => rows);
    expect(await arrayService.getPermissions(USER_ID)).toEqual([]);
  });

  it("rejects non-native adapter thenables and polluted then properties", async () => {
    const valid = permission("invoice.read");
    const resolvingThenable = {
      then(resolve: (value: unknown) => void) {
        resolve([valid]);
      },
    };
    const directThenableService = serviceFor(() => resolvingThenable);
    await expectInsufficient(directThenableService.authorize(subject(), { all: ["invoice.read"] }));

    let getterReads = 0;
    const getterThenable = {} as Record<string, unknown>;
    Object.defineProperty(getterThenable, "then", {
      configurable: true,
      get() {
        getterReads += 1;
        return (resolve: (value: unknown) => void) => resolve([valid]);
      },
    });
    await expectInsufficient(serviceFor(() => getterThenable).authorize(subject(), { all: ["invoice.read"] }));
    expect(getterReads).toBe(0);

    const originalThen = Object.getOwnPropertyDescriptor(Object.prototype, "then");
    let pollutedThenRejected = false;
    Object.defineProperty(Object.prototype, "then", {
      configurable: true,
      enumerable: false,
      value(resolve: (value: unknown) => void) {
        resolve([valid]);
      },
      writable: true,
    });
    try {
      try {
        await serviceFor(() => [valid]).authorize(subject(), { all: ["invoice.read"] });
      } catch (error) {
        pollutedThenRejected = (error as { readonly code?: unknown }).code === "insufficient_permission";
      }
    } finally {
      if (originalThen === undefined) Reflect.deleteProperty(Object.prototype, "then");
      else Object.defineProperty(Object.prototype, "then", originalThen);
    }
    expect(pollutedThenRejected).toBe(true);

    const rejectedThenable = {
      then(_resolve: (value: unknown) => void, reject: (reason: unknown) => void) {
        reject(new Error("thenable rejection"));
      },
    };
    await expectInsufficient(serviceFor(() => rejectedThenable).authorize(subject(), { all: ["invoice.read"] }));

    await expect(
      serviceFor(() => Promise.resolve([valid])).authorize(subject(), { all: ["invoice.read"] }),
    ).resolves.toMatchObject({ user_id: USER_ID });

    let speciesReads = 0;
    class ForgedPromise extends Promise<unknown> {
      static get [Symbol.species](): PromiseConstructor {
        speciesReads += 1;
        return Promise;
      }
    }
    const subclassPromise = new ForgedPromise((resolve) => resolve([valid]));
    await expectInsufficient(
      serviceFor(() => subclassPromise).authorize(subject(), { all: ["invoice.read"] }),
    );
    expect(speciesReads).toBe(0);

    let constructorReads = 0;
    const constructorPromise = Promise.resolve([valid]);
    Object.defineProperty(constructorPromise, "constructor", {
      configurable: true,
      get() {
        constructorReads += 1;
        return Promise;
      },
    });
    await expectInsufficient(
      serviceFor(() => constructorPromise).authorize(subject(), { all: ["invoice.read"] }),
    );
    expect(constructorReads).toBe(0);

    await expectInsufficient(
      serviceFor(() => Promise.reject(new Error("native rejection"))).authorize(
        subject(),
        { all: ["invoice.read"] },
      ),
    );
  });

  it("rejects descriptor accessors when Object.prototype.value is polluted", async () => {
    const service = serviceFor(() => [permission("invoice.read")]);

    let subjectReads = 0;
    const accessorSubject = {} as { readonly user_id: UUID };
    Object.defineProperty(accessorSubject, "user_id", {
      configurable: true,
      get() {
        subjectReads += 1;
        return USER_ID;
      },
    });
    const subjectFailure = await withPrototypeValue(
      USER_ID,
      () => captureFailure(service.authorize(accessorSubject, { all: ["invoice.read"] })),
    );
    expect(subjectFailure).toMatchObject({ code: "insufficient_permission", status: 403 });
    expect(subjectReads).toBe(0);

    for (const field of ["all", "any"] as const) {
      let reads = 0;
      const requirement = {} as Record<string, unknown>;
      Object.defineProperty(requirement, field, {
        configurable: true,
        get() {
          reads += 1;
          return ["invoice.read"];
        },
      });
      const failure = await withPrototypeValue(
        ["invoice.read"],
        () => captureFailure(service.authorize(subject(), requirement as never)),
      );
      expect(failure).toMatchObject({ code: "insufficient_permission", status: 403 });
      expect(reads).toBe(0);
    }

    let scopeReads = 0;
    const scopeRequirement = { all: ["invoice.read"] } as Record<string, unknown>;
    const pollutedScope: AuthorizationScope = {
      type: "tenant",
      id: scopeIdentifierSchema.parse("tenant_1"),
    };
    Object.defineProperty(scopeRequirement, "scope", {
      configurable: true,
      get() {
        scopeReads += 1;
        return pollutedScope;
      },
    });
    const scopeFailure = await withPrototypeValue(
      pollutedScope,
      () => captureFailure(service.authorize(subject(), scopeRequirement as never)),
    );
    expect(scopeFailure).toMatchObject({ code: "insufficient_permission", status: 403 });
    expect(scopeReads).toBe(0);

    const valid = permission("invoice.read");
    let elementReads = 0;
    const rows = new Array<Permission>(1);
    Object.defineProperty(rows, "0", {
      configurable: true,
      get() {
        elementReads += 1;
        return valid;
      },
    });
    const elementService = serviceFor(() => rows);
    const elementResult = await withPrototypeValue(valid, () => elementService.getPermissions(USER_ID));
    expect(elementResult).toEqual([]);
    expect(elementReads).toBe(0);

    for (const field of [
      "id",
      "key",
      "resource",
      "action",
      "description",
      "created_at",
      "updated_at",
    ] as const) {
      let reads = 0;
      const row = { ...valid } as Record<string, unknown>;
      const fieldValue = row[field];
      Object.defineProperty(row, field, {
        configurable: true,
        get() {
          reads += 1;
          return fieldValue;
        },
      });
      const rowService = serviceFor(() => [row]);
      const result = await withPrototypeValue(fieldValue, () => rowService.getPermissions(USER_ID, undefined));
      expect(result, field).toEqual([]);
      expect(reads, field).toBe(0);
    }
  });

  it("does not depend on mutable Set or Array prototype methods", async () => {
    const valid = permission("invoice.read");
    const service = serviceFor(() => [valid]);
    const originalAdd = Set.prototype.add;
    const originalSome = Array.prototype.some;
    const originalEvery = Array.prototype.every;
    try {
      Set.prototype.add = (() => {
        throw new Error("Set.add was mutated");
      }) as unknown as typeof Set.prototype.add;
      expect(await service.getPermissions(USER_ID)).toEqual(["invoice.read"]);

      Array.prototype.some = (() => {
        throw new Error("Array.some was mutated");
      }) as unknown as typeof Array.prototype.some;
      Array.prototype.every = (() => {
        throw new Error("Array.every was mutated");
      }) as unknown as typeof Array.prototype.every;
      let result: unknown;
      let failure: unknown;
      try {
        result = await service.authorize(subject(), { all: ["invoice.read"] });
      } catch (error) {
        failure = error;
      }
      Set.prototype.add = originalAdd;
      Array.prototype.some = originalSome;
      Array.prototype.every = originalEvery;
      expect(failure).toBeUndefined();
      expect(result).toMatchObject({ user_id: USER_ID });
    } finally {
      Set.prototype.add = originalAdd;
      Array.prototype.some = originalSome;
      Array.prototype.every = originalEvery;
    }
  });

  it("returns copied frozen standard arrays with normal public collection behavior", async () => {
    const service = serviceFor(() => [permission("invoice.read"), permission("invoice.write")]);
    const first = await service.getPermissions(USER_ID);
    const second = await service.getPermissions(USER_ID);

    expect(Array.isArray(first)).toBe(true);
    expect(Object.getPrototypeOf(first)).toBe(Array.prototype);
    expect([...first]).toEqual(["invoice.read", "invoice.write"]);
    const iterated: string[] = [];
    for (const key of first) iterated.push(key);
    expect(iterated).toEqual(["invoice.read", "invoice.write"]);
    const iterator = first[Symbol.iterator]();
    expect(iterator.next()).toEqual({ value: "invoice.read", done: false });
    expect(first.map((key) => key.toUpperCase())).toEqual(["INVOICE.READ", "INVOICE.WRITE"]);
    expect(first.includes("invoice.write")).toBe(true);
    expect(first).toEqual(["invoice.read", "invoice.write"]);
    expect(first).not.toBe(second);
    expect(Object.isFrozen(first)).toBe(true);

    const thenDescriptor = Object.getOwnPropertyDescriptor(first, "then");
    expect(thenDescriptor?.value).toBeUndefined();
    expect(thenDescriptor?.writable).toBe(false);
    expect(thenDescriptor?.enumerable).toBe(false);
    expect(thenDescriptor?.configurable).toBe(false);
    expect(Reflect.set(first as object, "0", "forged")).toBe(false);
    expect(first[0]).toBe("invoice.read");

    const context = createAuthorizationRequestContext(subject());
    expect(context).not.toBeNull();
    if (context !== null) {
      const contextResult = await service.getPermissions(USER_ID, undefined, context);
      expect(Object.getPrototypeOf(contextResult)).toBe(Array.prototype);
      expect([...contextResult]).toEqual(["invoice.read", "invoice.write"]);
      expect(Object.isFrozen(contextResult)).toBe(true);
    }
  });

  it("returns standard empty arrays and shields the async boundary from then pollution", async () => {
    const emptyService = serviceFor(() => []);
    const invalidScope = { type: "Tenant", id: "tenant_1" } as unknown as AuthorizationScope;
    const emptyResults = [
      await emptyService.getPermissions(USER_ID),
      await emptyService.getPermissions("not-a-uuid" as UUID),
      await emptyService.getPermissions(USER_ID, invalidScope),
      await emptyService.getPermissions(USER_ID, undefined, {} as never),
    ];
    for (const result of emptyResults) {
      expect(Array.isArray(result)).toBe(true);
      expect(Object.getPrototypeOf(result)).toBe(Array.prototype);
      expect([...result]).toEqual([]);
      expect(result.map((key) => key)).toEqual([]);
      expect(result.includes("invoice.read")).toBe(false);
      expect(Object.isFrozen(result)).toBe(true);
      expect(Object.getOwnPropertyDescriptor(result, "then")?.value).toBeUndefined();
      expect(Reflect.set(result as object, "0", "forged")).toBe(false);
    }

    const shieldedRows = [permission("invoice.read")];
    Object.setPrototypeOf(shieldedRows, null);
    const nonEmptyService = serviceFor(() => shieldedRows);
    const shieldedEmptyRows: Permission[] = [];
    Object.setPrototypeOf(shieldedEmptyRows, null);
    const pollutedEmptyService = serviceFor(() => shieldedEmptyRows);
    const scalarUnderPollution = async (
      target: object,
      expected: readonly string[],
    ): Promise<string> => {
      const original = Object.getOwnPropertyDescriptor(target, "then");
      Object.defineProperty(target, "then", {
        configurable: true,
        enumerable: false,
        value(resolve: (value: unknown) => void) {
          resolve("polluted");
        },
        writable: true,
      });
      try {
        const resultPromise = nonEmptyService.getPermissions(USER_ID);
        return await resultPromise.then((result) => {
          if (!Array.isArray(result) || Object.getPrototypeOf(result) !== Array.prototype) return "bad";
          const spread = [...result];
          const loop: string[] = [];
          for (const key of result) loop.push(key);
          const mapped = result.map((key) => key);
          const iteratorResult = result[Symbol.iterator]().next();
          const matches =
            spread.length === expected.length &&
            loop.length === expected.length &&
            mapped.length === expected.length &&
            iteratorResult.value === expected[0] &&
            result.includes(expected[0] ?? "");
          return matches ? "ok" : "bad";
        });
      } finally {
        if (original === undefined) Reflect.deleteProperty(target, "then");
        else Object.defineProperty(target, "then", original);
      }
    };

    expect(await scalarUnderPollution(Object.prototype, ["invoice.read"])).toBe("ok");
    expect(await scalarUnderPollution(Array.prototype, ["invoice.read"])).toBe("ok");

    const emptyScalarUnderPollution = async (target: object): Promise<string> => {
      const original = Object.getOwnPropertyDescriptor(target, "then");
      Object.defineProperty(target, "then", {
        configurable: true,
        enumerable: false,
        value(resolve: (value: unknown) => void) {
          resolve("polluted");
        },
        writable: true,
      });
      try {
        const resultPromise = pollutedEmptyService.getPermissions(USER_ID);
        return await resultPromise.then((result) => {
          if (!Array.isArray(result) || Object.getPrototypeOf(result) !== Array.prototype) return "bad";
          return result.length === 0 && [...result].length === 0 && result.includes("invoice.read") === false
            ? "ok"
            : "bad";
        });
      } finally {
        if (original === undefined) Reflect.deleteProperty(target, "then");
        else Object.defineProperty(target, "then", original);
      }
    };

    expect(await emptyScalarUnderPollution(Object.prototype)).toBe("ok");
    expect(await emptyScalarUnderPollution(Array.prototype)).toBe("ok");
  });

  it("uses explicit request-local contexts and does not reuse stale or cross-user grants", async () => {
    let revoked = false;
    let reads = 0;
    const service = serviceFor((userId) => {
      reads += 1;
      return !revoked && userId === USER_ID ? [permission("invoice.read")] : [];
    });
    const firstContext = createAuthorizationRequestContext(subject());
    expect(firstContext).not.toBeNull();
    if (firstContext === null) return;

    await expect(service.authorize(subject(), { all: ["invoice.read"] }, firstContext)).resolves.toMatchObject({ user_id: USER_ID });
    revoked = true;
    await expect(service.authorize(subject(), { all: ["invoice.read"] }, firstContext)).resolves.toMatchObject({ user_id: USER_ID });

    const freshContext = createAuthorizationRequestContext(subject());
    expect(freshContext).not.toBeNull();
    if (freshContext === null) return;
    await expect(service.authorize(subject(), { all: ["invoice.read"] }, freshContext)).rejects.toMatchObject({ code: "insufficient_permission" });

    const otherContext = createAuthorizationRequestContext(subject(OTHER_USER_ID));
    expect(otherContext).not.toBeNull();
    if (otherContext === null) return;
    await expect(service.authorize(subject(), { all: ["invoice.read"] }, otherContext)).rejects.toMatchObject({ code: "insufficient_permission" });
    expect(reads).toBe(2);
  });

  it("rejects reflected forged contexts and isolates cache state across services", async () => {
    let serviceAReads = 0;
    let serviceBReads = 0;
    const serviceA = serviceFor(async () => {
      serviceAReads += 1;
      return [permission("invoice.read")];
    });
    const serviceB = serviceFor(async () => {
      serviceBReads += 1;
      return [];
    });
    const genuine = createAuthorizationRequestContext(subject());
    expect(genuine).not.toBeNull();
    if (genuine === null) return;

    const forged = Object.create(Object.getPrototypeOf(genuine)) as Record<PropertyKey, unknown>;
    Object.defineProperty(forged, "subject", {
      configurable: true,
      enumerable: true,
      value: genuine.subject,
      writable: false,
    });
    const symbols = Object.getOwnPropertySymbols(genuine);
    let loaderSymbol: symbol | undefined;
    for (let index = 0; index < symbols.length; index += 1) {
      const symbol = symbols[index];
      if (symbol === undefined) continue;
      const descriptor = Object.getOwnPropertyDescriptor(genuine, symbol);
      if (descriptor === undefined) continue;
      if ("value" in descriptor && typeof descriptor.value === "function") {
        loaderSymbol = symbol;
      } else {
        Object.defineProperty(forged, symbol, descriptor);
      }
    }
    if (loaderSymbol !== undefined) {
      Object.defineProperty(forged, loaderSymbol, {
        configurable: true,
        enumerable: false,
        value: async () => ["invoice.read"],
        writable: false,
      });
    }

    await expectInsufficient(serviceB.authorize(subject(), { all: ["invoice.read"] }, forged as never));
    expect(serviceBReads).toBe(0);

    const context = createAuthorizationRequestContext(subject());
    expect(context).not.toBeNull();
    if (context === null) return;
    await expect(serviceA.authorize(subject(), { all: ["invoice.read"] }, context)).resolves.toMatchObject({ user_id: USER_ID });
    await expectInsufficient(serviceB.authorize(subject(), { all: ["invoice.read"] }, context));
    expect(serviceAReads).toBe(1);
    expect(serviceBReads).toBe(1);
  });

  it("deduplicates concurrent authorization reads inside one request context", async () => {
    let reads = 0;
    const service = serviceFor(async () => {
      reads += 1;
      await Promise.resolve();
      return [permission("invoice.read")];
    });
    const context = createAuthorizationRequestContext(subject());
    expect(context).not.toBeNull();
    if (context === null) return;

    const results = await Promise.all([
      service.authorize(subject(), { all: ["invoice.read"] }, context),
      service.authorize(subject(), { all: ["invoice.read"] }, context),
    ]);
    expect(results[0]?.user_id).toBe(USER_ID);
    expect(results[1]?.user_id).toBe(USER_ID);
    expect(reads).toBe(1);
  });

  it("resolves a deterministic large permission result within the practical indexed bound", async () => {
    const rows: Permission[] = [];
    for (let index = 0; index < 100_000; index += 1) {
      rows.push(generatedPermission(index));
    }
    const service = serviceFor(() => rows);
    const resolved = await service.getPermissions(USER_ID);
    expect(resolved).toHaveLength(100_000);
    expect(resolved[0]).toBe("resource_0.read");
    expect(resolved[99_999]).toBe("resource_zzz.read");
  }, 8_000);

  it("evaluates a deterministic large all-requirement without a full grant scan", async () => {
    const requirements: string[] = [];
    for (let index = 0; index < 10_000; index += 1) {
      requirements.push(`resource_${index.toString(36)}.read`);
    }
    const service = serviceFor(() => [permission("*.*")]);
    await expect(service.authorize(subject(), { all: requirements })).resolves.toMatchObject({ user_id: USER_ID });
  }, 8_000);

  it("rejects unknown and malformed query data under URL and RegExp prototype tampering", async () => {
    const service = serviceFor(() => [permission("invoice.read")]);
    const originalKeys = URLSearchParams.prototype.keys;
    const originalGet = URLSearchParams.prototype.get;
    const originalGetAll = URLSearchParams.prototype.getAll;
    const originalTest = RegExp.prototype.test;

    let response: Response;
    try {
      URLSearchParams.prototype.keys = (() => (function* emptyKeys() {})()) as typeof URLSearchParams.prototype.keys;
      URLSearchParams.prototype.get = (() => null) as typeof URLSearchParams.prototype.get;
      URLSearchParams.prototype.getAll = (() => []) as typeof URLSearchParams.prototype.getAll;
      RegExp.prototype.test = (() => true) as typeof RegExp.prototype.test;
      response = await permissionsRoute(
        service,
        new Request("https://project.example.com/user/permissions?unknown=grant"),
        subject(),
      );
    } finally {
      URLSearchParams.prototype.keys = originalKeys;
      URLSearchParams.prototype.get = originalGet;
      URLSearchParams.prototype.getAll = originalGetAll;
      RegExp.prototype.test = originalTest;
    }
    expect(response.status).toBe(400);

    const duplicateOriginalGetAll = URLSearchParams.prototype.getAll;
    try {
      URLSearchParams.prototype.getAll = (() => []) as typeof URLSearchParams.prototype.getAll;
      response = await permissionsRoute(
        service,
        new Request("https://project.example.com/user/permissions?scope_type=tenant&scope_type=other&scope_id=one"),
        subject(),
      );
    } finally {
      URLSearchParams.prototype.getAll = duplicateOriginalGetAll;
    }
    expect(response.status).toBe(400);

    const malformedOriginalGet = URLSearchParams.prototype.get;
    try {
      URLSearchParams.prototype.get = (() => null) as typeof URLSearchParams.prototype.get;
      response = await permissionsRoute(
        service,
        new Request("https://project.example.com/user/permissions?scope_type=TENANT&scope_id=one"),
        subject(),
      );
    } finally {
      URLSearchParams.prototype.get = malformedOriginalGet;
    }
    expect(response.status).toBe(400);
  });

  it("rejects unknown and duplicate queries when URLSearchParams keys and next are tampered", async () => {
    const service = serviceFor(() => [permission("invoice.read")]);
    const originalKeys = URLSearchParams.prototype.keys;
    const unknownRequest = new Request("https://project.example.com/user/permissions?unknown=grant");
    const duplicateRequest = new Request("https://project.example.com/user/permissions?scope_type=tenant&scope_type=other&scope_id=one");
    const iterator = originalKeys.call(new URLSearchParams("unknown=grant"));
    const iteratorPrototype = Object.getPrototypeOf(iterator) as {
      next: () => IteratorResult<string>;
    };
    const originalNext = iteratorPrototype.next;
    let unknownResponse: Response;
    let duplicateResponse: Response;
    try {
      URLSearchParams.prototype.keys = (() => {
        throw new Error("URLSearchParams.keys was mutated");
      }) as typeof URLSearchParams.prototype.keys;
      iteratorPrototype.next = (() => ({ done: true, value: undefined })) as typeof iteratorPrototype.next;
      unknownResponse = await permissionsRoute(service, unknownRequest, subject());
      duplicateResponse = await permissionsRoute(service, duplicateRequest, subject());
    } finally {
      URLSearchParams.prototype.keys = originalKeys;
      iteratorPrototype.next = originalNext;
    }
    expect(unknownResponse.status).toBe(400);
    expect(duplicateResponse.status).toBe(400);
  });

  it("rejects NUL scope IDs when String.prototype.includes is tampered", async () => {
    const service = serviceFor(() => [permission("invoice.read")]);
    const originalIncludes = String.prototype.includes;
    const request = new Request("https://project.example.com/user/permissions?scope_type=tenant&scope_id=tenant%00one");
    let response: Response;
    try {
      String.prototype.includes = (() => false) as typeof String.prototype.includes;
      response = await permissionsRoute(service, request, subject());
    } finally {
      String.prototype.includes = originalIncludes;
    }
    expect(response.status).toBe(400);
  });

  it("keeps insufficient-permission request IDs own, valid, and bounded", async () => {
    const service = serviceFor(() => []);

    const polluted = await withPrototypeProperty(
      "request_id",
      { configurable: true, enumerable: false, value: "x".repeat(1000), writable: true },
      () => captureFailure(service.authorize({ user_id: USER_ID }, { all: ["invoice.read"] })),
    );
    expect(polluted).toMatchObject({ code: "insufficient_permission", status: 403 });
    expect(typeof (polluted as { request_id?: unknown }).request_id).toBe("string");
    expect((polluted as { request_id: string }).request_id.length).toBeLessThanOrEqual(128);

    const inheritedGetter = await withPrototypeProperty(
      "request_id",
      { configurable: true, enumerable: false, get: () => { throw new Error("inherited request id getter must not run"); } },
      () => captureFailure(service.authorize({ user_id: USER_ID }, { all: ["invoice.read"] })),
    );
    expect(inheritedGetter).toMatchObject({ code: "insufficient_permission", status: 403 });
    expect((inheritedGetter as { request_id?: string }).request_id?.length).toBeLessThanOrEqual(128);

    const accessorSubject = { user_id: USER_ID } as { user_id: UUID; request_id?: string };
    Object.defineProperty(accessorSubject, "request_id", {
      configurable: true,
      get() {
        throw new Error("own request id getter must not run");
      },
    });
    const accessorFailure = await captureFailure(service.authorize(accessorSubject, { all: ["invoice.read"] }));
    expect(accessorFailure).toMatchObject({ code: "insufficient_permission", status: 403 });
    expect((accessorFailure as { request_id?: string }).request_id?.length).toBeLessThanOrEqual(128);

    const validFailure = await captureFailure(service.authorize(
      { user_id: USER_ID, request_id: "req-valid" },
      { all: ["invoice.read"] },
    ));
    expect(validFailure).toMatchObject({ code: "insufficient_permission", status: 403, request_id: "req-valid" });
  });

  it("uses bounded manual validators when RegExp test or exec is tampered", async () => {
    const deniedService = serviceFor(() => []);
    const grantedPermission = permission("invoice.read");
    const grantedService = serviceFor(() => [grantedPermission]);
    const originalTest = RegExp.prototype.test;
    const originalExec = RegExp.prototype.exec;
    const cases: readonly { readonly target: "test" | "exec"; readonly value: Function }[] = [
      { target: "test", value: () => true },
      { target: "test", value: () => false },
      { target: "test", value: () => { throw new Error("test tampered"); } },
      { target: "exec", value: () => ["forged"] },
      { target: "exec", value: () => null },
      { target: "exec", value: () => { throw new Error("exec tampered"); } },
    ];

    for (let caseIndex = 0; caseIndex < cases.length; caseIndex += 1) {
      const testCase = cases[caseIndex];
      if (testCase === undefined) continue;
      let invalidRequestId: unknown;
      let validAuthorizationError: unknown;
      let uppercaseScopeStatus: number | undefined;
      let validScopeStatus: number | undefined;
      let routeError: unknown;
      let routeChecked = false;
      try {
        if (testCase.target === "test") {
          RegExp.prototype.test = testCase.value as typeof RegExp.prototype.test;
        } else {
          RegExp.prototype.exec = testCase.value as typeof RegExp.prototype.exec;
        }

        invalidRequestId = await captureFailure(deniedService.authorize(
          { user_id: USER_ID, request_id: "x".repeat(129) },
          { all: ["invoice.read"] },
        ));
        try {
          await grantedService.authorize(
            { user_id: USER_ID, request_id: "A_valid-1" },
            { all: ["invoice.read"] },
          );
        } catch (error) {
          validAuthorizationError = error;
        }
        if (caseIndex === 3) {
          routeChecked = true;
          try {
            uppercaseScopeStatus = (await permissionsRoute(
              grantedService,
              new Request("https://project.example.com/user/permissions?scope_type=TENANT&scope_id=one"),
              subject(),
            )).status;
            validScopeStatus = (await permissionsRoute(
              grantedService,
              new Request("https://project.example.com/user/permissions?scope_type=tenant&scope_id=one"),
              subject(),
            )).status;
          } catch (error) {
            routeError = error;
          }
        }
      } finally {
        RegExp.prototype.test = originalTest;
        RegExp.prototype.exec = originalExec;
      }
      expect(invalidRequestId).toMatchObject({ code: "insufficient_permission", status: 403 });
      expect((invalidRequestId as { request_id?: string }).request_id?.length).toBeLessThanOrEqual(128);
      expect(validAuthorizationError).toBeUndefined();
      if (routeChecked) {
        expect(routeError).toBeUndefined();
        expect(uppercaseScopeStatus).toBe(400);
        expect(validScopeStatus).toBe(200);
      }
    }
  });

  it("snapshots route accessors and native URL state before prototype tampering", async () => {
    const service = serviceFor(() => [permission("invoice.read")]);
    const nativeURL = URL;
    const nativeRequest = Request;
    const nativeHeaders = Headers;
    const postRequest = new Request("https://project.example.com/user/permissions", { method: "POST" });
    const unknownRequest = new Request(
      "https://project.example.com/user/permissions?unknown=grant",
      { headers: { "x-request-id": "req-original" } },
    );
    const requestMethod = Object.getOwnPropertyDescriptor(nativeRequest.prototype, "method");
    const requestUrl = Object.getOwnPropertyDescriptor(nativeRequest.prototype, "url");
    const requestHeaders = Object.getOwnPropertyDescriptor(nativeRequest.prototype, "headers");
    const urlSearchParams = Object.getOwnPropertyDescriptor(nativeURL.prototype, "searchParams");
    const urlSearch = Object.getOwnPropertyDescriptor(nativeURL.prototype, "search");
    const headersGet = Object.getOwnPropertyDescriptor(nativeHeaders.prototype, "get");
    const originalKeys = URLSearchParams.prototype.keys;
    const iterator = originalKeys.call(new URLSearchParams("unknown=grant"));
    const iteratorPrototype = Object.getPrototypeOf(iterator) as { next: () => IteratorResult<string> };
    const originalNext = iteratorPrototype.next;
    const globalURL = Object.getOwnPropertyDescriptor(globalThis, "URL");

    try {
      Object.defineProperty(nativeRequest.prototype, "method", {
        configurable: true,
        get: () => "GET",
      });
      Object.defineProperty(nativeRequest.prototype, "url", {
        configurable: true,
        get: () => "https://project.example.com/user/permissions",
      });
      Object.defineProperty(nativeRequest.prototype, "headers", {
        configurable: true,
        get: () => new nativeHeaders({ "x-request-id": "forged" }),
      });
      Object.defineProperty(nativeURL.prototype, "searchParams", {
        configurable: true,
        get: () => new URLSearchParams(),
      });
      Object.defineProperty(nativeURL.prototype, "search", {
        configurable: true,
        get: () => "",
      });
      Object.defineProperty(nativeHeaders.prototype, "get", {
        configurable: true,
        writable: true,
        value: () => "forged",
      });
      URLSearchParams.prototype.keys = (() => (function* emptyKeys() {})()) as typeof URLSearchParams.prototype.keys;
      iteratorPrototype.next = (() => ({ done: true, value: undefined })) as typeof iteratorPrototype.next;
      Object.defineProperty(globalThis, "URL", {
        configurable: true,
        writable: true,
        value: class FakeURL {
          readonly searchParams = new URLSearchParams();
        },
      });

      const postResponse = await permissionsRoute(service, postRequest, subject());
      expect(postResponse.status).toBe(405);
      const unknownResponse = await permissionsRoute(service, unknownRequest, subject());
      expect(unknownResponse.status).toBe(400);
      const unknownBody = await unknownResponse.json() as { readonly error?: { readonly request_id?: string } };
      expect(unknownBody.error?.request_id).toBe("req-original");
    } finally {
      if (requestMethod === undefined) Reflect.deleteProperty(nativeRequest.prototype, "method");
      else Object.defineProperty(nativeRequest.prototype, "method", requestMethod);
      if (requestUrl === undefined) Reflect.deleteProperty(nativeRequest.prototype, "url");
      else Object.defineProperty(nativeRequest.prototype, "url", requestUrl);
      if (requestHeaders === undefined) Reflect.deleteProperty(nativeRequest.prototype, "headers");
      else Object.defineProperty(nativeRequest.prototype, "headers", requestHeaders);
      if (urlSearchParams === undefined) Reflect.deleteProperty(nativeURL.prototype, "searchParams");
      else Object.defineProperty(nativeURL.prototype, "searchParams", urlSearchParams);
      if (urlSearch === undefined) Reflect.deleteProperty(nativeURL.prototype, "search");
      else Object.defineProperty(nativeURL.prototype, "search", urlSearch);
      if (headersGet === undefined) Reflect.deleteProperty(nativeHeaders.prototype, "get");
      else Object.defineProperty(nativeHeaders.prototype, "get", headersGet);
      URLSearchParams.prototype.keys = originalKeys;
      iteratorPrototype.next = originalNext;
      if (globalURL === undefined) Reflect.deleteProperty(globalThis, "URL");
      else Object.defineProperty(globalThis, "URL", globalURL);
    }
  });

  it("uses captured response and serialization primitives for safe route bodies", async () => {
    const service = serviceFor(() => [permission("invoice.read")]);
    const requests = [
      { request: new Request("https://project.example.com/user/permissions"), subject: subject() },
      { request: new Request("https://project.example.com/user/permissions?unknown=grant"), subject: subject() },
      { request: new Request("https://project.example.com/user/permissions", { method: "POST" }), subject: subject() },
      { request: new Request("https://project.example.com/user/permissions"), subject: undefined },
    ] as const;

    const runRequests = async (): Promise<readonly { readonly status?: number; readonly text?: string; readonly error?: unknown }[]> => {
      const results: { status?: number; text?: string; error?: unknown }[] = [];
      for (let index = 0; index < requests.length; index += 1) {
        const entry = requests[index];
        if (entry === undefined) continue;
        try {
          const response = await permissionsRoute(service, entry.request, entry.subject);
          results.push({ status: response.status, text: await response.text() });
        } catch (error) {
          results.push({ error });
        }
      }
      return results;
    };

    const assertSafeResponses = (results: readonly { readonly status?: number; readonly text?: string; readonly error?: unknown }[]) => {
      expect(results).toHaveLength(4);
      expect(results.every((result) => result.error === undefined)).toBe(true);
      expect(results[0]?.status).toBe(200);
      expect(JSON.parse(results[0]?.text ?? "")).toEqual({
        data: { permissions: ["invoice.read"] },
        error: null,
      });
      expect(results[1]?.status).toBe(400);
      expect((JSON.parse(results[1]?.text ?? "") as { error?: { code?: string } }).error?.code).toBe("invalid_request");
      expect(results[2]?.status).toBe(405);
      expect((JSON.parse(results[2]?.text ?? "") as { error?: { code?: string } }).error?.code).toBe("invalid_request");
      expect(results[3]?.status).toBe(401);
      expect((JSON.parse(results[3]?.text ?? "") as { error?: { code?: string } }).error?.code).toBe("unauthorized");
    };

    const originalResponseDescriptor = Object.getOwnPropertyDescriptor(globalThis, "Response");
    const originalStringify = JSON.stringify;
    const restoreGlobals = () => {
      if (originalResponseDescriptor === undefined) Reflect.deleteProperty(globalThis, "Response");
      else Object.defineProperty(globalThis, "Response", originalResponseDescriptor);
      JSON.stringify = originalStringify;
    };

    try {
      Object.defineProperty(globalThis, "Response", {
        configurable: true,
        writable: true,
        value: class ForgedResponse {
          constructor() {
            throw new Error("global Response was used");
          }
        },
      });
      let results = await runRequests();
      restoreGlobals();
      assertSafeResponses(results);

      JSON.stringify = (() => {
        throw new Error("global JSON.stringify was used");
      }) as typeof JSON.stringify;
      results = await runRequests();
      restoreGlobals();
      assertSafeResponses(results);

      results = await withPrototypeProperty(
        "toJSON",
        {
          configurable: true,
          enumerable: false,
          value: () => "forged response",
          writable: true,
        },
        runRequests,
      );
      assertSafeResponses(results);

      results = await withPrototypeProperty(
        "toJSON",
        {
          configurable: true,
          enumerable: false,
          get() {
            throw new Error("Object.prototype.toJSON was used");
          },
        },
        runRequests,
      );
      assertSafeResponses(results);
    } finally {
      restoreGlobals();
    }
  });

  it("requires own service configuration and ignores inherited or accessor options", async () => {
    const effectivePermissions = async () => [];
    const authorization = { effectivePermissions };
    const repository = { authorization } as unknown as AuthRepository;

    await withPrototypeProperty("repository", { configurable: true, enumerable: false, value: repository, writable: true }, async () => {
      expect(() => new AuthorizationService({} as never)).toThrow();
    });
    await withPrototypeProperty("authorization", { configurable: true, enumerable: false, value: authorization, writable: true }, async () => {
      expect(() => new AuthorizationService({ repository: {} } as never)).toThrow();
    });
    await withPrototypeProperty("effectivePermissions", { configurable: true, enumerable: false, value: effectivePermissions, writable: true }, async () => {
      expect(() => new AuthorizationService({ repository: { authorization: {} } } as never)).toThrow();
    });
    await withPrototypeProperty("clock", { configurable: true, enumerable: false, value: () => new Date("invalid"), writable: true }, async () => {
      expect(() => new AuthorizationService({ repository })).not.toThrow();
    });

    const accessorOptions = {} as Record<string, unknown>;
    Object.defineProperty(accessorOptions, "repository", {
      configurable: true,
      get() { throw new Error("repository getter must not run"); },
    });
    expect(() => new AuthorizationService(accessorOptions as never)).toThrow();

    const accessorRepository = {} as Record<string, unknown>;
    Object.defineProperty(accessorRepository, "authorization", {
      configurable: true,
      get() { throw new Error("authorization getter must not run"); },
    });
    expect(() => new AuthorizationService({ repository: accessorRepository } as never)).toThrow();

    const accessorAuthorization = {} as Record<string, unknown>;
    Object.defineProperty(accessorAuthorization, "effectivePermissions", {
      configurable: true,
      get() { throw new Error("effectivePermissions getter must not run"); },
    });
    expect(() => new AuthorizationService({ repository: { authorization: accessorAuthorization } } as never)).toThrow();

    const accessorClockOptions = { repository } as Record<string, unknown>;
    Object.defineProperty(accessorClockOptions, "clock", {
      configurable: true,
      get() { throw new Error("clock getter must not run"); },
    });
    expect(() => new AuthorizationService(accessorClockOptions as never)).toThrow();
  });

  it("uses captured Date operations and fresh operation-time snapshots", async () => {
    const seenTimes: Date[] = [];
    const repository = {
      authorization: {
        effectivePermissions: async (_userId: UUID, _scope: AuthorizationScope | undefined, options?: { readonly now?: Date }) => {
          if (options?.now !== undefined) seenTimes.push(options.now);
          return [permission("time.read")];
        },
      },
    } as unknown as AuthRepository;
    const originalGetTime = Date.prototype.getTime;
    const originalNumberIsFinite = Number.isFinite;
    const originalDateDescriptor = Object.getOwnPropertyDescriptor(globalThis, "Date");
    const originalDate = Date;

    try {
      Date.prototype.getTime = (() => Number.POSITIVE_INFINITY) as typeof Date.prototype.getTime;
      const getTimeService = new AuthorizationService({ repository, clock: () => NOW });
      await expect(getTimeService.getPermissions(USER_ID)).resolves.toEqual(["time.read"]);

      Number.isFinite = (() => false) as typeof Number.isFinite;
      const finiteService = new AuthorizationService({ repository, clock: () => NOW });
      await expect(finiteService.getPermissions(USER_ID)).resolves.toEqual(["time.read"]);

      Object.defineProperty(globalThis, "Date", {
        configurable: true,
        writable: true,
        value: class FakeDate {
          constructor() { return {} as FakeDate; }
        },
      });
      const reassignedDateService = new AuthorizationService({ repository, clock: () => NOW });
      await expect(reassignedDateService.getPermissions(USER_ID)).resolves.toEqual(["time.read"]);
      const defaultClockService = new AuthorizationService({ repository });
      await expect(defaultClockService.getPermissions(USER_ID)).resolves.toEqual(["time.read"]);
    } finally {
      originalDate.prototype.getTime = originalGetTime;
      Number.isFinite = originalNumberIsFinite;
      if (originalDateDescriptor === undefined) Reflect.deleteProperty(globalThis, "Date");
      else Object.defineProperty(globalThis, "Date", originalDateDescriptor);
    }

    const subclass = new (class extends originalDate {})(NOW.getTime());
    expect(() => new AuthorizationService({ repository, clock: () => subclass })).not.toThrow();
    expect(() => new AuthorizationService({ repository, clock: () => new Date(Number.NaN) })).toThrow();
    expect(() => new AuthorizationService({ repository, clock: () => ({}) as Date })).toThrow();

    const snapshotService = new AuthorizationService({ repository, clock: () => NOW });
    await snapshotService.getPermissions(USER_ID);
    await snapshotService.getPermissions(USER_ID);
    expect(seenTimes.length).toBeGreaterThanOrEqual(2);
    expect(seenTimes[0]).not.toBe(NOW);
    expect(seenTimes[1]).not.toBe(NOW);
    expect(seenTimes[1]).not.toBe(seenTimes[0]);
    expect(originalGetTime.call(seenTimes[0])).toBe(originalGetTime.call(NOW));
    expect(originalGetTime.call(seenTimes[1])).toBe(originalGetTime.call(NOW));
  });
});
