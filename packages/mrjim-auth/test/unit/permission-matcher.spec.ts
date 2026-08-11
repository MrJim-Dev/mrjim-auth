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
});
