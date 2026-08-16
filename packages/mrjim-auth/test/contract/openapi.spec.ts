import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { AuthConfigurationError } from "../../src/shared/errors.js";
import { generateOpenApiDocument } from "../../src/server/openapi.js";
import { recoverVerifyRequestSchema } from "../../src/server/routes/contracts.js";

const BASE_URL = "https://project.example.com/auth/v1";

function operations(document: any): Array<[string, string, any]> {
  const output: Array<[string, string, any]> = [];
  for (const [path, item] of Object.entries(document.paths as Record<string, any>)) {
    for (const [method, operation] of Object.entries(item as Record<string, any>)) {
      output.push([path, method, operation]);
    }
  }
  return output;
}

function collectReferences(value: unknown, references: string[] = []): string[] {
  if (Array.isArray(value)) {
    for (const item of value) collectReferences(item, references);
    return references;
  }
  if (value !== null && typeof value === "object") {
    for (const [key, item] of Object.entries(value)) {
      if (key === "$ref" && typeof item === "string") references.push(item);
      collectReferences(item, references);
    }
  }
  return references;
}

describe("Task 9 deterministic OpenAPI contract", () => {
  it("rejects an OpenAPI base-url accessor without invoking it", () => {
    const options = Object.create(null) as Record<string, unknown>;
    let getterCalls = 0;
    Object.defineProperty(options, "baseUrl", {
      configurable: true,
      get: () => {
        getterCalls += 1;
        throw new Error("openapi base-url sentinel");
      },
    });
    let thrown: unknown;
    try {
      generateOpenApiDocument(options as never);
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(AuthConfigurationError);
    expect(String(thrown)).not.toContain("openapi base-url sentinel");
    expect(getterCalls).toBe(0);
  });

  it("validates refs, path parameters, runtime statuses, configured server URL, and byte parity", () => {
    const configured = generateOpenApiDocument({ baseUrl: BASE_URL }) as any;
    const defaultDocument = generateOpenApiDocument() as any;
    const repeated = generateOpenApiDocument() as any;
    const schemas = configured.components.schemas as Record<string, unknown>;
    const paths = configured.paths as Record<string, any>;
    const refs = collectReferences(configured);

    expect(configured.openapi).toBe("3.1.0");
    expect(configured.servers).toEqual([{ url: BASE_URL }]);
    expect(Object.keys(paths)).toHaveLength(30);
    expect(operations(configured)).toHaveLength(39);
    expect(Object.keys(paths).filter((path) => path.startsWith("/admin"))).toHaveLength(12);
    expect(paths["/admin/users"].get.security).toEqual([
      { secretKey: [] },
      { publishableKey: [], bearerAuth: [] },
    ]);
    expect(refs.every((ref) => ref.startsWith("#/components/schemas/") && Object.hasOwn(schemas, ref.slice("#/components/schemas/".length)))).toBe(true);
    expect(collectReferences(configured).some((ref) => ref.startsWith("#/$defs/"))).toBe(false);

    const authorize = paths["/authorize"].get as Record<string, any>;
    const authorizeParameters = authorize.parameters as Array<Record<string, any>>;
    expect(authorizeParameters).toEqual(expect.arrayContaining([
      expect.objectContaining({ name: "code_challenge", in: "query", required: true }),
      expect.objectContaining({ name: "code_challenge_method", in: "query", required: false }),
    ]));
    const authorizeResponseRef = authorize.responses["200"].content["application/json"].schema.$ref as string;
    const authorizeResponseName = authorizeResponseRef.slice("#/components/schemas/".length);
    const authorizeDataProperties = (schemas[authorizeResponseName] as any).properties.data.properties as Record<string, unknown>;
    expect(authorizeDataProperties).not.toHaveProperty("state");
    expect(authorizeDataProperties).not.toHaveProperty("code_verifier");

    for (const [path, _method, operation] of operations(configured)) {
      const templateNames = [...path.matchAll(/\{([^}]+)\}/gu)].map((match) => match[1]);
      const parameters = operation.parameters as Array<Record<string, any>>;
      for (const name of templateNames) {
        expect(parameters).toEqual(expect.arrayContaining([
          expect.objectContaining({ name, in: "path", required: true }),
        ]));
      }
      expect(Object.keys(operation.responses)).toEqual(expect.arrayContaining(["409", "429", "502"]));
    }

    expect(JSON.stringify(defaultDocument)).toBe(JSON.stringify(repeated));
    expect(JSON.stringify(defaultDocument, null, 2) + "\n").toBe(
      readFileSync(new URL("../../../../docs/reference/openapi.json", import.meta.url), "utf8"),
    );
  });

  it("matches recovery password and proof bounds at the route contract boundary", () => {
    const valid = { email: "user@example.com", token: "x".repeat(128), password: "x".repeat(1024) };
    const multibyte = "😀".repeat(300);
    expect(new TextEncoder().encode(multibyte).byteLength).toBe(1_200);
    expect(recoverVerifyRequestSchema.safeParse(valid).success).toBe(true);
    expect(recoverVerifyRequestSchema.safeParse({ ...valid, token: "x".repeat(129) }).success).toBe(false);
    expect(recoverVerifyRequestSchema.safeParse({ ...valid, password: "x".repeat(7) }).success).toBe(false);
    expect(recoverVerifyRequestSchema.safeParse({ ...valid, password: "x".repeat(1025) }).success).toBe(false);
    expect(recoverVerifyRequestSchema.safeParse({ ...valid, password: multibyte }).success).toBe(false);

    const document = generateOpenApiDocument() as any;
    const requestSchemaRef = document.paths["/recover/verify"].post.requestBody.content["application/json"].schema.$ref as string;
    const requestSchema = document.components.schemas[requestSchemaRef.slice("#/components/schemas/".length)] as any;
    expect(requestSchema.properties.token).toMatchObject({ minLength: 1, maxLength: 128 });
    expect(requestSchema.properties.password).toMatchObject({
      minLength: 8,
      maxLength: 1024,
      description: "Password containing at most 1,024 UTF-8 bytes",
      "x-mrjim-maxUtf8Bytes": 1024,
    });
  });

  it("does not depend on mutable post-import collection and string intrinsics", () => {
    const expected = JSON.stringify(generateOpenApiDocument());
    const cases: readonly [string, object, PropertyKey, unknown][] = [
      ["Array.map", Array.prototype, "map", () => { throw new Error("openapi-map-sentinel"); }],
      ["Object.keys", Object, "keys", () => { throw new Error("openapi-keys-sentinel"); }],
      ["Map.set", Map.prototype, "set", () => { throw new Error("openapi-set-sentinel"); }],
      ["String.replace", String.prototype, "replace", () => { throw new Error("openapi-replace-sentinel"); }],
      ["Array.sort", Array.prototype, "sort", () => { throw new Error("openapi-sort-sentinel"); }],
    ];
    for (const [label, target, key, value] of cases) {
      const descriptor = Object.getOwnPropertyDescriptor(target, key);
      let thrown: unknown;
      try {
        Object.defineProperty(target, key, {
          configurable: true,
          enumerable: descriptor?.enumerable ?? false,
          writable: true,
          value,
        });
        try {
          expect(JSON.stringify(generateOpenApiDocument()), label).toBe(expected);
        } catch (error) {
          thrown = error;
        }
      } finally {
        if (descriptor === undefined) Reflect.deleteProperty(target, key);
        else Object.defineProperty(target, key, descriptor);
      }
      expect(thrown, label).toBeUndefined();
    }
  });
});
