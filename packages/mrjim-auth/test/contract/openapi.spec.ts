import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { generateOpenApiDocument } from "../../src/server/openapi.js";

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
  it("validates refs, path parameters, runtime statuses, configured server URL, and byte parity", () => {
    const configured = generateOpenApiDocument({ baseUrl: BASE_URL }) as any;
    const defaultDocument = generateOpenApiDocument() as any;
    const repeated = generateOpenApiDocument() as any;
    const schemas = configured.components.schemas as Record<string, unknown>;
    const paths = configured.paths as Record<string, any>;
    const refs = collectReferences(configured);

    expect(configured.openapi).toBe("3.1.0");
    expect(configured.servers).toEqual([{ url: BASE_URL }]);
    expect(Object.keys(paths)).toHaveLength(16);
    expect(operations(configured)).toHaveLength(17);
    expect(Object.keys(paths).some((path) => path.startsWith("/admin"))).toBe(false);
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
});
