import { z } from "zod";
import { routeContracts, type RouteContract } from "./routes/contracts.js";

type JsonValue = null | boolean | number | string | readonly JsonValue[] | { readonly [key: string]: JsonValue };

export interface OpenApiDocumentOptions {
  readonly baseUrl?: string;
}

type OpenApiDocumentInput = string | OpenApiDocumentOptions | undefined;

function sortJson(value: unknown): JsonValue {
  if (value === null || typeof value === "boolean" || typeof value === "number" || typeof value === "string") return value;
  if (Array.isArray(value)) return value.map(sortJson);
  if (typeof value !== "object") return null;
  const output: Record<string, JsonValue> = {};
  for (const key of Object.keys(value).sort()) {
    if (key === "$schema") continue;
    output[key] = sortJson((value as Record<string, unknown>)[key]);
  }
  return output;
}

function schemaJson(schema: RouteContract["response"]): Record<string, JsonValue> {
  return sortJson(z.toJSONSchema(schema)) as Record<string, JsonValue>;
}

function schemaReference(componentName: string): string {
  return `#/components/schemas/${componentName}`;
}

function rewriteSchemaReferences(value: unknown, references: ReadonlyMap<string, string>): JsonValue {
  if (Array.isArray(value)) return value.map((item) => rewriteSchemaReferences(item, references));
  if (value === null || typeof value === "boolean" || typeof value === "number" || typeof value === "string") return value;
  if (typeof value !== "object") return null;
  const output: Record<string, JsonValue> = {};
  for (const key of Object.keys(value)) {
    if (key === "$defs") continue;
    const item = (value as Record<string, unknown>)[key];
    if (key === "$ref" && typeof item === "string") {
      output[key] = references.get(item) ?? item;
    } else {
      output[key] = rewriteSchemaReferences(item, references);
    }
  }
  return sortJson(output);
}

function addSchemaComponent(
  schemas: Record<string, JsonValue>,
  componentName: string,
  schema: RouteContract["response"],
): void {
  const source = schemaJson(schema);
  const definitions = source.$defs;
  const references = new Map<string, string>();
  if (definitions !== null && typeof definitions === "object" && !Array.isArray(definitions)) {
    for (const definitionName of Object.keys(definitions).sort()) {
      references.set(`#/$defs/${definitionName}`, schemaReference(`${componentName}_${definitionName}`));
    }
    for (const definitionName of Object.keys(definitions).sort()) {
      schemas[`${componentName}_${definitionName}`] = rewriteSchemaReferences(
        (definitions as Record<string, unknown>)[definitionName],
        references,
      );
    }
  }
  schemas[componentName] = rewriteSchemaReferences(source, references);
}

function pathParameters(contract: RouteContract): JsonValue[] {
  const output: JsonValue[] = [];
  for (const match of contract.path.matchAll(/\{([^}]+)\}/gu)) {
    const name = match[1];
    if (name === undefined) continue;
    output.push({
      name,
      in: "path",
      required: true,
      schema: { type: "string", ...(name === "id" ? { format: "uuid" } : {}) },
      description: name === "provider" ? "Configured OAuth provider name" : "Resource identifier",
    });
  }
  return output;
}

function configuredServerUrl(input: OpenApiDocumentInput): string {
  const candidate = typeof input === "string" ? input : input?.baseUrl;
  if (candidate === undefined) return "/auth/v1";
  if (typeof candidate !== "string" || candidate.length === 0) throw new TypeError("baseUrl must be a non-empty absolute HTTP(S) URL");
  let parsed: URL;
  try {
    parsed = new URL(candidate);
  } catch {
    throw new TypeError("baseUrl must be a non-empty absolute HTTP(S) URL");
  }
  if (!/^https?:$/u.test(parsed.protocol) || parsed.username !== "" || parsed.password !== "" || parsed.search !== "" || parsed.hash !== "") {
    throw new TypeError("baseUrl must be an absolute HTTP(S) URL without credentials or query parameters");
  }
  parsed.pathname = parsed.pathname.replace(/\/{2,}/gu, "/").replace(/\/$/u, "") || "/";
  return parsed.href;
}

function securityFor(contract: RouteContract): Record<string, readonly string[]>[] {
  if (contract.security === "signed") return [];
  if (contract.security === "user") {
    return [
      { publishableKey: [] },
      { secretKey: [] },
    ].map((entry) => ({ ...entry, bearerAuth: [] }));
  }
  return [{ publishableKey: [] }, { secretKey: [] }];
}

function requestBody(contract: RouteContract, componentName: string): Record<string, JsonValue> | undefined {
  if (contract.body === undefined) return undefined;
  const content: Record<string, JsonValue> = {
    "application/json": {
      schema: { $ref: `#/components/schemas/${componentName}` },
      ...(contract.example === undefined ? {} : { example: sortJson(contract.example) }),
    },
  };
  return { required: true, content };
}

function queryParameters(contract: RouteContract): JsonValue[] {
  return (contract.query ?? []).map((parameter) => ({
    name: parameter.name,
    in: "query",
    required: parameter.required,
    schema: { type: "string" },
    description: parameter.description,
  }));
}

function operation(contract: RouteContract): Record<string, JsonValue> {
  const operation: Record<string, JsonValue> = {
    operationId: contract.operationId,
    summary: contract.operationId,
    description: `Authentication operation ${contract.operationId}.`,
    tags: [contract.path.startsWith("/user") ? "current-user" : "public"],
    security: securityFor(contract),
    parameters: [...pathParameters(contract), ...queryParameters(contract)],
    responses: {},
  };
  const responseName = `Response_${contract.operationId}`;
  const bodyName = contract.body === undefined ? undefined : `Request_${contract.operationId}`;
  const responses = operation.responses as Record<string, JsonValue>;
  if (contract.path === "/callback/{provider}") {
    responses["303"] = {
      description: "Redirect to the exact configured callback target",
      headers: { Location: { schema: { type: "string", format: "uri" } } },
    };
  } else {
    responses["200"] = {
      description: "Successful authentication operation",
      content: { "application/json": { schema: { $ref: `#/components/schemas/${responseName}` } } },
    };
  }
  responses["400"] = { description: "Invalid authentication request", content: { "application/json": { schema: { $ref: "#/components/schemas/ErrorResponse" } } } };
  responses["401"] = { description: "Authentication failed", content: { "application/json": { schema: { $ref: "#/components/schemas/ErrorResponse" } } } };
  responses["403"] = { description: "Forbidden", content: { "application/json": { schema: { $ref: "#/components/schemas/ErrorResponse" } } } };
  responses["404"] = { description: "Not found", content: { "application/json": { schema: { $ref: "#/components/schemas/ErrorResponse" } } } };
  responses["405"] = { description: "Method not allowed", content: { "application/json": { schema: { $ref: "#/components/schemas/ErrorResponse" } } } };
  responses["413"] = { description: "Request body is too large", content: { "application/json": { schema: { $ref: "#/components/schemas/ErrorResponse" } } } };
  responses["409"] = { description: "Authentication state conflict", content: { "application/json": { schema: { $ref: "#/components/schemas/ErrorResponse" } } } };
  responses["429"] = { description: "Too many authentication attempts", content: { "application/json": { schema: { $ref: "#/components/schemas/ErrorResponse" } } } };
  responses["502"] = { description: "Configured provider dependency failure", content: { "application/json": { schema: { $ref: "#/components/schemas/ErrorResponse" } } } };
  responses["500"] = { description: "Internal authentication error", content: { "application/json": { schema: { $ref: "#/components/schemas/ErrorResponse" } } } };
  if (bodyName !== undefined) operation.requestBody = requestBody(contract, bodyName) as JsonValue;
  return sortJson(operation) as Record<string, JsonValue>;
}

/** Generates the deterministic, route-contract-derived HTTP API document. */
export function generateOpenApiDocument(input?: OpenApiDocumentInput): Record<string, unknown> {
  const paths: Record<string, JsonValue> = {};
  const schemas: Record<string, JsonValue> = {
    Error: {
      type: "object",
      additionalProperties: false,
      required: ["code", "message", "request_id"],
      properties: {
        code: { type: "string" },
        message: { type: "string" },
        request_id: { type: "string" },
      },
    },
    ErrorResponse: {
      type: "object",
      additionalProperties: false,
      required: ["error"],
      properties: { error: { $ref: "#/components/schemas/Error" } },
    },
  };
  for (const contract of routeContracts) {
    if (paths[contract.path] === undefined) paths[contract.path] = {};
    const path = paths[contract.path] as Record<string, JsonValue>;
    path[contract.method.toLowerCase()] = operation(contract);
    if (contract.body !== undefined) addSchemaComponent(schemas, `Request_${contract.operationId}`, contract.body);
    addSchemaComponent(schemas, `Response_${contract.operationId}`, contract.response);
  }
  const document = {
    openapi: "3.1.0",
    info: {
      title: "mrjim-auth HTTP API",
      version: "0.1.0",
      description: "Framework-neutral public and current-user authentication routes.",
    },
    servers: [{ url: configuredServerUrl(input) }],
    paths,
    components: {
      securitySchemes: {
        publishableKey: { type: "apiKey", in: "header", name: "apikey", description: "Project publishable API key." },
        secretKey: { type: "apiKey", in: "header", name: "apikey", description: "Project secret API key; never send from a browser origin." },
        bearerAuth: { type: "http", scheme: "bearer", bearerFormat: "JWT" },
      },
      schemas,
    },
  };
  return sortJson(document) as Record<string, unknown>;
}
