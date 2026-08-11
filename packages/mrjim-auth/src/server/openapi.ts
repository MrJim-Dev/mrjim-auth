import { z } from "zod";
import { AuthConfigurationError } from "../shared/errors.js";
import { routeContracts, type RouteContract } from "./routes/contracts.js";
import {
  assertBoundaryObject,
  optionalBoundaryOption,
} from "./callback-boundary.js";

type JsonValue = null | boolean | number | string | readonly JsonValue[] | { readonly [key: string]: JsonValue };

export interface OpenApiDocumentOptions {
  readonly baseUrl?: string;
}

type OpenApiDocumentInput = string | OpenApiDocumentOptions | undefined;

const openapiArrayIsArray = Array.isArray;
const openapiArrayMap = Array.prototype.map;
const openapiArrayPush = Array.prototype.push;
const openapiArraySort = Array.prototype.sort;
const openapiObjectKeys = Object.keys;
const openapiMapConstructor = Map;
const openapiMapGet = Map.prototype.get;
const openapiMapSet = Map.prototype.set;
const openapiReflectApply = Reflect.apply;
const openapiRegExpExec = RegExp.prototype.exec;
const openapiStringReplace = String.prototype.replace;
const openapiURL = URL;
const openapiSchemaCache: Array<{ readonly schema: object; readonly value: Record<string, JsonValue> }> = [];

function openapiKeys(value: object): string[] {
  try {
    return openapiObjectKeys(value);
  } catch {
    throw new AuthConfigurationError("OpenAPI schema is not a data object");
  }
}

function sortedOpenapiKeys(value: object): string[] {
  const keys = openapiKeys(value);
  try {
    return openapiReflectApply(openapiArraySort, keys, []) as string[];
  } catch {
    throw new AuthConfigurationError("OpenAPI schema keys are malformed");
  }
}

function appendOpenapiValue<T>(values: T[], value: T, label: string): void {
  try {
    openapiReflectApply(openapiArrayPush, values, [value]);
  } catch {
    throw new AuthConfigurationError(`${label} is malformed`);
  }
}

function sortJson(value: unknown): JsonValue {
  if (value === null || typeof value === "boolean" || typeof value === "number" || typeof value === "string") return value;
  if (openapiArrayIsArray(value)) {
    try {
      return openapiReflectApply(openapiArrayMap, value, [sortJson]) as JsonValue[];
    } catch {
      throw new AuthConfigurationError("OpenAPI schema array is malformed");
    }
  }
  if (typeof value !== "object") return null;
  const output: Record<string, JsonValue> = {};
  for (const key of sortedOpenapiKeys(value)) {
    if (key === "$schema") continue;
    output[key] = sortJson((value as Record<string, unknown>)[key]);
  }
  return output;
}

function schemaJsonUncached(schema: RouteContract["response"]): Record<string, JsonValue> {
  return sortJson(z.toJSONSchema(schema)) as Record<string, JsonValue>;
}

function schemaJson(schema: RouteContract["response"]): Record<string, JsonValue> {
  for (let index = 0; index < openapiSchemaCache.length; index += 1) {
    const entry = openapiSchemaCache[index];
    if (entry !== undefined && entry.schema === schema) return entry.value;
  }
  const value = schemaJsonUncached(schema);
  appendOpenapiValue(openapiSchemaCache, { schema: schema as object, value }, "OpenAPI schema cache");
  return value;
}

for (let contractIndex = 0; contractIndex < routeContracts.length; contractIndex += 1) {
  const contract = routeContracts[contractIndex];
  if (contract === undefined) throw new AuthConfigurationError("OpenAPI route contracts are malformed");
  schemaJson(contract.response);
  if (contract.body !== undefined) schemaJson(contract.body);
}

function schemaReference(componentName: string): string {
  return `#/components/schemas/${componentName}`;
}

function rewriteSchemaReferences(value: unknown, references: ReadonlyMap<string, string>): JsonValue {
  if (openapiArrayIsArray(value)) {
    try {
      return openapiReflectApply(openapiArrayMap, value, [(item: unknown) => rewriteSchemaReferences(item, references)]) as JsonValue[];
    } catch {
      throw new AuthConfigurationError("OpenAPI schema array is malformed");
    }
  }
  if (value === null || typeof value === "boolean" || typeof value === "number" || typeof value === "string") return value;
  if (typeof value !== "object") return null;
  const output: Record<string, JsonValue> = {};
  for (const key of openapiKeys(value)) {
    if (key === "$defs") continue;
    const item = (value as Record<string, unknown>)[key];
    if (key === "$ref" && typeof item === "string") {
      let replacement: string | undefined;
      try {
        replacement = openapiReflectApply(openapiMapGet, references, [item]) as string | undefined;
      } catch {
        throw new AuthConfigurationError("OpenAPI schema references are malformed");
      }
      output[key] = replacement ?? item;
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
  const references = new openapiMapConstructor<string, string>();
  if (definitions !== null && typeof definitions === "object" && !openapiArrayIsArray(definitions)) {
    for (const definitionName of sortedOpenapiKeys(definitions)) {
      try {
        openapiReflectApply(openapiMapSet, references, [`#/$defs/${definitionName}`, schemaReference(`${componentName}_${definitionName}`)]);
      } catch {
        throw new AuthConfigurationError("OpenAPI schema references are malformed");
      }
    }
    for (const definitionName of sortedOpenapiKeys(definitions)) {
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
  const matcher = /\{([^}]+)\}/gu;
  for (;;) {
    const match = openapiReflectApply(openapiRegExpExec, matcher, [contract.path]) as RegExpExecArray | null;
    if (match === null) break;
    const name = match[1];
    if (name === undefined) continue;
    appendOpenapiValue(output, {
      name,
      in: "path",
      required: true,
      schema: { type: "string", ...(name === "id" ? { format: "uuid" } : {}) },
      description: name === "provider" ? "Configured OAuth provider name" : "Resource identifier",
    }, "OpenAPI path parameters");
  }
  return output;
}

function configuredServerUrl(input: OpenApiDocumentInput): string {
  let candidate: unknown;
  if (typeof input === "string") {
    candidate = input;
  } else if (input === undefined) {
    candidate = undefined;
  } else {
    if (input === null || typeof input !== "object") throw new AuthConfigurationError("OpenAPI options must be an object");
    assertBoundaryObject(input, "OpenAPI options");
    candidate = optionalBoundaryOption(input, "baseUrl", "OpenAPI base URL");
  }
  if (candidate === undefined) return "/auth/v1";
  if (typeof candidate !== "string" || candidate.length === 0) throw new TypeError("baseUrl must be a non-empty absolute HTTP(S) URL");
  let parsed: URL;
  try {
    parsed = new openapiURL(candidate);
  } catch {
    throw new TypeError("baseUrl must be a non-empty absolute HTTP(S) URL");
  }
  if (!/^https?:$/u.test(parsed.protocol) || parsed.username !== "" || parsed.password !== "" || parsed.search !== "" || parsed.hash !== "") {
    throw new TypeError("baseUrl must be an absolute HTTP(S) URL without credentials or query parameters");
  }
  parsed.pathname = openapiReflectApply(openapiStringReplace, parsed.pathname, [/\/{2,}/gu, "/"]) as string;
  parsed.pathname = openapiReflectApply(openapiStringReplace, parsed.pathname, [/\/$/u, ""]) as string || "/";
  return parsed.href;
}

function securityFor(contract: RouteContract): Record<string, readonly string[]>[] {
  if (contract.security === "signed") return [];
  if (contract.security === "user") {
    return [
      { publishableKey: [], bearerAuth: [] },
      { secretKey: [], bearerAuth: [] },
    ];
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
  const output: JsonValue[] = [];
  const query = contract.query ?? [];
  for (let index = 0; index < query.length; index += 1) {
    const parameter = query[index];
    if (parameter === undefined) throw new AuthConfigurationError("OpenAPI query parameters are malformed");
    appendOpenapiValue(output, {
      name: parameter.name,
      in: "query",
      required: parameter.required,
      schema: { type: "string" },
      description: parameter.description,
    }, "OpenAPI query parameters");
  }
  return output;
}

function operation(contract: RouteContract): Record<string, JsonValue> {
  const operation: Record<string, JsonValue> = {
    operationId: contract.operationId,
    summary: contract.operationId,
    description: `Authentication operation ${contract.operationId}.`,
    tags: [contract.path.startsWith("/user") ? "current-user" : "public"],
    security: securityFor(contract),
    parameters: [],
    responses: {},
  };
  const parameters = operation.parameters as JsonValue[];
  const pathParameterValues = pathParameters(contract);
  const queryParameterValues = queryParameters(contract);
  for (let index = 0; index < pathParameterValues.length; index += 1) {
    const parameter = pathParameterValues[index];
    if (parameter !== undefined) appendOpenapiValue(parameters, parameter, "OpenAPI parameters");
  }
  for (let index = 0; index < queryParameterValues.length; index += 1) {
    const parameter = queryParameterValues[index];
    if (parameter !== undefined) appendOpenapiValue(parameters, parameter, "OpenAPI parameters");
  }
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
  for (let contractIndex = 0; contractIndex < routeContracts.length; contractIndex += 1) {
    const contract = routeContracts[contractIndex];
    if (contract === undefined) throw new AuthConfigurationError("OpenAPI route contracts are malformed");
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
