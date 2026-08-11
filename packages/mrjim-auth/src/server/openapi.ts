import { z } from "zod";
import { routeContracts, type RouteContract } from "./routes/contracts.js";

type JsonValue = null | boolean | number | string | readonly JsonValue[] | { readonly [key: string]: JsonValue };

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
    tags: [contract.path.startsWith("/user") ? "current-user" : "public"],
    security: securityFor(contract),
    parameters: queryParameters(contract),
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
  responses["500"] = { description: "Internal authentication error", content: { "application/json": { schema: { $ref: "#/components/schemas/ErrorResponse" } } } };
  if (bodyName !== undefined) operation.requestBody = requestBody(contract, bodyName) as JsonValue;
  return sortJson(operation) as Record<string, JsonValue>;
}

/** Generates the deterministic, route-contract-derived HTTP API document. */
export function generateOpenApiDocument(): Record<string, unknown> {
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
    if (contract.body !== undefined) schemas[`Request_${contract.operationId}`] = schemaJson(contract.body);
    schemas[`Response_${contract.operationId}`] = schemaJson(contract.response);
  }
  const document = {
    openapi: "3.1.0",
    info: {
      title: "mrjim-auth HTTP API",
      version: "0.1.0",
      description: "Framework-neutral public and current-user authentication routes.",
    },
    servers: [{ url: "/auth/v1" }],
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
