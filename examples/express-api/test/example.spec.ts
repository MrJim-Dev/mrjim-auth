import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { authorizationRequest, sampleInvoices } from "../src/example.js";

const root = resolve(import.meta.dirname, "..");
const source = (path: string): string => readFileSync(resolve(root, path), "utf8");

describe("Express API example", () => {
  it("builds a bounded authorization request without copying arbitrary headers", () => {
    const request = authorizationRequest({
      headers: {
        apikey: "publishable_example_key",
        authorization: "Bearer access-token",
        cookie: "must-not-cross-the-boundary",
        "x-request-id": "request_123",
      },
    }, "http://localhost:3000/auth/v1");
    expect(request.headers.get("apikey")).toBe("publishable_example_key");
    expect(request.headers.get("authorization")).toBe("Bearer access-token");
    expect(request.headers.get("cookie")).toBeNull();
    expect(request.headers.get("x-request-id")).toBe("request_123");
  });

  it("rejects ambiguous or missing credentials", () => {
    expect(() => authorizationRequest({ headers: { apikey: ["one", "two"], authorization: "Bearer token" } }, "http://localhost/auth/v1")).toThrow();
    expect(() => authorizationRequest({ headers: { apikey: "key" } }, "http://localhost/auth/v1")).toThrow();
  });

  it("mounts auth, migrates explicitly, seeds RBAC, and protects invoices", () => {
    expect(source("src/server.ts")).toContain('app.use("/auth/v1"');
    expect(source("src/server.ts")).toContain("toExpressHandler(authServer)");
    expect(source("src/server.ts")).toContain("authServer.authorize");
    expect(source("src/server.ts")).toContain('all: ["invoice.read"]');
    expect(source("src/migrate.ts")).toContain('migrate(pool, { direction: "up" })');
    expect(source("src/seed.ts")).toContain("ON CONFLICT (key) DO UPDATE");
    expect(source("src/seed.ts")).toContain("invoice.read");
    expect(sampleInvoices).toHaveLength(2);
  });
});
