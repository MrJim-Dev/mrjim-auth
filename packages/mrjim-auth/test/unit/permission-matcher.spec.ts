import { describe, expect, it } from "vitest";
import {
  normalizePermissionKey,
  permissionMatchRank,
  permissionMatches,
} from "../../src/server/authorization.js";

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
});
