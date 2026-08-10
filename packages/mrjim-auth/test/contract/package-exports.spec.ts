import { describe, expect, it } from "vitest";

describe("package export boundaries", () => {
  it("keeps the root entry browser safe", async () => {
    const root = await import("../../src/index.js");
    expect(Object.keys(root)).toEqual(expect.arrayContaining(["createClient"]));
    expect(root).not.toHaveProperty("createAuthServer");
    expect(root).not.toHaveProperty("createPostgresAdapter");
  });
});
