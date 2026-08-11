import { describe, expect, it } from "vitest";
import {
  createCodeChallenge,
  generateCodeVerifier,
  generatePkcePair,
} from "../../src/client/pkce.js";

describe("RFC 7636 PKCE", () => {
  it("computes the RFC 7636 S256 test-vector challenge", async () => {
    await expect(
      createCodeChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
    ).resolves.toBe("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
  });

  it("generates an RFC-compliant verifier and S256-only pair", async () => {
    const verifier = generateCodeVerifier();
    expect(verifier).toMatch(/^[A-Za-z0-9._~-]{43,128}$/);
    const pair = await generatePkcePair();
    expect(pair.method).toBe("S256");
    expect(pair.codeVerifier).toMatch(/^[A-Za-z0-9._~-]{43,128}$/);
    expect(pair.codeChallenge).toBe(await createCodeChallenge(pair.codeVerifier));
  });

  it("rejects malformed verifiers instead of accepting plain PKCE", async () => {
    await expect(createCodeChallenge("plain")).rejects.toThrow();
    await expect(createCodeChallenge("a".repeat(129))).rejects.toThrow();
    await expect(createCodeChallenge("a".repeat(43) + "=")).rejects.toThrow();
  });
});
