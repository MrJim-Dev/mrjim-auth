import { describe, expect, it } from "vitest";
import bcrypt from "bcryptjs";
import {
  EmailService,
  normalizeAndValidateEmail,
} from "../../src/server/email.js";
import {
  ARGON2ID_PASSWORD_POLICY,
  PasswordService,
  isStrongArgon2idHash,
} from "../../src/server/passwords.js";

const CALLBACK = "https://project.example.com/auth/callback";
const PASSWORD = "correct horse battery staple";

describe("Task 6 password and email primitives", () => {
  it("normalizes only with Unicode normalization, trim, and lowercase", () => {
    expect(normalizeAndValidateEmail("  Cafe\u0301+tag@Example.com ")).toEqual({
      display: "Café+tag@Example.com",
      normalized: "café+tag@example.com",
    });
    expect(normalizeAndValidateEmail("First.Last+tag@gmail.com").normalized).toBe("first.last+tag@gmail.com");
  });

  it("rejects malformed email input without echoing the identifier", () => {
    let thrown: unknown;
    try {
      normalizeAndValidateEmail("bad\naddress@example.com");
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toMatchObject({ message: "Invalid email address", code: "invalid_request" });
    expect((thrown as Error).message).not.toContain("bad");
  });

  it("uses the Argon2id floor and performs verification through the encoded hash", async () => {
    const service = new PasswordService();
    const encoded = await service.hash(PASSWORD);
    expect(encoded).toMatch(/^\$argon2id\$v=19\$m=65536,t=3,p=1\$/u);
    expect(isStrongArgon2idHash(encoded)).toBe(true);
    expect(ARGON2ID_PASSWORD_POLICY).toMatchObject({ memoryCost: 65536, timeCost: 3, parallelism: 1, version: 19 });
    await expect(service.verify(PASSWORD, encoded)).resolves.toEqual({ valid: true, needsRehash: false });
    await expect(service.verify("wrong password", encoded)).resolves.toEqual({ valid: false, needsRehash: false });
    await expect(service.verify(PASSWORD, null)).resolves.toEqual({ valid: false, needsRehash: false });
    expect(() => new PasswordService({ memoryCost: 32 * 1024 })).toThrowError(/security floor/i);
    expect(() => new PasswordService({ parallelism: 2 })).toThrowError(/security floor/i);
  });

  it("accepts legacy bcrypt credentials long enough to rehash them", async () => {
    const service = new PasswordService();
    const legacyHash = await bcrypt.hash(PASSWORD, 4);
    await expect(service.verify(PASSWORD, legacyHash)).resolves.toEqual({ valid: true, needsRehash: true });
    await expect(service.verify("wrong password", legacyHash)).resolves.toEqual({ valid: false, needsRehash: false });
  });

  it("requires exact configured redirects and only derives bearer links in memory", () => {
    const email = new EmailService({ allowedRedirects: [CALLBACK] });
    expect(email.resolveRedirect()).toBe(CALLBACK);
    expect(email.link(CALLBACK, "raw-token")).toBe(`${CALLBACK}?token=raw-token`);
    expect(() => email.resolveRedirect(`${CALLBACK}?next=other`)).toThrowError(/not allowed/i);
    expect(() => new EmailService({ allowedRedirects: [`${CALLBACK}#fragment`] })).toThrowError(/fragments/i);
  });
});
