import { beforeEach, describe, expect, it, vi } from "vitest";

const verifyMock = vi.hoisted(() => vi.fn(async () => false));
const hashMock = vi.hoisted(() => vi.fn(async () => "$argon2id$v=19$m=65536,t=3,p=1$CZkVMQPqPBYxj8mD1te76w$nxfqv7qdqAz+cacdCnL/AmlBR68JuZ9zyXYqVFf6Puw"));

vi.mock("argon2", () => ({
  default: {
    argon2id: 2,
    hash: hashMock,
    verify: verifyMock,
  },
  argon2id: 2,
  hash: hashMock,
  verify: verifyMock,
}));

import { verifyPassword } from "../../src/server/passwords.js";

const PASSWORD = "correct horse battery staple";
const VALID_WEAK_HASH = "$argon2id$v=19$m=32768,t=2,p=1$c2FsdHh4eHg$aGFzaGRhdGE";

describe("bounded Argon2id verification work paths", () => {
  beforeEach(() => verifyMock.mockClear());

  it.each([
    ["oversized memory", "$argon2id$v=19$m=999999999,t=3,p=1$c2FsdHh4eHg$aGFzaGRhdGE"],
    ["oversized time", "$argon2id$v=19$m=65536,t=999999999,p=1$c2FsdHh4eHg$aGFzaGRhdGE"],
    ["non-policy lanes", "$argon2id$v=19$m=65536,t=3,p=2$c2FsdHh4eHg$aGFzaGRhdGE"],
    ["version mismatch", "$argon2id$v=18$m=65536,t=3,p=1$c2FsdHh4eHg$aGFzaGRhdGE"],
    ["invalid PHC base64", "$argon2id$v=19$m=65536,t=3,p=1$not-base64$still-not-base64"],
  ])("routes %s through the fixed dummy hash", async (_label, encodedHash) => {
    await expect(verifyPassword(PASSWORD, encodedHash)).resolves.toEqual({ valid: false, needsRehash: false });
    expect(verifyMock).toHaveBeenCalledTimes(1);
    expect((verifyMock.mock.calls[0] as unknown[] | undefined)?.[0]).not.toBe(encodedHash);
    expect((verifyMock.mock.calls[0] as unknown[] | undefined)?.[0]).toContain("$m=65536,t=3,p=1$");
  });

  it("passes a structurally valid weaker Argon2id hash to native verification for rehash eligibility", async () => {
    await verifyPassword(PASSWORD, VALID_WEAK_HASH);
    expect(verifyMock).toHaveBeenCalledWith(VALID_WEAK_HASH, PASSWORD);
  });
});
