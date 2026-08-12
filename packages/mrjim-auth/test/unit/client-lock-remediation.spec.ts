import { describe, expect, it } from "vitest";
import { createLockController } from "../../src/client/lock.js";

describe("Task 10 review lock remediation", () => {
  it("never releases the fallback queue while an acquired callback is still running", async () => {
    const first = createLockController({ storageKey: "review-timeout", timeoutMs: 10 });
    const second = createLockController({ storageKey: "review-timeout", timeoutMs: 50 });
    let active = 0;
    let maxActive = 0;
    const work = async (delay: number): Promise<number> => {
      active += 1;
      maxActive = Math.max(maxActive, active);
      await new Promise((resolve) => setTimeout(resolve, delay));
      active -= 1;
      return delay;
    };

    const firstResult = first.run(() => work(30));
    await new Promise((resolve) => setTimeout(resolve, 15));
    const secondResult = second.run(() => work(1));

    await expect(firstResult).resolves.toBe(30);
    await expect(secondResult).resolves.toBe(1);
    expect(maxActive).toBe(1);
  });
});
