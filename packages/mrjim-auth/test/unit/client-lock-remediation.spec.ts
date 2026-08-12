import { afterEach, describe, expect, it, vi } from "vitest";
import { createLockController } from "../../src/client/lock.js";

describe("Task 10 review lock remediation", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("never releases the fallback queue while an acquired callback is still running", async () => {
    vi.stubGlobal("navigator", {});
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

  it("keeps later callers behind the active holder when a queued waiter times out", async () => {
    vi.stubGlobal("navigator", {});
    const owner = createLockController({ storageKey: "review-acquisition-timeout", timeoutMs: 1_000 });
    const abandoned = createLockController({ storageKey: "review-acquisition-timeout", timeoutMs: 10 });
    const later = createLockController({ storageKey: "review-acquisition-timeout", timeoutMs: 1_000 });
    let active = 0;
    let maxActive = 0;
    const work = async (delay: number): Promise<number> => {
      active += 1;
      maxActive = Math.max(maxActive, active);
      await new Promise((resolve) => setTimeout(resolve, delay));
      active -= 1;
      return delay;
    };

    const ownerResult = owner.run(() => work(60));
    await new Promise((resolve) => setTimeout(resolve, 1));
    const abandonedResult = abandoned.run(() => work(1));
    await expect(abandonedResult).rejects.toThrow("lock acquisition timed out");
    const laterResult = later.run(() => work(1));

    await expect(ownerResult).resolves.toBe(60);
    await expect(laterResult).resolves.toBe(1);
    expect(maxActive).toBe(1);
  });
});
