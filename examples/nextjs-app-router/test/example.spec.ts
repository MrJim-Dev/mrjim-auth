import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { credentialsFrom, hasPermission, navigationForPermissions, readObject, recoveryFrom, requiredText } from "../src/example.js";

const root = resolve(import.meta.dirname, "..");

function source(path: string): string {
  return readFileSync(resolve(root, path), "utf8");
}

describe("Next.js App Router example", () => {
  it("filters navigation using exact permissions and supported wildcards", () => {
    expect(hasPermission(["invoice.read"], "invoice.read")).toBe(true);
    expect(hasPermission(["invoice.*"], "invoice.read")).toBe(true);
    expect(hasPermission(["auth.users.*"], "auth.users.manage")).toBe(true);
    expect(hasPermission(["*.*"], "auth.users.manage")).toBe(true);
    expect(hasPermission(["invoice.read"], "auth.users.manage")).toBe(false);
    expect(navigationForPermissions(["invoice.read"]).map((item) => item.href)).toEqual(["/profile", "/invoices"]);
  });

  it("keeps auth input parsing bounded and rejects non-record JSON", () => {
    expect(readObject(null)).toBeNull();
    expect(readObject([])).toBeNull();
    expect(requiredText("  hello ", 5)).toBe("hello");
    expect(requiredText("too long", 3)).toBeNull();
    expect(credentialsFrom({ email: "user@example.test", password: "correct horse" })).toEqual({
      email: "user@example.test",
      password: "correct horse",
    });
    expect(credentialsFrom({ email: "user@example.test", password: "short" })).toBeNull();
    expect(recoveryFrom({ email: "user@example.test", password: "correct horse", token: "one-time" })).toEqual({
      email: "user@example.test",
      password: "correct horse",
      token: "one-time",
    });
  });

  it("keeps protected rendering on validated getUser and server-owned cookies", () => {
    const serverAuth = source("src/lib/server-auth.ts");
    const profile = source("src/app/profile/page.tsx");
    const callback = source("src/app/auth/callback/route.ts");
    expect(serverAuth).toContain("client.auth.getUser()");
    expect(serverAuth).toContain("createServerClient");
    expect(serverAuth).not.toContain("client.auth.getSession()");
    expect(profile).toContain("getServerAuthState");
    expect(profile).toContain("dynamic = \"force-dynamic\"");
    expect(callback).toContain("exchangeCodeForSession");
    expect(callback).toContain("NextResponse.redirect");
  });

  it("exposes all required browser and server flows in the runnable tree", () => {
    expect(source("src/lib/browser-auth.ts")).toContain("createBrowserClient");
    expect(source("src/app/api/auth/password/route.ts")).toContain("signInWithPassword");
    expect(source("src/app/api/auth/password/route.ts")).toContain("signUp");
    expect(source("src/app/api/auth/google/route.ts")).toContain("signInWithOAuth");
    expect(source("src/app/api/auth/recovery/request/route.ts")).toContain("resetPasswordForEmail");
    expect(source("src/app/api/auth/recovery/reset/route.ts")).toContain("resetPassword");
    expect(source("src/app/auth/logout/route.ts")).toContain("signOut");
  });
});
