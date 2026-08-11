import { describe, expect, it } from "vitest";
import { AuthConfigurationError } from "../../src/shared/errors.js";
import { authSuccess } from "../../src/shared/result.js";
import { uuidSchema } from "../../src/shared/types.js";
import { createOAuthRoutes } from "../../src/server/routes/oauth.js";
import { createPermissionRoutes } from "../../src/server/routes/permissions.js";
import type { OAuthService } from "../../src/server/oauth.js";
import type { AuthorizationService } from "../../src/server/authorization.js";

const USER_ID = uuidSchema.parse("00000000-0000-4000-8000-000000000901");

function oauthFixture() {
  const calls: string[] = [];
  const service = {
    listProviders() {
      calls.push("listProviders");
      return [];
    },
    authorize() {
      calls.push("authorize");
      return Promise.resolve(authSuccess({
        provider: "google",
        url: "https://accounts.example/authorize",
        redirect: "https://project.example.com/callback",
        expiresAt: "2026-08-11T00:01:00.000Z",
      }));
    },
    callback() {
      calls.push("callback");
      return Promise.resolve(authSuccess({
        code: "internal-code",
        redirect: "https://project.example.com/callback",
        url: "https://project.example.com/callback?code=internal-code",
        expiresAt: "2026-08-11T00:01:00.000Z",
      }));
    },
    exchangeCode() {
      calls.push("exchangeCode");
      return Promise.resolve(authSuccess({ user: {}, identity: {}, session: {} }));
    },
    listIdentities() {
      return Promise.resolve(authSuccess([]));
    },
    unlinkIdentity() {
      return Promise.resolve(authSuccess(null));
    },
  };
  return { calls, service };
}

describe("public route factory callback boundaries", () => {
  it("captures every OAuth route callback with its original receiver", async () => {
    const { calls, service } = oauthFixture();
    const routes = createOAuthRoutes(service as unknown as OAuthService);
    const mutable = service as Record<string, unknown>;
    for (const method of ["listProviders", "authorize", "callback", "exchangeCode"] as const) {
      mutable[method] = () => { throw new Error(`route-${method}-sentinel`); };
    }

    expect(routes.providers()?.status).toBe(200);
    expect((await routes.authorize(new Request("https://project.example.com/authorize?provider=google&code_challenge=challenge"))).status).toBe(200);
    expect((await routes.callback("google", new Request("https://project.example.com/callback"))).status).toBe(303);
    expect((await routes.exchange(new Request("https://project.example.com/exchange", {
      method: "POST",
      body: JSON.stringify({ code: "internal-code", code_verifier: "verifier" }),
      headers: { "content-type": "application/json" },
    }))).status).toBe(200);
    expect(calls).toEqual(["listProviders", "authorize", "callback", "exchangeCode"]);
  });

  it("rejects OAuth route accessor and thenable callbacks without invoking them", () => {
    const accessor = oauthFixture().service as Record<string, unknown>;
    let getterCalls = 0;
    Object.defineProperty(accessor, "listProviders", {
      configurable: true,
      get: () => { getterCalls += 1; throw new Error("route-accessor-sentinel"); },
    });
    expect(() => createOAuthRoutes(accessor as unknown as OAuthService)).toThrow(AuthConfigurationError);
    expect(getterCalls).toBe(0);

    const thenable = oauthFixture().service as Record<string, unknown>;
    let thenCalls = 0;
    thenable.listProviders = { then: () => { thenCalls += 1; } };
    expect(() => createOAuthRoutes(thenable as unknown as OAuthService)).toThrow(AuthConfigurationError);
    expect(thenCalls).toBe(0);
  });

  it("captures the permission route callback before caller mutation", async () => {
    let calls = 0;
    const service = {
      getPermissions() {
        calls += 1;
        return ["invoice.read"];
      },
      authorize() {
        return true;
      },
    } as Record<string, unknown>;
    const routes = createPermissionRoutes(service as unknown as AuthorizationService);
    service.getPermissions = () => { throw new Error("permission-route-sentinel"); };
    const response = await routes.permissions(
      new Request("https://project.example.com/user/permissions"),
      { user_id: USER_ID },
    );
    expect(response.status).toBe(200);
    expect(calls).toBe(1);
  });

  it("rejects permission route accessor and thenable callbacks without invoking them", () => {
    const accessor = { authorize() { return true; } } as Record<string, unknown>;
    let getterCalls = 0;
    Object.defineProperty(accessor, "getPermissions", {
      configurable: true,
      get: () => { getterCalls += 1; throw new Error("permission-accessor-sentinel"); },
    });
    expect(() => createPermissionRoutes(accessor as unknown as AuthorizationService)).toThrow(AuthConfigurationError);
    expect(getterCalls).toBe(0);

    const thenable = {
      getPermissions: { then: () => { throw new Error("permission-then-sentinel"); } },
      authorize() { return true; },
    } as Record<string, unknown>;
    expect(() => createPermissionRoutes(thenable as unknown as AuthorizationService)).toThrow(AuthConfigurationError);
  });
});
