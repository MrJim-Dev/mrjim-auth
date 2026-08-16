import { describe, expect, it, vi } from "vitest";
import { toNextRouteHandler } from "../../src/adapters/nextjs-route.js";

describe("Next.js App Router adapter", () => {
  it("delegates the unchanged Web Request and Response to the project-owned auth server", async () => {
    const response = new Response(JSON.stringify({ data: { ok: true }, error: null }), {
      status: 201,
      headers: {
        "cache-control": "no-store",
        "set-cookie": "mrjim-auth.0=session; HttpOnly; Secure; SameSite=Lax; Path=/",
      },
    });
    const server = {
      marker: "project-server",
      handle: vi.fn(async function (this: { marker: string }, request: Request) {
        expect(this.marker).toBe("project-server");
        expect(request.method).toBe("POST");
        expect(request.url).toBe("https://project.example.test/auth/v1/token?grant_type=password");
        expect(request.headers.get("x-request-id")).toBe("route-contract");
        expect(await request.json()).toEqual({ email: "user@example.test", password: "secret" });
        return response;
      }),
    };
    const request = new Request("https://project.example.test/auth/v1/token?grant_type=password", {
      method: "POST",
      headers: { "content-type": "application/json", "x-request-id": "route-contract" },
      body: JSON.stringify({ email: "user@example.test", password: "secret" }),
    });

    const handler = toNextRouteHandler(server);
    await expect(handler(request)).resolves.toBe(response);
    expect(server.handle).toHaveBeenCalledTimes(1);
    expect(server.handle).toHaveBeenCalledWith(request);
  });

  it("fails during setup when the supplied auth server is malformed", () => {
    expect(() => toNextRouteHandler(null as never)).toThrow(/auth server/i);
    expect(() => toNextRouteHandler({} as never)).toThrow(/auth server/i);
    expect(() => toNextRouteHandler({ handle: "not-a-function" } as never)).toThrow(/auth server/i);
  });
});
