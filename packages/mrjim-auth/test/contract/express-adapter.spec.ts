import { describe, expect, it } from "vitest";
import { toExpressHandler, type ExpressRequest, type ExpressResponse } from "../../src/adapters/express.js";

type CapturedRequest = {
  readonly method: string;
  readonly url: string;
  readonly headers: Headers;
  readonly body: string | null;
};

type FakeResponse = ExpressResponse & {
  readonly statusCode: number;
  readonly headers: Map<string, string[]>;
  readonly body: string;
  readonly ended: boolean;
};

function createRequest(input: Partial<ExpressRequest> = {}): ExpressRequest {
  const body = input.body ?? null;
  const request = {
    method: "POST",
    originalUrl: "/auth/v1/signup?invite=abc&invite=def",
    url: "/auth/v1/signup?invite=abc&invite=def",
    headers: {
      host: "direct.example.test",
      "content-type": "application/json",
      "x-request-id": "express-contract",
      ...(input.headers ?? {}),
    },
    body,
    socket: { remoteAddress: "192.0.2.10", encrypted: false },
    connection: { remoteAddress: "192.0.2.10", encrypted: false },
    ...input,
  } as ExpressRequest;
  return request;
}

function createResponse(): FakeResponse {
  const headers = new Map<string, string[]>();
  let statusCode = 200;
  let body = "";
  let ended = false;
  const response = {
    get statusCode() {
      return statusCode;
    },
    get headers() {
      return headers;
    },
    get body() {
      return body;
    },
    get ended() {
      return ended;
    },
    status(value: number) {
      statusCode = value;
      return response;
    },
    setHeader(name: string, value: string | readonly string[]) {
      headers.set(name.toLowerCase(), Array.isArray(value) ? [...value] : [value]);
      return response;
    },
    getHeader(name: string) {
      return headers.get(name.toLowerCase());
    },
    removeHeader(name: string) {
      headers.delete(name.toLowerCase());
    },
    end(value?: string | Uint8Array) {
      if (typeof value === "string") body += value;
      else if (value !== undefined) body += new TextDecoder().decode(value);
      ended = true;
      return response;
    },
    write(value: string | Uint8Array) {
      body += typeof value === "string" ? value : new TextDecoder().decode(value);
      return true;
    },
    on() {
      return response;
    },
    once() {
      return response;
    },
    emit() {
      return false;
    },
  } as unknown as FakeResponse;
  return response;
}

function createServer(capture: (request: CapturedRequest) => Response): { readonly server: { handle(request: Request): Promise<Response> }; readonly requests: CapturedRequest[] } {
  const requests: CapturedRequest[] = [];
  return {
    requests,
    server: {
      async handle(request) {
        requests.push({
          method: request.method,
          url: request.url,
          headers: new Headers(request.headers),
          body: request.body === null ? null : await request.text(),
        });
        return capture(requests[requests.length - 1]!);
      },
    },
  };
}

describe("Express adapter contract", () => {
  it("translates exact method/path/query/headers/body and streams response headers/body", async () => {
    const captured: CapturedRequest[] = [];
    const authServer = {
      async handle(request: Request) {
        captured.push({
          method: request.method,
          url: request.url,
          headers: new Headers(request.headers),
          body: request.body === null ? null : await request.text(),
        });
        return new Response(new ReadableStream({
          start(controller) {
            controller.enqueue(new TextEncoder().encode("part-1"));
            controller.enqueue(new TextEncoder().encode("part-2"));
            controller.close();
          },
        }), {
          status: 201,
          headers: [
            ["content-type", "text/plain"],
            ["set-cookie", "a=1; Path=/"],
            ["set-cookie", "b=2; Path=/"],
          ],
        });
      },
    };
    const response = createResponse();
    await toExpressHandler(authServer)(createRequest({ body: "{\"email\":\"user@example.test\"}" }), response);

    expect(captured).toHaveLength(1);
    expect(captured[0]).toMatchObject({
      method: "POST",
      url: "http://direct.example.test/auth/v1/signup?invite=abc&invite=def",
      body: "{\"email\":\"user@example.test\"}",
    });
    expect(captured[0]!.headers.get("content-type")).toBe("application/json");
    expect(captured[0]!.headers.get("x-request-id")).toBe("express-contract");
    expect(response.statusCode).toBe(201);
    expect(response.headers.get("content-type")).toEqual(["text/plain"]);
    expect(response.headers.get("set-cookie")).toEqual(["a=1; Path=/", "b=2; Path=/"]);
    expect(response.body).toBe("part-1part-2");
    expect(response.ended).toBe(true);
  });

  it("uses direct socket host/proto/ip and does not trust forwarded headers by default", async () => {
    const { server, requests } = createServer(() => new Response("ok"));
    const response = createResponse();
    await toExpressHandler(server)(createRequest({
      headers: {
        host: "direct.example.test",
        "x-forwarded-host": "attacker.example.test",
        "x-forwarded-proto": "https",
        "x-forwarded-for": "203.0.113.9",
      },
      socket: { remoteAddress: "192.0.2.10", encrypted: false },
    }), response);

    expect(requests[0]!.url).toBe("http://direct.example.test/auth/v1/signup?invite=abc&invite=def");
    expect(requests[0]!.headers.get("x-real-ip")).toBe("192.0.2.10");
    expect(requests[0]!.headers.get("x-forwarded-for")).toBe("203.0.113.9");
  });

  it("uses forwarded host/proto/ip only when explicitly trusted", async () => {
    const { server, requests } = createServer(() => new Response("ok"));
    const response = createResponse();
    await toExpressHandler(server, {
      trustProxy: { hops: 1 },
    })(createRequest({
      headers: {
        host: "proxy.internal.test",
        "x-forwarded-host": "public.example.test",
        "x-forwarded-proto": "https",
        "x-forwarded-for": "203.0.113.9, 192.0.2.20",
      },
      socket: { remoteAddress: "192.0.2.20", encrypted: false },
    }), response);

    expect(requests[0]!.url).toBe("https://public.example.test/auth/v1/signup?invite=abc&invite=def");
    expect(requests[0]!.headers.get("x-real-ip")).toBe("203.0.113.9");
  });

  it("rejects ambiguous or malformed forwarded values when proxy trust is enabled", async () => {
    const { server, requests } = createServer(() => new Response("should not run"));
    const response = createResponse();
    await toExpressHandler(server, { trustProxy: { hops: 1 } })(createRequest({
      headers: {
        "x-forwarded-host": "public.example.test, attacker.example.test",
        "x-forwarded-proto": "https,http",
        "x-forwarded-for": "not-an-ip, 192.0.2.20",
      },
    }), response);

    expect(requests).toHaveLength(0);
    expect(response.statusCode).toBe(400);
    expect(response.body).toBe(JSON.stringify({ error: "Invalid request" }));
    expect(response.body).not.toContain("not-an-ip");
  });

  it("contains handler, request, response, and stream failures behind a fixed redacted response", async () => {
    const secret = "body-token-secret";
    const response = createResponse();
    await toExpressHandler({
      async handle() {
        throw new Error(`boom ${secret}`);
      },
    })(createRequest({ body: secret }), response);

    expect(response.statusCode).toBe(500);
    expect(response.body).toBe(JSON.stringify({ error: "Internal authentication error" }));
    expect(response.body).not.toContain(secret);
    expect(response.body).not.toContain("Error");
  });
});
