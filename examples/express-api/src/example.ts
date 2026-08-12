import type { Request } from "express";

function oneHeader(value: string | readonly string[] | undefined, name: string): string {
  if (typeof value !== "string" || value.length === 0 || /[\r\n]/u.test(value)) {
    throw new TypeError(`${name} header is required`);
  }
  return value;
}

/** Builds the minimal credential request consumed by AuthServer.authorize(). */
export function authorizationRequest(request: Pick<Request, "headers">, authBaseUrl: string): globalThis.Request {
  const headers = new Headers({
    apikey: oneHeader(request.headers.apikey, "apikey"),
    authorization: oneHeader(request.headers.authorization, "authorization"),
  });
  const requestId = request.headers["x-request-id"];
  if (typeof requestId === "string") headers.set("x-request-id", requestId);
  const origin = request.headers.origin;
  if (typeof origin === "string") headers.set("origin", origin);
  return new globalThis.Request(`${authBaseUrl}/authorize-check`, { method: "GET", headers });
}

export const sampleInvoices = Object.freeze([
  Object.freeze({ id: "inv_1001", total: 12500, currency: "PHP" }),
  Object.freeze({ id: "inv_1002", total: 8900, currency: "PHP" }),
]);
