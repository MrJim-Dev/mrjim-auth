import { isIP } from "node:net";
import { Readable } from "node:stream";

export interface ExpressRequest {
  readonly method?: string;
  readonly originalUrl?: string;
  readonly url?: string;
  readonly headers?: Readonly<Record<string, string | readonly string[] | undefined>>;
  readonly body?: unknown;
  readonly socket?: { readonly remoteAddress?: string; readonly encrypted?: boolean };
  readonly connection?: { readonly remoteAddress?: string; readonly encrypted?: boolean };
}

export interface ExpressResponse {
  statusCode?: number;
  status?(status: number): ExpressResponse;
  setHeader(name: string, value: string | readonly string[]): unknown;
  write?(chunk: string | Uint8Array): unknown;
  end(chunk?: string | Uint8Array): unknown;
}

export interface ExpressAdapterOptions {
  readonly trustProxy?: { readonly hops: number };
}

export interface WebAuthServer {
  handle(request: Request): Promise<Response>;
}

function headerValue(headers: ExpressRequest["headers"], name: string): string | undefined {
  const value = headers?.[name];
  if (value === undefined) return undefined;
  if (typeof value === "string") return value;
  if (Array.isArray(value) && value.length === 1 && typeof value[0] === "string") return value[0];
  throw new TypeError("Ambiguous request header");
}

function requestHeaders(source: ExpressRequest["headers"], clientIp: string): Headers {
  const output = new Headers();
  if (source !== undefined) {
    for (const [name, value] of Object.entries(source)) {
      if (value === undefined || name.toLowerCase() === "x-real-ip") continue;
      if (typeof value === "string") output.append(name, value);
      else for (const item of value) output.append(name, item);
    }
  }
  output.set("x-real-ip", clientIp);
  return output;
}

function directIp(request: ExpressRequest): string {
  const value = request.socket?.remoteAddress ?? request.connection?.remoteAddress;
  if (typeof value !== "string" || isIP(value) === 0) throw new TypeError("Remote address is malformed");
  return value;
}

function requestTarget(request: ExpressRequest, options: ExpressAdapterOptions): { url: string; clientIp: string } {
  const direct = directIp(request);
  let host = headerValue(request.headers, "host");
  let protocol = request.socket?.encrypted === true || request.connection?.encrypted === true ? "https" : "http";
  let clientIp = direct;
  if (options.trustProxy !== undefined) {
    const hops = options.trustProxy.hops;
    if (!Number.isSafeInteger(hops) || hops < 1 || hops > 32) throw new TypeError("Proxy trust is malformed");
    const forwardedHost = headerValue(request.headers, "x-forwarded-host");
    const forwardedProtocol = headerValue(request.headers, "x-forwarded-proto");
    const forwardedFor = headerValue(request.headers, "x-forwarded-for");
    if (forwardedHost === undefined || forwardedProtocol === undefined || forwardedFor === undefined
      || forwardedHost.includes(",") || forwardedProtocol.includes(",") || !/^(?:http|https)$/u.test(forwardedProtocol)) throw new TypeError("Forwarded request is malformed");
    const chain = forwardedFor.split(",").map((value) => value.trim());
    if (chain.length === 0 || chain.length > 33 || chain.some((value) => isIP(value) === 0)) throw new TypeError("Forwarded request is malformed");
    host = forwardedHost;
    protocol = forwardedProtocol;
    clientIp = chain[Math.max(0, chain.length - hops)] ?? chain[0]!;
  }
  if (host === undefined || host.length === 0 || host.length > 253 || /[\s,@/\\]/u.test(host)) throw new TypeError("Host is malformed");
  const path = request.originalUrl ?? request.url ?? "/";
  if (typeof path !== "string" || !path.startsWith("/") || path.startsWith("//") || path.length > 16_384) throw new TypeError("Request URL is malformed");
  const url = new URL(path, `${protocol}://${host}`);
  if (url.username !== "" || url.password !== "") throw new TypeError("Request URL is malformed");
  return { url: url.href, clientIp };
}

function requestBody(request: ExpressRequest, method: string): RequestInit["body"] | undefined {
  if (method === "GET" || method === "HEAD") return undefined;
  if (request.body === undefined || request.body === null) {
    if (request instanceof Readable) return Readable.toWeb(request) as RequestInit["body"];
    return undefined;
  }
  if (typeof request.body === "string") return request.body;
  if (request.body instanceof Uint8Array) return new Uint8Array(request.body).buffer;
  if (request.body instanceof ArrayBuffer) return request.body;
  if (typeof request.body === "object") return JSON.stringify(request.body);
  throw new TypeError("Request body is malformed");
}

function setStatus(response: ExpressResponse, status: number): void {
  if (typeof response.status === "function") response.status(status);
  else response.statusCode = status;
}

function fail(response: ExpressResponse, status: 400 | 500): void {
  try {
    setStatus(response, status);
    response.setHeader("content-type", "application/json; charset=utf-8");
    response.setHeader("cache-control", "no-store");
    response.end(JSON.stringify({ error: status === 400 ? "Invalid request" : "Internal authentication error" }));
  } catch {
    try { response.end(); } catch { /* No further safe response action exists. */ }
  }
}

async function sendWebResponse(source: Response, target: ExpressResponse): Promise<void> {
  setStatus(target, source.status);
  const getSetCookie = (source.headers as Headers & { getSetCookie?: () => string[] }).getSetCookie;
  const cookies = typeof getSetCookie === "function" ? getSetCookie.call(source.headers) : [];
  for (const [name, value] of source.headers.entries()) if (name.toLowerCase() !== "set-cookie") target.setHeader(name, value);
  if (cookies.length > 0) target.setHeader("set-cookie", cookies);
  else {
    const cookie = source.headers.get("set-cookie");
    if (cookie !== null) target.setHeader("set-cookie", cookie);
  }
  if (source.body !== null && typeof target.write === "function") {
    const reader = source.body.getReader();
    for (;;) {
      const item = await reader.read();
      if (item.done) break;
      if (item.value !== undefined) target.write(item.value);
    }
    target.end();
  } else {
    const bytes = new Uint8Array(await source.arrayBuffer());
    target.end(bytes.length === 0 ? undefined : bytes);
  }
}

/** Adapts a framework-neutral AuthServer to an Express-compatible handler. */
export function toExpressHandler(server: WebAuthServer, options: ExpressAdapterOptions = {}) {
  if (server === null || typeof server !== "object" || typeof server.handle !== "function") throw new TypeError("Auth server is malformed");
  const handle = server.handle;
  return async (request: ExpressRequest, response: ExpressResponse): Promise<void> => {
    let webRequest: Request;
    try {
      const method = (request.method ?? "GET").toUpperCase();
      if (!/^[A-Z]{3,16}$/u.test(method)) throw new TypeError("Method is malformed");
      const target = requestTarget(request, options);
      const body = requestBody(request, method);
      webRequest = new Request(target.url, {
        method,
        headers: requestHeaders(request.headers, target.clientIp),
        ...(body === undefined ? {} : { body, duplex: "half" }),
      } as RequestInit);
    } catch {
      fail(response, 400);
      return;
    }
    try {
      const result = await Reflect.apply(handle, server, [webRequest]);
      if (!(result instanceof Response)) throw new TypeError("Auth server response is malformed");
      await sendWebResponse(result, response);
    } catch {
      fail(response, 500);
    }
  };
}
