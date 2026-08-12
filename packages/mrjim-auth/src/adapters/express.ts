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
  once?(event: "drain" | "error" | "close", listener: (error?: unknown) => void): unknown;
  off?(event: "drain" | "error" | "close", listener: (error?: unknown) => void): unknown;
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

interface RequestTarget {
  readonly url: string;
  readonly clientIp: string;
  readonly host: string;
  readonly protocol: "http" | "https";
  readonly forwarded: boolean;
}

function requestHeaders(source: ExpressRequest["headers"], target: RequestTarget, reconstructedBody: boolean): Headers {
  const output = new Headers();
  if (source !== undefined) {
    for (const [name, value] of Object.entries(source)) {
      const lower = name.toLowerCase();
      if (value === undefined || lower === "host" || lower === "x-real-ip" || lower === "forwarded"
        || lower.startsWith("x-forwarded-")
        || (reconstructedBody && (lower === "content-length" || lower === "transfer-encoding"))) continue;
      if (typeof value === "string") output.append(name, value);
      else for (const item of value) output.append(name, item);
    }
  }
  output.set("host", target.host);
  output.set("x-real-ip", target.clientIp);
  if (target.forwarded) {
    output.set("x-forwarded-for", target.clientIp);
    output.set("x-forwarded-host", target.host);
    output.set("x-forwarded-proto", target.protocol);
  }
  return output;
}

function directIp(request: ExpressRequest): string {
  const value = request.socket?.remoteAddress ?? request.connection?.remoteAddress;
  if (typeof value !== "string" || isIP(value) === 0) throw new TypeError("Remote address is malformed");
  return value;
}

function requestTarget(request: ExpressRequest, options: ExpressAdapterOptions): RequestTarget {
  const direct = directIp(request);
  let host = headerValue(request.headers, "host");
  let protocol: "http" | "https" = request.socket?.encrypted === true || request.connection?.encrypted === true ? "https" : "http";
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
    protocol = forwardedProtocol as "http" | "https";
    clientIp = chain[Math.max(0, chain.length - hops)] ?? chain[0]!;
  }
  if (host === undefined || host.length === 0 || host.length > 253 || /[\s,@/\\]/u.test(host)) throw new TypeError("Host is malformed");
  const path = request.originalUrl ?? request.url ?? "/";
  if (typeof path !== "string" || !path.startsWith("/") || path.startsWith("//") || path.length > 16_384) throw new TypeError("Request URL is malformed");
  const url = new URL(path, `${protocol}://${host}`);
  if (url.username !== "" || url.password !== "") throw new TypeError("Request URL is malformed");
  return { url: url.href, clientIp, host, protocol, forwarded: options.trustProxy !== undefined };
}

function formBody(value: object): string {
  const params = new URLSearchParams();
  for (const key of Object.keys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !("value" in descriptor)) throw new TypeError("Request body is malformed");
    const item = descriptor.value as unknown;
    const values = Array.isArray(item) ? item : [item];
    if (values.length > 256) throw new TypeError("Request body is malformed");
    for (const entry of values) {
      if (typeof entry !== "string" && typeof entry !== "number" && typeof entry !== "boolean") throw new TypeError("Request body is malformed");
      params.append(key, String(entry));
    }
  }
  return params.toString();
}

interface TranslatedBody {
  readonly body: RequestInit["body"] | undefined;
  readonly reconstructed: boolean;
}

function requestBody(request: ExpressRequest, method: string): TranslatedBody {
  if (method === "GET" || method === "HEAD") return { body: undefined, reconstructed: false };
  const value = request.body;
  const rawContentType = headerValue(request.headers, "content-type");
  const contentType = rawContentType?.split(";", 1)[0]?.trim().toLowerCase();
  if (value === undefined) {
    if (request instanceof Readable) return { body: Readable.toWeb(request) as RequestInit["body"], reconstructed: false };
    return { body: undefined, reconstructed: false };
  }
  if (value === null) {
    if (contentType === "application/json" || contentType?.endsWith("+json") === true) return { body: "null", reconstructed: true };
    throw new TypeError("Request body is malformed");
  }
  if (typeof value === "string") return { body: value, reconstructed: true };
  if (value instanceof Uint8Array) return { body: new Uint8Array(value).buffer, reconstructed: true };
  if (value instanceof ArrayBuffer) return { body: value, reconstructed: true };
  if (typeof value === "object") {
    if (contentType === "application/json" || contentType?.endsWith("+json") === true) return { body: JSON.stringify(value), reconstructed: true };
    if (contentType === "application/x-www-form-urlencoded") return { body: formBody(value), reconstructed: true };
  }
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
  const getSetCookie = (source.headers as Headers & { getSetCookie?: () => string[] }).getSetCookie;
  const combinedCookie = source.headers.get("set-cookie");
  if (combinedCookie !== null && typeof getSetCookie !== "function") throw new TypeError("Multi-value response cookies are unavailable");
  const cookies = typeof getSetCookie === "function" ? getSetCookie.call(source.headers) : [];
  if (!Array.isArray(cookies) || cookies.some((cookie) => typeof cookie !== "string")) throw new TypeError("Response cookies are malformed");
  setStatus(target, source.status);
  for (const [name, value] of source.headers.entries()) if (name.toLowerCase() !== "set-cookie") target.setHeader(name, value);
  if (cookies.length > 0) target.setHeader("set-cookie", cookies);
  if (source.body !== null && typeof target.write === "function") {
    const reader = source.body.getReader();
    try {
      for (;;) {
        const item = await reader.read();
        if (item.done) break;
        if (item.value !== undefined && target.write(item.value) === false) await waitForDrain(target);
      }
    } catch (error) {
      try { await reader.cancel(); } catch { /* Preserve the original stream failure. */ }
      throw error;
    }
    target.end();
  } else {
    const bytes = new Uint8Array(await source.arrayBuffer());
    target.end(bytes.length === 0 ? undefined : bytes);
  }
}

function waitForDrain(target: ExpressResponse): Promise<void> {
  if (typeof target.once !== "function") throw new TypeError("Response backpressure is unsupported");
  return new Promise<void>((resolve, reject) => {
    let settled = false;
    const cleanup = (): void => {
      if (typeof target.off !== "function") return;
      target.off("drain", onDrain);
      target.off("error", onFailure);
      target.off("close", onFailure);
    };
    const finish = (operation: () => void): void => {
      if (settled) return;
      settled = true;
      cleanup();
      operation();
    };
    const onDrain = (): void => finish(resolve);
    const onFailure = (): void => finish(() => reject(new TypeError("Response stream closed")));
    target.once!("drain", onDrain);
    target.once!("error", onFailure);
    target.once!("close", onFailure);
  });
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
      const translated = requestBody(request, method);
      webRequest = new Request(target.url, {
        method,
        headers: requestHeaders(request.headers, target, translated.reconstructed),
        ...(translated.body === undefined ? {} : { body: translated.body, duplex: "half" }),
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
