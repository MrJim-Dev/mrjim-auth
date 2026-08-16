export interface WebAuthServer {
  handle(request: Request): Promise<Response>;
}

/** Adapts a framework-neutral AuthServer to a Next.js App Router handler. */
export function toNextRouteHandler(server: WebAuthServer) {
  if (server === null || typeof server !== "object" || typeof server.handle !== "function") {
    throw new TypeError("Auth server is malformed");
  }
  const handle = server.handle;
  return async (request: Request): Promise<Response> => {
    return handle.call(server, request);
  };
}
