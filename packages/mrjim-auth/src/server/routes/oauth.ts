import type { AuthenticatedSubject } from "../users.js";
import { authFailure, authSuccess, type AuthResult } from "../../shared/result.js";
import { AuthApiError } from "../../shared/errors.js";
import {
  OAuthService,
  type OAuthAuthorizeResult,
  type OAuthCallbackResult,
  type OAuthExchangeInput,
  type OAuthLinkResult,
  type OAuthSessionResult,
  type OAuthSubject,
} from "../oauth.js";
import { captureBoundaryMethodGroup } from "../callback-boundary.js";

const OAUTH_ROUTE_METHODS = ["listProviders", "authorize", "callback", "exchangeCode", "listIdentities", "unlinkIdentity"] as const;

function captureOAuthRouteService(service: OAuthService): OAuthService {
  return captureBoundaryMethodGroup(
    service,
    "OAuth route service",
    OAUTH_ROUTE_METHODS,
    [],
    {},
    "source",
    true,
  ) as unknown as OAuthService;
}

function json(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}

function resultResponse<T>(result: AuthResult<T>): Response {
  return json(result, result.error === null ? 200 : result.error.status);
}

function methodNotAllowed(): Response {
  return json(authFailure(new AuthApiError("invalid_request", 405, "Method is not allowed")), 405);
}

function query(request: Request, key: string): string | null {
  return new URL(request.url).searchParams.get(key);
}

function safeAuthorizeResult(result: AuthResult<OAuthAuthorizeResult>): AuthResult<{
  readonly provider: string;
  readonly url: string;
  readonly redirect: string;
  readonly expires_at: string;
}> {
  if (result.error !== null || result.data === null) return result as AuthResult<never>;
  return authSuccess({
    provider: result.data.provider,
    url: result.data.url,
    redirect: result.data.redirect,
    expires_at: result.data.expiresAt,
  });
}

/** Serves the public enabled-provider discovery endpoint. */
export function providersRoute(service: OAuthService, request?: Request): Response {
  const capturedService = captureOAuthRouteService(service);
  if (request !== undefined && request.method !== "GET") return methodNotAllowed();
  return resultResponse(authSuccess(capturedService.listProviders()));
}

/** Serves the authorization endpoint; authenticated subjects are supplied by the caller. */
export async function authorizeRoute(
  service: OAuthService,
  request: Request,
  subject?: OAuthSubject,
): Promise<Response> {
  const capturedService = captureOAuthRouteService(service);
  if (request.method !== "GET") return methodNotAllowed();
  const flow = query(request, "flow");
  const codeChallengeMethod = query(request, "code_challenge_method");
  if (codeChallengeMethod !== null && codeChallengeMethod !== "S256") {
    return resultResponse(authFailure(new AuthApiError("invalid_request", 400, "Only PKCE S256 is supported")));
  }
  const input = {
    provider: query(request, "provider") ?? "",
    codeChallenge: query(request, "code_challenge") ?? "",
    ...(query(request, "redirect_to") === null ? {} : { redirectTo: query(request, "redirect_to") }),
    ...(flow === null ? {} : { flow: flow as "sign_in" | "link_identity" }),
    ...(subject === undefined ? {} : { subject }),
  };
  return resultResponse(safeAuthorizeResult(await capturedService.authorize(input)));
}

/** Consumes a provider callback and returns a redirect carrying only an internal code. */
export async function callbackRoute(service: OAuthService, provider: string, request: Request): Promise<Response> {
  const capturedService = captureOAuthRouteService(service);
  if (request.method !== "GET") return methodNotAllowed();
  const callback = await capturedService.callback({
    provider,
    code: query(request, "code") ?? "",
    state: query(request, "state") ?? "",
  });
  if (callback.error !== null) return resultResponse(callback);
  return new Response(null, {
    status: 303,
    headers: {
      location: callback.data.url,
      "cache-control": "no-store",
    },
  });
}

/** Exchanges a one-use callback code for the project session. */
export async function exchangeRoute(service: OAuthService, request: Request): Promise<Response> {
  const capturedService = captureOAuthRouteService(service);
  if (request.method !== "POST") return methodNotAllowed();
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return resultResponse(authFailure(new AuthApiError("invalid_request", 400, "Invalid JSON body")));
  }
  if (typeof body !== "object" || body === null) {
    return resultResponse(authFailure(new AuthApiError("invalid_request", 400, "Invalid OAuth exchange request")));
  }
  const value = body as Record<string, unknown>;
  const input: OAuthExchangeInput = {
    code: typeof value.code === "string" ? value.code : "",
    codeVerifier: typeof value.code_verifier === "string" ? value.code_verifier : "",
    ...(typeof value.redirect_to === "string" ? { redirectTo: value.redirect_to } : {}),
  };
  return resultResponse(await capturedService.exchangeCode(input));
}

/** Creates the four framework-neutral OAuth route handlers used by later HTTP adapters. */
export function createOAuthRoutes(service: OAuthService): {
  readonly providers: (request?: Request) => Response;
  readonly authorize: (request: Request, subject?: AuthenticatedSubject) => Promise<Response>;
  readonly callback: (provider: string, request: Request) => Promise<Response>;
  readonly exchange: (request: Request) => Promise<Response>;
} {
  const capturedService = captureOAuthRouteService(service);
  return {
    providers: (request) => providersRoute(capturedService, request),
    authorize: (request, subject) => authorizeRoute(capturedService, request, subject),
    callback: (provider, request) => callbackRoute(capturedService, provider, request),
    exchange: (request) => exchangeRoute(capturedService, request),
  };
}

export type {
  OAuthAuthorizeResult,
  OAuthCallbackResult,
  OAuthLinkResult,
  OAuthSessionResult,
};
