import type { AuthenticatedSubject } from "../users.js";
import { authFailure, authSuccess } from "../../shared/result.js";
import { AuthApiError, AuthConfigurationError, isPublicAuthErrorCode, type PublicAuthErrorCode } from "../../shared/errors.js";
import {
  OAuthService,
  type OAuthAuthorizeResult,
  type OAuthCallbackResult,
  type OAuthExchangeInput,
  type OAuthLinkResult,
  type OAuthSessionResult,
  type OAuthSubject,
} from "../oauth.js";
import {
  boundaryHasThen,
  boundaryIsArray,
  boundaryOwnDataProperty,
  captureBoundaryDataValue,
  captureBoundaryMethodGroup,
  captureBoundaryStringArray,
  invokeBoundaryResult,
} from "../callback-boundary.js";
import { safeDefineData, safeCreateRecord, safeNumberIsInteger, safeOwnDataEntries } from "../../shared/safe-intrinsics.js";
import { exchangeDataSchema } from "./contracts.js";

const routeResponse = Response;
const routeUrl = URL;
const routeJsonStringify = JSON.stringify;
const routeJsonParse = JSON.parse;
const routeReflectApply = Reflect.apply;
const routeObjectDefineProperty = Object.defineProperty;
const routeObjectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const routeUrlSearchParamsGetter = (() => {
  const descriptor = routeObjectGetOwnPropertyDescriptor(URL.prototype, "searchParams");
  if (descriptor === undefined || typeof descriptor.get !== "function") throw new Error("URL.searchParams is unavailable");
  return descriptor.get;
})();
const routeSearchParamsGet = (() => {
  const descriptor = routeObjectGetOwnPropertyDescriptor(URLSearchParams.prototype, "get");
  if (descriptor === undefined || !("value" in descriptor) || typeof descriptor.value !== "function") {
    throw new Error("URLSearchParams.get is unavailable");
  }
  return descriptor.value;
})();
const routeRequestText = (() => {
  const descriptor = Object.getOwnPropertyDescriptor(Request.prototype, "text");
  if (descriptor === undefined || typeof descriptor.value !== "function") {
    throw new Error("Request.text is unavailable");
  }
  return descriptor.value as Function;
})();

const OAUTH_ROUTE_METHODS = ["listProviders", "authorize", "callback", "exchangeCode", "listIdentities", "unlinkIdentity"] as const;

function captureOAuthRouteService(service: OAuthService): OAuthService {
  const redirects = boundaryOwnDataProperty(service, "allowedRedirects");
  if (!redirects.valid) throw new AuthConfigurationError("OAuth route redirects must be a data property");
  const allowedRedirects = redirects.present
    ? captureBoundaryStringArray(redirects.value, "OAuth route redirects", 1, 128)
    : undefined;
  return captureBoundaryMethodGroup(
    service,
    "OAuth route service",
    OAUTH_ROUTE_METHODS,
    [],
    allowedRedirects === undefined ? {} : { allowedRedirects },
    "source",
    true,
  ) as unknown as OAuthService;
}

type RouteResultParts = {
  readonly data: unknown;
  readonly error: unknown;
};

function defineRouteData(target: object, key: PropertyKey, value: unknown): void {
  if (!safeDefineData(target, key, value)) throw new AuthApiError("internal_error", 500, "Internal authentication error");
}

function routeErrorMessage(code: PublicAuthErrorCode): string {
  switch (code) {
    case "invalid_credentials": return "Invalid login credentials";
    case "unauthorized": return "Authentication is required";
    case "forbidden": return "Forbidden";
    case "insufficient_permission": return "Insufficient permission";
    case "not_found": return "Not found";
    case "conflict": return "Conflict";
    case "invalid_token": return "Invalid token";
    case "token_expired": return "Token has expired";
    case "refresh_token_reused": return "Refresh token has already been used";
    case "session_expired": return "Session has expired";
    case "otp_invalid": return "Invalid one-time code";
    case "otp_expired": return "One-time code has expired";
    case "otp_attempts_exceeded": return "Too many one-time-code attempts";
    case "rate_limit_exceeded": return "Too many requests";
    case "redirect_not_allowed": return "Redirect URL is not allowed";
    case "oauth_state_invalid": return "Invalid OAuth state";
    case "oauth_provider_error": return "OAuth provider request failed";
    case "identity_already_linked": return "Identity is already linked";
    case "identity_unlink_not_allowed": return "Identity cannot be unlinked";
    case "internal_error": return "Internal authentication error";
    case "invalid_request": return "Invalid request";
  }
}

function routeErrorStatus(code: PublicAuthErrorCode, value: unknown): number {
  const allowed = (status: number): boolean => {
    switch (code) {
      case "invalid_request": return status === 400 || status === 405;
      case "invalid_credentials":
      case "unauthorized":
      case "invalid_token":
      case "token_expired":
      case "refresh_token_reused":
      case "session_expired":
      case "otp_invalid":
      case "otp_expired":
      case "otp_attempts_exceeded": return status === 401;
      case "forbidden":
      case "insufficient_permission":
      case "identity_unlink_not_allowed": return status === 403;
      case "not_found": return status === 404;
      case "conflict":
      case "identity_already_linked": return status === 409;
      case "rate_limit_exceeded": return status === 429;
      case "oauth_provider_error": return status === 502;
      case "redirect_not_allowed":
      case "oauth_state_invalid": return status === 400;
      case "internal_error": return status === 500;
    }
  };
  return typeof value === "number" && safeNumberIsInteger(value) && value >= 100 && value <= 599 && allowed(value)
    ? value
    : (code === "invalid_request" ? 400 : code === "oauth_provider_error" ? 502 : code === "internal_error" ? 500 : 401);
}

function safeRouteError(value: unknown): { readonly code: PublicAuthErrorCode; readonly status: number; readonly message: string } {
  let code: PublicAuthErrorCode = "internal_error";
  let status: unknown;
  if (value !== null && (typeof value === "object" || typeof value === "function")) {
    const codeProperty = boundaryOwnDataProperty(value, "code");
    const statusProperty = boundaryOwnDataProperty(value, "status");
    if (codeProperty.valid && codeProperty.present && isPublicAuthErrorCode(codeProperty.value)) code = codeProperty.value;
    if (statusProperty.valid && statusProperty.present) status = statusProperty.value;
  }
  return { code, status: routeErrorStatus(code, status), message: routeErrorMessage(code) };
}

function errorBody(error: { readonly code: PublicAuthErrorCode; readonly status: number; readonly message: string }): object {
  const output = safeCreateRecord();
  defineRouteData(output, "name", "AuthError");
  defineRouteData(output, "message", error.message);
  defineRouteData(output, "status", error.status);
  defineRouteData(output, "code", error.code);
  return output;
}

function emptyResult(error: { readonly code: PublicAuthErrorCode; readonly status: number; readonly message: string }): object {
  const output = safeCreateRecord();
  defineRouteData(output, "data", null);
  defineRouteData(output, "error", errorBody(error));
  return output;
}

function successResult(data: unknown): object {
  const output = safeCreateRecord();
  defineRouteData(output, "data", data);
  defineRouteData(output, "error", null);
  return output;
}

function json(value: object, status = 200): Response {
  const serialized = routeJsonStringify(value);
  const response = new routeResponse(serialized, {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
    },
  });
  try {
    routeObjectDefineProperty(response, "then", {
      configurable: false,
      enumerable: false,
      value: undefined,
      writable: false,
    });
    const descriptor = routeObjectGetOwnPropertyDescriptor(response, "then");
    if (descriptor === undefined || !("value" in descriptor) || descriptor.value !== undefined) {
      throw new Error("Response then shield was not established");
    }
  } catch {
    throw new AuthApiError("internal_error", 500, "Internal authentication error");
  }
  return response;
}

function internalResponse(): Response {
  return json(emptyResult({ code: "internal_error", status: 500, message: "Internal authentication error" }), 500);
}

function resultParts(result: unknown): RouteResultParts | null {
  if (result === null || (typeof result !== "object" && typeof result !== "function")) return null;
  try {
    if (boundaryHasThen(result, true)) return null;
  } catch {
    return null;
  }
  const data = boundaryOwnDataProperty(result, "data");
  const error = boundaryOwnDataProperty(result, "error");
  if (!data.valid || !error.valid || !error.present) return null;
  return { data: data.present ? data.value : null, error: error.value };
}

function resultResponse(result: unknown, mapData: (data: unknown) => unknown = (data) => data): Response {
  try {
    const parts = resultParts(result);
    if (parts === null) return internalResponse();
    if (parts.error !== null) {
      const error = safeRouteError(parts.error);
      return json(emptyResult(error), error.status);
    }
    const data = captureBoundaryDataValue(mapData(parts.data), "OAuth route response");
    return json(successResult(data), 200);
  } catch {
    return internalResponse();
  }
}

function methodNotAllowed(): Response {
  return json(emptyResult({ code: "invalid_request", status: 405, message: "Method is not allowed" }), 405);
}

function query(request: Request, key: string): string | null {
  const url = new routeUrl(request.url);
  const params = routeReflectApply(routeUrlSearchParamsGetter, url, []);
  return routeReflectApply(routeSearchParamsGet, params, [key]) as string | null;
}

function recordValue(value: unknown, key: string): unknown {
  if (value === null || typeof value !== "object" || boundaryIsArray(value, "OAuth route record")) return undefined;
  const property = boundaryOwnDataProperty(value, key);
  return property.valid && property.present ? property.value : undefined;
}

function requiredString(value: unknown, key: string): string {
  const candidate = recordValue(value, key);
  if (typeof candidate !== "string" || candidate.length === 0) throw new AuthApiError("internal_error", 500, "Internal authentication error");
  return candidate;
}

function mapAuthorizeData(data: unknown): object {
  const snapshot = captureBoundaryDataValue(data, "OAuth authorize result");
  const output = safeCreateRecord();
  defineRouteData(output, "provider", requiredString(snapshot, "provider"));
  defineRouteData(output, "url", requiredString(snapshot, "url"));
  defineRouteData(output, "redirect", requiredString(snapshot, "redirect"));
  defineRouteData(output, "expires_at", requiredString(snapshot, "expiresAt"));
  return output;
}

function validCallbackUrl(
  redirect: string,
  url: string,
  code: string,
  providerCode: string,
  providerState: string,
  allowedRedirects: readonly string[] | undefined,
): boolean {
  try {
    if (allowedRedirects !== undefined) {
      let allowed = false;
      for (let index = 0; index < allowedRedirects.length; index += 1) {
        if (allowedRedirects[index] === redirect) {
          allowed = true;
          break;
        }
      }
      if (!allowed) return false;
    }
    const redirectUrl = new routeUrl(redirect);
    const callbackUrl = new routeUrl(url);
    if ((redirectUrl.protocol !== "https:" && redirectUrl.protocol !== "http:") || callbackUrl.protocol !== redirectUrl.protocol) return false;
    if (callbackUrl.origin !== redirectUrl.origin || callbackUrl.pathname !== redirectUrl.pathname || callbackUrl.hash !== "") return false;
    if (code.length < 1 || code.length > 512 || code === providerCode || code === providerState) return false;
    const callbackParams = routeReflectApply(routeUrlSearchParamsGetter, callbackUrl, []);
    const callbackCode = routeReflectApply(routeSearchParamsGet, callbackParams, ["code"]) as string | null;
    if (callbackCode !== code) return false;
    if (routeReflectApply(routeSearchParamsGet, callbackParams, ["state"]) !== null) return false;
    if (routeReflectApply(routeSearchParamsGet, callbackParams, ["code_verifier"]) !== null) return false;
    if (routeReflectApply(routeSearchParamsGet, callbackParams, ["access_token"]) !== null) return false;
    if (routeReflectApply(routeSearchParamsGet, callbackParams, ["refresh_token"]) !== null) return false;
    if (routeReflectApply(routeSearchParamsGet, callbackParams, ["id_token"]) !== null) return false;
    return true;
  } catch {
    return false;
  }
}

function mapCallbackData(
  data: unknown,
  providerCode: string,
  providerState: string,
  allowedRedirects: readonly string[] | undefined,
): { readonly url: string } {
  const snapshot = captureBoundaryDataValue(data, "OAuth callback result");
  const code = requiredString(snapshot, "code");
  const redirect = requiredString(snapshot, "redirect");
  const url = requiredString(snapshot, "url");
  if (!validCallbackUrl(redirect, url, code, providerCode, providerState, allowedRedirects)) {
    throw new AuthApiError("internal_error", 500, "Internal authentication error");
  }
  return { url };
}

function mapExchangeData(data: unknown): unknown {
  const snapshot = captureBoundaryDataValue(data, "OAuth exchange result");
  if (snapshot === null || typeof snapshot !== "object" || boundaryIsArray(snapshot, "OAuth exchange result")) {
    return { user: {}, identity: {}, session: {} };
  }
  const user = recordValue(snapshot, "user");
  const identity = recordValue(snapshot, "identity");
  const session = recordValue(snapshot, "session");
  if (user === undefined || identity === undefined || session === undefined) return { user: {}, identity: {}, session: {} };
  try {
    const parsed = exchangeDataSchema.safeParse(snapshot);
    if (parsed.success) return parsed.data;
  } catch {
  }
  const userEntries = safeOwnDataEntries(user);
  const identityEntries = safeOwnDataEntries(identity);
  const sessionEntries = safeOwnDataEntries(session);
  if (userEntries === null || identityEntries === null || sessionEntries === null) {
    throw new AuthApiError("internal_error", 500, "Internal authentication error");
  }
  if (userEntries.length !== 0 || identityEntries.length !== 0 || sessionEntries.length !== 0) {
    throw new AuthApiError("internal_error", 500, "Internal authentication error");
  }
  return { user: {}, identity: {}, session: {} };
}

async function readRequestTextSafely(request: Request): Promise<string> {
  const descriptor = routeObjectGetOwnPropertyDescriptor(Object.prototype, "then");
  if (descriptor === undefined || !("value" in descriptor) || typeof descriptor.value !== "function") {
    return await routeReflectApply(routeRequestText, request, []) as string;
  }
  // Undici resolves internal byte chunks through native Promise resolution.
  // A hostile Object.prototype.then would otherwise be assimilated before the
  // route can inspect the body. Temporarily making that ambient property a
  // non-callable data value is scoped to the captured native body read and is
  // restored even when the read fails.
  routeObjectDefineProperty(Object.prototype, "then", {
    configurable: descriptor.configurable === true,
    enumerable: descriptor.enumerable === true,
    writable: descriptor.writable === true,
    value: undefined,
  });
  try {
    return await routeReflectApply(routeRequestText, request, []) as string;
  } finally {
    routeObjectDefineProperty(Object.prototype, "then", descriptor);
  }
}

/** Serves the public enabled-provider discovery endpoint. */
export function providersRoute(service: OAuthService, request?: Request): Response {
  const capturedService = captureOAuthRouteService(service);
  if (request !== undefined && request.method !== "GET") return methodNotAllowed();
  try {
    const providers = captureBoundaryDataValue(capturedService.listProviders(), "OAuth provider discovery");
    return resultResponse(authSuccess(providers));
  } catch {
    return internalResponse();
  }
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
  try {
    const result = await invokeBoundaryResult<unknown>(
      capturedService.authorize,
      capturedService,
      [input],
      "OAuth authorize callback",
    );
    return resultResponse(result, mapAuthorizeData);
  } catch {
    return internalResponse();
  }
}

/** Consumes a provider callback and returns a redirect carrying only an internal code. */
export async function callbackRoute(service: OAuthService, provider: string, request: Request): Promise<Response> {
  const capturedService = captureOAuthRouteService(service);
  if (request.method !== "GET") return methodNotAllowed();
  const providerCode = query(request, "code") ?? "";
  const providerState = query(request, "state") ?? "";
  try {
    const callback = await invokeBoundaryResult<unknown>(
      capturedService.callback,
      capturedService,
      [{ provider, code: providerCode, state: providerState }],
      "OAuth callback handler",
    );
    const parts = resultParts(callback);
    if (parts === null) return internalResponse();
    if (parts.error !== null) {
      const error = safeRouteError(parts.error);
      return json(emptyResult(error), error.status);
    }
    const redirects = boundaryOwnDataProperty(capturedService, "allowedRedirects");
    const allowedRedirects = redirects.valid && redirects.present && boundaryIsArray(redirects.value, "OAuth route redirects")
      ? redirects.value as readonly string[]
      : undefined;
    const output = mapCallbackData(parts.data, providerCode, providerState, allowedRedirects);
    const response = new routeResponse(null, {
      status: 303,
      headers: {
        location: output.url,
        "cache-control": "no-store",
      },
    });
    routeObjectDefineProperty(response, "then", {
      configurable: false,
      enumerable: false,
      value: undefined,
      writable: false,
    });
    return response;
  } catch {
    return internalResponse();
  }
}

/** Exchanges a one-use callback code for the project session. */
export async function exchangeRoute(service: OAuthService, request: Request): Promise<Response> {
  const capturedService = captureOAuthRouteService(service);
  if (request.method !== "POST") return methodNotAllowed();
  let body: unknown;
  try {
    const bodyText = await readRequestTextSafely(request) as unknown;
    if (typeof bodyText !== "string") throw new Error("Invalid OAuth request body");
    body = routeJsonParse(bodyText) as unknown;
  } catch {
    return resultResponse(authFailure(new AuthApiError("invalid_request", 400, "Invalid JSON body")));
  }
  let bodySnapshot: unknown;
  try {
    bodySnapshot = captureBoundaryDataValue(body, "OAuth exchange request");
  } catch {
    return resultResponse(authFailure(new AuthApiError("invalid_request", 400, "Invalid OAuth exchange request")));
  }
  if (typeof bodySnapshot !== "object" || bodySnapshot === null || boundaryIsArray(bodySnapshot, "OAuth exchange request")) {
    return resultResponse(authFailure(new AuthApiError("invalid_request", 400, "Invalid OAuth exchange request")));
  }
  const code = recordValue(bodySnapshot, "code");
  const codeVerifier = recordValue(bodySnapshot, "code_verifier");
  const redirectTo = recordValue(bodySnapshot, "redirect_to");
  const input: OAuthExchangeInput = {
    code: typeof code === "string" ? code : "",
    codeVerifier: typeof codeVerifier === "string" ? codeVerifier : "",
    ...(typeof redirectTo === "string" ? { redirectTo } : {}),
  };
  try {
    const result = await invokeBoundaryResult<unknown>(
      capturedService.exchangeCode,
      capturedService,
      [input],
      "OAuth exchange handler",
    );
    return resultResponse(result, mapExchangeData);
  } catch {
    return internalResponse();
  }
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
