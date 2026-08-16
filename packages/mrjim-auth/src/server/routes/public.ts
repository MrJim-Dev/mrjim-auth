import { AuthApiError } from "../../shared/errors.js";
import { authSuccess } from "../../shared/result.js";
import { normalizeAndValidateEmail } from "../email.js";
import type { OAuthSubject, OAuthSessionResult } from "../oauth.js";
import type { AccessTokenClaims } from "../tokens.js";
import type { PublicAuthData, UserRequestContext } from "../users.js";
import type { ZodType } from "zod";
import type { RouteContext, RouteOutput } from "./contracts.js";
import {
  authorizeDataSchema as authorizeSchema,
  exchangeDataSchema as exchangeSchema,
  exchangeRequestSchema,
  jwksDataSchema as jwksSchema,
  otpRequestSchema,
  passwordTokenRequestSchema,
  providersDataSchema as providersSchema,
  publicAuthDataSchema as publicAuthSchema,
  recoverRequestSchema,
  recoverVerifyRequestSchema,
  refreshTokenRequestSchema,
  resendRequestSchema,
  sentSchema as sentResponseSchema,
  sessionSchema as sessionResponseSchema,
  signupRequestSchema,
  verifyRequestSchema,
  userDataSchema,
} from "./contracts.js";
import { safeStringSlice, safeStringStartsWith } from "../../shared/safe-intrinsics.js";
import { mapProviderDiscoveryData } from "./oauth.js";

function service(
  result: unknown,
  mapData: (data: unknown) => unknown,
  schema: ZodType,
  options: { readonly status?: number; readonly cache?: "no-store" | "public" } = {},
): RouteOutput {
  return { kind: "service", result, mapData, schema, ...options };
}

function mapPublicAuthData(data: unknown): unknown {
  if (data === null || typeof data !== "object") return data;
  const value = data as Record<string, unknown>;
  return { user: value.user ?? null, session: value.session ?? null };
}

function mapSession(data: unknown): unknown {
  return data;
}

function mapSent(data: unknown): unknown {
  return data;
}

function mapProviders(data: unknown): unknown {
  return { providers: data };
}

function mapAuthorize(data: unknown): unknown {
  if (data === null || typeof data !== "object") return data;
  const value = data as Record<string, unknown>;
  return {
    provider: value.provider,
    url: value.url,
    redirect: value.redirect,
    expires_at: value.expiresAt,
  };
}

function mapExchange(data: unknown): unknown {
  return data;
}

function mapJwks(data: unknown): unknown {
  return data;
}

function serviceContext(context: RouteContext): UserRequestContext {
  return {
    request_id: context.requestId,
  };
}

function requiredOauth(context: RouteContext): NonNullable<RouteContext["services"]["oauth"]> {
  if (context.services.oauth === undefined) {
    throw new AuthApiError("not_found", 404, "OAuth provider is not enabled");
  }
  return context.services.oauth;
}

/** Handles the public and signed OAuth/JWKS portion of the Task 9 surface. */
export async function handlePublicRoute(
  path: string,
  context: RouteContext,
): Promise<RouteOutput | null> {
  if (path === "/signup") {
    const value = context.body as typeof signupRequestSchema._output;
    const email = normalizeAndValidateEmail(value.email).normalized;
    const result = await context.invoke(() => context.services.users.signUp({
      email,
      password: value.password,
      ...(value.options === undefined ? {} : {
        options: {
          ...(value.options.redirect_to === undefined ? {} : { redirectTo: value.options.redirect_to }),
          ...(value.options.data === undefined ? {} : { data: value.options.data }),
        },
      }),
    }, serviceContext(context)));
    return service(result, mapPublicAuthData, publicAuthSchema);
  }

  if (path === "/token") {
    const grantType = context.query.get("grant_type");
    const value = context.body as typeof passwordTokenRequestSchema._output | typeof refreshTokenRequestSchema._output;
    if (grantType === "password") {
      const password = value as typeof passwordTokenRequestSchema._output;
      const result = await context.invoke(() => context.services.users.signIn({
        email: normalizeAndValidateEmail(password.email).normalized,
        password: password.password,
      }, serviceContext(context)));
      return service(result, (data) => {
        if (data === null || typeof data !== "object") return data;
        return (data as Record<string, unknown>).session;
      }, sessionResponseSchema);
    }
    if (grantType === "refresh_token") {
      const refresh = value as typeof refreshTokenRequestSchema._output;
      const result = await context.invoke(() => context.services.sessions.refresh(refresh.refresh_token, serviceContext(context)));
      return service(result, mapSession, sessionResponseSchema);
    }
    throw new AuthApiError("invalid_request", 400, "Invalid token grant type");
  }

  if (path === "/otp") {
    const value = context.body as typeof otpRequestSchema._output;
    const result = await context.invoke(() => context.services.users.signInWithOtp({
      email: normalizeAndValidateEmail(value.email).normalized,
      ...(value.options === undefined ? {} : {
        options: {
          ...(value.options.type === undefined ? {} : { type: value.options.type }),
          ...(value.options.redirect_to === undefined ? {} : { redirectTo: value.options.redirect_to }),
        },
      }),
    }, serviceContext(context)));
    return service(result, mapPublicAuthData, publicAuthSchema);
  }

  if (path === "/verify") {
    const value = context.body as typeof verifyRequestSchema._output;
    const input = {
      email: normalizeAndValidateEmail(value.email).normalized,
      token: value.token,
      ...(value.redirect_to === undefined ? {} : { redirectTo: value.redirect_to }),
    };
    const result = await context.invoke(() => value.type === "signup"
      ? context.services.users.confirmEmail(input, serviceContext(context))
      : context.services.users.verifyOtp({ ...input, type: value.type }, serviceContext(context)));
    return service(result, mapPublicAuthData, publicAuthSchema);
  }

  if (path === "/recover") {
    const value = context.body as typeof recoverRequestSchema._output;
    const result = await context.invoke(() => context.services.users.resetPasswordForEmail(
      normalizeAndValidateEmail(value.email).normalized,
      value.redirect_to === undefined ? {} : { redirectTo: value.redirect_to },
      serviceContext(context),
    ));
    return service(result, mapSent, sentResponseSchema);
  }

  if (path === "/recover/verify") {
    const value = context.body as typeof recoverVerifyRequestSchema._output;
    const result = await context.invoke(() => context.services.users.resetPassword({
      email: normalizeAndValidateEmail(value.email).normalized,
      token: value.token,
      password: value.password,
      ...(value.redirect_to === undefined ? {} : { redirectTo: value.redirect_to }),
    }, serviceContext(context)));
    return service(result, (data) => data, userDataSchema);
  }

  if (path === "/resend") {
    const value = context.body as typeof resendRequestSchema._output;
    const result = await context.invoke(() => context.services.users.resend({
      type: value.type,
      email: normalizeAndValidateEmail(value.email).normalized,
      ...(value.options === undefined ? {} : {
        options: value.options.redirect_to === undefined ? {} : { redirectTo: value.options.redirect_to },
      }),
    }, serviceContext(context)));
    return service(result, mapSent, sentResponseSchema);
  }

  if (path === "/providers") {
    const providers = mapProviderDiscoveryData(context.services.oauth?.listProviders() ?? []);
    return service(authSuccess(providers), mapProviders, providersSchema, { cache: "public" });
  }

  if (path === "/authorize") {
    const oauth = requiredOauth(context);
    const flowValue = context.query.get("flow");
    const codeChallengeMethod = context.query.get("code_challenge_method");
    if (codeChallengeMethod !== null && codeChallengeMethod !== "S256") {
      throw new AuthApiError("invalid_request", 400, "Only PKCE S256 is supported");
    }
    const input = {
      provider: context.query.get("provider") ?? "",
      codeChallenge: context.query.get("code_challenge") ?? "",
      ...(context.query.get("redirect_to") === null ? {} : { redirectTo: context.query.get("redirect_to") }),
      ...(flowValue === null ? {} : { flow: flowValue as "sign_in" | "link_identity" }),
      ...(flowValue === "link_identity" && context.auth?.subject !== undefined
        ? { subject: context.auth.subject as OAuthSubject }
        : {}),
    };
    const result = await context.invoke(() => oauth.authorize(input));
    return service(result, mapAuthorize, authorizeSchema);
  }

  if (safeStringStartsWith(path, "/callback/")) {
    const provider = safeStringSlice(path, "/callback/".length) ?? "";
    const oauth = requiredOauth(context);
    const result = await context.invoke(() => oauth.callback({
      provider,
      code: context.query.get("code") ?? "",
      state: context.query.get("state") ?? "",
    }));
    return { kind: "callback", result };
  }

  if (path === "/exchange") {
    const value = context.body as typeof exchangeRequestSchema._output;
    const oauth = requiredOauth(context);
    const result = await context.invoke(() => oauth.exchangeCode({
      code: value.code,
      codeVerifier: value.code_verifier,
      ...(value.redirect_to === undefined ? {} : { redirectTo: value.redirect_to }),
      context: serviceContext(context),
    }));
    return service(result, mapExchange, exchangeSchema);
  }

  if (path === "/.well-known/jwks.json") {
    const result = await context.invoke(() => context.services.tokens.jwks());
    return service(authSuccess(result), mapJwks, jwksSchema, { cache: "public" });
  }

  return null;
}

export type { AccessTokenClaims, OAuthSessionResult, PublicAuthData };
