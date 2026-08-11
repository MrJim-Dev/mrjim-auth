import { AuthApiError, AuthConfigurationError } from "../shared/errors.js";
import {
  assertBoundaryObject,
  captureBoundaryStringArray,
  optionalBoundaryOption,
  requiredBoundaryOption,
} from "./callback-boundary.js";

/** The only normalization applied to an email address. */
export function normalizeEmail(value: string): string {
  if (typeof value !== "string") throw new TypeError("email must be a string");
  return value.normalize("NFKC").trim().toLowerCase();
}

/** A display value and its internal normalized lookup value. */
export interface NormalizedEmail {
  readonly display: string;
  readonly normalized: string;
}

/** Normalizes an optional persistence value without applying provider rules. */
export function normalizeEmailParts(value: string | null | undefined): {
  readonly display: string | null;
  readonly normalized: string | null;
} {
  if (value === undefined || value === null) return { display: null, normalized: null };
  const display = value.normalize("NFKC").trim();
  return { display: display === "" ? null : display, normalized: display === "" ? null : display.toLowerCase() };
}

/** Normalizes and validates an email without returning it from an auth error. */
export function normalizeAndValidateEmail(value: unknown): NormalizedEmail {
  if (typeof value !== "string") {
    throw new AuthApiError("invalid_request", 400, "Invalid email address");
  }
  const parts = normalizeEmailParts(value);
  const display = parts.display ?? "";
  const normalized = parts.normalized ?? "";
  const utf8Length = new TextEncoder().encode(normalized).byteLength;
  if (
    display.length === 0 ||
    utf8Length > 320 ||
    display.length > 320 ||
    /[\u0000-\u001f\u007f-\u009f\s]/u.test(display) ||
    !/^[^@]+@[^@]+$/u.test(display) ||
    normalized.startsWith(".") ||
    normalized.endsWith(".") ||
    normalized.includes("..")
  ) {
    throw new AuthApiError("invalid_request", 400, "Invalid email address");
  }
  const [local, domain] = normalized.split("@");
  if (
    local === undefined ||
    domain === undefined ||
    local.length === 0 ||
    local.length > 64 ||
    domain.length === 0 ||
    domain.length > 255 ||
    domain.startsWith(".") ||
    domain.endsWith(".") ||
    domain.includes("..")
  ) {
    throw new AuthApiError("invalid_request", 400, "Invalid email address");
  }
  return { display, normalized };
}

/** A validated redirect target selected from the project's exact allowlist. */
export class EmailService {
  readonly allowedRedirects: readonly string[];
  readonly defaultRedirect: string;

  constructor(options: {
    readonly allowedRedirects: readonly string[];
    readonly defaultRedirect?: string;
  }) {
    if (options === null || typeof options !== "object") {
      throw new AuthConfigurationError("email options are incomplete");
    }
    const source = options as unknown as object;
    assertBoundaryObject(source, "email options");
    const allowedRedirects = captureBoundaryStringArray(
      requiredBoundaryOption(source, "allowedRedirects", "email redirects"),
      "email redirects",
      1,
    );
    const defaultRedirectValue = optionalBoundaryOption(source, "defaultRedirect", "email default redirect");
    for (let index = 0; index < allowedRedirects.length; index += 1) {
      const redirect = allowedRedirects[index];
      if (redirect === undefined) throw new AuthConfigurationError("email redirects must be a dense string array");
      validateConfiguredRedirect(redirect);
    }
    const defaultRedirect = defaultRedirectValue ?? allowedRedirects[0];
    if (typeof defaultRedirect !== "string" || !hasRedirect(allowedRedirects, defaultRedirect)) {
      throw new AuthConfigurationError("default email redirect must be exactly allowlisted");
    }
    this.allowedRedirects = allowedRedirects;
    this.defaultRedirect = defaultRedirect;
  }

  /** Returns an exact allowlisted redirect or a stable expected auth error. */
  resolveRedirect(redirect?: string | null): string {
    const candidate = redirect ?? this.defaultRedirect;
    if (!hasRedirect(this.allowedRedirects, candidate)) {
      throw new AuthApiError("redirect_not_allowed", 400, "Redirect URL is not allowed");
    }
    return candidate;
  }

  /** Derives a bearer-bearing link only in memory immediately before delivery. */
  link(redirect: string | null | undefined, rawToken: string): string {
    const target = new URL(this.resolveRedirect(redirect));
    target.searchParams.set("token", rawToken);
    return target.toString();
  }
}

function validateConfiguredRedirect(value: string): void {
  if (typeof value !== "string" || value.trim() !== value || value.length === 0 || value.includes("*")) {
    throw new AuthConfigurationError("email redirects must be exact URLs");
  }
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new AuthConfigurationError("email redirects must be valid URLs");
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new AuthConfigurationError("email redirects must use http or https");
  }
  if (parsed.hash !== "") {
    throw new AuthConfigurationError("email redirects may not include fragments");
  }
}

function hasRedirect(values: readonly string[], candidate: string): boolean {
  for (let index = 0; index < values.length; index += 1) {
    if (values[index] === candidate) return true;
  }
  return false;
}
