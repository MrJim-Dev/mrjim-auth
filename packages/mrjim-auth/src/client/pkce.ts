/** RFC 7636 code-verifier alphabet. */
const CODE_VERIFIER_PATTERN = /^[A-Za-z0-9._~-]{43,128}$/;

/** The only code-challenge method supported by mrjim-auth v1. */
export const PKCE_CODE_CHALLENGE_METHOD = "S256" as const;

/** A browser-safe authorization-code PKCE pair. */
export interface PkcePair {
  readonly codeVerifier: string;
  readonly codeChallenge: string;
  readonly method: typeof PKCE_CODE_CHALLENGE_METHOD;
}

function cryptoSource() {
  const source = globalThis.crypto;
  if (source === undefined || typeof source.getRandomValues !== "function" || source.subtle === undefined) {
    throw new Error("Web Crypto with getRandomValues and subtle.digest is required for PKCE");
  }
  return source;
}

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

/** Returns whether a value is a valid RFC 7636 code verifier. */
export function isCodeVerifier(value: unknown): value is string {
  return typeof value === "string" && CODE_VERIFIER_PATTERN.test(value);
}

/** Generates a 32-byte base64url RFC 7636 code verifier. */
export function generateCodeVerifier(): string {
  const bytes = new Uint8Array(32);
  cryptoSource().getRandomValues(bytes);
  return base64Url(bytes);
}

/** Computes the RFC 7636 S256 code challenge for a valid verifier. */
export async function createCodeChallenge(codeVerifier: string): Promise<string> {
  if (!isCodeVerifier(codeVerifier)) {
    throw new TypeError("PKCE code verifier must be 43-128 unreserved characters");
  }
  const digest = await cryptoSource().subtle.digest(
    "SHA-256",
    new TextEncoder().encode(codeVerifier),
  );
  return base64Url(new Uint8Array(digest));
}

/** Compatibility alias for callers that name the operation `generate`. */
export const generateCodeChallenge = createCodeChallenge;

/** Generates a PKCE verifier/challenge pair using S256 only. */
export async function generatePkcePair(): Promise<PkcePair> {
  const codeVerifier = generateCodeVerifier();
  return {
    codeVerifier,
    codeChallenge: await createCodeChallenge(codeVerifier),
    method: PKCE_CODE_CHALLENGE_METHOD,
  };
}
