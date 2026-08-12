import { Buffer } from "node:buffer";

export function requiredEnv(name: string, value = process.env[name]): string {
  if (value === undefined || value.trim() === "") throw new Error(`${name} is required`);
  return value.trim();
}

export function httpUrl(name: string, value = requiredEnv(name)): string {
  const url = new URL(value);
  if ((url.protocol !== "http:" && url.protocol !== "https:") || url.username !== "" || url.password !== "") {
    throw new Error(`${name} must be a credential-free HTTP(S) URL`);
  }
  return url.href.endsWith("/") ? url.href.slice(0, -1) : url.href;
}

export function secretBytes(name: string, input = process.env[name], exactBytes?: number): Uint8Array {
  const value = requiredEnv(name, input);
  if (!/^[A-Za-z0-9_-]+$/u.test(value)) throw new Error(`${name} must be unpadded base64url`);
  const bytes = Buffer.from(value, "base64url");
  if (bytes.byteLength < 32 || (exactBytes !== undefined && bytes.byteLength !== exactBytes)) {
    throw new Error(`${name} has invalid key length`);
  }
  return Uint8Array.from(bytes);
}

export function privateJwk(): Readonly<Record<string, unknown>> {
  const value: unknown = JSON.parse(requiredEnv("AUTH_ES256_PRIVATE_JWK"));
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("AUTH_ES256_PRIVATE_JWK must be a private JWK object");
  }
  return Object.freeze({ ...(value as Record<string, unknown>) });
}

export function allowedRedirects(): string[] {
  const values = requiredEnv("AUTH_ALLOWED_REDIRECTS").split(",").map((value) => value.trim()).filter(Boolean);
  if (values.length === 0) throw new Error("AUTH_ALLOWED_REDIRECTS must not be empty");
  return values;
}
