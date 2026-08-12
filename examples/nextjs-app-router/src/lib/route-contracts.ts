export interface AuthFields {
  readonly email: string;
  readonly password: string;
}

export interface RecoveryFields extends AuthFields {
  readonly token: string;
}

export function readObject(value: unknown): Record<string, unknown> | null {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}

export async function readJsonObject(request: Request): Promise<Record<string, unknown> | null> {
  try {
    return readObject(await request.json());
  } catch {
    return null;
  }
}

export function requiredText(value: unknown, maximum: number): string | null {
  if (typeof value !== "string") return null;
  const text = value.trim();
  return text.length > 0 && text.length <= maximum ? text : null;
}

export function credentialsFrom(value: Record<string, unknown>): AuthFields | null {
  const email = requiredText(value.email, 320);
  const password = typeof value.password === "string" && value.password.length >= 8 && value.password.length <= 1024
    ? value.password
    : null;
  return email === null || password === null ? null : { email, password };
}

export function recoveryFrom(value: Record<string, unknown>): RecoveryFields | null {
  const credentials = credentialsFrom(value);
  const token = requiredText(value.token, 128);
  return credentials === null || token === null ? null : { ...credentials, token };
}

export function publicAuthError(error: { readonly code: string; readonly message: string; readonly status: number; readonly name: string; readonly request_id?: string }): Response {
  const safe = {
    name: error.name,
    code: error.code,
    message: error.message,
    status: error.status,
    ...(error.request_id === undefined ? {} : { request_id: error.request_id }),
  };
  return Response.json({ error: safe }, {
    status: error.status,
    headers: { "cache-control": "no-store" },
  });
}

export function invalidRequest(): Response {
  return Response.json({
    error: {
      name: "AuthError",
      code: "invalid_request",
      message: "The request is invalid",
      status: 400,
    },
  }, {
    status: 400,
    headers: { "cache-control": "no-store" },
  });
}
