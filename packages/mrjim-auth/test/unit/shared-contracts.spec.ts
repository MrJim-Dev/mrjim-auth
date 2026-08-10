import { describe, expect, it } from "vitest";
import { authFailure, authSuccess } from "../../src/shared/result.js";
import { AuthApiError } from "../../src/shared/errors.js";
import {
  authServerOptionsSchema,
  clientOptionsSchema,
  type AuthServerOptions,
} from "../../src/shared/config.js";
import type {
  AuthChangeEvent,
  Identity,
  Permission,
  Role,
  Session,
  User,
} from "../../src/shared/types.js";

type TestServerOptions = {
  environment: "development" | "test" | "production";
  baseUrl: string;
  siteUrl: string;
  database: Record<string, never>;
  signingKeys: {
    issuer: string;
    audience: string;
    activeKeyId: string;
    keys: Record<string, string>;
  };
  secrets: {
    tokenHashKey: string;
    encryptionKey: string;
  };
  email: { send: () => Promise<undefined> };
  redirects: { allowed: string[] };
  accessTokenTtlSeconds: number;
  refreshTokenTtlSeconds: number;
};

const validServerOptions = (): TestServerOptions => ({
  environment: "production" as const,
  baseUrl: "https://project.example.com/auth/v1",
  siteUrl: "https://project.example.com",
  database: {},
  signingKeys: {
    issuer: "https://project.example.com/auth/v1",
    audience: "project",
    activeKeyId: "active",
    keys: { active: "private-key-material" },
  },
  secrets: {
    tokenHashKey: "token-hash-key-material",
    encryptionKey: "encryption-key-material",
  },
  email: { send: async () => undefined },
  redirects: {
    allowed: ["https://project.example.com/auth/callback"],
  },
  accessTokenTtlSeconds: 900,
  refreshTokenTtlSeconds: 2_592_000,
});

describe("AuthResult", () => {
  it("uses mutually exclusive data and error fields", () => {
    const error = new AuthApiError(
      "invalid_credentials",
      401,
      "Invalid login credentials",
    );

    expect(authSuccess({ user: null })).toEqual({
      data: { user: null },
      error: null,
    });
    expect(authFailure(error)).toEqual({ data: null, error });
    expect(Object.keys(authSuccess({ user: null }))).toEqual(["data", "error"]);
    expect(Object.keys(authFailure(error))).toEqual(["data", "error"]);
  });

  it("keeps stable API error fields while omitting provider credentials", () => {
    const error = new AuthApiError(
      "invalid_credentials",
      401,
      "Invalid login credentials",
      "request-123",
    );

    expect(error).toMatchObject({
      name: "AuthError",
      code: "invalid_credentials",
      status: 401,
      message: "Invalid login credentials",
      request_id: "request-123",
    });
    expect(error.toJSON()).toEqual({
      name: "AuthError",
      code: "invalid_credentials",
      status: 401,
      message: "Invalid login credentials",
      request_id: "request-123",
    });
  });
});

describe("shared identity and authorization types", () => {
  it("models safe user, identity, session, role, permission, and event values", () => {
    const user: User = {
      id: "00000000-0000-4000-8000-000000000001",
      email: "user@example.com",
      phone: null,
      email_confirmed_at: "2026-08-11T00:00:00.000Z",
      phone_confirmed_at: null,
      confirmed_at: "2026-08-11T00:00:00.000Z",
      last_sign_in_at: null,
      banned_until: null,
      user_metadata: { displayName: "User" },
      app_metadata: { provider: "email" },
      created_at: "2026-08-11T00:00:00.000Z",
      updated_at: "2026-08-11T00:00:00.000Z",
      deleted_at: null,
    };
    const session: Session = {
      access_token: "access-token",
      refresh_token: "refresh-token",
      token_type: "bearer",
      expires_in: 900,
      expires_at: 1_786_420_000,
      user,
    };
    const identity: Identity = {
      id: "00000000-0000-4000-8000-000000000002",
      user_id: user.id,
      provider: "google",
      provider_subject: "google-subject",
      email: user.email,
      identity_data: { name: "User", email_verified: true },
      created_at: "2026-08-11T00:00:00.000Z",
      updated_at: "2026-08-11T00:00:00.000Z",
    };
    const role: Role = {
      id: "00000000-0000-4000-8000-000000000003",
      key: "member",
      name: "Member",
      description: null,
      rank: 10,
      is_system: false,
      created_at: "2026-08-11T00:00:00.000Z",
      updated_at: "2026-08-11T00:00:00.000Z",
    };
    const permission: Permission = {
      id: "00000000-0000-4000-8000-000000000004",
      key: "invoice.read",
      resource: "invoice",
      action: "read",
      description: null,
      created_at: "2026-08-11T00:00:00.000Z",
      updated_at: "2026-08-11T00:00:00.000Z",
    };
    const event: AuthChangeEvent = "SIGNED_IN";

    expect(session.user).toBe(user);
    expect(identity).not.toHaveProperty("access_token");
    expect(identity).not.toHaveProperty("refresh_token");
    expect(identity).not.toHaveProperty("client_secret");
    expect(role.key).toBe(role.key.toLowerCase());
    expect(permission.key).toBe(permission.key.toLowerCase());
    expect(event).toBe("SIGNED_IN");
  });
});

describe("validated configuration", () => {
  it("accepts PKCE client options and rejects other flow types", () => {
    expect(clientOptionsSchema.parse({ auth: { flowType: "pkce" } })).toEqual({
      auth: { flowType: "pkce" },
    });
    expect(clientOptionsSchema.safeParse({ auth: { flowType: "implicit" } }).success).toBe(
      false,
    );
  });

  it("accepts production server configuration with required key material", () => {
    const parsed: AuthServerOptions = authServerOptionsSchema.parse(validServerOptions());

    expect(parsed.baseUrl).toBe("https://project.example.com/auth/v1");
    expect(parsed.accessTokenTtlSeconds).toBe(900);
    expect(parsed.refreshTokenTtlSeconds).toBe(2_592_000);
  });

  it("enforces HTTPS for production URLs and exact redirect targets", () => {
    const insecure = validServerOptions();
    insecure.baseUrl = "http://project.example.com/auth/v1";
    expect(authServerOptionsSchema.safeParse(insecure).success).toBe(false);

    const wildcard = validServerOptions();
    wildcard.redirects.allowed = ["https://project.example.com/auth/*"];
    expect(authServerOptionsSchema.safeParse(wildcard).success).toBe(false);

    const insecureRedirect = validServerOptions();
    insecureRedirect.redirects.allowed = ["http://project.example.com/auth/callback"];
    expect(authServerOptionsSchema.safeParse(insecureRedirect).success).toBe(false);
  });

  it("enforces access and refresh TTL boundaries", () => {
    const accessTooShort = validServerOptions();
    accessTooShort.accessTokenTtlSeconds = 299;
    expect(authServerOptionsSchema.safeParse(accessTooShort).success).toBe(false);

    const accessTooLong = validServerOptions();
    accessTooLong.accessTokenTtlSeconds = 3_601;
    expect(authServerOptionsSchema.safeParse(accessTooLong).success).toBe(false);

    const refreshTooShort = validServerOptions();
    refreshTooShort.refreshTokenTtlSeconds = 3_599;
    expect(authServerOptionsSchema.safeParse(refreshTooShort).success).toBe(false);

    const refreshTooLong = validServerOptions();
    refreshTooLong.refreshTokenTtlSeconds = 90 * 24 * 60 * 60 + 1;
    expect(authServerOptionsSchema.safeParse(refreshTooLong).success).toBe(false);
  });

  it("requires non-empty issuer, audience, and key material", () => {
    const emptyIssuer = validServerOptions();
    emptyIssuer.signingKeys.issuer = " ";
    expect(authServerOptionsSchema.safeParse(emptyIssuer).success).toBe(false);

    const emptyAudience = validServerOptions();
    emptyAudience.signingKeys.audience = " ";
    expect(authServerOptionsSchema.safeParse(emptyAudience).success).toBe(false);

    const missingSigningKey = validServerOptions();
    missingSigningKey.signingKeys.keys = {};
    expect(authServerOptionsSchema.safeParse(missingSigningKey).success).toBe(false);

    const missingTokenHashKey = validServerOptions();
    missingTokenHashKey.secrets.tokenHashKey = "";
    expect(authServerOptionsSchema.safeParse(missingTokenHashKey).success).toBe(false);

    const missingEncryptionKey = validServerOptions();
    missingEncryptionKey.secrets.encryptionKey = "";
    expect(authServerOptionsSchema.safeParse(missingEncryptionKey).success).toBe(false);
  });

  it("allows explicitly non-production HTTP development URLs", () => {
    const local = validServerOptions();
    local.environment = "development";
    local.baseUrl = "http://localhost:3000/auth/v1";
    local.siteUrl = "http://localhost:3000";
    local.signingKeys.issuer = "local-issuer";
    local.redirects.allowed = ["http://localhost:3000/auth/callback"];

    expect(authServerOptionsSchema.safeParse(local).success).toBe(true);
  });
});
