import { describe, expect, it } from "vitest";
import { authFailure, authSuccess } from "../../src/shared/result.js";
import {
  AUTH_ERROR_CODES,
  INTERNAL_AUTH_ERROR_CODES,
  AuthApiError,
  AuthProgrammingError,
  mapInternalAuthErrorCodeToPublic,
  type AuthError,
  type PublicAuthErrorCode,
} from "../../src/shared/errors.js";
import {
  authRepositorySchema,
  authServerOptionsSchema,
  clientBaseUrlSchema,
  clientOptionsSchema,
  type AuthServerOptions,
} from "../../src/shared/config.js";
import {
  permissionSchema,
  redactedMetadataSchema,
  roleKeySchema,
  roleSchema,
  safeIdentityDataSchema,
  sanitizeIdentityData,
  sanitizeRedactedMetadata,
  scopeIdentifierSchema,
  uuidSchema,
} from "../../src/shared/types.js";
import type { AuditEventInput, OneTimeTokenInput } from "../../src/shared/contracts.js";
import type {
  AuthChangeEvent,
  AuthorizationScope,
  Identity,
  Permission,
  Role,
  SafeIdentityData,
  Session,
  User,
} from "../../src/shared/types.js";

type TestServerOptions = {
  environment: "development" | "test" | "production";
  baseUrl: string;
  siteUrl: string;
  database: Record<string, unknown>;
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

const asyncMethod = async (..._arguments: unknown[]): Promise<null> => null;

const completeRepository = {
  transaction: async (..._arguments: unknown[]): Promise<null> => null,
  users: {
    findById: asyncMethod,
    findByNormalizedEmail: asyncMethod,
    create: asyncMethod,
    update: asyncMethod,
    softDelete: asyncMethod,
  },
  identities: {
    findByProviderSubject: asyncMethod,
    listByUserId: asyncMethod,
    create: asyncMethod,
    deleteById: asyncMethod,
  },
  passwordCredentials: {
    findByUserId: asyncMethod,
    upsert: asyncMethod,
    deleteByUserId: asyncMethod,
  },
  sessions: {
    create: asyncMethod,
    findRefreshForUpdate: asyncMethod,
    rotate: asyncMethod,
    revokeSession: asyncMethod,
    revokeFamily: asyncMethod,
    revokeUserSessions: asyncMethod,
  },
  oneTimeTokens: {
    issue: asyncMethod,
    consume: asyncMethod,
  },
  oauthStates: {
    create: asyncMethod,
    consume: asyncMethod,
  },
  authorization: {
    effectivePermissions: asyncMethod,
    assignRole: asyncMethod,
    unassignRole: asyncMethod,
    setRolePermissions: asyncMethod,
    setRoleInheritance: asyncMethod,
  },
  roles: {
    list: asyncMethod,
    findById: asyncMethod,
    create: asyncMethod,
    update: asyncMethod,
    delete: asyncMethod,
  },
  permissions: {
    list: asyncMethod,
    findById: asyncMethod,
    create: asyncMethod,
    update: asyncMethod,
    delete: asyncMethod,
  },
  operations: {
    appendAudit: asyncMethod,
    findApiKeyByHash: asyncMethod,
  },
};

const uuid = (value: string) => uuidSchema.parse(value);

const validServerOptions = (): TestServerOptions => ({
  environment: "production" as const,
  baseUrl: "https://project.example.com/auth/v1",
  siteUrl: "https://project.example.com",
  database: completeRepository,
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

  it("rejects arbitrary and enumeration-sensitive codes at the public boundary", () => {
    const acceptsPublicCode = (code: PublicAuthErrorCode) => code;

    // @ts-expect-error Arbitrary strings are not public API error codes.
    acceptsPublicCode("application_secret_leaked");

    expect(() =>
      new AuthApiError(
        "application_secret_leaked" as unknown as PublicAuthErrorCode,
        500,
        "Internal error",
      ),
    ).toThrow(AuthProgrammingError);
    expect(() =>
      new AuthApiError(
        INTERNAL_AUTH_ERROR_CODES.email_exists as unknown as PublicAuthErrorCode,
        400,
        "Internal conflict",
      ),
    ).toThrow(AuthProgrammingError);

    expect(AUTH_ERROR_CODES).not.toHaveProperty("email_exists");
    expect(AUTH_ERROR_CODES).not.toHaveProperty("email_not_confirmed");
    expect(mapInternalAuthErrorCodeToPublic(INTERNAL_AUTH_ERROR_CODES.email_exists)).toBe(
      "invalid_request",
    );
    expect(mapInternalAuthErrorCodeToPublic(INTERNAL_AUTH_ERROR_CODES.email_not_confirmed)).toBe(
      "invalid_credentials",
    );

    const unsafeError = {
      name: "AuthError",
      message: "not safe",
      status: 400,
      code: "email_exists",
    } as unknown as AuthError;
    expect(() => authFailure(unsafeError)).toThrow(AuthProgrammingError);
  });
});

describe("shared identity and authorization types", () => {
  it("models safe user, identity, session, role, permission, and event values", () => {
    const user: User = {
      id: uuid("00000000-0000-4000-8000-000000000001"),
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
      id: uuid("00000000-0000-4000-8000-000000000002"),
      user_id: user.id,
      provider: "google",
      provider_subject: "google-subject",
      email: user.email,
      identity_data: sanitizeIdentityData({ name: "User", email_verified: true }),
      created_at: "2026-08-11T00:00:00.000Z",
      updated_at: "2026-08-11T00:00:00.000Z",
    };
    const role: Role = {
      id: uuid("00000000-0000-4000-8000-000000000003"),
      key: roleKeySchema.parse("member"),
      name: "Member",
      description: null,
      rank: 10,
      is_system: false,
      created_at: "2026-08-11T00:00:00.000Z",
      updated_at: "2026-08-11T00:00:00.000Z",
    };
    const permission: Permission = {
      id: uuid("00000000-0000-4000-8000-000000000004"),
      key: "invoice.read" as Permission["key"],
      resource: "invoice" as Permission["resource"],
      action: "read" as Permission["action"],
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

  it("sanitizes raw provider claims into a scalar public allowlist recursively", () => {
    const sanitized = sanitizeIdentityData({
      sub: "provider-subject",
      email: "user@example.com",
      name: "User",
      access_token: "top-level-token",
      accessToken: "camel-case-token",
      privateKey: "-----BEGIN PRIVATE KEY-----",
      provider_secret: "provider-secret",
      nested: {
        name: "nested-name",
        refreshToken: "nested-refresh-token",
        oauthCode: "nested-oauth-code",
      },
      claims: [{ id_token: "array-token" }],
    });

    expect(sanitized).toEqual({
      sub: "provider-subject",
      email: "user@example.com",
      name: "User",
    });
    expect(safeIdentityDataSchema.safeParse(sanitized).success).toBe(true);
    expect(safeIdentityDataSchema.safeParse({ accessToken: "secret" }).success).toBe(false);
    expect(sanitized).not.toHaveProperty("access_token");
    expect(sanitized).not.toHaveProperty("accessToken");
    expect(sanitized).not.toHaveProperty("privateKey");
  });

  it("requires branded sanitized identity data and rejects credential-bearing avatar URLs", () => {
    const trustedClaims = sanitizeIdentityData({
      name: "User",
      avatar_url: "https://cdn.example.com/avatar.png",
    });
    const trustedIdentityData: SafeIdentityData = trustedClaims;
    expect(trustedIdentityData.avatar_url).toBe("https://cdn.example.com/avatar.png");

    const untrustedClaims = { name: "User", accessToken: "provider-token" };
    // @ts-expect-error SafeIdentityData is only obtainable from the runtime allowlist.
    const unsafeClaims: SafeIdentityData = untrustedClaims;
    // @ts-expect-error Identity.identity_data requires the branded sanitizer output.
    const unsafeIdentityData: Identity["identity_data"] = untrustedClaims;
    void unsafeClaims;
    void unsafeIdentityData;

    for (const avatarUrl of [
      "https://cdn.example.com/avatar.png?access_token=provider-token",
      "https://cdn.example.com/avatar.png#refresh_token=provider-token",
    ]) {
      expect(safeIdentityDataSchema.safeParse({ avatar_url: avatarUrl }).success).toBe(false);
    }
    expect(
      sanitizeIdentityData({ name: "User", avatar_url: "https://cdn.example.com/avatar.png?token=raw" }),
    ).toEqual({ name: "User" });
  });

  it("uses branded UUID and lowercase/RBAC schemas", () => {
    expect(uuidSchema.safeParse("00000000-0000-4000-8000-000000000001").success).toBe(true);
    expect(uuidSchema.safeParse("not-a-uuid").success).toBe(false);
    expect(roleKeySchema.safeParse("member").success).toBe(true);
    expect(roleKeySchema.safeParse("Member").success).toBe(false);
    expect(roleKeySchema.safeParse("member.role").success).toBe(false);
    expect(scopeIdentifierSchema.safeParse("org_123").success).toBe(true);
    expect(scopeIdentifierSchema.safeParse(" ").success).toBe(false);

    const role = {
      id: "00000000-0000-4000-8000-000000000003",
      key: "Member",
      name: "Member",
      description: null,
      rank: 10,
      is_system: false,
      created_at: "2026-08-11T00:00:00.000Z",
      updated_at: "2026-08-11T00:00:00.000Z",
    };
    expect(roleSchema.safeParse(role).success).toBe(false);

    expect(
      permissionSchema.safeParse({
        id: "00000000-0000-4000-8000-000000000004",
        key: "invoice.read",
        resource: "invoice",
        action: "read",
        description: null,
        created_at: "2026-08-11T00:00:00.000Z",
        updated_at: "2026-08-11T00:00:00.000Z",
      }).success,
    ).toBe(true);
    expect(
      permissionSchema.safeParse({
        id: "00000000-0000-4000-8000-000000000004",
        key: "invoice.*",
        resource: "invoice",
        action: "*",
        description: null,
        created_at: "2026-08-11T00:00:00.000Z",
        updated_at: "2026-08-11T00:00:00.000Z",
      }).success,
    ).toBe(true);
    expect(
      permissionSchema.safeParse({
        id: "00000000-0000-4000-8000-000000000004",
        key: "*.*",
        resource: "*",
        action: "*",
        description: null,
        created_at: "2026-08-11T00:00:00.000Z",
        updated_at: "2026-08-11T00:00:00.000Z",
      }).success,
    ).toBe(true);
    expect(
      permissionSchema.safeParse({
        id: "00000000-0000-4000-8000-000000000004",
        key: "invoice.write",
        resource: "invoice",
        action: "read",
        description: null,
        created_at: "2026-08-11T00:00:00.000Z",
        updated_at: "2026-08-11T00:00:00.000Z",
      }).success,
    ).toBe(false);
    expect(
      permissionSchema.safeParse({
        id: "00000000-0000-4000-8000-000000000004",
        key: "*.read",
        resource: "*",
        action: "read",
        description: null,
        created_at: "2026-08-11T00:00:00.000Z",
        updated_at: "2026-08-11T00:00:00.000Z",
      }).success,
    ).toBe(false);
  });

  it("uses a branded non-UUID authorization scope identifier", () => {
    const scope: AuthorizationScope = {
      type: "organization",
      id: scopeIdentifierSchema.parse("org_123"),
    };
    expect(scope.id).toBe("org_123");

    // @ts-expect-error Scope IDs must be parsed/branded before entering authorization contracts.
    const unsafeScope: AuthorizationScope = { type: "organization", id: "org_123" };
    void unsafeScope;
  });
});

describe("redacted metadata", () => {
  it("redacts credential-bearing keys recursively for token and audit metadata", () => {
    const credentialVariants = {
      OTP: "123456",
      oneTime: "123456",
      oneTimeCode: "123456",
      verifier: "pkce-verifier",
      code_verifier: "pkce-verifier",
      PKCEVerifier: "pkce-verifier",
      cookie: "session=raw",
      "Set-Cookie": "session=raw",
      sessionToken: "session-bearer",
      sessionBearer: "Bearer session-bearer",
      session: "Bearer session-bearer",
      authorizationCode: "oauth-code",
      rawLink: "https://project.example.com/auth/callback?token=raw-token",
      bearer: "Bearer raw-token",
    };

    for (const [key, value] of Object.entries(credentialVariants)) {
      expect(sanitizeRedactedMetadata({ [key]: value }), key).toEqual({});
    }

    const sanitized = sanitizeRedactedMetadata({
      safe: "keep",
      provider: "google",
      provider_id: "google-123",
      session_id: "session_123",
      organization_id: "org_123",
      access_token: "raw-token",
      tokenHash: "raw-hash",
      password: "raw-password",
      oauthCode: "oauth-code",
      providerSecret: "provider-secret",
      privateKey: "private-key",
      nested: {
        safe: true,
        refresh_token: "nested-token",
        authorizationCode: "nested-code",
        deeper: { passwordHash: "nested-hash", keep: 1 },
      },
      variants: credentialVariants,
      list: [{ clientSecret: "nested-secret" }, "safe"],
    });

    expect(sanitized).toEqual({
      safe: "keep",
      provider: "google",
      provider_id: "google-123",
      session_id: "session_123",
      organization_id: "org_123",
      nested: { safe: true, deeper: { keep: 1 } },
      list: ["safe"],
    });
    expect(redactedMetadataSchema.safeParse(sanitized).success).toBe(true);
    expect(redactedMetadataSchema.safeParse({ nested: { accessToken: "secret" } }).success).toBe(
      false,
    );

    const oneTimeToken: OneTimeTokenInput = {
      purpose: "recovery",
      token_hash: new Uint8Array([1]),
      target: "user@example.com",
      expires_at: new Date(),
      metadata: sanitized,
    };
    const auditEvent: AuditEventInput = {
      action: "recovery.requested",
      target_type: "user",
      outcome: "success",
      metadata: sanitized,
    };
    expect(oneTimeToken.metadata).toBe(sanitized);
    expect(auditEvent.metadata).toBe(sanitized);
  });
});

describe("repository and URL boundaries", () => {
  it("accepts a complete repository aggregate and rejects missing member methods", () => {
    expect(authRepositorySchema.safeParse(completeRepository).success).toBe(true);
    expect(authRepositorySchema.safeParse({}).success).toBe(false);

    const missingPasswordMethod = {
      ...completeRepository,
      passwordCredentials: {
        ...completeRepository.passwordCredentials,
        upsert: undefined,
      },
    };
    expect(authRepositorySchema.safeParse(missingPasswordMethod).success).toBe(false);

    const malformedRoleMethod = {
      ...completeRepository,
      roles: {
        ...completeRepository.roles,
        delete: "not-a-function",
      },
    };
    expect(authRepositorySchema.safeParse(malformedRoleMethod).success).toBe(false);

    const missingOAuthState = {
      ...completeRepository,
      oauthStates: {
        ...completeRepository.oauthStates,
        consume: undefined,
      },
    };
    expect(authRepositorySchema.safeParse(missingOAuthState).success).toBe(false);
  });

  it("accepts only HTTP(S) client URLs and applies HTTPS only in production", () => {
    for (const url of [
      "file:///tmp/auth",
      "javascript:alert(1)",
      "data:text/plain,auth",
      "ftp://project.example.com/auth",
    ]) {
      expect(clientBaseUrlSchema.safeParse(url).success).toBe(false);
    }
    expect(clientBaseUrlSchema.safeParse("http://localhost:3000/auth/v1").success).toBe(true);
    expect(clientBaseUrlSchema.safeParse("https://project.example.com/auth/v1").success).toBe(
      true,
    );
    expect(() => clientBaseUrlSchema.safeParse("not a url")).not.toThrow();
    expect(clientBaseUrlSchema.safeParse("not a url").success).toBe(false);

    for (const field of ["baseUrl", "siteUrl"] as const) {
      const invalid = validServerOptions();
      invalid[field] = "file:///tmp/auth";
      expect(authServerOptionsSchema.safeParse(invalid).success).toBe(false);

      const malformed = validServerOptions();
      malformed[field] = "not a url";
      expect(() => authServerOptionsSchema.safeParse(malformed)).not.toThrow();
      expect(authServerOptionsSchema.safeParse(malformed).success).toBe(false);
    }
    const invalidRedirect = validServerOptions();
    invalidRedirect.redirects.allowed = ["javascript:alert(1)"];
    expect(authServerOptionsSchema.safeParse(invalidRedirect).success).toBe(false);

    const malformedRedirect = validServerOptions();
    malformedRedirect.redirects.allowed = ["not a url"];
    expect(() => authServerOptionsSchema.safeParse(malformedRedirect)).not.toThrow();
    expect(authServerOptionsSchema.safeParse(malformedRedirect).success).toBe(false);

    const malformedOidc = {
      ...validServerOptions(),
      oauth: {
        oidc: {
          clientId: "oidc-client",
          clientSecret: "oidc-secret",
          issuer: "not a url",
        },
      },
    };
    expect(() => authServerOptionsSchema.safeParse(malformedOidc)).not.toThrow();
    expect(authServerOptionsSchema.safeParse(malformedOidc).success).toBe(false);

    const identifierIssuer = validServerOptions();
    identifierIssuer.signingKeys.issuer = "auth-prod-issuer";
    expect(authServerOptionsSchema.safeParse(identifierIssuer).success).toBe(true);

    const development = validServerOptions();
    development.environment = "development";
    development.baseUrl = "http://localhost:3000/auth/v1";
    development.siteUrl = "http://localhost:3000";
    development.redirects.allowed = ["http://localhost:3000/auth/callback"];
    development.signingKeys.issuer = "local-issuer";
    expect(authServerOptionsSchema.safeParse(development).success).toBe(true);
  });

  it("keeps repository contracts internal until a later package export task", async () => {
    const root = await import("../../src/index.js");
    expect(root).not.toHaveProperty("authRepositorySchema");
    expect(root).not.toHaveProperty("UserRepository");
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
