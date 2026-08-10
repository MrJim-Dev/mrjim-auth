import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import type {
  AuthRepository,
  KeyProvider,
  OperationsRepository,
  RefreshTokenRecord,
  SessionRecord,
  SessionRepository,
  UserRepository,
} from "../../src/shared/contracts.js";
import { AuthConfigurationError } from "../../src/shared/errors.js";
import type { Session, User } from "../../src/shared/types.js";
import { uuidSchema } from "../../src/shared/types.js";
import { SessionService } from "../../src/server/sessions.js";
import { TokenService } from "../../src/server/tokens.js";

const NOW = new Date("2026-08-11T05:00:00.000Z");
const RAW_REFRESH_TOKEN = "R".repeat(43);
const TOKEN_HASH_KEY = Uint8Array.from({ length: 32 }, (_, index) => index + 1);
const USER_ID = uuidSchema.parse("00000000-0000-4000-8000-000000000301");
const SESSION_ID = uuidSchema.parse("00000000-0000-4000-8000-000000000302");
const REFRESH_ID = uuidSchema.parse("00000000-0000-4000-8000-000000000303");
const REPLACEMENT_ID = uuidSchema.parse("00000000-0000-4000-8000-000000000304");
const FAMILY_ID = uuidSchema.parse("00000000-0000-4000-8000-000000000305");

function makeKeyProvider(): KeyProvider {
  const pair = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const privateKey = pair.privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const publicKey = pair.publicKey.export({ type: "spki", format: "pem" }).toString();
  return {
    getActiveKeyId: () => "unit",
    getSigningKey: () => privateKey,
    getVerificationKeys: () => new Map([["unit", publicKey]]),
  };
}

function makeTokenService(): TokenService {
  return new TokenService({
    issuer: "https://project.example.com/auth/v1",
    audience: "project",
    keyProvider: makeKeyProvider(),
    tokenHashKey: TOKEN_HASH_KEY,
    clock: () => NOW,
  });
}

function makeUser(): User {
  return {
    id: USER_ID,
    email: "operational-errors@example.com",
    phone: null,
    email_confirmed_at: "2026-08-11T00:00:00.000Z",
    phone_confirmed_at: null,
    confirmed_at: "2026-08-11T00:00:00.000Z",
    last_sign_in_at: null,
    banned_until: null,
    user_metadata: {},
    app_metadata: {},
    created_at: "2026-08-11T00:00:00.000Z",
    updated_at: "2026-08-11T00:00:00.000Z",
    deleted_at: null,
  };
}

function makeSessionRecord(): SessionRecord {
  return {
    id: SESSION_ID,
    user_id: USER_ID,
    aal: 1,
    ip_address: null,
    user_agent: "ua-sha256:0000000000000000000000000000000000000000000000000000000000000000",
    created_at: NOW,
    refreshed_at: NOW,
    expires_at: new Date("2026-09-10T05:00:00.000Z"),
    revoked_at: null,
  };
}

function makeRefreshToken(
  tokenService: TokenService,
  overrides: Partial<RefreshTokenRecord> = {},
): RefreshTokenRecord {
  return {
    id: REFRESH_ID,
    session_id: SESSION_ID,
    token_hash: tokenService.hashOpaqueToken(RAW_REFRESH_TOKEN),
    family_id: FAMILY_ID,
    parent_id: null,
    replacement_id: null,
    issued_at: NOW,
    used_at: null,
    expires_at: new Date("2026-09-10T05:00:00.000Z"),
    revoked_at: null,
    ...overrides,
  };
}

function makeRepository(
  transaction: AuthRepository["transaction"],
  parts: {
    readonly sessions?: Partial<SessionRepository>;
    readonly users?: Partial<UserRepository>;
    readonly operations?: Partial<OperationsRepository>;
  } = {},
): AuthRepository {
  return {
    transaction,
    users: parts.users as UserRepository,
    identities: {} as AuthRepository["identities"],
    passwordCredentials: {} as AuthRepository["passwordCredentials"],
    sessions: parts.sessions as SessionRepository,
    oneTimeTokens: {} as AuthRepository["oneTimeTokens"],
    oauthStates: {} as AuthRepository["oauthStates"],
    authorization: {} as AuthRepository["authorization"],
    roles: {} as AuthRepository["roles"],
    permissions: {} as AuthRepository["permissions"],
    operations: parts.operations as OperationsRepository,
  } as AuthRepository;
}

function makeService(repository: AuthRepository, tokenService = makeTokenService()): SessionService {
  return new SessionService({ repository, tokens: tokenService, clock: () => NOW });
}

function expectInternalError(result: { data: unknown; error: unknown }, detail: string): void {
  expect(result).toMatchObject({
    data: null,
    error: {
      name: "AuthError",
      code: "internal_error",
      message: "Internal authentication error",
      status: 500,
    },
  });
  expect(JSON.stringify(result)).not.toContain(detail);
}

describe("SessionService operational error boundary", () => {
  it("returns a stable internal_error when create transaction fails operationally", async () => {
    const detail = "postgres password=do-not-leak-create";
    const repository = makeRepository(async () => {
      throw new Error(detail);
    });

    const result = await makeService(repository).create(makeUser(), {});

    expectInternalError(result, detail);
  });

  it("returns a stable internal_error when create audit persistence fails", async () => {
    const detail = "audit connection secret=do-not-leak-create-audit";
    const tokenService = makeTokenService();
    const session = makeSessionRecord();
    const repository = makeRepository(
      async (callback) => callback(makeRepository(
        async () => {
          throw new Error("unused nested transaction");
        },
        {
          sessions: { create: async () => ({ session, refreshToken: makeRefreshToken(tokenService) }) },
          operations: { appendAudit: async () => { throw new Error(detail); } },
        },
      )),
    );

    const result = await makeService(repository, tokenService).create(makeUser(), {});

    expectInternalError(result, detail);
  });

  it("returns a stable internal_error when refresh transaction fails operationally", async () => {
    const detail = "database unavailable refresh-detail";
    const repository = makeRepository(async () => {
      throw new Error(detail);
    });

    const result = await makeService(repository).refresh(RAW_REFRESH_TOKEN, {});

    expectInternalError(result, detail);
  });

  it("returns a stable internal_error when refresh audit persistence fails", async () => {
    const detail = "audit token=do-not-leak-refresh-audit";
    const tokenService = makeTokenService();
    const session = makeSessionRecord();
    const refreshToken = makeRefreshToken(tokenService);
    const repository = makeRepository(
      async (callback) => callback(makeRepository(
        async () => {
          throw new Error("unused nested transaction");
        },
        {
          users: { findById: async () => makeUser() },
          sessions: {
            findRefreshForUpdate: async () => ({ session, refreshToken }),
            rotate: async (_tokenId, replacement) => ({
              ...refreshToken,
              id: REPLACEMENT_ID,
              parent_id: REFRESH_ID,
              token_hash: replacement.token_hash,
              expires_at: replacement.expires_at,
            }),
          },
          operations: { appendAudit: async () => { throw new Error(detail); } },
        },
      )),
    );

    const result = await makeService(repository, tokenService).refresh(RAW_REFRESH_TOKEN, {});

    expectInternalError(result, detail);
  });

  it("returns internal_error instead of claiming replay containment when revocation fails", async () => {
    const detail = "revocation database secret=do-not-leak-containment";
    const tokenService = makeTokenService();
    const session = makeSessionRecord();
    const refreshToken = makeRefreshToken(tokenService, { used_at: new Date("2026-08-11T05:01:00.000Z") });
    let transactions = 0;
    const repository = makeRepository(async (callback) => {
      transactions += 1;
      if (transactions > 1) throw new Error(detail);
      return callback(makeRepository(
        async () => {
          throw new Error("unused nested transaction");
        },
        { sessions: { findRefreshForUpdate: async () => ({ session, refreshToken }) } },
      ));
    });

    const result = await makeService(repository, tokenService).refresh(RAW_REFRESH_TOKEN, {});

    expectInternalError(result, detail);
    expect(result.error).not.toMatchObject({ code: "refresh_token_reused" });
  });

  it("returns a stable internal_error when signOut transaction fails operationally", async () => {
    const detail = "postgres connection secret=do-not-leak-signout";
    const tokenService = makeTokenService();
    const user = makeUser();
    const sessionRecord = makeSessionRecord();
    const accessToken = await tokenService.issueAccessToken(user, sessionRecord);
    const session: Session = {
      access_token: accessToken,
      refresh_token: RAW_REFRESH_TOKEN,
      token_type: "bearer",
      expires_in: 900,
      expires_at: Math.floor(NOW.getTime() / 1000) + 900,
      user,
    };
    const repository = makeRepository(async () => {
      throw new Error(detail);
    });

    const result = await makeService(repository, tokenService).signOut(session, "local");

    expectInternalError(result, detail);
  });

  it("preserves deliberately classified configuration errors as throws", async () => {
    const expected = new AuthConfigurationError("configuration must not become public detail");
    const repository = makeRepository(async () => {
      throw expected;
    });

    await expect(makeService(repository).create(makeUser(), {})).rejects.toBe(expected);
  });
});
