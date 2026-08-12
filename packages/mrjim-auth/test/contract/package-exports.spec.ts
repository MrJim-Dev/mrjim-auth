import { access, readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { build, type BuildResult, type Plugin } from "esbuild";
import { describe, expect, it } from "vitest";
import { FORBIDDEN_AUTH_NAMES } from "../../src/postgres/internal/schema-contract.js";

interface ExportTarget {
  readonly types: string;
  readonly import: string;
}

interface PackageManifest {
  readonly name: string;
  readonly exports: Record<string, ExportTarget>;
}

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const manifest = JSON.parse(
  await readFile(resolve(packageRoot, "package.json"), "utf8"),
) as PackageManifest;

const requiredExportKeys = [
  ".",
  "./server",
  "./postgres",
  "./express",
  "./nextjs",
  "./nextjs/server",
  "./client/pkce",
  "./testing",
] as const;

const browserEntryFiles = ["dist/index.js", "dist/adapters/nextjs-browser.js", "dist/client/pkce.js"] as const;
const migrationAssetFiles = [
  "dist/postgres/migrations/0001_core.sql",
  "dist/postgres/migrations/0002_authorization.sql",
  "dist/postgres/migrations/0003_oauth_operations.sql",
  "dist/postgres/migrations/0004_repository_hardening.sql",
  "dist/postgres/migrations/0005_oauth_callback.sql",
  "dist/postgres/migrations/0006_admin_operations.sql",
] as const;
const nodeOnlyImportPattern = /^(?:node:)?(?:assert|buffer|child_process|cluster|crypto|dgram|dns|events|fs|http|https|module|net|os|path|perf_hooks|process|readline|stream|string_decoder|timers|tls|tty|url|util|v8|vm|worker_threads|zlib)(?:\/.*)?$/;
const serverOnlyDependencyPattern = /^(?:@node-rs\/argon2|argon2|kysely|pg|pg-native|postgres|postgresjs)(?:\/.*)?$/;

const browserBoundaryPlugin: Plugin = {
  name: "mrjim-auth-browser-boundary",
  setup(buildContext) {
    buildContext.onResolve({ filter: nodeOnlyImportPattern }, (args) => ({
      errors: [{ text: `browser boundary rejected Node-only import: ${args.path}` }],
    }));
    buildContext.onResolve({ filter: serverOnlyDependencyPattern }, (args) => ({
      errors: [{ text: `browser boundary rejected server-only dependency: ${args.path}` }],
    }));
  },
};

function packageSpecifier(exportKey: string): string {
  return exportKey === "." ? manifest.name : `${manifest.name}${exportKey.slice(1)}`;
}

function packageTarget(exportKey: string): ExportTarget {
  const target = manifest.exports[exportKey];
  if (!target) {
    throw new Error(`Missing package export target for ${exportKey}`);
  }
  return target;
}

function bundleBrowserEntry(entryFile: string): Promise<BuildResult> {
  return build({
    absWorkingDir: packageRoot,
    bundle: true,
    entryPoints: [resolve(packageRoot, entryFile)],
    format: "esm",
    logLevel: "silent",
    platform: "browser",
    plugins: [browserBoundaryPlugin],
    write: false,
  });
}

function bundleBrowserSource(source: string): Promise<BuildResult> {
  return build({
    absWorkingDir: packageRoot,
    bundle: true,
    format: "esm",
    logLevel: "silent",
    platform: "browser",
    plugins: [browserBoundaryPlugin],
    stdin: {
      contents: source,
      resolveDir: packageRoot,
      sourcefile: "browser-boundary-fixture.ts",
    },
    write: false,
  });
}

async function captureBrowserBuildError(source: string): Promise<unknown> {
  try {
    await bundleBrowserSource(source);
    return null;
  } catch (error) {
    return error;
  }
}

function errorMessages(error: unknown): string {
  if (typeof error === "object" && error !== null && "errors" in error) {
    const errors = (error as { readonly errors?: readonly { readonly text?: string }[] }).errors;
    if (errors) {
      return errors.map(({ text }) => text ?? "").join("\n");
    }
  }
  return String(error);
}

describe("package export boundaries", () => {
  it("loads every declared export through the built package self-reference", async () => {
    expect(manifest.name).toBe("mrjim-auth");
    expect(Object.keys(manifest.exports).sort()).toEqual([...requiredExportKeys].sort());

    const importTargets = requiredExportKeys.map((exportKey) => packageTarget(exportKey).import);
    expect(new Set(importTargets).size).toBe(requiredExportKeys.length);

    for (const exportKey of requiredExportKeys) {
      const target = packageTarget(exportKey);
      expect(target.import).toMatch(/^\.\/dist\/.+\.js$/);
      expect(target.types).toMatch(/^\.\/dist\/.+\.d\.ts$/);
      await access(resolve(packageRoot, target.import));
      await access(resolve(packageRoot, target.types));
      await import(packageSpecifier(exportKey));
    }
  });

  it("exposes the browser-safe Task 10 client from the package root", async () => {
    const root = await import(manifest.name);
    expect(Object.keys(root)).toEqual(["createClient"]);

    const client = root.createClient(
      "https://project.example.com/auth/v1",
      "publishable-key",
    );
    expect(Object.isFrozen(client)).toBe(true);
    expect(Object.keys(client)).toEqual(["auth"]);
    expect(Object.isFrozen(client.auth)).toBe(true);
    expect(Object.keys(client.auth).sort()).toEqual([
      "dispose",
      "exchangeCodeForSession",
      "getPermissions",
      "getSession",
      "getUser",
      "getUserIdentities",
      "linkIdentity",
      "onAuthStateChange",
      "refreshSession",
      "resend",
      "resetPassword",
      "resetPasswordForEmail",
      "setSession",
      "signInWithOAuth",
      "signInWithOtp",
      "signInWithPassword",
      "signOut",
      "signUp",
      "startAutoRefresh",
      "stopAutoRefresh",
      "unlinkIdentity",
      "updateUser",
      "verifyOtp",
    ].sort());
    client.auth.dispose();
  });

  it("exposes the Task 3 PostgreSQL migration API and keeps SQL in built output", async () => {
    const postgres = await import("mrjim-auth/postgres");
    expect(Object.keys(postgres).sort()).toEqual([
      "MIGRATIONS",
      "MigrationError",
      "PACKAGE_VERSION",
      "REQUIRED_TABLES",
      "createPostgresAdapter",
      "migrate",
      "migrationStatus",
      "verifySchema",
    ]);
    expect(postgres.MIGRATIONS.map(({ migrationOrder, version, fileName, checksum, introducedIn }) => ({ migrationOrder, version, fileName, checksum, introducedIn }))).toEqual([
      {
        migrationOrder: 1,
        version: "0001_core",
        fileName: "0001_core.sql",
        checksum: expect.stringMatching(/^[0-9a-f]{64}$/),
        introducedIn: "0.1.0",
      },
      {
        migrationOrder: 2,
        version: "0002_authorization",
        fileName: "0002_authorization.sql",
        checksum: expect.stringMatching(/^[0-9a-f]{64}$/),
        introducedIn: "0.1.0",
      },
      {
        migrationOrder: 3,
        version: "0003_oauth_operations",
        fileName: "0003_oauth_operations.sql",
        checksum: expect.stringMatching(/^[0-9a-f]{64}$/),
        introducedIn: "0.1.0",
      },
      {
        migrationOrder: 4,
        version: "0004_repository_hardening",
        fileName: "0004_repository_hardening.sql",
        checksum: expect.stringMatching(/^[0-9a-f]{64}$/),
        introducedIn: "0.1.0",
      },
      {
        migrationOrder: 5,
        version: "0005_oauth_callback",
        fileName: "0005_oauth_callback.sql",
        checksum: expect.stringMatching(/^[0-9a-f]{64}$/),
        introducedIn: "0.1.0",
      },
      {
        migrationOrder: 6,
        version: "0006_admin_operations",
        fileName: "0006_admin_operations.sql",
        checksum: expect.stringMatching(/^[0-9a-f]{64}$/),
        introducedIn: "0.1.0",
      },
    ]);
    expect(Object.isFrozen(postgres.MIGRATIONS)).toBe(true);
    expect(postgres.MIGRATIONS.every((migration) => Object.isFrozen(migration))).toBe(true);
    for (const assetFile of migrationAssetFiles) {
      await access(resolve(packageRoot, assetFile));
    }
  });

  it("exposes the Node-only lifecycle and OAuth services without browser dependencies", async () => {
    const server = await import("mrjim-auth/server");
    expect(Object.keys(server).sort()).toEqual([
      "ADMIN_MUTATION_RATE_LIMIT_POLICY",
      "ARGON2ID_PASSWORD_POLICY",
      "AuthServer",
      "AuthorizationService",
      "ES256_ALGORITHM",
      "EmailService",
      "GenericOidcProvider",
      "GoogleOAuthProvider",
      "InMemoryRateLimiter",
      "LOGIN_IDENTIFIER_RATE_LIMIT_POLICY",
      "LOGIN_IP_RATE_LIMIT_POLICY",
      "OAUTH_START_RATE_LIMIT_POLICY",
      "OAuthProviderError",
      "OAuthService",
      "OTP_ISSUE_RATE_LIMIT_POLICY",
      "OTP_VERIFY_RATE_LIMIT_POLICY",
      "OidcOAuthProvider",
      "OneTimeTokenService",
      "PasswordService",
      "PostgresRateLimiter",
      "RATE_LIMIT_POLICIES",
      "RECOVERY_RATE_LIMIT_POLICY",
      "RESEND_RATE_LIMIT_POLICY",
      "SIGNUP_RATE_LIMIT_POLICY",
      "SessionService",
      "TokenService",
      "UserService",
      "authorizeRoute",
      "callbackRoute",
      "createAuthServer",
      "createAuthorizationRequestContext",
      "createOAuthRoutes",
      "createPermissionRoutes",
      "exchangeRoute",
      "generateOpenApiDocument",
      "normalizePermissionKey",
      "permissionMatchRank",
      "permissionMatches",
      "permissionsRoute",
      "providersRoute",
      "subjectUserId",
    ]);
  });

  it("exposes only browser-safe RFC 7636 helpers from the client subpath", async () => {
    const client = await import("mrjim-auth/client/pkce");
    expect(Object.keys(client).sort()).toEqual([
      "PKCE_CODE_CHALLENGE_METHOD",
      "createCodeChallenge",
      "generateCodeChallenge",
      "generateCodeVerifier",
      "generatePkcePair",
      "isCodeVerifier",
    ]);
    expect(client.PKCE_CODE_CHALLENGE_METHOD).toBe("S256");
  });

  it("exposes only the bundled fake mailer from the testing subpath", async () => {
    const testing = await import("mrjim-auth/testing");
    expect(Object.keys(testing)).toEqual(["FakeMailer"]);
  });

  it("exposes only the bounded framework adapter functions", async () => {
    expect(Object.keys(await import("mrjim-auth/express"))).toEqual(["toExpressHandler"]);
    expect(Object.keys(await import("mrjim-auth/nextjs"))).toEqual(["createBrowserClient"]);
    expect(Object.keys(await import("mrjim-auth/nextjs/server"))).toEqual(["createServerClient"]);
  });

  it("keeps the canonical forbidden-name list in reviewable documentation", async () => {
    const guide = await readFile(resolve(packageRoot, "../../docs/guides/postgres-migrations.md"), "utf8");
    expect(guide).toContain(FORBIDDEN_AUTH_NAMES.join(", "));
  });

  it("warns that SSR cookie sessions are not authorization proof", async () => {
    const guide = await readFile(resolve(packageRoot, "../../docs/guides/framework-adapters.md"), "utf8");
    expect(guide).toMatch(/getSession\(\).*not.*authorization proof/is);
    expect(guide).toMatch(/getUser\(\).*validated/is);
  });

  it("does not expose unfinished behavior from later-task subpaths", async () => {
    for (const exportKey of requiredExportKeys
      .slice(1)
      .filter((key) => key !== "./postgres" && key !== "./server" && key !== "./express" && key !== "./nextjs" && key !== "./nextjs/server" && key !== "./client/pkce" && key !== "./testing")) {
      expect(Object.keys(await import(packageSpecifier(exportKey)))).toEqual([]);
    }
  });

  it("builds a functional ESM CLI with a shebang", async () => {
    const cli = await readFile(resolve(packageRoot, "dist/cli/index.js"), "utf8");
    const runner = await readFile(resolve(packageRoot, "dist/cli/runner.js"), "utf8");
    expect(cli.startsWith("#!/usr/bin/env node")).toBe(true);
    expect(cli).toContain("./runner.js");
    expect(runner).toContain("migrate");
    expect(runner).toContain("doctor");
  });

  it("bundles browser entries through browser-platform resolution", async () => {
    for (const entryFile of browserEntryFiles) {
      await bundleBrowserEntry(entryFile);
    }
  });

  it("rejects static and dynamic Node built-in imports in browser code", async () => {
    for (const source of ['import "node:fs";', 'await import("node:fs");']) {
      const error = await captureBrowserBuildError(source);
      expect(error).not.toBeNull();
      expect(errorMessages(error)).toContain("browser boundary rejected Node-only import");
    }
  });

  it("rejects bare server-only dependencies in browser code", async () => {
    for (const source of ['import "pg";', 'await import("pg");', 'import "kysely";', 'await import("kysely");']) {
      const error = await captureBrowserBuildError(source);
      expect(error).not.toBeNull();
      expect(errorMessages(error)).toContain("browser boundary rejected server-only dependency");
    }
  });
});
