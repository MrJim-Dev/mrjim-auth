import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import ts from "typescript";
import { describe, expect, it } from "vitest";

const root = resolve(import.meta.dirname, "../../../..");

const requiredDocuments = [
  "README.md",
  "CHANGELOG.md",
  "docs/getting-started.md",
  "docs/concepts/architecture.md",
  "docs/concepts/sessions.md",
  "docs/reference/client.md",
  "docs/reference/server.md",
  "docs/reference/schema.md",
  "docs/guides/email-password.md",
  "docs/guides/google-oauth.md",
  "docs/guides/ssr-nextjs.md",
  "docs/guides/express.md",
  "docs/guides/roles-permissions.md",
  "docs/guides/migrating-to-supabase.md",
  "docs/compatibility/supabase-auth.md",
  "docs/security.md",
] as const;

const requiredExamples = [
  "examples/express-api/package.json",
  "examples/express-api/src/server.ts",
  "examples/express-api/test/example.spec.ts",
  "examples/nextjs-app-router/package.json",
  "examples/nextjs-app-router/src/example.ts",
  "examples/nextjs-app-router/test/example.spec.ts",
] as const;

const clientMethods = [
  "createClient",
  "signUp",
  "signInWithPassword",
  "signInWithOtp",
  "verifyOtp",
  "signInWithOAuth",
  "exchangeCodeForSession",
  "resetPasswordForEmail",
  "resetPassword",
  "resend",
  "getSession",
  "getUser",
  "setSession",
  "refreshSession",
  "updateUser",
  "getUserIdentities",
  "linkIdentity",
  "unlinkIdentity",
  "getPermissions",
  "signOut",
  "onAuthStateChange",
  "startAutoRefresh",
  "stopAutoRefresh",
  "dispose",
] as const;

const adminMethods = [
  "createAdminClient",
  "listUsers",
  "getUserById",
  "findUser",
  "createUser",
  "updateUserById",
  "deleteUser",
  "inviteUserByEmail",
  "listRoles",
  "createRole",
  "updateRole",
  "deleteRole",
  "setRolePermissions",
  "setRoleInheritance",
  "assignRole",
  "unassignRole",
  "listPermissions",
  "createPermission",
  "updatePermission",
  "deletePermission",
  "listAudit",
] as const;

function document(path: string): string {
  return readFileSync(resolve(root, path), "utf8");
}

function compileExamples(): readonly string[] {
  const snippets = requiredDocuments.flatMap((path) => {
    const markdown = document(path);
    return [...markdown.matchAll(/```(?:ts|typescript) compile\n([\s\S]*?)```/g)].map(
      (match, index) => ({ path, index, source: match[1] ?? "" }),
    );
  });
  expect(snippets.length, "at least one TypeScript example must be tagged `compile`").toBeGreaterThan(0);

  const directory = mkdtempSync(resolve(tmpdir(), "mrjim-auth-docs-"));
  try {
    const roots = snippets.map((snippet, index) => {
      const path = resolve(directory, `example-${index}.ts`);
      writeFileSync(path, snippet.source);
      return path;
    });
    const program = ts.createProgram(roots, {
      baseUrl: root,
      paths: {
        "mrjim-auth": ["packages/mrjim-auth/dist/index.d.ts"],
        "mrjim-auth/server": ["packages/mrjim-auth/dist/server/index.d.ts"],
        "mrjim-auth/postgres": ["packages/mrjim-auth/dist/postgres/index.d.ts"],
        "mrjim-auth/express": ["packages/mrjim-auth/dist/adapters/express.d.ts"],
        "mrjim-auth/nextjs": ["packages/mrjim-auth/dist/adapters/nextjs-browser.d.ts"],
        "mrjim-auth/nextjs/server": ["packages/mrjim-auth/dist/adapters/nextjs-server.d.ts"],
        "mrjim-auth/client/pkce": ["packages/mrjim-auth/dist/client/pkce.d.ts"],
        "mrjim-auth/testing": ["packages/mrjim-auth/dist/testing/index.d.ts"],
      },
      ignoreDeprecations: "6.0",
      module: ts.ModuleKind.ESNext,
      moduleResolution: ts.ModuleResolutionKind.Bundler,
      noEmit: true,
      skipLibCheck: true,
      strict: true,
      target: ts.ScriptTarget.ES2022,
      types: ["node"],
    });
    return ts.getPreEmitDiagnostics(program).map((diagnostic) => {
      const message = ts.flattenDiagnosticMessageText(diagnostic.messageText, "\n");
      if (diagnostic.file === undefined || diagnostic.start === undefined) return message;
      const position = diagnostic.file.getLineAndCharacterOfPosition(diagnostic.start);
      const snippetIndex = roots.indexOf(diagnostic.file.fileName);
      const source = snippets[snippetIndex];
      return `${source?.path ?? diagnostic.file.fileName}:${position.line + 1}:${position.character + 1} ${message}`;
    });
  } finally {
    rmSync(directory, { force: true, recursive: true });
  }
}

describe("published documentation and examples", () => {
  it("ships every required document and runnable example entry point", () => {
    for (const path of [...requiredDocuments, ...requiredExamples]) {
      expect(existsSync(resolve(root, path)), `${path} must exist`).toBe(true);
    }
  });

  it("documents every public client and administration method", () => {
    const client = document("docs/reference/client.md");
    const server = document("docs/reference/server.md");
    for (const method of clientMethods) expect(client, `${method} must be in the client reference`).toMatch(new RegExp(`\\b${method}\\b`));
    for (const method of adminMethods) expect(server, `${method} must be in the server reference`).toMatch(new RegExp(`\\b${method}\\b`));
  });

  it("compiles every TypeScript fence tagged compile against package declarations", () => {
    expect(compileExamples()).toEqual([]);
  });

  it("uses explicit Supabase compatibility statuses and names v1 exclusions", () => {
    const compatibility = document("docs/compatibility/supabase-auth.md");
    for (const status of ["Compatible", "Different", "Unsupported in v1"]) expect(compatibility).toContain(status);
    for (const exclusion of ["from", "rpc", "storage", "realtime", "phone auth", "MFA", "anonymous auth", "SAML"]) {
      expect(compatibility.toLowerCase()).toContain(exclusion.toLowerCase());
    }
  });
});
