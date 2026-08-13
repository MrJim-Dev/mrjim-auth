import { access } from "node:fs/promises";

const requiredDocuments = [
  "README.md",
  "CHANGELOG.md",
  "docs/implementation-status.md",
  "docs/getting-started.md",
  "docs/concepts/architecture.md",
  "docs/concepts/sessions.md",
  "docs/reference/client.md",
  "docs/reference/storage.md",
  "docs/reference/server.md",
  "docs/reference/schema.md",
  "docs/guides/email-password.md",
  "docs/guides/framework-adapters.md",
  "docs/guides/google-oauth.md",
  "docs/specs/mrjim-auth-v1.md",
  "docs/guides/ssr-nextjs.md",
  "docs/guides/express.md",
  "docs/guides/roles-permissions.md",
  "docs/guides/migrating-to-supabase.md",
  "docs/compatibility/supabase-auth.md",
  "docs/security.md",
];

for (const document of requiredDocuments) {
  await access(document);
}

console.log(`docs:check passed (${requiredDocuments.length} required documents)`);
