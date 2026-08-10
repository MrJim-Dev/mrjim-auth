import { access } from "node:fs/promises";

const requiredDocuments = [
  "docs/implementation-status.md",
  "docs/specs/mrjim-auth-v1.md",
];

for (const document of requiredDocuments) {
  await access(document);
}

console.log(`docs:check passed (${requiredDocuments.length} required documents)`);
