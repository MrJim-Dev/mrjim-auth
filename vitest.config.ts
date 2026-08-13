import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["./packages/mrjim-auth/test/**/*.spec.ts"],
    exclude: ["**/.worktrees/**"],
  },
});
