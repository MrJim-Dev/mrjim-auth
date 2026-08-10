import { defineWorkspace } from "vitest/config";

export default defineWorkspace([
  {
    test: {
      name: "mrjim-auth",
      include: ["packages/mrjim-auth/test/**/*.spec.ts"],
    },
  },
]);
