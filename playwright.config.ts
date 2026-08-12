import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./packages/mrjim-auth/test/browser",
  fullyParallel: false,
  workers: 1,
  reporter: "line",
  use: {
    browserName: "chromium",
    headless: true,
    channel: "chrome",
  },
});
