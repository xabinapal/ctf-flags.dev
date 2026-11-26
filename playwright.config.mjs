import { defineConfig } from "@playwright/test";

const baseURL = "http://127.0.0.1:4329";

export default defineConfig({
  testDir: "./test",
  testMatch: "**/*.spec.mjs",
  use: { baseURL, trace: "retain-on-failure" },
  webServer: {
    command: "npm run preview -- --host 127.0.0.1 --port 4329 --ignore-lock",
    url: baseURL,
    reuseExistingServer: false,
  },
});
