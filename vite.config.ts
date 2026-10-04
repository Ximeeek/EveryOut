import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"],
    clearMocks: true,
  },
  clearScreen: false,
  server: {
    strictPort: true,
    port: 1420,
    watch: { ignored: ["**/target/**", "**/src-tauri/gen/**"] },
  },
});
