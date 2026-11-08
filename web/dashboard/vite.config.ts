/// <reference types="vitest/config" />
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    // The login theme test reads the Keycloak theme's copy of the colours.
    fs: { allow: [".", "../../deployments/keycloak/themes"] },
    proxy: {
      "/api": "http://127.0.0.1:25800",
      "/ui-config": "http://127.0.0.1:25800",
    },
  },
  // CSS is read only by the login theme test, which compares the raw files.
  test: { environment: "jsdom", css: { include: [/\.css/] } },
});
