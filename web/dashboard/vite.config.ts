import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/api": "http://127.0.0.1:25800",
      "/ui-config": "http://127.0.0.1:25800",
    },
  },
  test: { environment: "jsdom" },
} as never);
