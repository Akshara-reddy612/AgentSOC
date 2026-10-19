import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Dev server proxies /api to the demo server (python -m soc_server, default 127.0.0.1:8000).
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: process.env.AGENTSOC_API ?? "http://127.0.0.1:8000",
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, ""),
      },
    },
  },
});
