import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { fileURLToPath, URL } from "node:url";

// The dev server proxies /api to the FastAPI process so the browser sees a
// single origin. `npm run build` emits to frontend/dist, which src/web/app.py
// serves directly — same URLs either way, so deep links behave identically.
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./src", import.meta.url)),
    },
  },
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8000",
        changeOrigin: false,
      },
      // The embedded call graph loads vis-network from /vendor, which only the
      // FastAPI process serves. Unproxied, Vite answers with index.html, the
      // browser gets HTML where it expected JavaScript, and the graph renders
      // empty in dev only.
      "/vendor": {
        target: "http://127.0.0.1:8000",
        changeOrigin: false,
      },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: true,
  },
});
