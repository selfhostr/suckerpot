/// <reference types="vitest/config" />
import path from "node:path"
import tailwindcss from "@tailwindcss/vite"
import react from "@vitejs/plugin-react"
import { copyFile, rm } from "node:fs/promises"
import { defineConfig, loadEnv, type Plugin } from "vite"

/** The mock service worker must never ship in a real build. */
function dropMockWorker(enabled: boolean): Plugin {
  let outDir = "dist"
  return {
    name: "suckerpot:drop-mock-worker",
    apply: "build",
    configResolved(c) {
      outDir = path.resolve(c.root, c.build.outDir)
    },
    async closeBundle() {
      if (!enabled) await rm(path.join(outDir, "mockServiceWorker.js"), { force: true })
    },
  }
}

/**
 * GitHub Pages demo (VITE_DEMO=1, with VITE_MOCK=1): a fixed "synthetic data"
 * badge injected into index.html, and a 404.html copy so deep links survive a
 * reload (Pages serves 404.html for unknown paths).
 */
function demoPages(enabled: boolean): Plugin {
  let outDir = "dist"
  return {
    name: "suckerpot:demo-pages",
    apply: "build",
    configResolved(c) {
      outDir = path.resolve(c.root, c.build.outDir)
    },
    transformIndexHtml(html) {
      if (!enabled) return html
      const badge = `<a class="demo-badge" href="../" title="Back to the SuckerPot project page"><span aria-hidden="true"></span>Demo &mdash; synthetic data</a>`
      const css = `<style>.demo-badge{position:fixed;z-index:60;right:12px;bottom:12px;display:inline-flex;align-items:center;gap:8px;padding:6px 12px;border:1px solid var(--border-strong);border-radius:999px;background:var(--surface-raised);color:var(--fg-muted);font:500 12px/16px "Inter Variable",system-ui,sans-serif;text-decoration:none;box-shadow:0 2px 8px rgb(0 0 0/.25)}.demo-badge:hover{color:var(--fg)}.demo-badge:focus-visible{outline:2px solid var(--fg);outline-offset:2px}.demo-badge span{width:6px;height:6px;border-radius:50%;background:#e0b341}@media(max-width:767px){.demo-badge{right:8px;bottom:auto;top:8px;padding:4px 10px;font-size:11px}}</style>`
      return html.replace("</head>", `${css}</head>`).replace("</body>", `${badge}</body>`)
    },
    async closeBundle() {
      if (enabled) await copyFile(path.join(outDir, "index.html"), path.join(outDir, "404.html"))
    },
  }
}

// The dev server proxies /api to the FastAPI service. Override the target
// with VITE_API_PROXY (for example http://localhost:8443) in web/.env.local.
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "")
  const apiTarget = env.VITE_API_PROXY ?? "http://localhost:8000"
  const mock = env.VITE_MOCK === "1"
  const demo = env.VITE_DEMO === "1"

  return {
    // Sub-path for static hosting, for example VITE_BASE=/demo/.
    base: env.VITE_BASE ?? "/",
    plugins: [react(), tailwindcss(), dropMockWorker(mock), demoPages(demo)],
    resolve: {
      alias: { "@": path.resolve(import.meta.dirname, "src") },
    },
    server: {
      host: true,
      proxy: {
        "/api": { target: apiTarget, changeOrigin: true, ws: true },
      },
    },
    preview: { host: true },
    build: {
      sourcemap: false,
      // Flags are loaded one by one as <img>, never inlined into the bundle.
      assetsInlineLimit: (file: string) =>
        file.includes("country-flag-icons") ? false : undefined,
      // React in its own long-lived chunk; heavy libraries split per feature.
      rolldownOptions: {
        output: {
          codeSplitting: {
            groups: [
              {
                name: "react",
                test: /node_modules[\\/](react|react-dom|scheduler|react-router)[\\/]/,
                priority: 20,
                includeDependenciesRecursively: false,
              },
              // Heavy libraries get their own chunks, loaded only by the pages that need them.
              {
                name: "charts",
                test: /node_modules[\\/](recharts|d3-[a-z-]+|victory-vendor)[\\/]/,
                priority: 15,
                includeDependenciesRecursively: false,
              },
              {
                name: "xterm",
                test: /node_modules[\\/]@xterm[\\/]/,
                priority: 15,
                includeDependenciesRecursively: false,
              },
            ],
          },
        },
      },
    },
    test: {
      globals: true,
      environment: "jsdom",
      setupFiles: ["./src/test/setup.ts"],
      include: ["src/**/*.test.{ts,tsx}"],
      css: false,
    },
  }
})
