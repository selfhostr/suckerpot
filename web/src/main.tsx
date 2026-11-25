import "@fontsource-variable/inter"
import "@fontsource-variable/jetbrains-mono"
import "./styles/index.css"

import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { StrictMode, useEffect, useState } from "react"
import { createRoot } from "react-dom/client"
import { RouterProvider } from "react-router"
import { TooltipProvider } from "@/components/ui/tooltip"
import { AuthProvider } from "./app/auth"
import { LiveFeedProvider } from "./app/live-feed"
import { IpMaskProvider } from "./app/ip-mask"
import { ScannerFilterProvider } from "./app/scanner-filter"
import { initLocale, onLocaleChange } from "./i18n"
import { applyMotionMode } from "./lib/motion"
import { ThemeProvider } from "./app/theme"
import { router } from "./app/router"

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { staleTime: 15_000, refetchOnWindowFocus: false, retry: 1 },
  },
})

async function enableMocks() {
  if (import.meta.env.VITE_MOCK !== "1") return
  const { worker } = await import("./mocks/browser")
  await worker.start({
    onUnhandledFrame: "bypass",
    quiet: true,
    // Under a sub-path (GitHub Pages demo) the worker lives next to index.html.
    serviceWorker: { url: `${import.meta.env.BASE_URL}mockServiceWorker.js` },
  })
}

/** Remounts the routed tree when the language changes, so every `t()` call renders again. */
function LocalizedRouter() {
  const [version, setVersion] = useState(0)
  useEffect(() => onLocaleChange(() => setVersion((v) => v + 1)), [])
  return <RouterProvider key={version} router={router} />
}

applyMotionMode()

void Promise.all([enableMocks(), initLocale()]).then(() => {
  const root = document.getElementById("root")
  if (!root) throw new Error("#root missing")
  createRoot(root).render(
    <StrictMode>
      <ThemeProvider>
        <IpMaskProvider>
          <QueryClientProvider client={queryClient}>
            <TooltipProvider delayDuration={300}>
              <AuthProvider>
                <LiveFeedProvider>
                  <ScannerFilterProvider>
                    <LocalizedRouter />
                  </ScannerFilterProvider>
                </LiveFeedProvider>
              </AuthProvider>
            </TooltipProvider>
          </QueryClientProvider>
        </IpMaskProvider>
      </ThemeProvider>
    </StrictMode>,
  )
})
