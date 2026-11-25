import "@testing-library/jest-dom/vitest"
// English, synchronous: components and libs call `t()` with no setup in a test.
import "@/i18n"

// jsdom has no matchMedia: report "no preference" everywhere.
if (typeof window !== "undefined") {
  Object.defineProperty(window, "matchMedia", {
    writable: true,
    value: (query: string) => ({
      matches: false,
      media: query,
      onchange: null,
      addEventListener: () => undefined,
      removeEventListener: () => undefined,
      addListener: () => undefined,
      removeListener: () => undefined,
      dispatchEvent: () => false,
    }),
  })
}
