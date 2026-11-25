// Each flag is its own small asset (see vite.config.ts), loaded only when shown. This module only
// holds the url table (about 260 entries), so country-flag.tsx fetches it lazily instead of
// shipping it in the entry chunk.
const FLAGS = import.meta.glob<string>("/node_modules/country-flag-icons/3x2/*.svg", {
  query: "?url",
  import: "default",
  eager: true,
})

export function flagUrl(code: string): string | null {
  return FLAGS[`/node_modules/country-flag-icons/3x2/${code.toUpperCase()}.svg`] ?? null
}
