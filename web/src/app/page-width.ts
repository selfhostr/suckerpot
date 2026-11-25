import type { UIMatch } from "react-router"

/**
 * How wide a page may grow, declared per route in the route table (`handle: { width }`):
 * - `prose`: reading pages (Settings, every detail page), about 1200 px, so lines stay short.
 * - `wide`: lists, hubs, Today, Results and Trends, about 1680 px: extra columns from `2xl`.
 * - `full`: the wall screen (Live), up to 2400 px.
 * The shell keeps the same gutters for all three, so switching pages never moves the edges on
 * a screen narrower than the cap.
 */
export type PageWidth = "prose" | "wide" | "full"

export interface RouteHandle {
  width?: PageWidth
}

/** Pages that declare nothing are reading pages: a new page stays readable by default. */
export const DEFAULT_PAGE_WIDTH: PageWidth = "prose"

/** The content column's cap, gutters included (Tailwind `--container-page-*` in index.css). */
export const PAGE_WIDTH_CLASS: Record<PageWidth, string> = {
  prose: "max-w-page-prose",
  wide: "max-w-page-wide",
  full: "max-w-page-full",
}

function widthOf(handle: unknown): PageWidth | undefined {
  if (typeof handle !== "object" || handle === null || !("width" in handle)) return undefined
  const w = (handle as RouteHandle).width
  return w === "prose" || w === "wide" || w === "full" ? w : undefined
}

/** The deepest matched route that declares a width wins. */
export function pageWidth(matches: readonly Pick<UIMatch, "handle">[]): PageWidth {
  for (let i = matches.length - 1; i >= 0; i--) {
    const w = widthOf(matches[i]?.handle)
    if (w) return w
  }
  return DEFAULT_PAGE_WIDTH
}
