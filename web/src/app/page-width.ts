import type { UIMatch } from "react-router"

/**
 * How a page uses the width, declared per route in the route table (`handle: { width }`):
 * - `wide`, the default: the page fills the content column, whatever its width, and grows when
 *   the sidebar folds. A safety cap of 2560 px (gutters included) only stops rows from stretching
 *   across an ultra-wide screen.
 * - `prose`: a text-heavy form (setup). The frame is the same, but the page's own column stops
 *   at about 1150 px, left-aligned under the breadcrumb, so its lines stay readable.
 * Every page keeps the same gutters, so switching pages never moves the edges.
 */
export type PageWidth = "wide" | "prose"

export interface RouteHandle {
  width?: PageWidth
}

/** Lists, hubs, dashboards and detail pages fill the column: their text blocks cap themselves. */
export const DEFAULT_PAGE_WIDTH: PageWidth = "wide"

/** The frame of every page: full width up to the safety cap (`--container-page-*`, index.css). */
export const PAGE_FRAME_CLASS = "max-w-page-wide"

/** The page's own column inside the frame. */
export const PAGE_WIDTH_CLASS: Record<PageWidth, string> = {
  wide: "",
  prose: "max-w-page-prose",
}

function widthOf(handle: unknown): PageWidth | undefined {
  if (typeof handle !== "object" || handle === null || !("width" in handle)) return undefined
  const w = (handle as RouteHandle).width
  return w === "prose" || w === "wide" ? w : undefined
}

/** The deepest matched route that declares a width wins. */
export function pageWidth(matches: readonly Pick<UIMatch, "handle">[]): PageWidth {
  for (let i = matches.length - 1; i >= 0; i--) {
    const w = widthOf(matches[i]?.handle)
    if (w) return w
  }
  return DEFAULT_PAGE_WIDTH
}
