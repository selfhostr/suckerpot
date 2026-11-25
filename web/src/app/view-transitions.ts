import type { MouseEvent } from "react"
import { resolvePath, type DataRouter, type Path, type To } from "react-router"
import { calmMotion, motionOff } from "@/lib/motion"

/**
 * Route changes animate with the View Transitions API, through React Router's `viewTransition`
 * navigation option (it wraps the update in `document.startViewTransition()` and replays the
 * transition on Back). The option is turned on here, once, for every navigation that changes the
 * page, instead of on each of the app's links: a filter or a `?tab=` that only rewrites the query
 * string never animates the page (its bars and numbers glide instead). One transition for every
 * page change (index.css): the shell stays put, the old page fades out fast, the new one rises in.
 *
 * Browsers without the API, reduced motion and frozen motion (tests, screenshots) navigate
 * without one. React Router marks this option deprecated in favour of React's `<ViewTransition>`;
 * that one skips Back and Forward (popstate updates are synchronous), which the row-to-header
 * morph needs, so the router's own option stays until React animates them too.
 */
type Place = Pick<Path, "pathname" | "search">

/** Whether going from one place to another changes the page (and so animates). */
export function changesPage(from: Place, to: Place): boolean {
  return from.pathname !== to.pathname
}

/* ---------------------------------------------------------------------------------------------
 * Shared element: the list row that was clicked becomes the header of the page it opens, and the
 * header turns back into that row on Back. A row and the detail header ask `subjectName(key)`
 * for the same key ("attacker:203.0.113.9"); only the current subject gets the name, so a name
 * is never on two elements at once (the browser would skip the whole transition).
 * --------------------------------------------------------------------------------------------- */

const SUBJECT = "vt-subject"
let subject: { key: string; origin: string } | null = null
/** Set by a row click, taken by the navigation that click starts. */
let pending: string | null = null

/** The `view-transition-name` for an element that stands for `key`, if it is the subject. */
export function subjectName(key: string): string | undefined {
  return subject?.key === key ? SUBJECT : undefined
}

/** Props for an element that stands for `key` (a row's chip, a detail page's title). */
export function subjectProps(key: string): {
  "data-vt-subject": string
  style: { viewTransitionName?: string }
} {
  return { "data-vt-subject": key, style: { viewTransitionName: subjectName(key) } }
}

/**
 * A row's link calls this on click, before the navigation starts: the row's visible
 * `[data-vt-subject]` element carries the name into the old snapshot.
 */
export function markSubject(key: string, event: MouseEvent<HTMLElement>): void {
  if (typeof document === "undefined") return
  for (const el of document.querySelectorAll<HTMLElement>("[data-vt-subject]")) {
    el.style.viewTransitionName = ""
  }
  subject = null
  pending = null
  const plain =
    event.button === 0 && !event.metaKey && !event.ctrlKey && !event.shiftKey && !event.altKey
  if (!plain || calmMotion()) return
  const row = event.currentTarget.closest("[data-vt-row]")
  const target = Array.from(row?.querySelectorAll<HTMLElement>("[data-vt-subject]") ?? []).find(
    (el) => el.dataset.vtSubject === key && el.getClientRects().length > 0,
  )
  if (!target) return
  target.style.viewTransitionName = SUBJECT
  pending = key
}

/** For tests. */
export function resetSubject(): void {
  subject = null
  pending = null
}

/** A navigation that is not the subject's own drops it, except the way back to its list. */
function settleSubject(from: Place, to: Place): void {
  if (pending) {
    subject = { key: pending, origin: from.pathname }
    pending = null
    return
  }
  if (subject && subject.origin !== to.pathname) subject = null
}

/** Turns view transitions on for the router's page changes. Call once, after createBrowserRouter. */
export function installViewTransitions(router: DataRouter): void {
  if (typeof document === "undefined" || typeof document.startViewTransition !== "function") return

  const navigate = router.navigate.bind(router)
  router.navigate = (to: To | number | null, opts?: Parameters<DataRouter["navigate"]>[1]) => {
    if (typeof to === "number") return navigate(to)
    const from = router.state.location
    const target = to == null ? from : resolvePath(to, from.pathname)
    settleSubject(from, target)
    const animate =
      // eslint-disable-next-line @typescript-eslint/no-deprecated -- see the comment at the top
      opts?.viewTransition !== false && !motionOff() && changesPage(from, target)
    return navigate(to, animate ? { ...opts, viewTransition: true } : opts)
  }
}
