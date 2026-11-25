/**
 * Entrance motion can be frozen without the visitor's reduced-motion setting: screenshots and
 * tests set `window.__SUCKERPOT_MOTION__ = { freeze: true }` (the Live map's older
 * `__SUCKERPOT_MAP__` hook counts too) or open a page with `?motion=off`. The CSS reacts to
 * `data-motion="off"` on the root element; `prefers-reduced-motion` needs no help.
 */
interface MotionHooks {
  __SUCKERPOT_MOTION__?: { freeze?: boolean }
  __SUCKERPOT_MAP__?: { freeze?: boolean }
}

export function motionFrozen(): boolean {
  const w = window as unknown as MotionHooks
  return (
    w.__SUCKERPOT_MOTION__?.freeze === true ||
    w.__SUCKERPOT_MAP__?.freeze === true ||
    new URLSearchParams(window.location.search).get("motion") === "off"
  )
}

/** Call once before the first render. */
export function applyMotionMode(): void {
  if (motionFrozen()) document.documentElement.dataset.motion = "off"
}

const REDUCED_QUERY = "(prefers-reduced-motion: reduce)"
/** Phones: below Tailwind's `sm`, the same breakpoint as calm mode in tokens.css. */
export const PHONE_QUERY = "(max-width: 639px)"

function matches(query: string): boolean {
  return typeof window !== "undefined" && typeof window.matchMedia === "function"
    ? window.matchMedia(query).matches
    : false
}

/**
 * Whether motion is off altogether: the visitor asked for reduced motion, or a test or a
 * screenshot froze it. The state still changes; it just does not move.
 */
export function motionOff(): boolean {
  return matches(REDUCED_QUERY) || (typeof window !== "undefined" && motionFrozen())
}

/**
 * Whether decorative motion driven from script is off: when motion is off, and on phones, where
 * count-ups, reorders and shared-element morphs cost frames for a screen read in a glance.
 * Short feedback (an underline, a disclosure, an overlay) does not ask.
 */
export function calmMotion(): boolean {
  return motionOff() || matches(PHONE_QUERY)
}
